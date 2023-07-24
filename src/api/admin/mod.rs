use axol::{prelude::*, Cookie, CookieJar, Form, Html, SameSite};
use chrono::Utc;
use log::error;
use serde::{de::DeserializeOwned, Deserialize, Serialize};
use serde_json::{json, Value};
use serde_with::serde_as;
use std::env;
use url::Url;
use uuid::Uuid;

use crate::{
    auth::{decode_admin, encode_jwt, generate_admin_claims, ClientIp},
    config::PUBLIC_NO_TRAILING_SLASH,
    db::{
        Attachment, Cipher, Collection, Conn, Device, Event, EventType, Group, Invitation, OrgPolicyErr, Organization, OrganizationPolicy, TwoFactor, User,
        UserOrgType, UserOrganization, DB,
    },
    events::log_event,
    mail,
    push::unregister_push_device,
    util::{docker_base_image, format_naive_datetime_local, get_display_size, get_reqwest_client, is_running_in_docker, AutoTxn},
    CONFIG, VERSION,
};

pub fn route() -> Router {
    if !CONFIG.advanced.disable_admin_token && CONFIG.settings.admin_token.is_none() {
        return Router::new().fallback("/", admin_disabled);
    }

    Router::new()
        .post("/", post_admin_login)
        .get("/", admin_page)
        .post("/invite", invite_user)
        .post("/test/smtp", test_smtp)
        .get("/logout", logout)
        .get("/users", get_users_json)
        .get("/users/overview", users_overview)
        .get("/users/by-mail/:mail", get_user_by_mail_json)
        .get("/users/:uuid", get_user_json)
        .post("/users/:uuid/delete", delete_user)
        .post("/users/:uuid/deauth", deauth_user)
        .post("/users/:uuid/disable", disable_user)
        .post("/users/:uuid/enable", enable_user)
        .post("/users/:uuid/remove-2fa", remove_2fa)
        .post("/users/:uuid/invite/resend", resend_user_invite)
        .post("/users/org_type", update_user_org_type)
        .get("/organizations/overview", organizations_overview)
        .post("/organizations/:uuid/delete", delete_organization)
        .get("/diagnostics", diagnostics)
        .get("/diagnostics/config", get_diagnostics_config)
}

async fn admin_disabled() -> &'static str {
    "The admin panel is disabled, please configure the 'ADMIN_TOKEN' variable to enable it"
}

const COOKIE_NAME: &str = "VW_ADMIN";
const DT_FMT: &str = "%Y-%m-%d %H:%M:%S %Z";

const BASE_TEMPLATE: &str = "admin/base";

fn admin_path() -> Url {
    let mut url = CONFIG.settings.public.clone();
    url.path_segments_mut().unwrap().push("admin");
    url
}

#[derive(Debug)]
struct IpHeader(Option<String>);

#[async_trait::async_trait]
impl<'a> FromRequestParts<'a> for IpHeader {
    async fn from_request_parts(req: RequestPartsRef<'a>) -> Result<Self> {
        if req.headers.get(&CONFIG.advanced.ip_header).is_some() {
            Ok(IpHeader(Some(CONFIG.advanced.ip_header.clone())))
        } else if req.headers.get("X-Client-IP").is_some() {
            Ok(IpHeader(Some(String::from("X-Client-IP"))))
        } else if req.headers.get("X-Real-IP").is_some() {
            Ok(IpHeader(Some(String::from("X-Real-IP"))))
        } else if req.headers.get("X-Forwarded-For").is_some() {
            Ok(IpHeader(Some(String::from("X-Forwarded-For"))))
        } else {
            Ok(IpHeader(None))
        }
    }
}

fn render_admin_login(msg: Option<&str>, redirect: Option<String>) -> Result<Html<String>> {
    // If there is an error, show it

    let msg = msg.map(|msg| format!("Error: {msg}"));
    let json = json!({
        "page_content": "admin/login",
        "error": msg,
        "redirect": redirect,
        "urlpath": &*PUBLIC_NO_TRAILING_SLASH,
    });
    println!("urlpath = '{}'", &*PUBLIC_NO_TRAILING_SLASH);

    // Return the page
    let text = crate::templates::render_template(BASE_TEMPLATE, &json)?;
    Ok(Html(text))
}

#[derive(Deserialize)]
struct LoginForm {
    token: String,
    redirect: Option<String>,
}

async fn post_admin_login(mut jar: CookieJar, ip: ClientIp, data: Form<LoginForm>) -> Result<Response> {
    let data = data.0;
    let redirect = data.redirect;

    if crate::ratelimit::check_limit_admin(&ip.ip).is_err() {
        return Err(Error::too_many_requests(render_admin_login(Some("Too many requests, try again later."), redirect)));
    }

    // If the token is invalid, redirect to login page
    if !validate_token(&data.token) {
        error!("Invalid admin token. IP: {}", ip.ip);
        return Err(Error::unauthorized(render_admin_login(Some("Invalid admin token, please try again."), redirect)));
    }
    // If the token received is valid, generate JWT and save it as a cookie
    let claims = generate_admin_claims();
    let jwt = encode_jwt(&claims);

    let cookie = Cookie::build(COOKIE_NAME, jwt)
        .path(admin_path().to_string())
        .max_age(cookie::time::Duration::minutes(CONFIG.advanced.admin_session_lifetime))
        .same_site(SameSite::Strict)
        .http_only(true)
        .finish();

    jar = jar.add(cookie);
    if let Some(redirect) = redirect {
        (jar, Url::parse(&format!("{}{}", admin_path(), redirect)).ise()?).into_response()
    } else {
        (jar, render_admin_page()).into_response()
    }
}

fn validate_token(token: &str) -> bool {
    match CONFIG.settings.admin_token.as_ref() {
        None => false,
        Some(t) if t.starts_with("$argon2") => {
            use argon2::password_hash::PasswordVerifier;
            match argon2::password_hash::PasswordHash::new(t) {
                Ok(h) => {
                    // NOTE: hash params from `ADMIN_TOKEN` are used instead of what is configured in the `Argon2` instance.
                    argon2::Argon2::default().verify_password(token.trim().as_ref(), &h).is_ok()
                }
                Err(e) => {
                    error!("The configured Argon2 PHC in `ADMIN_TOKEN` is invalid: {e}");
                    false
                }
            }
        }
        Some(t) => crate::crypto::ct_eq(t.trim(), token.trim()),
    }
}

#[derive(Serialize)]
struct AdminTemplateData {
    page_content: String,
    page_data: Option<Value>,
    logged_in: bool,
    urlpath: String,
}

impl AdminTemplateData {
    fn new(page_content: &str, page_data: Value) -> Self {
        Self {
            page_content: String::from(page_content),
            page_data: Some(page_data),
            logged_in: true,
            urlpath: (&*PUBLIC_NO_TRAILING_SLASH).clone(),
        }
    }

    fn render(self) -> Result<String> {
        crate::templates::render_template(BASE_TEMPLATE, &self)
    }
}

#[derive(Serialize)]
#[serde(rename_all = "snake_case")]
enum FieldType {
    Password,
    Text,
    Checkbox,
    Number,
}

#[derive(Serialize)]
struct FieldDoc {
    name: String,
    description: String,
}

#[derive(Serialize)]
struct FieldInfo {
    editable: bool,
    name: String,
    value: Value,
    default: Value,
    #[serde(rename = "type")]
    type_: FieldType,
    doc: FieldDoc,
    overridden: bool,
}

impl FieldInfo {
    fn new(name: &str, display_name: &str, description: &str, value: impl Into<Value>, type_: FieldType) -> Self {
        let value = value.into();
        Self {
            editable: false,
            name: name.to_string(),
            value: value.clone(),
            default: value,
            type_,
            doc: FieldDoc {
                name: display_name.to_string(),
                description: description.to_string(),
            },
            overridden: false,
        }
    }

    fn new_short(name: &str, display_name: &str, value: impl Into<Value>, type_: FieldType) -> Self {
        Self::new(name, display_name, display_name, value, type_)
    }
}

lazy_static::lazy_static! {
    static ref FOLDER_CONFIG: Vec<FieldInfo> = vec![
        FieldInfo::new("data", "Data folder", "Main data folder", CONFIG.folders.data.to_string_lossy(), FieldType::Text),
        FieldInfo::new_short("icon_cache", "Icon cache folder", CONFIG.folders.icon_cache().to_string_lossy(), FieldType::Text),
        FieldInfo::new_short("attachments", "Icon cache folder", CONFIG.folders.attachments().to_string_lossy(), FieldType::Text),
        FieldInfo::new_short("sends", "Sends folder", CONFIG.folders.sends().to_string_lossy(), FieldType::Text),
        FieldInfo::new("tmp", "Temp folder", "Used for storing temporary file uploads", CONFIG.folders.tmp().to_string_lossy(), FieldType::Text),
        FieldInfo::new_short("templates", "Templates folder", CONFIG.folders.templates().to_string_lossy(), FieldType::Text),
        FieldInfo::new_short("rsa_key", "Session JWT key", CONFIG.folders.rsa_key().to_string_lossy(), FieldType::Text),
        FieldInfo::new_short("web_vault", "Web vault folder", CONFIG.folders.web_vault().to_string_lossy(), FieldType::Text),
    ];
    static ref PUSH_CONFIG: Vec<FieldInfo> = vec![
        FieldInfo::new_short("relay_uri", "Push relay base uri", CONFIG.push.as_ref().map(|x| x.relay_uri.as_str()).unwrap_or_default(), FieldType::Text),
        FieldInfo::new("installation_id", "Push relay base uri", "The installation id from https://bitwarden.com/host", CONFIG.push.as_ref().map(|x| &*x.installation_id).unwrap_or_default(), FieldType::Password),
        FieldInfo::new("installation_key", "Push relay base uri", "The installation key from https://bitwarden.com/host", CONFIG.push.as_ref().map(|x| &*x.installation_key).unwrap_or_default(), FieldType::Password),
    ];
    static ref JOBS_CONFIG: Vec<FieldInfo> = vec![
        FieldInfo::new("job_poll_interval_ms", "Job scheduler poll interval", "How often the job scheduler thread checks for jobs to run. Set to 0 to globally disable scheduled jobs.", CONFIG.jobs.job_poll_interval_ms, FieldType::Number),
        FieldInfo::new("send_purge_schedule", "Send purge schedule", "Cron schedule of the job that checks for Sends past their deletion date.", CONFIG.jobs.send_purge_schedule.to_string(), FieldType::Text),
        FieldInfo::new("trash_purge_schedule", "Trash purge schedule", "Cron schedule of the job that checks for trashed items to delete permanently.", CONFIG.jobs.trash_purge_schedule.to_string(), FieldType::Text),
        FieldInfo::new("incomplete_2fa_schedule", "Incomplete 2FA login schedule", "Cron schedule of the job that checks for incomplete 2FA logins.", CONFIG.jobs.incomplete_2fa_schedule.to_string(), FieldType::Text),
        FieldInfo::new("emergency_notification_reminder_schedule", "Emergency notification reminder schedule", "Emergency notification reminder schedule |> Cron schedule of the job that sends expiration reminders to emergency access grantors.", CONFIG.jobs.emergency_notification_reminder_schedule.to_string(), FieldType::Text),
        FieldInfo::new("emergency_request_timeout_schedule", "Emergency request timeout schedule", "Cron schedule of the job that grants emergency access requests that have met the required wait time.", CONFIG.jobs.emergency_request_timeout_schedule.to_string(), FieldType::Text),
        FieldInfo::new("event_cleanup_schedule", "Event cleanup schedule", "Cron schedule of the job that cleans old events from the event table.", CONFIG.jobs.event_cleanup_schedule.to_string(), FieldType::Text),
    ];
    static ref SETTINGS_CONFIG: Vec<FieldInfo> = vec![
        FieldInfo::new("api_bind", "API bind address", "Usually 0.0.0.0:8080", CONFIG.settings.api_bind.to_string(), FieldType::Text),
        FieldInfo::new("public", "Domain URL", "This needs to be set to the URL used to access the server, including 'http[s]://' and port, if it's different than the default. Some server functions don't work correctly without this value", CONFIG.settings.public.to_string(), FieldType::Text),
        FieldInfo::new("web_vault_enabled", "Enable web vault", "Enable web vault", CONFIG.settings.web_vault_enabled, FieldType::Checkbox),
        FieldInfo::new("sends_allowed", "Allow Sends", "Controls whether users are allowed to create Bitwarden Sends. This setting applies globally to all users. To control this on a per-org basis instead, use the \"Disable Send\" org policy.", CONFIG.settings.sends_allowed, FieldType::Checkbox),
        FieldInfo::new("hibp_api_key", "HIBP Api Key", "HaveIBeenPwned API Key, request it here: https://haveibeenpwned.com/API/Key", CONFIG.settings.hibp_api_key.clone().unwrap_or_default(), FieldType::Password),
        FieldInfo::new("user_attachment_limit", "Per-user attachment storage limit (KB)", "Max kilobytes of attachment storage allowed per user. When this limit is reached, the user will not be allowed to upload further attachments.", CONFIG.settings.user_attachment_limit, FieldType::Number),
        FieldInfo::new("org_attachment_limit", "Per-organization attachment storage limit (KB)", "Max kilobytes of attachment storage allowed per org. When this limit is reached, org members will not be allowed to upload further attachments for ciphers owned by that org.", CONFIG.settings.org_attachment_limit, FieldType::Number),
        FieldInfo::new("trash_auto_delete_days", "Trash auto-delete days", "Number of days to wait before auto-deleting a trashed item. If unset, trashed items are not auto-deleted. This setting applies globally, so make sure to inform all users of any changes to this setting.", CONFIG.settings.trash_auto_delete_days, FieldType::Number),
        FieldInfo::new("incomplete_2fa_time_limit", "Incomplete 2FA time limit", "Number of minutes to wait before a 2FA-enabled login is considered incomplete, resulting in an email notification. An incomplete 2FA login is one where the correct master password was provided but the required 2FA step was not completed, which potentially indicates a master password compromise. Set to 0 to disable this check. This setting applies globally to all users.", CONFIG.settings.incomplete_2fa_time_limit, FieldType::Number),
        FieldInfo::new("disable_icon_download", "Disable icon downloads", "Set to true to disable icon downloading in the internal icon service. This still serves existing icons from $ICON_CACHE_FOLDER, without generating any external network requests. $ICON_CACHE_TTL must also be set to 0; otherwise, the existing icons will be deleted eventually, but won't be downloaded again.", CONFIG.settings.disable_icon_download, FieldType::Checkbox),
        FieldInfo::new("signups_allowed", "Allow new signups", "Controls whether new users can register. Users can be invited by the vaultwarden admin even if this is disabled", CONFIG.settings.signups_allowed, FieldType::Checkbox),
        FieldInfo::new("signups_verify", "Require email verification on signups", "This will prevent logins from succeeding until the address has been verified", CONFIG.settings.signups_verify, FieldType::Checkbox),
        FieldInfo::new("signups_verify_resend_time", "Verify Resend Time", "If signups require email verification, automatically re-send verification email if it hasn't been sent for a while (in seconds)", CONFIG.settings.signups_verify_resend_time, FieldType::Number),
        FieldInfo::new("signups_verify_resend_limit", "Verify Resend Limit", "If signups require email verification, limit how many emails are automatically sent when login is attempted (0 means no limit)", CONFIG.settings.signups_verify_resend_limit, FieldType::Number),
        FieldInfo::new("signups_domains_whitelist", "Email domain whitelist", "Allow signups only from this list of domains, even when signups are otherwise disabled", CONFIG.settings.signups_domains_whitelist.iter().map(|x| &**x).collect::<Vec<_>>().join(","), FieldType::Text),
        FieldInfo::new("org_events_enabled", "Enable event logging", "Enables event logging for organizations.", CONFIG.settings.org_events_enabled, FieldType::Checkbox),
        FieldInfo::new("org_creation_users", "Org creation users", "Allow org creation only by this list of user emails. Blank or 'all' means all users can create orgs; 'none' means no users can create orgs.", CONFIG.settings.org_creation_users.iter().map(|x| &**x).collect::<Vec<_>>().join(","), FieldType::Text),
        FieldInfo::new("invitations_allowed", "Allow invitations", "Controls whether users can be invited by organization admins, even when signups are otherwise disabled", CONFIG.settings.invitations_allowed, FieldType::Checkbox),
        FieldInfo::new("invitation_expiration_hours", "Invitation token expiration time (in hours)", "The number of hours after which an organization invite token, emergency access invite token, email verification token and deletion request token will expire (must be at least 1)", CONFIG.settings.invitation_expiration_hours, FieldType::Number),
        FieldInfo::new("emergency_access_allowed", "Allow emergency access", "Controls whether users can enable emergency access to their accounts. This setting applies globally to all users.", CONFIG.settings.emergency_access_allowed, FieldType::Checkbox),
        FieldInfo::new("password_iterations", "Password iterations", "Number of server-side passwords hashing iterations for the password hash. The default for new users. If changed, it will be updated during login for existing users.", CONFIG.settings.password_iterations, FieldType::Number),
        FieldInfo::new("password_hints_allowed", "Allow password hints", "Controls whether users can set password hints. This setting applies globally to all users.", CONFIG.settings.password_hints_allowed, FieldType::Checkbox),
        FieldInfo::new("show_password_hint", "Show password hint", "Controls whether a password hint should be shown directly in the web page if SMTP service is not configured. Not recommended for publicly-accessible instances as this provides unauthenticated access to potentially sensitive data.", CONFIG.settings.show_password_hint, FieldType::Checkbox),
        FieldInfo::new("admin_token", "Admin token/Argon2 PHC", "The plain text token or Argon2 PHC string used to authenticate in this very same page. Changing it here will not deauthorize the current session!", CONFIG.settings.admin_token.clone(), FieldType::Password),
        FieldInfo::new("invitation_org_name", "Invitation organization name", "Name shown in the invitation emails that don't come from a specific organization", CONFIG.settings.invitation_org_name.clone(), FieldType::Text),
        FieldInfo::new("events_days_retain", "Events days retain", "Number of days to retain events stored in the database. If unset, events are kept indefently.", CONFIG.settings.events_days_retain, FieldType::Number),
    ];
    static ref ADVANCED_CONFIG: Vec<FieldInfo> = vec![
        FieldInfo::new("ip_header", "Client IP header", "Set to empty string to just use remote IP.", CONFIG.advanced.ip_header.clone(), FieldType::Text),
        FieldInfo::new("icon_service", "Icon service", "The predefined icon services are: internal, bitwarden, duckduckgo, google. To specify a custom icon service, set a URL template with exactly one instance of `{}`, which is replaced with the domain. For example: `https://icon.example.com/domain/{}`. `internal` refers to Vaultwarden's built-in icon fetching implementation. If an external service is set, an icon request to Vaultwarden will return an HTTP redirect to the corresponding icon at the external service.", CONFIG.advanced.icon_service.to_string(), FieldType::Text),
        FieldInfo::new("icon_redirect_code", "Icon redirect code", "The HTTP status code to use for redirects to an external icon service. The supported codes are 301 (legacy permanent), 302 (legacy temporary), 307 (temporary), and 308 (permanent). Temporary redirects are useful while testing different icon services, but once a service has been decided on, consider using permanent redirects for cacheability. The legacy codes are currently better supported by the Bitwarden clients.", CONFIG.advanced.icon_redirect_code, FieldType::Number),
        FieldInfo::new("icon_cache_ttl", "Positive icon cache expiry", "Number of seconds to consider that an already cached icon is fresh. After this period, the icon will be redownloaded", CONFIG.advanced.icon_cache_ttl, FieldType::Number),
        FieldInfo::new("icon_cache_negttl", "Negative icon cache expiry", "Number of seconds before trying to download an icon that failed again.", CONFIG.advanced.icon_cache_negttl, FieldType::Number),
        FieldInfo::new("icon_download_timeout", "Icon download timeout", "Number of seconds when to stop attempting to download an icon.", CONFIG.advanced.icon_download_timeout, FieldType::Number),
        FieldInfo::new("icon_blacklist_regex", "Icon blacklist regex", "Any domains that match this regex won't be fetched by the icon service. Useful to hide other servers in the local network. Check the WIKI for more details", CONFIG.advanced.icon_blacklist_regex.as_ref().map(|x| x.as_str()), FieldType::Text),
        FieldInfo::new("icon_blacklist_ips", "Icon blacklist IPs", "Any ips that match any of these CIDRs won't be fetched by the icon service. Useful to hide other servers in the local network. Check the WIKI for more etails", CONFIG.advanced.icon_blacklist_ips.iter().map(|x| x.to_string()).collect::<Vec<_>>().join(","), FieldType::Text),
        FieldInfo::new("disable_2fa_remember", "Disable Two-Factor remember", "Enabling this would force the users to use a second factor to login every time. Note that the checkbox would still be present, but ignored.", CONFIG.advanced.disable_2fa_remember, FieldType::Checkbox),
        FieldInfo::new("authenticator_disable_time_drift", "Disable authenticator time drifted codes to be valid", "Enabling this only allows the current TOTP code to be valid TOTP codes of the previous and next 30 seconds will be invalid.", CONFIG.advanced.authenticator_disable_time_drift, FieldType::Checkbox),
        FieldInfo::new("require_device_email", "Require new device emails", "When a user logs in an email is required to be sent. If sending the email fails the login attempt will fail.", CONFIG.advanced.require_device_email, FieldType::Checkbox),
        FieldInfo::new("reload_templates", "Reload templates (Dev)", "When this is set to true, the templates get reloaded with every request. ONLY use this during development, as it can slow down the server", CONFIG.advanced.reload_templates, FieldType::Checkbox),
        FieldInfo::new("log_level", "Log level", "Log level", CONFIG.advanced.log_level.clone(), FieldType::Text),
        FieldInfo::new("enable_db_wal", "Enable DB WAL", "Turning this off might lead to worse performance, but might help if using vaultwarden on some exotic filesystems, that do not support WAL. Please make sure you read project wiki on the topic before changing this setting.", CONFIG.advanced.enable_db_wal, FieldType::Checkbox),
        FieldInfo::new("database_connection_retries", "Max database connection retries", "Number of times to retry the database connection during startup, with 1 second between each retry, set to 0 to retry indefinitely", CONFIG.advanced.database_connection_retries, FieldType::Number),
        FieldInfo::new("database_timeout", "Datebase Timeout", "Timeout (seconds) when aquiring database connection", CONFIG.advanced.database_timeout, FieldType::Number),
        FieldInfo::new("database_max_conns", "Database connection pool size", "Database connection pool size", CONFIG.advanced.database_max_conns, FieldType::Number),
        FieldInfo::new("disable_admin_token", "Bypass admin page security (Know the risks!)", "Disables the Admin Token for the admin page so you may use your own auth in-front", CONFIG.advanced.disable_admin_token, FieldType::Checkbox),
        FieldInfo::new("allowed_iframe_ancestors", "Allowed iframe ancestors (Know the risks!)", "Allows other domains to embed the web vault into an iframe, useful for embedding into secure intranets", CONFIG.advanced.allowed_iframe_ancestors.clone(), FieldType::Text),
        FieldInfo::new("login_ratelimit_seconds", "Seconds between login requests", "Number of seconds, on average, between login and 2FA requests from the same IP address before rate limiting kicks in", CONFIG.advanced.login_ratelimit_seconds, FieldType::Number),
        FieldInfo::new("login_ratelimit_max_burst", "Max burst size for login requests", "Allow a burst of requests of up to this size, while maintaining the average indicated by `login_ratelimit_seconds`. Note that this applies to both the login and the 2FA, so it's recommended to allow a burst size of at least 2", CONFIG.advanced.login_ratelimit_max_burst, FieldType::Number),
        FieldInfo::new("admin_ratelimit_seconds", "Seconds between admin login requests", "Number of seconds, on average, between admin requests from the same IP address before rate limiting kicks in", CONFIG.advanced.admin_ratelimit_seconds, FieldType::Number),
        FieldInfo::new("admin_ratelimit_max_burst", "Max burst size for admin login requests", "Allow a burst of requests of up to this size, while maintaining the average indicated by `admin_ratelimit_seconds`", CONFIG.advanced.admin_ratelimit_max_burst, FieldType::Number),
        FieldInfo::new("admin_session_lifetime", "Admin session lifetime", "Set the lifetime of admin sessions to this value (in minutes).", CONFIG.advanced.admin_session_lifetime, FieldType::Number),
        FieldInfo::new("org_groups_enabled", "Enable groups (BETA!) (Know the risks!)", "Enables groups support for organizations (Currently contains known issues!).", CONFIG.advanced.org_groups_enabled, FieldType::Checkbox),
    ];
    static ref YUBICO_CONFIG: Vec<FieldInfo> = vec![
        FieldInfo::new_short("client_id", "Client ID", CONFIG.yubico.as_ref().map(|x| x.client_id.clone()).unwrap_or_default(), FieldType::Text),
        FieldInfo::new_short("secret_key", "Secret Key", CONFIG.yubico.as_ref().map(|x| x.secret_key.as_str()).unwrap_or_default(), FieldType::Password),
        FieldInfo::new_short("server", "Yubico server", CONFIG.yubico.as_ref().and_then(|x| x.server.as_ref().map(|x| x.as_str())).unwrap_or_default(), FieldType::Text),
    ];
    static ref DUO_CONFIG: Vec<FieldInfo> = vec![
        FieldInfo::new_short("integration_key", "Integration ID", CONFIG.duo.as_ref().map(|x| x.integration_key.clone()).unwrap_or_default(), FieldType::Text),
        FieldInfo::new_short("secret_key", "Secret Key", CONFIG.duo.as_ref().map(|x| x.secret_key.as_str()).unwrap_or_default(), FieldType::Password),
        FieldInfo::new_short("server", "Duo server", CONFIG.duo.as_ref().map(|x| x.server.as_str()).unwrap_or_default(), FieldType::Text),
        FieldInfo::new_short("app_key", "Unique ID for App", CONFIG.duo.as_ref().map(|x| x.app_key.clone()).unwrap_or_default(), FieldType::Password),
    ];
    static ref SMTP_CONFIG: Vec<FieldInfo> = vec![
        FieldInfo::new("host", "Host name", "Host name of SMTP server, must not include port.", CONFIG.smtp.as_ref().map(|x| x.host.clone()), FieldType::Text),
        FieldInfo::new("security", "Secure SMTP", "(\"starttls\", \"force_tls\", \"off\") Enable a secure connection. Default is \"starttls\" (Explicit - ports 587 or 25), \"force_tls\" (Implicit - port 465) or \"off\", no encryption", CONFIG.smtp.as_ref().map(|x| x.security.to_string()), FieldType::Text),
        FieldInfo::new("port", "Port", "derived from 'security' if not specified", CONFIG.smtp.as_ref().map(|x| x.port), FieldType::Number),
        FieldInfo::new("from_address", "From Address", "Originating email address", CONFIG.smtp.as_ref().map(|x| x.from_address.clone()), FieldType::Text),
        FieldInfo::new("from_name", "From Name", "Name attached to email", CONFIG.smtp.as_ref().map(|x| x.from_name.clone()), FieldType::Text),
        FieldInfo::new("username", "SMTP Username", "SMTP Username. Optional.", CONFIG.smtp.as_ref().map(|x| x.username.clone()), FieldType::Text),
        FieldInfo::new("password", "SMTP Password", "SMTP Password. Optional.", CONFIG.smtp.as_ref().map(|x| x.password.clone()), FieldType::Text),
        FieldInfo::new("timeout", "SMTP connection timeout", "Number of seconds when to stop trying to connect to the SMTP server", CONFIG.smtp.as_ref().map(|x| x.timeout), FieldType::Number),
        FieldInfo::new("helo_name", "Server name sent during HELO", "By default this value should be is on the machine's hostname, but might need to be changed in case it trips some anti-spam filters", CONFIG.smtp.as_ref().map(|x| x.helo_name.clone()), FieldType::Text),
        FieldInfo::new("embed_images", "Embed images as email attachments.", "True by default.", CONFIG.smtp.as_ref().map(|x| x.embed_images), FieldType::Checkbox),
        FieldInfo::new("debug", "Enable SMTP debugging (Know the risks!)", "DANGEROUS: Enabling this will output very detailed SMTP messages. This could contain sensitive information like passwords and usernames! Only enable this during troubleshooting!", CONFIG.smtp.as_ref().map(|x| x.debug), FieldType::Checkbox),
        FieldInfo::new("accept_invalid_certs", "Accept Invalid Certs (Know the risks!)", "DANGEROUS: Allow invalid certificates. This option introduces significant vulnerabilities to man-in-the-middle attacks!", CONFIG.smtp.as_ref().map(|x| x.accept_invalid_certs), FieldType::Checkbox),
        FieldInfo::new("accept_invalid_hostnames", "Accept Invalid Hostnames (Know the risks!)", "DANGEROUS: Allow invalid hostnames. This option introduces significant vulnerabilities to man-in-the-middle attacks!", CONFIG.smtp.as_ref().map(|x| x.accept_invalid_hostnames), FieldType::Checkbox),
    ];
    static ref EMAIL_2FA_CONFIG: Vec<FieldInfo> = vec![
        FieldInfo::new("email_token_size", "Email token size", "Number of digits in an email 2FA token (min: 6, max: 255). Note that the Bitwarden clients are hardcoded to mention 6 digit codes regardless of this setting.", CONFIG.yubico.as_ref().map(|x| x.client_id.clone()).unwrap_or_default(), FieldType::Number),
        FieldInfo::new("email_expiration_time", "Token expiration time", "Maximum time in seconds a token is valid. The time the user has to open email client and copy token.", CONFIG.yubico.as_ref().map(|x| x.secret_key.as_str()).unwrap_or_default(), FieldType::Number),
        FieldInfo::new("email_attempts_limit", "Maximum attempts", "Maximum attempts before an email token is reset and a new email will need to be sent.", CONFIG.yubico.as_ref().and_then(|x| x.server.as_ref().map(|x| x.as_str())).unwrap_or_default(), FieldType::Number),
    ];
}

fn render_admin_page() -> Result<Html<String>> {
    let settings_json = json!({
        "config": [
            {
                "group": "folders",
                // "grouptoggle"
                // "groupdoc"
                "elements": &*FOLDER_CONFIG,
            },
            {
                "group": "push",
                "elements": &*PUSH_CONFIG,
            },
            {
                "group": "jobs",
                "elements": &*JOBS_CONFIG,
            },
            {
                "group": "settings",
                "elements": &*SETTINGS_CONFIG,
            },
            {
                "group": "advanced",
                "elements": &*ADVANCED_CONFIG,
            },
            {
                "group": "yubico",
                "elements": &*YUBICO_CONFIG,
            },
            {
                "group": "duo",
                "elements": &*DUO_CONFIG,
            },
            {
                "group": "smtp",
                "elements": &*SMTP_CONFIG,
            },
            {
                "group": "email_2fa",
                "elements": &*EMAIL_2FA_CONFIG,
            },
        ],
    });
    let text = AdminTemplateData::new("admin/settings", settings_json).render()?;
    Ok(Html(text))
}

async fn admin_page(token: Option<AdminToken>) -> Result<Html<String>> {
    if token.is_none() {
        return render_admin_login(None, None);
    }
    render_admin_page()
}

#[derive(Deserialize, Debug)]
#[allow(non_snake_case)]
struct InviteData {
    email: String,
}

async fn get_user_or_404(uuid: Uuid, conn: &Conn) -> Result<User> {
    User::get(conn, uuid).await?.ok_or(Error::NotFound)
}

async fn invite_user(_token: AdminToken, data: Json<InviteData>) -> Result<Json<Value>> {
    let data: InviteData = data.0;
    let email = data.email.clone();

    let conn = DB.get().await.map_err(Error::internal)?;

    if User::find_by_email(&conn, &data.email).await?.is_some() {
        err_code!("User already exists", StatusCode::Conflict)
    }

    let mut user = User::new(email);

    async fn generate_invite(user: &User, conn: &Conn) -> Result<()> {
        if CONFIG.mail_enabled() {
            mail::send_invite(&user.email, user.uuid, None, &CONFIG.settings.invitation_org_name, None).await?;
        } else {
            let invitation = Invitation::new(&user.email);
            invitation.save(conn).await?;
        }
        Ok(())
    }

    generate_invite(&user, &conn).await?;
    user.save(&conn).await?;

    Ok(Json(user.to_json(&conn).await?))
}

async fn test_smtp(_token: AdminToken, data: Json<InviteData>) -> Result<()> {
    let data: InviteData = data.0;

    if CONFIG.mail_enabled() {
        mail::send_test(&data.email).await
    } else {
        err!("Mail is not enabled")
    }
}

async fn logout(mut cookies: CookieJar) -> (CookieJar, Url) {
    cookies = cookies.remove(Cookie::build(COOKIE_NAME, "").path(admin_path().to_string()).finish());
    (cookies, admin_path())
}

async fn get_users_json(_token: AdminToken) -> Result<Json<Value>> {
    let conn = DB.get().await.map_err(Error::internal)?;
    let users = User::get_all(&conn).await?;
    let mut users_json = Vec::with_capacity(users.len());
    //TODO: N+1 query here
    for u in users {
        let mut usr = u.to_json(&conn).await?;
        usr["UserEnabled"] = json!(u.enabled);
        usr["CreatedAt"] = json!(format_naive_datetime_local(u.created_at, DT_FMT));
        users_json.push(usr);
    }

    Ok(Json(Value::Array(users_json)))
}

async fn users_overview(_token: AdminToken) -> Result<Html<String>> {
    let conn = DB.get().await.map_err(Error::internal)?;
    let users = User::get_all(&conn).await?;
    let mut users_json = Vec::with_capacity(users.len());
    //TODO: N+1 query here
    for u in users {
        let (size, count) = Attachment::size_count_by_user(&conn, u.uuid).await?;
        let mut usr = u.to_json(&conn).await?;
        usr["cipher_count"] = json!(Cipher::count_owned_by_user(&conn, u.uuid).await?);
        usr["attachment_count"] = json!(count);
        usr["attachment_size"] = json!(get_display_size(size as i32));
        usr["user_enabled"] = json!(u.enabled);
        usr["created_at"] = json!(format_naive_datetime_local(u.created_at, DT_FMT));
        usr["last_active"] = match u.last_active(&conn).await? {
            Some(dt) => json!(format_naive_datetime_local(dt, DT_FMT)),
            None => json!("Never"),
        };
        users_json.push(usr);
    }

    let text = AdminTemplateData::new("admin/users", json!(users_json)).render()?;
    Ok(Html(text))
}

async fn get_user_by_mail_json(Path(mail): Path<String>, _token: AdminToken) -> Result<Json<Value>> {
    let conn = DB.get().await.map_err(Error::internal)?;

    if let Some(u) = User::find_by_email(&conn, &mail).await? {
        let mut usr = u.to_json(&conn).await?;
        usr["UserEnabled"] = json!(u.enabled);
        usr["CreatedAt"] = json!(format_naive_datetime_local(u.created_at, DT_FMT));
        Ok(Json(usr))
    } else {
        err_code!("User doesn't exist", StatusCode::NotFound);
    }
}

async fn get_user_json(Path(uuid): Path<Uuid>, _token: AdminToken) -> Result<Json<Value>> {
    let conn = DB.get().await.map_err(Error::internal)?;

    let u = get_user_or_404(uuid, &conn).await?;
    let mut usr = u.to_json(&conn).await?;
    usr["UserEnabled"] = json!(u.enabled);
    usr["CreatedAt"] = json!(format_naive_datetime_local(u.created_at, DT_FMT));
    Ok(Json(usr))
}

async fn delete_user(Path(uuid): Path<Uuid>, token: AdminToken, conn: AutoTxn) -> Result<()> {
    let user = get_user_or_404(uuid, &conn).await?;

    // Get the user_org records before deleting the actual user
    let user_orgs = UserOrganization::find_by_user(&conn, uuid).await?;
    user.delete(&conn).await?;

    for user_org in user_orgs {
        log_event(
            EventType::OrganizationUserRemoved,
            uuid,
            user_org.organization_uuid,
            Uuid::default(),
            14, // Use UnknownBrowser type
            Utc::now(),
            token.ip.ip,
            &conn,
        )
        .await?;
    }
    conn.commit().await?;

    Ok(())
}

async fn deauth_user(Path(uuid): Path<Uuid>, _token: AdminToken) -> Result<()> {
    let conn = DB.get().await.map_err(Error::internal)?;
    let mut user = get_user_or_404(uuid, &conn).await?;

    ws_users().send_logout(&user, &conn, None).await?;

    if CONFIG.push.is_some() {
        for device in Device::find_push_devices_by_user(&conn, user.uuid).await? {
            match unregister_push_device(device.uuid).await {
                Ok(r) => r,
                Err(e) => error!("Unable to unregister devices from Bitwarden server: {}", e),
            };
        }
    }

    Device::delete_all_by_user(&conn, user.uuid).await?;
    user.reset_security_stamp();

    user.save(&conn).await
}

async fn disable_user(Path(uuid): Path<Uuid>, _token: AdminToken) -> Result<()> {
    let conn = DB.get().await.map_err(Error::internal)?;
    let mut user = get_user_or_404(uuid, &conn).await?;
    Device::delete_all_by_user(&conn, user.uuid).await?;
    user.reset_security_stamp();
    user.enabled = false;

    let save_result = user.save(&conn).await;

    ws_users().send_logout(&user, &conn, None).await?;

    save_result
}

async fn enable_user(Path(uuid): Path<Uuid>, _token: AdminToken) -> Result<()> {
    let conn = DB.get().await.map_err(Error::internal)?;

    let mut user = get_user_or_404(uuid, &conn).await?;
    user.enabled = true;

    user.save(&conn).await
}

async fn remove_2fa(Path(uuid): Path<Uuid>, _token: AdminToken, conn: AutoTxn) -> Result<()> {
    let mut user = get_user_or_404(uuid, &conn).await?;
    TwoFactor::delete_all_by_user(&conn, user.uuid).await?;
    user.totp_recover = None;
    user.save(&conn).await?;

    conn.commit().await?;
    Ok(())
}

async fn resend_user_invite(Path(uuid): Path<Uuid>, _token: AdminToken) -> Result<()> {
    let conn = DB.get().await.map_err(Error::internal)?;

    let Some(user) = User::get(&conn, uuid).await? else {
        err_code!("User doesn't exist", StatusCode::NotFound);
    };

    //TODO: replace this with user.status check when it will be available (PR#3397)
    if !user.password_hash.is_empty() {
        err_code!("User already accepted invitation", StatusCode::BadRequest);
    }

    if CONFIG.mail_enabled() {
        mail::send_invite(&user.email, user.uuid, None, &CONFIG.settings.invitation_org_name, None).await?;
    }
    Ok(())
}

#[serde_as]
#[derive(Deserialize, Debug)]
struct UserOrgTypeData {
    #[serde_as(as = "serde_with::PickFirst<(_, serde_with::DisplayFromStr)>")]
    user_type: UserOrgType,
    user_uuid: Uuid,
    org_uuid: Uuid,
}

async fn update_user_org_type(token: AdminToken, data: Json<UserOrgTypeData>) -> Result<()> {
    let conn = DB.get().await.map_err(Error::internal)?;

    let data: UserOrgTypeData = data.0;

    let mut user_to_edit = match UserOrganization::get(&conn, data.user_uuid, data.org_uuid).await? {
        Some(user) => user,
        None => err!("The specified user isn't member of the organization"),
    };

    let new_type = data.user_type;

    if user_to_edit.atype == UserOrgType::Owner && new_type != UserOrgType::Owner {
        // Removing owner permission, check that there is at least one other confirmed owner
        if UserOrganization::count_confirmed_by_org_and_type(&conn, data.org_uuid, UserOrgType::Owner).await? <= 1 {
            err!("Can't change the type of the last owner")
        }
    }

    // This check is also done at api::organizations::{accept_invite(), _confirm_invite, _activate_user(), edit_user()}, update_user_org_type
    // It returns different error messages per function.
    if new_type < UserOrgType::Admin {
        match OrganizationPolicy::is_user_allowed(&conn, user_to_edit.user_uuid, user_to_edit.organization_uuid, true).await? {
            Ok(_) => {}
            Err(OrgPolicyErr::TwoFactorMissing) => {
                err!("You cannot modify this user to this type because it has no two-step login method activated");
            }
            Err(OrgPolicyErr::SingleOrgEnforced) => {
                err!("You cannot modify this user to this type because it is a member of an organization which forbids it");
            }
        }
    }

    log_event(
        EventType::OrganizationUserUpdated,
        data.user_uuid,
        data.org_uuid,
        Uuid::default(),
        14, // Use UnknownBrowser type
        Utc::now(),
        token.ip.ip,
        &conn,
    )
    .await?;

    user_to_edit.atype = new_type;
    user_to_edit.save(&conn).await
}

async fn organizations_overview(_token: AdminToken) -> Result<Html<String>> {
    let conn = DB.get().await.map_err(Error::internal)?;

    let organizations = Organization::get_all(&conn).await?;
    let mut organizations_json = Vec::with_capacity(organizations.len());
    //TODO: N+1 Query
    for o in organizations {
        let (size, count) = Attachment::size_count_by_organization(&conn, o.uuid).await?;
        let mut org = o.to_json();
        org["user_count"] = json!(UserOrganization::count_by_org(&conn, o.uuid).await?);
        org["cipher_count"] = json!(Cipher::count_by_org(&conn, o.uuid).await?);
        org["collection_count"] = json!(Collection::count_by_org(&conn, o.uuid).await?);
        org["group_count"] = json!(Group::count_by_org(&conn, o.uuid).await?);
        org["event_count"] = json!(Event::count_by_organization(&conn, o.uuid).await?);
        org["attachment_count"] = json!(count);
        org["attachment_size"] = json!(get_display_size(size as i32));
        organizations_json.push(org);
    }

    let text = AdminTemplateData::new("admin/organizations", json!(organizations_json)).render()?;
    Ok(Html(text))
}

async fn delete_organization(Path(uuid): Path<Uuid>, _token: AdminToken) -> Result<()> {
    let conn = DB.get().await.map_err(Error::internal)?;

    let org = Organization::get(&conn, uuid).await?.ok_or(Error::NotFound)?;
    org.delete(&conn).await
}

#[derive(Deserialize)]
struct WebVaultVersion {
    version: String,
}

#[derive(Deserialize)]
struct GitRelease {
    tag_name: String,
}

#[derive(Deserialize)]
struct GitCommit {
    sha: String,
}

#[derive(Deserialize)]
struct TimeApi {
    year: u16,
    month: u8,
    day: u8,
    hour: u8,
    minute: u8,
    seconds: u8,
}

async fn get_json_api<T: DeserializeOwned>(url: &str) -> Result<T> {
    let json_api = get_reqwest_client();

    Ok(json_api.get(url).send().await.map_err(Error::internal)?.error_for_status().map_err(Error::internal)?.json::<T>().await.map_err(Error::internal)?)
}

async fn has_http_access() -> bool {
    let http_access = get_reqwest_client();

    match http_access.head("https://github.com/dani-garcia/vaultwarden").send().await {
        Ok(r) => r.status().is_success(),
        _ => false,
    }
}

use cached::proc_macro::cached;

use super::ws_users;
/// Cache this function to prevent API call rate limit. Github only allows 60 requests per hour, and we use 3 here already.
/// It will cache this function for 300 seconds (5 minutes) which should prevent the exhaustion of the rate limit.
#[cached(time = 300, sync_writes = true)]
async fn get_release_info(has_http_access: bool, running_within_docker: bool) -> (String, String, String) {
    // If the HTTP Check failed, do not even attempt to check for new versions since we were not able to connect with github.com anyway.
    if has_http_access {
        (
            match get_json_api::<GitRelease>("https://api.github.com/repos/dani-garcia/vaultwarden/releases/latest").await {
                Ok(r) => r.tag_name,
                _ => "-".to_string(),
            },
            match get_json_api::<GitCommit>("https://api.github.com/repos/dani-garcia/vaultwarden/commits/main").await {
                Ok(mut c) => {
                    c.sha.truncate(8);
                    c.sha
                }
                _ => "-".to_string(),
            },
            // Do not fetch the web-vault version when running within Docker.
            // The web-vault version is embedded within the container it self, and should not be updated manually
            if running_within_docker {
                "-".to_string()
            } else {
                match get_json_api::<GitRelease>("https://api.github.com/repos/dani-garcia/bw_web_builds/releases/latest").await {
                    Ok(r) => r.tag_name.trim_start_matches('v').to_string(),
                    _ => "-".to_string(),
                }
            },
        )
    } else {
        ("-".to_string(), "-".to_string(), "-".to_string())
    }
}

async fn get_ntp_time(has_http_access: bool) -> String {
    if has_http_access {
        if let Ok(ntp_time) = get_json_api::<TimeApi>("https://www.timeapi.io/api/Time/current/zone?timeZone=UTC").await {
            return format!(
                "{year}-{month:02}-{day:02} {hour:02}:{minute:02}:{seconds:02} UTC",
                year = ntp_time.year,
                month = ntp_time.month,
                day = ntp_time.day,
                hour = ntp_time.hour,
                minute = ntp_time.minute,
                seconds = ntp_time.seconds
            );
        }
    }
    String::from("Unable to fetch NTP time.")
}

async fn diagnostics(_token: AdminToken, ip_header: IpHeader) -> Result<Html<String>> {
    use chrono::prelude::*;
    use std::net::ToSocketAddrs;

    // Get current running versions
    let web_vault_version: WebVaultVersion = match tokio::fs::read_to_string(format!("{}/{}", CONFIG.folders.web_vault().display(), "vw-version.json")).await {
        Ok(s) => serde_json::from_str(&s).map_err(Error::internal)?,
        _ => match tokio::fs::read_to_string(format!("{}/{}", CONFIG.folders.web_vault().display(), "version.json")).await {
            Ok(s) => serde_json::from_str(&s).map_err(Error::internal)?,
            _ => WebVaultVersion {
                version: String::from("Version file missing"),
            },
        },
    };

    // Execute some environment checks
    let running_within_docker = is_running_in_docker();
    let has_http_access = has_http_access().await;
    let uses_proxy = env::var_os("HTTP_PROXY").is_some()
        || env::var_os("http_proxy").is_some()
        || env::var_os("HTTPS_PROXY").is_some()
        || env::var_os("https_proxy").is_some();

    // Check if we are able to resolve DNS entries
    let dns_resolved = match ("github.com", 0).to_socket_addrs().map(|mut i| i.next()) {
        Ok(Some(a)) => a.ip().to_string(),
        _ => "Unable to resolve domain name.".to_string(),
    };

    let (latest_release, latest_commit, latest_web_build) = get_release_info(has_http_access, running_within_docker).await;

    let ip_header_name = match &ip_header.0 {
        Some(h) => h,
        _ => "",
    };

    let db_version = {
        let conn = DB.get().await.map_err(Error::internal)?;
        conn.query_one("SELECT version()", &[]).await.map_err(Error::internal)?.get::<_, String>(0)
    };
    let admin_url = {
        let mut url = admin_path();
        url.path_segments_mut().unwrap().push("diagnostics");
        url
    };

    let diagnostics_json = json!({
        "dns_resolved": dns_resolved,
        "current_release": VERSION,
        "latest_release": latest_release,
        "latest_commit": latest_commit,
        "web_vault_enabled": CONFIG.settings.web_vault_enabled,
        "web_vault_version": web_vault_version.version.trim_start_matches('v'),
        "latest_web_build": latest_web_build,
        "running_within_docker": running_within_docker,
        "docker_base_image": if running_within_docker { docker_base_image() } else { "Not applicable" },
        "has_http_access": has_http_access,
        "ip_header_exists": &ip_header.0.is_some(),
        "ip_header_match": ip_header_name == CONFIG.advanced.ip_header,
        "ip_header_name": ip_header_name,
        "ip_header_config": CONFIG.advanced.ip_header,
        "uses_proxy": uses_proxy,
        "db_type": "postgresql",
        "db_version": db_version,
        "admin_url": admin_url,
        "overrides": "",
        "host_arch": std::env::consts::ARCH,
        "host_os":  std::env::consts::OS,
        "server_time_local": Local::now().format("%Y-%m-%d %H:%M:%S %Z").to_string(),
        "server_time": Utc::now().format("%Y-%m-%d %H:%M:%S UTC").to_string(), // Run the server date/time check as late as possible to minimize the time difference
        "ntp_time": get_ntp_time(has_http_access).await, // Run the ntp check as late as possible to minimize the time difference
    });

    let text = AdminTemplateData::new("admin/diagnostics", diagnostics_json).render()?;
    Ok(Html(text))
}

async fn get_diagnostics_config(_token: AdminToken) -> Json<Value> {
    // Define which config keys need to be masked.
    // Pass types will always be masked and no need to put them in the list.
    // Besides Pass, only String types will be masked via _privacy_mask.
    const _PRIVACY_CONFIG: &[&str] = &[
        "allowed_iframe_ancestors",
        "database_url",
        "domain_origin",
        "domain_path",
        "domain",
        "helo_name",
        "org_creation_users",
        "signups_domains_whitelist",
        "smtp_from",
        "smtp_host",
        "smtp_username",
    ];

    /// We map over the string and remove all alphanumeric, _ and - characters.
    /// This is the fastest way (within micro-seconds) instead of using a regex (which takes milli-seconds)
    fn _privacy_mask(value: &str) -> String {
        let mut n: u16 = 0;
        let mut colon_match = false;
        value
            .chars()
            .map(|c| {
                n += 1;
                match c {
                    ':' if n <= 11 => {
                        colon_match = true;
                        c
                    }
                    '/' if n <= 13 && colon_match => c,
                    ',' => c,
                    _ => '*',
                }
            })
            .collect::<String>()
    }

    //TODO
    Json(Default::default())
}

//TODO?

// #[post("/config", data = "<data>")]
// fn post_config(data: Json<ConfigBuilder>, _token: AdminToken) -> Result<()> {
//     let data: ConfigBuilder = data.into_inner();
//     CONFIG.update_config(data)
// }

// #[post("/config/delete")]
// fn delete_config(_token: AdminToken) -> Result<()> {
//     CONFIG.delete_user_config()
// }

pub struct AdminToken {
    ip: ClientIp,
}

#[async_trait::async_trait]
impl<'a> FromRequestParts<'a> for AdminToken {
    async fn from_request_parts(req: RequestPartsRef<'a>) -> Result<Self> {
        let ip = ClientIp::from_request_parts(req).await?;

        if CONFIG.advanced.disable_admin_token {
            return Ok(Self {
                ip,
            });
        }
        let mut cookies = CookieJar::from_request_parts(req).await?;

        let access_token = match cookies.get(COOKIE_NAME) {
            Some(cookie) => cookie.value(),
            None => {
                //TODO: requested_page?
                // let requested_page = req.headers.get(":path").and_then(|x| x.to_str().ok()).unwrap_or("/");
                // When the requested page is empty, it is `/admin`, in that case, Forward, so it will render the login page
                // Else, return a 401 failure, which will be caught
                return Err(Error::RedirectUrl(RedirectMode::TemporaryRedirect, admin_path()));
            }
        };

        if decode_admin(access_token).is_err() {
            // Remove admin cookie
            cookies = cookies.remove(Cookie::build(COOKIE_NAME, "").path(admin_path().to_string()).finish());
            error!("Invalid or expired admin JWT. IP: {}.", &ip.ip);
            return Err(Error::response((cookies, admin_path())));
        }

        Ok(Self {
            ip,
        })
    }
}
