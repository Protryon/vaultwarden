use std::borrow::Cow;
use std::net::SocketAddr;
use std::path::{Path, PathBuf};

use always_cell::AlwaysCell;
use indexmap::IndexSet;
use ipnetwork::IpNetwork;
use job_scheduler_ng::Schedule;
use log::warn;
use regex::Regex;
use reqwest::Url;
use serde::{Deserialize, Serialize};
use serde_with::{serde_as, DisplayFromStr};

use anyhow::{bail, Result};

pub static CONFIG: AlwaysCell<Config> = AlwaysCell::new();

#[derive(Serialize, Deserialize)]
pub struct Config {
    pub db: DbConfig,
    #[serde(flatten)]
    pub settings: SettingsConfig,
    #[serde(flatten)]
    pub advanced: AdvancedConfig,
    #[serde(flatten)]
    pub folders: FolderConfig,
    pub push: Option<PushConfig>,
    #[serde(default)]
    pub jobs: JobsConfig,
    pub sso: Option<SsoConfig>,
    pub yubico: Option<YubicoConfig>,
    pub duo: Option<DuoConfig>,
    pub smtp: Option<SmtpConfig>,
    pub email_2fa: Option<Email2FaConfig>,
}

fn default_port() -> u16 {
    5432
}

fn default_database() -> String {
    "vaultwarden".to_string()
}

#[derive(Serialize, Deserialize)]
pub struct DbConfig {
    pub host: String,
    #[serde(default = "default_port")]
    pub port: u16,
    #[serde(default = "default_database")]
    pub database: String,
    pub username: String,
    pub password: String,
}

#[derive(Serialize, Deserialize)]
pub struct FolderConfig {
    ///  Data folder |> Main data folder
    pub data: PathBuf,
    /// Icon cache folder
    pub icon_cache: Option<PathBuf>,
    /// Attachments folder
    pub attachments: Option<PathBuf>,
    /// Sends folder
    pub sends: Option<PathBuf>,
    /// Temp folder |> Used for storing temporary file uploads
    pub tmp: Option<PathBuf>,
    /// Templates folder
    pub templates: Option<PathBuf>,
    /// Session JWT key
    pub rsa_key: Option<PathBuf>,
    /// Web vault folder
    pub web_vault: Option<PathBuf>,
}

impl FolderConfig {
    pub fn web_vault(&self) -> &Path {
        self.web_vault.as_deref().unwrap_or_else(|| Path::new("web-vault/"))
    }

    pub fn icon_cache(&self) -> Cow<'_, Path> {
        self.icon_cache.as_deref().map(Cow::Borrowed).unwrap_or_else(|| Cow::Owned(self.data.join("icon_cache")))
    }

    pub fn attachments(&self) -> Cow<'_, Path> {
        self.attachments.as_deref().map(Cow::Borrowed).unwrap_or_else(|| Cow::Owned(self.data.join("attachments")))
    }

    pub fn sends(&self) -> Cow<'_, Path> {
        self.sends.as_deref().map(Cow::Borrowed).unwrap_or_else(|| Cow::Owned(self.data.join("sends")))
    }

    pub fn tmp(&self) -> Cow<'_, Path> {
        self.tmp.as_deref().map(Cow::Borrowed).unwrap_or_else(|| Cow::Owned(self.data.join("tmp")))
    }

    pub fn templates(&self) -> Cow<'_, Path> {
        self.templates.as_deref().map(Cow::Borrowed).unwrap_or_else(|| Cow::Owned(self.data.join("templates")))
    }

    pub fn rsa_key(&self) -> Cow<'_, Path> {
        self.rsa_key.as_deref().map(Cow::Borrowed).unwrap_or_else(|| Cow::Owned(self.data.join("rsa_key")))
    }
}

fn default_push_relay_uri() -> Url {
    "https://push.bitwarden.com".parse().unwrap()
}

#[derive(Serialize, Deserialize)]
pub struct PushConfig {
    /// Push relay base uri
    #[serde(default = "default_push_relay_uri")]
    pub relay_uri: Url,
    /// Installation id |> The installation id from https://bitwarden.com/host
    pub installation_id: String,
    /// Installation key |> The installation key from https://bitwarden.com/host
    pub installation_key: String,
}

fn default_job_poll_interval_ms() -> u64 {
    30000
}

fn default_send_purge_schedule() -> Schedule {
    "0 5 * * * *".parse().unwrap()
}

fn default_trash_purge_schedule() -> Schedule {
    "0 5 0 * * *".parse().unwrap()
}

fn default_incomplete_2fa_schedule() -> Schedule {
    "30 * * * * *".parse().unwrap()
}

fn default_emergency_notification_reminder_schedule() -> Schedule {
    "0 3 * * * *".parse().unwrap()
}

fn default_emergency_request_timeout_schedule() -> Schedule {
    "0 7 * * * *".parse().unwrap()
}

fn default_event_cleanup_schedule() -> Schedule {
    "0 10 0 * * *".parse().unwrap()
}

#[serde_as]
#[derive(Serialize, Deserialize)]
pub struct JobsConfig {
    /// Job scheduler poll interval |> How often the job scheduler thread checks for jobs to run.
    /// Set to 0 to globally disable scheduled jobs.
    #[serde(default = "default_job_poll_interval_ms")]
    pub job_poll_interval_ms: u64,
    /// Send purge schedule |> Cron schedule of the job that checks for Sends past their deletion date.
    /// Defaults to hourly. Set blank to disable this job.
    #[serde(default = "default_send_purge_schedule")]
    #[serde_as(as = "DisplayFromStr")]
    pub send_purge_schedule: Schedule,
    /// Trash purge schedule |> Cron schedule of the job that checks for trashed items to delete permanently.
    /// Defaults to daily. Set blank to disable this job.
    #[serde(default = "default_trash_purge_schedule")]
    #[serde_as(as = "DisplayFromStr")]
    pub trash_purge_schedule: Schedule,
    /// Incomplete 2FA login schedule |> Cron schedule of the job that checks for incomplete 2FA logins.
    /// Defaults to once every minute. Set blank to disable this job.
    #[serde(default = "default_incomplete_2fa_schedule")]
    #[serde_as(as = "DisplayFromStr")]
    pub incomplete_2fa_schedule: Schedule,
    /// Emergency notification reminder schedule |> Cron schedule of the job that sends expiration reminders to emergency access grantors.
    /// Defaults to hourly. (3 minutes after the hour) Set blank to disable this job.
    #[serde(default = "default_emergency_notification_reminder_schedule")]
    #[serde_as(as = "DisplayFromStr")]
    pub emergency_notification_reminder_schedule: Schedule,
    /// Send purge schedule |> Cron schedule of the job that checks for Sends past their deletion date.
    /// Defaults to hourly. Set blank to disable this job.
    #[serde(default = "default_emergency_request_timeout_schedule")]
    #[serde_as(as = "DisplayFromStr")]
    pub emergency_request_timeout_schedule: Schedule,
    /// Event cleanup schedule |> Cron schedule of the job that cleans old events from the event table.
    /// Defaults to daily. Set blank to disable this job.
    #[serde(default = "default_event_cleanup_schedule")]
    #[serde_as(as = "DisplayFromStr")]
    pub event_cleanup_schedule: Schedule,
}

impl Default for JobsConfig {
    fn default() -> Self {
        Self {
            job_poll_interval_ms: default_job_poll_interval_ms(),
            send_purge_schedule: default_send_purge_schedule(),
            trash_purge_schedule: default_trash_purge_schedule(),
            incomplete_2fa_schedule: default_incomplete_2fa_schedule(),
            emergency_notification_reminder_schedule: default_emergency_notification_reminder_schedule(),
            emergency_request_timeout_schedule: default_emergency_request_timeout_schedule(),
            event_cleanup_schedule: default_event_cleanup_schedule(),
        }
    }
}

fn default_public() -> Url {
    "http://localhost:8080/".parse().unwrap()
}

fn default_true() -> bool {
    true
}

fn default_int<T: TryFrom<i64>, const I: i64>() -> T {
    match I.try_into() {
        Ok(x) => x,
        Err(_) => panic!("invalid default int"),
    }
}

fn default_invitation_org_name() -> String {
    "Vaultwarden".to_string()
}

#[derive(Serialize, Deserialize)]
pub struct SettingsConfig {
    /// API bind address |> Usually 0.0.0.0:8080
    pub api_bind: SocketAddr,
    /// Domain URL |> This needs to be set to the URL used to access the server, including 'http[s]://'
    /// and port, if it's different than the default. Some server functions don't work correctly without this value
    #[serde(default = "default_public")]
    pub public: Url,
    /// Enable web vault
    #[serde(default = "default_true")]
    pub web_vault_enabled: bool,
    /// Allow Sends |> Controls whether users are allowed to create Bitwarden Sends.
    /// This setting applies globally to all users. To control this on a per-org basis instead, use the "Disable Send" org policy.
    #[serde(default = "default_true")]
    pub sends_allowed: bool,
    /// HIBP Api Key |> HaveIBeenPwned API Key, request it here: https://haveibeenpwned.com/API/Key
    pub hibp_api_key: Option<String>,
    /// Per-user attachment storage limit (KB) |> Max kilobytes of attachment storage allowed per user. When this limit is reached, the user will not be allowed to upload further attachments.
    pub user_attachment_limit: Option<i64>,
    /// Per-organization attachment storage limit (KB) |> Max kilobytes of attachment storage allowed per org. When this limit is reached, org members will not be allowed to upload further attachments for ciphers owned by that org.
    pub org_attachment_limit: Option<i64>,
    /// Trash auto-delete days |> Number of days to wait before auto-deleting a trashed item.
    /// If unset, trashed items are not auto-deleted. This setting applies globally, so make
    /// sure to inform all users of any changes to this setting.
    pub trash_auto_delete_days: Option<i64>,
    /// Incomplete 2FA time limit |> Number of minutes to wait before a 2FA-enabled login is
    /// considered incomplete, resulting in an email notification. An incomplete 2FA login is one
    /// where the correct master password was provided but the required 2FA step was not completed,
    /// which potentially indicates a master password compromise. Set to 0 to disable this check.
    /// This setting applies globally to all users.
    #[serde(default = "default_int::<_, 3>")]
    pub incomplete_2fa_time_limit: i64,
    /// Disable icon downloads |> Set to true to disable icon downloading in the internal icon service.
    /// This still serves existing icons from $ICON_CACHE_FOLDER, without generating any external
    /// network requests. $ICON_CACHE_TTL must also be set to 0; otherwise, the existing icons
    /// will be deleted eventually, but won't be downloaded again.
    #[serde(default)]
    pub disable_icon_download: bool,
    /// Allow new signups |> Controls whether new users can register. Users can be invited by the vaultwarden admin even if this is disabled
    #[serde(default = "default_true")]
    pub signups_allowed: bool,
    /// Require email verification on signups. This will prevent logins from succeeding until the address has been verified
    #[serde(default)]
    pub signups_verify: bool,
    /// If signups require email verification, automatically re-send verification email if it hasn't been sent for a while (in seconds)
    #[serde(default = "default_int::<_, 3600>")]
    pub signups_verify_resend_time: u64,
    /// If signups require email verification, limit how many emails are automatically sent when login is attempted (0 means no limit)
    #[serde(default = "default_int::<_, 6>")]
    pub signups_verify_resend_limit: u32,
    /// Email domain whitelist |> Allow signups only from this list of domains, even when signups are otherwise disabled
    #[serde(default)]
    pub signups_domains_whitelist: IndexSet<String>,
    /// Enable event logging |> Enables event logging for organizations.
    #[serde(default = "default_true")]
    pub org_events_enabled: bool,
    /// Org creation users |> Allow org creation only by this list of user emails.
    /// Blank or 'all' means all users can create orgs; 'none' means no users can create orgs.
    #[serde(default)]
    pub org_creation_users: IndexSet<String>,
    /// Allow invitations |> Controls whether users can be invited by organization admins, even when signups are otherwise disabled
    #[serde(default = "default_true")]
    pub invitations_allowed: bool,
    /// Invitation token expiration time (in hours) |> The number of hours after which an organization invite token, emergency access invite token,
    /// email verification token and deletion request token will expire (must be at least 1)
    #[serde(default = "default_int::<_, 120>")]
    pub invitation_expiration_hours: u32,
    /// Allow emergency access |> Controls whether users can enable emergency access to their accounts. This setting applies globally to all users.
    #[serde(default = "default_true")]
    pub emergency_access_allowed: bool,
    /// Password iterations |> Number of server-side passwords hashing iterations for the password hash.
    /// The default for new users. If changed, it will be updated during login for existing users.
    #[serde(default = "default_int::<_, 600000>")]
    pub password_iterations: i32,
    /// Allow password hints |> Controls whether users can set password hints. This setting applies globally to all users.
    #[serde(default = "default_true")]
    pub password_hints_allowed: bool,
    /// Show password hint |> Controls whether a password hint should be shown directly in the web page
    /// if SMTP service is not configured. Not recommended for publicly-accessible instances as this
    /// provides unauthenticated access to potentially sensitive data.
    #[serde(default)]
    pub show_password_hint: bool,
    /// Admin token/Argon2 PHC |> The plain text token or Argon2 PHC string used to authenticate in this very same page. Changing it here will not deauthorize the current session!
    pub admin_token: Option<String>,
    /// Invitation organization name |> Name shown in the invitation emails that don't come from a specific organization
    #[serde(default = "default_invitation_org_name")]
    pub invitation_org_name: String,
    /// Events days retain |> Number of days to retain events stored in the database. If unset, events are kept indefently.
    pub events_days_retain: Option<i64>,
}

fn default_ip_header() -> String {
    "X-Real-IP".to_string()
}

#[derive(Serialize, Deserialize, Default, Clone, Copy, strum::Display)]
#[serde(rename_all = "snake_case")]
#[strum(serialize_all = "snake_case")]
pub enum IconService {
    #[default]
    Internal,
    Bitwarden,
    Duckduckgo,
    Google,
}

impl IconService {
    pub fn url(&self) -> &'static str {
        match self {
            IconService::Internal => "",
            IconService::Bitwarden => "https://icons.bitwarden.net/{}/icon.png",
            IconService::Duckduckgo => "https://icons.duckduckgo.com/ip3/{}.ico",
            IconService::Google => "https://www.google.com/s2/favicons?domain={}&sz=32",
        }
    }
}

fn default_log_level() -> String {
    "info".to_string()
}

#[serde_as]
#[derive(Serialize, Deserialize)]
pub struct AdvancedConfig {
    /// Client IP header |> Set to empty string to just use remote IP.
    #[serde(default = "default_ip_header")]
    pub ip_header: String,
    /// Icon service |> The predefined icon services are: internal, bitwarden, duckduckgo, google.
    /// To specify a custom icon service, set a URL template with exactly one instance of `{}`,
    /// which is replaced with the domain. For example: `https://icon.example.com/domain/{}`.
    /// `internal` refers to Vaultwarden's built-in icon fetching implementation. If an external
    /// service is set, an icon request to Vaultwarden will return an HTTP redirect to the
    /// corresponding icon at the external service.
    #[serde(default)]
    pub icon_service: IconService,
    /// Icon redirect code |> The HTTP status code to use for redirects to an external icon service.
    /// The supported codes are 301 (legacy permanent), 302 (legacy temporary), 307 (temporary), and 308 (permanent).
    /// Temporary redirects are useful while testing different icon services, but once a service
    /// has been decided on, consider using permanent redirects for cacheability. The legacy codes
    /// are currently better supported by the Bitwarden clients.
    #[serde(default = "default_int::<_, 302>")]
    pub icon_redirect_code: u32,
    /// Positive icon cache expiry |> Number of seconds to consider that an already cached icon is fresh. After this period, the icon will be redownloaded
    #[serde(default = "default_int::<_, 2592000>")]
    pub icon_cache_ttl: u64,
    /// Negative icon cache expiry |> Number of seconds before trying to download an icon that failed again.
    #[serde(default = "default_int::<_, 259200>")]
    pub icon_cache_negttl: u64,
    /// Icon download timeout |> Number of seconds when to stop attempting to download an icon.
    #[serde(default = "default_int::<_, 10>")]
    pub icon_download_timeout: u64,
    /// Icon blacklist regex |> Any domains that match this regex won't be fetched by the icon service.
    /// Useful to hide other servers in the local network. Check the WIKI for more details
    #[serde(default)]
    #[serde_as(as = "Option<DisplayFromStr>")]
    pub icon_blacklist_regex: Option<Regex>,
    /// Icon blacklist IPs |> Any ips that match any of these CIDRs won't be fetched by the icon service.
    /// Useful to hide other servers in the local network. Check the WIKI for more etails
    #[serde(default)]
    pub icon_blacklist_ips: Vec<IpNetwork>,
    /// Disable Two-Factor remember |> Enabling this would force the users to use a second factor to login every time.
    /// Note that the checkbox would still be present, but ignored.
    #[serde(default)]
    pub disable_2fa_remember: bool,
    /// Disable authenticator time drifted codes to be valid |> Enabling this only allows the current TOTP code to be valid
    /// TOTP codes of the previous and next 30 seconds will be invalid.
    #[serde(default)]
    pub authenticator_disable_time_drift: bool,
    /// Require new device emails |> When a user logs in an email is required to be sent.
    /// If sending the email fails the login attempt will fail.
    #[serde(default)]
    pub require_device_email: bool,
    /// Reload templates (Dev) |> When this is set to true, the templates get reloaded with every request.
    /// ONLY use this during development, as it can slow down the server
    #[serde(default)]
    pub reload_templates: bool,
    /// Log level
    #[serde(default = "default_log_level")]
    pub log_level: String,
    /// Enable DB WAL |> Turning this off might lead to worse performance, but might help if using vaultwarden on some exotic filesystems,
    /// that do not support WAL. Please make sure you read project wiki on the topic before changing this setting.
    #[serde(default = "default_true")]
    pub enable_db_wal: bool,
    /// Max database connection retries |> Number of times to retry the database connection during startup, with 1 second between each retry, set to 0 to retry indefinitely
    #[serde(default = "default_int::<_, 15>")]
    pub database_connection_retries: u32,
    /// Timeout (seconds) when aquiring database connection
    #[serde(default = "default_int::<_, 30>")]
    pub database_timeout: u64,
    /// Database connection pool size
    #[serde(default = "default_int::<_, 10>")]
    pub database_max_conns: u32,
    /// Bypass admin page security (Know the risks!) |> Disables the Admin Token for the admin page so you may use your own auth in-front
    #[serde(default)]
    pub disable_admin_token: bool,
    /// Allowed iframe ancestors (Know the risks!) |> Allows other domains to embed the web vault into an iframe, useful for embedding into secure intranets
    #[serde(default)]
    pub allowed_iframe_ancestors: String,
    /// Seconds between login requests |> Number of seconds, on average, between login and 2FA requests from the same IP address before rate limiting kicks in
    #[serde(default = "default_int::<_, 60>")]
    pub login_ratelimit_seconds: u64,
    /// Max burst size for login requests |> Allow a burst of requests of up to this size, while maintaining the average indicated by `login_ratelimit_seconds`. Note that this applies to both the login and the 2FA, so it's recommended to allow a burst size of at least 2
    #[serde(default = "default_int::<_, 10>")]
    pub login_ratelimit_max_burst: u32,
    /// Seconds between admin login requests |> Number of seconds, on average, between admin requests from the same IP address before rate limiting kicks in
    #[serde(default = "default_int::<_, 300>")]
    pub admin_ratelimit_seconds: u64,
    /// Max burst size for admin login requests |> Allow a burst of requests of up to this size, while maintaining the average indicated by `admin_ratelimit_seconds`
    #[serde(default = "default_int::<_, 3>")]
    pub admin_ratelimit_max_burst: u32,
    /// Admin session lifetime |> Set the lifetime of admin sessions to this value (in minutes).
    #[serde(default = "default_int::<_, 20>")]
    pub admin_session_lifetime: i64,
    /// Enable groups |> Enables groups support for organizations.
    #[serde(default = "default_true")]
    pub org_groups_enabled: bool,
}

#[derive(Serialize, Deserialize)]
pub struct SsoConfig {
    /// Force SSO login
    #[serde(default)]
    pub force_sso: bool,
    /// Client ID
    #[serde(default)]
    pub client_id: String,
    /// Client Secret
    #[serde(default)]
    pub client_secret: String,
    #[serde(default)]
    pub authority: String,
    //TODO: oidc discovery url?
    /// Override callback url
    pub sso_callback_url: Option<Url>,
    /// Allow workaround so SSO logins accept all invites
    #[serde(default)]
    pub sso_acceptall_invites: bool,
}

#[derive(Serialize, Deserialize)]
pub struct YubicoConfig {
    /// Client ID
    pub client_id: String,
    /// Secret Key
    pub secret_key: String,
    /// Yubico server
    pub server: Option<Url>,
}

#[derive(Serialize, Deserialize)]
pub struct DuoConfig {
    /// Integration ID
    pub integration_key: String,
    /// Secret Key
    pub secret_key: String,
    /// Duo server
    pub server: Url,
    /// Unique ID for app
    pub app_key: String,
}

#[derive(Serialize, Deserialize, Default, Clone, Copy, PartialEq, Eq, strum::Display)]
#[serde(rename_all = "snake_case")]
#[strum(serialize_all = "snake_case")]
pub enum SmtpSecurity {
    Off,
    #[default]
    Starttls,
    ForceTls,
}

fn default_from_name() -> String {
    "Vaultwarden".to_string()
}

#[derive(Serialize, Deserialize)]
pub struct SmtpConfig {
    /// Host name |> Host name of SMTP server, must not include port.
    pub host: String,
    /// Secure SMTP |> ("starttls", "force_tls", "off") Enable a secure connection. Default is "starttls" (Explicit - ports 587 or 25), "force_tls" (Implicit - port 465) or "off", no encryption
    #[serde(default)]
    pub security: SmtpSecurity,
    /// Port |> derived from 'security' if not specified
    #[serde(default)]
    pub port: Option<u16>,
    /// From Address |> Originating email address
    pub from_address: String,
    /// From Name |> Name attached to email
    #[serde(default = "default_from_name")]
    pub from_name: String,
    /// SMTP Username |> SMTP Username. Optional.
    pub username: Option<String>,
    /// SMTP Password |> SMTP Password. Optional.
    pub password: Option<String>,
    /// SMTP connection timeout |> Number of seconds when to stop trying to connect to the SMTP server
    #[serde(default = "default_int::<_, 15>")]
    pub timeout: u64,
    /// Server name sent during HELO |> By default this value should be is on the machine's hostname, but might need to be changed in case it trips some anti-spam filters
    pub helo_name: Option<String>,
    /// Embed images as email attachments. |> True by default.
    #[serde(default = "default_true")]
    pub embed_images: bool,
    /// Enable SMTP debugging (Know the risks!) |> DANGEROUS: Enabling this will output very detailed SMTP messages. This could contain sensitive information like passwords and usernames! Only enable this during troubleshooting!
    #[serde(default)]
    pub debug: bool,
    /// Accept Invalid Certs (Know the risks!) |> DANGEROUS: Allow invalid certificates. This option introduces significant vulnerabilities to man-in-the-middle attacks!
    #[serde(default)]
    pub accept_invalid_certs: bool,
    /// Accept Invalid Hostnames (Know the risks!) |> DANGEROUS: Allow invalid hostnames. This option introduces significant vulnerabilities to man-in-the-middle attacks!
    #[serde(default)]
    pub accept_invalid_hostnames: bool,
}

#[derive(Serialize, Deserialize)]
pub struct Email2FaConfig {
    /// Email token size |> Number of digits in an email 2FA token (min: 6, max: 255). Note that the Bitwarden clients are hardcoded to mention 6 digit codes regardless of this setting.
    #[serde(default = "default_int::<_, 6>")]
    pub email_token_size: u8,
    /// Token expiration time |> Maximum time in seconds a token is valid. The time the user has to open email client and copy token.
    #[serde(default = "default_int::<_, 600>")]
    pub email_expiration_time: u64,
    /// Maximum attempts |> Maximum attempts before an email token is reset and a new email will need to be sent
    #[serde(default = "default_int::<_, 3>")]
    pub email_attempts_limit: u64,
}

fn validate_config(config: &Config) -> Result<()> {
    if config.settings.password_iterations < 100_000 {
        bail!("PASSWORD_ITERATIONS should be at least 100000 or higher. The default is 600000!");
    }

    let limit = 256;
    if config.advanced.database_max_conns < 1 || config.advanced.database_max_conns > limit {
        bail!(format!("`DATABASE_MAX_CONNS` contains an invalid value. Ensure it is between 1 and {limit}.",));
    }

    if let Some(ref token) = config.settings.admin_token {
        if token.trim().is_empty() && !config.advanced.disable_admin_token {
            eprintln!("[WARNING] `ADMIN_TOKEN` is enabled but has an empty value, so the admin page will be disabled.");
            eprintln!("[WARNING] To enable the admin page without a token, use `DISABLE_ADMIN_TOKEN`.");
        }
    }

    if let Some(smtp) = &config.smtp {
        if !smtp.from_address.contains('@') {
            bail!("SMTP_FROM does not contain a mandatory @ sign");
        }
    }

    if let Some(email_2fa) = &config.email_2fa {
        if email_2fa.email_token_size < 6 {
            bail!("`EMAIL_TOKEN_SIZE` has a minimum size of 6");
        }
        if config.smtp.is_none() {
            bail!("To enable email 2FA, a mail transport must be configured");
        }
    }

    // Check if the icon redirect code is valid
    match config.advanced.icon_redirect_code {
        301 | 302 | 307 | 308 => (),
        _ => bail!("Only HTTP 301/302 and 307/308 redirects are supported"),
    }

    if config.settings.invitation_expiration_hours < 1 {
        bail!("`INVITATION_EXPIRATION_HOURS` has a minimum duration of 1 hour")
    }

    if !config.advanced.disable_admin_token {
        match config.settings.admin_token.as_ref() {
            Some(t) if t.starts_with("$argon2") => {
                if let Err(e) = argon2::password_hash::PasswordHash::new(t) {
                    bail!(format!("The configured Argon2 PHC in `ADMIN_TOKEN` is invalid: '{e}'"))
                }
            }
            Some(_) => {
                eprintln!(
                    "[NOTICE] You are using a plain text `ADMIN_TOKEN` which is insecure.\n\
                Please generate a secure Argon2 PHC string by using `vaultwarden hash` or `argon2`.\n\
                See: https://github.com/dani-garcia/vaultwarden/wiki/Enabling-admin-page#secure-the-admin_token\n"
                );
            }
            _ => {}
        }
    }
    Ok(())
}

fn generate_smtp_img_src(embed_images: bool, domain: &str) -> String {
    if embed_images {
        "cid:".to_string()
    } else {
        format!("{domain}/vw_static/")
    }
}

fn generate_sso_callback_url(mut url: Url) -> Url {
    url.path_segments_mut().unwrap().push("identity");
    url.path_segments_mut().unwrap().push("connect");
    url.path_segments_mut().unwrap().push("oidc-signin");
    url
}

/// Generate the CSP string needed to allow redirected icon fetching
fn generate_icon_service_csp(icon_service: IconService) -> String {
    // We split on the first '{', since that is the variable delimiter for an icon service URL.
    // Everything up until the first '{' should be fixed and can be used as an CSP string.
    let csp_string = match icon_service.url().split_once('{') {
        Some((c, _)) => c.to_string(),
        None => String::new(),
    };

    // Because Google does a second redirect to there gstatic.com domain, we need to add an extra csp string.
    match icon_service {
        IconService::Google => csp_string + " https://*.gstatic.com/favicon",
        _ => csp_string,
    }
}

pub static ICON_SERVICE_CSP: AlwaysCell<String> = AlwaysCell::new();
pub static SMTP_IMAGE_SRC: AlwaysCell<String> = AlwaysCell::new();
pub static SSO_CALLBACK_URL: AlwaysCell<Url> = AlwaysCell::new();

pub async fn load() -> Result<()> {
    let path = std::env::var("VAULTWARDEN_CONF").unwrap_or_default();
    let path = if path.is_empty() {
        "./config.yaml".to_string()
    } else {
        path
    };
    let config: Config = serde_yaml::from_str(&tokio::fs::read_to_string(&path).await?)?;
    validate_config(&config)?;

    AlwaysCell::set(&ICON_SERVICE_CSP, generate_icon_service_csp(config.advanced.icon_service));
    AlwaysCell::set(&SMTP_IMAGE_SRC, generate_smtp_img_src(config.smtp.as_ref().map(|x| x.embed_images).unwrap_or_default(), &config.settings.public.as_str()));
    AlwaysCell::set(
        &SSO_CALLBACK_URL,
        config.sso.as_ref().and_then(|x| x.sso_callback_url.clone()).unwrap_or_else(|| generate_sso_callback_url(config.settings.public.clone())),
    );
    AlwaysCell::set(&CONFIG, config);

    Ok(())
}

impl Config {
    /// Tests whether an email's domain is allowed. A domain is allowed if it
    /// is in signups_domains_whitelist, or if no whitelist is set (so there
    /// are no domain restrictions in effect).
    pub fn is_email_domain_allowed(&self, email: &str) -> bool {
        let e: Vec<&str> = email.rsplitn(2, '@').collect();
        if e.len() != 2 || e[0].is_empty() || e[1].is_empty() {
            warn!("Failed to parse email address '{}'", email);
            return false;
        }
        let email_domain = e[0].to_ascii_lowercase();

        self.settings.signups_domains_whitelist.is_empty() || self.settings.signups_domains_whitelist.contains(&email_domain)
    }

    /// Tests whether signup is allowed for an email address, taking into
    /// account the signups_allowed and signups_domains_whitelist settings.
    pub fn is_signup_allowed(&self, email: &str) -> bool {
        if !self.settings.signups_domains_whitelist.is_empty() {
            // The whitelist setting overrides the signups_allowed setting.
            self.is_email_domain_allowed(email)
        } else {
            self.settings.signups_allowed
        }
    }

    /// Tests whether the specified user is allowed to create an organization.
    pub fn is_org_creation_allowed(&self, email: &str) -> bool {
        if self.settings.org_creation_users.is_empty() {
            true
        } else {
            self.settings.org_creation_users.contains(&email.to_ascii_lowercase())
        }
    }

    pub fn private_rsa_key(&self) -> String {
        format!("{}.pem", self.folders.rsa_key().display())
    }

    pub fn public_rsa_key(&self) -> String {
        format!("{}.pub.pem", self.folders.rsa_key().display())
    }

    pub fn mail_enabled(&self) -> bool {
        self.smtp.is_some()
    }

    /// Tests whether the admin token is set to a non-empty value.
    pub fn is_admin_token_set(&self) -> bool {
        self.settings.admin_token.is_some() && !self.settings.admin_token.as_deref().unwrap().trim().is_empty()
    }
}
