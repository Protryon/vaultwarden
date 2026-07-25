use axol::{Cookie, CookieJar, Form, prelude::*};
use chrono::Utc;
use log::{error, info};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};

use std::future::Future;
use std::pin::Pin;

use openidconnect::core::{
    CoreAuthDisplay, CoreAuthPrompt, CoreClient, CoreErrorResponseType, CoreGenderClaim, CoreJsonWebKey, CoreJweContentEncryptionAlgorithm,
    CoreProviderMetadata, CoreResponseType, CoreRevocableToken, CoreRevocationErrorResponse, CoreTokenIntrospectionResponse, CoreTokenResponse,
    CoreUserInfoClaims,
};
use openidconnect::{
    AccessToken, AsyncHttpClient, AuthenticationFlow, AuthorizationCode, ClientId, ClientSecret, CsrfToken, EmptyAdditionalClaims, EndpointNotSet, EndpointSet,
    HttpClientError, HttpRequest, HttpResponse, IssuerUrl, Nonce, OAuth2TokenResponse, RedirectUrl, Scope, StandardErrorResponse,
};
use url::Url;
use uuid::Uuid;

use crate::api::core::two_factor::email::{self, EmailTokenData};
use crate::api::core::two_factor::{duo, yubikey};
use crate::config::SSO_CALLBACK_URL;
use crate::db::{AuthRequest, Event, OrgPolicyType, OrganizationPolicy, SsoNonce};
use crate::{
    // util::{CookieManager, CustomRedirect},
    CONFIG,
    auth::{ClientHeaders, ClientIp, encode_jwt, generate_organization_api_key_login_claims, generate_ssotoken_claims},
    db::{Conn, DB, Device, EventType, Organization, OrganizationApiKey, TwoFactor, TwoFactorIncomplete, TwoFactorType, User, UserOrgStatus, UserOrganization},
    error::MapResult,
    events::log_user_event,
    mail,
    util,
};

use super::core::accounts::{prelogin, register, register_send_verification_email};

//todo: make this not panicky

pub fn route() -> Router {
    Router::new()
        .post("/connect/token", login)
        .post("/accounts/prelogin", prelogin)
        // Newer clients (web-vault) hit the /password suffix; same handler.
        .post("/accounts/prelogin/password", prelogin)
        .post("/accounts/register", register)
        .post("/accounts/register/finish", register)
        .post("/accounts/register/send-verification-email", register_send_verification_email)
        .get("/account/prevalidate", prevalidate)
        .get("/connect/oidc-signin", oidc_signin)
        .get("/connect/authorize", authorize)
}

async fn login(client_header: ClientHeaders, data: Form<ConnectData>) -> Result<Json<Value>> {
    let data = data.0;

    let mut conn = DB.get().await.ise()?;

    let mut user_uuid: Option<Uuid> = None;

    let login_result = match data.grant_type.as_ref() {
        "refresh_token" => {
            check_is_some(&data.refresh_token, "refresh_token cannot be blank")?;
            refresh_login(data, &conn).await
        }
        "password" => {
            check_is_some(&data.client_id, "client_id cannot be blank")?;
            check_is_some(&data.password, "password cannot be blank")?;
            check_is_some(&data.scope, "scope cannot be blank")?;
            check_is_some(&data.username, "username cannot be blank")?;

            check_is_some(&data.device_identifier, "device_identifier cannot be blank")?;
            check_is_some(&data.device_name, "device_name cannot be blank")?;
            check_is_some(&data.device_type, "device_type cannot be blank")?;

            password_login(data, &mut user_uuid, &conn, &client_header.ip).await
        }
        "client_credentials" => {
            check_is_some(&data.client_id, "client_id cannot be blank")?;
            check_is_some(&data.client_secret, "client_secret cannot be blank")?;
            check_is_some(&data.scope, "scope cannot be blank")?;

            check_is_some(&data.device_identifier, "device_identifier cannot be blank")?;
            check_is_some(&data.device_name, "device_name cannot be blank")?;
            check_is_some(&data.device_type, "device_type cannot be blank")?;

            api_key_login(data, &mut user_uuid, &conn, &client_header.ip).await
        }
        "authorization_code" => {
            check_is_some(&data.client_id, "client_id cannot be blank")?;
            check_is_some(&data.code, "code cannot be blank")?;

            check_is_some(&data.device_identifier, "device_identifier cannot be blank")?;
            check_is_some(&data.device_name, "device_name cannot be blank")?;
            check_is_some(&data.device_type, "device_type cannot be blank")?;
            authorization_login(data, &mut user_uuid, &conn, &client_header.ip).await
        }
        t => err!("Invalid type", t),
    };

    if let Some(user_uuid) = user_uuid {
        match &login_result {
            Ok(_) => {
                tokio::spawn(async move {
                    if let Err(e) =
                        log_user_event(EventType::UserLoggedIn, user_uuid, client_header.device_type, Utc::now(), client_header.ip.ip, &mut conn).await
                    {
                        error!("failed to write user login event: {e}");
                    }
                });
            }
            Err(e) => {
                // if let Some(ev) = e.get_event() {
                //     log_user_event(
                //         ev.event,
                //         user_uuid,
                //         client_header.device_type,
                //         Utc::now(),
                //         client_header.ip.ip,
                //         &mut conn,
                //     )
                //     .await?;
                // }
                //TODO:
                error!("unimplemented event tagged errors: {e}");
            }
        }
    }
    login_result
}

/// Build an OAuth-style error body. Clients key on `error == "invalid_grant"` (e.g. an
/// expired/invalid refresh token) to trigger a silent re-login instead of surfacing an error.
fn oauth_error(error: &str, description: &str) -> Error {
    Error::bad_request(Json(json!({
        "error": error,
        "error_description": description,
        "message": description,
        "object": "error",
    })))
}

async fn refresh_login(data: ConnectData, conn: &Conn) -> Result<Json<Value>> {
    // Extract token
    let token = data.refresh_token.unwrap();

    // Get device by refresh token
    let mut device = match Device::find_by_refresh_token(conn, &token).await? {
        Some(device) => device,
        None => return Err(oauth_error("invalid_grant", "The refresh token is invalid or has expired")),
    };

    let scope = "api offline_access";
    let scope_vec = vec!["api".into(), "offline_access".into()];

    // Common
    let user = User::get(conn, device.user_uuid).await?.unwrap();
    let orgs = UserOrganization::find_by_user_with_status(conn, user.uuid, UserOrgStatus::Confirmed).await?;
    let (access_token, expires_in) = device.refresh_tokens(&user, orgs, scope_vec);
    device.save(conn).await?;

    let mut result = json!({
        "access_token": access_token,
        "expires_in": expires_in,
        "token_type": "Bearer",
        "refresh_token": device.refresh_token,
        "scope": scope,
        "unofficialServer": true,
    });
    extend_object(&mut result, user_auth_response_fields(&user, conn).await?);

    Ok(Json(result))
}

#[derive(Debug, Serialize, Deserialize)]
struct TokenPayload {
    exp: i64,
    email: Option<String>,
    nonce: String,
}

async fn authorization_login(data: ConnectData, user_uuid: &mut Option<Uuid>, conn: &Conn, ip: &ClientIp) -> Result<Json<Value>> {
    let scope = data.scope.as_ref().unwrap();
    if scope != "api offline_access" {
        err!("Scope not supported")
    }

    let scope_vec = vec!["api".into(), "offline_access".into()];
    let code = data.code.as_ref().unwrap();

    let (refresh_token, id_token, userinfo) = match get_auth_code_access_token(code).await {
        Ok((refresh_token, id_token, userinfo)) => (refresh_token, id_token, userinfo),
        Err(err) => err!(err),
    };

    // We only read the (already provider-verified) id_token to extract the nonce; signature was checked during token exchange.
    let token = jsonwebtoken::dangerous::insecure_decode::<TokenPayload>(id_token.as_str()).unwrap().claims;

    // let expiry = token.exp;
    let nonce = token.nonce;
    let mut new_user = false;

    let Some(sso_nonce) = SsoNonce::get(conn, &nonce).await? else {
        err!("Invalid nonce");
    };
    sso_nonce.delete(conn).await?;

    // let expiry = token.exp;
    let user_email = match token.email {
        Some(email) => email,
        None => userinfo.email().unwrap().to_owned().to_string(),
    };
    let now = Utc::now();

    let mut user = match User::find_by_email(conn, &user_email).await? {
        Some(user) => user,
        None => {
            new_user = true;
            User::new(user_email.clone())
        }
    };

    if new_user {
        user.verified_at = Some(now);
        user.save(conn).await?;
    }

    // Set the user_uuid here to be passed back used for event logging.
    *user_uuid = Some(user.uuid);

    let (mut device, new_device) = get_device(&data, conn, &user).await?;

    let twofactor_token = twofactor_auth(user.uuid, &data, &mut device, ip, conn).await?;

    if CONFIG.mail_enabled() && new_device {
        if let Err(e) = mail::send_new_device_logged_in(&user.email, ip.ip, now, &device.name).await {
            error!("Error sending new device email: {:#?}", e);

            if CONFIG.advanced.require_device_email {
                err!("Could not send login notification email. Please contact your administrator.")
            }
        }
    }

    if CONFIG.sso.as_ref().map(|x| x.sso_acceptall_invites).unwrap_or_default() {
        for user_org in UserOrganization::find_by_user_with_status(conn, user.uuid, UserOrgStatus::Invited).await?.iter_mut() {
            user_org.status = UserOrgStatus::Accepted;
            user_org.save(conn).await?;
        }
    }

    device.refresh_token = refresh_token.clone();
    device.save(conn).await?;

    let orgs = UserOrganization::find_by_user_with_status(conn, user.uuid, UserOrgStatus::Confirmed).await?;
    let (access_token, expires_in) = device.refresh_tokens(&user, orgs, scope_vec);
    device.save(conn).await?;

    let mut result = json!({
        "access_token": access_token,
        "token_type": "Bearer",
        "refresh_token": device.refresh_token,
        "expires_in": expires_in,
        // "keyConnectorUrl": false,
        "scope": scope,
        "unofficialServer": true,
    });
    extend_object(&mut result, user_auth_response_fields(&user, conn).await?);

    if let Some(token) = twofactor_token {
        result["TwoFactorToken"] = Value::String(token);
    }

    info!("User {} logged in successfully. IP: {}", user.email, ip.ip);
    Ok(Json(result))
}

#[derive(Default, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
struct MasterPasswordPolicy {
    min_complexity: u8,
    min_length: u32,
    require_lower: bool,
    require_upper: bool,
    require_numbers: bool,
    require_special: bool,
    enforce_on_login: bool,
}

/// Insert every key of `extra` (a JSON object) into `base` (also a JSON object).
fn extend_object(base: &mut Value, extra: Value) {
    if let (Value::Object(b), Value::Object(e)) = (base, extra) {
        b.extend(e);
    }
}

/// The user-derived half of a successful `/connect/token` response: key material, KDF
/// params, master-password policy, account keys and `UserDecryptionOptions`. Shared by the
/// password, SSO, and API-key grants so their responses can't drift (Bitwarden emits the
/// same custom response for every grant).
async fn user_auth_response_fields(user: &User, conn: &Conn) -> Result<Value> {
    // Fetch all valid Master Password Policies and merge them into one with all true's and largest numbers as one policy
    let master_password_policies: Vec<MasterPasswordPolicy> =
        OrganizationPolicy::find_accepted_and_confirmed_by_user_and_active_policy(conn, user.uuid, OrgPolicyType::MasterPassword)
            .await?
            .into_iter()
            .filter_map(|p| serde_json::from_value(p.data).ok())
            .collect();

    let master_password_policy = if !master_password_policies.is_empty() {
        let mut mpp_json = json!(master_password_policies.into_iter().reduce(|acc, policy| {
            MasterPasswordPolicy {
                min_complexity: acc.min_complexity.max(policy.min_complexity),
                min_length: acc.min_length.max(policy.min_length),
                require_lower: acc.require_lower || policy.require_lower,
                require_upper: acc.require_upper || policy.require_upper,
                require_numbers: acc.require_numbers || policy.require_numbers,
                require_special: acc.require_special || policy.require_special,
                enforce_on_login: acc.enforce_on_login || policy.enforce_on_login,
            }
        }));
        mpp_json["object"] = json!("masterPasswordPolicy");
        mpp_json
    } else {
        json!({"object": "masterPasswordPolicy"})
    };

    let has_master_password = !user.password_hash.is_empty();
    let master_password_unlock = if has_master_password {
        json!({
            "Kdf": {
                "KdfType": user.client_kdf_type,
                "Iterations": user.client_kdf_iter,
                "Memory": user.client_kdf_memory,
                "Parallelism": user.client_kdf_parallelism
            },
            // This field is named inconsistently and will be removed and replaced by the "wrapped" variant in the apps.
            // https://github.com/bitwarden/android/blob/release/2025.12-rc41/network/src/main/kotlin/com/bitwarden/network/model/MasterPasswordUnlockDataJson.kt#L22-L26
            "MasterKeyEncryptedUserKey": user.akey,
            "MasterKeyWrappedUserKey": user.akey,
            "Salt": user.email
        })
    } else {
        Value::Null
    };

    let account_keys = user.account_keys_json();

    Ok(json!({
        "Key": user.akey,
        "PrivateKey": user.private_key,
        "Kdf": user.client_kdf_type,
        "KdfIterations": user.client_kdf_iter,
        "KdfMemory": user.client_kdf_memory,
        "KdfParallelism": user.client_kdf_parallelism,
        "ResetMasterPassword": !has_master_password,
        "ForcePasswordReset": user.force_password_reset,
        "MasterPasswordPolicy": master_password_policy,
        "AccountKeys": account_keys,
        "UserDecryptionOptions": {
            "HasMasterPassword": has_master_password,
            "MasterPasswordUnlock": master_password_unlock,
            "Object": "userDecryptionOptions"
        },
    }))
}

async fn password_login(data: ConnectData, user_uuid: &mut Option<Uuid>, conn: &Conn, ip: &ClientIp) -> Result<Json<Value>> {
    // Validate scope
    let scope = data.scope.as_ref().unwrap();
    if scope != "api offline_access" {
        err!("Scope not supported")
    }
    let scope_vec = vec!["api".into(), "offline_access".into()];

    // Ratelimit the login
    crate::ratelimit::check_limit_login(&ip.ip)?;

    if CONFIG.sso.as_ref().map(|x| x.force_sso).unwrap_or_default() {
        err!("SSO sign-in is required");
    }

    // Get the user
    let username = data.username.as_ref().unwrap().trim();
    let mut user = match User::find_by_email(conn, username).await? {
        Some(user) => user,
        None => err!("Username or password is incorrect. Try again", format!("IP: {}. Username: {}.", ip.ip, username)),
    };

    // Set the user_uuid here to be passed back used for event logging.
    *user_uuid = Some(user.uuid.clone());

    // Check password. With an auth request (login with device) we don't check the user's
    // password, but the access code of the approved auth request instead.
    let password = data.password.as_ref().unwrap();
    if let Some(auth_request_uuid) = data.auth_request {
        let Some(auth_request) = AuthRequest::find_by_uuid_and_user(conn, auth_request_uuid, user.uuid).await? else {
            Event::new(EventType::UserFailedLogIn, None).with_user_uuid(user.uuid).save(conn).await?;
            err!("Auth request not found. Try again.", format!("IP: {}. Username: {}.", ip.ip, username))
        };

        let request_expired = Utc::now() >= auth_request.creation_date + chrono::Duration::minutes(5);

        if auth_request.user_uuid != user.uuid
            || !auth_request.approved.unwrap_or(false)
            || request_expired
            || ip.ip.to_string() != auth_request.request_ip
            || !auth_request.check_access_code(password)
        {
            Event::new(EventType::UserFailedLogIn, None).with_user_uuid(user.uuid).save(conn).await?;
            err!("Username or access code is incorrect. Try again", format!("IP: {}. Username: {}.", ip.ip, username))
        }
    } else if !user.check_valid_password(password) {
        Event::new(EventType::UserFailedLogIn, None).with_user_uuid(user.uuid).save(conn).await?;
        err!("Username or password is incorrect. Try again", format!("IP: {}. Username: {}.", ip.ip, username))
    }

    // Change the KDF Iterations (only when not logging in with an auth request)
    if data.auth_request.is_none() && user.password_iterations != CONFIG.settings.password_iterations {
        user.password_iterations = CONFIG.settings.password_iterations;
        user.set_password(password, None, false, None, conn).await?;

        if let Err(e) = user.save(conn).await {
            error!("Error updating user: {:#?}", e);
        }
    }

    // Check if the user is disabled
    if !user.enabled {
        Event::new(EventType::UserFailedLogIn, None).with_user_uuid(user.uuid).save(conn).await?;
        err!("This user has been disabled", format!("IP: {}. Username: {}.", ip.ip, username))
    }

    let now = Utc::now();

    if user.verified_at.is_none() && CONFIG.mail_enabled() && CONFIG.settings.signups_verify {
        if user.last_verifying_at.is_none()
            || now.signed_duration_since(user.last_verifying_at.unwrap()).num_seconds() > CONFIG.settings.signups_verify_resend_time as i64
        {
            let resend_limit = CONFIG.settings.signups_verify_resend_limit as i32;
            if resend_limit == 0 || user.login_verify_count < resend_limit {
                // We want to send another email verification if we require signups to verify
                // their email address, and we haven't sent them a reminder in a while...
                user.last_verifying_at = Some(now);
                user.login_verify_count += 1;

                if let Err(e) = user.save(conn).await {
                    error!("Error updating user: {:#?}", e);
                }

                if let Err(e) = mail::send_verify_email(&user.email, user.uuid).await {
                    error!("Error auto-sending email verification email: {:#?}", e);
                }
            }
        }

        // We still want the login to fail until they actually verified the email address
        Event::new(EventType::UserFailedLogIn, None).with_user_uuid(user.uuid).save(conn).await?;
        err!("Please verify your email before trying again.", format!("IP: {}. Username: {}.", ip.ip, username))
    }

    let (mut device, new_device) = get_device(&data, conn, &user).await?;

    let twofactor_token = twofactor_auth(user.uuid, &data, &mut device, ip, conn).await?;

    if CONFIG.mail_enabled() && new_device {
        if let Err(e) = mail::send_new_device_logged_in(&user.email, ip.ip, now, &device.name).await {
            error!("Error sending new device email: {:#?}", e);

            if CONFIG.advanced.require_device_email {
                Event::new(EventType::UserFailedLogIn, None).with_user_uuid(user.uuid).save(conn).await?;
                err!("Could not send login notification email. Please contact your administrator.")
            }
        }
    }

    // Common
    let orgs = UserOrganization::find_by_user_with_status(conn, user.uuid, UserOrgStatus::Confirmed).await?;
    let (access_token, expires_in) = device.refresh_tokens(&user, orgs, scope_vec);
    device.save(conn).await?;

    let mut result = json!({
        "access_token": access_token,
        "expires_in": expires_in,
        "token_type": "Bearer",
        "refresh_token": device.refresh_token,
        "scope": scope,
        "unofficialServer": true,
    });
    extend_object(&mut result, user_auth_response_fields(&user, conn).await?);

    if let Some(token) = twofactor_token {
        result["TwoFactorToken"] = Value::String(token);
    }

    info!("User {} logged in successfully. IP: {}", username, ip.ip);
    Ok(Json(result))
}

async fn api_key_login(data: ConnectData, user_uuid: &mut Option<Uuid>, conn: &Conn, ip: &ClientIp) -> Result<Json<Value>> {
    // Ratelimit the login
    crate::ratelimit::check_limit_login(&ip.ip)?;

    // Validate scope
    match data.scope.as_ref().unwrap().as_ref() {
        "api" => user_api_key_login(data, user_uuid, conn, ip).await,
        "api.organization" => organization_api_key_login(data, conn, ip).await,
        _ => err!("Scope not supported"),
    }
}

async fn user_api_key_login(data: ConnectData, user_uuid: &mut Option<Uuid>, conn: &Conn, ip: &ClientIp) -> Result<Json<Value>> {
    // Get the user via the client_id
    let client_id = data.client_id.as_ref().unwrap();
    let client_user_uuid = match client_id.strip_prefix("user.").and_then(|x| Uuid::parse_str(x).ok()) {
        Some(uuid) => uuid,
        None => err!("Malformed client_id", format!("IP: {}.", ip.ip)),
    };
    let user = match User::get(conn, client_user_uuid).await? {
        Some(user) => user,
        None => err!("Invalid client_id", format!("IP: {}.", ip.ip)),
    };

    // Set the user_uuid here to be passed back used for event logging.
    *user_uuid = Some(user.uuid);

    // Check if the user is disabled
    if !user.enabled {
        Event::new(EventType::UserFailedLogIn, None).with_user_uuid(user.uuid).save(conn).await?;
        err!("This user has been disabled (API key login)", format!("IP: {}. Username: {}.", ip.ip, user.email))
    }

    // Check API key. Note that API key logins bypass 2FA.
    let client_secret = data.client_secret.as_ref().unwrap();
    if !user.check_valid_api_key(client_secret) {
        Event::new(EventType::UserFailedLogIn, None).with_user_uuid(user.uuid).save(conn).await?;
        err!("Incorrect client_secret", format!("IP: {}. Username: {}.", ip.ip, user.email))
    }

    let (mut device, new_device) = get_device(&data, conn, &user).await?;

    if CONFIG.mail_enabled() && new_device {
        let now = Utc::now();
        if let Err(e) = mail::send_new_device_logged_in(&user.email, ip.ip, now, &device.name).await {
            error!("Error sending new device email: {:#?}", e);

            if CONFIG.advanced.require_device_email {
                Event::new(EventType::UserFailedLogIn, None).with_user_uuid(user.uuid).save(conn).await?;
                err!("Could not send login notification email. Please contact your administrator.")
            }
        }
    }

    // Common
    let scope_vec = vec!["api".into()];
    let orgs = UserOrganization::find_by_user_with_status(conn, user.uuid, UserOrgStatus::Confirmed).await?;
    let (access_token, expires_in) = device.refresh_tokens(&user, orgs, scope_vec);
    device.save(conn).await?;

    info!("User {} logged in successfully via API key. IP: {}", user.email, ip.ip);

    // Note: No refresh_token is returned. The CLI just repeats the
    // client_credentials login flow when the existing token expires.
    let mut result = json!({
        "access_token": access_token,
        "expires_in": expires_in,
        "token_type": "Bearer",
        "scope": "api",
        "unofficialServer": true,
    });
    extend_object(&mut result, user_auth_response_fields(&user, conn).await?);

    Ok(Json(result))
}

async fn organization_api_key_login(data: ConnectData, conn: &Conn, ip: &ClientIp) -> Result<Json<Value>> {
    // Get the org via the client_id
    let client_id = data.client_id.as_ref().unwrap();
    let org_uuid = match client_id.strip_prefix("organization.").and_then(|x| Uuid::parse_str(x).ok()) {
        Some(uuid) => uuid,
        None => err!("Malformed client_id", format!("IP: {}.", ip.ip)),
    };
    let org_api_key = match OrganizationApiKey::find_by_org_uuid(conn, org_uuid).await? {
        Some(org_api_key) => org_api_key,
        None => err!("Invalid client_id", format!("IP: {}.", ip.ip)),
    };

    // Check API key.
    let client_secret = data.client_secret.as_ref().unwrap();
    if !org_api_key.check_valid_api_key(client_secret) {
        err!("Incorrect client_secret", format!("IP: {}. Organization: {}.", ip.ip, org_api_key.organization_uuid))
    }

    let claim = generate_organization_api_key_login_claims(org_api_key.uuid, org_api_key.organization_uuid);
    let access_token = crate::auth::encode_jwt(&claim);

    Ok(Json(json!({
        "access_token": access_token,
        "expires_in": 3600,
        "token_type": "Bearer",
        "scope": "api.organization",
        "unofficialServer": true,
    })))
}

/// Retrieves an existing device or creates a new device from ConnectData and the User
async fn get_device(data: &ConnectData, conn: &Conn, user: &User) -> Result<(Device, bool)> {
    // On iOS, device_type sends "iOS", on others it sends a number
    // When unknown or unable to parse, return 14, which is 'Unknown Browser'
    let device_type = util::try_parse_string(data.device_type.as_ref()).unwrap_or(14);
    let device_id = data.device_identifier.expect("No device id provided");
    let device_name = data.device_name.clone().expect("No device name provided");

    let mut new_device = false;
    // Find device or create new
    let device = match Device::find_by_uuid_and_user(conn, device_id, user.uuid).await? {
        Some(device) => device,
        None => {
            new_device = true;
            Device::new(device_id, user.uuid.clone(), device_name, device_type)
        }
    };

    Ok((device, new_device))
}

async fn twofactor_auth(user_uuid: Uuid, data: &ConnectData, device: &mut Device, ip: &ClientIp, conn: &Conn) -> Result<Option<String>> {
    let twofactors = TwoFactor::find_by_user_official(conn, user_uuid).await?;

    // No twofactor token if twofactor is disabled
    if twofactors.is_empty() {
        return Ok(None);
    }

    let incomplete_uuid = TwoFactorIncomplete::mark_incomplete(conn, user_uuid, device.uuid, &device.name, ip.ip).await?;

    let twofactor_ids: Vec<_> = twofactors.iter().map(|tf| tf.atype).collect();
    let selected_id = data.two_factor_provider.unwrap_or(twofactor_ids[0]); // If we aren't given a two factor provider, asume the first one

    let twofactor_code = match data.two_factor_token {
        Some(ref code) => code,
        None => err_json!(json_err_twofactor(&twofactor_ids, user_uuid, conn).await?, "2FA token not provided"),
    };

    let selected_twofactor = twofactors.into_iter().find(|tf| tf.atype == selected_id && tf.enabled);

    use crate::api::core::two_factor as _tf;
    use crate::crypto::ct_eq;

    let selected_data = selected_data(selected_twofactor)?;
    let mut remember = data.two_factor_remember.unwrap_or(0);

    match selected_id {
        TwoFactorType::Authenticator => _tf::authenticator::validate_totp_code_str(user_uuid, twofactor_code, selected_data, ip.ip, conn).await?,
        TwoFactorType::Webauthn => _tf::webauthn::validate_webauthn_login(user_uuid, twofactor_code, conn).await?,
        TwoFactorType::YubiKey => _tf::yubikey::validate_yubikey_login(twofactor_code, selected_data).await?,
        TwoFactorType::Duo => _tf::duo::validate_duo_login(user_uuid, data.username.as_ref().unwrap().trim(), twofactor_code, conn).await?,
        TwoFactorType::Email => _tf::email::validate_email_code_str(user_uuid, twofactor_code, selected_data).await?,

        TwoFactorType::Remember => {
            match device.twofactor_remember {
                Some(ref code) if !CONFIG.advanced.disable_2fa_remember && ct_eq(code, twofactor_code) => {
                    remember = 1; // Make sure we also return the token here, otherwise it will only remember the first time
                }
                _ => {
                    err_json!(json_err_twofactor(&twofactor_ids, user_uuid, conn).await?, "2FA Remember token not provided")
                }
            }
        }
        _ => {
            Event::new(EventType::UserFailedLogIn2fa, None).with_user_uuid(user_uuid).save(conn).await?;
            err!("Invalid two factor provider")
        }
    }

    if let Some(incomplete_uuid) = incomplete_uuid {
        TwoFactorIncomplete::mark_complete(conn, incomplete_uuid, user_uuid, device.uuid).await?;
    }

    if !CONFIG.advanced.disable_2fa_remember && remember == 1 {
        Ok(Some(device.refresh_twofactor_remember()))
    } else {
        device.delete_twofactor_remember();
        Ok(None)
    }
}

fn selected_data(tf: Option<TwoFactor>) -> Result<Value> {
    tf.map(|t| t.data).map_res("Two factor doesn't exist").map_err(Into::into)
}

async fn json_err_twofactor(providers: &[TwoFactorType], user_uuid: Uuid, conn: &Conn) -> Result<Value> {
    use crate::api::core::two_factor;

    let mut result = json!({
        "error" : "invalid_grant",
        "error_description" : "Two factor required.",
        "TwoFactorProviders" : providers,
        "TwoFactorProviders2" : {}, // { "0" : null }
        "MasterPasswordPolicy": {
            "Object": "masterPasswordPolicy"
        }
    });

    for provider in providers.iter().copied() {
        result["TwoFactorProviders2"][(provider as i32).to_string()] = Value::Null;

        match provider {
            TwoFactorType::Authenticator => { /* Nothing to do for TOTP */ }

            TwoFactorType::Webauthn => {
                let request = two_factor::webauthn::generate_webauthn_login(user_uuid, conn).await?;
                result["TwoFactorProviders2"][(provider as i32).to_string()] = request.0;
            }

            TwoFactorType::Duo => {
                let email = match User::get(conn, user_uuid).await? {
                    Some(u) => u.email,
                    None => err!("User does not exist"),
                };

                let (signature, host) = duo::generate_duo_signature(&email, conn).await?;

                result["TwoFactorProviders2"][(provider as i32).to_string()] = json!({
                    "Host": host,
                    "Signature": signature,
                });
            }

            TwoFactorType::YubiKey => {
                let twofactor = match TwoFactor::find_by_user_and_type(conn, user_uuid, provider).await? {
                    Some(tf) => tf,
                    None => err!("No YubiKey devices registered"),
                };

                let yubikey_metadata: yubikey::YubikeyMetadata =
                    serde_json::from_value(twofactor.data).map_err(|e| Error::bad_request(format!("malformed data: {e}")))?;

                result["TwoFactorProviders2"][(provider as i32).to_string()] = json!({
                    "Nfc": yubikey_metadata.nfc,
                })
            }

            TwoFactorType::Email => {
                use crate::api::core::two_factor as _tf;

                let twofactor = match TwoFactor::find_by_user_and_type(conn, user_uuid, provider).await? {
                    Some(tf) => tf,
                    None => err!("No twofactor email registered"),
                };

                // Send email immediately if email is the only 2FA option
                if providers.len() == 1 {
                    _tf::email::send_token(user_uuid, conn).await?
                }

                let email_data: EmailTokenData = serde_json::from_value(twofactor.data).map_err(|e| Error::bad_request(format!("malformed token: {e}")))?;
                result["TwoFactorProviders2"][(provider as i32).to_string()] = json!({
                    "Email": email::obscure_email(&email_data.email),
                })
            }

            _ => {}
        }
    }

    Ok(result)
}

// https://github.com/bitwarden/jslib/blob/master/common/src/models/request/tokenRequest.ts
// https://github.com/bitwarden/mobile/blob/master/src/Core/Models/Request/TokenRequest.cs
#[derive(Debug, Clone, Default, Deserialize)]
struct ConnectData {
    #[serde(alias = "grantType")]
    grant_type: String, // refresh_token, password, client_credentials (API key)

    // Needed for grant_type="refresh_token"
    #[serde(alias = "refreshToken")]
    refresh_token: Option<String>,

    // Needed for grant_type = "password" | "client_credentials"
    #[serde(alias = "clientId")]
    client_id: Option<String>, // web, cli, desktop, browser, mobile
    #[serde(alias = "clientSecret")]
    client_secret: Option<String>,
    password: Option<String>,
    scope: Option<String>,
    username: Option<String>,

    #[serde(alias = "deviceIdentifier")]
    device_identifier: Option<Uuid>,
    #[serde(alias = "deviceName")]
    device_name: Option<String>,
    #[serde(alias = "deviceType")]
    device_type: Option<String>,
    #[allow(unused)]
    _device_push_token: Option<String>, // Unused; mobile device push not yet supported.

    // Needed for two-factor auth
    #[serde(alias = "twoFactorProvider")]
    two_factor_provider: Option<TwoFactorType>,
    #[serde(alias = "twoFactorToken")]
    two_factor_token: Option<String>,
    #[serde(alias = "twoFactorRemember")]
    two_factor_remember: Option<i32>,
    // Needed for authorization code
    code: Option<String>,

    // Needed for login with device / passwordless login. When present, the `password` field
    // carries the auth-request access code instead of the master-password hash.
    #[serde(alias = "authRequest")]
    auth_request: Option<Uuid>,
}

fn check_is_some<T>(value: &Option<T>, msg: &str) -> Result<()> {
    if value.is_none() {
        err!(msg)
    }
    Ok(())
}

#[derive(Deserialize)]
struct PrevalidateQuery {
    #[serde(rename = "domainHint")]
    domain_hint: String,
}

async fn prevalidate(Query(query): Query<PrevalidateQuery>) -> Result<Json<Value>> {
    let conn = DB.get().await.map_err(Error::internal)?;
    info!("prevalidate domain name: {}", query.domain_hint);
    //TODO: this isn't properly unique and so is probably incorrect
    match Organization::find_by_name(&conn, &query.domain_hint).await? {
        Some(org) => {
            let claims = generate_ssotoken_claims(org.uuid, query.domain_hint);
            let ssotoken = encode_jwt(&claims);
            Ok(Json(json!({
                "token": ssotoken,
            })))
        }
        None => Ok(Json(json!({
            "token": "",
        }))),
    }
}

/// Fully-typed OpenID Connect client, with the auth/token/userinfo endpoints set (from discovery + config).
type SsoClient = openidconnect::Client<
    EmptyAdditionalClaims,
    CoreAuthDisplay,
    CoreGenderClaim,
    CoreJweContentEncryptionAlgorithm,
    CoreJsonWebKey,
    CoreAuthPrompt,
    StandardErrorResponse<CoreErrorResponseType>,
    CoreTokenResponse,
    CoreTokenIntrospectionResponse,
    CoreRevocableToken,
    CoreRevocationErrorResponse,
    EndpointSet,    // Auth
    EndpointNotSet, // Device authorization
    EndpointNotSet, // Introspection
    EndpointNotSet, // Revocation
    EndpointSet,    // Token
    EndpointSet,    // UserInfo
>;

/// `openidconnect` 4 no longer ships an HTTP client; callers must supply an [`AsyncHttpClient`].
/// We wrap `reqwest` with redirects disabled to avoid SSRF-style redirect following.
#[derive(Clone)]
struct OidcHttpClient {
    client: reqwest::Client,
}

impl OidcHttpClient {
    fn new() -> Result<Self, reqwest::Error> {
        reqwest::Client::builder().redirect(reqwest::redirect::Policy::none()).build().map(|client| Self {
            client,
        })
    }
}

impl<'c> AsyncHttpClient<'c> for OidcHttpClient {
    type Error = HttpClientError<reqwest::Error>;
    type Future = Pin<Box<dyn Future<Output = Result<HttpResponse, Self::Error>> + Send + Sync + 'c>>;

    fn call(&'c self, request: HttpRequest) -> Self::Future {
        Box::pin(async move {
            let response = self.client.execute(request.try_into().map_err(Box::new)?).await.map_err(Box::new)?;

            let mut builder = openidconnect::http::Response::builder().status(response.status()).version(response.version());
            for (name, value) in response.headers() {
                builder = builder.header(name, value);
            }

            let body = response.bytes().await.map_err(Box::new)?;
            builder.body(body.to_vec()).map_err(HttpClientError::Http)
        })
    }
}

async fn get_client_from_sso_config() -> Result<(OidcHttpClient, SsoClient), &'static str> {
    let Some(sso) = &CONFIG.sso else {
        return Err("no sso configured");
    };
    let client_id = ClientId::new(sso.client_id.clone());
    let client_secret = ClientSecret::new(sso.client_secret.clone());
    let issuer_url = IssuerUrl::new(sso.authority.clone()).or(Err("invalid issuer URL"))?;

    let http_client = OidcHttpClient::new().or(Err("Failed to build http client"))?;

    //TODO: This comparison will fail if one URI has a trailing slash and the other one does not.
    // Should we remove trailing slashes when saving? Or when checking?
    let provider_metadata = match CoreProviderMetadata::discover_async(issuer_url, &http_client).await {
        Ok(metadata) => metadata,
        Err(_err) => {
            return Err("Failed to discover OpenID provider");
        }
    };

    let base_client = CoreClient::from_provider_metadata(provider_metadata, client_id, Some(client_secret));

    let token_uri = base_client.token_uri().ok_or("Failed to discover token endpoint")?.clone();
    let user_info_url = base_client.user_info_url().ok_or("Failed to discover userinfo endpoint")?.clone();

    let client = base_client
        .set_redirect_uri(RedirectUrl::new(SSO_CALLBACK_URL.to_string()).or(Err("Invalid redirect URL"))?)
        .set_token_uri(token_uri)
        .set_user_info_url(user_info_url);

    Ok((http_client, client))
}

#[derive(Deserialize)]
struct OidcSigninQuery {
    #[serde(rename = "domainHint")]
    code: String,
}

async fn oidc_signin(Query(query): Query<OidcSigninQuery>, mut jar: CookieJar) -> Result<Response> {
    let redirect_uri = jar.get("redirect_uri").ok_or_else(|| Error::bad_request("missing redirect_uri cookie"))?.value().to_string();
    let orig_state = jar.get("state").ok_or_else(|| Error::bad_request("missing state cookie"))?.value().to_string();

    jar = jar.remove(Cookie::from("redirect_uri"));
    jar = jar.remove(Cookie::from("state"));

    (jar, Url::parse(&format!("{redirect_uri}?code={}&state={orig_state}", query.code)).map_err(Error::internal)?).into_response()
}

#[derive(Deserialize)]
#[allow(non_snake_case)]
struct AuthorizeData {
    #[allow(unused)]
    client_id: Option<String>,
    redirect_uri: String,
    #[allow(unused)]
    response_type: Option<String>,
    #[allow(unused)]
    scope: Option<String>,
    state: String,
    #[allow(unused)]
    code_challenge: Option<String>,
    #[allow(unused)]
    code_challenge_method: Option<String>,
    #[allow(unused)]
    response_mode: Option<String>,
    #[allow(unused)]
    domain_hint: Option<String>,
    #[allow(unused)]
    #[serde(rename = "ssoToken")]
    sso_token: Option<String>,
}

async fn authorize(Query(data): Query<AuthorizeData>, mut jar: CookieJar) -> Result<Response> {
    match get_client_from_sso_config().await {
        Ok((_http_client, client)) => {
            let (auth_url, _csrf_state, nonce) = client
                .authorize_url(AuthenticationFlow::<CoreResponseType>::AuthorizationCode, CsrfToken::new_random, Nonce::new_random)
                .add_scope(Scope::new("email".to_string()))
                .add_scope(Scope::new("profile".to_string()))
                .url();

            let conn = DB.get().await.map_err(Error::internal)?;
            let sso_nonce = SsoNonce::new(nonce.secret().to_string());
            sso_nonce.save(&conn).await?;

            let mut cookie = Cookie::from("redirect_uri");
            cookie.set_value(data.redirect_uri);
            jar = jar.add(cookie);
            let mut cookie = Cookie::from("state");
            cookie.set_value(data.state);
            jar = jar.add(cookie);

            (jar, (RedirectMode::TemporaryRedirect, auth_url)).into_response()
        }
        Err(err) => err!("Unable to find client from identifier {}", err),
    }
}

async fn get_auth_code_access_token(code: &str) -> Result<(String, String, CoreUserInfoClaims), &'static str> {
    let oidc_code = AuthorizationCode::new(String::from(code));
    match get_client_from_sso_config().await {
        Ok((http_client, client)) => match client.exchange_code(oidc_code).request_async(&http_client).await {
            Ok(token_response) => {
                //let refresh_token = token_response.refresh_token():
                let refreshtoken = match token_response.refresh_token() {
                    Some(token) => token.secret().to_string(),
                    None => String::new(),
                };
                let id_token = token_response.extra_fields().id_token().unwrap().to_string();

                let access_token: AccessToken = token_response.access_token().to_owned();
                let userinfo: CoreUserInfoClaims = match client.user_info(access_token, None).request_async(&http_client).await {
                    Ok(userinfo) => userinfo,
                    Err(_err) => return Err("Failed to contact userinfo endpoint"),
                };

                Ok((refreshtoken, id_token, userinfo))
            }
            Err(_err) => Err("Failed to contact token endpoint"),
        },
        Err(_err) => Err("unable to find client"),
    }
}

#[cfg(test)]
mod tests {
    use serde_json::json;

    use crate::test_harness::TestClient;

    #[tokio::test]
    async fn refresh_token_grant_returns_new_access_token() {
        let mut client = TestClient::new().await;
        client.register().await;

        // A password-grant login with offline_access yields a refresh token.
        let form = [
            ("grant_type", "password"),
            ("username", client.email.as_str()),
            ("password", client.master_password_hash.as_str()),
            ("scope", "api offline_access"),
            ("client_id", "web"),
            ("device_identifier", client.device_id.as_str()),
            ("device_name", "test-harness"),
            ("device_type", "14"),
        ];
        let resp = client.post_form("/identity/connect/token", &form).await;
        resp.assert_ok();
        let refresh_token = resp.json()["refresh_token"].as_str().expect("refresh_token present").to_string();

        // Exchanging the refresh token yields a fresh access token.
        let refresh_form = [("grant_type", "refresh_token"), ("refresh_token", refresh_token.as_str())];
        let refreshed = client.post_form("/identity/connect/token", &refresh_form).await;
        refreshed.assert_ok();
        assert!(refreshed.json()["access_token"].as_str().is_some(), "refresh should yield an access token: {}", refreshed.body);
    }

    #[tokio::test]
    async fn client_credentials_api_key_login() {
        let client = TestClient::register_and_login().await;

        // Obtain the user's personal API key.
        let key_resp = client.post("/api/accounts/api-key", json!({ "masterPasswordHash": client.master_password_hash })).await;
        key_resp.assert_ok();
        let api_key = key_resp.json()["apiKey"].as_str().expect("apiKey").to_string();

        // Log in with the client_credentials grant (client_id = "user.<uuid>").
        let client_id = format!("user.{}", client.user_id.unwrap());
        let form = [
            ("grant_type", "client_credentials"),
            ("client_id", client_id.as_str()),
            ("client_secret", api_key.as_str()),
            ("scope", "api"),
            ("device_identifier", client.device_id.as_str()),
            ("device_name", "test-harness"),
            ("device_type", "14"),
        ];
        let resp = client.post_form("/identity/connect/token", &form).await;
        resp.assert_ok();
        let j = resp.json();
        assert!(j["access_token"].as_str().is_some(), "api-key login should yield a token: {}", resp.body);
        // The API-key grant now emits the same modern decryption metadata as password login.
        assert_eq!(j["UserDecryptionOptions"]["Object"], "userDecryptionOptions", "api-key response should include UserDecryptionOptions: {}", resp.body);
        assert_eq!(j["UserDecryptionOptions"]["HasMasterPassword"], true, "{}", resp.body);
        assert!(j["AccountKeys"].is_object(), "api-key response should include AccountKeys: {}", resp.body);
    }

    #[tokio::test]
    async fn refresh_with_bad_token_returns_invalid_grant() {
        let client = TestClient::new().await;
        let form = [("grant_type", "refresh_token"), ("refresh_token", "definitely-not-a-real-refresh-token")];
        let resp = client.post_form("/identity/connect/token", &form).await;
        resp.assert_status(400);
        assert_eq!(resp.json()["error"], "invalid_grant", "bad refresh token should yield invalid_grant so clients re-login: {}", resp.body);
    }

    #[tokio::test]
    async fn prevalidate_unknown_domain_returns_empty_token() {
        let client = TestClient::new().await;
        let resp = client.get("/identity/account/prevalidate?domainHint=no-such-org").await;
        resp.assert_ok();
        assert_eq!(resp.json()["token"], "");
    }

    #[tokio::test]
    async fn invalid_grant_type_is_rejected() {
        let client = TestClient::new().await;
        let resp = client.post_form("/identity/connect/token", &[("grant_type", "made_up")]).await;
        assert!(resp.status >= 400, "invalid grant type should fail, got {}: {}", resp.status, resp.body);
    }
}
