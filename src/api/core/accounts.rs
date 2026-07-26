use std::str::FromStr;

use axol::prelude::*;
use chrono::Utc;
use log::error;
use serde::Deserialize;
use serde_json::{Value, json};
use uuid::Uuid;

use crate::{
    CONFIG,
    api::{PasswordData, UpdateType, ws_anonymous_subscriptions, ws_users},
    auth::{ClientHeaders, Headers, decode_delete, decode_invite, decode_verify_email},
    crypto,
    db::{AuthRequest, Cipher, DB, Device, EmergencyAccess, EventType, Folder, Invitation, Send, User, UserKdfType, UserOrgStatus, UserOrganization},
    events::log_user_event,
    mail,
    push::{register_push_device, unregister_push_device},
    util::AutoTxn,
};

pub fn route(router: Router) -> Router {
    router
        .post("/accounts/register", register)
        .post("/accounts/register/finish", register)
        .post("/accounts/register/send-verification-email", register_send_verification_email)
        .post("/accounts/set-password", post_set_password)
        .get("/accounts/profile", profile)
        .put("/accounts/profile", post_profile)
        .post("/accounts/profile", post_profile)
        .put("/accounts/avatar", put_avatar)
        .get("/users/:uuid/public-key", get_public_keys)
        .post("/accounts/keys", post_keys)
        .post("/accounts/password", post_password)
        .post("/accounts/kdf", post_kdf)
        .post("/accounts/key", post_rotatekey)
        .post("/accounts/key-management/rotate-user-account-keys", post_rotate_account_keys)
        .post("/accounts/security-stamp", post_sstamp)
        .post("/accounts/email-token", post_email_token)
        .post("/accounts/email", post_email)
        .post("/accounts/verify-email", post_verify_email)
        .post("/accounts/verify-email-token", post_verify_email_token)
        .post("/accounts/delete-recover", post_delete_recover)
        .post("/accounts/delete-recover-token", post_delete_recover_token)
        .post("/accounts/delete", delete_account)
        .delete("/accounts", delete_account)
        .get("/accounts/revision-date", revision_date)
        .post("/accounts/password-hint", password_hint)
        .post("/accounts/prelogin", prelogin)
        // Newer clients (web-vault) hit the /password suffix; same handler.
        .post("/accounts/prelogin/password", prelogin)
        .post("/accounts/api-key", api_key)
        .post("/accounts/rotate-api-key", rotate_api_key)
        .get("/tasks", get_tasks)
        .post("/auth-requests", post_auth_request)
        .get("/auth-requests", get_auth_requests_pending)
        .get("/auth-requests/pending", get_auth_requests_pending)
        .get("/auth-requests/:uuid", get_auth_request)
        .put("/auth-requests/:uuid", put_auth_request)
        .get("/auth-requests/:uuid/response", get_auth_request_response)
}

/// Stub for the security-tasks endpoint so newer web-vault/clients don't error.
/// Vaultwarden does not implement security tasks, so this always returns an empty list.
async fn get_tasks(_headers: Headers) -> Json<Value> {
    Json(json!({
        "data": [],
        "object": "list"
    }))
}

// Login-with-device / passwordless-login auth requests.
// A device that wants to log in (but has no key) creates an auth request; another already
// authenticated device of the same user approves it and hands back the encrypted user key.

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
struct AuthRequestRequest {
    access_code: String,
    device_identifier: Uuid,
    email: String,
    public_key: String,
    // Not used for now
    // #[serde(alias = "type")]
    // _type: i32,
}

async fn post_auth_request(client_headers: ClientHeaders, data: Json<AuthRequestRequest>) -> Result<Json<Value>> {
    let data = data.0;
    let conn = DB.get().await.ise()?;

    let Some(user) = User::find_by_email(&conn, &data.email).await? else {
        err!("AuthRequest doesn't exist", "User not found")
    };

    // Validate that the requesting device exists and its type matches the request headers.
    let device = match Device::find_by_uuid_and_user(&conn, data.device_identifier, user.uuid).await? {
        Some(device) if device.atype == client_headers.device_type => device,
        _ => err!("AuthRequest doesn't exist", "Device verification failed"),
    };

    let mut auth_request =
        AuthRequest::new(user.uuid, data.device_identifier, client_headers.device_type, client_headers.ip.ip.to_string(), data.access_code, data.public_key);
    auth_request.save(&conn).await?;

    ws_users().send_auth_request(user.uuid, auth_request.uuid, &device, &conn).await?;

    Ok(Json(auth_request.to_json()))
}

async fn get_auth_request(Path(uuid): Path<Uuid>, headers: Headers) -> Result<Json<Value>> {
    let conn = DB.get().await.ise()?;
    let Some(auth_request) = AuthRequest::find_by_uuid_and_user(&conn, uuid, headers.user.uuid).await? else {
        err!("AuthRequest doesn't exist", "Record not found or user uuid does not match")
    };

    Ok(Json(auth_request.to_json()))
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
struct AuthResponseRequest {
    device_identifier: Uuid,
    key: String,
    master_password_hash: Option<String>,
    request_approved: bool,
}

async fn put_auth_request(Path(uuid): Path<Uuid>, headers: Headers, data: Json<AuthResponseRequest>) -> Result<Json<Value>> {
    let data = data.0;
    let conn = DB.get().await.ise()?;

    let Some(mut auth_request) = AuthRequest::find_by_uuid_and_user(&conn, uuid, headers.user.uuid).await? else {
        err!("AuthRequest doesn't exist", "Record not found or user uuid does not match")
    };

    if headers.device.uuid != data.device_identifier {
        err!("AuthRequest doesn't exist", "Device verification failed")
    }

    if auth_request.approved.is_some() {
        err!("An authentication request with the same device already exists")
    }

    if data.request_approved {
        auth_request.approved = Some(true);
        auth_request.enc_key = Some(data.key);
        auth_request.master_password_hash = data.master_password_hash;
        auth_request.response_device_id = Some(data.device_identifier);
        auth_request.response_date = Some(Utc::now());
        auth_request.save(&conn).await?;

        // Notify both the anonymous hub (the still-unauthenticated requesting device) and the
        // authenticated hub of the user so any other devices update their pending list.
        ws_anonymous_subscriptions().send_auth_response(auth_request.user_uuid, auth_request.uuid).await;
        ws_users().send_auth_response(auth_request.user_uuid, auth_request.uuid, &headers.device, &conn).await?;
    } else {
        // If denied, there's no reason to keep the request around.
        auth_request.delete(&conn).await?;
    }

    Ok(Json(auth_request.to_json()))
}

#[derive(Deserialize)]
struct AuthRequestResponseQuery {
    code: String,
}

async fn get_auth_request_response(
    Path(uuid): Path<Uuid>,
    Query(query): Query<AuthRequestResponseQuery>,
    client_headers: ClientHeaders,
) -> Result<Json<Value>> {
    let conn = DB.get().await.ise()?;
    let Some(auth_request) = AuthRequest::find_by_uuid(&conn, uuid).await? else {
        err!("AuthRequest doesn't exist", "User not found")
    };

    if auth_request.device_type != client_headers.device_type
        || auth_request.request_ip != client_headers.ip.ip.to_string()
        || !auth_request.check_access_code(&query.code)
    {
        err!("AuthRequest doesn't exist", "Invalid device, IP or code")
    }

    Ok(Json(auth_request.to_json()))
}

async fn get_auth_requests_pending(headers: Headers) -> Result<Json<Value>> {
    let conn = DB.get().await.ise()?;
    let auth_requests = AuthRequest::find_by_user(&conn, headers.user.uuid).await?;

    Ok(Json(json!({
        "data": auth_requests
            .iter()
            .filter(|request| request.approved.is_none())
            .map(AuthRequest::to_json)
            .collect::<Vec<Value>>(),
        "continuationToken": null,
        "object": "list"
    })))
}

#[derive(Deserialize, Debug)]
#[serde(rename_all = "camelCase")]
pub struct RegisterData {
    email: String,
    #[serde(flatten)]
    credentials: MasterPasswordCredentials,
    #[serde(alias = "userAsymmetricKeys")]
    keys: Option<KeysData>,
    master_password_hint: Option<String>,
    name: Option<String>,
    token: Option<String>,
    #[allow(dead_code)]
    organization_user_id: Option<String>,
    // Sent by the two-step (email-verified) registration flow via /accounts/register/finish.
    email_verification_token: Option<String>,
}

#[derive(Deserialize, Debug)]
#[serde(rename_all = "camelCase")]
pub struct SetPasswordData {
    #[serde(flatten)]
    credentials: MasterPasswordCredentials,
    #[serde(alias = "userAsymmetricKeys")]
    keys: Option<KeysData>,
    master_password_hint: Option<String>,
    #[allow(dead_code)]
    #[serde(rename = "orgIdentifier")]
    org_identifier: Option<String>,
}

/// Master-password credentials sent to register / set-password. Clients send one of two wire
/// shapes: the legacy flat form (`masterPasswordHash` + `key` + flat `kdf*`) or the v2 nested
/// form (`masterPasswordAuthentication` + `masterPasswordUnlock`). Bitwarden collapses both
/// onto the same stored state — password hash, wrapped user key, KDF params, and salt (= the
/// user's email) — so we accept either and read through these accessors.
#[derive(Deserialize, Debug)]
#[serde(untagged)]
enum MasterPasswordCredentials {
    Legacy(LegacyCredentials),
    V2(V2Credentials),
}

#[derive(Deserialize, Debug)]
#[serde(rename_all = "camelCase")]
struct LegacyCredentials {
    kdf: Option<i32>,
    kdf_iterations: Option<i32>,
    kdf_memory: Option<i32>,
    kdf_parallelism: Option<i32>,
    #[serde(alias = "userSymmetricKey")]
    key: String,
    master_password_hash: String,
}

#[derive(Deserialize, Debug)]
#[serde(rename_all = "camelCase")]
struct V2Credentials {
    master_password_authentication: MasterPasswordAuthentication,
    master_password_unlock: MasterPasswordUnlock,
}

#[derive(Deserialize, Debug)]
#[serde(rename_all = "camelCase")]
struct KdfData {
    #[serde(alias = "kdfType")]
    kdf: i32,
    #[serde(alias = "iterations")]
    kdf_iterations: i32,
    #[serde(alias = "memory")]
    kdf_memory: Option<i32>,
    #[serde(alias = "parallelism")]
    kdf_parallelism: Option<i32>,
}

#[derive(Deserialize, Debug)]
#[serde(rename_all = "camelCase")]
struct MasterPasswordAuthentication {
    kdf: KdfData,
    salt: String,
    #[serde(alias = "masterPasswordAuthenticationHash")]
    hash: String,
}

#[derive(Deserialize, Debug)]
#[serde(rename_all = "camelCase")]
struct MasterPasswordUnlock {
    kdf: KdfData,
    salt: String,
    #[serde(alias = "masterKeyWrappedUserKey")]
    key: String,
}

impl MasterPasswordCredentials {
    /// The master-password hash the server re-hashes and stores.
    fn master_password_hash(&self) -> &str {
        match self {
            Self::Legacy(c) => &c.master_password_hash,
            Self::V2(c) => &c.master_password_authentication.hash,
        }
    }

    /// The master-key-wrapped user key (stored as `akey`).
    fn user_key(&self) -> &str {
        match self {
            Self::Legacy(c) => &c.key,
            Self::V2(c) => &c.master_password_unlock.key,
        }
    }

    /// `(kdf_type, kdf_iterations, kdf_memory, kdf_parallelism)`. v2 always carries type +
    /// iterations; the legacy form may omit them, in which case the caller keeps its defaults.
    fn kdf(&self) -> (Option<i32>, Option<i32>, Option<i32>, Option<i32>) {
        match self {
            Self::Legacy(c) => (c.kdf, c.kdf_iterations, c.kdf_memory, c.kdf_parallelism),
            Self::V2(c) => {
                let k = &c.master_password_unlock.kdf;
                (Some(k.kdf), Some(k.kdf_iterations), k.kdf_memory, k.kdf_parallelism)
            }
        }
    }

    /// A v2 body carries the KDF and salt twice (authentication + unlock); the two must agree
    /// and the salt must be the user's normalized email. The legacy form has nothing extra.
    fn validate(&self, email: &str) -> Result<()> {
        if let Self::V2(c) = self {
            let a = &c.master_password_authentication;
            let u = &c.master_password_unlock;
            if a.kdf.kdf != u.kdf.kdf || a.kdf.kdf_iterations != u.kdf.kdf_iterations || a.salt != email || u.salt != email {
                err!("Invalid master password credentials");
            }
        }
        Ok(())
    }
}

#[derive(Deserialize, Debug)]
#[serde(rename_all = "camelCase")]
pub struct KeysData {
    encrypted_private_key: String,
    public_key: String,
}

/// Trims whitespace from password hints, and converts blank password hints to `None`.
fn clean_password_hint(password_hint: &Option<String>) -> Option<String> {
    match password_hint {
        None => None,
        Some(h) => match h.trim() {
            "" => None,
            ht => Some(ht.to_string()),
        },
    }
}

fn enforce_password_hint_setting(password_hint: &Option<String>) -> Result<()> {
    if password_hint.is_some() && !CONFIG.settings.password_hints_allowed {
        err!("Password hints have been disabled by the administrator. Remove the hint and try again.");
    }
    Ok(())
}

pub async fn register(conn: AutoTxn, data: Json<RegisterData>) -> Result<Json<Value>> {
    let mut data: RegisterData = data.0;
    let email = data.email.to_lowercase();

    // The two-step registration flow (/accounts/register/finish) carries an email-verification
    // token minted by /accounts/register/send-verification-email. Validate it and, if it was
    // actually delivered by email, treat the address as verified.
    let mut email_verified = false;
    if let Some(token) = data.email_verification_token.take() {
        let claims = crate::auth::decode_register_verify(&token)?;
        if claims.sub.to_lowercase() != email {
            err!("Email verification token does not match email");
        }
        // The name isn't resent on finish, so recover it from the token.
        if data.name.is_none() {
            data.name = claims.name;
        }
        email_verified = claims.verified;
    }

    // Reject inconsistent v2 credential bodies before we touch the account.
    data.credentials.validate(&email)?;

    // Check if the length of the username exceeds 50 characters (Same is Upstream Bitwarden)
    // This also prevents issues with very long usernames causing to large JWT's. See #2419
    if let Some(ref name) = data.name
        && name.len() > 50
    {
        err!("The field Name must be a string with a maximum length of 50.");
    }

    // Check against the password hint setting here so if it fails, the user
    // can retry without losing their invitation below.
    let password_hint = clean_password_hint(&data.master_password_hint);
    enforce_password_hint_setting(&password_hint)?;

    let mut verified_by_invite = false;

    let mut user = match User::find_by_email(&conn, &email).await? {
        Some(mut user) => {
            if !user.password_hash.is_empty() {
                err!("Registration not allowed or user already exists")
            }

            if let Some(token) = data.token {
                let claims = decode_invite(&token)?;
                if claims.email == email {
                    // Verify the email address when signing up via a valid invite token
                    verified_by_invite = true;
                    user.verified_at = Some(Utc::now());
                    user
                } else {
                    err!("Registration email does not match invite email")
                }
            } else if Invitation::take(&conn, &email).await? {
                for user_org in UserOrganization::find_by_user_with_status(&conn, user.uuid, UserOrgStatus::Invited).await?.iter_mut() {
                    user_org.status = UserOrgStatus::Accepted;
                    user_org.save(&conn).await?;
                }
                user
            } else if CONFIG.is_signup_allowed(&email) || EmergencyAccess::find_invited_by_grantee_email(&conn, &email).await?.is_some() {
                user
            } else {
                err!("Registration not allowed or user already exists")
            }
        }
        None => {
            // Order is important here; the invitation check must come first
            // because the vaultwarden admin can invite anyone, regardless
            // of other signup restrictions.
            if Invitation::take(&conn, &email).await? || CONFIG.is_signup_allowed(&email) {
                User::new(email.clone())
            } else {
                err!("Registration not allowed or user already exists")
            }
        }
    };

    // Make sure we don't leave a lingering invitation.
    Invitation::take(&conn, &email).await?;

    let (kdf_type, kdf_iter, kdf_mem, kdf_para) = data.credentials.kdf();
    if let Some(kdf_type) = kdf_type {
        user.client_kdf_type = kdf_type;
    }
    if let Some(kdf_iter) = kdf_iter {
        user.client_kdf_iter = kdf_iter;
    }
    user.client_kdf_memory = kdf_mem;
    user.client_kdf_parallelism = kdf_para;

    user.set_password(data.credentials.master_password_hash(), Some(data.credentials.user_key().to_string()), true, None, &conn).await?;
    user.password_hint = password_hint;

    // Add extra fields if present
    if let Some(name) = data.name {
        user.name = name;
    }

    if let Some(keys) = data.keys {
        user.private_key = Some(keys.encrypted_private_key);
        user.public_key = Some(keys.public_key);
    }

    // A verified email-verification token counts as confirming the address.
    if email_verified {
        user.verified_at = Some(Utc::now());
    }

    if CONFIG.mail_enabled() {
        if CONFIG.settings.signups_verify && !verified_by_invite {
            if let Err(e) = mail::send_welcome_must_verify(&user.email, user.uuid).await {
                error!("Error sending welcome email: {:#?}", e);
            }

            user.last_verifying_at = Some(user.created_at);
        } else if let Err(e) = mail::send_welcome(&user.email).await {
            error!("Error sending welcome email: {:#?}", e);
        }
    }

    user.save(&conn).await?;
    conn.commit().await?;
    Ok(Json(json!({
      "object": "register",
      "captchaBypassToken": "",
    })))
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct RegisterVerificationData {
    email: String,
    name: Option<String>,
}

// First step of the two-step registration flow: mint an email-verification token. When mail
// is enabled and signups require verification, the token is emailed and we return 204;
// otherwise (the common self-host case) we hand the token straight back so the client can
// proceed to /accounts/register/finish. Ref: Bitwarden AccountsController.PostRegisterSendEmail.
pub async fn register_send_verification_email(conn: AutoTxn, data: Json<RegisterVerificationData>) -> Result<Response> {
    let data: RegisterVerificationData = data.0;
    let email = data.email.to_lowercase();

    // Registration can only continue if signups are allowed or a pending invitation exists.
    if !(CONFIG.is_signup_allowed(&email) || (!CONFIG.mail_enabled() && Invitation::find_by_email(&conn, &email).await?.is_some())) {
        err!("Registration not allowed or user already exists")
    }

    let should_send_mail = CONFIG.mail_enabled() && CONFIG.settings.signups_verify;
    let token = crate::auth::encode_jwt(&crate::auth::generate_register_verify_claims(email.clone(), data.name.clone(), should_send_mail));

    if should_send_mail {
        mail::send_register_verify_email(&email, &token).await?;
        // 204: the token was delivered by email, not in the response body.
        (axol::http::StatusCode::NoContent, ()).into_response()
    } else {
        // The client uses this token directly as `emailVerificationToken` on register/finish.
        Json(json!(token)).into_response()
    }
}

pub async fn post_set_password(headers: Headers, data: Json<SetPasswordData>) -> Result<Json<Value>> {
    let data: SetPasswordData = data.0;
    let mut user = headers.user;
    let conn = DB.get().await.ise()?;

    // Check against the password hint setting here so if it fails, the user
    // can retry without losing their invitation below.
    let password_hint = clean_password_hint(&data.master_password_hint);
    enforce_password_hint_setting(&password_hint)?;

    // Reject inconsistent v2 credential bodies before we touch the account.
    data.credentials.validate(&user.email)?;

    let (kdf_type, kdf_iter, kdf_mem, kdf_para) = data.credentials.kdf();
    if let Some(kdf_iter) = kdf_iter {
        user.client_kdf_iter = kdf_iter;
    }
    if let Some(kdf_type) = kdf_type {
        user.client_kdf_type = kdf_type;
    }

    //We need to allow revision-date to use the old security_timestamp
    let routes = ["revision_date"];
    let routes: Option<Vec<String>> = Some(routes.iter().map(ToString::to_string).collect());

    user.client_kdf_memory = kdf_mem;
    user.client_kdf_parallelism = kdf_para;

    user.set_password(data.credentials.master_password_hash(), Some(data.credentials.user_key().to_string()), false, routes, &conn).await?;
    user.password_hint = password_hint;

    if let Some(keys) = data.keys {
        user.private_key = Some(keys.encrypted_private_key);
        user.public_key = Some(keys.public_key);
    }

    if CONFIG.mail_enabled() {
        mail::send_set_password(&user.email.to_lowercase(), &user.name).await?;
    }

    user.save(&conn).await?;
    Ok(Json(json!({
      "object": "set-password",
      "captchaBypassToken": "",
    })))
}

pub async fn profile(headers: Headers) -> Result<Json<Value>> {
    let conn = DB.get().await.ise()?;
    Ok(Json(headers.user.to_json(&conn).await?))
}

#[derive(Deserialize, Debug)]
#[serde(rename_all = "camelCase")]
pub struct ProfileData {
    // Culture: String, // Ignored, always use en-US
    // master_password_hint: Option<String>, // Ignored, has been moved to ChangePassData
    name: String,
}

pub async fn post_profile(headers: Headers, data: Json<ProfileData>) -> Result<Json<Value>> {
    let data: ProfileData = data.0;
    let conn = DB.get().await.ise()?;

    // Check if the length of the username exceeds 50 characters (Same is Upstream Bitwarden)
    // This also prevents issues with very long usernames causing to large JWT's. See #2419
    if data.name.len() > 50 {
        err!("The field Name must be a string with a maximum length of 50.");
    }

    let mut user = headers.user;
    user.name = data.name;

    user.save(&conn).await?;
    Ok(Json(user.to_json(&conn).await?))
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct AvatarData {
    avatar_color: Option<String>,
}

pub async fn put_avatar(headers: Headers, data: Json<AvatarData>) -> Result<Json<Value>> {
    let data: AvatarData = data.0;

    // It looks like it only supports the 6 hex color format.
    // If you try to add the short value it will not show that color.
    // Check and force 7 chars, including the #.
    if let Some(color) = &data.avatar_color
        && color.len() != 7
    {
        err!("The field AvatarColor must be a HTML/Hex color code with a length of 7 characters")
    }
    let conn = DB.get().await.ise()?;

    let mut user = headers.user;
    user.avatar_color = data.avatar_color;

    user.save(&conn).await?;
    Ok(Json(user.to_json(&conn).await?))
}

pub async fn get_public_keys(Path(uuid): Path<Uuid>, _headers: Headers) -> Result<Json<Value>> {
    let conn = DB.get().await.ise()?;
    //TODO: does this need authorization
    let user = match User::get(&conn, uuid).await? {
        Some(user) => user,
        None => err!("User doesn't exist"),
    };

    Ok(Json(json!({
        "userId": user.uuid,
        "publicKey": user.public_key,
        "object":"userKey"
    })))
}

pub async fn post_keys(headers: Headers, data: Json<KeysData>) -> Result<Json<Value>> {
    let data: KeysData = data.0;

    let mut user = headers.user;

    user.private_key = Some(data.encrypted_private_key);
    user.public_key = Some(data.public_key);
    let conn = DB.get().await.ise()?;

    user.save(&conn).await?;

    Ok(Json(json!({
        "key": user.akey,
        "privateKey": user.private_key,
        "publicKey": user.public_key,
        "accountKeys": user.account_keys_json(),
        "object":"keys"
    })))
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ChangePassData {
    master_password_hash: String,
    new_master_password_hash: String,
    master_password_hint: Option<String>,
    key: String,
}

pub async fn post_password(headers: Headers, data: Json<ChangePassData>) -> Result<()> {
    let data: ChangePassData = data.0;
    let mut user = headers.user;

    if !user.check_valid_password(&data.master_password_hash) {
        err!("Invalid password")
    }

    user.password_hint = clean_password_hint(&data.master_password_hint);
    enforce_password_hint_setting(&user.password_hint)?;
    // The user has now set a password of their own choosing, so clear any admin-forced reset.
    user.force_password_reset = false;
    let mut conn = DB.get().await.ise()?;

    log_user_event(EventType::UserChangedPassword, user.uuid, headers.device.atype, Utc::now(), headers.ip, &mut conn).await?;

    user.set_password(
        &data.new_master_password_hash,
        Some(data.key),
        true,
        Some(vec![String::from("post_rotatekey"), String::from("get_contacts"), String::from("get_public_keys")]),
        &conn,
    )
    .await?;

    user.save(&conn).await?;

    // Prevent loging out the client where the user requested this endpoint from.
    // If you do logout the user it will causes issues at the client side.
    // Adding the device uuid will prevent this.
    ws_users().send_logout(&user, &conn, Some(headers.device.uuid)).await?;

    Ok(())
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ChangeKdfData {
    kdf: i32,
    kdf_iterations: i32,
    kdf_memory: Option<i32>,
    kdf_parallelism: Option<i32>,

    master_password_hash: String,
    new_master_password_hash: String,
    key: String,
}

pub async fn post_kdf(headers: Headers, data: Json<ChangeKdfData>) -> Result<()> {
    let data: ChangeKdfData = data.0;
    let mut user = headers.user;

    if !user.check_valid_password(&data.master_password_hash) {
        err!("Invalid password")
    }

    if data.kdf == UserKdfType::Pbkdf2 as i32 && data.kdf_iterations < 100_000 {
        err!("PBKDF2 KDF iterations must be at least 100000.")
    }

    if data.kdf == UserKdfType::Argon2id as i32 {
        if data.kdf_iterations < 1 {
            err!("Argon2 KDF iterations must be at least 1.")
        }
        if let Some(m) = data.kdf_memory {
            if !(15..=1024).contains(&m) {
                err!("Argon2 memory must be between 15 MB and 1024 MB.")
            }
            user.client_kdf_memory = data.kdf_memory;
        } else {
            err!("Argon2 memory parameter is required.")
        }
        if let Some(p) = data.kdf_parallelism {
            if !(1..=16).contains(&p) {
                err!("Argon2 parallelism must be between 1 and 16.")
            }
            user.client_kdf_parallelism = data.kdf_parallelism;
        } else {
            err!("Argon2 parallelism parameter is required.")
        }
    } else {
        user.client_kdf_memory = None;
        user.client_kdf_parallelism = None;
    }
    user.client_kdf_iter = data.kdf_iterations;
    user.client_kdf_type = data.kdf;
    let conn = DB.get().await.ise()?;
    user.set_password(&data.new_master_password_hash, Some(data.key), true, None, &conn).await?;

    user.save(&conn).await?;

    ws_users().send_logout(&user, &conn, Some(headers.device.uuid)).await?;

    Ok(())
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct UpdateFolderData {
    id: Uuid,
    name: String,
}

use super::ciphers::CipherData;

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct KeyData {
    ciphers: Vec<CipherData>,
    folders: Vec<UpdateFolderData>,
    key: String,
    private_key: String,
    master_password_hash: String,
}

pub async fn post_rotatekey(mut conn: AutoTxn, headers: Headers, data: Json<KeyData>) -> Result<()> {
    let data: KeyData = data.0;

    if !headers.user.check_valid_password(&data.master_password_hash) {
        err!("Invalid password")
    }

    // Validate the import before continuing
    // Bitwarden does not process the import if there is one item invalid.
    // Since we check for the size of the encrypted note length, we need to do that here to pre-validate it.
    // TODO: See if we can optimize the whole cipher adding/importing and prevent duplicate code and checks.
    Cipher::validate_cipher_data(&data.ciphers)?;

    let user_uuid = headers.user.uuid;

    // Update folder data
    for folder_data in data.folders {
        let mut saved_folder = match Folder::get_with_user(&conn, folder_data.id, user_uuid).await? {
            Some(folder) => folder,
            None => err!("Folder doesn't exist"),
        };

        saved_folder.name = folder_data.name;
        saved_folder.save(&conn).await?
    }

    // Update cipher data
    use super::ciphers::update_cipher_from_data;

    for cipher_data in data.ciphers {
        let mut saved_cipher = match Cipher::get_for_user_writable(&conn, user_uuid, cipher_data.id.ok_or(Error::NotFound)?).await? {
            Some(cipher) => cipher,
            None => err!("Cipher doesn't exist"),
        };

        // Prevent triggering cipher updates via WebSockets by settings UpdateType::None
        // The user sessions are invalidated because all the ciphers were re-encrypted and thus triggering an update could cause issues.
        // We force the users to logout after the user has been saved to try and prevent these issues.
        update_cipher_from_data(&mut saved_cipher, cipher_data, &headers, false, &mut conn, UpdateType::None).await?
    }

    // Update user data
    let mut user = headers.user;

    user.akey = data.key;
    user.private_key = Some(data.private_key);
    user.reset_security_stamp(&conn).await?;

    user.save(&conn).await?;

    // Prevent loging out the client where the user requested this endpoint from.
    // If you do logout the user it will causes issues at the client side.
    // Adding the device uuid will prevent this.
    ws_users().send_logout(&user, &conn, Some(headers.device.uuid)).await?;

    conn.commit().await?;
    Ok(())
}

// The current (v2) key-rotation request shape. Bitwarden moved rotation to
// POST /accounts/key-management/rotate-user-account-keys with this body; the legacy
// POST /accounts/key (KeyData / post_rotatekey above) is kept for older clients.
#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct RotateKeyData {
    account_unlock_data: RotateAccountUnlockData,
    account_keys: RotateAccountKeys,
    account_data: RotateAccountData,
    old_master_key_authentication_hash: String,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct RotateAccountUnlockData {
    emergency_access_unlock_data: Vec<RotateEmergencyAccessData>,
    master_password_unlock_data: RotateMasterPasswordUnlockData,
    organization_account_recovery_unlock_data: Vec<RotateResetPasswordData>,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct RotateMasterPasswordUnlockData {
    kdf_type: i32,
    kdf_iterations: i32,
    kdf_parallelism: Option<i32>,
    kdf_memory: Option<i32>,
    email: String,
    master_key_authentication_hash: String,
    master_key_encrypted_user_key: String,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct RotateAccountKeys {
    user_key_encrypted_account_private_key: String,
    account_public_key: String,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct RotateAccountData {
    ciphers: Vec<CipherData>,
    folders: Vec<UpdateFolderData>,
    sends: Vec<super::sends::SendData>,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct RotateEmergencyAccessData {
    id: Uuid,
    key_encrypted: String,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct RotateResetPasswordData {
    organization_id: Uuid,
    reset_password_key: String,
}

pub async fn post_rotate_account_keys(mut conn: AutoTxn, headers: Headers, data: Json<RotateKeyData>) -> Result<()> {
    let RotateKeyData {
        account_unlock_data,
        account_keys,
        account_data,
        old_master_key_authentication_hash,
    } = data.0;
    let RotateAccountUnlockData {
        emergency_access_unlock_data,
        master_password_unlock_data: mpu,
        organization_account_recovery_unlock_data,
    } = account_unlock_data;

    if !headers.user.check_valid_password(&old_master_key_authentication_hash) {
        err!("Invalid password")
    }

    // The KDF settings, email, and asymmetric keypair are not rotated; refuse if the client
    // tries to change them, which would leave the account in an inconsistent state.
    if headers.user.client_kdf_type != mpu.kdf_type
        || headers.user.client_kdf_iter != mpu.kdf_iterations
        || headers.user.client_kdf_memory != mpu.kdf_memory
        || headers.user.client_kdf_parallelism != mpu.kdf_parallelism
        || headers.user.email != mpu.email
    {
        err!("Changing the kdf variant or email is not supported during key rotation")
    }
    if headers.user.public_key.as_ref() != Some(&account_keys.account_public_key) {
        err!("Changing the asymmetric keypair is not possible during key rotation")
    }

    // Validate the ciphers before mutating anything (mirrors the import path).
    Cipher::validate_cipher_data(&account_data.ciphers)?;

    let user_uuid = headers.user.uuid;

    // Re-key folders.
    for folder_data in account_data.folders {
        let mut saved_folder = match Folder::get_with_user(&conn, folder_data.id, user_uuid).await? {
            Some(folder) => folder,
            None => err!("Folder doesn't exist"),
        };
        saved_folder.name = folder_data.name;
        saved_folder.save(&conn).await?;
    }

    // Re-key emergency access grants.
    for ea_data in emergency_access_unlock_data {
        let mut ea = match EmergencyAccess::get_with_grantor(&conn, ea_data.id, user_uuid).await? {
            Some(ea) => ea,
            None => err!("Emergency access doesn't exist or is not owned by the user"),
        };
        ea.key_encrypted = Some(ea_data.key_encrypted);
        ea.save(&conn).await?;
    }

    // Re-key organization account-recovery (reset password) keys.
    for rp_data in organization_account_recovery_unlock_data {
        let mut membership = match UserOrganization::get(&conn, user_uuid, rp_data.organization_id).await? {
            Some(m) => m,
            None => err!("Reset password key doesn't exist"),
        };
        membership.reset_password_key = Some(rp_data.reset_password_key);
        membership.save(&conn).await?;
    }

    // Re-key sends.
    for send_data in account_data.sends {
        let send_id = send_data.id.ok_or(Error::NotFound)?;
        let mut send = match Send::get_for_user(&conn, send_id, user_uuid).await? {
            Some(send) => send,
            None => err!("Send doesn't exist"),
        };
        super::sends::apply_send_rotation(&mut send, send_data)?;
        send.save(&conn).await?;
    }

    // Re-key personal ciphers.
    use super::ciphers::update_cipher_from_data;
    for cipher_data in account_data.ciphers {
        // Only the user's own ciphers are re-keyed; org ciphers use the org key.
        if cipher_data.organization_id.is_some() {
            continue;
        }
        let mut saved_cipher = match Cipher::get_for_user_writable(&conn, user_uuid, cipher_data.id.ok_or(Error::NotFound)?).await? {
            Some(cipher) => cipher,
            None => err!("Cipher doesn't exist"),
        };
        // UpdateType::None: the security stamp is reset below, forcing every other session to
        // re-sync, so per-cipher websocket updates would be redundant and racy.
        update_cipher_from_data(&mut saved_cipher, cipher_data, &headers, false, &mut conn, UpdateType::None).await?;
    }

    // Finally, swap the user's key material and master-password hash.
    let mut user = headers.user;
    user.private_key = Some(account_keys.user_key_encrypted_account_private_key);
    user.set_password(&mpu.master_key_authentication_hash, Some(mpu.master_key_encrypted_user_key), true, None, &conn).await?;
    user.save(&conn).await?;

    // Log every other session out (the session that issued the rotation is spared).
    ws_users().send_logout(&user, &conn, Some(headers.device.uuid)).await?;

    conn.commit().await?;
    Ok(())
}

pub async fn post_sstamp(headers: Headers, conn: AutoTxn, data: Json<PasswordData>) -> Result<()> {
    let data: PasswordData = data.0;
    let mut user = headers.user;

    if data.master_password_hash.as_ref().map(|x| !user.check_valid_password(x)).unwrap_or(false) {
        err!("Invalid password")
    }

    Device::delete_all_by_user(&conn, user.uuid).await?;
    user.reset_security_stamp(&conn).await?;
    user.save(&conn).await?;

    ws_users().send_logout(&user, &conn, None).await?;

    conn.commit().await?;

    Ok(())
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct EmailTokenData {
    master_password_hash: String,
    new_email: String,
}

pub async fn post_email_token(headers: Headers, data: Json<EmailTokenData>) -> Result<()> {
    let data: EmailTokenData = data.0;
    let mut user = headers.user;

    if !user.check_valid_password(&data.master_password_hash) {
        err!("Invalid password")
    }
    let conn = DB.get().await.ise()?;

    if User::find_by_email(&conn, &data.new_email).await?.is_some() {
        err!("Email already in use");
    }

    if !CONFIG.is_email_domain_allowed(&data.new_email) {
        err!("Email domain not allowed");
    }

    let token = crypto::generate_email_token(6);

    if CONFIG.mail_enabled() {
        mail::send_change_email(&data.new_email, &token).await?;
    }

    user.email_new = Some(data.new_email);
    user.email_new_token = Some(token);
    user.save(&conn).await?;
    Ok(())
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ChangeEmailData {
    master_password_hash: String,
    new_email: String,

    key: String,
    new_master_password_hash: String,
    #[serde(deserialize_with = "serde_aux::field_attributes::deserialize_string_from_number")]
    token: String,
}

pub async fn post_email(headers: Headers, data: Json<ChangeEmailData>) -> Result<()> {
    let data: ChangeEmailData = data.0;
    let mut user = headers.user;

    if !user.check_valid_password(&data.master_password_hash) {
        err!("Invalid password")
    }
    let conn = DB.get().await.ise()?;

    if User::find_by_email(&conn, &data.new_email).await?.is_some() {
        err!("Email already in use");
    }

    match user.email_new {
        Some(ref val) => {
            if val != &data.new_email {
                err!("Email change mismatch");
            }
        }
        None => err!("No email change pending"),
    }

    if CONFIG.mail_enabled() {
        // Only check the token if we sent out an email...
        match user.email_new_token {
            Some(ref val) => {
                if *val != data.token {
                    err!("Token mismatch");
                }
            }
            None => err!("No email change pending"),
        }
        user.verified_at = Some(Utc::now());
    } else {
        user.verified_at = None;
    }

    user.email = data.new_email;
    user.email_new = None;
    user.email_new_token = None;

    user.set_password(&data.new_master_password_hash, Some(data.key), true, None, &conn).await?;

    user.save(&conn).await?;

    ws_users().send_logout(&user, &conn, None).await?;

    Ok(())
}

pub async fn post_verify_email(headers: Headers) -> Result<()> {
    let user = headers.user;

    if !CONFIG.mail_enabled() {
        err!("Cannot verify email address");
    }

    if let Err(e) = mail::send_verify_email(&user.email, user.uuid).await {
        error!("Error sending verify_email email: {:#?}", e);
    }

    Ok(())
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct VerifyEmailTokenData {
    user_id: Uuid,
    token: String,
}

pub async fn post_verify_email_token(data: Json<VerifyEmailTokenData>) -> Result<()> {
    let data: VerifyEmailTokenData = data.0;
    let conn = DB.get().await.ise()?;

    let mut user = match User::get(&conn, data.user_id).await? {
        Some(user) => user,
        None => err!("User doesn't exist"),
    };

    let claims = match decode_verify_email(&data.token) {
        Ok(claims) => claims,
        Err(_) => err!("Invalid claim"),
    };

    if claims.sub != user.uuid.to_string() {
        err!("Invalid claim");
    }
    user.verified_at = Some(Utc::now());
    user.last_verifying_at = None;
    user.login_verify_count = 0;
    user.save(&conn).await?;

    Ok(())
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct DeleteRecoverData {
    email: String,
}

pub async fn post_delete_recover(data: Json<DeleteRecoverData>) -> Result<()> {
    let data: DeleteRecoverData = data.0;

    if CONFIG.mail_enabled() {
        let conn = DB.get().await.ise()?;

        if let Some(user) = User::find_by_email(&conn, &data.email).await?
            && let Err(e) = mail::send_delete_account(&user.email, user.uuid).await
        {
            error!("Error sending delete account email: {:#?}", e);
        }
        Ok(())
    } else {
        // We don't support sending emails, but we shouldn't allow anybody
        // to delete accounts without at least logging in... And if the user
        // cannot remember their password then they will need to contact
        // the administrator to delete it...
        err!("Please contact the administrator to delete your account");
    }
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct DeleteRecoverTokenData {
    user_id: Uuid,
    token: String,
}

pub async fn post_delete_recover_token(data: Json<DeleteRecoverTokenData>) -> Result<()> {
    let data: DeleteRecoverTokenData = data.0;
    let conn = DB.get().await.ise()?;

    let user = match User::get(&conn, data.user_id).await? {
        Some(user) => user,
        None => err!("User doesn't exist"),
    };

    let claims = match decode_delete(&data.token) {
        Ok(claims) => claims,
        Err(_) => err!("Invalid claim"),
    };
    if claims.sub != user.uuid.to_string() {
        err!("Invalid claim");
    }
    user.delete(&conn).await?;
    Ok(())
}

pub async fn delete_account(headers: Headers, data: Json<PasswordData>) -> Result<()> {
    let data: PasswordData = data.0;
    let user = headers.user;

    user.check_valid_password_data(&data)?;
    let conn = DB.get().await.ise()?;

    user.delete(&conn).await?;
    Ok(())
}

pub async fn revision_date(headers: Headers) -> Result<Json<Value>> {
    let conn = DB.get().await.ise()?;
    let revision_date = headers.user.last_revision(&conn).await?.timestamp_millis();
    Ok(Json(json!(revision_date)))
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct PasswordHintData {
    email: String,
}

pub async fn password_hint(data: Json<PasswordHintData>) -> Result<()> {
    if !CONFIG.mail_enabled() && !CONFIG.settings.show_password_hint {
        err!("This server is not configured to provide password hints.");
    }

    const NO_HINT: &str = "Sorry, you have no password hint...";

    let data: PasswordHintData = data.0;
    let email = &data.email;
    let conn = DB.get().await.ise()?;

    match User::find_by_email(&conn, email).await? {
        None => {
            // To prevent user enumeration, act as if the user exists.
            if CONFIG.mail_enabled() {
                // There is still a timing side channel here in that the code
                // paths that send mail take noticeably longer than ones that
                // don't. Add a randomized sleep to mitigate this somewhat.
                use rand::RngExt;
                let delta: i32 = 100;
                let sleep_ms = (1_000 + rand::rng().random_range(-delta..=delta)) as u64;
                tokio::time::sleep(tokio::time::Duration::from_millis(sleep_ms)).await;
                Ok(())
            } else {
                err!(NO_HINT);
            }
        }
        Some(user) => {
            let hint: Option<String> = user.password_hint;
            if CONFIG.mail_enabled() {
                mail::send_password_hint(email, hint).await?;
                Ok(())
            } else if let Some(hint) = hint {
                err!(format!("Your password hint is: {hint}"));
            } else {
                err!(NO_HINT);
            }
        }
    }
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct PreloginData {
    email: String,
}

pub async fn prelogin(data: Json<PreloginData>) -> Result<Json<Value>> {
    let data: PreloginData = data.0;
    let conn = DB.get().await.ise()?;

    let (kdf_type, kdf_iter, kdf_mem, kdf_para) = match User::find_by_email(&conn, &data.email).await? {
        Some(user) => (user.client_kdf_type, user.client_kdf_iter, user.client_kdf_memory, user.client_kdf_parallelism),
        None => (User::CLIENT_KDF_TYPE_DEFAULT, User::CLIENT_KDF_ITER_DEFAULT, None, None),
    };

    let result = json!({
        // Legacy flat fields (kept for older clients).
        "kdf": kdf_type,
        "kdfIterations": kdf_iter,
        "kdfMemory": kdf_mem,
        "kdfParallelism": kdf_para,
        // Newer clients read the nested settings + salt. BW currently just echoes the
        // request email as the salt (the client re-derives from it).
        "kdfSettings": {
            "kdfType": kdf_type,
            "iterations": kdf_iter,
            "memory": kdf_mem,
            "parallelism": kdf_para,
        },
        "salt": data.email.trim().to_lowercase(),
    });

    Ok(Json(result))
}

// https://github.com/bitwarden/server/blob/master/src/Api/Models/Request/Accounts/SecretVerificationRequestModel.cs
#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct SecretVerificationRequest {
    master_password_hash: String,
}

pub async fn _api_key(data: Json<SecretVerificationRequest>, rotate: bool, headers: Headers) -> Result<Json<Value>> {
    use crate::util::format_date;

    let data: SecretVerificationRequest = data.0;
    let mut user = headers.user;

    if !user.check_valid_password(&data.master_password_hash) {
        err!("Invalid password")
    }

    let conn = DB.get().await.ise()?;
    if rotate || user.api_key.is_none() {
        user.api_key = Some(crypto::generate_api_key());

        user.save(&conn).await?;
    }

    let revision = user.last_revision(&conn).await?;
    Ok(Json(json!({
      "apiKey": user.api_key,
      "revisionDate": format_date(&revision),
      "object": "apiKey",
    })))
}

pub async fn api_key(headers: Headers, data: Json<SecretVerificationRequest>) -> Result<Json<Value>> {
    _api_key(data, false, headers).await
}

pub async fn rotate_api_key(headers: Headers, data: Json<SecretVerificationRequest>) -> Result<Json<Value>> {
    _api_key(data, true, headers).await
}

#[derive(Deserialize)]
pub struct KnownDevicePath {
    email: String,
    uuid: Uuid,
}

// This variant is deprecated: https://github.com/bitwarden/server/pull/2682
pub async fn get_known_device_from_path(Path(path): Path<KnownDevicePath>) -> Result<Json<Value>> {
    // This endpoint doesn't have auth header
    let mut result = false;
    let conn = DB.get().await.ise()?;
    if let Some(user) = User::find_by_email(&conn, &path.email).await? {
        result = Device::find_by_uuid_and_user(&conn, path.uuid, user.uuid).await?.is_some();
    }
    Ok(Json(json!(result)))
}

pub async fn get_known_device(device: KnownDevice) -> Result<Json<Value>> {
    get_known_device_from_path(Path(KnownDevicePath {
        email: device.email,
        uuid: device.uuid,
    }))
    .await
}

pub struct KnownDevice {
    email: String,
    uuid: Uuid,
}

#[async_trait::async_trait]
impl<'a> FromRequestParts<'a> for KnownDevice {
    async fn from_request_parts(req: RequestPartsRef<'a>) -> Result<Self> {
        let email = if let Some(email_b64) = req.headers.get("x-request-email") {
            let email_bytes = match data_encoding::BASE64URL_NOPAD.decode(email_b64.as_bytes()) {
                Ok(bytes) => bytes,
                Err(_) => {
                    return Err(Error::bad_request("X-Request-Email value failed to decode as base64url"));
                }
            };
            match String::from_utf8(email_bytes) {
                Ok(email) => email,
                Err(_) => {
                    return Err(Error::bad_request("X-Request-Email value failed to decode as UTF-8"));
                }
            }
        } else {
            return Err(Error::bad_request("X-Request-Email value is required"));
        };

        let uuid = if let Some(uuid) = req.headers.get("x-device-identifier").and_then(|x| Uuid::from_str(x).ok()) {
            uuid
        } else {
            return Err(Error::bad_request("X-Device-Identifier value is required"));
        };

        Ok(KnownDevice {
            email,
            uuid,
        })
    }
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct PushToken {
    push_token: String,
}

pub async fn put_device_token(Path(uuid): Path<Uuid>, headers: Headers, data: Json<PushToken>) -> Result<()> {
    if CONFIG.push.is_none() {
        return Ok(());
    }
    let conn = DB.get().await.ise()?;

    let data = data.0;
    let token = data.push_token;
    let mut device = match Device::find_by_uuid_and_user(&conn, headers.device.uuid, headers.user.uuid).await? {
        Some(device) => device,
        None => err!(format!("Error: device {uuid} should be present before a token can be assigned")),
    };
    device.push_token = Some(token);
    if device.push_uuid.is_none() {
        device.push_uuid = Some(Uuid::new_v4());
    }
    device.save(&conn).await?;
    register_push_device(headers.user.uuid, device).await?;

    Ok(())
}

pub async fn put_clear_device_token(Path(uuid): Path<Uuid>) -> Result<()> {
    // This only clears push token
    // https://github.com/bitwarden/core/blob/master/src/Api/Controllers/DevicesController.cs#L109
    // https://github.com/bitwarden/core/blob/master/src/Core/Services/Implementations/DeviceService.cs#L37
    // This is somehow not implemented in any app, added it in case it is required
    if CONFIG.push.is_none() {
        return Ok(());
    }
    let conn = DB.get().await.ise()?;

    if let Some(device) = Device::get(&conn, uuid).await? {
        Device::clear_push_token_by_uuid(&conn, uuid).await?;
        unregister_push_device(device.uuid).await?;
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use serde_json::json;

    use crate::test_harness::TestClient;

    #[tokio::test]
    async fn register_then_login_returns_token() {
        let mut client = TestClient::new().await;
        client.register().await;
        client.login().await;

        // login() only succeeds if it got an access_token and could load the profile.
        assert!(client.user_id.is_some(), "expected a user id after login");
    }

    #[tokio::test]
    async fn profile_reflects_registered_user() {
        let client = TestClient::register_and_login().await;

        let resp = client.get("/api/accounts/profile").await;
        resp.assert_ok();
        let profile = resp.json();
        assert_eq!(profile["email"].as_str().unwrap().to_lowercase(), client.email.to_lowercase());
        assert_eq!(profile["object"], "profile");
        // A6: newer clients read structured accountKeys, verifyDevices, and organizationsNew.
        assert_eq!(profile["accountKeys"]["object"], "privateKeys");
        assert!(profile["verifyDevices"].is_boolean(), "profile should carry verifyDevices");
        assert!(profile["organizationsNew"].is_array(), "profile should carry organizationsNew");
        // A11: a normal account is not under an admin-forced password reset.
        assert_eq!(profile["forcePasswordReset"], false);
    }

    #[tokio::test]
    async fn profile_requires_authentication() {
        // An unauthenticated client (no token) must be rejected.
        let client = TestClient::new().await;
        client.get("/api/accounts/profile").await.assert_status(401);
    }

    #[tokio::test]
    async fn login_with_wrong_password_is_rejected() {
        let mut client = TestClient::new().await;
        client.register().await;

        let form = [
            ("grant_type", "password"),
            ("username", client.email.as_str()),
            ("password", "definitely-not-the-hash"),
            ("scope", "api offline_access"),
            ("client_id", "web"),
            ("device_identifier", client.device_id.as_str()),
            ("device_name", "test-harness"),
            ("device_type", "14"),
        ];
        let resp = client.post_form("/identity/connect/token", &form).await;
        assert!(resp.status >= 400, "expected auth failure, got {}: {}", resp.status, resp.body);
    }

    #[tokio::test]
    async fn prelogin_returns_kdf_settings() {
        let client = TestClient::register_and_login().await;

        let resp = client.post("/identity/accounts/prelogin", json!({ "email": client.email })).await;
        resp.assert_ok();
        let body = resp.json();
        // Pbkdf2 == 0, which is what the harness registers with.
        assert_eq!(body["kdf"], 0);
        assert!(body["kdfIterations"].as_i64().unwrap() >= 100_000);
        // A5: newer clients read the nested kdfSettings + salt (the normalized email).
        assert_eq!(body["kdfSettings"]["kdfType"], 0);
        assert_eq!(body["kdfSettings"]["iterations"], body["kdfIterations"]);
        assert_eq!(body["salt"], client.email.to_lowercase());
    }

    #[tokio::test]
    async fn prelogin_password_alias_returns_kdf_settings() {
        // Newer web-vault clients POST to /accounts/prelogin/password instead of
        // /accounts/prelogin; both must hit the same handler.
        let client = TestClient::register_and_login().await;

        let resp = client.post("/identity/accounts/prelogin/password", json!({ "email": client.email })).await;
        resp.assert_ok();
        let body = resp.json();
        assert_eq!(body["kdf"], 0);
        assert!(body["kdfIterations"].as_i64().unwrap() >= 100_000);
    }

    #[tokio::test]
    async fn duplicate_registration_is_rejected() {
        let mut client = TestClient::new().await;
        client.register().await;

        // Registering the same email again (already has a password) must fail.
        let body = json!({
            "email": client.email,
            "kdf": 0,
            "kdfIterations": 600_000,
            "key": client.akey,
            "masterPasswordHash": client.master_password_hash,
            "name": "Dup",
        });
        let resp = client.post("/identity/accounts/register", body).await;
        assert!(resp.status >= 400, "expected duplicate registration to fail, got {}: {}", resp.status, resp.body);
    }

    #[tokio::test]
    async fn register_v2_credential_body_round_trips() {
        // A4: newer clients send the v2 nested credential body (masterPasswordAuthentication +
        // masterPasswordUnlock) instead of the flat masterPasswordHash/key. It must register an
        // account that then logs in with the same hash.
        let mut client = TestClient::new().await;
        let email = client.email.to_lowercase();
        let body = json!({
            "email": client.email,
            "masterPasswordAuthentication": {
                "kdf": { "kdfType": 0, "iterations": 600_000 },
                "salt": email,
                "masterPasswordAuthenticationHash": client.master_password_hash,
            },
            "masterPasswordUnlock": {
                "kdf": { "kdfType": 0, "iterations": 600_000 },
                "salt": email,
                "masterKeyWrappedUserKey": client.akey,
            },
            "userAsymmetricKeys": { "encryptedPrivateKey": client.private_key, "publicKey": client.public_key },
            "name": "V2 User",
        });
        client.post("/identity/accounts/register", body).await.assert_ok();

        client.login().await;
        assert!(client.user_id.is_some(), "v2-registered account should log in");
    }

    #[tokio::test]
    async fn register_v2_rejects_salt_email_mismatch() {
        // A4: the v2 body carries the salt twice and it must equal the account email.
        let client = TestClient::new().await;
        let body = json!({
            "email": client.email,
            "masterPasswordAuthentication": {
                "kdf": { "kdfType": 0, "iterations": 600_000 },
                "salt": "someone-else@test.example",
                "masterPasswordAuthenticationHash": client.master_password_hash,
            },
            "masterPasswordUnlock": {
                "kdf": { "kdfType": 0, "iterations": 600_000 },
                "salt": "someone-else@test.example",
                "masterKeyWrappedUserKey": client.akey,
            },
            "userAsymmetricKeys": { "encryptedPrivateKey": client.private_key, "publicKey": client.public_key },
            "name": "V2 Bad",
        });
        let resp = client.post("/identity/accounts/register", body).await;
        assert!(resp.status >= 400, "salt/email mismatch should be rejected, got {}: {}", resp.status, resp.body);
    }

    /// Log in via the password grant with an arbitrary password hash, returning the
    /// raw token response. Used to assert credential changes take effect.
    async fn login_with_password(client: &TestClient, password: &str) -> crate::test_harness::TestResponse {
        let form = [
            ("grant_type", "password"),
            ("username", client.email.as_str()),
            ("password", password),
            ("scope", "api offline_access"),
            ("client_id", "web"),
            ("device_identifier", client.device_id.as_str()),
            ("device_name", "test-harness"),
            ("device_type", "14"),
        ];
        client.post_form("/identity/connect/token", &form).await
    }

    #[tokio::test]
    async fn update_profile_name() {
        let client = TestClient::register_and_login().await;

        let resp = client.post("/api/accounts/profile", json!({ "name": "Renamed User" })).await;
        resp.assert_ok();
        assert_eq!(resp.json()["name"], "Renamed User");

        // Persisted across a fresh read.
        let profile = client.get("/api/accounts/profile").await;
        assert_eq!(profile.json()["name"], "Renamed User");
    }

    #[tokio::test]
    async fn update_profile_rejects_overlong_name() {
        let client = TestClient::register_and_login().await;
        let long = "x".repeat(51);
        let resp = client.post("/api/accounts/profile", json!({ "name": long })).await;
        assert!(resp.status >= 400, "51-char name should be rejected, got {}: {}", resp.status, resp.body);
    }

    #[tokio::test]
    async fn set_avatar_color() {
        let client = TestClient::register_and_login().await;

        let resp = client.put("/api/accounts/avatar", json!({ "avatarColor": "#abcdef" })).await;
        resp.assert_ok();
        assert_eq!(resp.json()["avatarColor"], "#abcdef");

        // Must be a 7-char hex code.
        let bad = client.put("/api/accounts/avatar", json!({ "avatarColor": "#abc" })).await;
        assert!(bad.status >= 400, "short color should be rejected, got {}: {}", bad.status, bad.body);
    }

    #[tokio::test]
    async fn get_user_public_key() {
        let client = TestClient::register_and_login().await;
        let uid = client.user_id.unwrap();

        let resp = client.get(&format!("/api/users/{uid}/public-key")).await;
        resp.assert_ok();
        let j = resp.json();
        assert_eq!(j["userId"], uid.to_string());
        assert_eq!(j["publicKey"], client.public_key);
        assert_eq!(j["object"], "userKey");
    }

    #[tokio::test]
    async fn update_encryption_keys() {
        let client = TestClient::register_and_login().await;

        let resp = client.post("/api/accounts/keys", json!({ "encryptedPrivateKey": "2.newpriv|mac", "publicKey": "newpublickey" })).await;
        resp.assert_ok();
        let j = resp.json();
        assert_eq!(j["privateKey"], "2.newpriv|mac");
        assert_eq!(j["publicKey"], "newpublickey");
        // A7: newer clients read the wrapped user key + structured accountKeys.
        assert!(j["key"].as_str().is_some(), "keys response should include the wrapped user key");
        assert_eq!(j["accountKeys"]["object"], "privateKeys");
        assert_eq!(j["accountKeys"]["publicKeyEncryptionKeyPair"]["publicKey"], "newpublickey");
        assert_eq!(j["accountKeys"]["publicKeyEncryptionKeyPair"]["wrappedPrivateKey"], "2.newpriv|mac");
    }

    #[tokio::test]
    async fn revision_date_is_a_timestamp() {
        let client = TestClient::register_and_login().await;
        let resp = client.get("/api/accounts/revision-date").await;
        resp.assert_ok();
        assert!(resp.json().as_i64().is_some(), "revision date should be a number: {}", resp.body);
    }

    #[tokio::test]
    async fn api_key_get_and_rotate() {
        let client = TestClient::register_and_login().await;

        // Wrong password is rejected.
        let bad = client.post("/api/accounts/api-key", json!({ "masterPasswordHash": "wrong" })).await;
        assert!(bad.status >= 400, "wrong password should be rejected, got {}: {}", bad.status, bad.body);

        let first = client.post("/api/accounts/api-key", json!({ "masterPasswordHash": client.master_password_hash })).await;
        first.assert_ok();
        let key1 = first.json()["apiKey"].as_str().expect("apiKey").to_string();
        assert!(!key1.is_empty());

        // Fetching again returns the same key.
        let again = client.post("/api/accounts/api-key", json!({ "masterPasswordHash": client.master_password_hash })).await;
        assert_eq!(again.json()["apiKey"].as_str().unwrap(), key1);

        // Rotating replaces it.
        let rotated = client.post("/api/accounts/rotate-api-key", json!({ "masterPasswordHash": client.master_password_hash })).await;
        rotated.assert_ok();
        assert_ne!(rotated.json()["apiKey"].as_str().unwrap(), key1, "rotate should change the key");
    }

    #[tokio::test]
    async fn change_password_updates_login() {
        let client = TestClient::register_and_login().await;
        let new_hash = "new-master-password-hash";

        // Wrong current password is rejected.
        let bad = client
            .post(
                "/api/accounts/password",
                json!({ "masterPasswordHash": "wrong", "newMasterPasswordHash": new_hash, "key": client.akey, "masterPasswordHint": null }),
            )
            .await;
        assert!(bad.status >= 400, "wrong current password should be rejected, got {}: {}", bad.status, bad.body);

        let body = json!({
            "masterPasswordHash": client.master_password_hash,
            "newMasterPasswordHash": new_hash,
            "key": client.akey,
            "masterPasswordHint": null,
        });
        client.post("/api/accounts/password", body).await.assert_ok();

        // Old password no longer logs in; new one does.
        let old = login_with_password(&client, &client.master_password_hash).await;
        assert!(old.status >= 400, "old password should fail after change, got {}: {}", old.status, old.body);
        let new = login_with_password(&client, new_hash).await;
        new.assert_ok();
        assert!(new.json()["access_token"].as_str().is_some());
    }

    #[tokio::test]
    async fn change_kdf_settings() {
        let client = TestClient::register_and_login().await;
        let new_hash = "kdf-changed-hash";

        let body = json!({
            "kdf": 0, // Pbkdf2
            "kdfIterations": 200_000,
            "masterPasswordHash": client.master_password_hash,
            "newMasterPasswordHash": new_hash,
            "key": client.akey,
        });
        client.post("/api/accounts/kdf", body).await.assert_ok();

        // Prelogin reflects the new iteration count.
        let pre = client.post("/identity/accounts/prelogin", json!({ "email": client.email })).await;
        assert_eq!(pre.json()["kdfIterations"], 200_000);

        // The new password (bound to the new KDF) logs in.
        login_with_password(&client, new_hash).await.assert_ok();
    }

    #[tokio::test]
    async fn security_stamp_invalidates_existing_token() {
        let client = TestClient::register_and_login().await;
        client.get("/api/accounts/profile").await.assert_ok();

        client.post("/api/accounts/security-stamp", json!({ "masterPasswordHash": client.master_password_hash })).await.assert_ok();

        // The old access token's embedded security stamp is now stale.
        client.get("/api/accounts/profile").await.assert_status(401);
    }

    #[tokio::test]
    async fn delete_account_removes_user() {
        let client = TestClient::register_and_login().await;

        // Wrong password is rejected.
        let bad = client.post("/api/accounts/delete", json!({ "masterPasswordHash": "wrong" })).await;
        assert!(bad.status >= 400, "wrong password should be rejected, got {}: {}", bad.status, bad.body);

        client.post("/api/accounts/delete", json!({ "masterPasswordHash": client.master_password_hash })).await.assert_ok();

        // The user can no longer log in.
        let after = login_with_password(&client, &client.master_password_hash).await;
        assert!(after.status >= 400, "deleted user should not log in, got {}: {}", after.status, after.body);
    }

    #[tokio::test]
    async fn auth_request_approve_and_login() {
        // Login-with-device (passwordless) flow, all against one already-registered
        // device: create request → approve → poll response → log in via the request.
        let client = TestClient::register_and_login().await;
        let access_code = "test-access-code-123";

        let create = client
            .post(
                "/api/auth-requests",
                json!({ "accessCode": access_code, "deviceIdentifier": client.device_id, "email": client.email, "publicKey": "authreqpubkey" }),
            )
            .await;
        create.assert_ok();
        let req_id = create.json()["id"].as_str().expect("auth request id").to_string();

        // Appears in the pending list before approval.
        let pending = client.get("/api/auth-requests/pending").await;
        pending.assert_ok();
        let pending_ids: Vec<String> = pending.json()["data"].as_array().unwrap().iter().filter_map(|r| r["id"].as_str().map(String::from)).collect();
        assert!(pending_ids.contains(&req_id), "new request should be pending: {}", pending.body);

        // Approve from the authenticated device, handing back the wrapped key.
        let approve = client
            .put(
                &format!("/api/auth-requests/{req_id}"),
                json!({ "deviceIdentifier": client.device_id, "key": "2.userkey|mac", "masterPasswordHash": client.master_password_hash, "requestApproved": true }),
            )
            .await;
        approve.assert_ok();
        assert_eq!(approve.json()["requestApproved"], true);

        // The requester polls the response using its access code.
        let response = client.get(&format!("/api/auth-requests/{req_id}/response?code={access_code}")).await;
        response.assert_ok();
        assert_eq!(response.json()["key"], "2.userkey|mac");

        // Log in using the approved request (password field carries the access code).
        let form = [
            ("grant_type", "password"),
            ("username", client.email.as_str()),
            ("password", access_code),
            ("scope", "api offline_access"),
            ("client_id", "web"),
            ("device_identifier", client.device_id.as_str()),
            ("device_name", "test-harness"),
            ("device_type", "14"),
            ("authRequest", req_id.as_str()),
        ];
        let login = client.post_form("/identity/connect/token", &form).await;
        login.assert_ok();
        assert!(login.json()["access_token"].as_str().is_some(), "auth-request login should yield a token: {}", login.body);
    }

    #[tokio::test]
    async fn auth_request_denied_is_deleted() {
        let client = TestClient::register_and_login().await;

        let create = client
            .post("/api/auth-requests", json!({ "accessCode": "code", "deviceIdentifier": client.device_id, "email": client.email, "publicKey": "pk" }))
            .await;
        create.assert_ok();
        let req_id = create.json()["id"].as_str().unwrap().to_string();

        let deny = client
            .put(&format!("/api/auth-requests/{req_id}"), json!({ "deviceIdentifier": client.device_id, "key": "2.k|mac", "requestApproved": false }))
            .await;
        deny.assert_ok();

        // A denied request is removed.
        let after = client.get(&format!("/api/auth-requests/{req_id}")).await;
        assert!(after.status >= 400, "denied auth request should be gone, got {}: {}", after.status, after.body);
    }

    // Two-step (email-verified) registration: send-verification-email hands back a token when
    // mail is disabled, and register/finish consumes it to create a working account.
    #[tokio::test]
    async fn two_step_registration_finish() {
        let client = TestClient::new().await;
        let email = client.email.clone();

        // Step 1: request a verification token (mail disabled -> returned in the body).
        let verify = client.post("/identity/accounts/register/send-verification-email", json!({ "email": email, "name": "Two Step" })).await;
        verify.assert_ok();
        let token = verify.json().as_str().expect("token returned as a JSON string").to_string();
        assert!(!token.is_empty(), "verification token should not be empty: {}", verify.body);

        // Step 2: finish registration with the token (name is recovered from the token).
        let finish = client
            .post(
                "/identity/accounts/register/finish",
                json!({
                    "email": email,
                    "emailVerificationToken": token,
                    "kdf": 0,
                    "kdfIterations": 600_000,
                    "key": client.akey,
                    "keys": { "encryptedPrivateKey": client.private_key, "publicKey": client.public_key },
                    "masterPasswordHash": client.master_password_hash,
                }),
            )
            .await;
        finish.assert_ok();

        // Step 3: the account works.
        let form = [
            ("grant_type", "password"),
            ("username", email.as_str()),
            ("password", client.master_password_hash.as_str()),
            ("scope", "api offline_access"),
            ("client_id", "web"),
            ("device_identifier", client.device_id.as_str()),
            ("device_name", "test-harness"),
            ("device_type", "14"),
        ];
        let login = client.post_form("/identity/connect/token", &form).await;
        login.assert_ok();
        assert!(login.json()["access_token"].as_str().is_some(), "should log in after two-step registration: {}", login.body);
    }

    // A finish token whose email doesn't match the registration email is rejected.
    #[tokio::test]
    async fn two_step_registration_rejects_mismatched_token() {
        let alice = TestClient::new().await;
        let verify = alice.post("/identity/accounts/register/send-verification-email", json!({ "email": alice.email, "name": "Alice" })).await;
        verify.assert_ok();
        let token = verify.json().as_str().unwrap().to_string();

        // Reuse Alice's token to try to register a different email.
        let bob = TestClient::new().await;
        let finish = bob
            .post(
                "/identity/accounts/register/finish",
                json!({
                    "email": bob.email,
                    "emailVerificationToken": token,
                    "kdf": 0,
                    "kdfIterations": 600_000,
                    "key": bob.akey,
                    "keys": { "encryptedPrivateKey": bob.private_key, "publicKey": bob.public_key },
                    "masterPasswordHash": bob.master_password_hash,
                }),
            )
            .await;
        assert!(finish.status >= 400, "a token for a different email must be rejected, got {}: {}", finish.status, finish.body);
    }

    // The v2 key-rotation endpoint re-keys the user's key material and vault items, then the
    // new master-password hash must authenticate and return the rotated user key.
    #[tokio::test]
    async fn rotate_account_keys_v2_relogs_in_with_new_key() {
        let client = TestClient::register_and_login().await;
        let folder_id = client.create_folder("2.myfolder|mac").await;
        let cipher_id = client.create_login_cipher("2.mylogin|mac").await["id"].as_str().unwrap().to_string();

        let body = json!({
            "oldMasterKeyAuthenticationHash": client.master_password_hash,
            "accountUnlockData": {
                "emergencyAccessUnlockData": [],
                "organizationAccountRecoveryUnlockData": [],
                // KDF/email must match the account's current values (rotation doesn't change them).
                "masterPasswordUnlockData": {
                    "kdfType": 0,
                    "kdfIterations": 600_000,
                    "kdfMemory": null,
                    "kdfParallelism": null,
                    "email": client.email,
                    "masterKeyAuthenticationHash": "2.new-master-hash|mac",
                    "masterKeyEncryptedUserKey": "2.newuserkey|mac"
                }
            },
            "accountKeys": {
                "userKeyEncryptedAccountPrivateKey": "2.newprivkey|mac",
                // The asymmetric public key is unchanged.
                "accountPublicKey": client.public_key
            },
            "accountData": {
                "ciphers": [ { "id": cipher_id, "type": 1, "name": "2.mylogin|mac", "key": "2.newcipherkey|mac", "login": { "username": "2.u|mac", "password": "2.p|mac" }, "lastKnownRevisionDate": null } ],
                "folders": [ { "id": folder_id, "name": "2.myfolder|mac" } ],
                "sends": []
            }
        });
        client.post("/api/accounts/key-management/rotate-user-account-keys", body).await.assert_ok();

        // Rotation resets the security stamp, so the old session is gone. Log in with the new
        // master-password hash; the response should carry the rotated user key.
        let form = [
            ("grant_type", "password"),
            ("username", client.email.as_str()),
            ("password", "2.new-master-hash|mac"),
            ("scope", "api offline_access"),
            ("client_id", "web"),
            ("device_identifier", client.device_id.as_str()),
            ("device_name", "test-harness"),
            ("device_type", "14"),
        ];
        let login = client.post_form("/identity/connect/token", &form).await;
        login.assert_ok();
        assert_eq!(login.json()["Key"], "2.newuserkey|mac", "login after rotation should return the rotated user key: {}", login.body);

        // The old master-password hash no longer authenticates.
        let stale = [
            ("grant_type", "password"),
            ("username", client.email.as_str()),
            ("password", client.master_password_hash.as_str()),
            ("scope", "api offline_access"),
            ("client_id", "web"),
            ("device_identifier", client.device_id.as_str()),
            ("device_name", "test-harness"),
            ("device_type", "14"),
        ];
        let rejected = client.post_form("/identity/connect/token", &stale).await;
        assert!(rejected.status >= 400, "old master password must not authenticate after rotation, got {}: {}", rejected.status, rejected.body);
    }
}
