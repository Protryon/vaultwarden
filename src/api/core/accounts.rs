use std::str::FromStr;

use axol::prelude::*;
use chrono::Utc;
use log::error;
use serde::Deserialize;
use serde_json::{json, Value};
use uuid::Uuid;

use crate::{
    api::{ws_users, PasswordData, UpdateType},
    auth::{decode_delete, decode_invite, decode_verify_email, Headers},
    crypto,
    db::{Cipher, Device, EmergencyAccess, EventType, Folder, Invitation, User, UserKdfType, UserOrgStatus, UserOrganization, DB},
    events::log_user_event,
    mail,
    push::{register_push_device, unregister_push_device},
    util::AutoTxn,
    CONFIG,
};

pub fn route(router: Router) -> Router {
    router
        .post("/accounts/register", register)
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
        .post("/accounts/api-key", api_key)
        .post("/accounts/rotate-api-key", rotate_api_key)
}

#[derive(Deserialize, Debug)]
#[serde(rename_all = "camelCase")]
pub struct RegisterData {
    email: String,
    kdf: Option<i32>,
    kdf_iterations: Option<i32>,
    kdf_memory: Option<i32>,
    kdf_parallelism: Option<i32>,
    key: String,
    keys: Option<KeysData>,
    master_password_hash: String,
    master_password_hint: Option<String>,
    name: Option<String>,
    token: Option<String>,
    #[allow(dead_code)]
    organization_user_id: Option<String>,
}

#[derive(Deserialize, Debug)]
#[serde(rename_all = "camelCase")]
pub struct SetPasswordData {
    kdf: Option<i32>,
    kdf_iterations: Option<i32>,
    kdf_memory: Option<i32>,
    kdf_parallelism: Option<i32>,
    key: String,
    keys: Option<KeysData>,
    master_password_hash: String,
    master_password_hint: Option<String>,
    #[allow(dead_code)]
    #[serde(rename = "orgIdentifier")]
    org_identifier: Option<String>,
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
    let data: RegisterData = data.0;
    let email = data.email.to_lowercase();

    // Check if the length of the username exceeds 50 characters (Same is Upstream Bitwarden)
    // This also prevents issues with very long usernames causing to large JWT's. See #2419
    if let Some(ref name) = data.name {
        if name.len() > 50 {
            err!("The field Name must be a string with a maximum length of 50.");
        }
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

    if let Some(client_kdf_type) = data.kdf {
        user.client_kdf_type = client_kdf_type;
    }

    if let Some(client_kdf_iter) = data.kdf_iterations {
        user.client_kdf_iter = client_kdf_iter;
    }

    user.client_kdf_memory = data.kdf_memory;
    user.client_kdf_parallelism = data.kdf_parallelism;

    user.set_password(&data.master_password_hash, Some(data.key), true, None);
    user.password_hint = password_hint;

    // Add extra fields if present
    if let Some(name) = data.name {
        user.name = name;
    }

    if let Some(keys) = data.keys {
        user.private_key = Some(keys.encrypted_private_key);
        user.public_key = Some(keys.public_key);
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

pub async fn post_set_password(headers: Headers, data: Json<SetPasswordData>) -> Result<Json<Value>> {
    let data: SetPasswordData = data.0;
    let mut user = headers.user;
    let conn = DB.get().await.ise()?;

    // Check against the password hint setting here so if it fails, the user
    // can retry without losing their invitation below.
    let password_hint = clean_password_hint(&data.master_password_hint);
    enforce_password_hint_setting(&password_hint)?;

    if let Some(client_kdf_iter) = data.kdf_iterations {
        user.client_kdf_iter = client_kdf_iter;
    }

    if let Some(client_kdf_type) = data.kdf {
        user.client_kdf_type = client_kdf_type;
    }

    //We need to allow revision-date to use the old security_timestamp
    let routes = vec!["revision_date"];
    let routes: Option<Vec<String>> = Some(routes.iter().map(ToString::to_string).collect());

    user.client_kdf_memory = data.kdf_memory;
    user.client_kdf_parallelism = data.kdf_parallelism;

    user.set_password(&data.master_password_hash, Some(data.key), false, routes);
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
    if let Some(color) = &data.avatar_color {
        if color.len() != 7 {
            err!("The field AvatarColor must be a HTML/Hex color code with a length of 7 characters")
        }
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
        "privateKey": user.private_key,
        "publicKey": user.public_key,
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
    let mut conn = DB.get().await.ise()?;

    log_user_event(EventType::UserChangedPassword, user.uuid, headers.device.atype, Utc::now(), headers.ip, &mut conn).await?;

    user.set_password(
        &data.new_master_password_hash,
        Some(data.key),
        true,
        Some(vec![String::from("post_rotatekey"), String::from("get_contacts"), String::from("get_public_keys")]),
    );

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
    user.set_password(&data.new_master_password_hash, Some(data.key), true, None);
    let conn = DB.get().await.ise()?;

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
    user.reset_security_stamp();

    user.save(&conn).await?;

    // Prevent loging out the client where the user requested this endpoint from.
    // If you do logout the user it will causes issues at the client side.
    // Adding the device uuid will prevent this.
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
    user.reset_security_stamp();
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

    user.set_password(&data.new_master_password_hash, Some(data.key), true, None);

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

        if let Some(user) = User::find_by_email(&conn, &data.email).await? {
            if let Err(e) = mail::send_delete_account(&user.email, user.uuid).await {
                error!("Error sending delete account email: {:#?}", e);
            }
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
                use rand::{rngs::SmallRng, Rng, SeedableRng};
                let mut rng = SmallRng::from_entropy();
                let delta: i32 = 100;
                let sleep_ms = (1_000 + rng.gen_range(-delta..=delta)) as u64;
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
        "kdf": kdf_type,
        "kdfIterations": kdf_iter,
        "kdfMemory": kdf_mem,
        "kdfParallelism": kdf_para,
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
