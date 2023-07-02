use axum::{routing, Json, Router};
use axum_util::errors::{ApiError, ApiResult};
use chrono::Utc;
use data_encoding::BASE32;
use serde::Deserialize;
use serde_json::{json, Value};

use crate::{
    api::PasswordData,
    auth::{ClientHeaders, Headers},
    crypto,
    db::{Conn, EventType, OrgPolicyType, Organization, TwoFactor, TwoFactorType, User, UserOrgType, UserOrganization, DB},
    events::log_user_event,
    mail,
    util::Upcase,
    CONFIG,
};

pub mod authenticator;
pub mod duo;
pub mod email;
pub mod webauthn;
pub mod yubikey;

pub fn route(router: Router) -> Router {
    router
        .route("/two-factor", routing::get(get_twofactor))
        .route("/two-factor/get-recover", routing::post(get_recover))
        .route("/two-factor/recover", routing::post(recover))
        .route("/two-factor/disable", routing::post(disable_twofactor))
        .route("/two-factor/disable", routing::put(disable_twofactor))
        .route("/two-factor/get-device-verification-settings", routing::get(get_device_verification_settings))
        .route("/two-factor/send-email-login", routing::post(email::send_email_login))
        .route("/two-factor/get-email", routing::post(email::get_email))
        .route("/two-factor/send-email", routing::post(email::send_email))
        .route("/two-factor/email", routing::put(email::email))
        .route("/two-factor/get-authenticator", routing::post(authenticator::generate_authenticator))
        .route("/two-factor/authenticator", routing::post(authenticator::activate_authenticator))
        .route("/two-factor/authenticator", routing::put(authenticator::activate_authenticator))
        .route("/two-factor/get-yubikey", routing::post(yubikey::generate_yubikey))
        .route("/two-factor/yubikey", routing::post(yubikey::activate_yubikey))
        .route("/two-factor/yubikey", routing::put(yubikey::activate_yubikey))
        .route("/two-factor/get-webauthn", routing::post(webauthn::get_webauthn))
        .route("/two-factor/webauthn", routing::post(webauthn::activate_webauthn))
        .route("/two-factor/webauthn", routing::put(webauthn::activate_webauthn))
        .route("/two-factor/webauthn", routing::delete(webauthn::delete_webauthn))
        .route("/two-factor/get-webauthn-challenge", routing::post(webauthn::generate_webauthn_challenge))
        .route("/two-factor/get-duo", routing::post(duo::get_duo))
        .route("/two-factor/duo", routing::post(duo::activate_duo))
        .route("/two-factor/duo", routing::put(duo::activate_duo))
}

pub async fn get_twofactor(headers: Headers) -> ApiResult<Json<Value>> {
    let conn = DB.get().await?;
    let twofactors = TwoFactor::find_by_user_official(&conn, headers.user.uuid).await?;
    let twofactors_json: Vec<Value> = twofactors.iter().map(TwoFactor::to_json_provider).collect();

    Ok(Json(json!({
        "Data": twofactors_json,
        "Object": "list",
        "ContinuationToken": null,
    })))
}

pub async fn get_recover(headers: Headers, data: Json<Upcase<PasswordData>>) -> ApiResult<Json<Value>> {
    let data: PasswordData = data.0.data;
    let user = headers.user;

    if !user.check_valid_password(&data.master_password_hash) {
        err!("Invalid password");
    }

    Ok(Json(json!({
        "Code": user.totp_recover,
        "Object": "twoFactorRecover"
    })))
}

#[derive(Deserialize)]
#[serde(rename_all = "PascalCase")]
pub struct RecoverTwoFactor {
    master_password_hash: String,
    email: String,
    recovery_code: String,
}

pub async fn recover(client_headers: ClientHeaders, data: Json<Upcase<RecoverTwoFactor>>) -> ApiResult<Json<Value>> {
    let data: RecoverTwoFactor = data.0.data;
    let mut conn = DB.get().await?;

    // Get the user
    let mut user = match User::find_by_email(&conn, &data.email).await? {
        Some(user) => user,
        None => err!("Username or password is incorrect. Try again."),
    };

    // Check password
    if !user.check_valid_password(&data.master_password_hash) {
        err!("Username or password is incorrect. Try again.")
    }

    // Check if recovery code is correct
    if !user.check_valid_recovery_code(&data.recovery_code) {
        err!("Recovery code is incorrect. Try again.")
    }

    // Remove all twofactors from the user
    TwoFactor::delete_all_by_user(&conn, user.uuid).await?;

    log_user_event(EventType::UserRecovered2fa, user.uuid, client_headers.device_type, Utc::now(), client_headers.ip.ip, &mut conn).await?;

    // Remove the recovery code, not needed without twofactors
    user.totp_recover = None;
    user.save(&conn).await?;
    Ok(Json(Value::Object(serde_json::Map::new())))
}

pub async fn _generate_recover_code(user: &mut User, conn: &Conn) -> ApiResult<()> {
    if user.totp_recover.is_none() {
        let totp_recover = crypto::encode_random_bytes::<20>(BASE32);
        user.totp_recover = Some(totp_recover);
        user.save(conn).await?;
    }
    Ok(())
}

#[derive(Deserialize)]
#[serde(rename_all = "PascalCase")]
pub struct DisableTwoFactorData {
    master_password_hash: String,
    #[serde(deserialize_with = "serde_aux::field_attributes::deserialize_number_from_string")]
    r#type: i32,
}

pub async fn disable_twofactor(headers: Headers, data: Json<Upcase<DisableTwoFactorData>>) -> ApiResult<Json<Value>> {
    let data: DisableTwoFactorData = data.0.data;
    let password_hash = data.master_password_hash;
    let user = headers.user;

    if !user.check_valid_password(&password_hash) {
        err!("Invalid password");
    }

    let type_ = TwoFactorType::from_repr(data.r#type).ok_or(ApiError::NotFound)?;
    let mut conn = DB.get().await?;

    if let Some(twofactor) = TwoFactor::find_by_user_and_type(&conn, user.uuid, type_).await? {
        twofactor.delete(&conn).await?;
        log_user_event(EventType::UserDisabled2fa, user.uuid, headers.device.atype, Utc::now(), headers.ip, &mut conn).await?;
    }

    let twofactor_disabled = TwoFactor::find_by_user_official(&conn, user.uuid).await?.is_empty();

    if twofactor_disabled {
        for user_org in UserOrganization::find_by_user_and_policy(&conn, user.uuid, OrgPolicyType::TwoFactorAuthentication).await?.into_iter() {
            if user_org.atype < UserOrgType::Admin {
                if CONFIG.mail_enabled() {
                    let org = Organization::get(&conn, user_org.organization_uuid).await?.ok_or(ApiError::NotFound)?;
                    mail::send_2fa_removed_from_org(&user.email, &org.name).await?;
                }
                user_org.delete(&mut conn).await?;
            }
        }
    }

    Ok(Json(json!({
        "Enabled": false,
        "Type": type_,
        "Object": "twoFactorProvider"
    })))
}

// This function currently is just a dummy and the actual part is not implemented yet.
// This also prevents 404 errors.
//
// See the following Bitwarden PR's regarding this feature.
// https://github.com/bitwarden/clients/pull/2843
// https://github.com/bitwarden/clients/pull/2839
// https://github.com/bitwarden/server/pull/2016
//
// The HTML part is hidden via the CSS patches done via the bw_web_build repo
pub async fn get_device_verification_settings(_headers: Headers) -> Json<Value> {
    Json(json!({
        "isDeviceVerificationSectionEnabled":false,
        "unknownDeviceVerificationEnabled":false,
        "object":"deviceVerificationSettings"
    }))
}
