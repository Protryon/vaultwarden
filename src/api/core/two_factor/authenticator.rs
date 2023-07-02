use std::net::IpAddr;

use axum::Json;
use axum_util::errors::ApiResult;
use chrono::{Duration, NaiveDateTime, Utc};
use data_encoding::BASE32;
use log::warn;
use serde::Deserialize;
use serde_json::{json, Value};
use uuid::Uuid;

use crate::{
    api::PasswordData,
    auth::Headers,
    crypto,
    db::{Conn, EventType, TwoFactor, TwoFactorType, DB},
    events::log_user_event,
    util::Upcase,
};

pub use crate::config::CONFIG;

use super::_generate_recover_code;

pub async fn generate_authenticator(headers: Headers, data: Json<Upcase<PasswordData>>) -> ApiResult<Json<Value>> {
    let data: PasswordData = data.0.data;
    let user = headers.user;

    if !user.check_valid_password(&data.master_password_hash) {
        err!("Invalid password");
    }

    let conn = DB.get().await?;

    let twofactor = TwoFactor::find_by_user_and_type(&conn, user.uuid, TwoFactorType::Authenticator).await?;

    let (enabled, key) = match twofactor {
        Some(tf) => (true, tf.data.as_str().unwrap_or_default().to_string()),
        _ => (false, crypto::encode_random_bytes::<20>(BASE32)),
    };

    Ok(Json(json!({
        "Enabled": enabled,
        "Key": key,
        "Object": "twoFactorAuthenticator"
    })))
}

#[derive(Deserialize, Debug)]
#[serde(rename_all = "PascalCase")]
pub struct EnableAuthenticatorData {
    master_password_hash: String,
    key: String,
    #[serde(deserialize_with = "serde_aux::field_attributes::deserialize_string_from_number")]
    token: String,
}

pub async fn activate_authenticator(headers: Headers, data: Json<Upcase<EnableAuthenticatorData>>) -> ApiResult<Json<Value>> {
    let data: EnableAuthenticatorData = data.0.data;
    let password_hash = data.master_password_hash;
    let key = data.key;
    let token = data.token;

    let mut user = headers.user;

    if !user.check_valid_password(&password_hash) {
        err!("Invalid password");
    }

    // Validate key as base32 and 20 bytes length
    let decoded_key: Vec<u8> = match BASE32.decode(key.as_bytes()) {
        Ok(decoded) => decoded,
        _ => err!("Invalid totp secret"),
    };

    if decoded_key.len() != 20 {
        err!("Invalid key length")
    }
    let mut conn = DB.get().await?;

    // Validate the token provided with the key, and save new twofactor
    validate_totp_code(user.uuid, &token, Value::String(key.to_uppercase()), headers.ip, &conn).await?;

    _generate_recover_code(&mut user, &conn).await?;

    log_user_event(EventType::UserUpdated2fa, user.uuid, headers.device.atype, Utc::now(), headers.ip, &mut conn).await?;

    Ok(Json(json!({
        "Enabled": true,
        "Key": key,
        "Object": "twoFactorAuthenticator"
    })))
}

pub async fn validate_totp_code_str(user_uuid: Uuid, totp_code: &str, secret: Value, ip: IpAddr, conn: &Conn) -> ApiResult<()> {
    if !totp_code.chars().all(char::is_numeric) {
        err!("TOTP code is not a number");
    }

    validate_totp_code(user_uuid, totp_code, secret, ip, conn).await
}

pub async fn validate_totp_code(user_uuid: Uuid, totp_code: &str, secret: Value, ip: IpAddr, conn: &Conn) -> ApiResult<()> {
    use totp_lite::{totp_custom, Sha1};

    let decoded_secret = match secret.as_str().map(|x| BASE32.decode(x.as_bytes())) {
        Some(Ok(s)) => s,
        Some(Err(_)) | None => err!("Invalid TOTP secret"),
    };

    let mut twofactor = match TwoFactor::find_by_user_and_type(conn, user_uuid, TwoFactorType::Authenticator).await? {
        Some(tf) => tf,
        _ => TwoFactor::new(user_uuid, TwoFactorType::Authenticator, Value::String(secret.to_string())),
    };

    // The amount of steps back and forward in time
    // Also check if we need to disable time drifted TOTP codes.
    // If that is the case, we set the steps to 0 so only the current TOTP is valid.
    let steps = i64::from(!CONFIG.advanced.authenticator_disable_time_drift);

    // Get the current system time in UNIX Epoch (UTC)
    let current_time = Utc::now();
    let current_timestamp = current_time.timestamp();
    let last_used = twofactor.last_used.unwrap_or_else(|| Utc::now() - Duration::seconds(60)).timestamp() / 30i64;

    for step in -steps..=steps {
        let time_step = current_timestamp / 30i64 + step;

        // We need to calculate the time offsite and cast it as an u64.
        // Since we only have times into the future and the totp generator needs an u64 instead of the default i64.
        let time = (current_timestamp + step * 30i64) as u64;
        let generated = totp_custom::<Sha1>(30, 6, &decoded_secret, time);

        // Check the the given code equals the generated and if the time_step is larger then the one last used.
        if generated == totp_code && time_step > last_used {
            // If the step does not equals 0 the time is drifted either server or client side.
            if step != 0 {
                warn!("TOTP Time drift detected. The step offset is {}", step);
            }

            // Save the last used time step so only totp time steps higher then this one are allowed.
            // This will also save a newly created twofactor if the code is correct.
            twofactor.last_used = Some(NaiveDateTime::from_timestamp_opt(time_step * 30, 0).expect("timestamp overflow").and_utc());
            twofactor.save(conn).await?;
            return Ok(());
        } else if generated == totp_code && time_step <= last_used {
            warn!("This TOTP or a TOTP code within {} steps back or forward has already been used!", steps);
            err!(
                format!("Invalid TOTP code! Server time: {} IP: {}", current_time.format("%F %T UTC"), ip),
                ErrorEvent {
                    event: EventType::UserFailedLogIn2fa
                }
            );
        }
    }

    // Else no valide code received, deny access
    err!(
        format!("Invalid TOTP code! Server time: {} IP: {}", current_time.format("%F %T UTC"), ip),
        ErrorEvent {
            event: EventType::UserFailedLogIn2fa
        }
    );
}
