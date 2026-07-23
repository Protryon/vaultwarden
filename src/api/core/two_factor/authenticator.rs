use std::net::IpAddr;

use axol::prelude::*;
use chrono::{DateTime, Duration, Utc};
use data_encoding::BASE32;
use log::warn;
use serde::Deserialize;
use serde_json::{Value, json};
use uuid::Uuid;

use crate::{
    api::PasswordData,
    auth::Headers,
    crypto,
    db::{Conn, DB, Event, EventType, TwoFactor, TwoFactorType},
    events::log_user_event,
};

pub use crate::config::CONFIG;

use super::_generate_recover_code;

pub async fn generate_authenticator(headers: Headers, data: Json<PasswordData>) -> Result<Json<Value>> {
    let data: PasswordData = data.0;
    let user = headers.user;

    user.check_valid_password_data(&data)?;

    let conn = DB.get().await.ise()?;

    let twofactor = TwoFactor::find_by_user_and_type(&conn, user.uuid, TwoFactorType::Authenticator).await?;

    let (enabled, key) = match twofactor {
        Some(tf) => (true, tf.data.as_str().unwrap_or_default().to_string()),
        _ => (false, crypto::encode_random_bytes::<20>(BASE32)),
    };

    Ok(Json(json!({
        "enabled": enabled,
        "key": key,
        "object": "twoFactorAuthenticator"
    })))
}

#[derive(Deserialize, Debug)]
#[serde(rename_all = "camelCase")]
pub struct EnableAuthenticatorData {
    master_password_hash: String,
    key: String,
    #[serde(deserialize_with = "serde_aux::field_attributes::deserialize_string_from_number")]
    token: String,
}

pub async fn activate_authenticator(headers: Headers, data: Json<EnableAuthenticatorData>) -> Result<Json<Value>> {
    let data: EnableAuthenticatorData = data.0;
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
    let mut conn = DB.get().await.ise()?;

    // Validate the token provided with the key, and save new twofactor
    validate_totp_code(user.uuid, &token, Value::String(key.to_uppercase()), headers.ip, &conn).await?;

    _generate_recover_code(&mut user, &conn).await?;

    log_user_event(EventType::UserUpdated2fa, user.uuid, headers.device.atype, Utc::now(), headers.ip, &mut conn).await?;

    Ok(Json(json!({
        "enabled": true,
        "key": key,
        "object": "twoFactorAuthenticator"
    })))
}

pub async fn validate_totp_code_str(user_uuid: Uuid, totp_code: &str, secret: Value, ip: IpAddr, conn: &Conn) -> Result<()> {
    if !totp_code.chars().all(char::is_numeric) {
        err!("TOTP code is not a number");
    }

    validate_totp_code(user_uuid, totp_code, secret, ip, conn).await
}

pub async fn validate_totp_code(user_uuid: Uuid, totp_code: &str, secret: Value, ip: IpAddr, conn: &Conn) -> Result<()> {
    use totp_lite::{Sha1, totp_custom};

    let decoded_secret = match secret.as_str().map(|x| BASE32.decode(x.as_bytes())) {
        Some(Ok(s)) => s,
        Some(Err(_)) | None => err!("Invalid TOTP secret"),
    };

    let mut twofactor = match TwoFactor::find_by_user_and_type(conn, user_uuid, TwoFactorType::Authenticator).await? {
        Some(tf) => tf,
        // `secret` is already a `Value::String` holding the base32 key; store it
        // as-is. Wrapping it in `Value::String(secret.to_string())` would
        // JSON-encode the string a second time and corrupt the stored secret.
        _ => TwoFactor::new(user_uuid, TwoFactorType::Authenticator, secret),
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
            twofactor.last_used = Some(DateTime::from_timestamp(time_step * 30, 0).expect("timestamp overflow"));
            twofactor.save(conn).await?;
            return Ok(());
        } else if generated == totp_code && time_step <= last_used {
            warn!("This TOTP or a TOTP code within {} steps back or forward has already been used!", steps);
            Event::new(EventType::UserFailedLogIn2fa, None).with_user_uuid(user_uuid).save(conn).await?;
            err!(format!("Invalid TOTP code! Server time: {} IP: {}", current_time.format("%F %T UTC"), ip));
        }
    }

    // Else no valid code received, deny access
    Event::new(EventType::UserFailedLogIn2fa, None).with_user_uuid(user_uuid).save(conn).await?;
    err!(format!("Invalid TOTP code! Server time: {} IP: {}", current_time.format("%F %T UTC"), ip));
}

#[cfg(test)]
mod tests {
    use serde_json::json;

    use crate::test_harness::{TestClient, totp_code};

    /// Password-grant login form fields; extend with 2FA fields as needed.
    fn login_form<'a>(client: &'a TestClient, extra: &'a [(&'a str, &'a str)]) -> Vec<(&'a str, &'a str)> {
        let mut form = vec![
            ("grant_type", "password"),
            ("username", client.email.as_str()),
            ("password", client.master_password_hash.as_str()),
            ("scope", "api offline_access"),
            ("client_id", "web"),
            ("device_identifier", client.device_id.as_str()),
            ("device_name", "test-harness"),
            ("device_type", "14"),
        ];
        form.extend_from_slice(extra);
        form
    }

    #[tokio::test]
    async fn enable_authenticator_and_list() {
        let client = TestClient::register_and_login().await;
        let secret = client.enable_totp().await;
        assert!(!secret.is_empty());

        // It now shows in the 2FA provider list (type 0 = Authenticator).
        let list = client.get("/api/two-factor").await;
        list.assert_ok();
        let types: Vec<i64> = list.json()["data"].as_array().unwrap().iter().filter_map(|p| p["type"].as_i64()).collect();
        assert!(types.contains(&0), "authenticator should be listed: {}", list.body);
    }

    #[tokio::test]
    async fn activate_authenticator_rejects_bad_token() {
        let client = TestClient::register_and_login().await;
        let gen_resp = client.post("/api/two-factor/get-authenticator", json!({ "masterPasswordHash": client.master_password_hash })).await;
        gen_resp.assert_ok();
        let secret = gen_resp.json()["key"].as_str().unwrap().to_string();

        let bad = client
            .post("/api/two-factor/authenticator", json!({ "masterPasswordHash": client.master_password_hash, "key": secret, "token": "000000" }))
            .await;
        assert!(bad.status >= 400, "wrong TOTP code should be rejected, got {}: {}", bad.status, bad.body);
    }

    #[tokio::test]
    async fn login_requires_totp_then_succeeds() {
        let client = TestClient::register_and_login().await;
        let secret = client.enable_totp().await;

        // A fresh login without a 2FA token is refused and advertises the providers.
        let no2fa = client.post_form("/identity/connect/token", &login_form(&client, &[])).await;
        assert!(no2fa.status >= 400, "login without 2FA should fail, got {}: {}", no2fa.status, no2fa.body);
        assert!(no2fa.body.contains("TwoFactorProviders"), "should list 2FA providers: {}", no2fa.body);

        // A code for the next window (the current one was consumed on activation) works.
        let code = totp_code(&secret, 1);
        let ok = client.post_form("/identity/connect/token", &login_form(&client, &[("twoFactorProvider", "0"), ("twoFactorToken", code.as_str())])).await;
        ok.assert_ok();
        assert!(ok.json()["access_token"].as_str().is_some(), "2FA login should yield a token: {}", ok.body);
    }

    #[tokio::test]
    async fn disable_authenticator() {
        let client = TestClient::register_and_login().await;
        client.enable_totp().await;

        let resp = client.post("/api/two-factor/disable", json!({ "masterPasswordHash": client.master_password_hash, "type": 0 })).await;
        resp.assert_ok();
        assert_eq!(resp.json()["enabled"], false);

        // The provider list is empty again.
        let list = client.get("/api/two-factor").await;
        list.assert_ok();
        assert!(list.json()["data"].as_array().unwrap().is_empty(), "2FA list should be empty after disable: {}", list.body);
    }

    #[tokio::test]
    async fn recover_removes_twofactor() {
        let client = TestClient::register_and_login().await;
        client.enable_totp().await;

        // Fetch the recovery code generated on activation.
        let rec = client.post("/api/two-factor/get-recover", json!({ "masterPasswordHash": client.master_password_hash })).await;
        rec.assert_ok();
        // The server compares against the lowercased stored code, so clients send
        // the recovery code lowercased.
        let recovery_code = rec.json()["code"].as_str().expect("recovery code").to_lowercase();
        assert!(!recovery_code.is_empty());

        // Recover (an unauthenticated endpoint) clears all 2FA.
        let recover = client
            .post("/api/two-factor/recover", json!({ "masterPasswordHash": client.master_password_hash, "email": client.email, "recoveryCode": recovery_code }))
            .await;
        recover.assert_ok();

        let list = client.get("/api/two-factor").await;
        list.assert_ok();
        assert!(list.json()["data"].as_array().unwrap().is_empty(), "2FA should be cleared after recover: {}", list.body);
    }
}
