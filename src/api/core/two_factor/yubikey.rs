use axol::prelude::*;
use chrono::Utc;
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use yubico::{config::Config, verify};

use crate::{
    api::PasswordData,
    auth::Headers,
    db::{EventType, TwoFactor, TwoFactorType, DB},
    error::MapResult,
    events::log_user_event,
    CONFIG,
};

use super::_generate_recover_code;

#[derive(Deserialize, Debug)]
#[serde(rename_all = "camelCase")]
pub struct EnableYubikeyData {
    master_password_hash: String,
    key1: Option<String>,
    key2: Option<String>,
    key3: Option<String>,
    key4: Option<String>,
    key5: Option<String>,
    nfc: bool,
}

#[derive(Clone, Deserialize, Serialize, Debug)]
#[serde(rename_all = "camelCase")]
pub struct YubikeyMetadata {
    keys: Vec<String>,
    pub nfc: bool,
}

fn parse_yubikeys(data: &EnableYubikeyData) -> Vec<String> {
    let data_keys = [&data.key1, &data.key2, &data.key3, &data.key4, &data.key5];

    data_keys.iter().filter_map(|e| e.as_ref().cloned()).collect()
}

fn jsonify_yubikeys(yubikeys: Vec<String>) -> serde_json::Value {
    let mut result = Value::Object(serde_json::Map::new());

    for (i, key) in yubikeys.into_iter().enumerate() {
        result[format!("Key{}", i + 1)] = Value::String(key);
    }

    result
}

fn get_yubico_credentials() -> Result<(Option<String>, String, String)> {
    let Some(yubico) = CONFIG.yubico.as_ref() else {
        err!("Yubico support is disabled");
    };

    Ok((yubico.server.as_ref().map(|x| x.to_string()), yubico.client_id.clone(), yubico.secret_key.clone()))
}

async fn verify_yubikey_otp(otp: String) -> Result<()> {
    let (server, yubico_id, yubico_secret) = get_yubico_credentials()?;

    let config = Config::default().set_client_id(yubico_id).set_key(yubico_secret);

    match server {
        Some(server) => tokio::task::spawn_blocking(move || verify(otp, config.set_api_hosts(vec![server]))).await.ise()?,
        None => tokio::task::spawn_blocking(move || verify(otp, config)).await.ise()?,
    }
    .map_res("Failed to verify OTP")?;
    Ok(())
}

pub async fn generate_yubikey(headers: Headers, data: Json<PasswordData>) -> Result<Json<Value>> {
    // Make sure the credentials are set
    get_yubico_credentials()?;

    let data: PasswordData = data.0;
    let user = headers.user;

    user.check_valid_password_data(&data)?;

    let user_uuid = user.uuid;
    let conn = DB.get().await.ise()?;

    let r = TwoFactor::find_by_user_and_type(&conn, user_uuid, TwoFactorType::YubiKey).await?;

    if let Some(r) = r {
        let yubikey_metadata: YubikeyMetadata = serde_json::from_value(r.data).ise()?;

        let mut result = jsonify_yubikeys(yubikey_metadata.keys);

        result["enabled"] = Value::Bool(true);
        result["nfc"] = Value::Bool(yubikey_metadata.nfc);
        result["object"] = Value::String("twoFactorU2f".to_owned());

        Ok(Json(result))
    } else {
        Ok(Json(json!({
            "enabled": false,
            "object": "twoFactorU2f",
        })))
    }
}

pub async fn activate_yubikey(headers: Headers, data: Json<EnableYubikeyData>) -> Result<Json<Value>> {
    let data: EnableYubikeyData = data.0;
    let mut user = headers.user;

    if !user.check_valid_password(&data.master_password_hash) {
        err!("Invalid password");
    }
    let mut conn = DB.get().await.ise()?;

    // Check if we already have some data
    let mut yubikey_data = match TwoFactor::find_by_user_and_type(&conn, user.uuid, TwoFactorType::YubiKey).await? {
        Some(data) => data,
        None => TwoFactor::new(user.uuid.clone(), TwoFactorType::YubiKey, Value::Null),
    };

    let yubikeys = parse_yubikeys(&data);

    if yubikeys.is_empty() {
        return Ok(Json(json!({
            "enabled": false,
            "object": "twoFactorU2f",
        })));
    }

    // Ensure they are valid OTPs
    for yubikey in &yubikeys {
        if yubikey.len() == 12 {
            // YubiKey ID
            continue;
        }

        verify_yubikey_otp(yubikey.to_owned()).await?;
    }

    let yubikey_ids: Vec<String> = yubikeys.into_iter().map(|x| (x[..12]).to_owned()).collect();

    let yubikey_metadata = YubikeyMetadata {
        keys: yubikey_ids,
        nfc: data.nfc,
    };

    yubikey_data.data = serde_json::to_value(yubikey_metadata.clone()).ise()?;
    yubikey_data.save(&mut conn).await?;

    _generate_recover_code(&mut user, &conn).await?;

    log_user_event(EventType::UserUpdated2fa, user.uuid, headers.device.atype, Utc::now(), headers.ip, &mut conn).await?;

    let mut result = jsonify_yubikeys(yubikey_metadata.keys);

    result["enabled"] = Value::Bool(true);
    result["nfc"] = Value::Bool(yubikey_metadata.nfc);
    result["object"] = Value::String("twoFactorU2f".to_owned());

    Ok(Json(result))
}

pub async fn validate_yubikey_login(response: &str, twofactor_data: Value) -> Result<()> {
    if response.len() != 44 {
        err!("Invalid Yubikey OTP length");
    }

    let yubikey_metadata: YubikeyMetadata = serde_json::from_value(twofactor_data).ise()?;
    let response_id = &response[..12];

    if !yubikey_metadata.keys.contains(&response_id.to_owned()) {
        err!("Given Yubikey is not registered");
    }

    let result = verify_yubikey_otp(response.to_owned()).await;

    match result {
        Ok(_answer) => Ok(()),
        Err(_e) => err!("Failed to verify Yubikey against OTP server"),
    }
}
