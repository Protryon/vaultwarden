use axol::prelude::*;
use chrono::Utc;
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use url::Url;
use uuid::Uuid;

use crate::{
    CONFIG,
    api::PasswordData,
    auth::Headers,
    crypto,
    db::{Conn, DB, EventType, TwoFactor, TwoFactorType, User},
    error::MapResult,
    events::log_user_event,
    util::get_reqwest_client,
};

use super::{_generate_recover_code, UserVerify, mint_user_verification_token};

#[derive(Clone, Serialize, Deserialize)]
struct DuoData {
    host: Url,               // Duo API hostname
    integration_key: String, // integration key
    secret_key: String,      // secret key
}

impl DuoData {
    fn global() -> Option<Self> {
        CONFIG.duo.as_ref().map(|duo| Self {
            host: duo.server.clone(),
            integration_key: duo.integration_key.clone(),
            secret_key: duo.secret_key.clone(),
        })
    }
    fn msg(s: &str) -> Self {
        Self {
            host: Url::parse("http://none").unwrap(),
            integration_key: s.into(),
            secret_key: s.into(),
        }
    }
    fn secret() -> Self {
        Self::msg("<global_secret>")
    }
    fn obscure(self) -> Self {
        let host = self.host;
        let mut integration_key = self.integration_key;
        let mut secret_key = self.secret_key;

        let digits = 4;
        let replaced = "************";

        integration_key.replace_range(digits.., replaced);
        secret_key.replace_range(digits.., replaced);

        Self {
            host,
            integration_key,
            secret_key,
        }
    }
}

enum DuoStatus {
    Global(DuoData),
    // Using the global duo config
    User(DuoData),
    // Using the user's config
    Disabled(bool), // True if there is a global setting
}

impl DuoStatus {
    fn data(self) -> Option<DuoData> {
        match self {
            DuoStatus::Global(data) => Some(data),
            DuoStatus::User(data) => Some(data),
            DuoStatus::Disabled(_) => None,
        }
    }
}

const DISABLED_MESSAGE_DEFAULT: &str = "<To use the global Duo keys, please leave these fields untouched>";

pub async fn get_duo(headers: Headers, data: Json<PasswordData>) -> Result<Json<Value>> {
    let data: PasswordData = data.0;

    headers.user.check_valid_password_data(&data)?;
    let conn = DB.get().await.ise()?;

    let data = get_user_duo_data(headers.user.uuid, &conn).await?;

    let (enabled, data) = match data {
        DuoStatus::Global(_) => (true, Some(DuoData::secret())),
        DuoStatus::User(data) => (true, Some(data.obscure())),
        DuoStatus::Disabled(true) => (false, Some(DuoData::msg(DISABLED_MESSAGE_DEFAULT))),
        DuoStatus::Disabled(false) => (false, None),
    };

    // Duo Universal wire format: `clientId`/`clientSecret` (was `integrationKey`/`secretKey`).
    let uv_token = mint_user_verification_token(headers.user.uuid, TwoFactorType::Duo);
    let json = if let Some(data) = data {
        json!({
            "enabled": enabled,
            "host": data.host,
            "clientSecret": data.secret_key,
            "clientId": data.integration_key,
            "userVerificationToken": uv_token,
            "object": "twoFactorDuo"
        })
    } else {
        json!({
            "enabled": enabled,
            "host": null,
            "clientSecret": null,
            "clientId": null,
            "userVerificationToken": uv_token,
            "object": "twoFactorDuo"
        })
    };

    Ok(Json(json))
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct EnableDuoData {
    #[serde(flatten)]
    verify: UserVerify,
    host: Url,
    client_secret: String,
    client_id: String,
}

impl From<EnableDuoData> for DuoData {
    fn from(d: EnableDuoData) -> Self {
        Self {
            host: d.host,
            integration_key: d.client_id,
            secret_key: d.client_secret,
        }
    }
}

fn check_duo_fields_custom(data: &EnableDuoData) -> bool {
    fn empty_or_default(s: &str) -> bool {
        let st = s.trim();
        st.is_empty() || s == DISABLED_MESSAGE_DEFAULT
    }

    !empty_or_default(&data.client_secret) && !empty_or_default(&data.client_id)
}

pub async fn activate_duo(headers: Headers, data: Json<EnableDuoData>) -> Result<Json<Value>> {
    let data: EnableDuoData = data.0;
    let mut user = headers.user;

    data.verify.validate(&user, TwoFactorType::Duo)?;

    let (data, data_str) = if check_duo_fields_custom(&data) {
        let data_req: DuoData = data.into();
        let data_str = serde_json::to_value(data_req.clone()).ise()?;
        duo_api_request("GET", "/auth/v2/check", "", &data_req).await?;
        (data_req.obscure(), data_str)
    } else {
        (DuoData::secret(), Value::Null)
    };

    let mut conn = DB.get().await.ise()?;

    let twofactor = TwoFactor::new(user.uuid, TwoFactorType::Duo, data_str);
    twofactor.save(&conn).await?;

    _generate_recover_code(&mut user, &conn).await?;

    log_user_event(EventType::UserUpdated2fa, user.uuid, headers.device.atype, Utc::now(), headers.ip, &mut conn).await?;

    Ok(Json(json!({
        "enabled": true,
        "host": data.host,
        "clientSecret": data.secret_key,
        "clientId": data.integration_key,
        "object": "twoFactorDuo"
    })))
}

async fn duo_api_request(method: &str, path: &str, params: &str, data: &DuoData) -> Result<()> {
    use reqwest::{Method, header};
    use std::str::FromStr;

    // https://duo.com/docs/authapi#api-details
    let url = format!("https://{}{}", &data.host, path);
    let date = Utc::now().to_rfc2822();
    let username = &data.integration_key;
    let fields = [&date, method, data.host.as_ref(), path, params];
    let password = crypto::hmac_sign(&data.secret_key, &fields.join("\n"));

    let m = Method::from_str(method).unwrap_or_default();

    let client = get_reqwest_client();

    client
        .request(m, &url)
        .basic_auth(username, Some(password))
        .header(header::USER_AGENT, "vaultwarden:Duo/1.0 (Rust)")
        .header(header::DATE, date)
        .send()
        .await
        .ise()?
        .error_for_status()
        .ise()?;

    Ok(())
}

async fn get_user_duo_data(uuid: Uuid, conn: &Conn) -> Result<DuoStatus> {
    // If the user doesn't have an entry, disabled
    let twofactor = match TwoFactor::find_by_user_and_type(conn, uuid, TwoFactorType::Duo).await? {
        Some(t) => t,
        None => return Ok(DuoStatus::Disabled(DuoData::global().is_some())),
    };

    // If the user has the required values, we use those
    if let Ok(data) = serde_json::from_value(twofactor.data) {
        return Ok(DuoStatus::User(data));
    }

    // Otherwise, we try to use the globals
    if let Some(global) = DuoData::global() {
        return Ok(DuoStatus::Global(global));
    }

    // If there are no globals configured, just disable it
    Ok(DuoStatus::Disabled(false))
}

// let (ik, sk, ak, host) = get_duo_keys();
// Duo Universal (OIDC) only needs (client_id, client_secret, host); the app_key is retained in the
// tuple for signature compatibility but ignored by the OIDC flow (see `duo_oidc`).
pub async fn get_duo_keys_email(email: &str, conn: &Conn) -> Result<(String, String, String, Url)> {
    let data = match User::find_by_email(conn, email).await? {
        Some(u) => get_user_duo_data(u.uuid, conn).await?.data(),
        _ => DuoData::global(),
    }
    .map_res("Can't fetch Duo Keys")?;

    Ok((data.integration_key, data.secret_key, CONFIG.duo.as_ref().map(|x| x.app_key.clone()).ok_or(Error::NotFound)?, data.host))
}
