use axum::Json;
use axum_util::errors::{ApiError, ApiResult};
use chrono::Utc;
use data_encoding::BASE64;
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use url::Url;
use uuid::Uuid;

use crate::{
    api::PasswordData,
    auth::Headers,
    crypto,
    db::{Conn, EventType, TwoFactor, TwoFactorType, User, DB},
    error::MapResult,
    events::log_user_event,
    util::{get_reqwest_client, Upcase},
    CONFIG,
};

use super::_generate_recover_code;

#[derive(Clone, Serialize, Deserialize)]
struct DuoData {
    host: Url,               // Duo API hostname
    integration_key: String, // integration key
    secret_key: String,      // secret key
}

impl DuoData {
    fn global() -> Option<Self> {
        match CONFIG.duo.as_ref() {
            Some(duo) => Some(Self {
                host: duo.server.clone(),
                integration_key: duo.integration_key.clone(),
                secret_key: duo.secret_key.clone(),
            }),
            _ => None,
        }
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

pub async fn get_duo(headers: Headers, data: Json<Upcase<PasswordData>>) -> ApiResult<Json<Value>> {
    let data: PasswordData = data.0.data;

    if !headers.user.check_valid_password(&data.master_password_hash) {
        err!("Invalid password");
    }
    let conn = DB.get().await?;

    let data = get_user_duo_data(headers.user.uuid, &conn).await?;

    let (enabled, data) = match data {
        DuoStatus::Global(_) => (true, Some(DuoData::secret())),
        DuoStatus::User(data) => (true, Some(data.obscure())),
        DuoStatus::Disabled(true) => (false, Some(DuoData::msg(DISABLED_MESSAGE_DEFAULT))),
        DuoStatus::Disabled(false) => (false, None),
    };

    let json = if let Some(data) = data {
        json!({
            "Enabled": enabled,
            "Host": data.host,
            "SecretKey": data.secret_key,
            "IntegrationKey": data.integration_key,
            "Object": "twoFactorDuo"
        })
    } else {
        json!({
            "Enabled": enabled,
            "Object": "twoFactorDuo"
        })
    };

    Ok(Json(json))
}

#[derive(Deserialize)]
#[allow(dead_code)]
#[serde(rename_all = "PascalCase")]
pub struct EnableDuoData {
    master_password_hash: String,
    host: Url,
    secret_key: String,
    integration_key: String,
}

impl From<EnableDuoData> for DuoData {
    fn from(d: EnableDuoData) -> Self {
        Self {
            host: d.host,
            integration_key: d.integration_key,
            secret_key: d.secret_key,
        }
    }
}

fn check_duo_fields_custom(data: &EnableDuoData) -> bool {
    fn empty_or_default(s: &str) -> bool {
        let st = s.trim();
        st.is_empty() || s == DISABLED_MESSAGE_DEFAULT
    }

    !empty_or_default(&data.secret_key) && !empty_or_default(&data.integration_key)
}

pub async fn activate_duo(headers: Headers, data: Json<Upcase<EnableDuoData>>) -> ApiResult<Json<Value>> {
    let data: EnableDuoData = data.0.data;
    let mut user = headers.user;

    if !user.check_valid_password(&data.master_password_hash) {
        err!("Invalid password");
    }

    let (data, data_str) = if check_duo_fields_custom(&data) {
        let data_req: DuoData = data.into();
        let data_str = serde_json::to_value(data_req.clone())?;
        duo_api_request("GET", "/auth/v2/check", "", &data_req).await?;
        (data_req.obscure(), data_str)
    } else {
        (DuoData::secret(), Value::Null)
    };

    let mut conn = DB.get().await?;

    let twofactor = TwoFactor::new(user.uuid, TwoFactorType::Duo, data_str);
    twofactor.save(&conn).await?;

    _generate_recover_code(&mut user, &conn).await?;

    log_user_event(EventType::UserUpdated2fa, user.uuid, headers.device.atype, Utc::now(), headers.ip, &mut conn).await?;

    Ok(Json(json!({
        "Enabled": true,
        "Host": data.host,
        "SecretKey": data.secret_key,
        "IntegrationKey": data.integration_key,
        "Object": "twoFactorDuo"
    })))
}

async fn duo_api_request(method: &str, path: &str, params: &str, data: &DuoData) -> ApiResult<()> {
    use reqwest::{header, Method};
    use std::str::FromStr;

    // https://duo.com/docs/authapi#api-details
    let url = format!("https://{}{}", &data.host, path);
    let date = Utc::now().to_rfc2822();
    let username = &data.integration_key;
    let fields = [&date, method, &data.host.to_string(), path, params];
    let password = crypto::hmac_sign(&data.secret_key, &fields.join("\n"));

    let m = Method::from_str(method).unwrap_or_default();

    let client = get_reqwest_client();

    client
        .request(m, &url)
        .basic_auth(username, Some(password))
        .header(header::USER_AGENT, "vaultwarden:Duo/1.0 (Rust)")
        .header(header::DATE, date)
        .send()
        .await?
        .error_for_status()?;

    Ok(())
}

const DUO_EXPIRE: i64 = 300;
const APP_EXPIRE: i64 = 3600;

const AUTH_PREFIX: &str = "AUTH";
const DUO_PREFIX: &str = "TX";
const APP_PREFIX: &str = "APP";

async fn get_user_duo_data(uuid: Uuid, conn: &Conn) -> ApiResult<DuoStatus> {
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
async fn get_duo_keys_email(email: &str, conn: &Conn) -> ApiResult<(String, String, String, Url)> {
    let data = match User::find_by_email(conn, email).await? {
        Some(u) => get_user_duo_data(u.uuid, conn).await?.data(),
        _ => DuoData::global(),
    }
    .map_res("Can't fetch Duo Keys")?;

    Ok((data.integration_key, data.secret_key, CONFIG.duo.as_ref().map(|x| x.app_key.clone()).ok_or(ApiError::NotFound)?, data.host))
}

pub async fn generate_duo_signature(email: &str, conn: &Conn) -> ApiResult<(String, Url)> {
    let now = Utc::now().timestamp();

    let (ik, sk, ak, host) = get_duo_keys_email(email, conn).await?;

    let duo_sign = sign_duo_values(&sk, email, &ik, DUO_PREFIX, now + DUO_EXPIRE);
    let app_sign = sign_duo_values(&ak, email, &ik, APP_PREFIX, now + APP_EXPIRE);

    Ok((format!("{duo_sign}:{app_sign}"), host))
}

fn sign_duo_values(key: &str, email: &str, ikey: &str, prefix: &str, expire: i64) -> String {
    let val = format!("{email}|{ikey}|{expire}");
    let cookie = format!("{}|{}", prefix, BASE64.encode(val.as_bytes()));

    format!("{}|{}", cookie, crypto::hmac_sign(key, &cookie))
}

pub async fn validate_duo_login(email: &str, response: &str, conn: &Conn) -> ApiResult<()> {
    // email is as entered by the user, so it needs to be normalized before
    // comparison with auth_user below.
    let email = &email.to_lowercase();

    let split: Vec<&str> = response.split(':').collect();
    if split.len() != 2 {
        err!(
            "Invalid response length",
            ErrorEvent {
                event: EventType::UserFailedLogIn2fa
            }
        );
    }

    let auth_sig = split[0];
    let app_sig = split[1];

    let now = Utc::now().timestamp();

    let (ik, sk, ak, _host) = get_duo_keys_email(email, conn).await?;

    let auth_user = parse_duo_values(&sk, auth_sig, &ik, AUTH_PREFIX, now)?;
    let app_user = parse_duo_values(&ak, app_sig, &ik, APP_PREFIX, now)?;

    if !crypto::ct_eq(&auth_user, app_user) || !crypto::ct_eq(&auth_user, email) {
        err!(
            "Error validating duo authentication",
            ErrorEvent {
                event: EventType::UserFailedLogIn2fa
            }
        )
    }

    Ok(())
}

fn parse_duo_values(key: &str, val: &str, ikey: &str, prefix: &str, time: i64) -> ApiResult<String> {
    let split: Vec<&str> = val.split('|').collect();
    if split.len() != 3 {
        err!("Invalid value length")
    }

    let u_prefix = split[0];
    let u_b64 = split[1];
    let u_sig = split[2];

    let sig = crypto::hmac_sign(key, &format!("{u_prefix}|{u_b64}"));

    if !crypto::ct_eq(crypto::hmac_sign(key, &sig), crypto::hmac_sign(key, u_sig)) {
        err!("Duo signatures don't match")
    }

    if u_prefix != prefix {
        err!("Prefixes don't match")
    }

    let cookie_vec = match BASE64.decode(u_b64.as_bytes()) {
        Ok(c) => c,
        Err(_) => err!("Invalid Duo cookie encoding"),
    };

    let cookie = match String::from_utf8(cookie_vec) {
        Ok(c) => c,
        Err(_) => err!("Invalid Duo cookie encoding"),
    };

    let cookie_split: Vec<&str> = cookie.split('|').collect();
    if cookie_split.len() != 3 {
        err!("Invalid cookie length")
    }

    let username = cookie_split[0];
    let u_ikey = cookie_split[1];
    let expire = cookie_split[2];

    if !crypto::ct_eq(ikey, u_ikey) {
        err!("Invalid ikey")
    }

    let expire: i64 = match expire.parse() {
        Ok(e) => e,
        Err(_) => err!("Invalid expire time"),
    };

    if time >= expire {
        err!("Expired authorization")
    }

    Ok(username.into())
}
