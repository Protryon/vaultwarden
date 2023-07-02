//
// Web Headers and caching
//
use std::io::ErrorKind;

use axum::{
    body::BoxBody,
    response::{IntoResponseParts, Response},
};
use axum_util::{
    errors::{ApiError, ApiResult},
    interceptor::Interception,
};
use log::error;
use tokio::{fs::File, io::AsyncWriteExt, time::Duration};

use crate::{config::ICON_SERVICE_CSP, CONFIG};

#[derive(Clone)]
pub struct AppHeaders;

impl Interception for AppHeaders {
    type Carryover = String;

    fn on_request(&self, req: &mut http::request::Parts) -> ApiResult<String> {
        Ok(req.headers.get(":path").and_then(|x| x.to_str().ok()).unwrap_or_default().to_string())
    }

    fn on_response(&self, req_uri_path: String, res: &mut http::response::Parts) -> ApiResult<()> {
        res.headers.insert("permissions-policy", "accelerometer=(), ambient-light-sensor=(), autoplay=(), battery=(), camera=(), display-capture=(), document-domain=(), encrypted-media=(), execution-while-not-rendered=(), execution-while-out-of-viewport=(), fullscreen=(), geolocation=(), gyroscope=(), keyboard-map=(), magnetometer=(), microphone=(), midi=(), payment=(), picture-in-picture=(), screen-wake-lock=(), sync-xhr=(), usb=(), web-share=(), xr-spatial-tracking=()".parse().unwrap());
        res.headers.insert("referrer-policy", "same-origin".parse().unwrap());
        res.headers.insert("x-content-type-options", "nosniff".parse().unwrap());
        // Obsolete in modern browsers, unsafe (XS-Leak), and largely replaced by CSP
        res.headers.insert("x-xss-protection", "0".parse().unwrap());

        // Do not send the Content-Security-Policy (CSP) Header and X-Frame-Options for the *-connector.html files.
        // This can cause issues when some MFA requests needs to open a popup or page within the clients like WebAuthn, or Duo.
        // This is the same behaviour as upstream Bitwarden.
        if !req_uri_path.contains("connector.html") {
            // # Frame Ancestors:
            // Chrome Web Store: https://chrome.google.com/webstore/detail/bitwarden-free-password-m/nngceckbapebfimnlniiiahkandclblb
            // Edge Add-ons: https://microsoftedge.microsoft.com/addons/detail/bitwarden-free-password/jbkfoedolllekgbhcbcoahefnbanhhlh?hl=en-US
            // Firefox Browser Add-ons: https://addons.mozilla.org/en-US/firefox/addon/bitwarden-password-manager/
            // # img/child/frame src:
            // Have I Been Pwned and Gravator to allow those calls to work.
            // # Connect src:
            // Leaked Passwords check: api.pwnedpasswords.com
            // 2FA/MFA Site check: api.2fa.directory
            // # Mail Relay: https://bitwarden.com/blog/add-privacy-and-security-using-email-aliases-with-bitwarden/
            // app.simplelogin.io, app.anonaddy.com, api.fastmail.com, quack.duckduckgo.com
            let csp = format!(
                "default-src 'self'; \
                base-uri 'self'; \
                form-action 'self'; \
                object-src 'self' blob:; \
                script-src 'self' 'wasm-unsafe-eval'; \
                style-src 'self' 'unsafe-inline'; \
                child-src 'self' https://*.duosecurity.com https://*.duofederal.com; \
                frame-src 'self' https://*.duosecurity.com https://*.duofederal.com; \
                frame-ancestors 'self' \
                  chrome-extension://nngceckbapebfimnlniiiahkandclblb \
                  chrome-extension://jbkfoedolllekgbhcbcoahefnbanhhlh \
                  moz-extension://* \
                  {allowed_iframe_ancestors}; \
                img-src 'self' data: \
                  https://haveibeenpwned.com \
                  https://www.gravatar.com \
                  {icon_service_csp}; \
                connect-src 'self' \
                  https://api.pwnedpasswords.com \
                  https://api.2fa.directory \
                  https://app.simplelogin.io/api/ \
                  https://app.anonaddy.com/api/ \
                  https://api.fastmail.com/ \
                  ;\
                ",
                icon_service_csp = &*ICON_SERVICE_CSP,
                allowed_iframe_ancestors = CONFIG.advanced.allowed_iframe_ancestors
            );
            res.headers.insert("content-security-policy", csp.parse().unwrap());
            res.headers.insert("x-frame-options", "SAMEORIGIN".parse().unwrap());
        } else {
            // It looks like this header get's set somewhere else also, make sure this is not sent for these files, it will cause MFA issues.
            res.headers.remove("x-frame-options");
        }

        // Disable cache unless otherwise specified
        if !res.headers.contains_key("cache-control") {
            res.headers.insert("cache-control", "no-cache, no-store, max-age=0".parse().unwrap());
        }
        Ok(())
    }
}

#[derive(Clone)]
pub struct Cors;

impl Interception for Cors {
    type Carryover = String;

    fn on_request(&self, parts: &mut http::request::Parts) -> ApiResult<Self::Carryover> {
        if parts.method == http::Method::OPTIONS {
            let req_allow_headers = parts.headers.get("access-control-request-headers").map(|x| x.to_str().unwrap_or_default().to_string()).unwrap_or_default();
            let req_allow_method = parts.headers.get("access-control-request-method").map(|x| x.to_str().unwrap_or_default().to_string()).unwrap_or_default();

            let mut response = Response::new(BoxBody::default());

            response.headers_mut().insert("access-control-allow-methods", req_allow_method.parse().unwrap());
            response.headers_mut().insert("access-control-allow-headers", req_allow_headers.parse().unwrap());
            response.headers_mut().insert("access-control-allow-credentials", "true".parse().unwrap());
            return Err(ApiError::Response(response));
        }

        Ok(parts.headers.get("origin").map(|x| x.to_str().unwrap_or_default().to_string()).unwrap_or_default())
    }

    fn on_response(&self, carryover: Self::Carryover, parts: &mut http::response::Parts) -> ApiResult<()> {
        let domain_origin = CONFIG.settings.public.origin().ascii_serialization();
        // TODO: ?? let sso_origin = CONFIG.sso_authority();
        const SAFARI_EXTENSION_ORIGIN: &str = "file://";
        if carryover == domain_origin || carryover == SAFARI_EXTENSION_ORIGIN {
            parts.headers.insert("access-control-allow-origin", carryover.parse().unwrap());
        }

        Ok(())
    }
}

pub struct Cached {
    is_immutable: bool,
    ttl: u64,
}

impl Cached {
    pub fn long(is_immutable: bool) -> Cached {
        Self {
            is_immutable,
            ttl: 604800, // 7 days
        }
    }

    pub fn short(is_immutable: bool) -> Cached {
        Self {
            is_immutable,
            ttl: 600, // 10 minutes
        }
    }

    pub fn ttl(ttl: u64, is_immutable: bool) -> Cached {
        Self {
            is_immutable,
            ttl,
        }
    }
}

impl IntoResponseParts for Cached {
    type Error = ();

    fn into_response_parts(self, mut res: axum::response::ResponseParts) -> Result<axum::response::ResponseParts, Self::Error> {
        let cache_control_header = if self.is_immutable {
            format!("public, immutable, max-age={}", self.ttl)
        } else {
            format!("public, max-age={}", self.ttl)
        };
        res.headers_mut().insert("cache-control", cache_control_header.parse().unwrap());

        let time_now = chrono::Local::now();
        let expiry_time = time_now + chrono::Duration::seconds(self.ttl.try_into().unwrap());
        res.headers_mut().insert("expires", format_datetime_http(&expiry_time).parse().unwrap());
        Ok(res)
    }
}

//
// File handling
//
use std::{io::Result as IOResult, path::Path};

pub async fn file_exists(path: &str) -> Result<bool, std::io::Error> {
    tokio::fs::try_exists(path).await
}

pub async fn write_file(path: &str, content: &[u8]) -> Result<(), std::io::Error> {
    let mut f = match File::create(path).await {
        Ok(file) => file,
        Err(e) => {
            if e.kind() == ErrorKind::PermissionDenied {
                error!("Can't create '{}': Permission denied", path);
            }
            return Err(e);
        }
    };

    f.write_all(content).await?;
    f.flush().await?;
    Ok(())
}

pub async fn delete_file(path: &Path) -> IOResult<()> {
    let res = tokio::fs::remove_file(path).await;

    if let Some(parent) = Path::new(path).parent() {
        // If the directory isn't empty, this returns an error, which we ignore
        // We only want to delete the folder if it's empty
        tokio::fs::remove_dir(parent).await.ok();
    }

    res
}

pub fn get_display_size(size: i32) -> String {
    const UNITS: [&str; 6] = ["bytes", "KB", "MB", "GB", "TB", "PB"];

    let mut size: f64 = size.into();
    let mut unit_counter = 0;

    loop {
        if size > 1024. {
            size /= 1024.;
            unit_counter += 1;
        } else {
            break;
        }
    }

    format!("{:.2} {}", size, UNITS[unit_counter])
}

//
// String util methods
//

use std::str::FromStr;

#[inline]
pub fn upcase_first(s: &str) -> String {
    let mut c = s.chars();
    match c.next() {
        None => String::new(),
        Some(f) => f.to_uppercase().collect::<String>() + c.as_str(),
    }
}

#[inline]
pub fn lcase_first(s: &str) -> String {
    let mut c = s.chars();
    match c.next() {
        None => String::new(),
        Some(f) => f.to_lowercase().collect::<String>() + c.as_str(),
    }
}

pub fn try_parse_string<S, T>(string: Option<S>) -> Option<T>
where
    S: AsRef<str>,
    T: FromStr,
{
    if let Some(Ok(value)) = string.map(|s| s.as_ref().parse::<T>()) {
        Some(value)
    } else {
        None
    }
}

//
// Date util methods
//

use chrono::{DateTime, Local, SecondsFormat, TimeZone, Utc};

/// Formats a UTC-offset `NaiveDateTime` in the format used by Bitwarden API
/// responses with "date" fields (`CreationDate`, `RevisionDate`, etc.).
pub fn format_date(dt: &DateTime<Utc>) -> String {
    dt.to_rfc3339_opts(SecondsFormat::Micros, true)
}

/// Formats a `DateTime<Local>` using the specified format string.
///
/// For a `DateTime<Local>`, the `%Z` specifier normally formats as the
/// time zone's UTC offset (e.g., `+00:00`). In this function, if the
/// `TZ` environment variable is set, then `%Z` instead formats as the
/// abbreviation for that time zone (e.g., `UTC`).
pub fn format_datetime_local(dt: &DateTime<Local>, fmt: &str) -> String {
    // Try parsing the `TZ` environment variable to enable formatting `%Z` as
    // a time zone abbreviation.
    if let Ok(tz) = std::env::var("TZ") {
        if let Ok(tz) = tz.parse::<chrono_tz::Tz>() {
            return dt.with_timezone(&tz).format(fmt).to_string();
        }
    }

    // Otherwise, fall back to formatting `%Z` as a UTC offset.
    dt.format(fmt).to_string()
}

/// Formats a UTC-offset `NaiveDateTime` as a datetime in the local time zone.
///
/// This function basically converts the `NaiveDateTime` to a `DateTime<Local>`,
/// and then calls [format_datetime_local](crate::util::format_datetime_local).
pub fn format_naive_datetime_local(dt: DateTime<Utc>, fmt: &str) -> String {
    format_datetime_local(&Local.from_utc_datetime(&dt.naive_utc()), fmt)
}

/// Formats a `DateTime<Local>` as required for HTTP
///
/// https://httpwg.org/specs/rfc7231.html#http.date
pub fn format_datetime_http(dt: &DateTime<Local>) -> String {
    let expiry_time: chrono::DateTime<chrono::Utc> = chrono::DateTime::from_utc(dt.naive_utc(), chrono::Utc);

    // HACK: HTTP expects the date to always be GMT (UTC) rather than giving an
    // offset (which would always be 0 in UTC anyway)
    expiry_time.to_rfc2822().replace("+0000", "GMT")
}

//
// Deployment environment methods
//

/// Returns true if the program is running in Docker or Podman.
pub fn is_running_in_docker() -> bool {
    Path::new("/.dockerenv").exists() || Path::new("/run/.containerenv").exists()
}

/// Simple check to determine on which docker base image vaultwarden is running.
/// We build images based upon Debian or Alpine, so these we check here.
pub fn docker_base_image() -> &'static str {
    if Path::new("/etc/debian_version").exists() {
        "Debian"
    } else if Path::new("/etc/alpine-release").exists() {
        "Alpine"
    } else {
        "Unknown"
    }
}

//
// Deserialization methods
//

use std::fmt;

use serde::{
    de::{self, DeserializeOwned, Deserializer, MapAccess, SeqAccess, Visitor},
    Deserialize, Serialize,
};
use serde_json::{self, Value};

pub type JsonMap = serde_json::Map<String, Value>;

#[derive(Serialize, Deserialize)]
pub struct Upcase<T: DeserializeOwned> {
    #[serde(deserialize_with = "upcase_deserialize")]
    #[serde(flatten)]
    pub data: T,
}

// https://github.com/serde-rs/serde/issues/586
pub fn upcase_deserialize<'de, T, D>(deserializer: D) -> Result<T, D::Error>
where
    T: DeserializeOwned,
    D: Deserializer<'de>,
{
    let d = deserializer.deserialize_any(UpcaseVisitor)?;
    T::deserialize(d).map_err(de::Error::custom)
}

struct UpcaseVisitor;

impl<'de> Visitor<'de> for UpcaseVisitor {
    type Value = Value;

    fn expecting(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("an object or an array")
    }

    fn visit_map<A>(self, mut map: A) -> Result<Self::Value, A::Error>
    where
        A: MapAccess<'de>,
    {
        let mut result_map = JsonMap::new();

        while let Some((key, value)) = map.next_entry()? {
            result_map.insert(upcase_first(key), upcase_value(value));
        }

        Ok(Value::Object(result_map))
    }

    fn visit_seq<A>(self, mut seq: A) -> Result<Self::Value, A::Error>
    where
        A: SeqAccess<'de>,
    {
        let mut result_seq = Vec::<Value>::new();

        while let Some(value) = seq.next_element()? {
            result_seq.push(upcase_value(value));
        }

        Ok(Value::Array(result_seq))
    }
}

fn upcase_value(value: Value) -> Value {
    if let Value::Object(map) = value {
        let mut new_value = Value::Object(serde_json::Map::new());

        for (key, val) in map.into_iter() {
            let processed_key = _process_key(&key);
            new_value[processed_key] = upcase_value(val);
        }
        new_value
    } else if let Value::Array(array) = value {
        // Initialize array with null values
        let mut new_value = Value::Array(vec![Value::Null; array.len()]);

        for (index, val) in array.into_iter().enumerate() {
            new_value[index] = upcase_value(val);
        }
        new_value
    } else {
        value
    }
}

// Inner function to handle some speciale case for the 'ssn' key.
// This key is part of the Identity Cipher (Social Security Number)
fn _process_key(key: &str) -> String {
    match key.to_lowercase().as_ref() {
        "ssn" => "SSN".into(),
        _ => self::upcase_first(key),
    }
}

use reqwest::{header, Client, ClientBuilder};

pub fn get_reqwest_client() -> Client {
    match get_reqwest_client_builder().build() {
        Ok(client) => client,
        Err(e) => {
            error!("Possible trust-dns error, trying with trust-dns disabled: '{e}'");
            get_reqwest_client_builder().trust_dns(false).build().expect("Failed to build client")
        }
    }
}

pub fn get_reqwest_client_builder() -> ClientBuilder {
    let mut headers = header::HeaderMap::new();
    headers.insert(header::USER_AGENT, header::HeaderValue::from_static("Vaultwarden"));
    Client::builder().default_headers(headers).timeout(Duration::from_secs(10))
}

pub fn convert_json_key_lcase_first(src_json: Value) -> Value {
    match src_json {
        Value::Array(elm) => {
            let mut new_array: Vec<Value> = Vec::with_capacity(elm.len());

            for obj in elm {
                new_array.push(convert_json_key_lcase_first(obj));
            }
            Value::Array(new_array)
        }

        Value::Object(obj) => {
            let mut json_map = JsonMap::new();
            for (key, value) in obj.iter() {
                match (key, value) {
                    (key, Value::Object(elm)) => {
                        let inner_value = convert_json_key_lcase_first(Value::Object(elm.clone()));
                        json_map.insert(lcase_first(key), inner_value);
                    }

                    (key, Value::Array(elm)) => {
                        let mut inner_array: Vec<Value> = Vec::with_capacity(elm.len());

                        for inner_obj in elm {
                            inner_array.push(convert_json_key_lcase_first(inner_obj.clone()));
                        }

                        json_map.insert(lcase_first(key), Value::Array(inner_array));
                    }

                    (key, value) => {
                        json_map.insert(lcase_first(key), value.clone());
                    }
                }
            }

            Value::Object(json_map)
        }

        value => value,
    }
}

// pub struct CookieManager<'a> {
//     jar: &'a CookieJar<'a>,
// }

// impl<'a> CookieManager<'a> {
//     pub fn new(jar: &'a CookieJar<'a>) -> Self {
//         Self {
//             jar,
//         }
//     }

//     pub fn set_cookie(&self, name: String, value: String) {
//         let cookie = Cookie::build(name, value).same_site(SameSite::Lax).finish();

//         self.jar.add(cookie)
//     }

//     pub fn get_cookie(&self, name: String) -> Option<String> {
//         self.jar.get(&name).map(|c| c.value().to_string())
//     }

//     pub fn delete_cookie(&self, name: String) {
//         self.jar.remove(Cookie::named(name));
//     }
// }
