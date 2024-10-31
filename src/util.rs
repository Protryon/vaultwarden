//
// Web Headers and caching
//
use std::{
    io::ErrorKind,
    ops::{Deref, Range, RangeFrom},
};

use axol::{
    cors::{AllowHeaders, AllowMethods, Cors},
    http::{response::ResponsePartsRef, Uri},
    prelude::*,
};
use log::error;
use tokio::{fs::File, io::AsyncWriteExt, time::Duration};
use tokio_postgres::{types::FromSql, Row};

use crate::{
    config::ICON_SERVICE_CSP,
    db::{Conn, ConnOwned, DB},
    CONFIG,
};

pub async fn app_headers(uri: Uri, mut res: Response) -> Response {
    res.headers.insert("permissions-policy", "accelerometer=(), ambient-light-sensor=(), autoplay=(), battery=(), camera=(), display-capture=(), document-domain=(), encrypted-media=(), execution-while-not-rendered=(), execution-while-out-of-viewport=(), fullscreen=(), geolocation=(), gyroscope=(), keyboard-map=(), magnetometer=(), microphone=(), midi=(), payment=(), picture-in-picture=(), screen-wake-lock=(), sync-xhr=(), usb=(), web-share=(), xr-spatial-tracking=()");
    res.headers.insert("referrer-policy", "same-origin");
    res.headers.insert("x-content-type-options", "nosniff");
    // Obsolete in modern browsers, unsafe (XS-Leak), and largely replaced by CSP
    res.headers.insert("x-xss-protection", "0");

    //TODO: this looks insecure, fix it?

    // Do not send the Content-Security-Policy (CSP) Header and X-Frame-Options for the *-connector.html files.
    // This can cause issues when some MFA requests needs to open a popup or page within the clients like WebAuthn, or Duo.
    // This is the same behaviour as upstream Bitwarden.
    if !uri.path().ends_with("connector.html") {
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
        res.headers.insert("content-security-policy", csp);
        res.headers.insert("x-frame-options", "SAMEORIGIN");
    } else {
        // It looks like this header get's set somewhere else also, make sure this is not sent for these files, it will cause MFA issues.
        res.headers.remove("x-frame-options");
    }

    // Disable cache unless otherwise specified
    if !res.headers.contains_key("cache-control") {
        res.headers.insert("cache-control", "no-cache, no-store, max-age=0");
    }
    res
}

const SAFARI_EXTENSION_ORIGIN: &str = "file://";

pub fn build_cors() -> Cors {
    Cors::default()
        .allow_headers(AllowHeaders::MirrorRequest)
        .allow_methods(AllowMethods::MirrorRequest)
        .allow_credentials(true)
        .allow_origin([&CONFIG.settings.public.origin().ascii_serialization(), SAFARI_EXTENSION_ORIGIN])
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
    fn into_response_parts(self, response: &mut ResponsePartsRef<'_>) -> Result<()> {
        let cache_control_header = if self.is_immutable {
            format!("public, immutable, max-age={}", self.ttl)
        } else {
            format!("public, max-age={}", self.ttl)
        };
        response.headers.insert("cache-control", cache_control_header);

        let time_now = chrono::Local::now();
        let expiry_time = time_now + chrono::Duration::seconds(self.ttl.try_into().unwrap());
        response.headers.insert("expires", format_datetime_http(&expiry_time));
        Ok(())
    }
}

pub struct AutoTxn {
    conn: Option<ConnOwned>,
    deferred: Vec<Box<dyn FnOnce() + Send + Sync + 'static>>,
}

#[async_trait::async_trait]
impl<'a> FromRequestParts<'a> for AutoTxn {
    async fn from_request_parts(_: RequestPartsRef<'a>) -> Result<Self> {
        let conn = DB.get().await.map_err(Error::internal)?;
        conn.batch_execute("BEGIN").await.map_err(Error::internal)?;
        Ok(Self {
            conn: Some(conn),
            deferred: vec![],
        })
    }
}

impl Deref for AutoTxn {
    type Target = Conn;

    fn deref(&self) -> &Self::Target {
        self.conn.as_ref().unwrap()
    }
}

impl AutoTxn {
    pub async fn commit(mut self) -> Result<ConnOwned> {
        self.batch_execute("COMMIT").await.map_err(Error::internal)?;
        for deferred in std::mem::take(&mut self.deferred) {
            deferred();
        }
        Ok(self.conn.take().unwrap())
    }

    #[allow(dead_code)]
    pub async fn rollback(mut self) -> Result<ConnOwned> {
        self.batch_execute("ROLLBACK").await.map_err(Error::internal)?;
        Ok(self.conn.take().unwrap())
    }

    pub fn defer(&mut self, func: impl FnOnce() + Send + Sync + 'static) {
        self.deferred.push(Box::new(func));
    }
}

impl Drop for AutoTxn {
    fn drop(&mut self) {
        if let Some(conn) = self.conn.take() {
            tokio::spawn(async move {
                if let Err(e) = conn.batch_execute("ROLLBACK").await {
                    error!("failed to dispatch rollback to dropped txn: {e}");
                }
            });
        }
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
pub struct LowerCase<T: DeserializeOwned> {
    #[serde(deserialize_with = "lowercase_deserialize")]
    #[serde(flatten)]
    pub data: T,
}

// https://github.com/serde-rs/serde/issues/586
pub fn lowercase_deserialize<'de, T, D>(deserializer: D) -> Result<T, D::Error>
where
    T: DeserializeOwned,
    D: Deserializer<'de>,
{
    let d = deserializer.deserialize_any(LowercaseVisitor)?;
    T::deserialize(d).map_err(de::Error::custom)
}

impl Default for LowerCase<Value> {
    fn default() -> Self {
        Self {
            data: Value::Null,
        }
    }
}

struct LowercaseVisitor;

impl<'de> Visitor<'de> for LowercaseVisitor {
    type Value = Value;

    fn expecting(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("an object or an array")
    }

    fn visit_map<A>(self, mut map: A) -> Result<Self::Value, A::Error>
    where
        A: MapAccess<'de>,
    {
        let mut result_map = JsonMap::new();

        while let Some((key, value)) = map.next_entry::<String, Value>()? {
            result_map.insert(_process_key(&key), convert_json_key_lcase_first(value));
        }

        Ok(Value::Object(result_map))
    }

    fn visit_seq<A>(self, mut seq: A) -> Result<Self::Value, A::Error>
    where
        A: SeqAccess<'de>,
    {
        let mut result_seq = Vec::<Value>::new();

        while let Some(value) = seq.next_element()? {
            result_seq.push(convert_json_key_lcase_first(value));
        }

        Ok(Value::Array(result_seq))
    }
}

// Inner function to handle some speciale case for the 'ssn' key.
// This key is part of the Identity Cipher (Social Security Number)
fn _process_key(key: &str) -> String {
    match key.to_lowercase().as_ref() {
        "ssn" => "ssn".into(),
        _ => self::lcase_first(key),
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
            for (key, value) in obj.into_iter() {
                match (key, value) {
                    (key, Value::Object(elm)) => {
                        let inner_value = convert_json_key_lcase_first(Value::Object(elm));
                        json_map.insert(_process_key(&key), inner_value);
                    }

                    (key, Value::Array(elm)) => {
                        let mut inner_array: Vec<Value> = Vec::with_capacity(elm.len());

                        for inner_obj in elm {
                            inner_array.push(convert_json_key_lcase_first(inner_obj));
                        }

                        json_map.insert(_process_key(&key), Value::Array(inner_array));
                    }

                    (key, value) => {
                        json_map.insert(_process_key(&key), value.clone());
                    }
                }
            }

            Value::Object(json_map)
        }

        value => value,
    }
}

#[derive(Clone, Copy)]
pub struct RowSlice<'a> {
    inner: &'a Row,
    start: usize,
    end: usize,
}

impl<'a> From<&'a Row> for RowSlice<'a> {
    fn from(value: &'a Row) -> Self {
        Self {
            inner: value,
            start: 0,
            end: value.len(),
        }
    }
}

#[allow(dead_code)]
impl<'a> RowSlice<'a> {
    pub fn new(row: &'a Row) -> Self {
        row.into()
    }

    pub fn get<T: FromSql<'a>>(&self, idx: usize) -> T {
        let idx = self.start + idx;
        if idx >= self.end {
            panic!("error retrieving column {}: out of bounds", idx);
        }
        self.inner.get(idx)
    }

    pub fn len(&self) -> usize {
        self.end - self.start
    }

    pub fn slice(&self, index: Range<usize>) -> Self {
        Self {
            inner: self.inner,
            start: self.start + index.start,
            end: self.end - (self.len() - index.end),
        }
    }

    pub fn slice_from(&self, index: RangeFrom<usize>) -> Self {
        Self {
            inner: self.inner,
            start: self.start + index.start,
            end: self.end,
        }
    }
}
