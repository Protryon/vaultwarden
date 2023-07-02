use std::io::ErrorKind;

use super::OutHeader;
use axum::body::Full;
use axum::extract::Path;
use axum::headers::ContentType;
use axum::response::{Html, IntoResponse, Response};
use axum::{routing, Json, Router};
use axum_util::errors::ApiError;
use http::header::CONTENT_DISPOSITION;
use http::{header, HeaderValue, StatusCode, Uri};
use serde::Deserialize;
use serde_json::json;
use uuid::Uuid;

use crate::db::{Attachment, DB};
use crate::templates::render_template;
use crate::util::Cached;
use crate::{api::ApiResult, CONFIG};

pub fn route(mut router: Router) -> Router {
    if CONFIG.settings.web_vault_enabled {
        router = router.route("/", routing::get(web_index));
        router = router.route("/app-id.json", routing::get(app_id));
        router = router.fallback(web_files);
    }
    router = router.route("/attachments/:uuid/:filename", routing::get(attachments));
    router = router.route("/alive", routing::get(alive));
    router = router.route("/vw_static/:filename", routing::get(static_files));
    router
}

fn not_found() -> ApiResult<Response> {
    let json = json!({
        "urlpath": &*PUBLIC_NO_TRAILING_SLASH,
    });
    let text = render_template("404", &json)?;
    Ok((StatusCode::NOT_FOUND, Html(text)).into_response())
}

lazy_static::lazy_static! {
    pub static ref PUBLIC_NO_TRAILING_SLASH: String = {
        let mut path = CONFIG.settings.public.to_string();
        if path.ends_with("/") {
            path.truncate(path.len() - 1);
        }
        path
    };
}

async fn web_index() -> ApiResult<Response> {
    let path = CONFIG.folders.web_vault().join("index.html");
    let raw = tokio::fs::read_to_string(&path).await?;
    Ok((Cached::short(false), Html(raw)).into_response())
}

async fn app_id() -> Response {
    (
        [(header::CONTENT_TYPE, HeaderValue::from_static("application/fido.trusted-apps+json"))],
        Cached::long(true),
        Json(json!({
        "trustedFacets": [
            {
            "version": { "major": 1, "minor": 0 },
            "ids": [
                // Per <https://fidoalliance.org/specs/fido-v2.0-id-20180227/fido-appid-and-facets-v2.0-id-20180227.html#determining-the-facetid-of-a-calling-application>:
                //
                // "In the Web case, the FacetID MUST be the Web Origin [RFC6454]
                // of the web page triggering the FIDO operation, written as
                // a URI with an empty path. Default ports are omitted and any
                // path component is ignored."
                //
                // This leaves it unclear as to whether the path must be empty,
                // or whether it can be non-empty and will be ignored. To be on
                // the safe side, use a proper web origin (with empty path).
                &CONFIG.settings.public,
                "ios:bundle-id:com.8bit.bitwarden",
                "android:apk-key-hash:dUGFzUzf3lmHSLBDBIv+WaFyZMI" ]
            }]
        })),
    )
        .into_response()
}

async fn web_files(uri: Uri) -> Response {
    let base = CONFIG.folders.web_vault();
    let mut path = uri.path();
    if path.contains("..") {
        return StatusCode::NOT_FOUND.into_response();
    }
    while path.starts_with("/") {
        path = &path[1..];
    }
    //todo: confirm this is safe
    let total = base.join(path);
    let content_type = match total.extension().and_then(|x| x.to_str()) {
        None => return StatusCode::NOT_FOUND.into_response(),
        Some(x) => mime_guess::from_ext(x).first().unwrap_or(mime::APPLICATION_OCTET_STREAM),
    };
    match tokio::fs::read(&total).await {
        Ok(raw) => (OutHeader(ContentType::from(content_type)), Cached::long(true), Full::from(raw)).into_response(),
        Err(e) if e.kind() == ErrorKind::NotFound => not_found().into_response(),
        Err(e) => ApiError::from(e).into_response(),
    }
}

#[derive(Deserialize)]
struct AttachmentPath {
    uuid: Uuid,
    filename: Uuid,
}

async fn attachments(Path(path): Path<AttachmentPath>) -> ApiResult<Response> {
    let conn = DB.get().await?;
    //TODO: why no user auth??
    let Some(attachment) = Attachment::get_with_cipher(&conn, path.filename, path.uuid).await? else {
        return Ok(not_found().into_response());
    };
    let path = CONFIG.folders.attachments().join(path.uuid.to_string()).join(path.filename.to_string());
    match tokio::fs::read(&path).await {
        Ok(raw) => Ok((
            [(CONTENT_DISPOSITION, format!(r#"attachment; filename="{}""#, attachment.file_name).parse::<HeaderValue>().unwrap())],
            OutHeader(ContentType::from(mime::APPLICATION_OCTET_STREAM)),
            Full::from(raw),
        )
            .into_response()),
        Err(e) if e.kind() == ErrorKind::NotFound => Ok(not_found().into_response()),
        Err(e) => Err(ApiError::from(e)),
    }
}

async fn alive() {}

pub async fn static_files(Path(filename): Path<String>) -> Response {
    let content_type: OutHeader<ContentType> = OutHeader(
        match std::path::Path::new(&filename).extension().and_then(|x| x.to_str()) {
            None => return StatusCode::NOT_FOUND.into_response(),
            Some(x) => mime_guess::from_ext(x).first().unwrap_or(mime::APPLICATION_OCTET_STREAM),
        }
        .into(),
    );
    let bytes = match &*filename {
        "404.png" => &include_bytes!("../../static/images/404.png")[..],
        "mail-github.png" => &include_bytes!("../../static/images/mail-github.png")[..],
        "logo-gray.png" => &include_bytes!("../../static/images/logo-gray.png")[..],
        "error-x.svg" => &include_bytes!("../../static/images/error-x.svg")[..],
        "hibp.png" => &include_bytes!("../../static/images/hibp.png")[..],
        "vaultwarden-icon.png" => &include_bytes!("../../static/images/vaultwarden-icon.png")[..],
        "vaultwarden-favicon.png" => &include_bytes!("../../static/images/vaultwarden-favicon.png")[..],
        "404.css" => &include_bytes!("../../static/scripts/404.css")[..],
        "admin.css" => &include_bytes!("../../static/scripts/admin.css")[..],
        "admin.js" => &include_bytes!("../../static/scripts/admin.js")[..],
        "admin_settings.js" => &include_bytes!("../../static/scripts/admin_settings.js")[..],
        "admin_users.js" => &include_bytes!("../../static/scripts/admin_users.js")[..],
        "admin_organizations.js" => &include_bytes!("../../static/scripts/admin_organizations.js")[..],
        "admin_diagnostics.js" => &include_bytes!("../../static/scripts/admin_diagnostics.js")[..],
        "bootstrap.css" => &include_bytes!("../../static/scripts/bootstrap.css")[..],
        "bootstrap-native.js" => &include_bytes!("../../static/scripts/bootstrap-native.js")[..],
        "jdenticon.js" => &include_bytes!("../../static/scripts/jdenticon.js")[..],
        "datatables.js" => &include_bytes!("../../static/scripts/datatables.js")[..],
        "datatables.css" => &include_bytes!("../../static/scripts/datatables.css")[..],
        "jquery-3.6.4.slim.js" => &include_bytes!("../../static/scripts/jquery-3.6.4.slim.js")[..],
        _ => return StatusCode::NOT_FOUND.into_response(),
    };
    (content_type, Full::from(bytes)).into_response()
}
