use std::io::ErrorKind;

use axol::http::header::{CONTENT_DISPOSITION, CONTENT_TYPE};
use axol::http::response::Response;
use axol::http::typed_headers::ContentType;
use axol::http::{StatusCode, Uri};
use axol::{prelude::*, Html};
use serde::Deserialize;
use serde_json::json;
use uuid::Uuid;

use crate::config::PUBLIC_NO_TRAILING_SLASH;
use crate::db::{Attachment, DB};
use crate::templates::render_template;
use crate::util::Cached;
use crate::CONFIG;

pub fn route(mut router: Router) -> Router {
    if CONFIG.settings.web_vault_enabled {
        router = router.get("/", web_index);
        router = router.get("/app-id.json", app_id);
        router = router.fallback("/", web_files);
    }
    router = router.get("/attachments/:uuid/:filename", attachments);
    router = router.get("/alive", alive);
    router = router.get("/vw_static/:filename", static_files);
    router
}

fn not_found() -> Result<Response> {
    let json = json!({
        "urlpath": &*PUBLIC_NO_TRAILING_SLASH,
    });
    let text = render_template("404", &json)?;
    (StatusCode::NotFound, Html(text)).into_response()
}

async fn web_index() -> Result<Response> {
    let path = CONFIG.folders.web_vault().join("index.html");
    let raw = tokio::fs::read_to_string(&path).await?;
    (Cached::short(false), Html(raw)).into_response()
}

async fn app_id() -> Result<Response> {
    (
        [(CONTENT_TYPE, "application/fido.trusted-apps+json")],
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

async fn web_files(uri: Uri) -> Result<Response> {
    let base = CONFIG.folders.web_vault();
    let mut path = uri.path();
    if path.contains("..") {
        return Err(Error::NotFound);
    }
    while path.starts_with("/") {
        path = &path[1..];
    }
    //todo: confirm this is safe
    let total = base.join(path);
    let content_type = match total.extension().and_then(|x| x.to_str()) {
        None => return Err(Error::NotFound),
        Some(x) => mime_guess::from_ext(x).first().unwrap_or(mime::APPLICATION_OCTET_STREAM),
    };
    match tokio::fs::read(&total).await {
        Ok(raw) => (Typed(ContentType::from(content_type)), Cached::long(true), raw).into_response(),
        Err(e) if e.kind() == ErrorKind::NotFound => not_found().into_response(),
        Err(e) => Err(Error::internal(e)),
    }
}

#[derive(Deserialize)]
struct AttachmentPath {
    uuid: Uuid,
    filename: Uuid,
}

async fn attachments(Path(path): Path<AttachmentPath>) -> Result<Response> {
    let conn = DB.get().await.map_err(Error::internal)?;
    //TODO: why no user auth??
    let Some(attachment) = Attachment::get_with_cipher(&conn, path.filename, path.uuid).await? else {
        return not_found();
    };
    let path = CONFIG.folders.attachments().join(path.uuid.to_string()).join(path.filename.to_string());
    match tokio::fs::read(&path).await {
        Ok(raw) => (
            [(CONTENT_DISPOSITION, format!(r#"attachment; filename="{}""#, attachment.file_name))],
            Typed(ContentType::from(mime::APPLICATION_OCTET_STREAM)),
            raw,
        )
            .into_response(),
        Err(e) if e.kind() == ErrorKind::NotFound => not_found(),
        Err(e) => Err(Error::internal(e)),
    }
}

async fn alive() {}

pub async fn static_files(Path(filename): Path<String>) -> Result<Response> {
    let content_type: Typed<ContentType> = Typed(
        match std::path::Path::new(&filename).extension().and_then(|x| x.to_str()) {
            None => return Err(Error::NotFound),
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
        _ => return Err(Error::NotFound),
    };
    (content_type, bytes).into_response()
}
