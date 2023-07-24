use std::io::ErrorKind;

use axol::http::{header::CONTENT_DISPOSITION, typed_headers::ContentType};
use axol::{prelude::*, Multipart};
use bytes::Bytes;
use chrono::{DateTime, Duration, Utc};
use serde::Deserialize;
use serde_json::{json, Value};
use serde_with::serde_as;
use uuid::Uuid;

use crate::{
    api::{ws_users, Result, UpdateType},
    auth::{ClientIp, Headers},
    db::{Attachment, Conn, OrgPolicyType, OrganizationPolicy, Send, SendType, DB},
    util::{AutoTxn, Upcase},
    CONFIG,
};

const SEND_INACCESSIBLE_MSG: &str = "Send does not exist or is no longer available";

// The max file size allowed by Bitwarden clients and add an extra 5% to avoid issues
const SIZE_525_MB: u64 = 550_502_400;

pub fn route(router: Router) -> Router {
    router
        .get("/sends", get_sends)
        .get("/sends/:uuid", get_send)
        .post("/sends", post_send)
        .post("/sends/file", post_send_file)
        .post("/sends/file/v2", post_send_file_v2)
        .post("/sends/:uuid/file/:file_id", post_send_file_v2_data)
        .post("/sends/access/:access_id", post_access)
        .post("/sends/:uuid/access/file/:file_id", post_access_file)
        .get("/sends/:uuid/:file_id", download_send)
        .put("/sends/:uuid", put_send)
        .delete("/sends/:uuid", delete_send)
        .put("/sends/:uuid/remove-password", put_remove_password)
}

#[serde_as]
#[derive(Deserialize)]
#[serde(rename_all = "PascalCase")]
struct SendData {
    r#type: SendType,
    key: String,
    password: Option<String>,
    #[serde_as(as = "serde_with::PickFirst<(_, Option<serde_with::DisplayFromStr>)>")]
    #[serde(default)]
    max_access_count: Option<i32>,
    expiration_date: Option<DateTime<Utc>>,
    deletion_date: DateTime<Utc>,
    disabled: bool,
    hide_email: Option<bool>,

    // Data field
    name: String,
    notes: Option<String>,
    text: Option<Value>,
    file: Option<Value>,
    #[serde_as(as = "serde_with::PickFirst<(_, Option<serde_with::DisplayFromStr>)>")]
    #[serde(default)]
    file_length: Option<i32>,
}

/// Enforces the `Disable Send` policy. A non-owner/admin user belonging to
/// an org with this policy enabled isn't allowed to create new Sends or
/// modify existing ones, but is allowed to delete them.
///
/// Ref: https://bitwarden.com/help/article/policies/#disable-send
///
/// There is also a Vaultwarden-specific `sends_allowed` config setting that
/// controls this policy globally.
async fn enforce_disable_send_policy(headers: &Headers, conn: &Conn) -> Result<()> {
    let user_uuid = headers.user.uuid;
    if !CONFIG.settings.sends_allowed || OrganizationPolicy::is_applicable_to_user(conn, user_uuid, OrgPolicyType::DisableSend, None).await? {
        err!("Due to an Enterprise Policy, you are only able to delete an existing Send.")
    }
    Ok(())
}

/// Enforces the `DisableHideEmail` option of the `Send Options` policy.
/// A non-owner/admin user belonging to an org with this option enabled isn't
/// allowed to hide their email address from the recipient of a Bitwarden Send,
/// but is allowed to remove this option from an existing Send.
///
/// Ref: https://bitwarden.com/help/article/policies/#send-options
async fn enforce_disable_hide_email_policy(data: &SendData, headers: &Headers, conn: &Conn) -> Result<()> {
    let user_uuid = headers.user.uuid;
    let hide_email = data.hide_email.unwrap_or(false);
    if hide_email && OrganizationPolicy::is_hide_email_disabled(conn, user_uuid).await? {
        err!(
            "Due to an Enterprise Policy, you are not allowed to hide your email address \
              from recipients when creating or editing a Send."
        )
    }
    Ok(())
}

fn create_send(data: SendData, user_uuid: Uuid) -> Result<Send> {
    let data_val = if data.r#type == SendType::Text {
        data.text
    } else if data.r#type == SendType::File {
        data.file
    } else {
        err!("Invalid Send type")
    };

    let data_str = if let Some(mut d) = data_val {
        d.as_object_mut().and_then(|o| o.remove("Response"));
        serde_json::to_value(&d).ise()?
    } else {
        err!("Send data not provided");
    };

    if data.deletion_date > Utc::now() + Duration::days(31) {
        err!(
            "You cannot have a Send with a deletion date that far into the future. Adjust the Deletion Date to a value less than 31 days from now and try again."
        );
    }

    let mut send = Send::new(data.r#type, data.name, data_str, data.key, data.deletion_date);
    send.user_uuid = Some(user_uuid);
    send.notes = data.notes;
    send.max_access_count = match data.max_access_count {
        Some(m) => Some(m),
        _ => None,
    };
    send.expiration_date = data.expiration_date.map(|d| d);
    send.disabled = data.disabled;
    send.hide_email = data.hide_email;
    send.atype = data.r#type;

    send.set_password(data.password.as_deref());

    Ok(send)
}

async fn get_sends(headers: Headers) -> Result<Json<Value>> {
    let conn = DB.get().await.ise()?;
    let sends = Send::find_by_user(&conn, headers.user.uuid).await?;
    let sends_json: Vec<Value> = sends.iter().map(|s| s.to_json()).collect();

    Ok(Json(json!({
      "Data": sends_json,
      "Object": "list",
      "ContinuationToken": null
    })))
}

async fn get_send(Path(uuid): Path<Uuid>, headers: Headers) -> Result<Json<Value>> {
    let conn = DB.get().await.ise()?;
    let send = match Send::get_for_user(&conn, uuid, headers.user.uuid).await? {
        Some(send) => send,
        None => err!("Send not found"),
    };

    Ok(Json(send.to_json()))
}

async fn post_send(headers: Headers, data: Json<Upcase<SendData>>) -> Result<Json<Value>> {
    let conn = DB.get().await.ise()?;

    enforce_disable_send_policy(&headers, &conn).await?;

    let data: SendData = data.0.data;
    enforce_disable_hide_email_policy(&data, &headers, &conn).await?;

    if data.r#type == SendType::File {
        err!("File sends should use /api/sends/file")
    }

    let mut send = create_send(data, headers.user.uuid)?;
    send.save(&conn).await?;
    ws_users().send_send_update(UpdateType::SyncSendCreate, &send, &[send.user_uuid.unwrap()], headers.device.uuid, &conn).await?;

    Ok(Json(send.to_json()))
}

pub struct UploadData {
    model: SendData,
    data: Bytes,
}

impl UploadData {
    pub async fn read(mut multipart: Multipart) -> Result<Self> {
        let mut model = None::<SendData>;
        let mut data = None::<Bytes>;
        while let Some(field) = multipart.next_field().await? {
            match field.name() {
                Some("model") => {
                    if model.is_some() {
                        return Err(Error::bad_request("duplicated multipart field"));
                    }
                    let raw: Upcase<SendData> =
                        serde_json::from_slice(&field.bytes().await.ise()?[..]).map_err(|e| Error::bad_request(format!("invalid model: {e}")))?;
                    model = Some(raw.data);
                }
                Some("data") => {
                    if data.is_some() {
                        return Err(Error::bad_request("duplicated multipart field"));
                    }
                    data = Some(field.bytes().await?);
                }
                _ => return Err(Error::bad_request("unknown multipart field")),
            }
        }
        if let (Some(model), Some(data)) = (model, data) {
            Ok(Self {
                model,
                data,
            })
        } else {
            Err(Error::bad_request("missing fields"))
        }
    }
}

pub struct UploadDataV2 {
    data: Bytes,
}

impl UploadDataV2 {
    pub async fn read(mut multipart: Multipart) -> Result<Self> {
        let mut data = None::<Bytes>;
        while let Some(field) = multipart.next_field().await? {
            match field.name() {
                Some("data") => {
                    if data.is_some() {
                        return Err(Error::bad_request("duplicated multipart field"));
                    }
                    data = Some(field.bytes().await?);
                }
                _ => return Err(Error::bad_request("unknown multipart field")),
            }
        }
        if let Some(data) = data {
            Ok(Self {
                data,
            })
        } else {
            Err(Error::bad_request("missing fields"))
        }
    }
}

// @deprecated Mar 25 2021: This method has been deprecated in favor of direct uploads (v2).
// This method still exists to support older clients, probably need to remove it sometime.
// Upstream: https://github.com/bitwarden/server/blob/d0c793c95181dfb1b447eb450f85ba0bfd7ef643/src/Api/Controllers/SendsController.cs#L164-L167
async fn post_send_file(conn: AutoTxn, headers: Headers, data: Multipart) -> Result<Json<Value>> {
    enforce_disable_send_policy(&headers, &conn).await?;

    let UploadData {
        model,
        data,
    } = UploadData::read(data).await?;

    enforce_disable_hide_email_policy(&model, &headers, &conn).await?;

    let size_limit = match CONFIG.settings.user_attachment_limit {
        Some(0) => err!("File uploads are disabled"),
        Some(limit_kb) => {
            let left = (limit_kb * 1024) - Attachment::size_count_by_user(&conn, headers.user.uuid).await?.0;
            if left <= 0 {
                err!("Attachment storage limit reached! Delete some attachments to free up space")
            }
            std::cmp::Ord::max(left as u64, SIZE_525_MB)
        }
        None => SIZE_525_MB,
    };

    let mut send = create_send(model, headers.user.uuid)?;
    if send.atype != SendType::File {
        err!("Send content is not a file");
    }

    let size = data.len();
    if size as u64 > size_limit {
        err!("Attachment storage limit exceeded with this file");
    }

    let file_id = Uuid::new_v4();
    let folder_path = tokio::fs::canonicalize(CONFIG.folders.sends()).await?.join(send.uuid.to_string());
    let file_path = folder_path.join(file_id.to_string());
    tokio::fs::create_dir_all(&folder_path).await?;

    tokio::fs::write(file_path, &data).await?;

    if let Some(o) = send.data.as_object_mut() {
        o.insert(String::from("Id"), Value::String(file_id.to_string()));
        o.insert(String::from("Size"), Value::Number(size.into()));
        o.insert(String::from("SizeName"), Value::String(crate::util::get_display_size(size as i32)));
    }

    send.save(&conn).await?;
    let conn = conn.commit().await?;
    ws_users().send_send_update(UpdateType::SyncSendCreate, &send, &[headers.user.uuid], headers.device.uuid, &conn).await?;

    Ok(Json(send.to_json()))
}

// Upstream: https://github.com/bitwarden/server/blob/d0c793c95181dfb1b447eb450f85ba0bfd7ef643/src/Api/Controllers/SendsController.cs#L190
async fn post_send_file_v2(headers: Headers, data: Json<Upcase<SendData>>) -> Result<Json<Value>> {
    let conn = DB.get().await.ise()?;
    enforce_disable_send_policy(&headers, &conn).await?;

    let data = data.0.data;

    if data.r#type != SendType::File {
        err!("Send content is not a file");
    }

    enforce_disable_hide_email_policy(&data, &headers, &conn).await?;

    let file_length = match data.file_length {
        Some(m) => Some(m),
        _ => None,
    };

    let size_limit = match CONFIG.settings.user_attachment_limit {
        Some(0) => err!("File uploads are disabled"),
        Some(limit_kb) => {
            let left = (limit_kb * 1024) - Attachment::size_count_by_user(&conn, headers.user.uuid).await?.0;
            if left <= 0 {
                err!("Attachment storage limit reached! Delete some attachments to free up space")
            }
            std::cmp::Ord::max(left as u64, SIZE_525_MB)
        }
        None => SIZE_525_MB,
    };

    if file_length.is_some() && file_length.unwrap() as u64 > size_limit {
        err!("Attachment storage limit exceeded with this file");
    }

    let mut send = create_send(data, headers.user.uuid)?;

    let file_id = Uuid::new_v4();

    if let Some(o) = send.data.as_object_mut() {
        o.insert(String::from("Id"), Value::String(file_id.to_string()));
        o.insert(String::from("Size"), Value::Number(file_length.unwrap().into()));
        o.insert(String::from("SizeName"), Value::String(crate::util::get_display_size(file_length.unwrap())));
    }
    send.save(&conn).await?;

    Ok(Json(json!({
        "fileUploadType": 0, // 0 == Direct | 1 == Azure
        "object": "send-fileUpload",
        "url": format!("/sends/{}/file/{}", send.uuid, file_id),
        "sendResponse": send.to_json()
    })))
}

#[derive(Deserialize)]
struct SendFilePath {
    uuid: Uuid,
    file_id: Uuid,
}

// https://github.com/bitwarden/server/blob/d0c793c95181dfb1b447eb450f85ba0bfd7ef643/src/Api/Controllers/SendsController.cs#L243
async fn post_send_file_v2_data(conn: AutoTxn, Path(path): Path<SendFilePath>, headers: Headers, data: Multipart) -> Result<()> {
    enforce_disable_send_policy(&headers, &conn).await?;

    let data = UploadDataV2::read(data).await?;

    //TODO: disable overwriting of already existing file? atomic file replacement?

    let Some(mut send) = Send::get_for_user(&conn, path.uuid, headers.user.uuid).await? else {
        err!("Send not found. Unable to save the file.");
    };

    let folder_path = tokio::fs::canonicalize(CONFIG.folders.sends()).await?.join(path.uuid.to_string());
    let file_path = folder_path.join(path.file_id.to_string());
    tokio::fs::create_dir_all(&folder_path).await?;

    tokio::fs::write(&file_path, &data.data).await?;

    send.save(&conn).await?;

    let conn = conn.commit().await?;
    ws_users().send_send_update(UpdateType::SyncSendCreate, &send, &[send.user_uuid.unwrap()], headers.device.uuid, &conn).await?;

    Ok(())
}

#[derive(Deserialize)]
#[serde(rename_all = "PascalCase")]
pub struct SendAccessData {
    pub password: Option<String>,
}

async fn post_access(Path(access_id): Path<String>, ip: ClientIp, data: Json<Upcase<SendAccessData>>) -> Result<Json<Value>> {
    let conn = DB.get().await.ise()?;

    let uuid = Send::decode_access_id(&access_id)?;

    let mut send = match Send::get(&conn, uuid).await? {
        Some(s) => s,
        None => err_code!(SEND_INACCESSIBLE_MSG, StatusCode::NotFound),
    };

    if let Some(max_access_count) = send.max_access_count {
        if send.access_count >= max_access_count {
            err_code!(SEND_INACCESSIBLE_MSG, StatusCode::NotFound);
        }
    }

    if let Some(expiration) = send.expiration_date {
        if Utc::now() >= expiration {
            err_code!(SEND_INACCESSIBLE_MSG, StatusCode::NotFound)
        }
    }

    if Utc::now() >= send.deletion_date {
        err_code!(SEND_INACCESSIBLE_MSG, StatusCode::NotFound)
    }

    if send.disabled {
        err_code!(SEND_INACCESSIBLE_MSG, StatusCode::NotFound)
    }

    if send.password_hash.is_some() {
        match data.0.data.password {
            Some(ref p) if send.check_password(p) => { /* Nothing to do here */ }
            Some(_) => err!("Invalid password", format!("IP: {}.", ip.ip)),
            None => err_code!("Password not provided", format!("IP: {}.", ip.ip), StatusCode::Unauthorized),
        }
    }

    // Files are incremented during the download
    if send.atype == SendType::Text {
        send.access_count += 1;
    }

    send.save(&conn).await?;

    ws_users().send_send_update(UpdateType::SyncSendUpdate, &send, &[send.user_uuid.unwrap()], Uuid::default(), &conn).await?;

    Ok(Json(send.to_json_access(&conn).await?))
}

async fn post_access_file(Path(path): Path<SendFilePath>, data: Json<Upcase<SendAccessData>>) -> Result<Json<Value>> {
    let conn = DB.get().await.ise()?;

    let mut send = match Send::get(&conn, path.uuid).await? {
        Some(s) => s,
        None => err_code!(SEND_INACCESSIBLE_MSG, StatusCode::NotFound),
    };

    if let Some(max_access_count) = send.max_access_count {
        if send.access_count >= max_access_count {
            err_code!(SEND_INACCESSIBLE_MSG, StatusCode::NotFound)
        }
    }

    if let Some(expiration) = send.expiration_date {
        if Utc::now() >= expiration {
            err_code!(SEND_INACCESSIBLE_MSG, StatusCode::NotFound)
        }
    }

    if Utc::now() >= send.deletion_date {
        err_code!(SEND_INACCESSIBLE_MSG, StatusCode::NotFound)
    }

    if send.disabled {
        err_code!(SEND_INACCESSIBLE_MSG, StatusCode::NotFound)
    }

    if send.password_hash.is_some() {
        match data.0.data.password {
            Some(ref p) if send.check_password(p) => { /* Nothing to do here */ }
            Some(_) => err!("Invalid password."),
            None => err_code!("Password not provided", StatusCode::Unauthorized),
        }
    }

    send.access_count += 1;

    send.save(&conn).await?;

    ws_users().send_send_update(UpdateType::SyncSendUpdate, &send, &[send.user_uuid.unwrap()], Uuid::default(), &conn).await?;

    let token_claims = crate::auth::generate_send_claims(path.uuid, path.file_id);
    let token = crate::auth::encode_jwt(&token_claims);
    let mut url = CONFIG.settings.public.clone();
    url.path_segments_mut().unwrap().push("api");
    url.path_segments_mut().unwrap().push("sends");
    url.path_segments_mut().unwrap().push(&path.uuid.to_string());
    url.path_segments_mut().unwrap().push(&path.file_id.to_string());
    url.query_pairs_mut().append_pair("t", &token);
    Ok(Json(json!({
        "Object": "send-fileDownload",
        "Id": path.file_id,
        "Url": url,
    })))
}

#[derive(Deserialize)]
struct DownloadSendQuery {
    t: String,
}

async fn download_send(Path(path): Path<SendFilePath>, Query(t): Query<DownloadSendQuery>) -> Result<Response> {
    let Ok(claims) = crate::auth::decode_send(&t.t) else {
        return Err(Error::NotFound);
    };

    if claims.sub != format!("{}/{}", path.uuid, path.file_id) {
        return Err(Error::NotFound);
    }
    let conn = DB.get().await.ise()?;
    let Some(_) = Send::get(&conn, path.uuid).await? else {
        return Err(Error::NotFound);
    };

    let path = CONFIG.folders.sends().join(path.uuid.to_string()).join(path.file_id.to_string());
    match tokio::fs::read(&path).await {
        Ok(raw) => ([(CONTENT_DISPOSITION, "attachment")], Typed(ContentType::from(mime::APPLICATION_OCTET_STREAM)), raw).into_response(),
        Err(e) if e.kind() == ErrorKind::NotFound => Err(Error::NotFound),
        Err(e) => Err(Error::from(e)),
    }
}

async fn put_send(Path(uuid): Path<Uuid>, headers: Headers, data: Json<Upcase<SendData>>) -> Result<Json<Value>> {
    let conn = DB.get().await.ise()?;
    enforce_disable_send_policy(&headers, &conn).await?;

    let data: SendData = data.0.data;
    enforce_disable_hide_email_policy(&data, &headers, &conn).await?;

    let mut send = match Send::get_for_user(&conn, uuid, headers.user.uuid).await? {
        Some(s) => s,
        None => err!("Send not found"),
    };

    if send.atype != data.r#type {
        err!("Sends can't change type")
    }

    // When updating a file Send, we receive nulls in the File field, as it's immutable,
    // so we only need to update the data field in the Text case
    if data.r#type == SendType::Text {
        let data_str = if let Some(mut d) = data.text {
            d.as_object_mut().and_then(|d| d.remove("Response"));
            d
        } else {
            err!("Send data not provided");
        };
        send.data = data_str;
    }

    if data.deletion_date > Utc::now() + Duration::days(31) {
        err!(
            "You cannot have a Send with a deletion date that far into the future. Adjust the Deletion Date to a value less than 31 days from now and try again."
        );
    }
    send.name = data.name;
    send.akey = data.key;
    send.deletion_date = data.deletion_date;
    send.notes = data.notes;
    send.max_access_count = match data.max_access_count {
        Some(m) => Some(m),
        _ => None,
    };
    send.expiration_date = data.expiration_date.map(|d| d);
    send.hide_email = data.hide_email;
    send.disabled = data.disabled;

    // Only change the value if it's present
    if let Some(password) = data.password {
        send.set_password(Some(&password));
    }

    send.save(&conn).await?;
    ws_users().send_send_update(UpdateType::SyncSendUpdate, &send, &[send.user_uuid.unwrap()], headers.device.uuid, &conn).await?;

    Ok(Json(send.to_json()))
}

async fn delete_send(Path(uuid): Path<Uuid>, headers: Headers) -> Result<()> {
    let mut conn = DB.get().await.ise()?;

    let send = match Send::get_for_user(&conn, uuid, headers.user.uuid).await? {
        Some(s) => s,
        None => err!("Send not found"),
    };

    send.delete(&mut conn).await?;
    ws_users().send_send_update(UpdateType::SyncSendDelete, &send, &[send.user_uuid.unwrap()], headers.device.uuid, &conn).await?;

    Ok(())
}

async fn put_remove_password(Path(uuid): Path<Uuid>, headers: Headers) -> Result<Json<Value>> {
    let conn = DB.get().await.ise()?;

    enforce_disable_send_policy(&headers, &conn).await?;

    let mut send = match Send::get_for_user(&conn, uuid, headers.user.uuid).await? {
        Some(s) => s,
        None => err!("Send not found"),
    };

    send.set_password(None);
    send.save(&conn).await?;
    ws_users().send_send_update(UpdateType::SyncSendUpdate, &send, &[send.user_uuid.unwrap()], headers.device.uuid, &conn).await?;

    Ok(Json(send.to_json()))
}
