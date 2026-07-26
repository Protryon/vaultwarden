use std::io::ErrorKind;

use axol::http::{header::CONTENT_DISPOSITION, typed_headers::ContentType};
use axol::{Multipart, prelude::*};
use bytes::Bytes;
use chrono::{DateTime, Duration, Utc};
use serde::Deserialize;
use serde_json::{Value, json};
use serde_with::serde_as;
use uuid::Uuid;

use crate::{
    CONFIG,
    api::{Result, UpdateType, ws_users},
    auth::{ClientIp, Headers},
    db::{Attachment, Conn, DB, OrgPolicyType, OrganizationPolicy, Send, SendType},
    util::AutoTxn,
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
#[serde(rename_all = "camelCase")]
pub struct SendData {
    // Only sent by the account key-rotation flow, to match the send being re-keyed.
    #[serde(default)]
    pub id: Option<Uuid>,
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
    // Comma-separated recipient list for an email-restricted Send. Not supported here (see
    // `reject_email_restricted`), but it must be captured rather than ignored so the request
    // can be rejected instead of creating an unrestricted Send.
    emails: Option<String>,

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

/// Rejects Sends restricted to a list of recipient emails.
///
/// Bitwarden gates access to such a Send behind an emailed OTP; we have no storage or
/// verification flow for it. Accepting the request and dropping the field would hand the user
/// a Send they believe is restricted but that anyone with the link can open, so refuse instead.
/// Bitwarden treats a blank `emails` as "no restriction" (`SendRequestModel.cs`), so only a
/// non-blank list is an error.
fn reject_email_restricted(data: &SendData) -> Result<()> {
    if data.emails.as_deref().is_some_and(|emails| !emails.trim().is_empty()) {
        err!("Sends with email verification are not supported");
    }
    Ok(())
}

fn create_send(data: SendData, user_uuid: Uuid) -> Result<Send> {
    reject_email_restricted(&data)?;

    let data_val = if data.r#type == SendType::Text {
        data.text
    } else if data.r#type == SendType::File {
        data.file
    } else {
        err!("Invalid Send type")
    };

    let data_str = if let Some(mut d) = data_val {
        d.as_object_mut().and_then(|o| o.remove("response"));
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
    send.max_access_count = data.max_access_count;
    send.expiration_date = data.expiration_date;
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
      "data": sends_json,
      "object": "list",
      "continuationToken": null
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

async fn post_send(headers: Headers, data: Json<SendData>) -> Result<Json<Value>> {
    let conn = DB.get().await.ise()?;

    enforce_disable_send_policy(&headers, &conn).await?;

    let data: SendData = data.0;
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
                    let raw: SendData =
                        serde_json::from_slice(&field.bytes().await.ise()?[..]).map_err(|e| Error::bad_request(format!("invalid model: {e}")))?;
                    model = Some(raw);
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
        o.insert(String::from("id"), Value::String(file_id.to_string()));
        o.insert(String::from("size"), Value::Number(size.into()));
        o.insert(String::from("sizeName"), Value::String(crate::util::get_display_size(size as i32)));
    }

    send.save(&conn).await?;
    let conn = conn.commit().await?;
    ws_users().send_send_update(UpdateType::SyncSendCreate, &send, &[headers.user.uuid], headers.device.uuid, &conn).await?;

    Ok(Json(send.to_json()))
}

// Upstream: https://github.com/bitwarden/server/blob/d0c793c95181dfb1b447eb450f85ba0bfd7ef643/src/Api/Controllers/SendsController.cs#L190
async fn post_send_file_v2(headers: Headers, data: Json<SendData>) -> Result<Json<Value>> {
    let conn = DB.get().await.ise()?;
    enforce_disable_send_policy(&headers, &conn).await?;

    let data = data.0;

    if data.r#type != SendType::File {
        err!("Send content is not a file");
    }

    enforce_disable_hide_email_policy(&data, &headers, &conn).await?;

    let file_length = data.file_length;

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
        o.insert(String::from("id"), Value::String(file_id.to_string()));
        o.insert(String::from("size"), Value::Number(file_length.unwrap().into()));
        o.insert(String::from("sizeName"), Value::String(crate::util::get_display_size(file_length.unwrap())));
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
#[serde(rename_all = "camelCase")]
pub struct SendAccessData {
    pub password: Option<String>,
}

async fn post_access(Path(access_id): Path<String>, ip: ClientIp, data: Json<SendAccessData>) -> Result<Json<Value>> {
    let conn = DB.get().await.ise()?;

    let uuid = Send::decode_access_id(&access_id)?;

    let mut send = match Send::get(&conn, uuid).await? {
        Some(s) => s,
        None => err_code!(SEND_INACCESSIBLE_MSG, StatusCode::NotFound),
    };

    if let Some(max_access_count) = send.max_access_count
        && send.access_count >= max_access_count
    {
        err_code!(SEND_INACCESSIBLE_MSG, StatusCode::NotFound);
    }

    if let Some(expiration) = send.expiration_date
        && Utc::now() >= expiration
    {
        err_code!(SEND_INACCESSIBLE_MSG, StatusCode::NotFound)
    }

    if Utc::now() >= send.deletion_date {
        err_code!(SEND_INACCESSIBLE_MSG, StatusCode::NotFound)
    }

    if send.disabled {
        err_code!(SEND_INACCESSIBLE_MSG, StatusCode::NotFound)
    }

    if send.password_hash.is_some() {
        match data.0.password {
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

async fn post_access_file(Path(path): Path<SendFilePath>, data: Json<SendAccessData>) -> Result<Json<Value>> {
    let conn = DB.get().await.ise()?;

    let mut send = match Send::get(&conn, path.uuid).await? {
        Some(s) => s,
        None => err_code!(SEND_INACCESSIBLE_MSG, StatusCode::NotFound),
    };

    if let Some(max_access_count) = send.max_access_count
        && send.access_count >= max_access_count
    {
        err_code!(SEND_INACCESSIBLE_MSG, StatusCode::NotFound)
    }

    if let Some(expiration) = send.expiration_date
        && Utc::now() >= expiration
    {
        err_code!(SEND_INACCESSIBLE_MSG, StatusCode::NotFound)
    }

    if Utc::now() >= send.deletion_date {
        err_code!(SEND_INACCESSIBLE_MSG, StatusCode::NotFound)
    }

    if send.disabled {
        err_code!(SEND_INACCESSIBLE_MSG, StatusCode::NotFound)
    }

    if send.password_hash.is_some() {
        match data.0.password {
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
        "object": "send-fileDownload",
        "id": path.file_id,
        "url": url,
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

async fn put_send(Path(uuid): Path<Uuid>, headers: Headers, data: Json<SendData>) -> Result<Json<Value>> {
    let conn = DB.get().await.ise()?;
    enforce_disable_send_policy(&headers, &conn).await?;

    let data: SendData = data.0;
    enforce_disable_hide_email_policy(&data, &headers, &conn).await?;
    reject_email_restricted(&data)?;

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
    send.max_access_count = data.max_access_count;
    send.expiration_date = data.expiration_date;
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

/// Re-key an existing send during account key rotation: the send's wrapped key (`akey`) is
/// re-encrypted under the new user key, and the (re-encrypted) encrypted fields are refreshed.
/// Unlike a normal update this leaves dates, access counts, and the disabled flag untouched.
pub fn apply_send_rotation(send: &mut Send, data: SendData) -> Result<()> {
    if send.atype != data.r#type {
        err!("Sends can't change type")
    }
    // The file blob is immutable, so only Text sends carry updated data.
    if data.r#type == SendType::Text
        && let Some(mut d) = data.text
    {
        d.as_object_mut().and_then(|d| d.remove("Response"));
        send.data = d;
    }
    send.name = data.name;
    send.akey = data.key;
    send.notes = data.notes;
    Ok(())
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

#[cfg(test)]
mod tests {
    use serde_json::json;

    use crate::test_harness::TestClient;

    #[tokio::test]
    async fn create_list_get_update_delete_text_send() {
        let client = TestClient::register_and_login().await;

        let created = client.create_text_send("2.mysend|mac").await;
        assert_eq!(created["object"], "send");
        assert_eq!(created["name"], "2.mysend|mac");
        assert_eq!(created["authType"], 2, "a passwordless send reports authType None (2): {}", created);
        let id = created["id"].as_str().expect("send id").to_string();

        // List.
        let list = client.get("/api/sends").await;
        list.assert_ok();
        let data = list.json();
        assert_eq!(data["object"], "list");
        let ids: Vec<&str> = data["data"].as_array().unwrap().iter().filter_map(|s| s["id"].as_str()).collect();
        assert!(ids.contains(&id.as_str()), "created send not in list: {}", list.body);

        // Get.
        let got = client.get(&format!("/api/sends/{id}")).await;
        got.assert_ok();
        assert_eq!(got.json()["id"], id);

        // Update (rename).
        let deletion = (chrono::Utc::now() + chrono::Duration::days(5)).to_rfc3339();
        let update = json!({
            "type": 0,
            "key": "2.sendkey|mac",
            "name": "2.renamed|mac",
            "text": { "text": "2.secret|mac", "hidden": false },
            "deletionDate": deletion,
            "disabled": false,
        });
        let updated = client.put(&format!("/api/sends/{id}"), update).await;
        updated.assert_ok();
        assert_eq!(updated.json()["name"], "2.renamed|mac");

        // Delete.
        client.delete(&format!("/api/sends/{id}")).await.assert_ok();
        let after = client.get(&format!("/api/sends/{id}")).await;
        assert!(after.status >= 400, "expected deleted send to be gone, got {}: {}", after.status, after.body);
    }

    #[tokio::test]
    async fn send_can_be_accessed_anonymously() {
        let owner = TestClient::register_and_login().await;
        let created = owner.create_text_send("2.public|mac").await;
        let access_id = created["accessId"].as_str().expect("accessId").to_string();

        // An unauthenticated client can access it by accessId.
        let anon = TestClient::new().await;
        let resp = anon.post(&format!("/api/sends/access/{access_id}"), json!({ "password": null })).await;
        resp.assert_ok();
        assert_eq!(resp.json()["object"], "send-access");
    }

    #[tokio::test]
    async fn remove_password_from_send() {
        let client = TestClient::register_and_login().await;
        let id = client.create_text_send("2.pw|mac").await["id"].as_str().unwrap().to_string();

        let resp = client.put(&format!("/api/sends/{id}/remove-password"), json!({})).await;
        resp.assert_ok();
    }

    #[tokio::test]
    async fn sends_are_isolated_per_user() {
        let alice = TestClient::register_and_login().await;
        let bob = TestClient::register_and_login().await;
        let id = alice.create_text_send("2.alice|mac").await["id"].as_str().unwrap().to_string();

        let cross = bob.get(&format!("/api/sends/{id}")).await;
        assert!(cross.status >= 400, "user should not see another user's send, got {}: {}", cross.status, cross.body);
    }

    // Email-restricted sends are not supported. The request must be refused outright rather
    // than accepted with the restriction dropped, which would leave the send open to anyone
    // holding the link while the client shows it as restricted.
    #[tokio::test]
    async fn email_restricted_send_is_rejected() {
        let client = TestClient::register_and_login().await;
        let deletion = (chrono::Utc::now() + chrono::Duration::days(7)).to_rfc3339();
        let body = |emails: serde_json::Value| {
            json!({
                "type": 0,
                "key": "2.sendkey|mac",
                "name": "2.restricted|mac",
                "text": { "text": "2.secret|mac", "hidden": false },
                "deletionDate": deletion,
                "disabled": false,
                "emails": emails,
            })
        };

        let resp = client.post("/api/sends", body(json!("someone@example.com,other@example.com"))).await;
        assert!(resp.status >= 400, "email-restricted send should be refused, got {}: {}", resp.status, resp.body);

        // A blank list means "no restriction" to Bitwarden, so it must still create.
        let created = client.post("/api/sends", body(json!(""))).await;
        created.assert_ok();

        // Updating an existing send into an email-restricted one is refused too.
        let id = created.json()["id"].as_str().expect("send id").to_string();
        let updated = client.put(&format!("/api/sends/{id}"), body(json!("someone@example.com"))).await;
        assert!(updated.status >= 400, "update to email-restricted send should be refused, got {}: {}", updated.status, updated.body);
    }

    #[tokio::test]
    async fn sends_require_auth() {
        let client = TestClient::new().await;
        client.get("/api/sends").await.assert_status(401);
    }

    #[tokio::test]
    async fn legacy_file_send_upload() {
        let owner = TestClient::register_and_login().await;
        let contents = "legacy-send-file-bytes";
        let deletion = (chrono::Utc::now() + chrono::Duration::days(7)).to_rfc3339();

        // The legacy endpoint takes the model and the bytes in one multipart POST.
        let model = json!({
            "type": 1, // File
            "key": "2.sendkey|mac",
            "name": "2.legacyfile|mac",
            "file": { "fileName": "2.secret.txt|mac" },
            "fileLength": contents.len(),
            "deletionDate": deletion,
            "disabled": false,
        })
        .to_string();

        let resp = owner.post_multipart("/api/sends/file", &[("model", None, model.as_bytes()), ("data", Some("2.secret.txt|mac"), contents.as_bytes())]).await;
        resp.assert_ok();
        let created = resp.json();
        assert_eq!(created["type"], 1);
        let id = created["id"].as_str().expect("send id").to_string();

        // It's listed.
        let list = owner.get("/api/sends").await;
        let ids: Vec<String> = list.json()["data"].as_array().unwrap().iter().filter_map(|s| s["id"].as_str().map(String::from)).collect();
        assert!(ids.contains(&id), "legacy file send not listed: {}", list.body);

        // The stored file carries its id under "id" (regression guard: it was once "od"),
        // so a recipient can resolve and download it anonymously.
        let file_id = created["file"]["id"].as_str().expect("file id under \"id\"").to_string();
        let anon = TestClient::new().await;
        let file_access = anon.post(&format!("/api/sends/{id}/access/file/{file_id}"), json!({ "password": null })).await;
        file_access.assert_ok();
        let dl_url = file_access.json()["url"].as_str().expect("download url").to_string();
        let rel = &dl_url[dl_url.find("/api/").expect("api path in download url")..];
        let download = anon.get(rel).await;
        download.assert_ok();
        assert_eq!(download.body, contents, "downloaded bytes should match what was uploaded");
    }

    #[tokio::test]
    async fn file_send_v2_upload_access_download() {
        let owner = TestClient::register_and_login().await;
        let contents = "encrypted-send-file-bytes";
        let deletion = (chrono::Utc::now() + chrono::Duration::days(7)).to_rfc3339();

        // 1. Reserve the file send (v2 handshake) and get the upload URL.
        let create = owner
            .post(
                "/api/sends/file/v2",
                json!({
                    "type": 1, // File
                    "key": "2.sendkey|mac",
                    "name": "2.filesend|mac",
                    "file": { "fileName": "2.secret.txt|mac" },
                    "fileLength": contents.len(),
                    "deletionDate": deletion,
                    "disabled": false,
                }),
            )
            .await;
        create.assert_ok();
        let cj = create.json();
        assert_eq!(cj["object"], "send-fileUpload");
        let upload_path = cj["url"].as_str().expect("upload url").to_string(); // /sends/{uuid}/file/{file_id}
        let send_id = cj["sendResponse"]["id"].as_str().unwrap().to_string();
        let access_id = cj["sendResponse"]["accessId"].as_str().expect("accessId").to_string();
        let file_id = upload_path.rsplit('/').next().unwrap().to_string();

        // 2. Upload the bytes to the returned URL (server routes are under /api).
        owner.post_multipart(&format!("/api{upload_path}"), &[("data", Some("2.secret.txt|mac"), contents.as_bytes())]).await.assert_ok();

        // 3. Anonymous access to the send metadata by accessId.
        let anon = TestClient::new().await;
        let access = anon.post(&format!("/api/sends/access/{access_id}"), json!({ "password": null })).await;
        access.assert_ok();
        assert_eq!(access.json()["type"], 1, "should be a file send: {}", access.body);

        // 4. Request a download token for the file, then download it.
        let file_access = anon.post(&format!("/api/sends/{send_id}/access/file/{file_id}"), json!({ "password": null })).await;
        file_access.assert_ok();
        let dl_url = file_access.json()["url"].as_str().expect("download url").to_string();
        // The URL is absolute (built from the public config); take the path+query and
        // fetch it against the test server (same host) so the JWT `t` token is preserved.
        let rel = &dl_url[dl_url.find("/api/").expect("api path in download url")..];
        let download = anon.get(rel).await;
        download.assert_ok();
        assert_eq!(download.body, contents, "downloaded bytes should match what was uploaded");
    }
}
