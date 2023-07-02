use axum::{extract::Path, Json};
use axum_util::errors::ApiResult;
use serde::Deserialize;
use serde_json::{json, Value};
use uuid::Uuid;

use crate::{
    api::{ws_users, UpdateType},
    auth::Headers,
    db::{Folder, DB},
    util::Upcase,
};

pub async fn get_folders(headers: Headers) -> ApiResult<Json<Value>> {
    let conn = DB.get().await?;
    let folders = Folder::find_by_user(&conn, headers.user.uuid).await?;
    let folders_json: Vec<Value> = folders.iter().map(Folder::to_json).collect();

    Ok(Json(json!({
      "Data": folders_json,
      "Object": "list",
      "ContinuationToken": null,
    })))
}

pub async fn get_folder(Path(uuid): Path<Uuid>, headers: Headers) -> ApiResult<Json<Value>> {
    let conn = DB.get().await?;
    let folder = match Folder::get_with_user(&conn, uuid, headers.user.uuid).await? {
        Some(folder) => folder,
        _ => err!("Invalid folder"),
    };

    Ok(Json(folder.to_json()))
}

#[derive(Deserialize)]
#[serde(rename_all = "PascalCase")]
pub struct FolderData {
    pub name: String,
}

pub async fn post_folders(headers: Headers, data: Json<Upcase<FolderData>>) -> ApiResult<Json<Value>> {
    let data: FolderData = data.0.data;

    let mut folder = Folder::new(headers.user.uuid, data.name);
    let conn = DB.get().await?;

    folder.save(&conn).await?;
    ws_users().send_folder_update(UpdateType::SyncFolderCreate, &folder, headers.device.uuid, &conn).await?;

    Ok(Json(folder.to_json()))
}

pub async fn put_folder(Path(uuid): Path<Uuid>, headers: Headers, data: Json<Upcase<FolderData>>) -> ApiResult<Json<Value>> {
    let data: FolderData = data.0.data;
    let conn = DB.get().await?;

    let mut folder = match Folder::get_with_user(&conn, uuid, headers.user.uuid).await? {
        Some(folder) => folder,
        _ => err!("Invalid folder"),
    };

    folder.name = data.name;

    folder.save(&conn).await?;
    ws_users().send_folder_update(UpdateType::SyncFolderUpdate, &folder, headers.device.uuid, &conn).await?;

    Ok(Json(folder.to_json()))
}

pub async fn delete_folder(Path(uuid): Path<Uuid>, headers: Headers) -> ApiResult<()> {
    let conn = DB.get().await?;

    let folder = match Folder::get_with_user(&conn, uuid, headers.user.uuid).await? {
        Some(folder) => folder,
        _ => err!("Invalid folder"),
    };

    // Delete the actual folder entry
    folder.delete(&conn).await?;

    ws_users().send_folder_update(UpdateType::SyncFolderDelete, &folder, headers.device.uuid, &conn).await?;
    Ok(())
}
