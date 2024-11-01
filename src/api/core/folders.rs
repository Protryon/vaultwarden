use axol::prelude::*;
use serde::Deserialize;
use serde_json::{json, Value};
use uuid::Uuid;

use crate::{
    api::{ws_users, UpdateType},
    auth::Headers,
    db::{Folder, DB},
};

pub async fn get_folders(headers: Headers) -> Result<Json<Value>> {
    let conn = DB.get().await.ise()?;
    let folders = Folder::find_by_user(&conn, headers.user.uuid).await?;
    let folders_json: Vec<Value> = folders.iter().map(Folder::to_json).collect();

    Ok(Json(json!({
      "data": folders_json,
      "object": "list",
      "continuationToken": null,
    })))
}

pub async fn get_folder(Path(uuid): Path<Uuid>, headers: Headers) -> Result<Json<Value>> {
    let conn = DB.get().await.ise()?;
    let folder = match Folder::get_with_user(&conn, uuid, headers.user.uuid).await? {
        Some(folder) => folder,
        _ => err!("Invalid folder"),
    };

    Ok(Json(folder.to_json()))
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct FolderData {
    pub name: String,
}

pub async fn post_folders(headers: Headers, data: Json<FolderData>) -> Result<Json<Value>> {
    let data: FolderData = data.0;

    let mut folder = Folder::new(headers.user.uuid, data.name);
    let conn = DB.get().await.ise()?;

    folder.save(&conn).await?;
    ws_users().send_folder_update(UpdateType::SyncFolderCreate, &folder, headers.device.uuid, &conn).await?;

    Ok(Json(folder.to_json()))
}

pub async fn put_folder(Path(uuid): Path<Uuid>, headers: Headers, data: Json<FolderData>) -> Result<Json<Value>> {
    let data: FolderData = data.0;
    let conn = DB.get().await.ise()?;

    let mut folder = match Folder::get_with_user(&conn, uuid, headers.user.uuid).await? {
        Some(folder) => folder,
        _ => err!("Invalid folder"),
    };

    folder.name = data.name;

    folder.save(&conn).await?;
    ws_users().send_folder_update(UpdateType::SyncFolderUpdate, &folder, headers.device.uuid, &conn).await?;

    Ok(Json(folder.to_json()))
}

pub async fn delete_folder(Path(uuid): Path<Uuid>, headers: Headers) -> Result<()> {
    let conn = DB.get().await.ise()?;

    let folder = match Folder::get_with_user(&conn, uuid, headers.user.uuid).await? {
        Some(folder) => folder,
        _ => err!("Invalid folder"),
    };

    // Delete the actual folder entry
    folder.delete(&conn).await?;

    ws_users().send_folder_update(UpdateType::SyncFolderDelete, &folder, headers.device.uuid, &conn).await?;
    Ok(())
}
