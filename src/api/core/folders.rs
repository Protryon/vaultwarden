use axol::prelude::*;
use serde::Deserialize;
use serde_json::{Value, json};
use uuid::Uuid;

use crate::{
    api::{UpdateType, ws_users},
    auth::Headers,
    db::{DB, Folder},
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

#[cfg(test)]
mod tests {
    use serde_json::json;

    use crate::test_harness::TestClient;

    #[tokio::test]
    async fn create_list_get_update_delete_folder() {
        let client = TestClient::register_and_login().await;

        // Create.
        let resp = client.post("/api/folders", json!({ "name": "2.encryptedname|mac" })).await;
        resp.assert_ok();
        let created = resp.json();
        assert_eq!(created["object"], "folder");
        assert_eq!(created["name"], "2.encryptedname|mac");
        let id = created["id"].as_str().expect("folder id").to_string();

        // List — the new folder should be present.
        let list = client.get("/api/folders").await;
        list.assert_ok();
        let data = list.json();
        assert_eq!(data["object"], "list");
        let ids: Vec<&str> = data["data"].as_array().unwrap().iter().filter_map(|f| f["id"].as_str()).collect();
        assert!(ids.contains(&id.as_str()), "created folder not in list: {}", list.body);

        // Get by id.
        let got = client.get(&format!("/api/folders/{id}")).await;
        got.assert_ok();
        assert_eq!(got.json()["id"], id);

        // Update (rename).
        let updated = client.put(&format!("/api/folders/{id}"), json!({ "name": "2.renamed|mac" })).await;
        updated.assert_ok();
        assert_eq!(updated.json()["name"], "2.renamed|mac");

        // Delete.
        client.delete(&format!("/api/folders/{id}")).await.assert_ok();

        // Getting it again should now fail.
        let after = client.get(&format!("/api/folders/{id}")).await;
        assert!(after.status >= 400, "expected deleted folder to be gone, got {}: {}", after.status, after.body);
    }

    #[tokio::test]
    async fn folders_are_isolated_per_user() {
        // A folder created by one user must not be visible to another.
        let alice = TestClient::register_and_login().await;
        let bob = TestClient::register_and_login().await;

        let created = alice.post("/api/folders", json!({ "name": "2.alicefolder|mac" })).await;
        created.assert_ok();
        let id = created.json()["id"].as_str().unwrap().to_string();

        // Bob cannot fetch Alice's folder.
        let cross = bob.get(&format!("/api/folders/{id}")).await;
        assert!(cross.status >= 400, "user should not see another user's folder, got {}: {}", cross.status, cross.body);

        // Bob's list is empty of Alice's folder.
        let bob_list = bob.get("/api/folders").await;
        bob_list.assert_ok();
        let bob_data = bob_list.json();
        let ids: Vec<&str> = bob_data["data"].as_array().unwrap().iter().filter_map(|f| f["id"].as_str()).collect();
        assert!(!ids.contains(&id.as_str()), "another user's folder leaked into list");
    }

    #[tokio::test]
    async fn folder_endpoints_require_auth() {
        let client = TestClient::new().await;
        client.get("/api/folders").await.assert_status(401);
    }
}
