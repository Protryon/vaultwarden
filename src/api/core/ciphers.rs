use std::collections::{HashMap, HashSet};

use axol::prelude::*;
use axol::Multipart;
use bytes::Bytes;
use chrono::{DateTime, Utc};
use log::warn;
use serde::Deserialize;
use serde::{de::Error as _E, Deserializer};
use serde_json::{json, Value};
use uuid::Uuid;

use crate::{
    api::{self, ws_users, PasswordData, UpdateType},
    auth::Headers,
    db::{
        Attachment, Cipher, CipherType, Collection, CollectionCipher, CollectionWithAccess, Conn, EventType, Folder, FullCipher, OrgPolicyType,
        OrganizationPolicy, RepromptType, UserOrgType, UserOrganization, DB,
    },
    events::log_event,
    util::AutoTxn,
    CONFIG,
};

use super::{folders::FolderData, GlobalDomainQuery};

pub fn route(router: Router) -> Router {
    router
        .get("/sync", sync)
        .get("/ciphers", get_ciphers)
        .get("/ciphers/:uuid", get_cipher)
        .get("/ciphers/:uuid/admin", get_cipher)
        .get("/ciphers/:uuid/details", get_cipher)
        .post("/ciphers/admin", post_ciphers_create)
        .post("/ciphers/create", post_ciphers_create)
        .post("/ciphers", post_ciphers)
        .post("/ciphers/import", post_ciphers_import)
        .put("/ciphers/:uuid/admin", put_cipher)
        .post("/ciphers/:uuid/admin", put_cipher)
        .put("/ciphers/:uuid", put_cipher)
        .post("/ciphers/:uuid", put_cipher)
        .put("/ciphers/:uuid/partial", put_cipher_partial)
        .post("/ciphers/:uuid/partial", put_cipher_partial)
        .put("/ciphers/:uuid/collections", post_collections)
        .post("/ciphers/:uuid/collections", post_collections)
        .put("/ciphers/:uuid/collections-admin", post_collections)
        .post("/ciphers/:uuid/collections-admin", post_collections)
        .put("/ciphers/:uuid/share", put_cipher_share)
        .post("/ciphers/:uuid/share", put_cipher_share)
        .put("/ciphers/share", put_cipher_share_selected)
        .get("/ciphers/:uuid/attachment/:attachment_id", get_attachment)
        .post("/ciphers/:uuid/attachment/v2", post_attachment_v2)
        .post("/ciphers/:uuid/attachment/:attachment_id", post_attachment_v2_data)
        .post("/ciphers/:uuid/attachment", post_attachment)
        .post("/ciphers/:uuid/attachment-admin", post_attachment)
        .post("/ciphers/:uuid/attachment/:attachment_id/share", post_attachment_share)
        .post("/ciphers/:uuid/attachment/:attachment_id/delete-admin", delete_attachment)
        .post("/ciphers/:uuid/attachment/:attachment_id/delete", delete_attachment)
        .delete("/ciphers/:uuid/attachment/:attachment_id", delete_attachment)
        .delete("/ciphers/:uuid/attachment/:attachment_id/admin", delete_attachment)
        .post("/ciphers/:uuid/delete", delete_cipher_hard)
        .post("/ciphers/:uuid/delete-admin", delete_cipher_hard)
        .put("/ciphers/:uuid/delete", delete_cipher_soft)
        .put("/ciphers/:uuid/delete-admin", delete_cipher_soft)
        .delete("/ciphers/:uuid", delete_cipher_hard)
        .delete("/ciphers/:uuid/admin", delete_cipher_hard)
        .delete("/ciphers", delete_cipher_selected_hard)
        .post("/ciphers/delete", delete_cipher_selected_hard)
        .put("/ciphers/delete", delete_cipher_selected_soft)
        .delete("/ciphers/admin", delete_cipher_selected_hard)
        .post("/ciphers/delete-admin", delete_cipher_selected_hard)
        .put("/ciphers/delete-admin", delete_cipher_selected_soft)
        .put("/ciphers/:uuid/restore", restore_cipher_put)
        .put("/ciphers/:uuid/restore-admin", restore_cipher_put)
        .put("/ciphers/restore", restore_cipher_selected)
        .post("/ciphers/move", move_cipher_selected)
        .put("/ciphers/move", move_cipher_selected)
        .post("/ciphers/purge", delete_all)
}

#[derive(Deserialize, Default)]
pub struct SyncData {
    #[serde(rename = "excludeDomains", default)]
    exclude_domains: bool,
}

pub async fn sync(Query(data): Query<SyncData>, headers: Headers) -> Result<Json<Value>> {
    let conn = DB.get().await.ise()?;
    let user_json = headers.user.to_json(&conn).await?;

    let ciphers_json = FullCipher::find_by_user(&conn, headers.user.uuid).await?.iter().map(|x| x.to_json(true)).collect::<Vec<_>>();

    let collections_json =
        CollectionWithAccess::find_by_user(&conn, headers.user.uuid).await?.iter().map(CollectionWithAccess::to_json_details).collect::<Vec<_>>();

    let folders_json: Vec<Value> = Folder::find_by_user(&conn, headers.user.uuid).await?.iter().map(Folder::to_json).collect();

    let sends_json: Vec<Value> = crate::db::Send::find_by_user(&conn, headers.user.uuid).await?.iter().map(crate::db::Send::to_json).collect();

    let policies_json: Vec<Value> =
        OrganizationPolicy::find_confirmed_by_user(&conn, headers.user.uuid).await?.iter().map(OrganizationPolicy::to_json).collect();

    let domains_json = if data.exclude_domains {
        Value::Null
    } else {
        api::core::get_eq_domains(
            headers,
            Query(GlobalDomainQuery {
                no_excluded: true,
            }),
        )
        .await
        .0
    };

    Ok(Json(json!({
        "profile": user_json,
        "folders": folders_json,
        "collections": collections_json,
        "policies": policies_json,
        "ciphers": ciphers_json,
        "domains": domains_json,
        "sends": sends_json,
        "unofficialServer": true,
        "object": "sync"
    })))
}

pub async fn get_ciphers(headers: Headers) -> Result<Json<Value>> {
    let conn = DB.get().await.ise()?;

    let ciphers_json = FullCipher::find_by_user(&conn, headers.user.uuid).await?.iter().map(|x| x.to_json(true)).collect::<Vec<_>>();

    Ok(Json(json!({
      "data": ciphers_json,
      "object": "list",
      "continuationToken": null
    })))
}

pub async fn get_cipher(Path(uuid): Path<Uuid>, headers: Headers) -> Result<Json<Value>> {
    let conn = DB.get().await.ise()?;
    let cipher = match Cipher::get_for_user(&conn, headers.user.uuid, uuid).await? {
        Some(cipher) => cipher,
        None => err!("Cipher doesn't exist"),
    };

    Ok(Json(cipher.to_json(&conn, headers.user.uuid, true).await?))
}

#[derive(Deserialize, Debug)]
#[serde(rename_all = "camelCase")]
pub struct CipherData {
    // Id is optional as it is included only in bulk share
    pub id: Option<Uuid>,
    // Folder id is not included in import
    folder_id: Option<Uuid>,
    // TODO: Some of these might appear all the time, no need for Option
    organization_id: Option<Uuid>,

    /*
    Login = 1,
    SecureNote = 2,
    Card = 3,
    Identity = 4
    Fido2Key = 5
    */
    pub r#type: CipherType,
    pub name: String,
    pub notes: Option<String>,
    fields: Option<Vec<Value>>,

    // Only one of these should exist, depending on type
    login: Option<Value>,
    secure_note: Option<Value>,
    card: Option<Value>,
    identity: Option<Value>,
    fido2_key: Option<Value>,

    favorite: Option<bool>,
    reprompt: Option<RepromptType>,

    password_history: Option<Value>,

    // These are used during key rotation
    // 'Attachments' is unused, contains map of {id: filename}
    #[serde(rename = "Attachments")]
    _attachments: Option<Value>,
    attachments2: Option<HashMap<Uuid, Attachments2Data>>,

    // The revision datetime (in ISO 8601 format) of the client's local copy
    // of the cipher. This is used to prevent a client from updating a cipher
    // when it doesn't have the latest version, as that can result in data
    // loss. It's not an error when no value is provided; this can happen
    // when using older client versions, or if the operation doesn't involve
    // updating an existing cipher.
    #[serde(deserialize_with = "deserialize_last_known_revision_date")]
    last_known_revision_date: Option<DateTime<Utc>>,
}

fn deserialize_last_known_revision_date<'de, D: Deserializer<'de>>(de: D) -> Result<Option<DateTime<Utc>>, D::Error> {
    let Some(raw_str): Option<String> = Option::<String>::deserialize(de)? else {
        return Ok(None);
    };
    if raw_str == "0001-01-01T00:00:00" {
        return Ok(None);
    }
    Ok(Some(raw_str.parse().map_err(D::Error::custom)?))
}

#[derive(Deserialize, Debug)]
#[serde(rename_all = "camelCase")]
pub struct PartialCipherData {
    folder_id: Option<Uuid>,
    favorite: bool,
}

#[derive(Deserialize, Debug)]
#[serde(rename_all = "camelCase")]
pub struct Attachments2Data {
    file_name: String,
    key: String,
}

/// Called when creating a new org-owned cipher, or cloning a cipher (whether
/// user- or org-owned). When cloning a cipher to a user-owned cipher,
/// `organizationId` is null.
pub async fn post_ciphers_create(mut conn: AutoTxn, headers: Headers, data: Json<ShareCipherData>) -> Result<Json<Value>> {
    let mut data: ShareCipherData = data.0;

    // Check if there are one more more collections selected when this cipher is part of an organization.
    // err if this is not the case before creating an empty cipher.
    if data.cipher.organization_id.is_some() && data.collection_ids.is_empty() {
        err!("You must select at least one collection.");
    }

    // This check is usually only needed in update_cipher_from_data(), but we
    // need it here as well to avoid creating an empty cipher in the call to
    // cipher.save() below.
    enforce_personal_ownership_policy(Some(&data.cipher), &headers, &conn).await?;

    let mut cipher = Cipher::new(data.cipher.r#type, data.cipher.name.clone());
    cipher.user_uuid = Some(headers.user.uuid);
    cipher.save(&conn).await?;

    // When cloning a cipher, the Bitwarden clients seem to set this field
    // based on the cipher being cloned (when creating a new cipher, it's set
    // to null as expected). However, `cipher.created_at` is initialized to
    // the current time, so the stale data check will end up failing down the
    // line. Since this function only creates new ciphers (whether by cloning
    // or otherwise), we can just ignore this field entirely.
    data.cipher.last_known_revision_date = None;

    let out = share_cipher_by_uuid(cipher.uuid, data, &headers, &mut conn).await?;
    conn.commit().await?;

    Ok(out)
}

/// Called when creating a new user-owned cipher.
pub async fn post_ciphers(mut conn: AutoTxn, headers: Headers, data: Json<CipherData>) -> Result<Json<Value>> {
    let mut data: CipherData = data.0;

    // The web/browser clients set this field to null as expected, but the
    // mobile clients seem to set the invalid value `0001-01-01T00:00:00`,
    // which results in a warning message being logged. This field isn't
    // needed when creating a new cipher, so just ignore it unconditionally.
    data.last_known_revision_date = None;

    let mut cipher = Cipher::new(data.r#type, data.name.clone());
    update_cipher_from_data(&mut cipher, data, &headers, false, &mut conn, UpdateType::SyncCipherCreate).await?;

    let out = Json(cipher.to_json(&conn, headers.user.uuid, true).await?);
    conn.commit().await?;
    Ok(out)
}

/// Enforces the personal ownership policy on user-owned ciphers, if applicable.
/// A non-owner/admin user belonging to an org with the personal ownership policy
/// enabled isn't allowed to create new user-owned ciphers or modify existing ones
/// (that were created before the policy was applicable to the user). The user is
/// allowed to delete or share such ciphers to an org, however.
///
/// Ref: https://bitwarden.com/help/article/policies/#personal-ownership
async fn enforce_personal_ownership_policy(data: Option<&CipherData>, headers: &Headers, conn: &Conn) -> Result<()> {
    if data.is_none() || data.unwrap().organization_id.is_none() {
        let user_uuid = headers.user.uuid;
        let policy_type = OrgPolicyType::PersonalOwnership;
        if OrganizationPolicy::is_applicable_to_user(conn, user_uuid, policy_type, None).await? {
            err!("Due to an Enterprise Policy, you are restricted from saving items to your personal vault.")
        }
    }
    Ok(())
}

pub async fn update_cipher_from_data(
    cipher: &mut Cipher,
    data: CipherData,
    headers: &Headers,
    shared_to_collection: bool,
    conn: &mut AutoTxn,
    ut: UpdateType,
) -> Result<()> {
    enforce_personal_ownership_policy(Some(&data), headers, conn).await?;

    // Check that the client isn't updating an existing cipher with stale data.
    if let Some(dt) = data.last_known_revision_date {
        if cipher.updated_at.signed_duration_since(dt).num_seconds() > 1 {
            err!("The client copy of this cipher is out of date. Resync the client and try again.");
        }
    }

    if cipher.organization_uuid.is_some() && cipher.organization_uuid != data.organization_id {
        err!("Organization mismatch. Please resync the client before updating the cipher")
    }

    if let Some(note) = &data.notes {
        if note.len() > 10_000 {
            err!("The field Notes exceeds the maximum encrypted value length of 10000 characters.")
        }
    }

    // Check if this cipher is being transferred from a personal to an organization vault
    let transfer_cipher = cipher.organization_uuid.is_none() && data.organization_id.is_some();

    if let Some(org_id) = data.organization_id {
        match UserOrganization::get(conn, headers.user.uuid, org_id).await? {
            None => err!("You don't have permission to add item to organization"),
            Some(org_user) => {
                if shared_to_collection || org_user.has_full_access() || cipher.is_write_accessible_to_user(conn, headers.user.uuid).await? {
                    cipher.organization_uuid = Some(org_id);
                    // After some discussion in PR #1329 re-added the user_uuid = None again.
                    // TODO: Audit/Check the whole save/update cipher chain.
                    // Upstream uses the user_uuid to allow a cipher added by a user to an org to still allow the user to view/edit the cipher
                    // even when the user has hide-passwords configured as there policy.
                    // Removing the line below would fix that, but we have to check which effect this would have on the rest of the code.
                    cipher.user_uuid = None;
                } else {
                    err!("You don't have permission to add cipher directly to organization")
                }
            }
        }
    } else {
        cipher.user_uuid = Some(headers.user.uuid);
    }

    if let Some(folder_id) = data.folder_id {
        match Folder::get_with_user(conn, folder_id, headers.user.uuid).await? {
            Some(_) => (),
            None => err!("Folder doesn't exist"),
        }
    }

    // Modify attachments name and keys when rotating
    if let Some(attachments) = data.attachments2 {
        for (id, attachment) in attachments {
            let mut saved_att = match Attachment::get(conn, id).await? {
                Some(att) => att,
                None => {
                    // Warn and continue here.
                    // A missing attachment means it was removed via an other client.
                    // Also the Desktop Client supports removing attachments and save an update afterwards.
                    // Bitwarden it self ignores these mismatches server side.
                    warn!("Attachment {id} doesn't exist");
                    continue;
                }
            };

            if saved_att.cipher_uuid != cipher.uuid {
                // Warn and break here since cloning ciphers provides attachment data but will not be cloned.
                // If we error out here it will break the whole cloning and causes empty ciphers to appear.
                warn!("Attachment is not owned by the cipher");
                break;
            }

            saved_att.akey = Some(attachment.key);
            saved_att.file_name = attachment.file_name;

            saved_att.save(conn).await?;
        }
    }

    // Cleanup cipher data, like removing the 'response' key.
    // This key is somewhere generated during Javascript so no way for us this fix this.
    // Also, upstream only retrieves keys they actually want to store, and thus skip the 'Response' key.
    // We do not mind which data is in it, the keep our model more flexible when there are upstream changes.
    // But, we at least know we do not need to store and return this specific key.
    fn _clean_cipher_data(mut json_data: Vec<Value>) -> Vec<Value> {
        json_data.iter_mut().for_each(|ref mut f| {
            f.as_object_mut().unwrap().remove("response");
        });
        json_data
    }

    let type_data_opt = match data.r#type {
        CipherType::Login => data.login,
        CipherType::SecureNote => data.secure_note,
        CipherType::Card => data.card,
        CipherType::Identity => data.identity,
        CipherType::Fido2Key => data.fido2_key,
        _ => err!("Invalid type"),
    };

    let type_data = match type_data_opt {
        Some(mut data) => {
            // Remove the 'Response' key from the base object.
            data.as_object_mut().unwrap().remove("response");
            // Remove the 'Response' key from every Uri.
            if data["uris"].is_array() {
                data["uris"] = Value::Array(_clean_cipher_data(data["uris"].as_array().unwrap().clone()));
            }
            data
        }
        None => err!("Data missing"),
    };

    cipher.name = data.name;
    cipher.notes = data.notes;
    cipher.fields = data.fields.map(|f| _clean_cipher_data(f));
    cipher.data = type_data;
    cipher.password_history = data.password_history.map(|f| serde_json::from_value(f)).transpose().ise()?.unwrap_or_default();
    cipher.reprompt = data.reprompt;

    cipher.save(conn).await?;
    cipher.move_to_folder(conn, data.folder_id, headers.user.uuid).await?;
    if let Some(favorite) = data.favorite {
        cipher.set_favorite(conn, favorite, headers.user.uuid).await?;
    }

    if ut != UpdateType::None {
        // Only log events for organizational ciphers
        if let Some(org_uuid) = cipher.organization_uuid {
            let event_type = match (&ut, transfer_cipher) {
                (UpdateType::SyncCipherCreate, true) => EventType::CipherCreated,
                (UpdateType::SyncCipherUpdate, true) => EventType::CipherShared,
                (_, _) => EventType::CipherUpdated,
            };

            log_event(event_type, cipher.uuid, org_uuid, headers.user.uuid, headers.device.atype, Utc::now(), headers.ip, conn).await?;
        }
        let cipher = cipher.clone();
        let acting_device_uuid = headers.device.uuid;
        conn.defer(move || {
            tokio::spawn(async move {
                let Ok(conn) = DB.get().await else {
                    return;
                };
                ws_users().send_cipher_update_all(ut, &cipher, acting_device_uuid, None, &conn).await;
            });
        });
    }
    Ok(())
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ImportData {
    ciphers: Vec<CipherData>,
    folders: Vec<FolderData>,
    folder_relationships: Vec<RelationsData>,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct RelationsData {
    // Cipher id
    key: usize,
    // Folder id
    value: usize,
}

pub async fn post_ciphers_import(mut conn: AutoTxn, headers: Headers, data: Json<ImportData>) -> Result<()> {
    enforce_personal_ownership_policy(None, &headers, &conn).await?;

    let data: ImportData = data.0;

    // Validate the import before continuing
    // Bitwarden does not process the import if there is one item invalid.
    // Since we check for the size of the encrypted note length, we need to do that here to pre-validate it.
    // TODO: See if we can optimize the whole cipher adding/importing and prevent duplicate code and checks.
    Cipher::validate_notes(&data.ciphers)?;

    // Read and create the folders
    let mut folders: Vec<_> = Vec::new();
    for folder in data.folders.into_iter() {
        let mut new_folder = Folder::new(headers.user.uuid, folder.name);
        new_folder.save(&conn).await?;

        folders.push(new_folder);
    }

    // Read the relations between folders and ciphers
    let relations_map: HashMap<usize, usize> = data.folder_relationships.into_iter().map(|x| (x.key, x.value)).collect();

    // Read and create the ciphers
    for (index, mut cipher_data) in data.ciphers.into_iter().enumerate() {
        let folder_uuid = relations_map.get(&index).and_then(|i| Some(folders.get(*i)?.uuid));
        cipher_data.folder_id = folder_uuid;

        let mut cipher = Cipher::new(cipher_data.r#type, cipher_data.name.clone());
        update_cipher_from_data(&mut cipher, cipher_data, &headers, false, &mut conn, UpdateType::None).await?;
    }

    let user = headers.user;

    let conn = conn.commit().await?;

    //TODO: can user_update be affected by active txn?
    ws_users().send_user_update(UpdateType::SyncVault, &conn, &user).await?;

    Ok(())
}

pub async fn put_cipher(mut conn: AutoTxn, Path(uuid): Path<Uuid>, headers: Headers, data: Json<CipherData>) -> Result<Json<Value>> {
    let data: CipherData = data.0;

    let mut cipher = match Cipher::get_for_user_writable(&conn, headers.user.uuid, uuid).await? {
        Some(cipher) => cipher,
        None => err!("Cipher doesn't exist"),
    };

    // TODO: Check if only the folder ID or favorite status is being changed.
    // These are per-user properties that technically aren't part of the
    // cipher itself, so the user shouldn't need write access to change these.
    // Interestingly, upstream Bitwarden doesn't properly handle this either.

    update_cipher_from_data(&mut cipher, data, &headers, false, &mut conn, UpdateType::SyncCipherUpdate).await?;

    let conn = conn.commit().await?;

    Ok(Json(cipher.to_json(&conn, headers.user.uuid, true).await?))
}

// Only update the folder and favorite for the user, since this cipher is read-only
pub async fn put_cipher_partial(conn: AutoTxn, Path(uuid): Path<Uuid>, headers: Headers, data: Json<PartialCipherData>) -> Result<Json<Value>> {
    let data: PartialCipherData = data.0;

    let cipher = match Cipher::get_for_user(&conn, headers.user.uuid, uuid).await? {
        Some(cipher) => cipher,
        None => err!("Cipher doesn't exist"),
    };

    if let Some(folder_id) = data.folder_id {
        match Folder::get_with_user(&conn, folder_id, headers.user.uuid).await? {
            Some(_) => (),
            None => err!("Folder doesn't exist"),
        }
    }

    // Move cipher
    cipher.move_to_folder(&conn, data.folder_id, headers.user.uuid).await?;
    // Update favorite
    cipher.set_favorite(&conn, data.favorite, headers.user.uuid).await?;

    let conn = conn.commit().await?;

    Ok(Json(cipher.to_json(&conn, headers.user.uuid, true).await?))
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct CollectionsAdminData {
    collection_ids: Vec<Uuid>,
}

pub async fn post_collections(conn: AutoTxn, Path(uuid): Path<Uuid>, headers: Headers, data: Json<CollectionsAdminData>) -> Result<()> {
    let data: CollectionsAdminData = data.0;

    let cipher = match Cipher::get_for_user_writable(&conn, headers.user.uuid, uuid).await? {
        Some(cipher) => cipher,
        None => err!("Cipher doesn't exist"),
    };

    if cipher.organization_uuid.is_none() {
        err!("Not org cipher");
    }

    let posted_collections: HashSet<Uuid> = data.collection_ids.iter().cloned().collect();
    let current_collections: HashSet<Uuid> = cipher.get_collections(&conn, headers.user.uuid).await?.iter().cloned().collect();

    for collection in posted_collections.symmetric_difference(&current_collections) {
        //TODO: N+1 query
        match Collection::get_for_user_writable(&conn, headers.user.uuid, *collection).await? {
            None => err!("Invalid collection ID provided"),
            Some(collection) => {
                if posted_collections.contains(&collection.uuid) {
                    // Add to collection
                    CollectionCipher::save(&conn, cipher.uuid, collection.uuid).await?;
                } else {
                    // Remove from collection
                    CollectionCipher::delete(&conn, cipher.uuid, collection.uuid).await?;
                }
            }
        }
    }

    log_event(
        EventType::CipherUpdatedCollections,
        cipher.uuid,
        cipher.organization_uuid.unwrap(),
        headers.user.uuid.clone(),
        headers.device.atype,
        Utc::now(),
        headers.ip,
        &conn,
    )
    .await?;

    let conn = conn.commit().await?;

    let users = cipher.get_auth_users(&conn).await?;

    ws_users().send_cipher_update(UpdateType::SyncCipherUpdate, &cipher, &users, headers.device.uuid, Some(Vec::from_iter(posted_collections)), &conn).await?;

    Ok(())
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ShareCipherData {
    #[serde(alias = "Cipher")]
    cipher: CipherData,
    #[serde(alias = "CollectionIds")]
    collection_ids: Vec<Uuid>,
}

pub async fn put_cipher_share(mut conn: AutoTxn, Path(uuid): Path<Uuid>, headers: Headers, data: Json<ShareCipherData>) -> Result<Json<Value>> {
    let data: ShareCipherData = data.0;

    let out = share_cipher_by_uuid(uuid, data, &headers, &mut conn).await?;
    conn.commit().await?;
    Ok(out)
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ShareSelectedCipherData {
    ciphers: Vec<CipherData>,
    collection_ids: Vec<Uuid>,
}

pub async fn put_cipher_share_selected(mut conn: AutoTxn, headers: Headers, data: Json<ShareSelectedCipherData>) -> Result<()> {
    let mut data: ShareSelectedCipherData = data.0;
    let mut cipher_ids: Vec<Uuid> = Vec::new();

    if data.ciphers.is_empty() {
        err!("You must select at least one cipher.")
    }

    if data.collection_ids.is_empty() {
        err!("You must select at least one collection.")
    }

    for cipher in data.ciphers.iter() {
        match cipher.id {
            Some(ref id) => cipher_ids.push(*id),
            None => err!("Request missing ids field"),
        };
    }

    while let Some(cipher) = data.ciphers.pop() {
        let mut shared_cipher_data = ShareCipherData {
            cipher,
            collection_ids: data.collection_ids.clone(),
        };

        match shared_cipher_data.cipher.id.take() {
            Some(id) => share_cipher_by_uuid(id, shared_cipher_data, &headers, &mut conn).await?.0,
            None => err!("Request missing ids field"),
        };
    }
    conn.commit().await?;

    Ok(())
}

async fn share_cipher_by_uuid(uuid: Uuid, data: ShareCipherData, headers: &Headers, conn: &mut AutoTxn) -> Result<Json<Value>> {
    let mut cipher = match Cipher::get_for_user_writable(conn, headers.user.uuid, uuid).await? {
        Some(cipher) => cipher,
        None => err!("Cipher doesn't exist"),
    };

    let mut shared_to_collection = false;

    //TODO: N+1 query
    for uuid in &data.collection_ids {
        match Collection::find_by_uuid_and_user_writable(conn, *uuid, headers.user.uuid).await? {
            None => err!("Invalid collection ID provided"),
            Some(collection) => {
                CollectionCipher::save(conn, cipher.uuid, collection.uuid).await?;
                shared_to_collection = true;
            }
        }
    }

    // When LastKnownRevisionDate is None, it is a new cipher, so send CipherCreate.
    let ut = if data.cipher.last_known_revision_date.is_some() {
        UpdateType::SyncCipherUpdate
    } else {
        UpdateType::SyncCipherCreate
    };

    update_cipher_from_data(&mut cipher, data.cipher, headers, shared_to_collection, conn, ut).await?;
    let out = cipher.to_json(conn, headers.user.uuid, true).await?;

    Ok(Json(out))
}

#[derive(Deserialize)]
pub struct AttachmentPath {
    uuid: Uuid,
    attachment_id: Uuid,
}

/// v2 API for downloading an attachment. This just redirects the client to
/// the actual location of an attachment.
///
/// Upstream added this v2 API to support direct download of attachments from
/// their object storage service. For self-hosted instances, it basically just
/// redirects to the same location as before the v2 API.
pub async fn get_attachment(Path(path): Path<AttachmentPath>, headers: Headers) -> Result<Json<Value>> {
    let conn = DB.get().await.ise()?;
    match Attachment::get_with_cipher_and_user(&conn, path.attachment_id, path.uuid, headers.user.uuid).await? {
        Some(attachment) => Ok(Json(attachment.to_json())),
        None => err!("Attachment doesn't exist"),
    }
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct AttachmentRequestData {
    key: String,
    file_name: String,
    file_size: i32,
    admin_request: Option<bool>, // true when attaching from an org vault view
}

pub enum FileUploadType {
    Direct = 0,
    // Azure = 1, // only used upstream
}

/// v2 API for creating an attachment associated with a cipher.
/// This redirects the client to the API it should use to upload the attachment.
/// For upstream's cloud-hosted service, it's an Azure object storage API.
/// For self-hosted instances, it's another API on the local instance.
pub async fn post_attachment_v2(Path(uuid): Path<Uuid>, headers: Headers, data: Json<AttachmentRequestData>) -> Result<Json<Value>> {
    let conn = DB.get().await.ise()?;
    let cipher = match Cipher::get_for_user_writable(&conn, headers.user.uuid, uuid).await? {
        Some(cipher) => cipher,
        None => err!("Cipher doesn't exist"),
    };

    let attachment_id = Uuid::new_v4();
    let data: AttachmentRequestData = data.0;
    let attachment = Attachment::new(attachment_id, cipher.uuid, data.file_name, data.file_size, Some(data.key));
    attachment.save(&conn).await?;

    let url = format!("/ciphers/{}/attachment/{}", cipher.uuid, attachment_id);
    let response_key = match data.admin_request {
        Some(b) if b => "CipherMiniResponse",
        _ => "CipherResponse",
    };

    Ok(Json(json!({ // AttachmentUploadDataResponseModel
        "object": "attachment-fileUpload",
        "attachmentId": attachment_id,
        "url": url,
        "fileUploadType": FileUploadType::Direct as i32,
        response_key: cipher.to_json(&conn, headers.user.uuid, true).await?,
    })))
}

pub struct UploadData {
    key: Option<String>,
    filename: Option<String>,
    data: Bytes,
}

impl UploadData {
    pub async fn read(mut multipart: Multipart) -> Result<Self> {
        let mut key = None::<String>;
        let mut filename = None::<String>;
        let mut data = None::<Bytes>;
        while let Some(field) = multipart.next_field().await? {
            match field.name() {
                Some("key") => {
                    if key.is_some() {
                        return Err(Error::bad_request("duplicated multipart field"));
                    }
                    key = Some(String::from_utf8(field.bytes().await.ise()?.to_vec()).ok().ok_or_else(|| Error::bad_request("invalid utf-8 in key"))?);
                }
                Some("data") => {
                    if data.is_some() {
                        return Err(Error::bad_request("duplicated multipart field"));
                    }
                    filename = field.file_name().map(|x| x.to_string());
                    data = Some(field.bytes().await?);
                }
                _ => return Err(Error::bad_request("unknown multipart field")),
            }
        }
        if let Some(data) = data {
            Ok(Self {
                key,
                filename,
                data,
            })
        } else {
            Err(Error::bad_request("missing fields"))
        }
    }
}

/// Saves the data content of an attachment to a file. This is common code
/// shared between the v2 and legacy attachment APIs.
///
/// When used with the legacy API, this function is responsible for creating
/// the attachment database record, so `attachment` is None.
///
/// When used with the v2 API, post_attachment_v2() has already created the
/// database record, which is passed in as `attachment`.
async fn save_attachment(mut attachment: Option<Attachment>, cipher_uuid: Uuid, data: UploadData, headers: &Headers, conn: &mut AutoTxn) -> Result<Cipher> {
    let cipher = match Cipher::get_for_user_writable(conn, headers.user.uuid, cipher_uuid).await? {
        Some(cipher) => cipher,
        None => err!("Cipher doesn't exist"),
    };

    // In the v2 API, the attachment record has already been created,
    // so the size limit needs to be adjusted to account for that.
    let size_adjust = match &attachment {
        None => 0,                         // Legacy API
        Some(a) => i64::from(a.file_size), // v2 API
    };

    let size_limit = if let Some(user_uuid) = cipher.user_uuid {
        match CONFIG.settings.user_attachment_limit {
            Some(0) => err!("Attachments are disabled"),
            Some(limit_kb) => {
                let left = (limit_kb * 1024) - Attachment::size_count_by_user(conn, user_uuid).await?.0 + size_adjust;
                if left <= 0 {
                    err!("Attachment storage limit reached! Delete some attachments to free up space")
                }
                Some(left as u64)
            }
            None => None,
        }
    } else if let Some(org_uuid) = cipher.organization_uuid {
        match CONFIG.settings.org_attachment_limit {
            Some(0) => err!("Attachments are disabled"),
            Some(limit_kb) => {
                let left = (limit_kb * 1024) - Attachment::size_count_by_organization(conn, org_uuid).await?.0 + size_adjust;
                if left <= 0 {
                    err!("Attachment storage limit reached! Delete some attachments to free up space")
                }
                Some(left as u64)
            }
            None => None,
        }
    } else {
        err!("Cipher is neither owned by a user nor an organization");
    };

    if let Some(size_limit) = size_limit {
        if data.data.len() as u64 > size_limit {
            err!("Attachment storage limit exceeded with this file");
        }
    }

    let file_id = match &attachment {
        Some(attachment) => attachment.uuid, // v2 API
        None => Uuid::new_v4(),              // Legacy API
    };

    let folder_path = tokio::fs::canonicalize(CONFIG.folders.attachments()).await?.join(cipher_uuid.to_string());
    let file_path = folder_path.join(file_id.to_string());
    tokio::fs::create_dir_all(&folder_path).await?;

    let size = data.data.len() as i32;
    if let Some(attachment) = &mut attachment {
        // v2 API

        // Check the actual size against the size initially provided by
        // the client. Upstream allows +/- 1 MiB deviation from this
        // size, but it's not clear when or why this is needed.
        const LEEWAY: i32 = 1024 * 1024; // 1 MiB
        let min_size = attachment.file_size - LEEWAY;
        let max_size = attachment.file_size + LEEWAY;

        if min_size <= size && size <= max_size {
            if size != attachment.file_size {
                // Update the attachment with the actual file size.
                attachment.file_size = size;
                attachment.save(&conn).await?;
            }
        } else {
            attachment.delete(&conn).await?;

            err!(format!("Attachment size mismatch (expected within [{min_size}, {max_size}], got {size})"));
        }
    } else {
        // Legacy API
        let encrypted_filename = data.filename;

        if encrypted_filename.is_none() {
            err!("No filename provided")
        }
        if data.key.is_none() {
            err!("No attachment key provided")
        }
        let attachment = Attachment::new(file_id, cipher_uuid, encrypted_filename.unwrap(), size, data.key);
        attachment.save(conn).await?;
    }

    tokio::fs::write(&file_path, &data.data).await?;

    let cipher2 = cipher.clone();
    let acting_device_uuid = headers.device.uuid;
    conn.defer(move || {
        tokio::spawn(async move {
            let Ok(conn) = DB.get().await else {
                return;
            };
            ws_users().send_cipher_update_all(UpdateType::SyncCipherUpdate, &cipher2, acting_device_uuid, None, &conn).await;
        });
    });

    if let Some(org_uuid) = cipher.organization_uuid {
        log_event(EventType::CipherAttachmentCreated, cipher.uuid, org_uuid, headers.user.uuid, headers.device.atype, Utc::now(), headers.ip, &conn).await?;
    }

    Ok(cipher)
}

/// v2 API for uploading the actual data content of an attachment.
/// This route needs a rank specified so that Rocket prioritizes the
/// /ciphers/<uuid>/attachment/v2 route, which would otherwise conflict
/// with this one.
pub async fn post_attachment_v2_data(mut conn: AutoTxn, Path(path): Path<AttachmentPath>, headers: Headers, data: Multipart) -> Result<()> {
    let data = UploadData::read(data).await?;
    let attachment = match Attachment::get_with_cipher_and_user(&conn, path.attachment_id, path.uuid, headers.user.uuid).await? {
        Some(attachment) => Some(attachment),
        None => err!("Attachment doesn't exist"),
    };

    save_attachment(attachment, path.uuid, data, &headers, &mut conn).await?;
    conn.commit().await?;

    Ok(())
}

async fn do_attachment_post(conn: &mut AutoTxn, uuid: Uuid, headers: Headers, data: Multipart) -> Result<Json<Value>> {
    let data = UploadData::read(data).await?;
    // Setting this as None signifies to save_attachment() that it should create
    // the attachment database record as well as saving the data to disk.
    let attachment = None;

    let cipher = save_attachment(attachment, uuid, data, &headers, conn).await?;

    Ok(Json(cipher.to_json(conn, headers.user.uuid, true).await?))
}

/// Legacy API for creating an attachment associated with a cipher.
pub async fn post_attachment(mut conn: AutoTxn, Path(uuid): Path<Uuid>, headers: Headers, data: Multipart) -> Result<Json<Value>> {
    let out = do_attachment_post(&mut conn, uuid, headers, data).await?;
    conn.commit().await?;
    Ok(out)
}

pub async fn post_attachment_share(mut conn: AutoTxn, Path(path): Path<AttachmentPath>, headers: Headers, data: Multipart) -> Result<Json<Value>> {
    _delete_cipher_attachment_by_id(path.uuid, path.attachment_id, &headers, &mut conn).await?;
    let out = do_attachment_post(&mut conn, path.uuid, headers, data).await?;
    conn.commit().await?;
    Ok(out)
}

pub async fn delete_attachment(mut conn: AutoTxn, Path(path): Path<AttachmentPath>, headers: Headers) -> Result<()> {
    _delete_cipher_attachment_by_id(path.uuid, path.attachment_id, &headers, &mut conn).await?;
    conn.commit().await?;
    Ok(())
}

pub async fn delete_cipher_soft(mut conn: AutoTxn, Path(uuid): Path<Uuid>, headers: Headers) -> Result<()> {
    _delete_cipher_by_uuid(uuid, &headers, &mut conn, true).await?;
    conn.commit().await?;
    Ok(())
}

pub async fn delete_cipher_hard(mut conn: AutoTxn, Path(uuid): Path<Uuid>, headers: Headers) -> Result<()> {
    _delete_cipher_by_uuid(uuid, &headers, &mut conn, false).await?;
    conn.commit().await?;
    Ok(())
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct IdData {
    ids: Vec<Uuid>,
}

pub async fn delete_cipher_selected_hard(conn: AutoTxn, headers: Headers, data: Json<IdData>) -> Result<()> {
    _delete_multiple_ciphers(conn, headers, false, data).await
}

pub async fn delete_cipher_selected_soft(conn: AutoTxn, headers: Headers, data: Json<IdData>) -> Result<()> {
    _delete_multiple_ciphers(conn, headers, true, data).await
}

pub async fn restore_cipher_put(mut conn: AutoTxn, Path(uuid): Path<Uuid>, headers: Headers) -> Result<Json<Value>> {
    let out = _restore_cipher_by_uuid(uuid, &headers, &mut conn).await?;
    conn.commit().await?;
    Ok(out)
}

pub async fn restore_cipher_selected(mut conn: AutoTxn, headers: Headers, data: Json<IdData>) -> Result<Json<Value>> {
    let uuids = data.0.ids;

    let mut ciphers: Vec<Value> = Vec::new();
    for uuid in uuids {
        ciphers.push(_restore_cipher_by_uuid(uuid, &headers, &mut conn).await?.0);
    }

    conn.commit().await?;

    Ok(Json(json!({
      "data": ciphers,
      "object": "list",
      "continuationToken": null
    })))
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct MoveCipherData {
    folder_id: Option<Uuid>,
    ids: Vec<Uuid>,
}

pub async fn move_cipher_selected(conn: AutoTxn, headers: Headers, data: Json<MoveCipherData>) -> Result<()> {
    let data = data.0;
    let user_uuid = headers.user.uuid;

    if let Some(folder_id) = data.folder_id {
        match Folder::get_with_user(&conn, folder_id, user_uuid).await? {
            Some(_) => (),
            None => err!("Folder doesn't exist"),
        }
    }

    let mut to_update = vec![];
    for uuid in data.ids {
        let cipher = match Cipher::get_for_user_writable(&conn, headers.user.uuid, uuid).await? {
            Some(cipher) => cipher,
            None => err!("Cipher doesn't exist"),
        };

        cipher.move_to_folder(&conn, data.folder_id, user_uuid).await?;

        to_update.push(cipher);
    }
    let conn = conn.commit().await?;
    for cipher in to_update {
        ws_users().send_cipher_update(UpdateType::SyncCipherUpdate, &cipher, &[user_uuid], headers.device.uuid, None, &conn).await?;
    }

    Ok(())
}

#[derive(Deserialize)]
pub struct OrganizationId {
    #[serde(rename = "organizationId")]
    organization_id: Uuid,
}

pub async fn delete_all(conn: AutoTxn, Query(organization): Query<Option<OrganizationId>>, headers: Headers, data: Json<PasswordData>) -> Result<()> {
    let data: PasswordData = data.0;
    let password_hash = data.master_password_hash;

    let user = headers.user;

    if !user.check_valid_password(&password_hash) {
        err!("Invalid password")
    }

    match organization {
        Some(org_data) => {
            // Organization ID in query params, purging organization vault
            match UserOrganization::get(&conn, user.uuid, org_data.organization_id).await? {
                None => err!("You don't have permission to purge the organization vault"),
                Some(user_org) => {
                    if user_org.atype == UserOrgType::Owner {
                        Cipher::delete_all_by_organization(&conn, org_data.organization_id).await?;
                        ws_users().send_user_update(UpdateType::SyncVault, &conn, &user).await?;

                        log_event(
                            EventType::OrganizationPurgedVault,
                            org_data.organization_id,
                            org_data.organization_id,
                            user.uuid,
                            headers.device.atype,
                            Utc::now(),
                            headers.ip,
                            &conn,
                        )
                        .await?;
                    } else {
                        err!("You don't have permission to purge the organization vault");
                    }
                }
            }
        }
        None => {
            // No organization ID in query params, purging user vault
            // Delete ciphers and their attachments

            Cipher::delete_owned_by_user(&conn, user.uuid).await?;

            Folder::delete_by_user(&conn, user.uuid).await?;

            ws_users().send_user_update(UpdateType::SyncVault, &conn, &user).await?;
        }
    }
    conn.commit().await?;
    Ok(())
}

async fn _delete_cipher_by_uuid(uuid: Uuid, headers: &Headers, conn: &mut AutoTxn, soft_delete: bool) -> Result<()> {
    let mut cipher = match Cipher::get_for_user_writable(conn, headers.user.uuid, uuid).await? {
        Some(cipher) => cipher,
        None => err!("Cipher doesn't exist"),
    };

    let update_type = if soft_delete {
        cipher.deleted_at = Some(Utc::now());
        cipher.save(conn).await?;
        UpdateType::SyncCipherUpdate
    } else {
        cipher.delete(conn).await?;
        UpdateType::SyncCipherDelete
    };

    let cipher2 = cipher.clone();
    let acting_device_uuid = headers.device.uuid;
    conn.defer(move || {
        tokio::spawn(async move {
            let Ok(conn) = DB.get().await else {
                return;
            };
            ws_users().send_cipher_update_all(update_type, &cipher2, acting_device_uuid, None, &conn).await;
        });
    });

    if let Some(org_uuid) = cipher.organization_uuid {
        let event_type = match soft_delete {
            true => EventType::CipherSoftDeleted,
            false => EventType::CipherDeleted,
        };

        log_event(event_type, cipher.uuid, org_uuid, headers.user.uuid, headers.device.atype, Utc::now(), headers.ip, conn).await?;
    }

    Ok(())
}

async fn _delete_multiple_ciphers(mut conn: AutoTxn, headers: Headers, soft_delete: bool, data: Json<IdData>) -> Result<()> {
    let uuids = data.0.ids;

    for uuid in uuids {
        _delete_cipher_by_uuid(uuid, &headers, &mut conn, soft_delete).await?;
    }
    conn.commit().await?;

    Ok(())
}

async fn _restore_cipher_by_uuid(uuid: Uuid, headers: &Headers, conn: &mut AutoTxn) -> Result<Json<Value>> {
    let mut cipher = match Cipher::get_for_user_writable(conn, headers.user.uuid, uuid).await? {
        Some(cipher) => cipher,
        None => err!("Cipher doesn't exist"),
    };

    cipher.deleted_at = None;
    cipher.save(conn).await?;

    let cipher2 = cipher.clone();
    let acting_device_uuid = headers.device.uuid;
    conn.defer(move || {
        tokio::spawn(async move {
            let Ok(conn) = DB.get().await else {
                return;
            };
            ws_users().send_cipher_update_all(UpdateType::SyncCipherUpdate, &cipher2, acting_device_uuid, None, &conn).await;
        });
    });

    if let Some(org_uuid) = cipher.organization_uuid {
        log_event(EventType::CipherRestored, cipher.uuid, org_uuid, headers.user.uuid, headers.device.atype, Utc::now(), headers.ip, conn).await?;
    }

    Ok(Json(cipher.to_json(conn, headers.user.uuid, true).await?))
}

async fn _delete_cipher_attachment_by_id(uuid: Uuid, attachment_id: Uuid, headers: &Headers, conn: &mut AutoTxn) -> Result<()> {
    let attachment = match Attachment::get_with_cipher_and_user_writable(conn, attachment_id, uuid, headers.user.uuid).await? {
        Some(attachment) => attachment,
        None => err!("Attachment doesn't exist"),
    };

    let cipher = match Cipher::get_for_user_writable(conn, headers.user.uuid, uuid).await? {
        Some(cipher) => cipher,
        None => err!("Cipher doesn't exist"),
    };

    // Delete attachment
    attachment.delete(conn).await?;
    if let Some(org_uuid) = cipher.organization_uuid {
        log_event(EventType::CipherAttachmentDeleted, cipher.uuid, org_uuid, headers.user.uuid, headers.device.atype, Utc::now(), headers.ip, conn).await?;
    }

    let acting_device_uuid = headers.device.uuid;
    conn.defer(move || {
        tokio::spawn(async move {
            let Ok(conn) = DB.get().await else {
                return;
            };
            ws_users().send_cipher_update_all(UpdateType::SyncCipherUpdate, &cipher, acting_device_uuid, None, &conn).await;
        });
    });
    Ok(())
}
