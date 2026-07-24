use std::collections::{HashMap, HashSet};

use axol::Multipart;
use axol::prelude::*;
use bytes::Bytes;
use chrono::{DateTime, Utc};
use log::warn;
use serde::Deserialize;
use serde::{Deserializer, de::Error as _E};
use serde_json::{Value, json};
use uuid::Uuid;

use crate::{
    CONFIG,
    api::{self, PasswordData, UpdateType, ws_users},
    auth::Headers,
    db::{
        Archive, Attachment, Cipher, CipherType, Collection, CollectionCipher, CollectionWithAccess, Conn, DB, EventType, Folder, FullCipher, OrgPolicyType,
        OrganizationPolicy, RepromptType, UserOrgType, UserOrganization,
    },
    events::log_event,
    util::AutoTxn,
};

use super::{GlobalDomainQuery, folders::FolderData};

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
        .put("/ciphers/:uuid/collections_v2", post_collections_v2)
        .post("/ciphers/:uuid/collections_v2", post_collections_v2)
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
        .put("/ciphers/:uuid/archive", archive_cipher_put)
        .put("/ciphers/archive", archive_cipher_selected)
        .put("/ciphers/:uuid/unarchive", unarchive_cipher_put)
        .put("/ciphers/unarchive", unarchive_cipher_selected)
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

    // This is very similar to the userDecryptionOptions sent in connect/token,
    // but as of 2025-12-19 they're both using different casing conventions.
    // Computed before `domains_json` since `get_eq_domains` consumes `headers`.
    let has_master_password = !headers.user.password_hash.is_empty();
    let master_password_unlock = if has_master_password {
        json!({
            "kdf": {
                "kdfType": headers.user.client_kdf_type,
                "iterations": headers.user.client_kdf_iter,
                "memory": headers.user.client_kdf_memory,
                "parallelism": headers.user.client_kdf_parallelism
            },
            // This field is named inconsistently and will be removed and replaced by the "wrapped" variant in the apps.
            // https://github.com/bitwarden/android/blob/release/2025.12-rc41/network/src/main/kotlin/com/bitwarden/network/model/MasterPasswordUnlockDataJson.kt#L22-L26
            "masterKeyEncryptedUserKey": headers.user.akey,
            "masterKeyWrappedUserKey": headers.user.akey,
            "salt": headers.user.email
        })
    } else {
        Value::Null
    };

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
        "userDecryption": {
            "masterPasswordUnlock": master_password_unlock,
        },
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
    pub organization_id: Option<Uuid>,

    /*
    Login = 1,
    SecureNote = 2,
    Card = 3,
    Identity = 4
    SshKey = 5
    */
    pub r#type: CipherType,
    pub name: String,
    pub notes: Option<String>,
    fields: Option<Vec<Value>>,

    // Per-cipher encryption key ("cipher key encryption"), wrapped under the
    // user/org key. Must be persisted and echoed back or clients (notably the
    // native mobile apps) cannot decrypt the item and will crash.
    key: Option<String>,

    // Only one of these should exist, depending on type
    login: Option<Value>,
    secure_note: Option<Value>,
    card: Option<Value>,
    identity: Option<Value>,
    ssh_key: Option<Value>,

    // Newer Bitwarden clients may send the whole cipher body as a single
    // serialized-JSON string here instead of the per-type structured objects
    // above. Consulted only as a fallback when the structured field is absent.
    data: Option<Value>,

    favorite: Option<bool>,
    reprompt: Option<RepromptType>,

    // Per-user archive timestamp. Sent by clients to preserve archive state on edit
    // and during key rotation. Clearing archive state is done via the unarchive endpoint.
    #[serde(default, deserialize_with = "deserialize_last_known_revision_date")]
    archived_date: Option<DateTime<Utc>>,

    pub password_history: Option<Value>,

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
        CipherType::SshKey => data.ssh_key,
        // Bitwarden obsoleted the structured request field for these types in favor of
        // the serialized `data` string, so there is no per-type field to read here.
        CipherType::BankAccount | CipherType::DriversLicense | CipherType::Passport => None,
        CipherType::Unknown => err!("Invalid type"),
    };

    // The cipher body is normally sent as a structured per-type object, but
    // newer clients may instead send it as a serialized-JSON string in `data`.
    // Prefer the structured field (matching how existing clients behave) and
    // fall back to `data` only when the structured field is missing.
    let mut type_data = match type_data_opt {
        Some(type_data) => type_data,
        None => match data.data {
            Some(Value::String(raw)) => match serde_json::from_str(&raw) {
                Ok(parsed) => parsed,
                Err(_) => err!("Invalid cipher data"),
            },
            Some(raw @ Value::Object(_)) => raw,
            Some(_) => err!("Invalid cipher data"),
            None => err!("Data missing"),
        },
    };

    if !type_data.is_object() {
        err!("Invalid cipher data");
    }
    // Remove the 'Response' key from the base object.
    type_data.as_object_mut().unwrap().remove("response");
    // Remove the 'Response' key from every Uri.
    if type_data["uris"].is_array() {
        type_data["uris"] = Value::Array(_clean_cipher_data(type_data["uris"].as_array().unwrap().clone()));
    }

    cipher.key = data.key;
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
    if let Some(archived_at) = data.archived_date {
        Archive::save(conn, headers.user.uuid, cipher.uuid, archived_at).await?;
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
    Cipher::validate_cipher_data(&data.ciphers)?;

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

async fn post_collections_inner(conn: AutoTxn, uuid: Uuid, headers: Headers, data: CollectionsAdminData) -> Result<Value> {
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

    cipher.to_json(&conn, headers.user.uuid, true).await
}

pub async fn post_collections(conn: AutoTxn, Path(uuid): Path<Uuid>, headers: Headers, data: Json<CollectionsAdminData>) -> Result<Json<Value>> {
    Ok(Json(post_collections_inner(conn, uuid, headers, data.0).await?))
}

// The v2 variant wraps the updated cipher in an `optionalCipherDetails` envelope so
// newer clients can refresh their local cipher state after editing its collections.
pub async fn post_collections_v2(conn: AutoTxn, Path(uuid): Path<Uuid>, headers: Headers, data: Json<CollectionsAdminData>) -> Result<Json<Value>> {
    let cipher = post_collections_inner(conn, uuid, headers, data.0).await?;
    Ok(Json(json!({
        "object": "optionalCipherDetails",
        "unavailable": false,
        "cipher": cipher,
    })))
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
        Some(b) if b => "cipherMiniResponse",
        _ => "cipherResponse",
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

pub async fn archive_cipher_put(mut conn: AutoTxn, Path(uuid): Path<Uuid>, headers: Headers) -> Result<Json<Value>> {
    let out = _set_cipher_archived_by_uuid(uuid, &headers, &mut conn, true).await?;
    conn.commit().await?;
    Ok(out)
}

pub async fn unarchive_cipher_put(mut conn: AutoTxn, Path(uuid): Path<Uuid>, headers: Headers) -> Result<Json<Value>> {
    let out = _set_cipher_archived_by_uuid(uuid, &headers, &mut conn, false).await?;
    conn.commit().await?;
    Ok(out)
}

pub async fn archive_cipher_selected(conn: AutoTxn, headers: Headers, data: Json<IdData>) -> Result<Json<Value>> {
    _set_multiple_ciphers_archived(conn, headers, data, true).await
}

pub async fn unarchive_cipher_selected(conn: AutoTxn, headers: Headers, data: Json<IdData>) -> Result<Json<Value>> {
    _set_multiple_ciphers_archived(conn, headers, data, false).await
}

async fn _set_multiple_ciphers_archived(mut conn: AutoTxn, headers: Headers, data: Json<IdData>, archive: bool) -> Result<Json<Value>> {
    let mut ciphers: Vec<Value> = Vec::new();
    for uuid in data.0.ids {
        ciphers.push(_set_cipher_archived_by_uuid(uuid, &headers, &mut conn, archive).await?.0);
    }

    conn.commit().await?;

    Ok(Json(json!({
      "data": ciphers,
      "object": "list",
      "continuationToken": null
    })))
}

/// Archives (or unarchives) a cipher for the requesting user. Archive state is per-user, so
/// a user may archive even a read-only org cipher — it only affects their own view.
async fn _set_cipher_archived_by_uuid(uuid: Uuid, headers: &Headers, conn: &mut AutoTxn, archive: bool) -> Result<Json<Value>> {
    let cipher = match Cipher::get_for_user(conn, headers.user.uuid, uuid).await? {
        Some(cipher) => cipher,
        None => err!("Cipher doesn't exist"),
    };

    if archive {
        Archive::save(conn, headers.user.uuid, cipher.uuid, Utc::now()).await?;
    } else {
        Archive::delete_by_cipher(conn, headers.user.uuid, cipher.uuid).await?;
    }

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

    Ok(Json(cipher.to_json(conn, headers.user.uuid, true).await?))
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
    // Optional: absent when purging the personal vault. Note this must be an
    // Option on the field rather than `Query<Option<OrganizationId>>`, since
    // serde_urlencoded can't deserialize an empty query string into an Option.
    #[serde(rename = "organizationId", default)]
    organization_id: Option<Uuid>,
}

pub async fn delete_all(conn: AutoTxn, Query(organization): Query<OrganizationId>, headers: Headers, data: Json<PasswordData>) -> Result<()> {
    let data: PasswordData = data.0;

    let user = headers.user;

    user.check_valid_password_data(&data)?;

    match organization.organization_id {
        Some(org_id) => {
            // Organization ID in query params, purging organization vault
            match UserOrganization::get(&conn, user.uuid, org_id).await? {
                None => err!("You don't have permission to purge the organization vault"),
                Some(user_org) => {
                    if user_org.atype == UserOrgType::Owner {
                        Cipher::delete_all_by_organization(&conn, org_id).await?;
                        ws_users().send_user_update(UpdateType::SyncVault, &conn, &user).await?;

                        log_event(EventType::OrganizationPurgedVault, org_id, org_id, user.uuid, headers.device.atype, Utc::now(), headers.ip, &conn).await?;
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

#[cfg(test)]
mod tests {
    use serde_json::json;

    use crate::test_harness::TestClient;

    #[tokio::test]
    async fn create_get_update_delete_cipher() {
        let client = TestClient::register_and_login().await;

        // Create.
        let created = client.create_login_cipher("2.name|mac").await;
        assert_eq!(created["object"], "cipherDetails");
        assert_eq!(created["type"], 1);
        assert_eq!(created["name"], "2.name|mac");
        let id = created["id"].as_str().expect("cipher id").to_string();

        // Get by id.
        let got = client.get(&format!("/api/ciphers/{id}")).await;
        got.assert_ok();
        assert_eq!(got.json()["id"], id);

        // Update (rename).
        let update = json!({
            "type": 1,
            "name": "2.renamed|mac",
            "login": { "username": "2.user|mac", "password": "2.pass|mac" },
            "lastKnownRevisionDate": null,
        });
        let updated = client.put(&format!("/api/ciphers/{id}"), update).await;
        updated.assert_ok();
        assert_eq!(updated.json()["name"], "2.renamed|mac");

        // Hard delete.
        client.delete(&format!("/api/ciphers/{id}")).await.assert_ok();
        let after = client.get(&format!("/api/ciphers/{id}")).await;
        assert!(after.status >= 400, "expected deleted cipher to be gone, got {}: {}", after.status, after.body);
    }

    #[tokio::test]
    async fn cipher_key_round_trips() {
        let client = TestClient::register_and_login().await;

        // Create with a per-cipher key ("cipher key encryption").
        let created = client
            .post(
                "/api/ciphers",
                json!({
                    "type": 1,
                    "name": "2.keyed|mac",
                    "key": "2.cipherkey|mac",
                    "login": { "username": "2.user|mac", "password": "2.pass|mac" },
                    "lastKnownRevisionDate": null,
                }),
            )
            .await;
        created.assert_ok();
        let created = created.json();
        assert_eq!(created["key"], "2.cipherkey|mac", "key must be echoed on create");
        let id = created["id"].as_str().expect("cipher id").to_string();

        // Get by id preserves the key.
        let got = client.get(&format!("/api/ciphers/{id}")).await;
        got.assert_ok();
        assert_eq!(got.json()["key"], "2.cipherkey|mac", "key must persist on get");

        // Update to a rotated key survives.
        let updated = client
            .put(
                &format!("/api/ciphers/{id}"),
                json!({
                    "type": 1,
                    "name": "2.keyed|mac",
                    "key": "2.rotatedkey|mac",
                    "login": { "username": "2.user|mac", "password": "2.pass|mac" },
                    "lastKnownRevisionDate": null,
                }),
            )
            .await;
        updated.assert_ok();
        assert_eq!(updated.json()["key"], "2.rotatedkey|mac", "key must update");

        // Sync surfaces the stored key too.
        let sync = client.get("/api/sync").await;
        sync.assert_ok();
        let sync = sync.json();
        let cipher = sync["ciphers"].as_array().unwrap().iter().find(|c| c["id"] == id).expect("cipher in sync");
        assert_eq!(cipher["key"], "2.rotatedkey|mac", "key must appear in sync");
    }

    // Bank account (6), driver's license (7) and passport (8) are newer Bitwarden cipher
    // types whose body is sent in the serialized `data` string rather than a typed
    // sub-object. They must be accepted (not 400'd) and round-trip through `data`.
    #[tokio::test]
    async fn newer_cipher_types_round_trip_via_data() {
        let client = TestClient::register_and_login().await;

        for (atype, key) in [(6, "bankAccount"), (7, "driversLicense"), (8, "passport")] {
            let data = json!({ "value": format!("2.secret-{atype}|mac") }).to_string();
            let created = client
                .post(
                    "/api/ciphers",
                    json!({
                        "type": atype,
                        "name": format!("2.item-{atype}|mac"),
                        "data": data,
                        "lastKnownRevisionDate": null,
                    }),
                )
                .await;
            created.assert_ok();
            let created = created.json();
            assert_eq!(created["type"], atype, "type must be preserved: {}", created);
            assert_eq!(created[key]["value"], format!("2.secret-{atype}|mac"), "typed sub-object must carry the data: {}", created);
            assert_eq!(created["data"]["value"], format!("2.secret-{atype}|mac"), "data must carry the body: {}", created);

            // And it survives a sync (exercises the response builder for a stored cipher).
            let id = created["id"].as_str().expect("cipher id").to_string();
            let sync = client.get("/api/sync").await;
            sync.assert_ok();
            let cipher = sync.json()["ciphers"].as_array().unwrap().iter().find(|c| c["id"] == id).cloned().expect("cipher in sync");
            assert_eq!(cipher["type"], atype);
            assert_eq!(cipher[key]["value"], format!("2.secret-{atype}|mac"));
        }
    }

    #[tokio::test]
    async fn create_cipher_with_raw_data_string() {
        let client = TestClient::register_and_login().await;

        // Newer-client shape: no structured `login`, body carried as a
        // serialized-JSON string in `data`.
        let raw = json!({ "username": "2.user|mac", "password": "2.pass|mac", "uris": [] }).to_string();
        let created = client
            .post(
                "/api/ciphers",
                json!({
                    "type": 1,
                    "name": "2.raw|mac",
                    "data": raw,
                    "lastKnownRevisionDate": null,
                }),
            )
            .await;
        created.assert_ok();
        let created = created.json();
        assert_eq!(created["name"], "2.raw|mac");
        // The body should be surfaced under the per-type `login` key.
        assert_eq!(created["login"]["username"], "2.user|mac");

        // Missing both structured and raw data is still an error.
        let bad = client.post("/api/ciphers", json!({ "type": 1, "name": "2.empty|mac", "lastKnownRevisionDate": null })).await;
        assert!(bad.status >= 400, "expected error when no cipher body provided, got {}", bad.status);
    }

    #[tokio::test]
    async fn sync_returns_profile_and_ciphers() {
        let client = TestClient::register_and_login().await;
        let created = client.create_login_cipher("2.synced|mac").await;
        let id = created["id"].as_str().unwrap().to_string();

        let resp = client.get("/api/sync").await;
        resp.assert_ok();
        let sync = resp.json();
        assert_eq!(sync["object"], "sync");
        assert_eq!(sync["profile"]["email"].as_str().unwrap().to_lowercase(), client.email.to_lowercase());
        let cipher_ids: Vec<&str> = sync["ciphers"].as_array().unwrap().iter().filter_map(|c| c["id"].as_str()).collect();
        assert!(cipher_ids.contains(&id.as_str()), "created cipher missing from sync: {}", resp.body);
    }

    #[tokio::test]
    async fn soft_delete_then_restore() {
        let client = TestClient::register_and_login().await;
        let id = client.create_login_cipher("2.trash|mac").await["id"].as_str().unwrap().to_string();

        // Soft delete → still present but with a deletedDate.
        client.put(&format!("/api/ciphers/{id}/delete"), json!({})).await.assert_ok();
        let trashed = client.get(&format!("/api/ciphers/{id}")).await;
        trashed.assert_ok();
        assert!(!trashed.json()["deletedDate"].is_null(), "soft-deleted cipher should have a deletedDate");

        // Restore → deletedDate cleared.
        let restored = client.put(&format!("/api/ciphers/{id}/restore"), json!({})).await;
        restored.assert_ok();
        assert!(restored.json()["deletedDate"].is_null(), "restored cipher should have no deletedDate");
    }

    #[tokio::test]
    async fn ciphers_are_isolated_per_user() {
        let alice = TestClient::register_and_login().await;
        let bob = TestClient::register_and_login().await;

        let id = alice.create_login_cipher("2.alice|mac").await["id"].as_str().unwrap().to_string();

        // Bob cannot read Alice's cipher.
        let cross = bob.get(&format!("/api/ciphers/{id}")).await;
        assert!(cross.status >= 400, "user should not see another user's cipher, got {}: {}", cross.status, cross.body);
    }

    #[tokio::test]
    async fn cipher_endpoints_require_auth() {
        let client = TestClient::new().await;
        client.get("/api/sync").await.assert_status(401);
        client.get("/api/ciphers").await.assert_status(401);
    }

    #[tokio::test]
    async fn archive_then_unarchive_cipher() {
        let client = TestClient::register_and_login().await;
        let id = client.create_login_cipher("2.arch|mac").await["id"].as_str().unwrap().to_string();

        let archived = client.put(&format!("/api/ciphers/{id}/archive"), json!({})).await;
        archived.assert_ok();
        assert!(!archived.json()["archivedDate"].is_null(), "archived cipher should have archivedDate: {}", archived.body);

        let unarchived = client.put(&format!("/api/ciphers/{id}/unarchive"), json!({})).await;
        unarchived.assert_ok();
        assert!(unarchived.json()["archivedDate"].is_null(), "unarchived cipher should have no archivedDate: {}", unarchived.body);
    }

    #[tokio::test]
    async fn move_cipher_to_folder() {
        let client = TestClient::register_and_login().await;
        let id = client.create_login_cipher("2.movable|mac").await["id"].as_str().unwrap().to_string();
        let folder_id = client.create_folder("2.dest|mac").await;

        client.post("/api/ciphers/move", json!({ "folderId": folder_id, "ids": [id] })).await.assert_ok();

        let got = client.get(&format!("/api/ciphers/{id}")).await;
        got.assert_ok();
        assert_eq!(got.json()["folderId"], folder_id, "cipher should be in the folder: {}", got.body);
    }

    #[tokio::test]
    async fn toggle_favorite_via_update() {
        let client = TestClient::register_and_login().await;
        let id = client.create_login_cipher("2.fav|mac").await["id"].as_str().unwrap().to_string();

        let make_body = |favorite: bool| {
            json!({
                "type": 1,
                "name": "2.fav|mac",
                "login": { "username": "2.u|mac", "password": "2.p|mac" },
                "favorite": favorite,
                "lastKnownRevisionDate": null,
            })
        };

        let faved = client.put(&format!("/api/ciphers/{id}"), make_body(true)).await;
        faved.assert_ok();
        assert_eq!(faved.json()["favorite"], true, "cipher should be favorited: {}", faved.body);

        let unfaved = client.put(&format!("/api/ciphers/{id}"), make_body(false)).await;
        unfaved.assert_ok();
        assert_eq!(unfaved.json()["favorite"], false, "cipher should be unfavorited: {}", unfaved.body);
    }

    #[tokio::test]
    async fn bulk_soft_delete_then_restore() {
        let client = TestClient::register_and_login().await;
        let a = client.create_login_cipher("2.a|mac").await["id"].as_str().unwrap().to_string();
        let b = client.create_login_cipher("2.b|mac").await["id"].as_str().unwrap().to_string();

        // Bulk soft delete.
        client.put("/api/ciphers/delete", json!({ "ids": [a, b] })).await.assert_ok();
        for id in [&a, &b] {
            let got = client.get(&format!("/api/ciphers/{id}")).await;
            got.assert_ok();
            assert!(!got.json()["deletedDate"].is_null(), "cipher {id} should be soft-deleted: {}", got.body);
        }

        // Bulk restore.
        client.put("/api/ciphers/restore", json!({ "ids": [a, b] })).await.assert_ok();
        for id in [&a, &b] {
            let got = client.get(&format!("/api/ciphers/{id}")).await;
            got.assert_ok();
            assert!(got.json()["deletedDate"].is_null(), "cipher {id} should be restored: {}", got.body);
        }
    }

    #[tokio::test]
    async fn bulk_hard_delete() {
        let client = TestClient::register_and_login().await;
        let a = client.create_login_cipher("2.x|mac").await["id"].as_str().unwrap().to_string();
        let b = client.create_login_cipher("2.y|mac").await["id"].as_str().unwrap().to_string();

        client.post("/api/ciphers/delete", json!({ "ids": [a, b] })).await.assert_ok();
        for id in [&a, &b] {
            let after = client.get(&format!("/api/ciphers/{id}")).await;
            assert!(after.status >= 400, "cipher {id} should be gone, got {}: {}", after.status, after.body);
        }
    }

    #[tokio::test]
    async fn list_ciphers_and_details() {
        let client = TestClient::register_and_login().await;
        let id = client.create_login_cipher("2.listed|mac").await["id"].as_str().unwrap().to_string();

        // List: GET /ciphers.
        let list = client.get("/api/ciphers").await;
        list.assert_ok();
        let listed = list.json();
        assert_eq!(listed["object"], "list");
        let ids: Vec<&str> = listed["data"].as_array().unwrap().iter().filter_map(|c| c["id"].as_str()).collect();
        assert!(ids.contains(&id.as_str()), "created cipher missing from list: {}", list.body);

        // Details variant of the single-cipher GET.
        let details = client.get(&format!("/api/ciphers/{id}/details")).await;
        details.assert_ok();
        assert_eq!(details.json()["id"], id);
    }

    #[tokio::test]
    async fn create_secure_note_cipher() {
        let client = TestClient::register_and_login().await;
        let body = json!({
            "type": 2, // SecureNote
            "name": "2.note|mac",
            "secureNote": { "type": 0 },
            "notes": "2.notebody|mac",
            "lastKnownRevisionDate": null,
        });
        let resp = client.post("/api/ciphers", body).await;
        resp.assert_ok();
        let created = resp.json();
        assert_eq!(created["type"], 2);
        assert_eq!(created["notes"], "2.notebody|mac");
    }

    #[tokio::test]
    async fn partial_update_sets_folder_and_favorite() {
        let client = TestClient::register_and_login().await;
        let id = client.create_login_cipher("2.partial|mac").await["id"].as_str().unwrap().to_string();
        let folder_id = client.create_folder("2.pfolder|mac").await;

        let resp = client.put(&format!("/api/ciphers/{id}/partial"), json!({ "folderId": folder_id, "favorite": true })).await;
        resp.assert_ok();
        let updated = resp.json();
        assert_eq!(updated["folderId"], folder_id, "partial update should move to folder: {}", resp.body);
        assert_eq!(updated["favorite"], true, "partial update should set favorite: {}", resp.body);
    }

    #[tokio::test]
    async fn stale_update_is_rejected() {
        let client = TestClient::register_and_login().await;
        let id = client.create_login_cipher("2.stale|mac").await["id"].as_str().unwrap().to_string();

        // A lastKnownRevisionDate well in the past means the client copy is out of
        // date; the server must refuse the update to avoid clobbering newer data.
        let body = json!({
            "type": 1,
            "name": "2.stale-renamed|mac",
            "login": { "username": "2.u|mac", "password": "2.p|mac" },
            "lastKnownRevisionDate": "2000-01-01T00:00:00Z",
        });
        let resp = client.put(&format!("/api/ciphers/{id}"), body).await;
        assert!(resp.status >= 400, "stale update should be rejected, got {}: {}", resp.status, resp.body);
    }

    #[tokio::test]
    async fn bulk_archive_then_unarchive() {
        let client = TestClient::register_and_login().await;
        let a = client.create_login_cipher("2.ba|mac").await["id"].as_str().unwrap().to_string();
        let b = client.create_login_cipher("2.bb|mac").await["id"].as_str().unwrap().to_string();

        let archived = client.put("/api/ciphers/archive", json!({ "ids": [a, b] })).await;
        archived.assert_ok();
        let arch = archived.json();
        for c in arch["data"].as_array().unwrap() {
            assert!(!c["archivedDate"].is_null(), "bulk-archived cipher should have archivedDate: {}", archived.body);
        }

        client.put("/api/ciphers/unarchive", json!({ "ids": [a, b] })).await.assert_ok();
        for id in [&a, &b] {
            let got = client.get(&format!("/api/ciphers/{id}")).await;
            got.assert_ok();
            assert!(got.json()["archivedDate"].is_null(), "cipher {id} should be unarchived: {}", got.body);
        }
    }

    #[tokio::test]
    async fn import_creates_ciphers_and_folders() {
        let client = TestClient::register_and_login().await;
        let body = json!({
            "ciphers": [
                { "type": 1, "name": "2.imp-a|mac", "login": { "username": "2.u|mac", "password": "2.p|mac" }, "lastKnownRevisionDate": null },
                { "type": 1, "name": "2.imp-b|mac", "login": { "username": "2.u|mac", "password": "2.p|mac" }, "lastKnownRevisionDate": null },
            ],
            "folders": [ { "name": "2.impfolder|mac" } ],
            "folderRelationships": [ { "key": 0, "value": 0 } ],
        });
        client.post("/api/ciphers/import", body).await.assert_ok();

        let resp = client.get("/api/sync").await;
        resp.assert_ok();
        let sync = resp.json();
        let names: Vec<&str> = sync["ciphers"].as_array().unwrap().iter().filter_map(|c| c["name"].as_str()).collect();
        assert!(names.contains(&"2.imp-a|mac") && names.contains(&"2.imp-b|mac"), "imported ciphers missing: {}", resp.body);
        let folders: Vec<&str> = sync["folders"].as_array().unwrap().iter().filter_map(|f| f["name"].as_str()).collect();
        assert!(folders.contains(&"2.impfolder|mac"), "imported folder missing: {}", resp.body);

        // The relationship put cipher 0 into folder 0.
        let a = sync["ciphers"].as_array().unwrap().iter().find(|c| c["name"] == "2.imp-a|mac").unwrap();
        assert!(!a["folderId"].is_null(), "imported cipher should be in a folder: {}", resp.body);
    }

    #[tokio::test]
    async fn purge_user_vault() {
        let client = TestClient::register_and_login().await;
        let id = client.create_login_cipher("2.purgeme|mac").await["id"].as_str().unwrap().to_string();

        // Wrong password is rejected.
        let bad = client.post("/api/ciphers/purge", json!({ "masterPasswordHash": "not-the-password" })).await;
        assert!(bad.status >= 400, "purge with wrong password should fail, got {}: {}", bad.status, bad.body);

        // Correct password purges the personal vault.
        client.post("/api/ciphers/purge", json!({ "masterPasswordHash": client.master_password_hash })).await.assert_ok();
        let after = client.get(&format!("/api/ciphers/{id}")).await;
        assert!(after.status >= 400, "purged cipher should be gone, got {}: {}", after.status, after.body);
    }

    #[tokio::test]
    async fn share_personal_cipher_to_org() {
        let client = TestClient::register_and_login().await;
        let org = client.create_org("2.shareorg|mac").await;
        let org_id = org["id"].as_str().unwrap().to_string();
        let col_id = client.create_org_collection(&org_id, "2.sharecol|mac").await;
        let id = client.create_login_cipher("2.tomove|mac").await["id"].as_str().unwrap().to_string();

        let body = json!({
            "cipher": {
                "type": 1,
                "name": "2.tomove|mac",
                "organizationId": org_id,
                "login": { "username": "2.u|mac", "password": "2.p|mac" },
                "lastKnownRevisionDate": null,
            },
            "collectionIds": [col_id],
        });
        let resp = client.put(&format!("/api/ciphers/{id}/share"), body).await;
        resp.assert_ok();
        let shared = resp.json();
        assert_eq!(shared["organizationId"], org_id, "shared cipher should belong to the org: {}", resp.body);
        let cids: Vec<&str> = shared["collectionIds"].as_array().unwrap().iter().filter_map(|c| c.as_str()).collect();
        assert!(cids.contains(&col_id.as_str()), "shared cipher should be in the collection: {}", resp.body);
    }

    #[tokio::test]
    async fn update_org_cipher_collections() {
        let client = TestClient::register_and_login().await;
        let org = client.create_org("2.colorg|mac").await;
        let org_id = org["id"].as_str().unwrap().to_string();
        let col1 = client.create_org_collection(&org_id, "2.c1|mac").await;
        let col2 = client.create_org_collection(&org_id, "2.c2|mac").await;
        let id = client.create_org_cipher(&org_id, &col1, "2.orgc|mac").await["id"].as_str().unwrap().to_string();

        // Put the cipher into both collections; the response now echoes the updated cipher.
        let put = client.put(&format!("/api/ciphers/{id}/collections"), json!({ "collectionIds": [col1, col2] })).await;
        put.assert_ok();
        assert_eq!(put.json()["object"], "cipherDetails", "non-v2 collections should return the cipher: {}", put.body);

        let got = client.get(&format!("/api/ciphers/{id}")).await;
        got.assert_ok();
        let j = got.json();
        let cids: Vec<&str> = j["collectionIds"].as_array().unwrap().iter().filter_map(|c| c.as_str()).collect();
        assert!(cids.contains(&col1.as_str()) && cids.contains(&col2.as_str()), "cipher should be in both collections: {}", got.body);

        // The v2 endpoint wraps the cipher in an optionalCipherDetails envelope.
        let v2 = client.put(&format!("/api/ciphers/{id}/collections_v2"), json!({ "collectionIds": [col1] })).await;
        v2.assert_ok();
        let vj = v2.json();
        assert_eq!(vj["object"], "optionalCipherDetails", "v2 should return an envelope: {}", v2.body);
        assert_eq!(vj["unavailable"], false);
        assert_eq!(vj["cipher"]["id"], id, "envelope should carry the cipher: {}", v2.body);
    }

    // Personal ciphers expose a permissions object clients use to gate delete/restore.
    #[tokio::test]
    async fn cipher_response_includes_permissions() {
        let client = TestClient::register_and_login().await;
        let created = client.create_login_cipher("2.perm|mac").await;
        assert_eq!(created["permissions"]["delete"], true, "owner can delete: {}", created);
        assert_eq!(created["permissions"]["restore"], true, "owner can restore: {}", created);

        // And it persists through sync.
        let id = created["id"].as_str().unwrap().to_string();
        let sync = client.get("/api/sync").await;
        let cipher = sync.json()["ciphers"].as_array().unwrap().iter().find(|c| c["id"] == id).cloned().expect("cipher in sync");
        assert_eq!(cipher["permissions"]["delete"], true, "permissions must appear in sync: {}", sync.body);
    }

    #[tokio::test]
    async fn attachment_v2_upload_get_delete() {
        let client = TestClient::register_and_login().await;
        let id = client.create_login_cipher("2.withatt|mac").await["id"].as_str().unwrap().to_string();

        let file = b"encrypted-attachment-bytes";

        // 1. Reserve the attachment record (v2 handshake).
        let reserve = client
            .post(&format!("/api/ciphers/{id}/attachment/v2"), json!({ "key": "2.attkey|mac", "fileName": "2.secret.txt|mac", "fileSize": file.len() }))
            .await;
        reserve.assert_ok();
        let attachment_id = reserve.json()["attachmentId"].as_str().expect("attachmentId").to_string();

        // 2. Upload the bytes to the returned URL.
        client.post_multipart(&format!("/api/ciphers/{id}/attachment/{attachment_id}"), &[("data", Some("2.secret.txt|mac"), file)]).await.assert_ok();

        // 3. The cipher now advertises the attachment.
        let got = client.get(&format!("/api/ciphers/{id}")).await;
        got.assert_ok();
        let atts = got.json()["attachments"].as_array().cloned().unwrap_or_default();
        assert_eq!(atts.len(), 1, "cipher should have exactly one attachment: {}", got.body);

        // 4. Metadata is fetchable directly.
        let meta = client.get(&format!("/api/ciphers/{id}/attachment/{attachment_id}")).await;
        meta.assert_ok();
        assert_eq!(meta.json()["id"], attachment_id);

        // 5. Delete it; it's then gone.
        client.delete(&format!("/api/ciphers/{id}/attachment/{attachment_id}")).await.assert_ok();
        let after = client.get(&format!("/api/ciphers/{id}/attachment/{attachment_id}")).await;
        assert!(after.status >= 400, "attachment should be gone, got {}: {}", after.status, after.body);
    }

    #[tokio::test]
    async fn legacy_attachment_upload() {
        let client = TestClient::register_and_login().await;
        let id = client.create_login_cipher("2.legatt|mac").await["id"].as_str().unwrap().to_string();

        // The legacy single-step API creates the record and stores the bytes at once.
        let resp = client
            .post_multipart(
                &format!("/api/ciphers/{id}/attachment"),
                &[("key", None, b"2.attkey|mac"), ("data", Some("2.legacy.txt|mac"), b"legacy-attachment-bytes")],
            )
            .await;
        resp.assert_ok();
        let atts = resp.json()["attachments"].as_array().cloned().unwrap_or_default();
        assert_eq!(atts.len(), 1, "legacy upload should attach one file: {}", resp.body);
    }
}
