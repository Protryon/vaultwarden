use std::collections::HashSet;
use std::str::FromStr;

use axum::extract::{Path, Query};
use axum::{routing, Json, Router};
use axum_util::errors::{ApiError, ApiResult};
use chrono::Utc;
use log::{debug, error};
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use serde_with::{serde_as, DisplayFromStr};
use uuid::Uuid;

use crate::api::{ws_users, PasswordData, UpdateType};
use crate::auth::{decode_invite, Headers, ManagerHeaders, ManagerHeadersLoose, OrgAdminHeaders, OrgOwnerHeaders};
use crate::db::{
    Cipher, Collection, CollectionCipher, CollectionGroup, CollectionUser, Conn, EventType, Group, GroupUser, Invitation, OrgPolicyErr, OrgPolicyType,
    Organization, OrganizationApiKey, OrganizationPolicy, TwoFactor, User, UserOrgStatus, UserOrgType, UserOrganization, DB,
};
use crate::events::log_event;
use crate::util::{Upcase, AutoTxn};
use crate::{error::Error, mail, util::convert_json_key_lcase_first, CONFIG};

pub fn route(router: Router) -> Router {
    router
        .route("/organizations", routing::post(create_organization))
        .route("/organizations/:org_uuid", routing::delete(delete_organization))
        .route("/organizations/:org_uuid/delete", routing::post(delete_organization))
        .route("/organizations/:org_uuid/leave", routing::post(leave_organization))
        .route("/organizations/:org_uuid", routing::get(get_organization))
        .route("/organizations/:org_uuid", routing::put(post_organization))
        .route("/organizations/:org_uuid", routing::post(post_organization))
        .route("/collections", routing::get(get_user_collections))
        // actually should be :identifier, but axum panics...
        .route("/organizations/:org_uuid/auto-enroll-status", routing::get(get_auto_enroll_status))
        .route("/organizations/:org_uuid/collections", routing::get(get_org_collections))
        .route("/organizations/:org_uuid/collections/details", routing::get(get_org_collections_details))
        .route("/organizations/:org_uuid/collections", routing::post(post_organization_collections))
        .route("/organizations/:org_uuid/collections/:col_id", routing::put(post_organization_collection_update))
        .route("/organizations/:org_uuid/collections/:col_id", routing::post(post_organization_collection_update))
        .route("/organizations/:org_uuid/collections/:col_id/user/:user_id", routing::delete(delete_organization_collection_user))
        .route("/organizations/:org_uuid/collections/:col_id/delete-user/:user_id", routing::post(delete_organization_collection_user))
        .route("/organizations/:org_uuid/collections/:col_id", routing::delete(delete_organization_collection))
        .route("/organizations/:org_uuid/collections/:col_id/delete", routing::post(post_organization_collection_delete))
        .route("/organizations/:org_uuid/collections", routing::delete(bulk_delete_organization_collections))
        .route("/organizations/:org_uuid/collections/:col_id/details", routing::get(get_org_collection_detail))
        .route("/organizations/:org_uuid/collections/:col_id/users", routing::get(get_collection_users))
        .route("/organizations/:org_uuid/collections/:col_id/users", routing::put(put_collection_users))
        .route("/ciphers/organization-details", routing::get(get_org_details))
        .route("/organizations/:org_uuid/users", routing::get(get_org_users))
        .route("/organizations/:org_uuid/keys", routing::post(post_org_keys))
        .route("/organizations/:org_uuid/users/invite", routing::post(send_invite))
        .route("/organizations/:org_uuid/users/reinvite", routing::post(bulk_reinvite_user))
        .route("/organizations/:org_uuid/users/:user_id/reinvite", routing::post(reinvite_user))
        .route("/organizations/:org_uuid/users/:user_id/accept", routing::post(accept_invite))
        .route("/organizations/:org_uuid/users/confirm", routing::post(bulk_confirm_invite))
        .route("/organizations/:org_uuid/users/:user_id/confirm", routing::post(confirm_invite))
        .route("/organizations/:org_uuid/users/:user_id", routing::get(get_user))
        .route("/organizations/:org_uuid/users/:user_id", routing::put(edit_user))
        .route("/organizations/:org_uuid/users/:user_id", routing::post(edit_user))
        .route("/organizations/:org_uuid/users", routing::delete(bulk_delete_user))
        .route("/organizations/:org_uuid/users/:user_id", routing::delete(delete_user))
        .route("/organizations/:org_uuid/users/:user_id/delete", routing::post(delete_user))
        .route("/organizations/:org_uuid/users/public-keys", routing::post(bulk_public_keys))
        .route("/ciphers/import-organization", routing::post(post_org_import))
        .route("/organizations/:org_uuid/policies", routing::get(list_policies))
        .route("/organizations/:org_uuid/policies/token", routing::get(list_policies_token))
        .route("/organizations/:org_uuid/policies/invited-user", routing::get(list_policies_invited_user))
        .route("/organizations/:org_uuid/policies/:pol_type", routing::get(get_policy))
        .route("/organizations/:org_uuid/policies/:pol_type", routing::put(put_policy))
        .route("/organizations/:org_uuid/tax", routing::get(get_organization_tax))
        .route("/plans", routing::get(get_plans))
        .route("/plans/", routing::get(get_plans))
        .route("/plans/sales-tax-rates", routing::get(get_plans_tax_rates))
        .route("/organizations/:org_uuid/import", routing::post(import))
        .route("/organizations/:org_uuid/users/:user_id/deactivate", routing::put(revoke_organization_user))
        .route("/organizations/:org_uuid/users/deactivate", routing::put(bulk_revoke_organization_user))
        .route("/organizations/:org_uuid/users/:user_id/revoke", routing::put(revoke_organization_user))
        .route("/organizations/:org_uuid/users/revoke", routing::put(bulk_revoke_organization_user))
        .route("/organizations/:org_uuid/users/:user_id/activate", routing::put(restore_organization_user))
        .route("/organizations/:org_uuid/users/activate", routing::put(bulk_restore_organization_user))
        .route("/organizations/:org_uuid/users/:user_id/restore", routing::put(restore_organization_user))
        .route("/organizations/:org_uuid/users/restore", routing::put(bulk_restore_organization_user))
        .route("/organizations/:org_uuid/groups", routing::get(get_groups))
        .route("/organizations/:org_uuid/groups/:group_id", routing::post(put_group))
        .route("/organizations/:org_uuid/groups", routing::post(post_groups))
        .route("/organizations/:org_uuid/groups/:group_id", routing::put(put_group))
        .route("/organizations/:org_uuid/groups/:group_id/details", routing::get(get_group_details))
        .route("/organizations/:org_uuid/groups/:group_id/delete", routing::post(delete_group))
        .route("/organizations/:org_uuid/groups/:group_id", routing::delete(delete_group))
        .route("/organizations/:org_uuid/groups", routing::delete(bulk_delete_groups))
        .route("/organizations/:org_uuid/groups/:group_id", routing::get(get_group))
        .route("/organizations/:org_uuid/groups/:group_id/users", routing::get(get_group_users))
        .route("/organizations/:org_uuid/groups/:group_id/users", routing::put(put_group_users))
        .route("/organizations/:org_uuid/users/:user_id/groups", routing::get(get_user_groups))
        .route("/organizations/:org_uuid/users/:user_id/groups", routing::post(put_user_groups))
        .route("/organizations/:org_uuid/users/:user_id/groups", routing::put(put_user_groups))
        .route("/organizations/:org_uuid/groups/:group_id/delete-user/:user_id", routing::post(delete_group_user))
        .route("/organizations/:org_uuid/groups/:group_id/users/:user_id", routing::delete(delete_group_user))
        .route("/organizations/:org_uuid/keys", routing::get(get_organization_keys))
        .route("/organizations/:org_uuid/users/:user_id/reset-password", routing::put(put_reset_password))
        .route("/organizations/:org_uuid/users/:user_id/reset-password-details", routing::get(get_reset_password_details))
        .route("/organizations/:org_uuid/users/:user_id/reset-password-enrollment", routing::put(put_reset_password_enrollment))
        .route("/organizations/:org_uuid/export", routing::get(get_org_export))
        .route("/organizations/:org_uuid/api-key", routing::post(api_key))
        .route("/organizations/:org_uuid/rotate-api-key", routing::post(rotate_api_key))
}

#[derive(Deserialize)]
#[serde(rename_all = "PascalCase")]
struct OrgData {
    billing_email: String,
    collection_name: String,
    key: String,
    name: String,
    keys: Option<OrgKeyData>,
    // #[serde(rename = "PlanType")]
    // _PlanType: NumberOrString, // Ignored, always use the same plan
}

#[derive(Deserialize, Debug)]
#[serde(rename_all = "PascalCase")]
struct OrganizationUpdateData {
    billing_email: String,
    name: String,
}

#[derive(Deserialize)]
#[serde(rename_all = "PascalCase")]
struct NewCollectionData {
    name: String,
    groups: Vec<NewCollectionObjectData>,
    users: Vec<NewCollectionObjectData>,
}

#[derive(Deserialize)]
#[serde(rename_all = "PascalCase")]
struct NewCollectionObjectData {
    hide_passwords: bool,
    id: Uuid,
    read_only: bool,
}

#[derive(Deserialize)]
#[serde(rename_all = "PascalCase")]
struct OrgKeyData {
    encrypted_private_key: String,
    public_key: String,
}

#[derive(Deserialize, Debug)]
#[serde(rename_all = "PascalCase")]
struct OrgBulkIds {
    ids: Vec<Uuid>,
}

async fn create_organization(conn: AutoTxn, headers: Headers, data: Json<Upcase<OrgData>>) -> ApiResult<Json<Value>> {
    if !CONFIG.is_org_creation_allowed(&headers.user.email) {
        err!("User not allowed to create organizations")
    }

    if OrganizationPolicy::is_applicable_to_user(&conn, headers.user.uuid, OrgPolicyType::SingleOrg, None).await? {
        err!(
            "You may not create an organization. You belong to an organization which has a policy that prohibits you from being a member of any other organization."
        )
    }

    let data: OrgData = data.0.data;
    let (private_key, public_key) = if data.keys.is_some() {
        let keys: OrgKeyData = data.keys.unwrap();
        (Some(keys.encrypted_private_key), Some(keys.public_key))
    } else {
        (None, None)
    };

    let org = Organization::new(data.name, data.billing_email, private_key, public_key);
    let mut user_org = UserOrganization::new(headers.user.uuid, org.uuid);
    let collection = Collection::new(org.uuid, data.collection_name);

    user_org.akey = data.key;
    user_org.access_all = true;
    user_org.atype = UserOrgType::Owner;
    user_org.status = UserOrgStatus::Confirmed;

    org.save(&conn).await?;
    user_org.save(&conn).await?;
    collection.save(&conn).await?;

    conn.commit().await?;

    Ok(Json(org.to_json()))
}

async fn delete_organization(Path(org_uuid): Path<Uuid>, headers: OrgOwnerHeaders, data: Json<Upcase<PasswordData>>) -> ApiResult<()> {
    let data: PasswordData = data.0.data;
    let password_hash = data.master_password_hash;

    if !headers.user.check_valid_password(&password_hash) {
        err!("Invalid password")
    }
    let conn = DB.get().await?;

    match Organization::get(&conn, org_uuid).await? {
        None => err!("Organization not found"),
        Some(org) => org.delete(&conn).await,
    }
}

async fn leave_organization(Path(org_uuid): Path<Uuid>, headers: Headers) -> ApiResult<()> {
    let conn = DB.get().await?;

    match UserOrganization::get(&conn, headers.user.uuid, org_uuid).await? {
        None => err!("User not part of organization"),
        Some(user_org) => {
            if user_org.atype == UserOrgType::Owner && UserOrganization::count_confirmed_by_org_and_type(&conn, org_uuid, UserOrgType::Owner).await? <= 1 {
                err!("The last owner can't leave")
            }

            log_event(EventType::OrganizationUserRemoved, user_org.user_uuid, org_uuid, headers.user.uuid, headers.device.atype, Utc::now(), headers.ip, &conn)
                .await?;

            user_org.delete(&conn).await
        }
    }
}

async fn get_organization(Path(org_uuid): Path<Uuid>, _headers: OrgOwnerHeaders) -> ApiResult<Json<Value>> {
    let conn = DB.get().await?;

    match Organization::get(&conn, org_uuid).await? {
        Some(organization) => Ok(Json(organization.to_json())),
        None => err!("Can't find organization details"),
    }
}

async fn post_organization(Path(org_uuid): Path<Uuid>, headers: OrgOwnerHeaders, data: Json<Upcase<OrganizationUpdateData>>) -> ApiResult<Json<Value>> {
    let conn = DB.get().await?;

    let data: OrganizationUpdateData = data.0.data;

    let mut org = match Organization::get(&conn, org_uuid).await? {
        Some(organization) => organization,
        None => err!("Can't find organization details"),
    };

    org.name = data.name;
    org.billing_email = data.billing_email;

    org.save(&conn).await?;

    log_event(EventType::OrganizationUpdated, org_uuid, org_uuid, headers.user.uuid, headers.device.atype, Utc::now(), headers.ip, &conn).await?;

    Ok(Json(org.to_json()))
}

async fn get_user_collections(headers: Headers) -> ApiResult<Json<Value>> {
    let conn = DB.get().await?;

    Ok(Json(json!({
        "Data":
            Collection::find_by_user(&conn, headers.user.uuid, false).await?
            .iter()
            .map(Collection::to_json)
            .collect::<Value>(),
        "Object": "list",
        "ContinuationToken": null,
    })))
}

#[derive(Deserialize)]
struct IdentifierPath {
    #[serde(rename = "org_id")]
    #[allow(dead_code)]
    identifier: String,
}

#[allow(unused_variables)]
async fn get_auto_enroll_status(Path(path): Path<IdentifierPath>) -> ApiResult<Json<Value>> {
    //TODO
    Ok(Json(json!({
        "ResetPasswordEnabled": false, //Not Implemented.
    })))
}

async fn get_org_collections(Path(org_uuid): Path<Uuid>, _headers: ManagerHeadersLoose) -> ApiResult<Json<Value>> {
    let conn = DB.get().await?;

    Ok(Json(json!({
        "Data": _get_org_collections(&conn, org_uuid).await?,
        "Object": "list",
        "ContinuationToken": null,
    })))
}

async fn get_org_collections_details(Path(org_uuid): Path<Uuid>, headers: ManagerHeadersLoose) -> ApiResult<Json<Value>> {
    let mut data = Vec::new();
    let conn = DB.get().await?;

    let user_org = match UserOrganization::get(&conn, headers.user.uuid, org_uuid).await? {
        Some(u) => u,
        None => err!("User is not part of organization"),
    };

    let coll_users = CollectionUser::find_by_organization(&conn, org_uuid).await?;

    //TODO: N+1 query
    for col in Collection::find_by_organization(&conn, org_uuid).await? {
        let groups: Vec<Value> = if CONFIG.advanced.org_groups_enabled {
            CollectionGroup::find_by_collection(&conn, col.uuid)
                .await?
                .iter()
                .map(|collection_group| SelectionReadOnly::to_collection_group_details_read_only(collection_group).to_json())
                .collect()
        } else {
            // The Bitwarden clients seem to call this API regardless of whether groups are enabled,
            // so just act as if there are no groups.
            Vec::with_capacity(0)
        };

        let mut assigned = false;
        let users: Vec<Value> = coll_users
            .iter()
            .filter(|collection_user| collection_user.collection_uuid == col.uuid)
            .map(|collection_user| {
                // Remember `user_uuid` is swapped here with the `user_org.uuid` with a join during the `CollectionUser::find_by_organization` call.
                // We check here if the current user is assigned to this collection or not.
                if collection_user.user_uuid == user_org.user_uuid {
                    assigned = true;
                }
                SelectionReadOnly::to_collection_user_details_read_only(collection_user).to_json()
            })
            .collect();

        if user_org.access_all {
            assigned = true;
        }

        let mut json_object = col.to_json();
        json_object["Assigned"] = json!(assigned);
        json_object["Users"] = json!(users);
        json_object["Groups"] = json!(groups);
        json_object["Object"] = json!("collectionAccessDetails");
        data.push(json_object)
    }

    Ok(Json(json!({
        "Data": data,
        "Object": "list",
        "ContinuationToken": null,
    })))
}

async fn _get_org_collections(conn: &Conn, org_uuid: Uuid) -> ApiResult<Value> {
    Ok(Collection::find_by_organization(conn, org_uuid).await?.iter().map(Collection::to_json).collect::<Value>())
}

async fn post_organization_collections(
    conn: AutoTxn,
    Path(org_uuid): Path<Uuid>,
    headers: ManagerHeadersLoose,
    data: Json<Upcase<NewCollectionData>>,
) -> ApiResult<Json<Value>> {
    let data: NewCollectionData = data.0.data;

    let org = match Organization::get(&conn, org_uuid).await? {
        Some(organization) => organization,
        None => err!("Can't find organization details"),
    };

    let collection = Collection::new(org.uuid, data.name);
    collection.save(&conn).await?;

    log_event(EventType::CollectionCreated, collection.uuid, org_uuid, headers.user.uuid, headers.device.atype, Utc::now(), headers.ip, &conn).await?;

    for group in data.groups {
        CollectionGroup::new(collection.uuid, group.id, group.read_only, group.hide_passwords).save(&conn).await?;
    }

    //TODO: N+1 query
    for user in data.users {
        let org_user = match UserOrganization::get(&conn, user.id, org.uuid).await? {
            Some(u) => u,
            None => err!("User is not part of organization"),
        };

        if org_user.access_all {
            continue;
        }

        CollectionUser {
            user_uuid: org_user.user_uuid,
            collection_uuid: collection.uuid,
            read_only: user.read_only,
            hide_passwords: user.hide_passwords,
        }
        .save(&conn)
        .await?;
    }

    conn.commit().await?;

    Ok(Json(collection.to_json()))
}

#[derive(Deserialize)]
struct OrgColId {
    org_uuid: Uuid,
    col_id: Uuid,
}

#[derive(Deserialize)]
struct OrgUserId {
    org_uuid: Uuid,
    user_id: Uuid,
}

#[derive(Deserialize)]
struct OrgColUserId {
    org_uuid: Uuid,
    col_id: Uuid,
    user_id: Uuid,
}

async fn post_organization_collection_update(
    conn: AutoTxn,
    Path(OrgColId {
        org_uuid,
        col_id,
    }): Path<OrgColId>,
    headers: ManagerHeaders,
    data: Json<Upcase<NewCollectionData>>,
) -> ApiResult<Json<Value>> {
    let data: NewCollectionData = data.0.data;

    let org = match Organization::get(&conn, org_uuid).await? {
        Some(organization) => organization,
        None => err!("Can't find organization details"),
    };

    let mut collection = match Collection::get_for_org(&conn, org.uuid, col_id).await? {
        Some(collection) => collection,
        None => err!("Collection not found"),
    };

    collection.name = data.name;
    collection.save(&conn).await?;

    log_event(EventType::CollectionUpdated, collection.uuid, org_uuid, headers.user.uuid, headers.device.atype, Utc::now(), headers.ip, &conn).await?;

    CollectionGroup::delete_all_by_collection(&conn, col_id).await?;

    for group in data.groups {
        CollectionGroup::new(col_id, group.id, group.read_only, group.hide_passwords).save(&conn).await?;
    }

    CollectionUser::delete_all_by_collection(&conn, col_id).await?;

    for user in data.users {
        //todo
        let org_user = match UserOrganization::get(&conn, user.id, org_uuid).await? {
            Some(u) => u,
            None => err!("User is not part of organization"),
        };

        if org_user.access_all {
            continue;
        }

        CollectionUser {
            user_uuid: org_user.user_uuid,
            collection_uuid: collection.uuid,
            read_only: user.read_only,
            hide_passwords: user.hide_passwords,
        }
        .save(&conn)
        .await?;
    }

    conn.commit().await?;

    Ok(Json(collection.to_json()))
}

async fn delete_organization_collection_user(
    Path(OrgColUserId {
        org_uuid,
        col_id,
        user_id,
    }): Path<OrgColUserId>,
    _headers: OrgAdminHeaders,
) -> ApiResult<()> {
    let conn = DB.get().await?;

    let collection = match Collection::get(&conn, col_id).await? {
        None => err!("Collection not found"),
        Some(collection) => {
            if collection.organization_uuid == org_uuid {
                collection
            } else {
                err!("Collection and Organization id do not match")
            }
        }
    };

    match UserOrganization::get(&conn, user_id, org_uuid).await? {
        None => err!("User not found in organization"),
        Some(user_org) => match CollectionUser::find_by_collection_and_user(&conn, collection.uuid, user_org.user_uuid).await? {
            None => err!("User not assigned to collection"),
            Some(col_user) => col_user.delete(&conn).await,
        },
    }
}

async fn _delete_organization_collection(org_uuid: Uuid, col_id: Uuid, headers: &ManagerHeaders, conn: &Conn) -> ApiResult<()> {
    match Collection::get(conn, col_id).await? {
        None => err!("Collection not found"),
        Some(collection) => {
            if collection.organization_uuid == org_uuid {
                log_event(EventType::CollectionDeleted, collection.uuid, org_uuid, headers.user.uuid, headers.device.atype, Utc::now(), headers.ip, conn)
                    .await?;
                collection.delete(conn).await?;
            } else {
                err!("Collection and Organization id do not match")
            }
        }
    }
    Ok(())
}

async fn delete_organization_collection(
    Path(OrgColId {
        org_uuid,
        col_id,
    }): Path<OrgColId>,
    headers: ManagerHeaders,
) -> ApiResult<()> {
    let conn = DB.get().await?;
    _delete_organization_collection(org_uuid, col_id, &headers, &conn).await
}

#[derive(Deserialize, Debug)]
#[serde(rename_all = "PascalCase")]
#[allow(dead_code)]
struct DeleteCollectionData {
    id: String,
    org_uuid: String,
}

async fn post_organization_collection_delete(
    Path(OrgColId {
        org_uuid,
        col_id,
    }): Path<OrgColId>,
    headers: ManagerHeaders,
    _data: Json<Upcase<DeleteCollectionData>>,
) -> ApiResult<()> {
    let conn = DB.get().await?;
    _delete_organization_collection(org_uuid, col_id, &headers, &conn).await
}

#[derive(Deserialize, Debug)]
#[serde(rename_all = "PascalCase")]
struct BulkCollectionIds {
    ids: Vec<Uuid>,
    organization_id: Uuid,
}

async fn bulk_delete_organization_collections(
    Path(org_uuid): Path<Uuid>,
    headers: ManagerHeadersLoose,
    data: Json<Upcase<BulkCollectionIds>>,
) -> ApiResult<()> {
    let data: BulkCollectionIds = data.0.data;
    if org_uuid != data.organization_id {
        err!("OrganizationId mismatch");
    }
    let conn = DB.get().await?;

    let collections = data.ids;

    let headers = ManagerHeaders::from_loose(headers, &collections, &conn).await?;

    for col_id in collections {
        _delete_organization_collection(org_uuid, col_id, &headers, &conn).await?
    }
    Ok(())
}

async fn get_org_collection_detail(
    Path(OrgColId {
        org_uuid,
        col_id,
    }): Path<OrgColId>,
    headers: ManagerHeaders,
) -> ApiResult<Json<Value>> {
    let conn = DB.get().await?;

    match Collection::find_by_uuid_and_user(&conn, col_id, headers.user.uuid).await? {
        None => err!("Collection not found"),
        Some(collection) => {
            if collection.organization_uuid != org_uuid {
                err!("Collection is not owned by organization")
            }

            let user_org = match UserOrganization::get(&conn, headers.user.uuid, org_uuid).await? {
                Some(u) => u,
                None => err!("User is not part of organization"),
            };

            let groups: Vec<Value> = if CONFIG.advanced.org_groups_enabled {
                CollectionGroup::find_by_collection(&conn, collection.uuid)
                    .await?
                    .iter()
                    .map(|collection_group| SelectionReadOnly::to_collection_group_details_read_only(collection_group).to_json())
                    .collect()
            } else {
                // The Bitwarden clients seem to call this API regardless of whether groups are enabled,
                // so just act as if there are no groups.
                Vec::with_capacity(0)
            };

            let mut assigned = false;
            let users: Vec<Value> = CollectionUser::find_by_organization(&conn, collection.uuid)
                .await?
                .iter()
                .map(|collection_user| {
                    if collection_user.user_uuid == user_org.user_uuid {
                        assigned = true;
                    }
                    SelectionReadOnly::to_collection_user_details_read_only(collection_user).to_json()
                })
                .collect();

            if user_org.access_all {
                assigned = true;
            }

            let mut json_object = collection.to_json();
            json_object["Assigned"] = json!(assigned);
            json_object["Users"] = json!(users);
            json_object["Groups"] = json!(groups);
            json_object["Object"] = json!("collectionAccessDetails");

            Ok(Json(json_object))
        }
    }
}

async fn get_collection_users(
    Path(OrgColId {
        org_uuid,
        col_id,
    }): Path<OrgColId>,
    _headers: ManagerHeaders,
) -> ApiResult<Json<Value>> {
    // Get org and collection, check that collection is from org
    let conn = DB.get().await?;

    let collection = match Collection::find_by_uuid_and_org(&conn, col_id, org_uuid).await? {
        None => err!("Collection not found in Organization"),
        Some(collection) => collection,
    };

    let mut user_list = Vec::new();
    //TODO: N+1 query
    for col_user in CollectionUser::find_by_collection(&conn, collection.uuid).await? {
        let Some(uo) = UserOrganization::get(&conn, col_user.user_uuid, org_uuid).await? else {
            continue;
        };
        user_list.push(uo.to_json_user_access_restrictions(&col_user));
    }

    Ok(Json(json!(user_list)))
}

async fn put_collection_users(
    conn: AutoTxn,
    Path(OrgColId {
        org_uuid,
        col_id,
    }): Path<OrgColId>,
    _headers: ManagerHeaders,
    data: Json<Vec<Upcase<CollectionData>>>,
) -> ApiResult<()> {
    // Get org and collection, check that collection is from org
    if Collection::find_by_uuid_and_org(&conn, col_id, org_uuid).await?.is_none() {
        err!("Collection not found in Organization")
    }

    // Delete all the user-collections
    CollectionUser::delete_all_by_collection(&conn, col_id).await?;

    // And then add all the received ones (except if the user has access_all)
    for d in data.iter().map(|d| &d.data) {
        let user = match UserOrganization::get(&conn, d.id, org_uuid).await? {
            Some(u) => u,
            None => err!("User is not part of organization"),
        };

        if user.access_all {
            continue;
        }

        CollectionUser {
            user_uuid: user.user_uuid,
            collection_uuid: col_id,
            read_only: d.read_only,
            hide_passwords: d.hide_passwords,
        }
        .save(&conn)
        .await?;
    }

    conn.commit().await?;

    Ok(())
}

#[derive(Deserialize)]
struct OrgIdData {
    #[serde(rename = "organizationId")]
    organization_id: Uuid,
}

async fn get_org_details(Query(data): Query<OrgIdData>, headers: Headers) -> ApiResult<Json<Value>> {
    let conn = DB.get().await?;

    Ok(Json(json!({
        "Data": _get_org_details(data.organization_id, headers.user.uuid, &conn).await?,
        "Object": "list",
        "ContinuationToken": null,
    })))
}

async fn _get_org_details(org_uuid: Uuid, user_uuid: Uuid, conn: &Conn) -> ApiResult<Value> {
    let ciphers = Cipher::find_by_org(conn, org_uuid).await?;

    let mut ciphers_json = Vec::with_capacity(ciphers.len());
    for c in ciphers {
        ciphers_json.push(c.to_json(conn, user_uuid, false).await?);
    }
    Ok(json!(ciphers_json))
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct GetOrgUserData {
    include_collections: Option<bool>,
    include_groups: Option<bool>,
}

async fn get_org_users(Query(data): Query<GetOrgUserData>, Path(org_uuid): Path<Uuid>, _headers: ManagerHeadersLoose) -> ApiResult<Json<Value>> {
    let mut users_json = Vec::new();
    let conn = DB.get().await?;

    for u in UserOrganization::find_by_org(&conn, org_uuid).await? {
        users_json.push(u.to_json_user_details(&conn, data.include_collections.unwrap_or(false), data.include_groups.unwrap_or(false)).await?);
    }

    Ok(Json(json!({
        "Data": users_json,
        "Object": "list",
        "ContinuationToken": null,
    })))
}

async fn post_org_keys(Path(org_uuid): Path<Uuid>, _headers: OrgAdminHeaders, data: Json<Upcase<OrgKeyData>>) -> ApiResult<Json<Value>> {
    let data: OrgKeyData = data.0.data;
    let conn = DB.get().await?;

    let mut org = match Organization::get(&conn, org_uuid).await? {
        Some(organization) => {
            if organization.private_key.is_some() && organization.public_key.is_some() {
                err!("Organization Keys already exist")
            }
            organization
        }
        None => err!("Can't find organization details"),
    };

    org.private_key = Some(data.encrypted_private_key);
    org.public_key = Some(data.public_key);

    org.save(&conn).await?;

    Ok(Json(json!({
        "Object": "organizationKeys",
        "public_key": org.public_key,
        "PrivateKey": org.private_key,
    })))
}

#[derive(Deserialize)]
#[serde(rename_all = "PascalCase")]
struct CollectionData {
    id: Uuid,
    read_only: bool,
    hide_passwords: bool,
}

#[serde_as]
#[derive(Deserialize)]
#[serde(rename_all = "PascalCase")]
struct InviteData {
    emails: Vec<String>,
    groups: Vec<Uuid>,
    #[serde_as(as = "DisplayFromStr")]
    r#type: UserOrgType,
    collections: Option<Vec<CollectionData>>,
    access_all: Option<bool>,
}

async fn send_invite(conn: AutoTxn, Path(org_uuid): Path<Uuid>, headers: OrgAdminHeaders, data: Json<Upcase<InviteData>>) -> ApiResult<()> {
    let data: InviteData = data.0.data;

    if data.r#type != UserOrgType::User && headers.org_user_type != UserOrgType::Owner {
        err!("Only Owners can invite Managers, Admins or Owners")
    }

    for email in data.emails.iter() {
        let email = email.to_lowercase();
        let mut user_org_status = UserOrgStatus::Invited;
        let user = match User::find_by_email(&conn, &email).await? {
            None => {
                if !CONFIG.settings.invitations_allowed {
                    err!(format!("User does not exist: {email}"))
                }

                if !CONFIG.is_email_domain_allowed(&email) {
                    err!("Email domain not eligible for invitations")
                }

                if !CONFIG.mail_enabled() {
                    let invitation = Invitation::new(&email);
                    invitation.save(&conn).await?;
                }

                let mut user = User::new(email.clone());
                user.save(&conn).await?;
                user
            }
            Some(user) => {
                if UserOrganization::get(&conn, user.uuid, org_uuid).await?.is_some() {
                    err!(format!("User already in organization: {email}"))
                } else {
                    // automatically accept existing users if mail is disabled
                    if !CONFIG.mail_enabled() && !user.password_hash.is_empty() {
                        user_org_status = UserOrgStatus::Accepted;
                    }
                    user
                }
            }
        };

        let mut new_user = UserOrganization::new(user.uuid, org_uuid);
        let access_all = data.access_all.unwrap_or(false);
        new_user.access_all = access_all;
        new_user.atype = data.r#type;
        new_user.status = user_org_status;

        // If no accessAll, add the collections received
        if !access_all {
            for col in data.collections.iter().flatten() {
                match Collection::find_by_uuid_and_org(&conn, col.id, org_uuid).await? {
                    None => err!("Collection not found in Organization"),
                    Some(collection) => {
                        CollectionUser {
                            user_uuid: user.uuid,
                            collection_uuid: collection.uuid,
                            read_only: col.read_only,
                            hide_passwords: col.hide_passwords,
                        }
                        .save(&conn)
                        .await?;
                    }
                }
            }
        }

        new_user.save(&conn).await?;

        for group in &data.groups {
            let group_entry = GroupUser::new(*group, user.uuid);
            group_entry.save(&conn).await?;
        }

        log_event(EventType::OrganizationUserInvited, new_user.user_uuid, org_uuid, headers.user.uuid, headers.device.atype, Utc::now(), headers.ip, &conn)
            .await?;

        if CONFIG.mail_enabled() {
            let org_name = match Organization::get(&conn, org_uuid).await? {
                Some(org) => org.name,
                None => err!("Error looking up organization"),
            };

            mail::send_invite(&email, user.uuid, Some(org_uuid), &org_name, Some(headers.user.email.clone())).await?;
        }
    }

    Ok(())
}

async fn bulk_reinvite_user(Path(org_uuid): Path<Uuid>, headers: OrgAdminHeaders, data: Json<Upcase<OrgBulkIds>>) -> ApiResult<Json<Value>> {
    let data: OrgBulkIds = data.0.data;
    let conn = DB.get().await?;

    let mut bulk_response = Vec::new();
    for org_user_id in data.ids {
        let err_msg = match _reinvite_user(org_uuid, org_user_id, &headers.user.email, &conn).await {
            Ok(_) => String::new(),
            Err(e) => format!("{e:?}"),
        };

        bulk_response.push(json!(
            {
                "Object": "OrganizationBulkConfirmResponseModel",
                "Id": org_user_id,
                "Error": err_msg
            }
        ))
    }

    Ok(Json(json!({
        "Data": bulk_response,
        "Object": "list",
        "ContinuationToken": null
    })))
}

async fn reinvite_user(
    Path(OrgUserId {
        org_uuid,
        user_id,
    }): Path<OrgUserId>,
    headers: OrgAdminHeaders,
) -> ApiResult<()> {
    let conn = DB.get().await?;
    _reinvite_user(org_uuid, user_id, &headers.user.email, &conn).await
}

async fn _reinvite_user(org_uuid: Uuid, user_id: Uuid, invited_by_email: &str, conn: &Conn) -> ApiResult<()> {
    if !CONFIG.settings.invitations_allowed {
        err!("Invitations are not allowed.")
    }

    if !CONFIG.mail_enabled() {
        err!("SMTP is not configured.")
    }

    let user_org = match UserOrganization::get(conn, user_id, org_uuid).await? {
        Some(user_org) => user_org,
        None => err!("The user hasn't been invited to the organization."),
    };

    if user_org.status() != UserOrgStatus::Invited {
        err!("The user is already accepted or confirmed to the organization")
    }

    let user = match User::get(conn, user_org.user_uuid).await? {
        Some(user) => user,
        None => err!("User not found."),
    };

    let org_name = match Organization::get(conn, org_uuid).await? {
        Some(org) => org.name,
        None => err!("Error looking up organization."),
    };

    if CONFIG.mail_enabled() {
        mail::send_invite(&user.email, user.uuid, Some(org_uuid), &org_name, Some(invited_by_email.to_string())).await?;
    } else {
        let invitation = Invitation::new(&user.email);
        invitation.save(conn).await?;
    }

    Ok(())
}

#[derive(Deserialize)]
#[serde(rename_all = "PascalCase")]
struct AcceptData {
    token: String,
    reset_password_key: Option<String>,
}

async fn accept_invite(
    Path(OrgUserId {
        org_uuid,
        user_id,
    }): Path<OrgUserId>,
    data: Json<Upcase<AcceptData>>,
) -> ApiResult<()> {
    // The web-vault passes org_uuid and org_user_id in the URL, but we are just reading them from the JWT instead
    let data: AcceptData = data.0.data;
    let claims = decode_invite(&data.token)?;
    let conn = DB.get().await?;

    match User::find_by_email(&conn, &claims.email).await? {
        Some(_) => {
            Invitation::take(&conn, &claims.email).await?;

            if claims.sub != user_id || claims.org_uuid != Some(org_uuid) {
                err!("Mismatch between URL and token");
            }

            if let (user_id, Some(org_uuid)) = (claims.sub, claims.org_uuid) {
                let mut user_org = match UserOrganization::get(&conn, user_id, org_uuid).await? {
                    Some(user_org) => user_org,
                    None => err!("Error accepting the invitation"),
                };

                if user_org.status() != UserOrgStatus::Invited {
                    err!("User already accepted the invitation")
                }

                let master_password_required = OrganizationPolicy::org_is_reset_password_auto_enroll(&conn, org_uuid).await?;
                if data.reset_password_key.is_none() && master_password_required {
                    err!("Reset password key is required, but not provided.");
                }

                // This check is also done at accept_invite(), _confirm_invite, _activate_user(), edit_user(), admin::update_user_org_type
                // It returns different error messages per function.
                if user_org.atype < UserOrgType::Admin {
                    match OrganizationPolicy::is_user_allowed(&conn, user_org.user_uuid, org_uuid, false).await? {
                        Ok(_) => {}
                        Err(OrgPolicyErr::TwoFactorMissing) => {
                            err!("You cannot join this organization until you enable two-step login on your user account");
                        }
                        Err(OrgPolicyErr::SingleOrgEnforced) => {
                            err!("You cannot join this organization because you are a member of an organization which forbids it");
                        }
                    }
                }

                user_org.status = UserOrgStatus::Accepted;

                if master_password_required {
                    user_org.reset_password_key = data.reset_password_key;
                }

                user_org.save(&conn).await?;
            }
        }
        None => err!("Invited user not found"),
    }

    if CONFIG.mail_enabled() {
        let mut org_name = CONFIG.settings.invitation_org_name.clone();
        if let Some(org_uuid) = claims.org_uuid {
            org_name = match Organization::get(&conn, org_uuid).await? {
                Some(org) => org.name,
                None => err!("Organization not found."),
            };
        };
        if let Some(invited_by_email) = &claims.invited_by_email {
            // User was invited to an organization, so they must be confirmed manually after acceptance
            mail::send_invite_accepted(&claims.email, invited_by_email, &org_name).await?;
        } else {
            // User was invited from /admin, so they are automatically confirmed
            mail::send_invite_confirmed(&claims.email, &org_name).await?;
        }
    }

    Ok(())
}

async fn bulk_confirm_invite(Path(org_uuid): Path<Uuid>, headers: OrgAdminHeaders, data: Json<Upcase<Value>>) -> ApiResult<Json<Value>> {
    let data = data.0.data;
    let conn = DB.get().await?;

    let mut bulk_response = Vec::new();
    match data["Keys"].as_array() {
        Some(keys) => {
            for invite in keys {
                let Ok(user_id) = Uuid::from_str(invite["Id"].as_str().unwrap_or_default()) else {
                    err!("Malformed invite ID");
                };
                let user_key = invite["Key"].as_str().unwrap_or_default();
                let err_msg = match _confirm_invite(org_uuid, user_id, user_key, &headers, &conn).await {
                    Ok(_) => String::new(),
                    Err(e @ ApiError::Other(_)) => return Err(e),
                    Err(e) => format!("{e:?}"),
                };

                bulk_response.push(json!(
                    {
                        "Object": "OrganizationBulkConfirmResponseModel",
                        "Id": user_id,
                        "Error": err_msg
                    }
                ));
            }
        }
        None => error!("No keys to confirm"),
    }

    Ok(Json(json!({
        "Data": bulk_response,
        "Object": "list",
        "ContinuationToken": null
    })))
}

async fn confirm_invite(
    Path(OrgUserId {
        org_uuid,
        user_id,
    }): Path<OrgUserId>,
    headers: OrgAdminHeaders,
    data: Json<Upcase<Value>>,
) -> ApiResult<()> {
    let data = data.0.data;
    let user_key = data["Key"].as_str().unwrap_or_default();
    let conn = DB.get().await?;
    _confirm_invite(org_uuid, user_id, user_key, &headers, &conn).await
}

async fn _confirm_invite(org_uuid: Uuid, user_id: Uuid, key: &str, headers: &OrgAdminHeaders, conn: &Conn) -> ApiResult<()> {
    if key.is_empty() {
        err!("Key or UserId is not set, unable to process request");
    }

    let mut user_to_confirm = match UserOrganization::get(conn, user_id, org_uuid).await? {
        Some(user) => user,
        None => err!("The specified user isn't a member of the organization"),
    };

    if user_to_confirm.atype != UserOrgType::User && headers.org_user_type != UserOrgType::Owner {
        err!("Only Owners can confirm Managers, Admins or Owners")
    }

    if user_to_confirm.status() != UserOrgStatus::Accepted {
        err!("User in invalid state")
    }

    // This check is also done at accept_invite(), _confirm_invite, _activate_user(), edit_user(), admin::update_user_org_type
    // It returns different error messages per function.
    if user_to_confirm.atype < UserOrgType::Admin {
        match OrganizationPolicy::is_user_allowed(conn, user_to_confirm.user_uuid, org_uuid, true).await? {
            Ok(_) => {}
            Err(OrgPolicyErr::TwoFactorMissing) => {
                err!("You cannot confirm this user because it has no two-step login method activated");
            }
            Err(OrgPolicyErr::SingleOrgEnforced) => {
                err!("You cannot confirm this user because it is a member of an organization which forbids it");
            }
        }
    }

    user_to_confirm.status = UserOrgStatus::Confirmed;
    user_to_confirm.akey = key.to_string();

    log_event(EventType::OrganizationUserConfirmed, user_to_confirm.user_uuid, org_uuid, headers.user.uuid, headers.device.atype, Utc::now(), headers.ip, conn)
        .await?;

    if CONFIG.mail_enabled() {
        let org_name = match Organization::get(conn, org_uuid).await? {
            Some(org) => org.name,
            None => err!("Error looking up organization."),
        };
        let address = match User::get(conn, user_to_confirm.user_uuid).await? {
            Some(user) => user.email,
            None => err!("Error looking up user."),
        };
        mail::send_invite_confirmed(&address, &org_name).await?;
    }

    user_to_confirm.save(conn).await?;

    if let Some(user) = User::get(conn, user_to_confirm.user_uuid).await? {
        ws_users().send_user_update(UpdateType::SyncOrgKeys, conn, &user).await?;
    }

    Ok(())
}

async fn get_user(
    Path(OrgUserId {
        org_uuid,
        user_id,
    }): Path<OrgUserId>,
    _headers: OrgAdminHeaders,
    Query(data): Query<GetOrgUserData>,
) -> ApiResult<Json<Value>> {
    let conn = DB.get().await?;

    let user = match UserOrganization::get(&conn, user_id, org_uuid).await? {
        Some(user) => user,
        None => err!("The specified user isn't a member of the organization"),
    };

    // In this case, when groups are requested we also need to include collections.
    // Else these will not be shown in the interface, and could lead to missing collections when saved.
    let include_groups = data.include_groups.unwrap_or(false);
    Ok(Json(user.to_json_user_details(&conn, data.include_collections.unwrap_or(include_groups), include_groups).await?))
}

#[serde_as]
#[derive(Deserialize)]
#[serde(rename_all = "PascalCase")]
struct EditUserData {
    #[serde_as(as = "DisplayFromStr")]
    r#type: UserOrgType,
    collections: Option<Vec<CollectionData>>,
    groups: Option<Vec<Uuid>>,
    access_all: bool,
}

async fn edit_user(
    conn: AutoTxn,
    Path(OrgUserId {
        org_uuid,
        user_id,
    }): Path<OrgUserId>,
    headers: OrgAdminHeaders,
    data: Json<Upcase<EditUserData>>,
) -> ApiResult<()> {
    let data: EditUserData = data.0.data;

    let mut user_to_edit = match UserOrganization::get(&conn, user_id, org_uuid).await? {
        Some(user) => user,
        None => err!("The specified user isn't member of the organization"),
    };

    if data.r#type != user_to_edit.atype
        && (user_to_edit.atype >= UserOrgType::Admin || data.r#type >= UserOrgType::Admin)
        && headers.org_user_type != UserOrgType::Owner
    {
        err!("Only Owners can grant and remove Admin or Owner privileges")
    }

    if user_to_edit.atype == UserOrgType::Owner && headers.org_user_type != UserOrgType::Owner {
        err!("Only Owners can edit Owner users")
    }

    if user_to_edit.atype == UserOrgType::Owner && data.r#type != UserOrgType::Owner && user_to_edit.status() == UserOrgStatus::Confirmed {
        // Removing owner permission, check that there is at least one other confirmed owner
        if UserOrganization::count_confirmed_by_org_and_type(&conn, org_uuid, UserOrgType::Owner).await? <= 1 {
            err!("Can't delete the last owner")
        }
    }

    // This check is also done at accept_invite(), _confirm_invite, _activate_user(), edit_user(), admin::update_user_org_type
    // It returns different error messages per function.
    if data.r#type < UserOrgType::Admin {
        match OrganizationPolicy::is_user_allowed(&conn, user_to_edit.user_uuid, org_uuid, true).await? {
            Ok(_) => {}
            Err(OrgPolicyErr::TwoFactorMissing) => {
                err!("You cannot modify this user to this type because it has no two-step login method activated");
            }
            Err(OrgPolicyErr::SingleOrgEnforced) => {
                err!("You cannot modify this user to this type because it is a member of an organization which forbids it");
            }
        }
    }

    user_to_edit.access_all = data.access_all;
    user_to_edit.atype = data.r#type;

    // Delete all the odd collections
    //TODO: fix this N+1
    for c in CollectionUser::find_by_organization_and_user_uuid(&conn, org_uuid, user_to_edit.user_uuid).await? {
        c.delete(&conn).await?;
    }

    // If no accessAll, add the collections received
    if !data.access_all {
        for col in data.collections.iter().flatten() {
            match Collection::find_by_uuid_and_org(&conn, col.id, org_uuid).await? {
                None => err!("Collection not found in Organization"),
                Some(collection) => {
                    CollectionUser {
                        user_uuid: user_to_edit.user_uuid,
                        collection_uuid: collection.uuid,
                        read_only: col.read_only,
                        hide_passwords: col.hide_passwords,
                    }
                    .save(&conn)
                    .await?;
                }
            }
        }
    }

    GroupUser::delete_all_by_user(&conn, user_to_edit.user_uuid, user_to_edit.organization_uuid).await?;

    for group in data.groups.iter().flatten() {
        let group_entry = GroupUser::new(*group, user_to_edit.user_uuid);
        group_entry.save(&conn).await?;
    }

    log_event(EventType::OrganizationUserUpdated, user_to_edit.user_uuid, org_uuid, headers.user.uuid, headers.device.atype, Utc::now(), headers.ip, &conn)
        .await?;

    user_to_edit.save(&conn).await?;

    conn.commit().await?;
    Ok(())
}

async fn bulk_delete_user(Path(org_uuid): Path<Uuid>, headers: OrgAdminHeaders, data: Json<Upcase<OrgBulkIds>>) -> ApiResult<Json<Value>> {
    let data: OrgBulkIds = data.0.data;

    let mut bulk_response = Vec::new();
    let conn = DB.get().await?;
    //TODO: N+1 query
    for user_id in data.ids {
        let err_msg = match _delete_user(
            Path(OrgUserId {
                org_uuid,
                user_id,
            }),
            &headers,
            &conn,
        )
        .await
        {
            Ok(_) => String::new(),
            Err(e) => format!("{e}"),
        };

        bulk_response.push(json!(
            {
                "Object": "OrganizationBulkConfirmResponseModel",
                "Id": user_id,
                "Error": err_msg
            }
        ))
    }

    Ok(Json(json!({
        "Data": bulk_response,
        "Object": "list",
        "ContinuationToken": null
    })))
}

async fn delete_user(path: Path<OrgUserId>, headers: OrgAdminHeaders) -> ApiResult<()> {
    let conn = DB.get().await?;
    _delete_user(path, &headers, &conn).await
}

async fn _delete_user(
    Path(OrgUserId {
        org_uuid,
        user_id,
    }): Path<OrgUserId>,
    headers: &OrgAdminHeaders,
    conn: &Conn,
) -> ApiResult<()> {
    let user_to_delete = match UserOrganization::get(&conn, user_id, org_uuid).await? {
        Some(user) => user,
        None => err!("User to delete isn't member of the organization"),
    };

    if user_to_delete.atype != UserOrgType::User && headers.org_user_type != UserOrgType::Owner {
        err!("Only Owners can delete Admins or Owners")
    }

    if user_to_delete.atype == UserOrgType::Owner && user_to_delete.status() == UserOrgStatus::Confirmed {
        // Removing owner, check that there is at least one other confirmed owner
        if UserOrganization::count_confirmed_by_org_and_type(&conn, org_uuid, UserOrgType::Owner).await? <= 1 {
            err!("Can't delete the last owner")
        }
    }

    log_event(EventType::OrganizationUserRemoved, user_to_delete.user_uuid, org_uuid, headers.user.uuid, headers.device.atype, Utc::now(), headers.ip, &conn)
        .await?;

    if let Some(user) = User::get(&conn, user_to_delete.user_uuid).await? {
        ws_users().send_user_update(UpdateType::SyncOrgKeys, &conn, &user).await?;
    }

    user_to_delete.delete(&conn).await
}

async fn bulk_public_keys(conn: AutoTxn, Path(org_uuid): Path<Uuid>, _headers: OrgAdminHeaders, data: Json<Upcase<OrgBulkIds>>) -> ApiResult<Json<Value>> {
    let data: OrgBulkIds = data.0.data;

    let mut bulk_response = Vec::new();
    // Check all received UserOrg UUID's and find the matching User to retreive the public-key.
    // If the user does not exists, just ignore it, and do not return any information regarding that UserOrg UUID.
    // The web-vault will then ignore that user for the folowing steps.
    //TODO: N+1 query
    for user_id in data.ids {
        match UserOrganization::get(&conn, user_id, org_uuid).await? {
            Some(user_org) => match User::get(&conn, user_org.user_uuid).await? {
                Some(user) => bulk_response.push(json!(
                    {
                        "Object": "organizationUserpublic_keyResponseModel",
                        "Id": user_id,
                        "UserId": user.uuid,
                        "Key": user.public_key
                    }
                )),
                None => debug!("User doesn't exist"),
            },
            None => debug!("UserOrg doesn't exist"),
        }
    }

    conn.commit().await?;

    Ok(Json(json!({
        "Data": bulk_response,
        "Object": "list",
        "ContinuationToken": null
    })))
}

use super::ciphers::update_cipher_from_data;
use super::ciphers::CipherData;

#[derive(Deserialize)]
#[serde(rename_all = "PascalCase")]
struct ImportData {
    ciphers: Vec<CipherData>,
    collections: Vec<NewCollectionData>,
    collection_relationships: Vec<RelationsData>,
}

#[derive(Deserialize)]
#[serde(rename_all = "PascalCase")]
struct RelationsData {
    // Cipher index
    key: usize,
    // Collection index
    value: usize,
}

async fn post_org_import(conn: AutoTxn, Query(query): Query<OrgIdData>, headers: OrgAdminHeaders, data: Json<Upcase<ImportData>>) -> ApiResult<()> {
    let data: ImportData = data.0.data;
    let org_uuid = query.organization_id;

    // Validate the import before continuing
    // Bitwarden does not process the import if there is one item invalid.
    // Since we check for the size of the encrypted note length, we need to do that here to pre-validate it.
    // TODO: See if we can optimize the whole cipher adding/importing and prevent duplicate code and checks.
    Cipher::validate_notes(&data.ciphers)?;

    let mut collections = Vec::new();
    for coll in data.collections {
        let collection = Collection::new(org_uuid, coll.name);
        if collection.save(&conn).await.is_err() {
            collections.push(Err(Error::new("Failed to create Collection", "Failed to create Collection")));
        } else {
            collections.push(Ok(collection));
        }
    }

    // Read the relations between collections and ciphers
    let mut relations = Vec::new();
    for relation in data.collection_relationships {
        relations.push((relation.key, relation.value));
    }

    let headers: Headers = headers.into();

    let mut ciphers = Vec::new();
    for cipher_data in data.ciphers {
        let mut cipher = Cipher::new(cipher_data.r#type, cipher_data.name.clone());
        update_cipher_from_data(&mut cipher, cipher_data, &headers, false, &conn, UpdateType::None).await.ok();
        ciphers.push(cipher);
    }

    // Assign the collections
    for (cipher_index, coll_index) in relations {
        let cipher_id = ciphers[cipher_index].uuid;
        let coll = &collections[coll_index];
        let coll_id = match coll {
            Ok(coll) => coll.uuid,
            Err(_) => err!("Failed to assign to collection"),
        };

        CollectionCipher::save(&conn, cipher_id, coll_id).await?;
    }

    conn.commit().await?;
    Ok(())
}

async fn list_policies(Path(org_uuid): Path<Uuid>, _headers: OrgAdminHeaders) -> ApiResult<Json<Value>> {
    let conn = DB.get().await?;
    let policies = OrganizationPolicy::find_by_org(&conn, org_uuid).await?;
    let policies_json: Vec<Value> = policies.iter().map(OrganizationPolicy::to_json).collect();

    Ok(Json(json!({
        "Data": policies_json,
        "Object": "list",
        "ContinuationToken": null
    })))
}

#[derive(Deserialize)]
struct PoliciesToken {
    token: String,
}

async fn list_policies_token(Path(org_uuid): Path<Uuid>, Query(token): Query<PoliciesToken>) -> ApiResult<Json<Value>> {
    let invite = crate::auth::decode_invite(&token.token)?;

    let invite_org_uuid = match invite.org_uuid {
        Some(invite_org_uuid) => invite_org_uuid,
        None => err!("Invalid token"),
    };

    if invite_org_uuid != org_uuid {
        err!("Token doesn't match request organization");
    }
    let conn = DB.get().await?;

    // TODO: We receive the invite token as ?token=<>, validate it contains the org id
    let policies = OrganizationPolicy::find_by_org(&conn, org_uuid).await?;
    let policies_json: Vec<Value> = policies.iter().map(OrganizationPolicy::to_json).collect();

    Ok(Json(json!({
        "Data": policies_json,
        "Object": "list",
        "ContinuationToken": null
    })))
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct UserIdQuery {
    user_id: Uuid,
}

//TODO: check authorization on this endpoint
async fn list_policies_invited_user(_headers: OrgAdminHeaders, Path(org_uuid): Path<Uuid>, Query(user_id): Query<UserIdQuery>) -> ApiResult<Json<Value>> {
    let conn = DB.get().await?;

    if UserOrganization::get(&conn, user_id.user_id, org_uuid).await?.is_none() {
        err!("user not in organization");
    }

    let policies = OrganizationPolicy::find_by_org(&conn, org_uuid).await?;
    let policies_json: Vec<Value> = policies.iter().map(OrganizationPolicy::to_json).collect();

    Ok(Json(json!({
        "Data": policies_json,
        "Object": "list",
        "ContinuationToken": null
    })))
}

#[derive(Deserialize)]
struct OrgPolicy {
    org_uuid: Uuid,
    pol_type: OrgPolicyType,
}

async fn get_policy(
    Path(OrgPolicy {
        org_uuid,
        pol_type,
    }): Path<OrgPolicy>,
    _headers: OrgAdminHeaders,
) -> ApiResult<Json<Value>> {
    let conn = DB.get().await?;

    let policy = match OrganizationPolicy::find_by_org_and_type(&conn, org_uuid, pol_type).await? {
        Some(p) => p,
        None => OrganizationPolicy::new(org_uuid, pol_type, Value::Null),
    };

    Ok(Json(policy.to_json()))
}

#[derive(Deserialize)]
struct PolicyData {
    enabled: bool,
    // r#type: i32,
    data: Option<Value>,
}

async fn put_policy(
    conn: AutoTxn,
    Path(OrgPolicy {
        org_uuid,
        pol_type,
    }): Path<OrgPolicy>,
    headers: OrgAdminHeaders,
    Json(data): Json<PolicyData>,
) -> ApiResult<Json<Value>> {

    // When enabling the TwoFactorAuthentication policy, remove this org's members that do have 2FA
    if pol_type == OrgPolicyType::TwoFactorAuthentication && data.enabled {
        for member in UserOrganization::find_by_org(&conn, org_uuid).await?.into_iter() {
            let user_twofactor_disabled = TwoFactor::find_by_user_official(&conn, member.user_uuid).await?.is_empty();

            // Policy only applies to non-Owner/non-Admin members who have accepted joining the org
            // Invited users still need to accept the invite and will get an error when they try to accept the invite.
            if user_twofactor_disabled && member.atype < UserOrgType::Admin && member.status() != UserOrgStatus::Invited {
                if CONFIG.mail_enabled() {
                    let org = Organization::get(&conn, member.organization_uuid).await?.unwrap();
                    let user = User::get(&conn, member.user_uuid).await?.unwrap();

                    mail::send_2fa_removed_from_org(&user.email, &org.name).await?;
                }

                log_event(
                    EventType::OrganizationUserRemoved,
                    member.user_uuid,
                    org_uuid,
                    headers.user.uuid,
                    headers.device.atype,
                    Utc::now(),
                    headers.ip,
                    &conn,
                )
                .await?;

                member.delete(&conn).await?;
            }
        }
    }

    // When enabling the SingleOrg policy, remove this org's members that are members of other orgs
    if pol_type == OrgPolicyType::SingleOrg && data.enabled {
        for member in UserOrganization::find_by_org(&conn, org_uuid).await?.into_iter() {
            // Policy only applies to non-Owner/non-Admin members who have accepted joining the org
            // Exclude invited and revoked users when checking for this policy.
            // Those users will not be allowed to accept or be activated because of the policy checks done there.
            // We check if the count is larger then 1, because it includes this organization also.
            if member.atype < UserOrgType::Admin
                && member.status() != UserOrgStatus::Invited
                && UserOrganization::count_accepted_and_confirmed_by_user(&conn, member.user_uuid).await? > 1
            {
                if CONFIG.mail_enabled() {
                    let Some(org) = Organization::get(&conn, member.organization_uuid).await? else {
                        err!("org missing");
                    };
                    let Some(user) = User::get(&conn, member.user_uuid).await? else {
                        err!("user missing");
                    };

                    mail::send_single_org_removed_from_org(&user.email, &org.name).await?;
                }

                log_event(
                    EventType::OrganizationUserRemoved,
                    member.user_uuid,
                    org_uuid,
                    headers.user.uuid,
                    headers.device.atype,
                    Utc::now(),
                    headers.ip,
                    &conn,
                )
                .await?;

                member.delete(&conn).await?;
            }
        }
    }

    let mut policy = match OrganizationPolicy::find_by_org_and_type(&conn, org_uuid, pol_type).await? {
        Some(p) => p,
        None => OrganizationPolicy::new(org_uuid, pol_type, Value::Object(Default::default())),
    };

    policy.enabled = data.enabled;
    policy.data = serde_json::to_value(data.data)?;
    policy.save(&conn).await?;

    log_event(EventType::PolicyUpdated, policy.uuid, org_uuid, headers.user.uuid, headers.device.atype, Utc::now(), headers.ip, &conn).await?;

    conn.commit().await?;

    Ok(Json(policy.to_json()))
}

#[allow(unused_variables)]
async fn get_organization_tax(Path(org_uuid): Path<Uuid>, _headers: Headers) -> Json<Value> {
    // Prevent a 404 error, which also causes Javascript errors.
    // Upstream sends "Only allowed when not self hosted." As an error message.
    // If we do the same it will also output this to the log, which is overkill.
    // An empty list/data also works fine.
    Json(_empty_data_json())
}

async fn get_plans() -> Json<Value> {
    // Respond with a minimal json just enough to allow the creation of an new organization.
    Json(json!({
        "Object": "list",
        "Data": [{
            "Object": "plan",
            "Type": 0,
            "Product": 0,
            "Name": "Free",
            "NameLocalizationKey": "planNameFree",
            "DescriptionLocalizationKey": "planDescFree"
        }],
        "ContinuationToken": null
    }))
}

async fn get_plans_tax_rates(_headers: Headers) -> Json<Value> {
    // Prevent a 404 error, which also causes Javascript errors.
    Json(_empty_data_json())
}

fn _empty_data_json() -> Value {
    json!({
        "Object": "list",
        "Data": [],
        "ContinuationToken": null
    })
}

#[derive(Deserialize, Debug)]
#[allow(dead_code)]
#[serde(rename_all = "PascalCase")]
struct OrgImportGroupData {
    name: String,        // "GroupName"
    external_id: String, // "cn=GroupName,ou=Groups,dc=example,dc=com"
    users: Vec<String>,  // ["uid=user,ou=People,dc=example,dc=com"]
}

#[derive(Deserialize, Debug)]
#[serde(rename_all = "PascalCase")]
struct OrgImportUserData {
    email: String, // "user@maildomain.net"
    #[allow(dead_code)]
    external_id: String, // "uid=user,ou=People,dc=example,dc=com"
    deleted: bool,
}

#[derive(Deserialize, Debug)]
#[serde(rename_all = "PascalCase")]
struct OrgImportData {
    #[allow(dead_code)]
    groups: Vec<OrgImportGroupData>,
    overwrite_existing: bool,
    users: Vec<OrgImportUserData>,
}

//TODO: remove all data.0.data stuff
async fn import(conn: AutoTxn, Path(org_uuid): Path<Uuid>, headers: OrgAdminHeaders, data: Json<Upcase<OrgImportData>>) -> ApiResult<()> {
    let data = data.0.data;

    // TODO: Currently we aren't storing the externalId's anywhere, so we also don't have a way
    // to differentiate between auto-imported users and manually added ones.
    // This means that this endpoint can end up removing users that were added manually by an admin,
    // as opposed to upstream which only removes auto-imported users.

    for user_data in &data.users {
        if user_data.deleted {
            // If user is marked for deletion and it exists, delete it
            if let Some(user_org) = UserOrganization::find_by_email_and_organization(&conn, &user_data.email, org_uuid).await? {
                //TODO: all these log events should be in the model
                log_event(
                    EventType::OrganizationUserRemoved,
                    user_org.user_uuid,
                    org_uuid,
                    headers.user.uuid,
                    headers.device.atype,
                    Utc::now(),
                    headers.ip,
                    &conn,
                )
                .await?;

                user_org.delete(&conn).await?;
            }

        // If user is not part of the organization, but it exists
        } else if UserOrganization::find_by_email_and_organization(&conn, &user_data.email, org_uuid).await?.is_none() {
            if let Some(user) = User::find_by_email(&conn, &user_data.email).await? {
                let user_org_status = if CONFIG.mail_enabled() {
                    UserOrgStatus::Invited
                } else {
                    UserOrgStatus::Accepted // Automatically mark user as accepted if no email invites
                };

                let mut new_org_user = UserOrganization::new(user.uuid, org_uuid);
                new_org_user.access_all = false;
                new_org_user.atype = UserOrgType::User;
                new_org_user.status = user_org_status;

                new_org_user.save(&conn).await?;

                log_event(
                    EventType::OrganizationUserInvited,
                    new_org_user.user_uuid,
                    org_uuid,
                    headers.user.uuid,
                    headers.device.atype,
                    Utc::now(),
                    headers.ip,
                    &conn,
                )
                .await?;

                if CONFIG.mail_enabled() {
                    let org_name = match Organization::get(&conn, org_uuid).await? {
                        Some(org) => org.name,
                        None => err!("Error looking up organization"),
                    };

                    mail::send_invite(&user_data.email, user.uuid, Some(org_uuid), &org_name, Some(headers.user.email.clone())).await?;
                }
            }
        }
    }

    // If this flag is enabled, any user that isn't provided in the Users list will be removed (by default they will be kept unless they have Deleted == true)
    if data.overwrite_existing {
        for user_org in UserOrganization::find_by_org_and_type(&conn, org_uuid, UserOrgType::User).await? {
            if let Some(user_email) = User::get(&conn, user_org.user_uuid).await?.map(|u| u.email) {
                if !data.users.iter().any(|u| u.email == user_email) {
                    log_event(
                        EventType::OrganizationUserRemoved,
                        user_org.user_uuid,
                        org_uuid,
                        headers.user.uuid,
                        headers.device.atype,
                        Utc::now(),
                        headers.ip,
                        &conn,
                    )
                    .await?;

                    user_org.delete(&conn).await?;
                }
            }
        }
    }

    conn.commit().await?;

    Ok(())
}

async fn bulk_revoke_organization_user(conn: AutoTxn, Path(org_uuid): Path<Uuid>, headers: OrgAdminHeaders, data: Json<Upcase<Value>>) -> ApiResult<Json<Value>> {
    let data = data.0.data;

    let mut bulk_response = Vec::new();
    match data["Ids"].as_array() {
        Some(org_users) => {
            for user_id in org_users {
                let Ok(user_id) = Uuid::from_str(user_id.as_str().unwrap_or_default()) else {
                    err!("Malformed user_id");
                };

                let err_msg = match _revoke_organization_user(org_uuid, user_id, &headers, &conn).await {
                    Ok(_) => String::new(),
                    Err(e @ ApiError::Other(_)) => return Err(e),
                    Err(e) => format!("{e:?}"),
                };

                bulk_response.push(json!(
                    {
                        "Object": "OrganizationUserBulkResponseModel",
                        "Id": user_id,
                        "Error": err_msg
                    }
                ));
            }
        }
        None => error!("No users to revoke"),
    }

    conn.commit().await?;

    Ok(Json(json!({
        "Data": bulk_response,
        "Object": "list",
        "ContinuationToken": null
    })))
}

async fn revoke_organization_user(
    Path(OrgUserId {
        org_uuid,
        user_id,
    }): Path<OrgUserId>,
    headers: OrgAdminHeaders,
) -> ApiResult<()> {
    let conn = DB.get().await?;
    _revoke_organization_user(org_uuid, user_id, &headers, &conn).await
}

//TODO: there are a ton of places where identation can be squished
async fn _revoke_organization_user(org_uuid: Uuid, user_id: Uuid, headers: &OrgAdminHeaders, conn: &Conn) -> ApiResult<()> {
    match UserOrganization::get(conn, user_id, org_uuid).await? {
        Some(mut user_org) if !user_org.revoked => {
            if user_org.user_uuid == headers.user.uuid {
                err!("You cannot revoke yourself")
            }
            if user_org.atype == UserOrgType::Owner && headers.org_user_type != UserOrgType::Owner {
                err!("Only owners can revoke other owners")
            }
            if user_org.atype == UserOrgType::Owner && UserOrganization::count_confirmed_by_org_and_type(conn, org_uuid, UserOrgType::Owner).await? <= 1 {
                err!("Organization must have at least one confirmed owner")
            }

            user_org.revoke();
            user_org.save(conn).await?;

            log_event(EventType::OrganizationUserRevoked, user_org.user_uuid, org_uuid, headers.user.uuid, headers.device.atype, Utc::now(), headers.ip, conn)
                .await?;
        }
        Some(_) => err!("User is already revoked"),
        None => err!("User not found in organization"),
    }
    Ok(())
}

async fn bulk_restore_organization_user(conn: AutoTxn, Path(org_uuid): Path<Uuid>, headers: OrgAdminHeaders, data: Json<Upcase<Value>>) -> ApiResult<Json<Value>> {
    let data = data.0.data;

    let mut bulk_response = Vec::new();
    match data["Ids"].as_array() {
        Some(org_users) => {
            for user_id in org_users {
                let Ok(user_id) = Uuid::from_str(user_id.as_str().unwrap_or_default()) else {
                    err!("Malformed user_id");
                };

                let err_msg = match _restore_organization_user(org_uuid, user_id, &headers, &conn).await {
                    Ok(_) => String::new(),
                    Err(e @ ApiError::Other(_)) => return Err(e),
                    Err(e) => format!("{e:?}"),
                };

                bulk_response.push(json!(
                    {
                        "Object": "OrganizationUserBulkResponseModel",
                        "Id": user_id,
                        "Error": err_msg
                    }
                ));
            }
        }
        None => error!("No users to restore"),
    }

    conn.commit().await?;

    Ok(Json(json!({
        "Data": bulk_response,
        "Object": "list",
        "ContinuationToken": null
    })))
}

async fn restore_organization_user(
    Path(OrgUserId {
        org_uuid,
        user_id,
    }): Path<OrgUserId>,
    headers: OrgAdminHeaders,
) -> ApiResult<()> {
    let conn = DB.get().await?;
    _restore_organization_user(org_uuid, user_id, &headers, &conn).await
}

async fn _restore_organization_user(org_uuid: Uuid, user_id: Uuid, headers: &OrgAdminHeaders, conn: &Conn) -> ApiResult<()> {
    match UserOrganization::get(conn, user_id, org_uuid).await? {
        Some(mut user_org) if user_org.revoked => {
            if user_org.user_uuid == headers.user.uuid {
                err!("You cannot restore yourself")
            }
            if user_org.atype == UserOrgType::Owner && headers.org_user_type != UserOrgType::Owner {
                err!("Only owners can restore other owners")
            }

            // This check is also done at accept_invite(), _confirm_invite, _activate_user(), edit_user(), admin::update_user_org_type
            // It returns different error messages per function.
            if user_org.atype < UserOrgType::Admin {
                match OrganizationPolicy::is_user_allowed(conn, user_org.user_uuid, org_uuid, false).await? {
                    Ok(_) => {}
                    Err(OrgPolicyErr::TwoFactorMissing) => {
                        err!("You cannot restore this user because it has no two-step login method activated");
                    }
                    Err(OrgPolicyErr::SingleOrgEnforced) => {
                        err!("You cannot restore this user because it is a member of an organization which forbids it");
                    }
                }
            }

            user_org.restore();
            user_org.save(conn).await?;

            log_event(EventType::OrganizationUserRestored, user_org.user_uuid, org_uuid, headers.user.uuid, headers.device.atype, Utc::now(), headers.ip, conn)
                .await?;
        }
        Some(_) => err!("User is already active"),
        None => err!("User not found in organization"),
    }
    Ok(())
}

async fn get_groups(Path(org_uuid): Path<Uuid>, _headers: ManagerHeadersLoose) -> ApiResult<Json<Value>> {
    let groups: Vec<Value> = if CONFIG.advanced.org_groups_enabled {
        let conn = DB.get().await?;

        let groups = Group::find_by_organization(&conn, org_uuid).await?;
        let mut groups_json = Vec::with_capacity(groups.len());
        for g in groups {
            groups_json.push(g.to_json_details(&conn).await?);
        }
        groups_json
    } else {
        // The Bitwarden clients seem to call this API regardless of whether groups are enabled,
        // so just act as if there are no groups.
        Vec::with_capacity(0)
    };

    Ok(Json(json!({
        "Data": groups,
        "Object": "list",
        "ContinuationToken": null,
    })))
}

#[derive(Deserialize)]
#[serde(rename_all = "PascalCase")]
struct GroupRequest {
    name: String,
    access_all: Option<bool>,
    external_id: Option<String>,
    collections: Vec<SelectionReadOnly>,
    users: Vec<Uuid>,
}

impl GroupRequest {
    pub fn to_group(&self, organizations_uuid: Uuid) -> ApiResult<Group> {
        match self.access_all {
            Some(access_all_value) => Ok(Group::new(organizations_uuid, self.name.clone(), access_all_value, self.external_id.clone())),
            _ => err!("Could not convert GroupRequest to Group, because access_all has no value!"),
        }
    }

    pub fn update_group(&self, mut group: Group) -> ApiResult<Group> {
        match self.access_all {
            Some(access_all_value) => {
                group.name = self.name.clone();
                group.access_all = access_all_value;
                group.set_external_id(self.external_id.clone());

                Ok(group)
            }
            _ => err!("Could not update group, because access_all has no value!"),
        }
    }
}

#[derive(Deserialize, Serialize)]
#[serde(rename_all = "PascalCase")]
struct SelectionReadOnly {
    id: Uuid,
    read_only: bool,
    hide_passwords: bool,
}

impl SelectionReadOnly {
    pub fn to_collection_group(&self, group_uuid: Uuid) -> CollectionGroup {
        CollectionGroup::new(self.id, group_uuid, self.read_only, self.hide_passwords)
    }

    pub fn to_collection_group_details_read_only(collection_group: &CollectionGroup) -> SelectionReadOnly {
        SelectionReadOnly {
            id: collection_group.group_uuid,
            read_only: collection_group.read_only,
            hide_passwords: collection_group.hide_passwords,
        }
    }

    pub fn to_collection_user_details_read_only(collection_user: &CollectionUser) -> SelectionReadOnly {
        SelectionReadOnly {
            id: collection_user.user_uuid,
            read_only: collection_user.read_only,
            hide_passwords: collection_user.hide_passwords,
        }
    }

    pub fn to_json(&self) -> Value {
        json!(self)
    }
}

async fn post_groups(conn: AutoTxn, Path(org_uuid): Path<Uuid>, headers: OrgAdminHeaders, data: Json<Upcase<GroupRequest>>) -> ApiResult<Json<Value>> {
    if !CONFIG.advanced.org_groups_enabled {
        err!("Group support is disabled");
    }

    let group_request = data.0.data;
    let group = group_request.to_group(org_uuid)?;

    let group_uuid = group.uuid;
    let out = add_update_group(group, group_request.collections, group_request.users, org_uuid, &headers, &conn).await?;

    log_event(EventType::GroupCreated, group_uuid, org_uuid, headers.user.uuid, headers.device.atype, Utc::now(), headers.ip, &conn).await?;

    conn.commit().await?;
    Ok(out)
}

#[derive(Deserialize)]
struct OrgGroupId {
    org_uuid: Uuid,
    group_id: Uuid,
}

#[derive(Deserialize)]
struct OrgGroupUserId {
    org_uuid: Uuid,
    group_id: Uuid,
    user_id: Uuid,
}

async fn put_group(
    conn: AutoTxn,
    Path(OrgGroupId {
        org_uuid,
        group_id,
    }): Path<OrgGroupId>,
    headers: OrgAdminHeaders,
    data: Json<Upcase<GroupRequest>>,
) -> ApiResult<Json<Value>> {
    if !CONFIG.advanced.org_groups_enabled {
        err!("Group support is disabled");
    }

    let group = match Group::get(&conn, group_id).await? {
        Some(group) => group,
        None => err!("Group not found"),
    };

    let group_request = data.0.data;
    let updated_group = group_request.update_group(group)?;

    CollectionGroup::delete_all_by_group(&conn, group_id).await?;
    GroupUser::delete_all_by_group(&conn, group_id).await?;

    log_event(EventType::GroupUpdated, updated_group.uuid, org_uuid, headers.user.uuid, headers.device.atype, Utc::now(), headers.ip, &conn).await?;

    let out = add_update_group(updated_group, group_request.collections, group_request.users, org_uuid, &headers, &conn).await?;
    conn.commit().await?;
    Ok(out)
}

async fn add_update_group(
    mut group: Group,
    collections: Vec<SelectionReadOnly>,
    users: Vec<Uuid>,
    org_uuid: Uuid,
    headers: &OrgAdminHeaders,
    conn: &Conn,
) -> ApiResult<Json<Value>> {
    group.save(conn).await?;

    for selection_read_only_request in collections {
        let collection_group = selection_read_only_request.to_collection_group(group.uuid.clone());
        collection_group.save(conn).await?;
    }

    for assigned_user_id in users {
        let user_entry = GroupUser::new(group.uuid.clone(), assigned_user_id.clone());
        user_entry.save(conn).await?;

        log_event(
            EventType::OrganizationUserUpdatedGroups,
            assigned_user_id,
            org_uuid,
            headers.user.uuid.clone(),
            headers.device.atype,
            Utc::now(),
            headers.ip,
            conn,
        )
        .await?;
    }

    Ok(Json(json!({
        "Id": group.uuid,
        "OrganizationId": group.organization_uuid,
        "Name": group.name,
        "AccessAll": group.access_all,
        "ExternalId": group.external_id
    })))
}

async fn get_group_details(
    Path(OrgGroupId {
        org_uuid,
        group_id,
    }): Path<OrgGroupId>,
    _headers: OrgAdminHeaders,
) -> ApiResult<Json<Value>> {
    if !CONFIG.advanced.org_groups_enabled {
        err!("Group support is disabled");
    }
    let conn = DB.get().await?;

    let group = match Group::get_for_org(&conn, group_id, org_uuid).await? {
        Some(group) => group,
        _ => err!("Group could not be found!"),
    };

    Ok(Json(group.to_json_details(&conn).await?))
}

async fn _delete_group(org_uuid: Uuid, group_id: Uuid, headers: &OrgAdminHeaders, conn: &Conn) -> ApiResult<()> {
    let group = match Group::get_for_org(&conn, group_id, org_uuid).await? {
        Some(group) => group,
        _ => err!("Group not found"),
    };

    log_event(EventType::GroupDeleted, group.uuid, org_uuid, headers.user.uuid.clone(), headers.device.atype, Utc::now(), headers.ip, &conn).await?;

    group.delete(&conn).await
}

async fn delete_group(
    Path(OrgGroupId {
        org_uuid,
        group_id,
    }): Path<OrgGroupId>,
    headers: OrgAdminHeaders,
) -> ApiResult<()> {
    if !CONFIG.advanced.org_groups_enabled {
        err!("Group support is disabled");
    }
    let conn = DB.get().await?;
    _delete_group(org_uuid, group_id, &headers, &conn).await?;
    Ok(())
}

async fn bulk_delete_groups(conn: AutoTxn, Path(org_uuid): Path<Uuid>, headers: OrgAdminHeaders, data: Json<Upcase<OrgBulkIds>>) -> ApiResult<()> {
    if !CONFIG.advanced.org_groups_enabled {
        err!("Group support is disabled");
    }

    let data: OrgBulkIds = data.0.data;

    for group_id in data.ids {
        _delete_group(org_uuid, group_id, &headers, &conn).await?
    }
    conn.commit().await?;
    Ok(())
}

async fn get_group(
    Path(OrgGroupId {
        org_uuid,
        group_id,
    }): Path<OrgGroupId>,
    _headers: OrgAdminHeaders,
) -> ApiResult<Json<Value>> {
    if !CONFIG.advanced.org_groups_enabled {
        err!("Group support is disabled");
    }
    let conn = DB.get().await?;

    let group = match Group::get_for_org(&conn, group_id, org_uuid).await? {
        Some(group) => group,
        _ => err!("Group not found"),
    };

    Ok(Json(group.to_json()))
}

async fn get_group_users(
    Path(OrgGroupId {
        org_uuid,
        group_id,
    }): Path<OrgGroupId>,
    _headers: OrgAdminHeaders,
) -> ApiResult<Json<Value>> {
    if !CONFIG.advanced.org_groups_enabled {
        err!("Group support is disabled");
    }
    let conn = DB.get().await?;

    match Group::get_for_org(&conn, group_id, org_uuid).await? {
        Some(_) => { /* Do nothing */ }
        _ => err!("Group could not be found!"),
    };

    let group_users: Vec<Uuid> = GroupUser::find_by_group(&conn, group_id).await?.iter().map(|entry| entry.user_uuid).collect();

    Ok(Json(json!(group_users)))
}

async fn put_group_users(
    conn: AutoTxn,
    Path(OrgGroupId {
        org_uuid,
        group_id,
    }): Path<OrgGroupId>,
    headers: OrgAdminHeaders,
    data: Json<Vec<Uuid>>,
) -> ApiResult<()> {
    if !CONFIG.advanced.org_groups_enabled {
        err!("Group support is disabled");
    }

    match Group::get_for_org(&conn, group_id, org_uuid).await? {
        Some(_) => { /* Do nothing */ }
        _ => err!("Group could not be found!"),
    };

    GroupUser::delete_all_by_group(&conn, group_id).await?;

    let assigned_user_ids = data.0;
    for assigned_user_id in assigned_user_ids {
        let user_entry = GroupUser::new(group_id, assigned_user_id);
        user_entry.save(&conn).await?;

        log_event(
            EventType::OrganizationUserUpdatedGroups,
            assigned_user_id,
            org_uuid,
            headers.user.uuid.clone(),
            headers.device.atype,
            Utc::now(),
            headers.ip,
            &conn,
        )
        .await?;
    }

    conn.commit().await?;

    Ok(())
}

async fn get_user_groups(
    Path(OrgUserId {
        org_uuid,
        user_id,
    }): Path<OrgUserId>,
    _headers: OrgAdminHeaders,
) -> ApiResult<Json<Value>> {
    if !CONFIG.advanced.org_groups_enabled {
        err!("Group support is disabled");
    }
    let conn = DB.get().await?;

    match UserOrganization::get(&conn, user_id, org_uuid).await? {
        Some(_) => { /* Do nothing */ }
        _ => err!("User could not be found!"),
    };

    let user_groups: Vec<Uuid> = GroupUser::find_by_user(&conn, user_id, org_uuid).await?.iter().map(|entry| entry.group_uuid).collect();

    Ok(Json(json!(user_groups)))
}

#[derive(Deserialize)]
#[serde(rename_all = "PascalCase")]
struct OrganizationUserUpdateGroupsRequest {
    group_ids: Vec<Uuid>,
}

async fn put_user_groups(
    conn: AutoTxn,
    Path(OrgUserId {
        org_uuid,
        user_id,
    }): Path<OrgUserId>,
    headers: OrgAdminHeaders,
    data: Json<Upcase<OrganizationUserUpdateGroupsRequest>>,
) -> ApiResult<()> {
    if !CONFIG.advanced.org_groups_enabled {
        err!("Group support is disabled");
    }

    match UserOrganization::get(&conn, user_id, org_uuid).await? {
        Some(_) => { /* Do nothing */ }
        _ => err!("User could not be found!"),
    };

    let known_groups = Group::find_by_organization(&conn, org_uuid).await?.into_iter().map(|x| x.uuid).collect::<HashSet<Uuid>>();

    for id in &data.0.data.group_ids {
        if !known_groups.contains(id) {
            err!("referenced unknown group");
        }
    }

    GroupUser::delete_all_by_user(&conn, user_id, org_uuid).await?;

    let assigned_group_ids = data.0.data;
    for assigned_group_id in assigned_group_ids.group_ids {
        let group_user = GroupUser::new(assigned_group_id, user_id);
        group_user.save(&conn).await?;
    }

    log_event(EventType::OrganizationUserUpdatedGroups, user_id, org_uuid, headers.user.uuid, headers.device.atype, Utc::now(), headers.ip, &conn).await?;

    conn.commit().await?;

    Ok(())
}

async fn delete_group_user(
    Path(OrgGroupUserId {
        org_uuid,
        group_id,
        user_id,
    }): Path<OrgGroupUserId>,
    headers: OrgAdminHeaders,
) -> ApiResult<()> {
    if !CONFIG.advanced.org_groups_enabled {
        err!("Group support is disabled");
    }
    let conn = DB.get().await?;

    match UserOrganization::get(&conn, user_id, org_uuid).await? {
        Some(_) => { /* Do nothing */ }
        _ => err!("User could not be found!"),
    };

    match Group::get_for_org(&conn, group_id, org_uuid).await? {
        Some(_) => { /* Do nothing */ }
        _ => err!("Group could not be found!"),
    };

    log_event(EventType::OrganizationUserUpdatedGroups, user_id, org_uuid, headers.user.uuid, headers.device.atype, Utc::now(), headers.ip, &conn).await?;

    GroupUser::delete_by_group_uuid_and_user_id(&conn, group_id, user_id).await
}

#[derive(Deserialize)]
#[serde(rename_all = "PascalCase")]
struct OrganizationUserResetPasswordEnrollmentRequest {
    reset_password_key: Option<String>,
}

#[derive(Deserialize)]
#[serde(rename_all = "PascalCase")]
struct OrganizationUserResetPasswordRequest {
    new_master_password_hash: String,
    key: String,
}

async fn get_organization_keys(Path(org_uuid): Path<Uuid>) -> ApiResult<Json<Value>> {
    let conn = DB.get().await?;

    let org = match Organization::get(&conn, org_uuid).await? {
        Some(organization) => organization,
        None => err!("Organization not found"),
    };

    Ok(Json(json!({
        "Object": "organizationKeys",
        "public_key": org.public_key,
        "PrivateKey": org.private_key,
    })))
}

async fn put_reset_password(
    Path(OrgUserId {
        org_uuid,
        user_id,
    }): Path<OrgUserId>,
    headers: OrgAdminHeaders,
    data: Json<Upcase<OrganizationUserResetPasswordRequest>>,
) -> ApiResult<()> {
    let conn = DB.get().await?;

    let org = match Organization::get(&conn, org_uuid).await? {
        Some(org) => org,
        None => err!("Required organization not found"),
    };

    let org_user = match UserOrganization::get(&conn, user_id, org.uuid).await? {
        Some(user) => user,
        None => err!("User to reset isn't member of required organization"),
    };

    let user = match User::get(&conn, org_user.user_uuid).await? {
        Some(user) => user,
        None => err!("User not found"),
    };

    check_reset_password_applicable_and_permissions(org_uuid, user_id, &headers, &conn).await?;

    if org_user.reset_password_key.is_none() {
        err!("Password reset not or not correctly enrolled");
    }
    if org_user.status() != UserOrgStatus::Confirmed {
        err!("Organization user must be confirmed for password reset functionality");
    }

    // Sending email before resetting password to ensure working email configuration and the resulting
    // user notification. Also this might add some protection against security flaws and misuse
    if let Err(e) = mail::send_admin_reset_password(&user.email, &user.name, &org.name).await {
        err!(format!("Error sending user reset password email: {e:#?}"));
    }

    let reset_request = data.0.data;

    let mut user = user;
    user.set_password(reset_request.new_master_password_hash.as_str(), Some(reset_request.key), true, None);
    user.save(&conn).await?;

    ws_users().send_logout(&user, &conn, None).await?;

    log_event(EventType::OrganizationUserAdminResetPassword, user_id, org_uuid, headers.user.uuid, headers.device.atype, Utc::now(), headers.ip, &conn).await?;

    Ok(())
}

async fn get_reset_password_details(
    Path(OrgUserId {
        org_uuid,
        user_id,
    }): Path<OrgUserId>,
    headers: OrgAdminHeaders,
) -> ApiResult<Json<Value>> {
    let conn = DB.get().await?;

    let org = match Organization::get(&conn, org_uuid).await? {
        Some(org) => org,
        None => err!("Required organization not found"),
    };

    let org_user = match UserOrganization::get(&conn, user_id, org_uuid).await? {
        Some(user) => user,
        None => err!("User to reset isn't member of required organization"),
    };

    let user = match User::get(&conn, org_user.user_uuid).await? {
        Some(user) => user,
        None => err!("User not found"),
    };

    check_reset_password_applicable_and_permissions(org_uuid, user_id, &headers, &conn).await?;

    // https://github.com/bitwarden/server/blob/3b50ccb9f804efaacdc46bed5b60e5b28eddefcf/src/Api/Models/Response/Organizations/OrganizationUserResponseModel.cs#L111
    Ok(Json(json!({
        "Object": "organizationUserResetPasswordDetails",
        "Kdf":user.client_kdf_type,
        "KdfIterations":user.client_kdf_iter,
        "KdfMemory":user.client_kdf_memory,
        "KdfParallelism":user.client_kdf_parallelism,
        "reset_password_key":org_user.reset_password_key,
        "encrypted_private_key":org.private_key,

    })))
}

async fn check_reset_password_applicable_and_permissions(org_uuid: Uuid, user_id: Uuid, headers: &OrgAdminHeaders, conn: &Conn) -> ApiResult<()> {
    check_reset_password_applicable(org_uuid, conn).await?;

    let target_user = match UserOrganization::get(conn, user_id, org_uuid).await? {
        Some(user) => user,
        None => err!("Reset target user not found"),
    };

    // Resetting user must be higher/equal to user to reset
    match headers.org_user_type {
        UserOrgType::Owner => Ok(()),
        UserOrgType::Admin if target_user.atype <= UserOrgType::Admin => Ok(()),
        _ => err!("No permission to reset this user's password"),
    }
}

async fn check_reset_password_applicable(org_uuid: Uuid, conn: &Conn) -> ApiResult<()> {
    if !CONFIG.mail_enabled() {
        err!("Password reset is not supported on an email-disabled instance.");
    }

    let policy = match OrganizationPolicy::find_by_org_and_type(conn, org_uuid, OrgPolicyType::ResetPassword).await? {
        Some(p) => p,
        None => err!("Policy not found"),
    };

    if !policy.enabled {
        err!("Reset password policy not enabled");
    }

    Ok(())
}

async fn put_reset_password_enrollment(
    Path(OrgUserId {
        org_uuid,
        user_id,
    }): Path<OrgUserId>,
    headers: Headers,
    data: Json<Upcase<OrganizationUserResetPasswordEnrollmentRequest>>,
) -> ApiResult<()> {
    let conn = DB.get().await?;

    if user_id != headers.user.uuid {
        err!("path and token mismatch for uuid");
    }

    let mut org_user = match UserOrganization::get(&conn, headers.user.uuid, org_uuid).await? {
        Some(u) => u,
        None => err!("User to enroll isn't member of required organization"),
    };

    check_reset_password_applicable(org_uuid, &conn).await?;

    let reset_request = data.0.data;

    if reset_request.reset_password_key.is_none() && OrganizationPolicy::org_is_reset_password_auto_enroll(&conn, org_uuid).await? {
        err!("Reset password can't be withdrawed due to an enterprise policy");
    }

    org_user.reset_password_key = reset_request.reset_password_key;
    org_user.save(&conn).await?;

    let log_id = if org_user.reset_password_key.is_some() {
        EventType::OrganizationUserResetPasswordEnroll
    } else {
        EventType::OrganizationUserResetPasswordWithdraw
    };

    log_event(log_id, user_id, org_uuid, headers.user.uuid, headers.device.atype, Utc::now(), headers.ip, &conn).await?;

    Ok(())
}

// This is a new function active since the v2022.9.x clients.
// It combines the previous two calls done before.
// We call those two functions here and combine them our selfs.
//
// NOTE: It seems clients can't handle uppercase-first keys!!
//       We need to convert all keys so they have the first character to be a lowercase.
//       Else the export will be just an empty JSON file.
async fn get_org_export(Path(org_uuid): Path<Uuid>, headers: OrgAdminHeaders) -> ApiResult<Json<Value>> {
    use semver::{Version, VersionReq};

    // Since version v2023.1.0 the format of the export is different.
    // Also, this endpoint was created since v2022.9.0.
    // Therefore, we will check for any version smaller then v2023.1.0 and return a different response.
    // If we can't determine the version, we will use the latest default v2023.1.0 and higher.
    // https://github.com/bitwarden/server/blob/9ca93381ce416454734418c3a9f99ab49747f1b6/src/Api/Controllers/OrganizationExportController.cs#L44
    let use_list_response_model = if let Some(client_version) = headers.client_version {
        let ver_match = VersionReq::parse("<2023.1.0").unwrap();
        let client_version = Version::parse(&client_version).unwrap();
        ver_match.matches(&client_version)
    } else {
        false
    };
    let conn = DB.get().await?;

    // Also both main keys here need to be lowercase, else the export will fail.
    Ok(if use_list_response_model {
        // Backwards compatible pre v2023.1.0 response
        Json(json!({
            "collections": {
                "data": convert_json_key_lcase_first(_get_org_collections(&conn, org_uuid).await?),
                "object": "list",
                "continuationToken": null,
            },
            "ciphers": {
                "data": convert_json_key_lcase_first(_get_org_details(org_uuid, headers.user.uuid, &conn).await?),
                "object": "list",
                "continuationToken": null,
            }
        }))
    } else {
        // v2023.1.0 and newer response
        Json(json!({
            "collections": convert_json_key_lcase_first(_get_org_collections(&conn, org_uuid).await?),
            "ciphers": convert_json_key_lcase_first(_get_org_details(org_uuid, headers.user.uuid, &conn).await?),
        }))
    })
}

async fn _api_key(org_uuid: Uuid, rotate: bool, headers: OrgAdminHeaders, data: PasswordData) -> ApiResult<Json<Value>> {
    let user = headers.user;

    // Validate the admin users password
    if !user.check_valid_password(&data.master_password_hash) {
        err!("Invalid password")
    }
    let conn = DB.get().await?;

    let org_api_key = match OrganizationApiKey::find_by_org_uuid(&conn, org_uuid).await? {
        Some(mut org_api_key) => {
            if rotate {
                org_api_key.api_key = crate::crypto::generate_api_key();
                org_api_key.revision_date = chrono::Utc::now();
                org_api_key.save(&conn).await.expect("Error rotating organization API Key");
            }
            org_api_key
        }
        None => {
            let api_key = crate::crypto::generate_api_key();
            let new_org_api_key = OrganizationApiKey::new(org_uuid, api_key);
            new_org_api_key.save(&conn).await.expect("Error creating organization API Key");
            new_org_api_key
        }
    };

    Ok(Json(json!({
      "ApiKey": org_api_key.api_key,
      "RevisionDate": crate::util::format_date(&org_api_key.revision_date),
      "Object": "apiKey",
    })))
}

async fn api_key(Path(org_uuid): Path<Uuid>, headers: OrgAdminHeaders, data: Json<Upcase<PasswordData>>) -> ApiResult<Json<Value>> {
    _api_key(org_uuid, false, headers, data.0.data).await
}

async fn rotate_api_key(Path(org_uuid): Path<Uuid>, headers: OrgAdminHeaders, data: Json<Upcase<PasswordData>>) -> ApiResult<Json<Value>> {
    _api_key(org_uuid, true, headers, data.0.data).await
}
