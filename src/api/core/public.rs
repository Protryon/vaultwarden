use axol::prelude::*;
use chrono::Utc;
use log::warn;
use serde::Deserialize;
use uuid::Uuid;

use std::collections::HashSet;

use crate::{
    auth,
    db::{Group, GroupUser, Invitation, Organization, OrganizationApiKey, User, UserOrgStatus, UserOrgType, UserOrganization, DB},
    mail,
    util::AutoTxn,
    CONFIG,
};

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct OrgImportGroupData {
    name: String,
    external_id: String,
    member_external_ds: Vec<String>,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct OrgImportUserData {
    email: String,
    external_id: String,
    deleted: bool,
}

#[derive(Deserialize)]
#[allow(non_snake_case)]
pub struct OrgImportData {
    groups: Vec<OrgImportGroupData>,
    members: Vec<OrgImportUserData>,
    overwrite_existing: bool,
    // LargeImport: bool, // For now this will not be used, upstream uses this to prevent syncs of more then 2000 users or groups without the flag set.
}

pub async fn ldap_import(conn: AutoTxn, token: PublicToken, data: Json<OrgImportData>) -> Result<()> {
    // Most of the logic for this function can be found here
    // https://github.com/bitwarden/server/blob/fd892b2ff4547648a276734fb2b14a8abae2c6f5/src/Core/Services/Implementations/OrganizationService.cs#L1797

    let org_id = token.0;
    let data = data.0;

    for user_data in &data.members {
        if user_data.deleted {
            // If user is marked for deletion and it exists, revoke it
            if let Some(mut user_org) = UserOrganization::find_by_email_and_organization(&conn, &user_data.email, org_id).await? {
                user_org.revoke();
                user_org.save(&conn).await?;
            }

        // If user is part of the organization, restore it
        } else if let Some(mut user_org) = UserOrganization::find_by_email_and_organization(&conn, &user_data.email, org_id).await? {
            if user_org.revoked {
                user_org.restore();
                user_org.save(&conn).await?;
            }
        } else {
            // If user is not part of the organization
            let user = match User::find_by_email(&conn, &user_data.email).await? {
                Some(user) => user, // exists in vaultwarden
                None => {
                    // doesn't exist in vaultwarden
                    let mut new_user = User::new(user_data.email.clone());
                    new_user.set_external_id(Some(user_data.external_id.clone()));
                    new_user.save(&conn).await?;

                    if !CONFIG.mail_enabled() {
                        let invitation = Invitation::new(&new_user.email);
                        invitation.save(&conn).await?;
                    }
                    new_user
                }
            };
            let user_org_status = if CONFIG.mail_enabled() {
                UserOrgStatus::Invited
            } else {
                UserOrgStatus::Accepted // Automatically mark user as accepted if no email invites
            };

            let mut new_org_user = UserOrganization::new(user.uuid.clone(), org_id.clone());
            new_org_user.access_all = false;
            new_org_user.atype = UserOrgType::User;
            new_org_user.status = user_org_status;

            new_org_user.save(&conn).await?;

            if CONFIG.mail_enabled() {
                let (org_name, org_email) = match Organization::get(&conn, org_id).await? {
                    Some(org) => (org.name, org.billing_email),
                    None => err!("Error looking up organization"),
                };

                mail::send_invite(&user_data.email, user.uuid, Some(org_id), &org_name, Some(org_email)).await?;
            }
        }
    }

    if CONFIG.advanced.org_groups_enabled {
        for group_data in &data.groups {
            let group_uuid = match Group::find_by_external_id(&conn, &group_data.external_id).await? {
                Some(group) => group.uuid,
                None => {
                    let mut group = Group::new(org_id, group_data.name.clone(), false, Some(group_data.external_id.clone()));
                    group.save(&conn).await?;
                    group.uuid
                }
            };

            GroupUser::delete_all_by_group(&conn, group_uuid).await?;

            for ext_id in &group_data.member_external_ds {
                if let Some(user) = User::find_by_external_id(&conn, ext_id).await? {
                    if let Some(user_org) = UserOrganization::get(&conn, user.uuid, org_id).await? {
                        let group_user = GroupUser::new(group_uuid.clone(), user_org.user_uuid);
                        group_user.save(&conn).await?;
                    }
                }
            }
        }
    } else {
        warn!("Group support is disabled, groups will not be imported!");
    }

    // If this flag is enabled, any user that isn't provided in the Users list will be removed (by default they will be kept unless they have Deleted == true)
    if data.overwrite_existing {
        // Generate a HashSet to quickly verify if a member is listed or not.
        let sync_members: HashSet<String> = data.members.into_iter().map(|m| m.external_id).collect();
        for user_org in UserOrganization::find_by_org(&conn, org_id).await? {
            let Some(user_external_id) = User::get(&conn, user_org.user_uuid).await?.and_then(|u| u.external_id) else {
                continue;
            };
            if sync_members.contains(&user_external_id) {
                continue;
            }
            if user_org.atype == UserOrgType::Owner && user_org.status == UserOrgStatus::Confirmed {
                // Removing owner, check that there is at least one other confirmed owner
                if UserOrganization::count_confirmed_by_org_and_type(&conn, org_id, UserOrgType::Owner).await? <= 1 {
                    warn!("Can't delete the last owner");
                    continue;
                }
            }
            user_org.delete(&conn).await?;
        }
    }

    Ok(())
}

pub struct PublicToken(Uuid);

#[async_trait::async_trait]
impl<'a> FromRequestParts<'a> for PublicToken {
    async fn from_request_parts(req: RequestPartsRef<'a>) -> Result<Self> {
        let access_token =
            req.headers.get("authorization").and_then(|x| x.strip_prefix("Bearer ")).ok_or(Error::unauthorized("missing authorization header"))?;
        let claims = match auth::decode_api_org(access_token) {
            Ok(claims) => claims,
            Err(_) => err!("Invalid claim"),
        };
        // Check if time is between claims.nbf and claims.exp
        let time_now = Utc::now().timestamp();
        if time_now < claims.nbf {
            err!("Token issued in the future");
        }
        if time_now > claims.exp {
            err!("Token expired");
        }
        // Check if claims.iss is host|claims.scope[0]

        let complete_host = format!("{}|{}", CONFIG.settings.public.host_str().unwrap(), claims.scope[0]);
        if complete_host != claims.iss {
            err!("Token not issued by this server");
        }

        // Check if claims.sub is org_api_key.uuid
        // Check if claims.client_sub is org_api_key.org_uuid
        let conn = DB.get().await.ise()?;
        let org_uuid = match claims.client_id.strip_prefix("organization.").and_then(|x| Uuid::parse_str(x).ok()) {
            Some(uuid) => uuid,
            None => err!("Malformed client_id"),
        };
        let org_api_key = match OrganizationApiKey::find_by_org_uuid(&conn, org_uuid).await? {
            Some(org_api_key) => org_api_key,
            None => err!("Invalid client_id"),
        };
        if org_api_key.organization_uuid != claims.client_sub {
            err!("Token not issued for this org");
        }
        if org_api_key.uuid != claims.sub {
            err!("Token not issued for this client");
        }

        Ok(PublicToken(claims.client_sub))
    }
}
