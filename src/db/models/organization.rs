use axol::{Error, ErrorExt, Result};
use chrono::{DateTime, Utc};
use serde_json::{json, Value};
use serde_repr::{Deserialize_repr, Serialize_repr};
use std::{cmp::Ordering, str::FromStr};
use tokio_postgres::Row;
use uuid::Uuid;

use super::{CollectionUser, GroupUser, OrgPolicyType, TwoFactor, User};
use crate::{db::Conn, CONFIG};

#[derive(Debug)]
pub struct Organization {
    pub uuid: Uuid,
    pub name: String,
    pub billing_email: String,
    pub private_key: Option<String>,
    pub public_key: Option<String>,
}

#[derive(Debug)]
pub struct UserOrganization {
    pub user_uuid: Uuid,
    pub organization_uuid: Uuid,

    pub access_all: bool,
    pub akey: String,
    pub status: UserOrgStatus,
    pub atype: UserOrgType,
    pub reset_password_key: Option<String>,
    pub revoked: bool,
}

#[derive(Debug)]
pub struct OrganizationApiKey {
    pub uuid: Uuid,
    pub organization_uuid: Uuid,
    pub atype: i32,
    pub api_key: String,
    pub revision_date: DateTime<Utc>,
}

// https://github.com/bitwarden/server/blob/b86a04cef9f1e1b82cf18e49fc94e017c641130c/src/Core/Enums/OrganizationUserStatusType.cs
#[derive(Debug, Clone, Copy, PartialEq, Eq, strum::FromRepr, PartialOrd, Ord)]
#[repr(i32)]
pub enum UserOrgStatus {
    Revoked = -1,
    Invited = 0,
    Accepted = 1,
    Confirmed = 2,
    Unknown = i32::MAX,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, strum::FromRepr, Serialize_repr, Deserialize_repr)]
#[repr(i32)]
pub enum UserOrgType {
    Owner = 0,
    Admin = 1,
    User = 2,
    Manager = 3,
    Unknown = i32::MAX,
}

impl From<Row> for Organization {
    fn from(row: Row) -> Self {
        Self {
            uuid: row.get(0),
            name: row.get(1),
            billing_email: row.get(2),
            private_key: row.get(3),
            public_key: row.get(4),
        }
    }
}

impl From<Row> for OrganizationApiKey {
    fn from(row: Row) -> Self {
        Self {
            uuid: row.get(0),
            organization_uuid: row.get(1),
            atype: row.get(2),
            api_key: row.get(3),
            revision_date: row.get(4),
        }
    }
}

impl From<Row> for UserOrganization {
    fn from(row: Row) -> Self {
        Self {
            user_uuid: row.get(0),
            organization_uuid: row.get(1),
            access_all: row.get(2),
            akey: row.get(3),
            status: UserOrgStatus::from_repr(row.get(4)).unwrap_or(UserOrgStatus::Unknown),
            atype: UserOrgType::from_repr(row.get(5)).unwrap_or(UserOrgType::Unknown),
            reset_password_key: row.get(6),
            revoked: row.get(7),
        }
    }
}

impl FromStr for UserOrgType {
    fn from_str(s: &str) -> Result<Self, &'static str> {
        match s {
            "0" | "Owner" => Ok(UserOrgType::Owner),
            "1" | "Admin" => Ok(UserOrgType::Admin),
            "2" | "User" => Ok(UserOrgType::User),
            "3" | "Manager" => Ok(UserOrgType::Manager),
            _ => Err("invalid org type"),
        }
    }

    type Err = &'static str;
}

impl Ord for UserOrgType {
    fn cmp(&self, other: &UserOrgType) -> Ordering {
        // For easy comparison, map each variant to an access level (where 0 is lowest).
        static ACCESS_LEVEL: [i32; 4] = [
            3, // Owner
            2, // Admin
            0, // User
            1, // Manager
        ];
        ACCESS_LEVEL[*self as usize].cmp(&ACCESS_LEVEL[*other as usize])
    }
}

impl PartialOrd for UserOrgType {
    fn partial_cmp(&self, other: &UserOrgType) -> Option<Ordering> {
        Some(self.cmp(other))
    }
}

impl Organization {
    pub fn new(name: String, billing_email: String, private_key: Option<String>, public_key: Option<String>) -> Self {
        Self {
            uuid: Uuid::new_v4(),
            name,
            billing_email,
            private_key,
            public_key,
        }
    }
    // https://github.com/bitwarden/server/blob/13d1e74d6960cf0d042620b72d85bf583a4236f7/src/Api/Models/Response/Organizations/OrganizationResponseModel.cs
    pub fn to_json(&self) -> Value {
        json!({
            "id": self.uuid,
            "identifier": null, // Not supported
            "name": self.name,
            "seats": 10, // The value doesn't matter, we don't check server-side
            // "MaxAutoscaleSeats": null, // The value doesn't matter, we don't check server-side
            "maxCollections": 10, // The value doesn't matter, we don't check server-side
            "maxStorageGb": 10, // The value doesn't matter, we don't check server-side
            "use2fa": true,
            "useDirectory": false, // Is supported, but this value isn't checked anywhere (yet)
            "useEvents": CONFIG.settings.org_events_enabled,
            "useGroups": CONFIG.advanced.org_groups_enabled,
            "useTotp": true,
            "usePolicies": true,
            // "UseScim": false, // Not supported (Not AGPLv3 Licensed)
            "useSso": CONFIG.sso.is_some(),
            // "UseKeyConnector": false, // Not supported
            "selfHost": true,
            "useApi": true,
            "hasPublicAndPrivateKeys": self.private_key.is_some() && self.public_key.is_some(),
            "useResetPassword": CONFIG.mail_enabled(),

            "businessName": null,
            "businessAddress1": null,
            "businessAddress2": null,
            "businessAddress3": null,
            "businessCountry": null,
            "businessTaxNumber": null,

            "billingEmail": self.billing_email,
            "plan": "TeamsAnnually",
            "planType": 5, // TeamsAnnually plan
            "usersGetPremium": true,
            "object": "organization",
        })
    }
}

impl UserOrganization {
    pub fn new(user_uuid: Uuid, organization_uuid: Uuid) -> Self {
        Self {
            user_uuid,
            organization_uuid,

            access_all: false,
            akey: String::new(),
            status: UserOrgStatus::Accepted,
            atype: UserOrgType::User,
            reset_password_key: None,
            revoked: false,
        }
    }

    pub fn status(&self) -> UserOrgStatus {
        if self.revoked {
            UserOrgStatus::Revoked
        } else {
            self.status
        }
    }

    pub fn restore(&mut self) {
        self.revoked = false;
    }

    pub fn revoke(&mut self) {
        self.revoked = true;
    }
}

impl OrganizationApiKey {
    pub fn new(organization_uuid: Uuid, api_key: String) -> Self {
        Self {
            uuid: Uuid::new_v4(),

            organization_uuid,
            atype: 0, // Type 0 is the default and only type we support currently
            api_key,
            revision_date: Utc::now(),
        }
    }

    pub fn check_valid_api_key(&self, api_key: &str) -> bool {
        crate::crypto::ct_eq(&self.api_key, api_key)
    }
}
/*
   uuid UUID NOT NULL PRIMARY KEY,
   name TEXT NOT NULL,
   billing_email TEXT NOT NULL,
   private_key TEXT,
   public_key TEXT

*/
impl Organization {
    pub async fn save(&self, conn: &Conn) -> Result<()> {
        if !email_address::EmailAddress::is_valid(self.billing_email.trim()) {
            err!(format!("BillingEmail {} is not a valid email address", self.billing_email.trim()))
        }

        conn.execute(
            r"INSERT INTO organizations (uuid, name, billing_email, private_key, public_key) VALUES ($1, $2, $3, $4, $5) ON CONFLICT (uuid) DO UPDATE
        SET
        name = EXCLUDED.name,
        billing_email = EXCLUDED.billing_email,
        private_key = EXCLUDED.private_key,
        public_key = EXCLUDED.public_key",
            &[&self.uuid, &self.name, &self.billing_email, &self.private_key, &self.public_key],
        )
        .await
        .ise()?;
        Self::flag_revision(conn, self.uuid).await.ise()?;
        Ok(())
    }

    pub async fn flag_revision(conn: &Conn, uuid: Uuid) -> Result<()> {
        conn.execute(
            r"UPDATE user_revisions u SET updated_at = now() FROM user_organizations uo WHERE uo.organization_uuid = $1 AND uo.user_uuid = u.uuid",
            &[&uuid],
        )
        .await
        .ise()?;
        Ok(())
    }

    pub async fn delete(&self, conn: &Conn) -> Result<()> {
        Self::flag_revision(conn, self.uuid).await.ise()?;
        conn.execute(r"DELETE FROM organizations WHERE uuid = $1", &[&self.uuid]).await.ise()?;
        Ok(())
    }

    pub async fn get(conn: &Conn, uuid: Uuid) -> Result<Option<Self>> {
        Ok(conn.query_opt(r"SELECT * FROM organizations WHERE uuid = $1", &[&uuid]).await.ise()?.map(Into::into))
    }

    pub async fn find_by_name(conn: &Conn, name: &str) -> Result<Option<Self>> {
        Ok(conn.query_opt(r"SELECT * FROM organizations WHERE name = $1 LIMIT 1", &[&name]).await.ise()?.map(Into::into))
    }

    pub async fn get_all(conn: &Conn) -> Result<Vec<Self>> {
        Ok(conn.query(r"SELECT * FROM organizations", &[]).await.ise()?.into_iter().map(|x| x.into()).collect())
    }
}

impl UserOrganization {
    pub async fn to_json(&self, conn: &Conn) -> Result<Value> {
        let org = Organization::get(conn, self.organization_uuid).await.ise()?.ok_or(Error::NotFound)?;

        // https://github.com/bitwarden/server/blob/13d1e74d6960cf0d042620b72d85bf583a4236f7/src/Api/Models/Response/ProfileOrganizationResponseModel.cs
        Ok(json!({
            "id": self.organization_uuid,
            "identifier": null, // Not supported
            "name": org.name,
            "seats": 10, // The value doesn't matter, we don't check server-side
            "maxCollections": 10, // The value doesn't matter, we don't check server-side
            "usersGetPremium": true,
            "use2fa": true,
            "useDirectory": false, // Is supported, but this value isn't checked anywhere (yet)
            "useEvents": CONFIG.settings.org_events_enabled,
            "useGroups": CONFIG.advanced.org_groups_enabled,
            "useTotp": true,
            "useScim": false, // Not supported (Not AGPLv3 Licensed)
            "usePolicies": true,
            "useApi": true,
            "selfHost": true,
            "hasPublicAndPrivateKeys": org.private_key.is_some() && org.public_key.is_some(),
            "resetPasswordEnrolled": self.reset_password_key.is_some(),
            "useResetPassword": CONFIG.mail_enabled(),
            "ssoBound": false, // Not supported
            "useSso": CONFIG.sso.is_some(),

            "useKeyConnector": false,
            "useSecretsManager": false,
            "usePasswordManager": true,
            "useCustomPermissions": false,
            "useActivateAutofillPolicy": false,

            "organizationUserId": self.user_uuid,
            "providerId": null,
            "providerName": null,
            "providerType": null,
            "familySponsorshipFriendlyName": null,
            "familySponsorshipAvailable": false,
            "planProductType": 3,
            "productTierType": 3, // Enterprise tier
            "keyConnectorEnabled": false,
            "keyConnectorUrl": null,
            "familySponsorshipLastSyncDate": null,
            "familySponsorshipValidUntil": null,
            "familySponsorshipToDelete": null,
            "accessSecretsManager": false,
            "limitCollectionCreationDeletion": false, // This should be set to true only when we can handle roles like createNewCollections
            "allowAdminAccessToAllCollectionItems": true,
            "flexibleCollections": false,

            "permissions": {
                // TODO: Add support for Custom User Roles
                // See: https://bitwarden.com/help/article/user-types-access-control/#custom-role
                "accessEventLogs": false,
                "accessImportExport": false,
                "accessReports": false,
                "createNewCollections": false,
                "editAnyCollection": false,
                "deleteAnyCollection": false,
                "editAssignedCollections": false,
                "deleteAssignedCollections": false,
                "manageGroups": false,
                "managePolicies": false,
                "manageSso": false, // Not supported
                "manageUsers": false,
                "manageResetPassword": false,
                "manageScim": false // Not supported (Not AGPLv3 Licensed)
            },

            "maxStorageGb": 10, // The value doesn't matter, we don't check server-side

            // These are per user
            "userId": self.user_uuid,
            "key": self.akey,
            "status": self.status as i32,
            "type": self.atype as i32,
            "enabled": true,

            "object": "profileOrganization",
        }))
    }

    pub async fn to_json_user_details(&self, conn: &Conn, include_collections: bool, include_groups: bool) -> Result<Value> {
        let user = User::get(conn, self.user_uuid).await.ise()?.ok_or(Error::NotFound)?;

        // Because BitWarden want the status to be -1 for revoked users we need to catch that here.
        // We subtract/add a number so we can restore/activate the user to it's previous state again.
        let status = self.status() as i32;

        let twofactor_enabled = !TwoFactor::find_by_user_official(conn, user.uuid).await.ise()?.is_empty();

        let groups: Vec<Uuid> = if include_groups && CONFIG.advanced.org_groups_enabled {
            GroupUser::find_by_user(conn, self.user_uuid, self.organization_uuid).await.ise()?.iter().map(|gu| gu.group_uuid).collect()
        } else {
            // The Bitwarden clients seem to call this API regardless of whether groups are enabled,
            // so just act as if there are no groups.
            Vec::with_capacity(0)
        };

        let collections: Vec<Value> = if include_collections {
            CollectionUser::find_by_organization_and_user_uuid(conn, self.organization_uuid, self.user_uuid)
                .await
                .ise()?
                .iter()
                .map(|cu| {
                    json!({
                        "Id": cu.collection_uuid,
                        "ReadOnly": cu.read_only,
                        "HidePasswords": cu.hide_passwords,
                    })
                })
                .collect()
        } else {
            Vec::with_capacity(0)
        };

        Ok(json!({
            "id": self.user_uuid,
            "userId": self.user_uuid,
            "name": user.name,
            "email": user.email,
            "groups": groups,
            "collections": collections,

            "status": status,
            "type": self.atype as i32,
            "accessAll": self.access_all,
            "twoFactorEnabled": twofactor_enabled,
            "resetPasswordEnrolled":self.reset_password_key.is_some(),

            "object": "organizationUserUserDetails",
        }))
    }

    pub fn to_json_user_access_restrictions(&self, col_user: &CollectionUser) -> Value {
        json!({
            "id": self.user_uuid,
            "readOnly": col_user.read_only,
            "hidePasswords": col_user.hide_passwords,
        })
    }

    #[allow(dead_code)]
    pub async fn to_json_details(&self, conn: &Conn) -> Result<Value> {
        let coll_uuids = if self.access_all {
            vec![] // If we have complete access, no need to fill the array
        } else {
            let collections = CollectionUser::find_by_organization_and_user_uuid(conn, self.organization_uuid, self.user_uuid).await.ise()?;
            collections
                .iter()
                .map(|c| {
                    json!({
                        "id": c.collection_uuid,
                        "readOnly": c.read_only,
                        "hidePasswords": c.hide_passwords,
                    })
                })
                .collect()
        };

        // Because BitWarden want the status to be -1 for revoked users we need to catch that here.
        // We subtract/add a number so we can restore/activate the user to it's previouse state again.
        let status = self.status() as i32;

        Ok(json!({
            "id": self.user_uuid,
            "userId": self.user_uuid,

            "status": status,
            "type": self.atype as i32,
            "accessAll": self.access_all,
            "collections": coll_uuids,

            "object": "organizationUserDetails",
        }))
    }

    pub async fn save(&self, conn: &Conn) -> Result<()> {
        conn.execute(r"INSERT INTO user_organizations (user_uuid, organization_uuid, access_all, akey, status, atype, reset_password_key, revoked) VALUES ($1, $2, $3, $4, $5, $6, $7, $8) ON CONFLICT (user_uuid, organization_uuid) DO UPDATE
        SET
        access_all = EXCLUDED.access_all,
        akey = EXCLUDED.akey,
        status = EXCLUDED.status,
        atype = EXCLUDED.atype,
        reset_password_key = EXCLUDED.reset_password_key,
        revoked = EXCLUDED.revoked", &[
            &self.user_uuid,
            &self.organization_uuid,
            &self.access_all,
            &self.akey,
            &(self.status as i32),
            &(self.atype as i32),
            &self.reset_password_key,
            &self.revoked,
        ]).await.ise()?;
        User::flag_revision_for(conn, self.user_uuid).await.ise()?;
        Ok(())
    }

    pub async fn delete(&self, conn: &Conn) -> Result<()> {
        conn.execute(r"DELETE FROM user_organizations WHERE user_uuid = $1 AND organization_uuid = $2", &[&self.user_uuid, &self.organization_uuid])
            .await
            .ise()?;
        User::flag_revision_for(conn, self.user_uuid).await.ise()?;
        Ok(())
    }

    pub async fn find_by_email_and_organization(conn: &Conn, email: &str, organization_uuid: Uuid) -> Result<Option<Self>> {
        Ok(conn
            .query_opt(
                r"SELECT * FROM user_organizations uo INNER JOIN users u ON u.uuid == uo.user_id WHERE uo.organization_uuid = $1 AND u.email ILIKE $2",
                &[&organization_uuid, &email],
            )
            .await
            .ise()?
            .map(Into::into))
    }

    pub fn has_status(&self, status: UserOrgStatus) -> bool {
        self.status() == status
    }

    pub fn has_full_access(&self) -> bool {
        (self.access_all || self.atype >= UserOrgType::Admin) && self.has_status(UserOrgStatus::Confirmed)
    }

    pub async fn get(conn: &Conn, user_uuid: Uuid, organization_uuid: Uuid) -> Result<Option<Self>> {
        Ok(conn
            .query_opt(r"SELECT * FROM user_organizations WHERE user_uuid = $1 AND organization_uuid = $2", &[&user_uuid, &organization_uuid])
            .await
            .ise()?
            .map(Into::into))
    }

    pub async fn find_by_user_with_status(conn: &Conn, user_uuid: Uuid, status: UserOrgStatus) -> Result<Vec<Self>> {
        Ok(conn
            .query(r"SELECT * FROM user_organizations WHERE user_uuid = $1 AND status = $2", &[&user_uuid, &(status as i32)])
            .await
            .ise()?
            .into_iter()
            .map(|x| x.into())
            .collect())
    }

    pub async fn find_by_user(conn: &Conn, user_uuid: Uuid) -> Result<Vec<Self>> {
        Ok(conn.query(r"SELECT * FROM user_organizations WHERE user_uuid = $1", &[&user_uuid]).await.ise()?.into_iter().map(|x| x.into()).collect())
    }

    pub async fn count_accepted_and_confirmed_by_user(conn: &Conn, user_uuid: Uuid) -> Result<i64> {
        Ok(conn
            .query_one(
                r"SELECT COUNT(1) FROM user_organizations WHERE user_uuid = $1 AND (status = $2 OR status = $3)",
                &[&user_uuid, &(UserOrgStatus::Accepted as i32), &(UserOrgStatus::Confirmed as i32)],
            )
            .await
            .ise()?
            .get(0))
    }

    pub async fn find_by_org(conn: &Conn, organization_uuid: Uuid) -> Result<Vec<Self>> {
        Ok(conn
            .query(r"SELECT * FROM user_organizations WHERE organization_uuid = $1", &[&organization_uuid])
            .await
            .ise()?
            .into_iter()
            .map(|x| x.into())
            .collect())
    }

    pub async fn count_by_org(conn: &Conn, organization_uuid: Uuid) -> Result<i64> {
        Ok(conn.query_one(r"SELECT COUNT(1) FROM user_organizations WHERE organization_uuid = $1", &[&organization_uuid]).await.ise()?.get(0))
    }

    pub async fn find_by_org_and_type(conn: &Conn, organization_uuid: Uuid, atype: UserOrgType) -> Result<Vec<Self>> {
        Ok(conn
            .query(r"SELECT * FROM user_organizations WHERE organization_uuid = $1 AND atype = $2", &[&organization_uuid, &(atype as i32)])
            .await
            .ise()?
            .into_iter()
            .map(|x| x.into())
            .collect())
    }

    pub async fn count_confirmed_by_org_and_type(conn: &Conn, organization_uuid: Uuid, atype: UserOrgType) -> Result<i64> {
        Ok(conn
            .query_one(
                r"SELECT COUNT(1) FROM user_organizations WHERE organization_uuid = $1 AND atype = $2 AND status = $3",
                &[&organization_uuid, &(atype as i32), &(UserOrgStatus::Confirmed as i32)],
            )
            .await
            .ise()?
            .get(0))
    }

    pub async fn get_organization_uuid_by_user(conn: &Conn, user_uuid: Uuid) -> Result<Vec<Uuid>> {
        Ok(conn
            .query(r"SELECT organization_uuid FROM user_organizations WHERE user_uuid = $1", &[&user_uuid])
            .await
            .ise()?
            .into_iter()
            .map(|x| x.get(0))
            .collect())
    }

    pub async fn find_by_user_and_policy(conn: &Conn, user_uuid: Uuid, policy_type: OrgPolicyType) -> Result<Vec<Self>> {
        Ok(conn
            .query(
                r"SELECT uo.*
        FROM user_organizations uo
        INNER JOIN organization_policies op ON op.organization_uuid = uo.organization_uuid AND uo.user_uuid = $1 AND op.atype = $2 AND op.enabled
        WHERE uo.status = 2
        ",
                &[&user_uuid, &(policy_type as i32)],
            )
            .await
            .ise()?
            .into_iter()
            .map(|x| x.into())
            .collect())
    }

    pub async fn user_has_ge_admin_access_to_cipher(conn: &Conn, user_uuid: Uuid, cipher_uuid: Uuid) -> Result<bool> {
        Ok(conn
            .query_one(
                r"
            SELECT count(1)
            FROM user_organizations uo
            INNER JOIN ciphers c ON c.uuid = $2 AND c.organization_uuid = uo.organization_uuid
            WHERE uo.user_uuid = $1 AND (uo.atype = $3 OR uo.atype = $4)
        ",
                &[&user_uuid, &cipher_uuid, &(UserOrgType::Owner as i32), &(UserOrgType::Admin as i32)],
            )
            .await
            .ise()?
            .get::<_, i64>(0)
            > 0)
    }
}

impl OrganizationApiKey {
    pub async fn save(&self, conn: &Conn) -> Result<()> {
        conn.execute(
            r"INSERT INTO organization_api_key (uuid, organization_uuid, atype, api_key, revision_date) VALUES ($1, $2, $3, $4, $5) ON CONFLICT (uuid) DO UPDATE
        SET
        organization_uuid = EXCLUDED.organization_uuid,
        atype = EXCLUDED.atype,
        api_key = EXCLUDED.api_key,
        revision_date = EXCLUDED.revision_date",
            &[&self.uuid, &self.organization_uuid, &self.atype, &self.api_key, &self.revision_date],
        )
        .await
        .ise()?;
        Ok(())
    }

    //TODO: the logic here must be wrong (there can be multiple keys)
    pub async fn find_by_org_uuid(conn: &Conn, organization_uuid: Uuid) -> Result<Option<Self>> {
        Ok(conn.query_opt(r"SELECT * FROM organization_api_key WHERE organization_uuid = $1", &[&organization_uuid]).await.ise()?.map(Into::into))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    #[allow(non_snake_case)]
    fn partial_cmp_UserOrgType() {
        assert!(UserOrgType::Owner > UserOrgType::Admin);
        assert!(UserOrgType::Admin > UserOrgType::Manager);
        assert!(UserOrgType::Manager > UserOrgType::User);
    }
}
