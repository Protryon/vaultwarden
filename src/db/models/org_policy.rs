use axol::{ErrorExt, Result};
use log::error;
use serde::Deserialize;
use serde_json::{json, Value};
use serde_repr::{Deserialize_repr, Serialize_repr};
use tokio_postgres::Row;
use uuid::Uuid;

use crate::db::Conn;

use super::{TwoFactor, UserOrgType, UserOrganization};

//TODO: i think primary key can just be (org_id, atype)
pub struct OrganizationPolicy {
    pub uuid: Uuid,
    pub organization_uuid: Uuid,
    pub atype: OrgPolicyType,
    pub enabled: bool,
    pub data: Value,
}

// https://github.com/bitwarden/server/blob/b86a04cef9f1e1b82cf18e49fc94e017c641130c/src/Core/Enums/PolicyType.cs
#[derive(Copy, Clone, Eq, PartialEq, strum::FromRepr, Serialize_repr, Deserialize_repr)]
#[repr(i32)]
pub enum OrgPolicyType {
    TwoFactorAuthentication = 0,
    MasterPassword = 1,
    PasswordGenerator = 2,
    SingleOrg = 3,
    RequireSso = 4,
    PersonalOwnership = 5,
    DisableSend = 6,
    SendOptions = 7,
    ResetPassword = 8,
    // MaximumVaultTimeout = 9, // Not supported (Not AGPLv3 Licensed)
    // DisablePersonalVaultExport = 10, // Not supported (Not AGPLv3 Licensed)
    Unknown = i32::MAX,
}

// https://github.com/bitwarden/server/blob/5cbdee137921a19b1f722920f0fa3cd45af2ef0f/src/Core/Models/Data/Organizations/Policies/SendOptionsPolicyData.cs
#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct SendOptionsPolicyData {
    pub disable_hide_email: bool,
}

// https://github.com/bitwarden/server/blob/5cbdee137921a19b1f722920f0fa3cd45af2ef0f/src/Core/Models/Data/Organizations/Policies/ResetPasswordDataModel.cs
#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ResetPasswordDataModel {
    pub auto_enroll_enabled: bool,
}

pub type OrgPolicyResult = Result<(), OrgPolicyErr>;

#[derive(Copy, Clone, Eq, PartialEq)]
pub enum OrgPolicyErr {
    TwoFactorMissing,
    SingleOrgEnforced,
}

impl From<Row> for OrganizationPolicy {
    fn from(row: Row) -> Self {
        Self {
            uuid: row.get(0),
            organization_uuid: row.get(1),
            atype: OrgPolicyType::from_repr(row.get(2)).unwrap_or(OrgPolicyType::Unknown),
            enabled: row.get(3),
            data: row.get(4),
        }
    }
}

/// Local methods
impl OrganizationPolicy {
    pub fn new(organization_uuid: Uuid, atype: OrgPolicyType, data: Value) -> Self {
        Self {
            uuid: Uuid::new_v4(),
            organization_uuid,
            atype: atype,
            enabled: false,
            data,
        }
    }

    pub fn to_json(&self) -> Value {
        json!({
            "id": self.uuid,
            "organizationId": self.organization_uuid,
            "type": self.atype,
            "data": self.data,
            "enabled": self.enabled,
            "object": "policy",
        })
    }
}

/// Database methods
impl OrganizationPolicy {
    pub async fn save(&mut self, conn: &Conn) -> Result<()> {
        conn.execute(
            r"INSERT INTO organization_policies (uuid, organization_uuid, atype, enabled, data) VALUES ($1, $2, $3, $4, $5) ON CONFLICT (uuid) DO UPDATE
        SET
        organization_uuid = EXCLUDED.organization_uuid,
        atype = EXCLUDED.atype,
        enabled = EXCLUDED.enabled,
        data = EXCLUDED.data",
            &[&self.uuid, &self.organization_uuid, &(self.atype as i32), &self.enabled, &self.data],
        )
        .await
        .ise()?;
        Ok(())
    }

    pub async fn find_by_org(conn: &Conn, organization_uuid: Uuid) -> Result<Vec<Self>> {
        Ok(conn
            .query(r"SELECT * FROM organization_policies WHERE organization_uuid = $1", &[&organization_uuid])
            .await
            .ise()?
            .into_iter()
            .map(|x| x.into())
            .collect())
    }

    pub async fn find_confirmed_by_user(conn: &Conn, user_uuid: Uuid) -> Result<Vec<Self>> {
        Ok(conn
            .query(
                r"
        SELECT op.*
        FROM organization_policies op
        INNER JOIN user_organizations uo ON uo.organization_uuid = op.organization_uuid
        WHERE uo.user_uuid = $1 AND uo.status = 2
        ",
                &[&user_uuid],
            )
            .await
            .ise()?
            .into_iter()
            .map(|x| x.into())
            .collect())
    }

    pub async fn find_by_org_and_type(conn: &Conn, organization_uuid: Uuid, policy_type: OrgPolicyType) -> Result<Option<Self>> {
        Ok(conn
            .query_opt(r"SELECT * FROM organization_policies WHERE organization_uuid = $1 AND atype = $2", &[&organization_uuid, &(policy_type as i32)])
            .await
            .ise()?
            .map(Into::into))
    }

    pub async fn find_accepted_and_confirmed_by_user_and_active_policy(conn: &Conn, user_uuid: Uuid, policy_type: OrgPolicyType) -> Result<Vec<Self>> {
        Ok(conn
            .query(
                r"
        SELECT op.*
        FROM organization_policies op
        INNER JOIN user_organizations uo ON uo.organization_uuid = op.organization_uuid
        WHERE uo.user_uuid = $1 AND (uo.status = 2 OR uo.status = 1) AND op.atype = $2 AND op.enabled
        ",
                &[&user_uuid, &(policy_type as i32)],
            )
            .await
            .ise()?
            .into_iter()
            .map(|x| x.into())
            .collect())
    }

    pub async fn find_confirmed_by_user_and_active_policy(conn: &Conn, user_uuid: Uuid, policy_type: OrgPolicyType) -> Result<Vec<Self>> {
        Ok(conn
            .query(
                r"
        SELECT op.*
        FROM organization_policies op
        INNER JOIN user_organizations uo ON uo.organization_uuid = op.organization_uuid
        WHERE uo.user_uuid = $1 AND uo.status = 2 AND op.atype = $2 AND op.enabled
        ",
                &[&user_uuid, &(policy_type as i32)],
            )
            .await
            .ise()?
            .into_iter()
            .map(|x| x.into())
            .collect())
    }

    /// Returns true if the user belongs to an org that has enabled the specified policy type,
    /// and the user is not an owner or admin of that org. This is only useful for checking
    /// applicability of policy types that have these particular semantics.
    pub async fn is_applicable_to_user(conn: &Conn, user_uuid: Uuid, policy_type: OrgPolicyType, exclude_org_uuid: Option<Uuid>) -> Result<bool> {
        //TODO: refactor this to not be N+1 query
        for policy in OrganizationPolicy::find_accepted_and_confirmed_by_user_and_active_policy(conn, user_uuid, policy_type).await.ise()? {
            // Check if we need to skip this organization.
            if exclude_org_uuid == Some(policy.organization_uuid) {
                continue;
            }

            if let Some(user) = UserOrganization::get(conn, user_uuid, policy.organization_uuid).await.ise()? {
                if user.atype < UserOrgType::Admin {
                    return Ok(true);
                }
            }
        }
        Ok(false)
    }

    pub async fn is_user_allowed(conn: &Conn, user_uuid: Uuid, org_uuid: Uuid, exclude_current_org: bool) -> Result<OrgPolicyResult> {
        // Enforce TwoFactor/TwoStep login
        if TwoFactor::find_by_user_official(conn, user_uuid).await.ise()?.is_empty() {
            match Self::find_by_org_and_type(conn, org_uuid, OrgPolicyType::TwoFactorAuthentication).await.ise()? {
                Some(p) if p.enabled => {
                    return Ok(Err(OrgPolicyErr::TwoFactorMissing));
                }
                _ => {}
            };
        }

        // Enforce Single Organization Policy of other organizations user is a member of
        // This check here needs to exclude this current org-id, else an accepted user can not be confirmed.
        let exclude_org = if exclude_current_org {
            Some(org_uuid)
        } else {
            None
        };
        if Self::is_applicable_to_user(conn, user_uuid, OrgPolicyType::SingleOrg, exclude_org).await.ise()? {
            return Ok(Err(OrgPolicyErr::SingleOrgEnforced));
        }

        Ok(Ok(()))
    }

    pub async fn org_is_reset_password_auto_enroll(conn: &Conn, org_uuid: Uuid) -> Result<bool> {
        match OrganizationPolicy::find_by_org_and_type(conn, org_uuid, OrgPolicyType::ResetPassword).await.ise()? {
            Some(policy) => match serde_json::from_value::<ResetPasswordDataModel>(policy.data) {
                Ok(opts) => {
                    return Ok(policy.enabled && opts.auto_enroll_enabled);
                }
                Err(e) => error!("Failed to deserialize ResetPasswordDataModel: {e}"),
            },
            None => return Ok(false),
        }

        Ok(false)
    }

    /// Returns true if the user belongs to an org that has enabled the `DisableHideEmail`
    /// option of the `Send Options` policy, and the user is not an owner or admin of that org.
    pub async fn is_hide_email_disabled(conn: &Conn, user_uuid: Uuid) -> Result<bool> {
        for policy in OrganizationPolicy::find_confirmed_by_user_and_active_policy(conn, user_uuid, OrgPolicyType::SendOptions).await.ise()? {
            if let Some(user) = UserOrganization::get(conn, user_uuid, policy.organization_uuid).await.ise()? {
                if user.atype < UserOrgType::Admin {
                    match serde_json::from_value::<SendOptionsPolicyData>(policy.data) {
                        Ok(opts) => {
                            if opts.disable_hide_email {
                                return Ok(true);
                            }
                        }
                        Err(e) => error!("Failed to deserialize SendOptionsPolicyData: {e}"),
                    }
                }
            }
        }
        Ok(false)
    }
}
