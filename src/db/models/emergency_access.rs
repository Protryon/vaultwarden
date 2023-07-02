use std::str::FromStr;

use axum_util::errors::{ApiError, ApiResult};
use chrono::{DateTime, Utc};
use serde_json::{json, Value};
use serde_repr::{Deserialize_repr, Serialize_repr};
use tokio_postgres::Row;
use uuid::Uuid;

use crate::db::Conn;

use super::User;

#[derive(Debug)]
pub struct EmergencyAccess {
    pub uuid: Uuid,
    pub grantor_uuid: Uuid,
    pub grantee_uuid: Option<Uuid>,
    pub email: Option<String>,
    pub key_encrypted: Option<String>,
    pub atype: EmergencyAccessType,
    pub status: EmergencyAccessStatus,
    pub wait_time_days: i32,
    pub recovery_initiated_at: Option<DateTime<Utc>>,
    pub last_notification_at: Option<DateTime<Utc>>,
    pub updated_at: DateTime<Utc>,
    pub created_at: DateTime<Utc>,
}

impl From<Row> for EmergencyAccess {
    fn from(row: Row) -> Self {
        Self {
            uuid: row.get(0),
            grantor_uuid: row.get(1),
            grantee_uuid: row.get(2),
            email: row.get(3),
            key_encrypted: row.get(4),
            atype: EmergencyAccessType::from_repr(row.get(5)).unwrap_or(EmergencyAccessType::Unknown),
            status: EmergencyAccessStatus::from_repr(row.get(6)).unwrap_or(EmergencyAccessStatus::Unknown),
            wait_time_days: row.get(7),
            recovery_initiated_at: row.get(8),
            last_notification_at: row.get(9),
            updated_at: row.get(10),
            created_at: row.get(11),
        }
    }
}

impl EmergencyAccess {
    pub fn new(grantor_uuid: Uuid, email: String, status: EmergencyAccessStatus, atype: EmergencyAccessType, wait_time_days: i32) -> Self {
        let now = Utc::now();

        Self {
            uuid: Uuid::new_v4(),
            grantor_uuid,
            grantee_uuid: None,
            email: Some(email),
            status,
            atype,
            wait_time_days,
            recovery_initiated_at: None,
            created_at: now,
            updated_at: now,
            key_encrypted: None,
            last_notification_at: None,
        }
    }

    pub fn get_type_as_str(&self) -> &'static str {
        if self.atype == EmergencyAccessType::View {
            "View"
        } else {
            "Takeover"
        }
    }

    pub fn to_json(&self) -> Value {
        json!({
            "Id": self.uuid,
            "Status": self.status as i32,
            "Type": self.atype as i32,
            "WaitTimeDays": self.wait_time_days,
            "Object": "emergencyAccess",
        })
    }

    pub async fn to_json_grantor_details(&self, conn: &Conn) -> ApiResult<Value> {
        let grantor_user = User::get(conn, self.grantor_uuid).await?.ok_or(ApiError::NotFound)?;

        Ok(json!({
            "Id": self.uuid,
            "Status": self.status as i32,
            "Type": self.atype as i32,
            "WaitTimeDays": self.wait_time_days,
            "GrantorId": grantor_user.uuid,
            "Email": grantor_user.email,
            "Name": grantor_user.name,
            "Object": "emergencyAccessGrantorDetails",
        }))
    }

    pub async fn to_json_grantee_details(&self, conn: &Conn) -> ApiResult<Value> {
        let grantee_user = if let Some(grantee_uuid) = self.grantee_uuid {
            Some(User::get(conn, grantee_uuid).await?.ok_or(ApiError::NotFound)?)
        } else if let Some(email) = self.email.as_deref() {
            Some(User::find_by_email(conn, email).await?.ok_or(ApiError::NotFound)?)
        } else {
            None
        };

        Ok(json!({
            "Id": self.uuid,
            "Status": self.status as i32,
            "Type": self.atype as i32,
            "WaitTimeDays": self.wait_time_days,
            "GranteeId": grantee_user.as_ref().map_or(Uuid::default(), |u| u.uuid),
            "Email": grantee_user.as_ref().map_or("", |u| &u.email),
            "Name": grantee_user.as_ref().map_or("", |u| &u.name),
            "Object": "emergencyAccessGranteeDetails",
        }))
    }
}

#[derive(Copy, Clone, Debug, PartialEq, Eq, strum::FromRepr, Serialize_repr, Deserialize_repr)]
#[repr(i32)]
pub enum EmergencyAccessType {
    View = 0,
    Takeover = 1,
    Unknown = i32::MAX,
}

impl FromStr for EmergencyAccessType {
    type Err = &'static str;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s {
            "0" | "View" => Ok(EmergencyAccessType::View),
            "1" | "Takeover" => Ok(EmergencyAccessType::Takeover),
            _ => Err("invalid type"),
        }
    }
}

#[derive(Copy, Clone, Debug, strum::FromRepr, PartialEq, Eq)]
#[repr(i32)]
pub enum EmergencyAccessStatus {
    Invited = 0,
    Accepted = 1,
    Confirmed = 2,
    RecoveryInitiated = 3,
    RecoveryApproved = 4,
    Unknown = i32::MAX,
}

// region Database methods

impl EmergencyAccess {
    pub async fn save(&mut self, conn: &Conn) -> ApiResult<()> {
        self.updated_at = Utc::now();

        conn.execute(r"INSERT INTO emergency_access (uuid, grantor_uuid, grantee_uuid, email, key_encrypted, atype, status, wait_time_days, recovery_initiated_at, last_notification_at, updated_at, created_at) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12) ON CONFLICT (uuid) DO UPDATE
        SET
        grantor_uuid = EXCLUDED.grantor_uuid,
        grantee_uuid = EXCLUDED.grantee_uuid,
        email = EXCLUDED.email,
        key_encrypted = EXCLUDED.key_encrypted,
        atype = EXCLUDED.atype,
        status = EXCLUDED.status,
        wait_time_days = EXCLUDED.wait_time_days,
        recovery_initiated_at = EXCLUDED.recovery_initiated_at,
        last_notification_at = EXCLUDED.last_notification_at,
        updated_at = EXCLUDED.updated_at,
        created_at = EXCLUDED.created_at", &[
            &self.uuid,
            &self.grantor_uuid,
            &self.grantee_uuid,
            &self.email,
            &self.key_encrypted,
            &(self.atype as i32),
            &(self.status as i32),
            &self.wait_time_days,
            &self.recovery_initiated_at,
            &self.last_notification_at,
            &self.updated_at,
            &self.created_at,
        ]).await?;
        Ok(())
    }

    pub async fn update_access_status_and_save(&mut self, conn: &Conn, status: EmergencyAccessStatus, date: DateTime<Utc>) -> ApiResult<()> {
        self.status = status;
        self.updated_at = date;

        conn.execute(r"UPDATE emergency_access SET status = $1, updated_at = $2 WHERE uuid = $3", &[&(self.status as i32), &self.updated_at, &self.uuid])
            .await?;
        Ok(())
    }

    pub async fn update_last_notification_date_and_save(&mut self, conn: &Conn, date: DateTime<Utc>) -> ApiResult<()> {
        self.last_notification_at = Some(date);
        self.updated_at = date;

        conn.execute(
            r"UPDATE emergency_access SET last_notification_at = $1, updated_at = $2 WHERE uuid = $3",
            &[&self.last_notification_at, &self.updated_at, &self.uuid],
        )
        .await?;
        Ok(())
    }

    pub async fn delete(&self, conn: &Conn) -> ApiResult<()> {
        conn.execute(r"DELETE FROM emergency_access WHERE uuid = $1", &[&self.uuid]).await?;
        Ok(())
    }

    pub async fn get(conn: &Conn, uuid: Uuid) -> ApiResult<Option<Self>> {
        Ok(conn.query_opt(r"SELECT * FROM emergency_access WHERE uuid = $1", &[&uuid]).await?.map(Into::into))
    }

    pub async fn get_with_grantor(conn: &Conn, uuid: Uuid, user_uuid: Uuid) -> ApiResult<Option<Self>> {
        Ok(conn.query_opt(r"SELECT * FROM emergency_access WHERE uuid = $1 AND grantor_uuid = $2", &[&uuid, &user_uuid]).await?.map(Into::into))
    }

    pub async fn get_with_grantee(conn: &Conn, uuid: Uuid, user_uuid: Uuid) -> ApiResult<Option<Self>> {
        Ok(conn.query_opt(r"SELECT * FROM emergency_access WHERE uuid = $1 AND grantee_uuid = $2", &[&uuid, &user_uuid]).await?.map(Into::into))
    }

    pub async fn find_by_grantor_uuid_and_grantee_uuid_or_email(conn: &Conn, grantor_uuid: Uuid, grantee_uuid: Uuid, email: &str) -> ApiResult<Option<Self>> {
        Ok(conn
            .query_opt(r"SELECT * FROM emergency_access WHERE grantor_uuid = $1 AND (grantee_uuid = $2 OR email = $3)", &[&grantor_uuid, &grantee_uuid, &email])
            .await?
            .map(Into::into))
    }

    pub async fn find_all_recoveries_initiated(conn: &Conn) -> ApiResult<Vec<Self>> {
        Ok(conn
            .query(
                r"SELECT * FROM emergency_access WHERE status = $1 AND recovery_initiated_at IS NOT NULL",
                &[&(EmergencyAccessStatus::RecoveryInitiated as i32)],
            )
            .await?
            .into_iter()
            .map(|x| x.into())
            .collect())
    }

    pub async fn find_all_by_grantee_uuid(conn: &Conn, grantee_uuid: Uuid) -> ApiResult<Vec<Self>> {
        Ok(conn.query(r"SELECT * FROM emergency_access WHERE grantee_uuid = $1", &[&grantee_uuid]).await?.into_iter().map(|x| x.into()).collect())
    }

    pub async fn find_invited_by_grantee_email(conn: &Conn, grantee_email: &str) -> ApiResult<Option<Self>> {
        Ok(conn
            .query_opt(r"SELECT * FROM emergency_access WHERE email = $1 AND status = $2", &[&grantee_email, &(EmergencyAccessStatus::Invited as i32)])
            .await?
            .map(Into::into))
    }

    pub async fn find_all_by_grantor_uuid(conn: &Conn, grantor_uuid: Uuid) -> ApiResult<Vec<Self>> {
        Ok(conn.query(r"SELECT * FROM emergency_access WHERE grantor_uuid = $1", &[&grantor_uuid]).await?.into_iter().map(|x| x.into()).collect())
    }
}
