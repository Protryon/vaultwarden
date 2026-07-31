use axol::{ErrorExt, Result};
use chrono::{DateTime, Utc};
use serde_json::{Value, json};
use tokio_postgres::Row;
use uuid::Uuid;

use crate::{config::PUBLIC_NO_TRAILING_SLASH, crypto::ct_eq, db::Conn, db::models::device_type_name, util::format_date};

pub struct AuthRequest {
    pub uuid: Uuid,
    pub user_uuid: Uuid,
    pub organization_uuid: Option<Uuid>,

    pub request_device_identifier: Uuid,
    pub device_type: i32, // https://github.com/bitwarden/server/blob/master/src/Core/Enums/DeviceType.cs

    pub request_ip: String,
    pub response_device_id: Option<Uuid>,

    pub access_code: String,
    pub public_key: String,

    pub enc_key: Option<String>,

    pub master_password_hash: Option<String>,
    pub approved: Option<bool>,
    pub creation_date: DateTime<Utc>,
    pub response_date: Option<DateTime<Utc>>,

    pub authentication_date: Option<DateTime<Utc>>,
}

impl From<Row> for AuthRequest {
    fn from(row: Row) -> Self {
        Self {
            uuid: row.get(0),
            user_uuid: row.get(1),
            organization_uuid: row.get(2),
            request_device_identifier: row.get(3),
            device_type: row.get(4),
            request_ip: row.get(5),
            response_device_id: row.get(6),
            access_code: row.get(7),
            public_key: row.get(8),
            enc_key: row.get(9),
            master_password_hash: row.get(10),
            approved: row.get(11),
            creation_date: row.get(12),
            response_date: row.get(13),
            authentication_date: row.get(14),
        }
    }
}

/// Local methods
impl AuthRequest {
    pub fn new(user_uuid: Uuid, request_device_identifier: Uuid, device_type: i32, request_ip: String, access_code: String, public_key: String) -> Self {
        Self {
            uuid: Uuid::new_v4(),
            user_uuid,
            organization_uuid: None,

            request_device_identifier,
            device_type,
            request_ip,
            response_device_id: None,
            access_code,
            public_key,
            enc_key: None,
            master_password_hash: None,
            approved: None,
            creation_date: Utc::now(),
            response_date: None,
            authentication_date: None,
        }
    }

    pub fn check_access_code(&self, access_code: &str) -> bool {
        ct_eq(&self.access_code, access_code)
    }

    pub fn to_json(&self) -> Value {
        json!({
            "id": self.uuid,
            "publicKey": self.public_key,
            "requestDeviceType": device_type_name(self.device_type),
            "requestIpAddress": self.request_ip,
            "key": self.enc_key,
            "masterPasswordHash": self.master_password_hash,
            "creationDate": format_date(&self.creation_date),
            "responseDate": self.response_date.as_ref().map(format_date),
            "requestApproved": self.approved,
            "origin": &*PUBLIC_NO_TRAILING_SLASH,
            "object": "auth-request",
        })
    }
}

/// Database methods
impl AuthRequest {
    pub async fn save(&mut self, conn: &Conn) -> Result<()> {
        conn.execute(
            r"INSERT INTO auth_requests (uuid, user_uuid, organization_uuid, request_device_identifier, device_type, request_ip, response_device_id, access_code, public_key, enc_key, master_password_hash, approved, creation_date, response_date, authentication_date)
        VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14, $15) ON CONFLICT (uuid) DO UPDATE
        SET
        user_uuid = EXCLUDED.user_uuid,
        organization_uuid = EXCLUDED.organization_uuid,
        request_device_identifier = EXCLUDED.request_device_identifier,
        device_type = EXCLUDED.device_type,
        request_ip = EXCLUDED.request_ip,
        response_device_id = EXCLUDED.response_device_id,
        access_code = EXCLUDED.access_code,
        public_key = EXCLUDED.public_key,
        enc_key = EXCLUDED.enc_key,
        master_password_hash = EXCLUDED.master_password_hash,
        approved = EXCLUDED.approved,
        creation_date = EXCLUDED.creation_date,
        response_date = EXCLUDED.response_date,
        authentication_date = EXCLUDED.authentication_date",
            &[
                &self.uuid,
                &self.user_uuid,
                &self.organization_uuid,
                &self.request_device_identifier,
                &self.device_type,
                &self.request_ip,
                &self.response_device_id,
                &self.access_code,
                &self.public_key,
                &self.enc_key,
                &self.master_password_hash,
                &self.approved,
                &self.creation_date,
                &self.response_date,
                &self.authentication_date,
            ],
        )
        .await
        .ise()?;
        Ok(())
    }

    pub async fn find_by_uuid(conn: &Conn, uuid: Uuid) -> Result<Option<Self>> {
        Ok(conn.query_opt(r"SELECT * FROM auth_requests WHERE uuid = $1", &[&uuid]).await.ise()?.map(Into::into))
    }

    pub async fn find_by_uuid_and_user(conn: &Conn, uuid: Uuid, user_uuid: Uuid) -> Result<Option<Self>> {
        Ok(conn.query_opt(r"SELECT * FROM auth_requests WHERE uuid = $1 AND user_uuid = $2", &[&uuid, &user_uuid]).await.ise()?.map(Into::into))
    }

    pub async fn find_by_user(conn: &Conn, user_uuid: Uuid) -> Result<Vec<Self>> {
        Ok(conn.query(r"SELECT * FROM auth_requests WHERE user_uuid = $1", &[&user_uuid]).await.ise()?.into_iter().map(Into::into).collect())
    }

    pub async fn delete(&self, conn: &Conn) -> Result<()> {
        conn.execute(r"DELETE FROM auth_requests WHERE uuid = $1", &[&self.uuid]).await.ise()?;
        Ok(())
    }

    /// Delete auth requests older than 15 minutes, which is functionally equivalent to upstream:
    /// https://github.com/bitwarden/server/blob/main/src/Sql/dbo/Auth/Stored%20Procedures/AuthRequest_DeleteIfExpired.sql
    pub async fn purge_expired_auth_requests(conn: &Conn) -> Result<()> {
        let expiry = Utc::now() - chrono::TimeDelta::minutes(15);
        conn.execute(r"DELETE FROM auth_requests WHERE creation_date < $1", &[&expiry]).await.ise()?;
        Ok(())
    }
}
