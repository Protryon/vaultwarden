use axum_util::errors::ApiResult;
use chrono::{DateTime, Utc};
use tokio_postgres::Row;
use uuid::Uuid;

use crate::{
    crypto,
    db::{Conn, UserOrgType},
    CONFIG,
};

#[derive(Debug)]
pub struct Device {
    pub uuid: Uuid,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,

    pub user_uuid: Uuid,

    pub name: String,
    pub atype: i32, // https://github.com/bitwarden/server/blob/master/src/Core/Enums/DeviceType.cs
    pub push_uuid: Option<Uuid>,
    pub push_token: Option<String>,

    pub refresh_token: String,

    pub twofactor_remember: Option<String>,
}

impl From<Row> for Device {
    fn from(row: Row) -> Self {
        Self {
            uuid: row.get(0),
            created_at: row.get(1),
            updated_at: row.get(2),
            user_uuid: row.get(3),
            name: row.get(4),
            atype: row.get(5),
            push_token: row.get(6),
            refresh_token: row.get(7),
            twofactor_remember: row.get(8),
            push_uuid: row.get(9),
        }
    }
}

impl Device {
    pub fn new(uuid: Uuid, user_uuid: Uuid, name: String, atype: i32) -> Self {
        let now = Utc::now();

        Self {
            uuid,
            created_at: now,
            updated_at: now,

            user_uuid,
            name,
            atype,

            push_uuid: None,
            push_token: None,
            refresh_token: String::new(),
            twofactor_remember: None,
        }
    }

    pub fn refresh_twofactor_remember(&mut self) -> String {
        use data_encoding::BASE64;
        let twofactor_remember = crypto::encode_random_bytes::<180>(BASE64);
        self.twofactor_remember = Some(twofactor_remember.clone());

        twofactor_remember
    }

    pub fn delete_twofactor_remember(&mut self) {
        self.twofactor_remember = None;
    }

    pub fn refresh_tokens(&mut self, user: &super::User, orgs: Vec<super::UserOrganization>, scope: Vec<String>) -> (String, i64) {
        // If there is no refresh token, we create one
        if self.refresh_token.is_empty() {
            use data_encoding::BASE64URL;
            self.refresh_token = crypto::encode_random_bytes::<64>(BASE64URL);
        }

        // Update the expiration of the device and the last update date
        let time_now = Utc::now();
        self.updated_at = time_now;

        let orgowner: Vec<_> = orgs.iter().filter(|o| o.atype == UserOrgType::Owner).map(|o| o.organization_uuid.clone()).collect();
        let orgadmin: Vec<_> = orgs.iter().filter(|o| o.atype == UserOrgType::Admin).map(|o| o.organization_uuid.clone()).collect();
        let orguser: Vec<_> = orgs.iter().filter(|o| o.atype == UserOrgType::User).map(|o| o.organization_uuid.clone()).collect();
        let orgmanager: Vec<_> = orgs.iter().filter(|o| o.atype == UserOrgType::Manager).map(|o| o.organization_uuid.clone()).collect();

        // Create the JWT claims struct, to send to the client
        use crate::auth::{encode_jwt, LoginJwtClaims, DEFAULT_VALIDITY, JWT_LOGIN_ISSUER};
        let claims = LoginJwtClaims {
            nbf: time_now.timestamp(),
            exp: (time_now + *DEFAULT_VALIDITY).timestamp(),
            iss: JWT_LOGIN_ISSUER.to_string(),
            sub: user.uuid.clone(),

            premium: true,
            name: user.name.clone(),
            email: user.email.clone(),
            email_verified: !CONFIG.mail_enabled() || user.verified_at.is_some(),

            orgowner,
            orgadmin,
            orguser,
            orgmanager,

            sstamp: user.security_stamp,
            device: self.uuid,
            scope,
            amr: vec!["Application".into()],
        };

        (encode_jwt(&claims), DEFAULT_VALIDITY.num_seconds())
    }
}

impl Device {
    pub async fn save(&mut self, conn: &Conn) -> ApiResult<()> {
        self.updated_at = Utc::now();
        conn.execute(r"INSERT INTO devices (uuid, created_at, updated_at, user_uuid, name, atype, push_token, refresh_token, twofactor_remember, push_uuid) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10) ON CONFLICT (uuid) DO UPDATE
        SET
        updated_at = EXCLUDED.updated_at,
        user_uuid = EXCLUDED.user_uuid,
        name = EXCLUDED.name,
        atype = EXCLUDED.atype,
        push_token = EXCLUDED.push_token,
        refresh_token = EXCLUDED.refresh_token,
        twofactor_remember = EXCLUDED.twofactor_remember,
        push_uuid = EXCLUDED.push_uuid", &[
            &self.uuid,
            &self.created_at,
            &self.updated_at,
            &self.user_uuid,
            &self.name,
            &self.atype,
            &self.push_token,
            &self.refresh_token,
            &self.twofactor_remember,
            &self.push_uuid,
        ]).await?;
        Ok(())
    }

    pub async fn delete_all_by_user(conn: &Conn, user_uuid: Uuid) -> ApiResult<()> {
        conn.execute(r"DELETE FROM devices WHERE user_uuid = $1", &[&user_uuid]).await?;
        Ok(())
    }

    pub async fn find_by_uuid_and_user(conn: &Conn, uuid: Uuid, user_uuid: Uuid) -> ApiResult<Option<Self>> {
        Ok(conn.query_opt(r"SELECT * FROM devices WHERE uuid = $1 AND user_uuid = $2", &[&uuid, &user_uuid]).await?.map(Into::into))
    }

    pub async fn get(conn: &Conn, uuid: Uuid) -> ApiResult<Option<Self>> {
        Ok(conn.query_opt(r"SELECT * FROM devices WHERE uuid = $1", &[&uuid]).await?.map(Into::into))
    }

    pub async fn clear_push_token_by_uuid(conn: &Conn, uuid: Uuid) -> ApiResult<()> {
        conn.execute(r"UPDATE devices SET push_token = NULL WHERE uuid = $1", &[&uuid]).await?;
        Ok(())
    }

    pub async fn find_by_refresh_token(conn: &Conn, refresh_token: &str) -> ApiResult<Option<Self>> {
        Ok(conn.query_opt(r"SELECT * FROM devices WHERE refresh_token = $1", &[&refresh_token]).await?.map(Into::into))
    }

    pub async fn find_latest_active_by_user(conn: &Conn, user_uuid: Uuid) -> ApiResult<Option<Self>> {
        Ok(conn.query_opt(r"SELECT * FROM devices WHERE user_uuid = $1 ORDER BY updated_at DESC LIMIT 1", &[&user_uuid]).await?.map(Into::into))
    }

    pub async fn find_push_devices_by_user(conn: &Conn, user_uuid: Uuid) -> ApiResult<Vec<Self>> {
        Ok(conn.query(r"SELECT * FROM devices WHERE user_uuid = $1 AND push_token IS NOT NULL", &[&user_uuid]).await?.into_iter().map(|x| x.into()).collect())
    }

    pub async fn check_user_has_push_device(conn: &Conn, user_uuid: Uuid) -> ApiResult<bool> {
        Ok(conn.query_one(r"SELECT count(1) FROM devices WHERE user_uuid = $1 AND push_token IS NOT NULL", &[&user_uuid]).await?.get::<_, i64>(0) > 0)
    }
}
