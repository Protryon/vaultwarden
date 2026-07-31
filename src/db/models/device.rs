use axol::{ErrorExt, Result};
use chrono::{DateTime, Utc};
use tokio_postgres::Row;
use uuid::Uuid;

use crate::{
    CONFIG, crypto,
    db::{Conn, UserOrgType},
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

    pub fn generate_refresh_token() -> String {
        use data_encoding::BASE64URL;
        crypto::encode_random_bytes::<64>(BASE64URL)
    }

    pub fn refresh_tokens(&mut self, user: &super::User, orgs: Vec<super::UserOrganization>, scope: Vec<String>) -> (String, i64) {
        // If there is no refresh token, we create one
        if self.refresh_token.is_empty() {
            self.refresh_token = Device::generate_refresh_token();
        }

        // Update the expiration of the device and the last update date
        let time_now = Utc::now();
        self.updated_at = time_now;

        let orgowner: Vec<_> = orgs.iter().filter(|o| o.atype == UserOrgType::Owner).map(|o| o.organization_uuid).collect();
        let orgadmin: Vec<_> = orgs.iter().filter(|o| o.atype == UserOrgType::Admin).map(|o| o.organization_uuid).collect();
        let orguser: Vec<_> = orgs.iter().filter(|o| o.atype == UserOrgType::User).map(|o| o.organization_uuid).collect();
        let orgmanager: Vec<_> = orgs.iter().filter(|o| o.atype == UserOrgType::Manager).map(|o| o.organization_uuid).collect();

        // Create the JWT claims struct, to send to the client
        use crate::auth::{DEFAULT_VALIDITY, JWT_LOGIN_ISSUER, LoginJwtClaims, encode_jwt};
        let claims = LoginJwtClaims {
            nbf: time_now.timestamp(),
            exp: (time_now + *DEFAULT_VALIDITY).timestamp(),
            iss: JWT_LOGIN_ISSUER.to_string(),
            sub: user.uuid,

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
    pub async fn save(&mut self, conn: &Conn) -> Result<()> {
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
        ]).await.ise()?;
        Ok(())
    }

    pub async fn delete_all_by_user(conn: &Conn, user_uuid: Uuid) -> Result<()> {
        conn.execute(r"DELETE FROM devices WHERE user_uuid = $1", &[&user_uuid]).await.ise()?;
        Ok(())
    }

    pub async fn find_by_uuid_and_user(conn: &Conn, uuid: Uuid, user_uuid: Uuid) -> Result<Option<Self>> {
        Ok(conn.query_opt(r"SELECT * FROM devices WHERE uuid = $1 AND user_uuid = $2", &[&uuid, &user_uuid]).await.ise()?.map(Into::into))
    }

    pub async fn get(conn: &Conn, uuid: Uuid) -> Result<Option<Self>> {
        Ok(conn.query_opt(r"SELECT * FROM devices WHERE uuid = $1", &[&uuid]).await.ise()?.map(Into::into))
    }

    pub async fn clear_push_token_by_uuid(conn: &Conn, uuid: Uuid) -> Result<()> {
        conn.execute(r"UPDATE devices SET push_token = NULL WHERE uuid = $1", &[&uuid]).await.ise()?;
        Ok(())
    }

    pub async fn find_by_refresh_token(conn: &Conn, refresh_token: &str) -> Result<Option<Self>> {
        Ok(conn.query_opt(r"SELECT * FROM devices WHERE refresh_token = $1", &[&refresh_token]).await.ise()?.map(Into::into))
    }

    pub async fn find_by_user(conn: &Conn, user_uuid: Uuid) -> Result<Vec<Self>> {
        Ok(conn.query(r"SELECT * FROM devices WHERE user_uuid = $1", &[&user_uuid]).await.ise()?.into_iter().map(Into::into).collect())
    }

    /// Rotate the refresh-token of every device belonging to a user.
    /// Called when a security-stamp is reset so that old refresh-tokens can no longer be used.
    /// Each device needs a unique token, so a single UPDATE with one value cannot be used.
    pub async fn rotate_refresh_tokens_by_user(conn: &Conn, user_uuid: Uuid) -> Result<()> {
        for mut device in Self::find_by_user(conn, user_uuid).await? {
            device.refresh_token = Device::generate_refresh_token();
            device.save(conn).await?;
        }
        Ok(())
    }

    pub async fn find_latest_active_by_user(conn: &Conn, user_uuid: Uuid) -> Result<Option<Self>> {
        Ok(conn.query_opt(r"SELECT * FROM devices WHERE user_uuid = $1 ORDER BY updated_at DESC LIMIT 1", &[&user_uuid]).await.ise()?.map(Into::into))
    }

    pub async fn find_push_devices_by_user(conn: &Conn, user_uuid: Uuid) -> Result<Vec<Self>> {
        Ok(conn
            .query(r"SELECT * FROM devices WHERE user_uuid = $1 AND push_token IS NOT NULL", &[&user_uuid])
            .await
            .ise()?
            .into_iter()
            .map(|x| x.into())
            .collect())
    }

    pub async fn check_user_has_push_device(conn: &Conn, user_uuid: Uuid) -> Result<bool> {
        Ok(conn.query_one(r"SELECT count(1) FROM devices WHERE user_uuid = $1 AND push_token IS NOT NULL", &[&user_uuid]).await.ise()?.get::<_, i64>(0) > 0)
    }
}

/// Maps a Bitwarden device-type id to its display name.
/// https://github.com/bitwarden/server/blob/master/src/Core/Enums/DeviceType.cs
pub fn device_type_name(value: i32) -> &'static str {
    match value {
        0 => "Android",
        1 => "iOS",
        2 => "Chrome Extension",
        3 => "Firefox Extension",
        4 => "Opera Extension",
        5 => "Edge Extension",
        6 => "Windows",
        7 => "macOS",
        8 => "Linux",
        9 => "Chrome",
        10 => "Firefox",
        11 => "Opera",
        12 => "Edge",
        13 => "Internet Explorer",
        15 => "Android",
        16 => "UWP",
        17 => "Safari",
        18 => "Vivaldi",
        19 => "Vivaldi Extension",
        20 => "Safari Extension",
        21 => "SDK",
        22 => "Server",
        23 => "Windows CLI",
        24 => "macOS CLI",
        25 => "Linux CLI",
        26 => "DuckDuckGo",
        _ => "Unknown Browser",
    }
}
