use axum_util::errors::ApiError;
use axum_util::errors::ApiResult;
use chrono::{DateTime, Duration, Utc};
use serde::Deserialize;
use serde::Serialize;
use serde_json::json;
use serde_json::Value;
use tokio_postgres::Row;

use crate::crypto;
use crate::db::Conn;
use crate::db::TwoFactor;
use crate::CONFIG;
use uuid::Uuid;

use super::Device;
use super::Invitation;
use super::UserOrgStatus;
use super::UserOrgType;
use super::UserOrganization;

#[derive(Debug)]
pub struct User {
    pub uuid: Uuid,
    pub enabled: bool,
    pub created_at: DateTime<Utc>,
    pub verified_at: Option<DateTime<Utc>>,
    pub last_verifying_at: Option<DateTime<Utc>>,
    pub login_verify_count: i32,

    pub email: String,
    pub email_new: Option<String>,
    pub email_new_token: Option<String>,
    pub name: String,

    pub password_hash: Vec<u8>,
    pub salt: Vec<u8>,
    pub password_iterations: i32,
    pub password_hint: Option<String>,

    pub akey: String,
    pub private_key: Option<String>,
    pub public_key: Option<String>,

    pub totp_secret: Option<String>, // todo: do we need to hide this somewhere?
    pub totp_recover: Option<String>,

    pub security_stamp: Uuid,
    pub stamp_exception: Option<String>,

    pub equivalent_domains: String,
    pub excluded_globals: String,

    pub client_kdf_type: i32,
    pub client_kdf_iter: i32,
    pub client_kdf_memory: Option<i32>,
    pub client_kdf_parallelism: Option<i32>,

    pub api_key: Option<String>,

    pub avatar_color: Option<String>,

    pub external_id: Option<String>,
}

impl From<Row> for User {
    fn from(row: Row) -> Self {
        Self {
            uuid: row.get(0),
            created_at: row.get(1),
            email: row.get(2),
            name: row.get(3),
            password_hash: row.get(4),
            salt: row.get(5),
            password_iterations: row.get(6),
            password_hint: row.get(7),
            akey: row.get(8),
            private_key: row.get(9),
            public_key: row.get(10),
            totp_secret: row.get(11),
            totp_recover: row.get(12),
            security_stamp: row.get(13),
            equivalent_domains: row.get(14),
            excluded_globals: row.get(15),
            client_kdf_type: row.get(16),
            client_kdf_iter: row.get(17),
            verified_at: row.get(18),
            last_verifying_at: row.get(19),
            login_verify_count: row.get(20),
            email_new: row.get(21),
            email_new_token: row.get(22),
            enabled: row.get(23),
            stamp_exception: row.get(24),
            api_key: row.get(25),
            avatar_color: row.get(26),
            client_kdf_memory: row.get(27),
            client_kdf_parallelism: row.get(28),
            external_id: row.get(29),
        }
    }
}

#[derive(Clone, Copy, strum::FromRepr)]
#[repr(i32)]
pub enum UserKdfType {
    Pbkdf2 = 0,
    Argon2id = 1,
}

#[derive(Clone, Copy, strum::FromRepr)]
#[repr(i32)]
enum UserStatus {
    Enabled = 0,
    Invited = 1,
    _Disabled = 2,
}

#[derive(Serialize, Deserialize)]
pub struct UserStampException {
    pub routes: Vec<String>,
    pub security_stamp: Uuid,
    pub expire: i64,
}

impl User {
    pub const CLIENT_KDF_TYPE_DEFAULT: i32 = UserKdfType::Pbkdf2 as i32;
    pub const CLIENT_KDF_ITER_DEFAULT: i32 = 600_000;

    pub fn new(email: String) -> Self {
        let now = Utc::now();
        let email = email.to_lowercase();

        Self {
            uuid: Uuid::new_v4(),
            enabled: true,
            created_at: now,
            verified_at: None,
            last_verifying_at: None,
            login_verify_count: 0,
            name: email.clone(),
            email,
            akey: String::new(),
            email_new: None,
            email_new_token: None,
            password_hash: Vec::new(),
            salt: crypto::get_random_bytes::<64>().to_vec(),
            password_iterations: CONFIG.settings.password_iterations,
            security_stamp: Uuid::new_v4(),
            stamp_exception: None,
            password_hint: None,
            private_key: None,
            public_key: None,
            totp_secret: None,
            totp_recover: None,
            equivalent_domains: "[]".to_string(),
            excluded_globals: "[]".to_string(),
            client_kdf_type: Self::CLIENT_KDF_TYPE_DEFAULT,
            client_kdf_iter: Self::CLIENT_KDF_ITER_DEFAULT,
            client_kdf_memory: None,
            client_kdf_parallelism: None,
            api_key: None,
            avatar_color: None,
            external_id: None,
        }
    }

    pub fn check_valid_password(&self, password: &str) -> bool {
        crypto::verify_password_hash(password.as_bytes(), &self.salt, &self.password_hash, self.password_iterations as u32)
    }

    pub fn check_valid_recovery_code(&self, recovery_code: &str) -> bool {
        if let Some(ref totp_recover) = self.totp_recover {
            crate::crypto::ct_eq(recovery_code, totp_recover.to_lowercase())
        } else {
            false
        }
    }

    pub fn check_valid_api_key(&self, key: &str) -> bool {
        matches!(self.api_key, Some(ref api_key) if crate::crypto::ct_eq(api_key, key))
    }

    pub fn set_external_id(&mut self, external_id: Option<String>) {
        //Check if external id is empty. We don't want to have
        //empty strings in the database
        let mut ext_id: Option<String> = None;
        if let Some(external_id) = external_id {
            if !external_id.is_empty() {
                ext_id = Some(external_id);
            }
        }
        self.external_id = ext_id;
    }

    /// Set the password hash generated
    /// And resets the security_stamp. Based upon the allow_next_route the security_stamp will be different.
    ///
    /// # Arguments
    ///
    /// * `password` - A str which contains a hashed version of the users master password.
    /// * `new_key` - A String  which contains the new aKey value of the users master password.
    /// * `allow_next_route` - A Option<Vec<String>> with the function names of the next allowed (rocket) routes.
    ///                       These routes are able to use the previous stamp id for the next 2 minutes.
    ///                       After these 2 minutes this stamp will expire.
    ///
    pub fn set_password(&mut self, password: &str, new_key: Option<String>, reset_security_stamp: bool, allow_next_route: Option<Vec<String>>) {
        self.password_hash = crypto::hash_password(password.as_bytes(), &self.salt, self.password_iterations as u32);

        if let Some(route) = allow_next_route {
            self.set_stamp_exception(route);
        }

        if let Some(new_key) = new_key {
            self.akey = new_key;
        }

        if reset_security_stamp {
            self.reset_security_stamp()
        }
    }

    pub fn reset_security_stamp(&mut self) {
        self.security_stamp = Uuid::new_v4();
    }

    /// Set the stamp_exception to only allow a subsequent request matching a specific route using the current security-stamp.
    ///
    /// # Arguments
    /// * `route_exception` - A Vec<String> with the function names of the next allowed (rocket) routes.
    ///                       These routes are able to use the previous stamp id for the next 2 minutes.
    ///                       After these 2 minutes this stamp will expire.
    ///
    pub fn set_stamp_exception(&mut self, route_exception: Vec<String>) {
        let stamp_exception = UserStampException {
            routes: route_exception,
            security_stamp: self.security_stamp,
            expire: (Utc::now() + Duration::minutes(2)).timestamp(),
        };
        self.stamp_exception = Some(serde_json::to_string(&stamp_exception).unwrap_or_default());
    }

    /// Resets the stamp_exception to prevent re-use of the previous security-stamp
    pub fn reset_stamp_exception(&mut self) {
        self.stamp_exception = None;
    }
}

impl User {
    pub async fn last_revision(&self, conn: &Conn) -> ApiResult<DateTime<Utc>> {
        Ok(conn.query_one(r"SELECT coalesce(updated_at, now()) FROM user_revisions WHERE uuid = $1", &[&self.uuid]).await?.get(0))
    }

    pub async fn flag_revision_for(conn: &Conn, uuid: Uuid) -> ApiResult<()> {
        conn.execute(r"INSERT INTO user_revisions (uuid, updated_at) VALUES ($1, now()) ON CONFLICT (uuid) DO UPDATE SET uuid = EXCLUDED.uuid", &[&uuid])
            .await?;
        Ok(())
    }

    pub async fn flag_revision(&self, conn: &Conn) -> ApiResult<()> {
        Self::flag_revision_for(conn, self.uuid).await
    }

    pub async fn to_json(&self, conn: &Conn) -> ApiResult<Value> {
        let mut orgs_json = Vec::new();
        for c in UserOrganization::find_by_user_with_status(conn, self.uuid, UserOrgStatus::Confirmed).await? {
            orgs_json.push(c.to_json(conn).await?);
        }

        let twofactor_enabled = !TwoFactor::find_by_user_official(conn, self.uuid).await?.is_empty();

        // TODO: Might want to save the status field in the DB
        let status = if self.password_hash.is_empty() {
            UserStatus::Invited
        } else {
            UserStatus::Enabled
        };

        Ok(json!({
            "_Status": status as i32,
            "Id": self.uuid,
            "Name": self.name,
            "Email": self.email,
            "EmailVerified": !CONFIG.mail_enabled() || self.verified_at.is_some(),
            "Premium": true,
            "MasterPasswordHint": self.password_hint,
            "Culture": "en-US",
            "TwoFactorEnabled": twofactor_enabled,
            "Key": self.akey,
            "PrivateKey": self.private_key,
            "SecurityStamp": self.security_stamp,
            "Organizations": orgs_json,
            "Providers": [],
            "ProviderOrganizations": [],
            "ForcePasswordReset": false,
            "AvatarColor": self.avatar_color,
            "Object": "profile",
        }))
    }

    pub async fn save(&mut self, conn: &Conn) -> ApiResult<()> {
        if self.email.trim().is_empty() {
            return Err(ApiError::BadRequest("User email can't be empty".to_string()));
        }

        conn.execute(r"INSERT INTO users (uuid, enabled, created_at, verified_at, last_verifying_at, login_verify_count, name, email, akey, email_new, email_new_token, password_hash, salt, password_iterations, security_stamp, stamp_exception, password_hint, private_key, public_key, totp_secret, totp_recover, equivalent_domains, excluded_globals, client_kdf_type, client_kdf_iter, client_kdf_memory, client_kdf_parallelism, api_key, avatar_color, external_id) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14, $15, $16, $17, $18, $19, $20, $21, $22, $23, $24, $25, $26, $27, $28, $29, $30) ON CONFLICT (uuid) DO UPDATE
        SET
        enabled = EXCLUDED.enabled,
        created_at = EXCLUDED.created_at,
        verified_at = EXCLUDED.verified_at,
        last_verifying_at = EXCLUDED.last_verifying_at,
        login_verify_count = EXCLUDED.login_verify_count,
        name = EXCLUDED.name,
        email = EXCLUDED.email,
        akey = EXCLUDED.akey,
        email_new = EXCLUDED.email_new,
        email_new_token = EXCLUDED.email_new_token,
        password_hash = EXCLUDED.password_hash,
        salt = EXCLUDED.salt,
        password_iterations = EXCLUDED.password_iterations,
        security_stamp = EXCLUDED.security_stamp,
        stamp_exception = EXCLUDED.stamp_exception,
        password_hint = EXCLUDED.password_hint,
        private_key = EXCLUDED.private_key,
        public_key = EXCLUDED.public_key,
        totp_secret = EXCLUDED.totp_secret,
        totp_recover = EXCLUDED.totp_recover,
        equivalent_domains = EXCLUDED.equivalent_domains,
        excluded_globals = EXCLUDED.excluded_globals,
        client_kdf_type = EXCLUDED.client_kdf_type,
        client_kdf_iter = EXCLUDED.client_kdf_iter,
        client_kdf_memory = EXCLUDED.client_kdf_memory,
        client_kdf_parallelism = EXCLUDED.client_kdf_parallelism,
        api_key = EXCLUDED.api_key,
        avatar_color = EXCLUDED.avatar_color,
        external_id = EXCLUDED.external_id", &[
            &self.uuid,
            &self.enabled,
            &self.created_at,
            &self.verified_at,
            &self.last_verifying_at,
            &self.login_verify_count,
            &self.name,
            &self.email,
            &self.akey,
            &self.email_new,
            &self.email_new_token,
            &self.password_hash,
            &self.salt,
            &self.password_iterations,
            &self.security_stamp,
            &self.stamp_exception,
            &self.password_hint,
            &self.private_key,
            &self.public_key,
            &self.totp_secret,
            &self.totp_recover,
            &self.equivalent_domains,
            &self.excluded_globals,
            &self.client_kdf_type,
            &self.client_kdf_iter,
            &self.client_kdf_memory,
            &self.client_kdf_parallelism,
            &self.api_key,
            &self.avatar_color,
            &self.external_id,
        ]).await?;
        self.flag_revision(conn).await?;
        Ok(())
    }

    pub async fn delete(&self, conn: &Conn) -> ApiResult<()> {
        for user_org in UserOrganization::find_by_user_with_status(conn, self.uuid, UserOrgStatus::Confirmed).await? {
            if user_org.atype == UserOrgType::Owner
                && UserOrganization::count_confirmed_by_org_and_type(conn, user_org.organization_uuid, UserOrgType::Owner).await? <= 1
            {
                err!("Can't delete last owner")
            }
        }
        Invitation::take(conn, &self.email).await?; // Delete invitation if any
        conn.execute(r"DELETE FROM users WHERE uuid = $1", &[&self.uuid]).await?;
        Ok(())
    }

    pub async fn get(conn: &Conn, uuid: Uuid) -> ApiResult<Option<Self>> {
        Ok(conn.query_opt(r"SELECT * FROM users WHERE uuid = $1", &[&uuid]).await?.map(Into::into))
    }

    pub async fn find_by_email(conn: &Conn, email: &str) -> ApiResult<Option<Self>> {
        Ok(conn.query_opt(r"SELECT * FROM users WHERE email = $1", &[&email]).await?.map(Into::into))
    }

    pub async fn find_by_external_id(conn: &Conn, id: &str) -> ApiResult<Option<Self>> {
        Ok(conn.query_opt(r"SELECT * FROM users WHERE external_id = $1", &[&id]).await?.map(Into::into))
    }

    pub async fn get_all(conn: &Conn) -> ApiResult<Vec<Self>> {
        Ok(conn.query(r"SELECT * FROM users", &[]).await?.into_iter().map(|x| x.into()).collect())
    }

    pub async fn last_active(&self, conn: &Conn) -> ApiResult<Option<DateTime<Utc>>> {
        Ok(Device::find_latest_active_by_user(conn, self.uuid).await?.map(|x| x.updated_at))
    }
}
