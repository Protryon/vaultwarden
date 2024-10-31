use axol::{Error, ErrorExt, Result};
use chrono::{DateTime, Utc};
use data_encoding::BASE64URL_NOPAD;
use log::error;
use serde_json::{json, Value};
use serde_repr::{Deserialize_repr, Serialize_repr};
use tokio_postgres::{types::Json, Row};

use crate::{db::Conn, util::LowerCase, CONFIG};

use super::User;
use uuid::Uuid;

#[derive(Debug)]
pub struct Send {
    pub uuid: Uuid,

    pub user_uuid: Option<Uuid>,
    pub organization_uuid: Option<Uuid>,

    pub name: String,
    pub notes: Option<String>,

    pub atype: SendType,
    pub data: Value,
    pub akey: String,
    pub password_hash: Option<Vec<u8>>,
    password_salt: Option<Vec<u8>>,
    password_iter: Option<i32>,

    pub max_access_count: Option<i32>,
    pub access_count: i32,

    pub creation_date: DateTime<Utc>,
    pub revision_date: DateTime<Utc>,
    pub expiration_date: Option<DateTime<Utc>>,
    pub deletion_date: DateTime<Utc>,

    pub disabled: bool,
    pub hide_email: Option<bool>,
}

impl From<Row> for Send {
    fn from(row: Row) -> Self {
        Self {
            uuid: row.get(0),
            user_uuid: row.get(1),
            organization_uuid: row.get(2),
            name: row.get(3),
            notes: row.get(4),
            atype: SendType::from_repr(row.get(5)).unwrap_or(SendType::Unknown),
            data: row.get::<_, Json<LowerCase<Value>>>(6).0.data,
            akey: row.get(7),
            password_hash: row.get(8),
            password_salt: row.get(9),
            password_iter: row.get(10),
            max_access_count: row.get(11),
            access_count: row.get(12),
            creation_date: row.get(13),
            revision_date: row.get(14),
            expiration_date: row.get(15),
            deletion_date: row.get(16),
            disabled: row.get(17),
            hide_email: row.get(18),
        }
    }
}

#[derive(Copy, Clone, PartialEq, Eq, strum::FromRepr, Debug, Serialize_repr, Deserialize_repr)]
#[repr(i32)]
pub enum SendType {
    Text = 0,
    File = 1,
    Unknown = i32::MAX,
}

impl Send {
    pub fn new(atype: SendType, name: String, data: Value, akey: String, deletion_date: DateTime<Utc>) -> Self {
        let now = Utc::now();

        Self {
            uuid: Uuid::new_v4(),
            user_uuid: None,
            organization_uuid: None,

            name,
            notes: None,

            atype,
            data,
            akey,
            password_hash: None,
            password_salt: None,
            password_iter: None,

            max_access_count: None,
            access_count: 0,

            creation_date: now,
            revision_date: now,
            expiration_date: None,
            deletion_date,

            disabled: false,
            hide_email: None,
        }
    }

    pub fn set_password(&mut self, password: Option<&str>) {
        const PASSWORD_ITER: i32 = 100_000;

        if let Some(password) = password {
            self.password_iter = Some(PASSWORD_ITER);
            let salt = crate::crypto::get_random_bytes::<64>().to_vec();
            let hash = crate::crypto::hash_password(password.as_bytes(), &salt, PASSWORD_ITER as u32);
            self.password_salt = Some(salt);
            self.password_hash = Some(hash);
        } else {
            self.password_iter = None;
            self.password_salt = None;
            self.password_hash = None;
        }
    }

    pub fn check_password(&self, password: &str) -> bool {
        match (&self.password_hash, &self.password_salt, self.password_iter) {
            (Some(hash), Some(salt), Some(iter)) => crate::crypto::verify_password_hash(password.as_bytes(), salt, hash, iter as u32),
            _ => false,
        }
    }

    pub async fn creator_identifier(&self, conn: &Conn) -> Result<Option<String>> {
        if let Some(hide_email) = self.hide_email {
            if hide_email {
                return Ok(None);
            }
        }

        if let Some(user_uuid) = self.user_uuid {
            if let Some(user) = User::get(conn, user_uuid).await.ise()? {
                return Ok(Some(user.email));
            }
        }

        Ok(None)
    }

    pub fn to_json(&self) -> Value {
        use crate::util::format_date;

        let mut data = self.data.clone();

        if let Some(size) = data.get("size").and_then(|v| v.as_i64()) {
            data["size"] = Value::String(size.to_string());
        }

        json!({
            "id": self.uuid,
            "accessId": BASE64URL_NOPAD.encode(self.uuid.as_bytes()),
            "type": self.atype as i32,

            "name": self.name,
            "notes": self.notes,
            "text": if self.atype == SendType::Text { Some(&data) } else { None },
            "file": if self.atype == SendType::File { Some(&data) } else { None },

            "key": self.akey,
            "maxAccessCount": self.max_access_count,
            "accessCount": self.access_count,
            "password": self.password_hash.as_deref().map(|h| BASE64URL_NOPAD.encode(h)),
            "disabled": self.disabled,
            "hideEmail": self.hide_email,

            "revisionDate": format_date(&self.revision_date),
            "expirationDate": self.expiration_date.as_ref().map(format_date),
            "deletionDate": format_date(&self.deletion_date),
            "object": "send",
        })
    }

    pub async fn to_json_access(&self, conn: &Conn) -> Result<Value> {
        use crate::util::format_date;

        let mut data = self.data.clone();

        // Mobile clients expect size to be a string instead of a number
        if let Some(size) = data.get("size").and_then(|v| v.as_i64()) {
            data["size"] = Value::String(size.to_string());
        }

        Ok(json!({
            "id": self.uuid,
            "type": self.atype as i32,

            "name": self.name,
            "text": if self.atype == SendType::Text { Some(&data) } else { None },
            "file": if self.atype == SendType::File { Some(&data) } else { None },

            "expirationDate": self.expiration_date.as_ref().map(format_date),
            "creatorIdentifier": self.creator_identifier(conn).await.ise()?,
            "object": "send-access",
        }))
    }
}

impl Send {
    pub fn decode_access_id(access_id: &str) -> Result<Uuid> {
        let uuid_vec = match BASE64URL_NOPAD.decode(access_id.as_bytes()) {
            Ok(v) => v,
            Err(_) => return Err(Error::bad_request("invalid access id")),
        };

        Uuid::from_slice(&uuid_vec).map_err(|_| Error::bad_request("invalid access id"))
    }

    pub async fn save(&mut self, conn: &Conn) -> Result<()> {
        self.revision_date = Utc::now();

        conn.execute(r"INSERT INTO sends (uuid, user_uuid, organization_uuid, name, notes, atype, data, akey, password_hash, password_salt, password_iter, max_access_count, access_count, creation_date, revision_date, expiration_date, deletion_date, disabled, hide_email) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14, $15, $16, $17, $18, $19) ON CONFLICT (uuid) DO UPDATE
        SET
        uuid = EXCLUDED.uuid,
        user_uuid = EXCLUDED.user_uuid,
        organization_uuid = EXCLUDED.organization_uuid,
        name = EXCLUDED.name,
        notes = EXCLUDED.notes,
        atype = EXCLUDED.atype,
        data = EXCLUDED.data,
        akey = EXCLUDED.akey,
        password_hash = EXCLUDED.password_hash,
        password_salt = EXCLUDED.password_salt,
        password_iter = EXCLUDED.password_iter,
        max_access_count = EXCLUDED.max_access_count,
        access_count = EXCLUDED.access_count,
        creation_date = EXCLUDED.creation_date,
        revision_date = EXCLUDED.revision_date,
        expiration_date = EXCLUDED.expiration_date,
        deletion_date = EXCLUDED.deletion_date,
        disabled = EXCLUDED.disabled,
        hide_email = EXCLUDED.hide_email", &[
            &self.uuid,
            &self.user_uuid,
            &self.organization_uuid,
            &self.name,
            &self.notes,
            &(self.atype as i32),
            &self.data,
            &self.akey,
            &self.password_hash,
            &self.password_salt,
            &self.password_iter,
            &self.max_access_count,
            &self.access_count,
            &self.creation_date,
            &self.revision_date,
            &self.expiration_date,
            &self.deletion_date,
            &self.disabled,
            &self.hide_email,
        ]).await.ise()?;
        if let Some(uuid) = self.user_uuid {
            User::flag_revision_for(conn, uuid).await.ise()?;
        }
        Ok(())
    }

    pub async fn delete(&self, conn: &mut Conn) -> Result<()> {
        let txn = conn.transaction().await.ise()?;
        txn.execute(r"DELETE FROM sends WHERE uuid = $1", &[&self.uuid]).await.ise()?;
        if self.atype == SendType::File {
            tokio::fs::remove_dir_all(CONFIG.folders.sends().join(self.uuid.to_string())).await.ise()?;
        }
        if let Some(uuid) = self.user_uuid {
            User::flag_revision_for(txn.client(), uuid).await.ise()?;
        }
        txn.commit().await.ise()?;
        Ok(())
    }

    /// Purge all sends that are past their deletion date.
    pub async fn purge(conn: &mut Conn) -> Result<()> {
        for send in Self::find_by_past_deletion_date(conn).await.ise()? {
            if let Err(e) = send.delete(conn).await {
                error!("failed to purge send {}: {e}", send.uuid);
            }
        }
        Ok(())
    }

    pub async fn find_by_past_deletion_date(conn: &Conn) -> Result<Vec<Self>> {
        Ok(conn.query(r"SELECT * FROM sends WHERE deletion_date < $1", &[&Utc::now()]).await.ise()?.into_iter().map(|x| x.into()).collect())
    }

    pub async fn get(conn: &Conn, uuid: Uuid) -> Result<Option<Self>> {
        Ok(conn.query_opt(r"SELECT * FROM sends WHERE uuid = $1", &[&uuid]).await.ise()?.map(Into::into))
    }

    pub async fn get_for_user(conn: &Conn, uuid: Uuid, user_uuid: Uuid) -> Result<Option<Self>> {
        Ok(conn.query_opt(r"SELECT * FROM sends WHERE uuid = $1 AND user_uuid = $2", &[&uuid, &user_uuid]).await.ise()?.map(Into::into))
    }

    pub async fn find_by_user(conn: &Conn, user_uuid: Uuid) -> Result<Vec<Self>> {
        Ok(conn.query(r"SELECT * FROM sends WHERE user_uuid = $1", &[&user_uuid]).await.ise()?.into_iter().map(|x| x.into()).collect())
    }
}
