use axol::{ErrorExt, Result};
use chrono::{DateTime, Utc};
use serde_json::{json, Value};

use serde_repr::{Deserialize_repr, Serialize_repr};
use tokio_postgres::Row;
use uuid::Uuid;

use crate::db::Conn;

pub struct TwoFactor {
    pub user_uuid: Uuid,
    pub atype: TwoFactorType,
    pub enabled: bool,
    pub data: Value,
    pub last_used: Option<DateTime<Utc>>,
}

impl From<Row> for TwoFactor {
    fn from(row: Row) -> Self {
        Self {
            user_uuid: row.get(0),
            atype: TwoFactorType::from_repr(row.get(1)).unwrap_or(TwoFactorType::Unknown),
            enabled: row.get(2),
            data: row.get(3),
            last_used: row.get(4),
        }
    }
}

#[allow(dead_code)]
#[derive(Serialize_repr, Deserialize_repr, strum::FromRepr, Clone, Copy, Debug, PartialEq, Eq)]
#[repr(i32)]
pub enum TwoFactorType {
    Authenticator = 0,
    Email = 1,
    Duo = 2,
    YubiKey = 3,
    U2f = 4,
    Remember = 5,
    OrganizationDuo = 6,
    Webauthn = 7,

    // These are implementation details
    U2fRegisterChallenge = 1000,
    U2fLoginChallenge = 1001,
    EmailVerificationChallenge = 1002,
    WebauthnRegisterChallenge = 1003,
    WebauthnLoginChallenge = 1004,

    Unknown = i32::MAX,
}

/// Local methods
impl TwoFactor {
    pub fn new(user_uuid: Uuid, atype: TwoFactorType, data: Value) -> Self {
        Self {
            user_uuid,
            atype,
            enabled: true,
            data,
            last_used: None,
        }
    }

    #[allow(dead_code)]
    pub fn to_json(&self) -> Value {
        json!({
            "enabled": self.enabled,
            "tey": "", // This key and value vary
            "object": "twoFactorAuthenticator" // This value varies
        })
    }

    pub fn to_json_provider(&self) -> Value {
        json!({
            "enabled": self.enabled,
            "type": self.atype as i32,
            "object": "twoFactorProvider"
        })
    }
}

/// Database methods
impl TwoFactor {
    pub async fn save(&self, conn: &Conn) -> Result<()> {
        conn.execute(
            r"INSERT INTO twofactor (user_uuid, atype, enabled, data, last_used) VALUES ($1, $2, $3, $4, $5, $6) ON CONFLICT (user_uuid, atype) DO UPDATE
        SET
        enabled = EXCLUDED.enabled,
        data = EXCLUDED.data,
        last_used = EXCLUDED.last_used",
            &[&self.user_uuid, &(self.atype as i32), &self.enabled, &self.data, &self.last_used],
        )
        .await
        .ise()?;
        Ok(())
    }

    pub async fn delete(&self, conn: &Conn) -> Result<()> {
        conn.execute(r"DELETE FROM twofactor WHERE user_uuid = $1 AND atype = $2", &[&self.user_uuid, &(self.atype as i32)]).await.ise()?;
        Ok(())
    }

    pub async fn find_by_user_official(conn: &Conn, user_uuid: Uuid) -> Result<Vec<Self>> {
        Ok(conn.query(r"SELECT * FROM twofactor WHERE user_uuid = $1 AND atype < 1000", &[&user_uuid]).await.ise()?.into_iter().map(|x| x.into()).collect())
    }

    pub async fn find_by_user_and_type(conn: &Conn, user_uuid: Uuid, atype: TwoFactorType) -> Result<Option<Self>> {
        Ok(conn.query_opt(r"SELECT * FROM twofactor WHERE user_uuid = $1 AND atype = $2", &[&user_uuid, &(atype as i32)]).await.ise()?.map(Into::into))
    }

    pub async fn delete_all_by_user(conn: &Conn, user_uuid: Uuid) -> Result<()> {
        conn.execute(r"DELETE FROM twofactor WHERE user_uuid = $1", &[&user_uuid]).await.ise()?;
        Ok(())
    }
}
