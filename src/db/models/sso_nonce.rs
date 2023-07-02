use axum_util::errors::ApiResult;
use chrono::{DateTime, Utc};
use tokio_postgres::Row;

use crate::db::Conn;

pub struct SsoNonce {
    pub nonce: String,
    pub created_at: DateTime<Utc>,
}

/// Local methods
impl SsoNonce {
    pub fn new(nonce: String) -> Self {
        Self {
            nonce,
            created_at: Utc::now(),
        }
    }
}

impl From<Row> for SsoNonce {
    fn from(row: Row) -> Self {
        Self {
            nonce: row.get(0),
            created_at: row.get(1),
        }
    }
}

/// Database methods
impl SsoNonce {
    pub async fn save(&self, conn: &Conn) -> ApiResult<()> {
        conn.execute(r"INSERT INTO sso_nonces (nonce, created_at) VALUES ($1, $2)", &[&self.nonce, &self.created_at]).await?;
        Ok(())
    }

    pub async fn delete(&self, conn: &Conn) -> ApiResult<()> {
        conn.execute(r"DELETE FROM sso_nonces WHERE nonce = $1", &[&self.nonce]).await?;
        Ok(())
    }

    pub async fn purge_expired(conn: &Conn, expire_before: DateTime<Utc>) -> ApiResult<()> {
        conn.execute(r"DELETE FROM sso_nonces WHERE created_at < $1", &[&expire_before]).await?;
        Ok(())
    }

    pub async fn get(conn: &Conn, nonce: &str) -> ApiResult<Option<Self>> {
        Ok(conn.query_opt(r"SELECT * FROM sso_nonces WHERE nonce = $1", &[&nonce]).await?.map(Into::into))
    }
}
