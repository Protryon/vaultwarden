use axol::{ErrorExt, Result};
use chrono::Utc;
use tokio_postgres::Row;

use crate::db::Conn;

/// Server-side context for an in-flight Duo Universal (OIDC) login. Keyed by the random OAuth2
/// `state`; binds the authenticating user's email and the OIDC `nonce` so the redirect-back can be
/// validated. Rows are single-use (created on redirect-out, deleted on redirect-back) and expire
/// via `exp` (a UNIX timestamp).
pub struct TwoFactorDuoContext {
    pub state: String,
    pub user_email: String,
    pub nonce: String,
    pub exp: i64,
}

impl From<Row> for TwoFactorDuoContext {
    fn from(row: Row) -> Self {
        Self {
            state: row.get(0),
            user_email: row.get(1),
            nonce: row.get(2),
            exp: row.get(3),
        }
    }
}

impl TwoFactorDuoContext {
    pub async fn find_by_state(conn: &Conn, state: &str) -> Result<Option<Self>> {
        Ok(conn.query_opt(r"SELECT * FROM twofactor_duo_ctx WHERE state = $1", &[&state]).await.ise()?.map(Into::into))
    }

    /// Creates a new context for `state`. A saved context is immutable — if one already exists for
    /// this state (astronomically unlikely given the random 64-char state), it is left untouched.
    pub async fn save(conn: &Conn, state: &str, user_email: &str, nonce: &str, ttl_secs: i64) -> Result<()> {
        let exp = Utc::now().timestamp() + ttl_secs;
        conn.execute(
            r"INSERT INTO twofactor_duo_ctx (state, user_email, nonce, exp) VALUES ($1, $2, $3, $4) ON CONFLICT (state) DO NOTHING",
            &[&state, &user_email, &nonce, &exp],
        )
        .await
        .ise()?;
        Ok(())
    }

    pub async fn delete(&self, conn: &Conn) -> Result<()> {
        conn.execute(r"DELETE FROM twofactor_duo_ctx WHERE state = $1", &[&self.state]).await.ise()?;
        Ok(())
    }

    pub async fn purge_expired(conn: &Conn) -> Result<()> {
        conn.execute(r"DELETE FROM twofactor_duo_ctx WHERE exp < $1", &[&Utc::now().timestamp()]).await.ise()?;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::test_harness::run_db_test;

    #[tokio::test]
    async fn duo_context_save_find_delete_and_purge() {
        run_db_test(async |db| {
            let conn = db.conn();

            // Save then fetch a live context.
            TwoFactorDuoContext::save(conn, "state-live", "user@example.test", "nonce-1", 300).await.unwrap();
            let found = TwoFactorDuoContext::find_by_state(conn, "state-live").await.unwrap().expect("context exists");
            assert_eq!(found.user_email, "user@example.test");
            assert_eq!(found.nonce, "nonce-1");

            // Save is single-use: a second save for the same state does not overwrite it.
            TwoFactorDuoContext::save(conn, "state-live", "other@example.test", "nonce-2", 300).await.unwrap();
            let unchanged = TwoFactorDuoContext::find_by_state(conn, "state-live").await.unwrap().unwrap();
            assert_eq!(unchanged.user_email, "user@example.test", "existing context must not be overwritten");

            // An already-expired context (negative ttl) is removed by purge; the live one survives.
            TwoFactorDuoContext::save(conn, "state-expired", "old@example.test", "nonce-3", -1).await.unwrap();
            TwoFactorDuoContext::purge_expired(conn).await.unwrap();
            assert!(TwoFactorDuoContext::find_by_state(conn, "state-expired").await.unwrap().is_none(), "expired context purged");
            assert!(TwoFactorDuoContext::find_by_state(conn, "state-live").await.unwrap().is_some(), "live context retained");

            // Explicit delete removes the row.
            found.delete(conn).await.unwrap();
            assert!(TwoFactorDuoContext::find_by_state(conn, "state-live").await.unwrap().is_none(), "deleted context gone");
        })
        .await;
    }
}
