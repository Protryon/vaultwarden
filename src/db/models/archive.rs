use axol::{ErrorExt, Result};
use chrono::{DateTime, Utc};
use uuid::Uuid;

use crate::db::Conn;

use super::User;

/// A per-user record marking a cipher as archived, with the timestamp it was archived.
pub struct Archive;

impl Archive {
    /// Returns the date the specified cipher was archived for this user, if any.
    pub async fn get_archived_at(conn: &Conn, user_uuid: Uuid, cipher_uuid: Uuid) -> Result<Option<DateTime<Utc>>> {
        Ok(conn
            .query_opt(r"SELECT archived_at FROM archives WHERE user_uuid = $1 AND cipher_uuid = $2", &[&user_uuid, &cipher_uuid])
            .await
            .ise()?
            .map(|row| row.get(0)))
    }

    /// Inserts or updates an archive record with the provided timestamp.
    pub async fn save(conn: &Conn, user_uuid: Uuid, cipher_uuid: Uuid, archived_at: DateTime<Utc>) -> Result<()> {
        conn.execute(
            r"INSERT INTO archives (user_uuid, cipher_uuid, archived_at) VALUES ($1, $2, $3)
        ON CONFLICT (user_uuid, cipher_uuid) DO UPDATE SET archived_at = EXCLUDED.archived_at",
            &[&user_uuid, &cipher_uuid, &archived_at],
        )
        .await
        .ise()?;
        User::flag_revision_for(conn, user_uuid).await?;
        Ok(())
    }

    /// Deletes the archive record for a specific cipher.
    pub async fn delete_by_cipher(conn: &Conn, user_uuid: Uuid, cipher_uuid: Uuid) -> Result<()> {
        conn.execute(r"DELETE FROM archives WHERE user_uuid = $1 AND cipher_uuid = $2", &[&user_uuid, &cipher_uuid]).await.ise()?;
        User::flag_revision_for(conn, user_uuid).await?;
        Ok(())
    }
}
