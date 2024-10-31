use axol::{ErrorExt, Result};
use chrono::{DateTime, Utc};
use serde_json::{json, Value};
use tokio_postgres::Row;
use uuid::Uuid;

use crate::db::Conn;

use super::User;

#[derive(Debug)]
pub struct Folder {
    pub uuid: Uuid,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
    pub user_uuid: Uuid,
    pub name: String,
}

#[derive(Debug)]
pub struct FolderCipher {
    pub cipher_uuid: Uuid,
    pub folder_uuid: Uuid,
}

impl From<Row> for Folder {
    fn from(row: Row) -> Self {
        Self {
            uuid: row.get(0),
            updated_at: row.get(1),
            created_at: row.get(2),
            user_uuid: row.get(3),
            name: row.get(4),
        }
    }
}

impl From<Row> for FolderCipher {
    fn from(row: Row) -> Self {
        Self {
            cipher_uuid: row.get(0),
            folder_uuid: row.get(1),
        }
    }
}

impl Folder {
    pub fn new(user_uuid: Uuid, name: String) -> Self {
        let now = Utc::now();

        Self {
            uuid: Uuid::new_v4(),
            created_at: now,
            updated_at: now,
            user_uuid,
            name,
        }
    }

    pub fn to_json(&self) -> Value {
        use crate::util::format_date;

        json!({
            "id": self.uuid,
            "revisionDate": format_date(&self.updated_at),
            "name": self.name,
            "object": "folder",
        })
    }
}

impl FolderCipher {
    pub fn new(folder_uuid: Uuid, cipher_uuid: Uuid) -> Self {
        Self {
            folder_uuid,
            cipher_uuid,
        }
    }
}

impl Folder {
    pub async fn save(&mut self, conn: &Conn) -> Result<()> {
        self.updated_at = Utc::now();

        conn.execute(
            r"INSERT INTO folders (uuid, created_at, updated_at, user_uuid, name) VALUES ($1, $2, $3, $4, $5) ON CONFLICT (uuid) DO UPDATE
        SET
        created_at = EXCLUDED.created_at,
        updated_at = EXCLUDED.updated_at,
        user_uuid = EXCLUDED.user_uuid,
        name = EXCLUDED.name",
            &[&self.uuid, &self.created_at, &self.updated_at, &self.user_uuid, &self.name],
        )
        .await
        .ise()?;
        User::flag_revision_for(conn, self.user_uuid).await.ise()?;
        Ok(())
    }

    pub async fn delete(&self, conn: &Conn) -> Result<()> {
        conn.execute(r"DELETE FROM folders WHERE uuid = $1", &[&self.uuid]).await.ise()?;
        User::flag_revision_for(conn, self.user_uuid).await.ise()?;
        Ok(())
    }

    pub async fn get_with_user(conn: &Conn, uuid: Uuid, user_uuid: Uuid) -> Result<Option<Self>> {
        Ok(conn.query_opt(r"SELECT * FROM folders WHERE uuid = $1 AND user_uuid = $2", &[&uuid, &user_uuid]).await.ise()?.map(Into::into))
    }

    pub async fn find_by_user(conn: &Conn, user_uuid: Uuid) -> Result<Vec<Self>> {
        Ok(conn.query(r"SELECT * FROM folders WHERE user_uuid = $1", &[&user_uuid]).await.ise()?.into_iter().map(|x| x.into()).collect())
    }

    pub async fn delete_by_user(conn: &Conn, user_uuid: Uuid) -> Result<()> {
        User::flag_revision_for(conn, user_uuid).await.ise()?;
        conn.execute(r"DELETE FROM folders WHERE user_uuid = $1", &[&user_uuid]).await.ise()?;
        Ok(())
    }
}

impl FolderCipher {
    pub async fn save(&self, conn: &Conn) -> Result<()> {
        conn.execute(
            "INSERT INTO folder_ciphers (cipher_uuid, folder_uuid) VALUES ($1, $2) ON CONFLICT (cipher_uuid, folder_uuid) DO NOTHING",
            &[&self.cipher_uuid, &self.folder_uuid],
        )
        .await
        .ise()?;
        self.flag_revision(conn).await.ise()?;
        Ok(())
    }

    pub async fn flag_revision(&self, conn: &Conn) -> Result<()> {
        conn.execute(r"UPDATE user_revisions u SET updated_at = now() FROM folders f WHERE f.uuid = $1 AND f.user_uuid = u.uuid", &[&self.folder_uuid])
            .await
            .ise()?;
        Ok(())
    }

    pub async fn delete(&self, conn: &Conn) -> Result<()> {
        self.flag_revision(conn).await.ise()?;
        conn.execute(r"DELETE FROM folder_ciphers WHERE cipher_uuid = $1 AND folder_uuid = $2", &[&self.cipher_uuid, &self.folder_uuid]).await.ise()?;
        Ok(())
    }

    pub async fn find_by_folder_and_cipher(conn: &Conn, folder_uuid: Uuid, cipher_uuid: Uuid) -> Result<Option<Self>> {
        Ok(conn
            .query_opt(r"SELECT * FROM folder_ciphers WHERE folder_uuid = $1 AND cipher_uuid = $2", &[&folder_uuid, &cipher_uuid])
            .await
            .ise()?
            .map(Into::into))
    }
}
