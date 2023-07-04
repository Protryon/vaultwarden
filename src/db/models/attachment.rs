use std::{io::ErrorKind, path::PathBuf};

use axum_util::errors::ApiResult;
use log::debug;
use serde_json::{json, Value};
use tokio_postgres::Row;
use url::Url;
use uuid::Uuid;

use crate::{db::Conn, CONFIG};

use super::Cipher;

#[derive(Debug, Clone)]
pub struct Attachment {
    pub uuid: Uuid,
    pub cipher_uuid: Uuid,
    pub file_name: String,
    pub file_size: i32,
    pub akey: Option<String>,
}

impl From<Row> for Attachment {
    fn from(row: Row) -> Self {
        Self {
            uuid: row.get(0),
            cipher_uuid: row.get(1),
            file_name: row.get(2),
            file_size: row.get(3),
            akey: row.get(4),
        }
    }
}

impl Attachment {
    pub const fn new(uuid: Uuid, cipher_uuid: Uuid, file_name: String, file_size: i32, akey: Option<String>) -> Self {
        Self {
            uuid,
            cipher_uuid,
            file_name,
            file_size,
            akey,
        }
    }

    pub fn get_file_path(&self) -> PathBuf {
        CONFIG.folders.attachments().join(self.cipher_uuid.to_string()).join(self.uuid.to_string())
    }

    pub fn get_url(&self) -> Url {
        let mut url = CONFIG.settings.public.clone();
        url.path_segments_mut().unwrap().push("attachments");
        url.path_segments_mut().unwrap().push(&self.cipher_uuid.to_string());
        url.path_segments_mut().unwrap().push(&self.uuid.to_string());
        url
    }

    pub fn to_json(&self) -> Value {
        json!({
            "Id": self.uuid,
            "Url": self.get_url(),
            "FileName": self.file_name,
            "Size": self.file_size.to_string(),
            "SizeName": crate::util::get_display_size(self.file_size),
            "Key": self.akey,
            "Object": "attachment"
        })
    }
}

/// Database methods
impl Attachment {
    pub async fn save(&self, conn: &Conn) -> ApiResult<()> {
        conn.execute(
            r"INSERT INTO attachments (uuid, cipher_uuid, file_name, file_size, akey) VALUES ($1, $2, $3, $4, $5) ON CONFLICT (uuid) DO UPDATE
        SET
        cipher_uuid = EXCLUDED.cipher_uuid,
        file_name = EXCLUDED.file_name,
        file_size = EXCLUDED.file_size,
        akey = EXCLUDED.akey",
            &[&self.uuid, &self.cipher_uuid, &self.file_name, &self.file_size, &self.akey],
        )
        .await?;
        Cipher::flag_revision(conn, self.cipher_uuid).await?;
        Ok(())
    }

    pub async fn delete(&self, conn: &Conn) -> ApiResult<()> {
        conn.execute(r"DELETE FROM attachments WHERE uuid = $1", &[&self.uuid]).await?;
        Cipher::flag_revision(conn, self.cipher_uuid).await?;
        self.delete_file().await?;
        Ok(())
    }

    async fn delete_file(&self) -> ApiResult<()> {
        let file_path = self.get_file_path();
        match crate::util::delete_file(&file_path).await {
            // Ignore "file not found" errors. This can happen when the
            // upstream caller has already cleaned up the file as part of
            // its own error handling.
            Err(e) if e.kind() == ErrorKind::NotFound => {
                debug!("File '{}' already deleted.", file_path.display());
                Ok(())
            }
            Err(e) => Err(e.into()),
            _ => Ok(()),
        }
    }

    pub async fn get(conn: &Conn, uuid: Uuid) -> ApiResult<Option<Self>> {
        Ok(conn.query_opt(r"SELECT * FROM attachments WHERE uuid = $1", &[&uuid]).await?.map(Into::into))
    }

    pub async fn get_with_cipher(conn: &Conn, uuid: Uuid, cipher_uuid: Uuid) -> ApiResult<Option<Self>> {
        Ok(conn.query_opt(r"SELECT * FROM attachments WHERE uuid = $1 AND cipher_uuid = $2", &[&uuid, &cipher_uuid]).await?.map(Into::into))
    }

    pub async fn get_with_cipher_and_user(conn: &Conn, uuid: Uuid, cipher_uuid: Uuid, user_uuid: Uuid) -> ApiResult<Option<Self>> {
        Ok(conn
            .query_opt(
                r"
            SELECT a.* FROM attachments a
            INNER JOIN user_cipher_auth uca ON uca.cipher_uuid = a.cipher_uuid AND uca.user_uuid = $3
            WHERE a.uuid = $1 AND a.cipher_uuid = $2",
                &[&uuid, &cipher_uuid, &user_uuid],
            )
            .await?
            .map(Into::into))
    }

    pub async fn get_with_cipher_and_user_writable(conn: &Conn, uuid: Uuid, cipher_uuid: Uuid, user_uuid: Uuid) -> ApiResult<Option<Self>> {
        Ok(conn
            .query_opt(
                r"
            SELECT a.* FROM attachments a
            INNER JOIN user_cipher_auth uca ON uca.cipher_uuid = a.cipher_uuid AND uca.user_uuid = $3 AND NOT uca.read_only
            WHERE a.uuid = $1 AND a.cipher_uuid = $2",
                &[&uuid, &cipher_uuid, &user_uuid],
            )
            .await?
            .map(Into::into))
    }

    pub async fn find_by_user(conn: &Conn, user_uuid: Uuid) -> ApiResult<Vec<Self>> {
        Ok(conn
            .query_opt(
                r"
            SELECT a.* FROM attachments a
            INNER JOIN user_cipher_auth uca ON uca.cipher_uuid = a.cipher_uuid AND uca.user_uuid = $1",
                &[&user_uuid],
            )
            .await?
            .into_iter()
            .map(|x| x.into())
            .collect())
    }

    pub async fn find_by_cipher(conn: &Conn, cipher_uuid: Uuid) -> ApiResult<Vec<Self>> {
        Ok(conn.query(r"SELECT * FROM attachments WHERE cipher_uuid = $1", &[&cipher_uuid]).await?.into_iter().map(|x| x.into()).collect())
    }

    pub async fn size_count_by_user(conn: &Conn, user_uuid: Uuid) -> ApiResult<(i64, i64)> {
        let row = conn
            .query_one(
                r"
            SELECT coalesce(sum(a.file_size), 0), coalesce(count(a.uuid), 0)
            FROM attachments a
            INNER JOIN ciphers c ON c.uuid = a.cipher_uuid
            WHERE c.user_uuid = $1
        ",
                &[&user_uuid],
            )
            .await?;
        Ok((row.get(0), row.get(1)))
    }

    pub async fn size_count_by_organization(conn: &Conn, organization_uuid: Uuid) -> ApiResult<(i64, i64)> {
        let row = conn
            .query_one(
                r"
            SELECT coalesce(sum(a.file_size), 0), coalesce(count(a.uuid), 0)
            FROM attachments a
            INNER JOIN ciphers c ON c.uuid = a.cipher_uuid
            WHERE c.organization_uuid = $1
        ",
                &[&organization_uuid],
            )
            .await?;
        Ok((row.get(0), row.get(1)))
    }
}
