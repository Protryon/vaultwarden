use axum_util::errors::{ApiError, ApiResult};
use serde_json::{json, Value};

use tokio_postgres::Row;
use uuid::Uuid;

use crate::db::Conn;

use super::{cipher::AccessRestrictions, User};

#[derive(Debug)]
pub struct Collection {
    pub uuid: Uuid,
    pub organization_uuid: Uuid,
    pub name: String,
}

#[derive(Debug)]
pub struct CollectionUser {
    pub user_uuid: Uuid,
    pub collection_uuid: Uuid,
    pub read_only: bool,
    pub hide_passwords: bool,
}

#[derive(Debug)]
pub struct CollectionCipher {
    pub cipher_uuid: Uuid,
    pub collection_uuid: Uuid,
}

impl From<Row> for Collection {
    fn from(row: Row) -> Self {
        Self {
            uuid: row.get(0),
            organization_uuid: row.get(1),
            name: row.get(2),
        }
    }
}

impl From<Row> for CollectionUser {
    fn from(row: Row) -> Self {
        Self {
            user_uuid: row.get(0),
            collection_uuid: row.get(1),
            read_only: row.get(2),
            hide_passwords: row.get(3),
        }
    }
}

impl From<Row> for CollectionCipher {
    fn from(row: Row) -> Self {
        Self {
            cipher_uuid: row.get(0),
            collection_uuid: row.get(1),
        }
    }
}

impl Collection {
    pub fn new(organization_uuid: Uuid, name: String) -> Self {
        Self {
            uuid: Uuid::new_v4(),

            organization_uuid,
            name,
        }
    }

    pub fn to_json(&self) -> Value {
        json!({
            "ExternalId": null, // Not support by us
            "Id": self.uuid,
            "OrganizationId": self.organization_uuid,
            "Name": self.name,
            "Object": "collection",
        })
    }

    pub async fn to_json_details(&self, conn: &Conn, user_uuid: Uuid) -> ApiResult<Value> {
        let access = self.get_access_restrictions(conn, user_uuid).await?.ok_or(ApiError::NotFound)?;

        let mut json_object = self.to_json();
        json_object["Object"] = json!("collectionDetails");
        json_object["ReadOnly"] = json!(access.read_only);
        json_object["HidePasswords"] = json!(access.hide_passwords);
        Ok(json_object)
    }
}

impl Collection {
    pub async fn save(&self, conn: &Conn) -> ApiResult<()> {
        conn.execute(
            r"INSERT INTO collections (uuid, organization_uuid, name) VALUES ($1, $2, $3) ON CONFLICT (uuid) DO UPDATE
        SET
        organization_uuid = EXCLUDED.organization_uuid,
        name = EXCLUDED.name",
            &[&self.uuid, &self.organization_uuid, &self.name],
        )
        .await?;
        Self::flag_revision(conn, self.uuid).await?;
        Ok(())
    }

    pub async fn flag_revision(conn: &Conn, uuid: Uuid) -> ApiResult<()> {
        conn.execute(r"UPDATE user_revisions u SET updated_at = now() FROM user_collection_auth uca WHERE uca.collection_uuid = $1 AND uca.user_uuid = u.uuid", &[&uuid]).await?;
        Ok(())
    }

    pub async fn delete(&self, conn: &Conn) -> ApiResult<()> {
        Self::flag_revision(conn, self.uuid).await?;
        conn.execute(r"DELETE FROM collections WHERE uuid = $1", &[&self.uuid]).await?;
        Ok(())
    }

    pub async fn get(conn: &Conn, uuid: Uuid) -> ApiResult<Option<Self>> {
        Ok(conn.query_opt(r"SELECT * FROM collections WHERE uuid = $1", &[&uuid]).await?.map(Into::into))
    }

    pub async fn get_for_org(conn: &Conn, organization_uuid: Uuid, uuid: Uuid) -> ApiResult<Option<Self>> {
        Ok(conn.query_opt(r"SELECT * FROM collections c WHERE uuid = $2 AND organization_uuid = $1", &[&organization_uuid, &uuid]).await?.map(Into::into))
    }

    pub async fn get_for_user_writable(conn: &Conn, user_uuid: Uuid, uuid: Uuid) -> ApiResult<Option<Self>> {
        Ok(conn.query_opt(r"SELECT * FROM collections c INNER JOIN user_collection_auth uca ON uca.collection_uuid = c.uuid AND uca.user_uuid = $1 WHERE uuid = $2 AND NOT uca.read_only", &[&user_uuid, &uuid]).await?.map(Into::into))
    }

    pub async fn find_by_user(conn: &Conn, user_uuid: Uuid, visible_only: bool) -> ApiResult<Vec<Self>> {
        //TODO: implement visible_only
        Ok(conn
            .query(
                r"
        SELECT co.*
        FROM collections co
        INNER JOIN user_collection_auth uca ON uca.collection_uuid = co.uuid AND uca.user_uuid = $1
        ",
                &[&user_uuid],
            )
            .await?
            .into_iter()
            .map(|x| x.into())
            .collect())
    }

    pub async fn find_by_organization(conn: &Conn, organization_uuid: Uuid) -> ApiResult<Vec<Self>> {
        Ok(conn
            .query(
                r"
        SELECT co.*
        FROM collections co
        WHERE co.organization_uuid = $1
        ",
                &[&organization_uuid],
            )
            .await?
            .into_iter()
            .map(|x| x.into())
            .collect())
    }

    pub async fn count_by_org(conn: &Conn, organization_uuid: Uuid) -> ApiResult<i64> {
        Ok(conn.query_one(r"SELECT count(1) FROM collections WHERE organization_uuid = $1", &[&organization_uuid]).await?.get(0))
    }

    pub async fn find_by_uuid_and_org(conn: &Conn, uuid: Uuid, organization_uuid: Uuid) -> ApiResult<Option<Self>> {
        Ok(conn.query_opt(r"SELECT * FROM collections WHERE uuid = $1 AND organization_uuid = $2", &[&uuid, &organization_uuid]).await?.map(Into::into))
    }

    pub async fn find_by_uuid_and_user(conn: &Conn, uuid: Uuid, user_uuid: Uuid) -> ApiResult<Option<Self>> {
        Ok(conn
            .query_opt(
                r"
        SELECT co.*
        FROM collections co
        INNER JOIN user_collection_auth uca ON uca.collection_uuid = co.uuid AND uca.user_uuid = $1
        WHERE co.uuid = $2
        ",
                &[&user_uuid, &uuid],
            )
            .await?
            .map(Into::into))
    }

    pub async fn find_by_uuid_and_user_writable(conn: &Conn, uuid: Uuid, user_uuid: Uuid) -> ApiResult<Option<Self>> {
        Ok(conn
            .query_opt(
                r"
        SELECT co.*
        FROM collections co
        INNER JOIN user_collection_auth uca ON uca.collection_uuid = co.uuid AND uca.user_uuid = $1 AND NOT uca.read_only
        WHERE co.uuid = $2
        ",
                &[&user_uuid, &uuid],
            )
            .await?
            .map(Into::into))
    }

    pub async fn get_access_restrictions(&self, conn: &Conn, user_uuid: Uuid) -> ApiResult<Option<AccessRestrictions>> {
        Ok(conn
            .query_opt(r"SELECT read_only, hide_passwords FROM user_collection_auth WHERE user_uuid = $1 AND collection_uuid = $2", &[&user_uuid, &self.uuid])
            .await?
            .map(|x| AccessRestrictions {
                read_only: x.get(0),
                hide_passwords: x.get(1),
            }))
    }
}

impl CollectionUser {
    pub async fn find_by_organization_and_user_uuid(conn: &Conn, organization_uuid: Uuid, user_uuid: Uuid) -> ApiResult<Vec<Self>> {
        Ok(conn
            .query(
                r"
        SELECT cu.*
        FROM collection_users cu
        INNER JOIN user_collection_auth uca ON uca.collection_uuid = cu.collection_uuid AND uca.user_uuid = $1
        INNER JOIN collections co ON co.uuid = cu.collection_uuid
        WHERE co.organization_uuid = $2
        ",
                &[&user_uuid, &organization_uuid],
            )
            .await?
            .into_iter()
            .map(|x| x.into())
            .collect())
    }

    pub async fn find_by_organization(conn: &Conn, organization_uuid: Uuid) -> ApiResult<Vec<Self>> {
        Ok(conn
            .query(
                r"
        SELECT cu.*
        FROM collection_users cu
        INNER JOIN collections co ON co.uuid = cu.collection_uuid
        WHERE co.organization_uuid = $1
        ",
                &[&organization_uuid],
            )
            .await?
            .into_iter()
            .map(|x| x.into())
            .collect())
    }

    pub async fn save(&self, conn: &Conn) -> ApiResult<()> {
        conn.execute(r"INSERT INTO collection_users (user_uuid, collection_uuid, read_only, hide_passwords) VALUES ($1, $2, $3, $4) ON CONFLICT (user_uuid, collection_uuid) DO UPDATE
        SET
        read_only = EXCLUDED.read_only,
        hide_passwords = EXCLUDED.hide_passwords", &[
            &self.user_uuid,
            &self.collection_uuid,
            &self.read_only,
            &self.hide_passwords,
        ]).await?;
        User::flag_revision_for(conn, self.user_uuid).await?;
        Ok(())
    }

    pub async fn delete(&self, conn: &Conn) -> ApiResult<()> {
        User::flag_revision_for(conn, self.user_uuid).await?;
        conn.execute(r"DELETE FROM collection_users WHERE user_uuid = $1 AND collection_uuid = $2", &[&self.user_uuid, &self.collection_uuid]).await?;
        Ok(())
    }

    pub async fn find_by_collection(conn: &Conn, collection_uuid: Uuid) -> ApiResult<Vec<Self>> {
        Ok(conn
            .query(r"SELECT cu.* FROM collection_users cu WHERE cu.collection_uuid = $1", &[&collection_uuid])
            .await?
            .into_iter()
            .map(|x| x.into())
            .collect())
    }

    pub async fn find_by_collection_and_user(conn: &Conn, collection_uuid: Uuid, user_uuid: Uuid) -> ApiResult<Option<Self>> {
        Ok(conn
            .query_opt(r"SELECT cu.* FROM collection_users cu WHERE cu.collection_uuid = $1 AND cu.user_uuid = $2", &[&collection_uuid, &user_uuid])
            .await?
            .map(Into::into))
    }

    pub async fn delete_all_by_collection(conn: &Conn, collection_uuid: Uuid) -> ApiResult<()> {
        Collection::flag_revision(conn, collection_uuid).await?;
        conn.execute(r"DELETE FROM collection_users WHERE collection_uuid = $1", &[&collection_uuid]).await?;
        Ok(())
    }
}

/// Database methods
impl CollectionCipher {
    pub async fn save(conn: &Conn, cipher_uuid: Uuid, collection_uuid: Uuid) -> ApiResult<()> {
        conn.execute(
            "INSERT INTO collection_ciphers (cipher_uuid, collection_uuid) VALUES ($1, $2) ON CONFLICT (cipher_uuid, collection_uuid) DO NOTHING",
            &[&cipher_uuid, &collection_uuid],
        )
        .await?;
        Collection::flag_revision(conn, collection_uuid).await?;
        Ok(())
    }

    pub async fn delete(conn: &Conn, cipher_uuid: Uuid, collection_uuid: Uuid) -> ApiResult<()> {
        Collection::flag_revision(conn, collection_uuid).await?;
        conn.execute(r"DELETE FROM collection_ciphers WHERE cipher_uuid = $1 AND collection_uuid = $2", &[&cipher_uuid, &collection_uuid]).await?;
        Ok(())
    }
}
