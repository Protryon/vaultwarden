use axol::{ErrorExt, Result};
use serde_json::{json, Value};

use tokio_postgres::Row;
use uuid::Uuid;

use crate::{db::Conn, util::RowSlice};

use super::{cipher::AccessRestrictions, User};

#[derive(Debug)]
pub struct Collection {
    pub uuid: Uuid,
    pub organization_uuid: Uuid,
    pub name: String,
}

#[derive(Debug)]
pub struct CollectionWithAccess {
    pub collection: Collection,
    pub access: AccessRestrictions,
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

impl<'a> From<RowSlice<'a>> for Collection {
    fn from(row: RowSlice<'a>) -> Self {
        Self {
            uuid: row.get(0),
            organization_uuid: row.get(1),
            name: row.get(2),
        }
    }
}

impl From<Row> for Collection {
    fn from(row: Row) -> Self {
        RowSlice::new(&row).into()
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
}

impl CollectionWithAccess {
    pub fn to_json_details(&self) -> Value {
        let mut json_object = self.collection.to_json();
        json_object["Object"] = json!("collectionDetails");
        json_object["ReadOnly"] = json!(self.access.read_only);
        json_object["HidePasswords"] = json!(self.access.hide_passwords);
        json_object
    }

    pub async fn find_by_user(conn: &Conn, user_uuid: Uuid) -> Result<Vec<Self>> {
        Ok(conn
            .query(
                r"
        SELECT uca.read_only, uca.hide_passwords, co.*
        FROM collections co
        INNER JOIN user_collection_auth uca ON uca.collection_uuid = co.uuid AND uca.user_uuid = $1
        ",
                &[&user_uuid],
            )
            .await
            .ise()?
            .into_iter()
            .map(|row| {
                let collection: Collection = RowSlice::new(&row).slice_from(2..).into();
                CollectionWithAccess {
                    collection,
                    access: AccessRestrictions {
                        read_only: row.get(0),
                        hide_passwords: row.get(1),
                    },
                }
            })
            .collect())
    }
}

impl Collection {
    pub async fn save(&self, conn: &Conn) -> Result<()> {
        conn.execute(
            r"INSERT INTO collections (uuid, organization_uuid, name) VALUES ($1, $2, $3) ON CONFLICT (uuid) DO UPDATE
        SET
        organization_uuid = EXCLUDED.organization_uuid,
        name = EXCLUDED.name",
            &[&self.uuid, &self.organization_uuid, &self.name],
        )
        .await
        .ise()?;
        Self::flag_revision(conn, self.uuid).await.ise()?;
        Ok(())
    }

    pub async fn flag_revision(conn: &Conn, uuid: Uuid) -> Result<()> {
        conn.execute(
            r"UPDATE user_revisions u SET updated_at = now() FROM user_collection_auth uca WHERE uca.collection_uuid = $1 AND uca.user_uuid = u.uuid",
            &[&uuid],
        )
        .await
        .ise()?;
        Ok(())
    }

    pub async fn delete(&self, conn: &Conn) -> Result<()> {
        Self::flag_revision(conn, self.uuid).await.ise()?;
        conn.execute(r"DELETE FROM collections WHERE uuid = $1", &[&self.uuid]).await.ise()?;
        Ok(())
    }

    pub async fn get(conn: &Conn, uuid: Uuid) -> Result<Option<Self>> {
        Ok(conn.query_opt(r"SELECT * FROM collections WHERE uuid = $1", &[&uuid]).await.ise()?.map(Into::into))
    }

    pub async fn get_for_org(conn: &Conn, organization_uuid: Uuid, uuid: Uuid) -> Result<Option<Self>> {
        Ok(conn.query_opt(r"SELECT * FROM collections c WHERE uuid = $2 AND organization_uuid = $1", &[&organization_uuid, &uuid]).await.ise()?.map(Into::into))
    }

    pub async fn get_for_user_writable(conn: &Conn, user_uuid: Uuid, uuid: Uuid) -> Result<Option<Self>> {
        Ok(conn.query_opt(r"SELECT * FROM collections c INNER JOIN user_collection_auth uca ON uca.collection_uuid = c.uuid AND uca.user_uuid = $1 WHERE uuid = $2 AND NOT uca.read_only", &[&user_uuid, &uuid]).await.ise()?.map(Into::into))
    }

    pub async fn find_by_user(conn: &Conn, user_uuid: Uuid, _visible_only: bool) -> Result<Vec<Self>> {
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
            .await
            .ise()?
            .into_iter()
            .map(|x| x.into())
            .collect())
    }

    pub async fn find_by_organization(conn: &Conn, organization_uuid: Uuid) -> Result<Vec<Self>> {
        Ok(conn
            .query(
                r"
        SELECT co.*
        FROM collections co
        WHERE co.organization_uuid = $1
        ",
                &[&organization_uuid],
            )
            .await
            .ise()?
            .into_iter()
            .map(|x| x.into())
            .collect())
    }

    pub async fn count_by_org(conn: &Conn, organization_uuid: Uuid) -> Result<i64> {
        Ok(conn.query_one(r"SELECT count(1) FROM collections WHERE organization_uuid = $1", &[&organization_uuid]).await.ise()?.get(0))
    }

    pub async fn find_by_uuid_and_org(conn: &Conn, uuid: Uuid, organization_uuid: Uuid) -> Result<Option<Self>> {
        Ok(conn.query_opt(r"SELECT * FROM collections WHERE uuid = $1 AND organization_uuid = $2", &[&uuid, &organization_uuid]).await.ise()?.map(Into::into))
    }

    pub async fn find_by_uuid_and_user(conn: &Conn, uuid: Uuid, user_uuid: Uuid) -> Result<Option<Self>> {
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
            .await
            .ise()?
            .map(Into::into))
    }

    pub async fn find_by_uuid_and_user_writable(conn: &Conn, uuid: Uuid, user_uuid: Uuid) -> Result<Option<Self>> {
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
            .await
            .ise()?
            .map(Into::into))
    }
}

impl CollectionUser {
    pub async fn find_by_organization_and_user_uuid(conn: &Conn, organization_uuid: Uuid, user_uuid: Uuid) -> Result<Vec<Self>> {
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
            .await
            .ise()?
            .into_iter()
            .map(|x| x.into())
            .collect())
    }

    pub async fn find_by_organization(conn: &Conn, organization_uuid: Uuid) -> Result<Vec<Self>> {
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
            .await
            .ise()?
            .into_iter()
            .map(|x| x.into())
            .collect())
    }

    pub async fn save(&self, conn: &Conn) -> Result<()> {
        conn.execute(r"INSERT INTO collection_users (user_uuid, collection_uuid, read_only, hide_passwords) VALUES ($1, $2, $3, $4) ON CONFLICT (user_uuid, collection_uuid) DO UPDATE
        SET
        read_only = EXCLUDED.read_only,
        hide_passwords = EXCLUDED.hide_passwords", &[
            &self.user_uuid,
            &self.collection_uuid,
            &self.read_only,
            &self.hide_passwords,
        ]).await.ise()?;
        User::flag_revision_for(conn, self.user_uuid).await.ise()?;
        Ok(())
    }

    pub async fn delete(&self, conn: &Conn) -> Result<()> {
        User::flag_revision_for(conn, self.user_uuid).await.ise()?;
        conn.execute(r"DELETE FROM collection_users WHERE user_uuid = $1 AND collection_uuid = $2", &[&self.user_uuid, &self.collection_uuid]).await.ise()?;
        Ok(())
    }

    pub async fn find_by_collection(conn: &Conn, collection_uuid: Uuid) -> Result<Vec<Self>> {
        Ok(conn
            .query(r"SELECT cu.* FROM collection_users cu WHERE cu.collection_uuid = $1", &[&collection_uuid])
            .await
            .ise()?
            .into_iter()
            .map(|x| x.into())
            .collect())
    }

    pub async fn find_by_collection_and_user(conn: &Conn, collection_uuid: Uuid, user_uuid: Uuid) -> Result<Option<Self>> {
        Ok(conn
            .query_opt(r"SELECT cu.* FROM collection_users cu WHERE cu.collection_uuid = $1 AND cu.user_uuid = $2", &[&collection_uuid, &user_uuid])
            .await
            .ise()?
            .map(Into::into))
    }

    pub async fn delete_all_by_collection(conn: &Conn, collection_uuid: Uuid) -> Result<()> {
        Collection::flag_revision(conn, collection_uuid).await.ise()?;
        conn.execute(r"DELETE FROM collection_users WHERE collection_uuid = $1", &[&collection_uuid]).await.ise()?;
        Ok(())
    }
}

/// Database methods
impl CollectionCipher {
    pub async fn save(conn: &Conn, cipher_uuid: Uuid, collection_uuid: Uuid) -> Result<()> {
        conn.execute(
            "INSERT INTO collection_ciphers (cipher_uuid, collection_uuid) VALUES ($1, $2) ON CONFLICT (cipher_uuid, collection_uuid) DO NOTHING",
            &[&cipher_uuid, &collection_uuid],
        )
        .await
        .ise()?;
        Collection::flag_revision(conn, collection_uuid).await.ise()?;
        Ok(())
    }

    pub async fn delete(conn: &Conn, cipher_uuid: Uuid, collection_uuid: Uuid) -> Result<()> {
        Collection::flag_revision(conn, collection_uuid).await.ise()?;
        conn.execute(r"DELETE FROM collection_ciphers WHERE cipher_uuid = $1 AND collection_uuid = $2", &[&cipher_uuid, &collection_uuid]).await.ise()?;
        Ok(())
    }
}
