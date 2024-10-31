use axol::{ErrorExt, Result};
use chrono::{DateTime, Utc};
use serde_json::{json, Value};
use tokio_postgres::Row;
use uuid::Uuid;

use crate::db::Conn;

use super::{Collection, User};

pub struct Group {
    pub uuid: Uuid,
    pub organization_uuid: Uuid,
    pub name: String,
    pub access_all: bool,
    pub external_id: Option<String>,
    pub creation_date: DateTime<Utc>,
    pub revision_date: DateTime<Utc>,
}

impl From<Row> for Group {
    fn from(row: Row) -> Self {
        Self {
            uuid: row.get(0),
            organization_uuid: row.get(1),
            name: row.get(2),
            access_all: row.get(3),
            external_id: row.get(4),
            creation_date: row.get(5),
            revision_date: row.get(6),
        }
    }
}

pub struct CollectionGroup {
    pub collection_uuid: Uuid,
    pub group_uuid: Uuid,
    pub read_only: bool,
    pub hide_passwords: bool,
}

impl From<Row> for CollectionGroup {
    fn from(row: Row) -> Self {
        Self {
            collection_uuid: row.get(0),
            group_uuid: row.get(1),
            read_only: row.get(2),
            hide_passwords: row.get(3),
        }
    }
}

pub struct GroupUser {
    pub group_uuid: Uuid,
    pub user_uuid: Uuid,
}

impl From<Row> for GroupUser {
    fn from(row: Row) -> Self {
        Self {
            group_uuid: row.get(0),
            user_uuid: row.get(1),
        }
    }
}

/// Local methods
impl Group {
    pub fn new(organization_uuid: Uuid, name: String, access_all: bool, external_id: Option<String>) -> Self {
        let now = Utc::now();

        let mut new_model = Self {
            uuid: Uuid::new_v4(),
            organization_uuid,
            name,
            access_all,
            external_id: None,
            creation_date: now,
            revision_date: now,
        };

        new_model.set_external_id(external_id);

        new_model
    }

    pub fn to_json(&self) -> Value {
        use crate::util::format_date;

        json!({
            "id": self.uuid,
            "organizationId": self.organization_uuid,
            "name": self.name,
            "accessAll": self.access_all,
            "externalId": self.external_id,
            "creationDate": format_date(&self.creation_date),
            "revisionDate": format_date(&self.revision_date),
            "object": "group"
        })
    }

    pub async fn to_json_details(&self, conn: &Conn) -> Result<Value> {
        let collections_groups: Vec<Value> = CollectionGroup::find_by_group(conn, self.uuid)
            .await
            .ise()?
            .iter()
            .map(|entry| {
                json!({
                    "id": entry.collection_uuid,
                    "readOnly": entry.read_only,
                    "hidePasswords": entry.hide_passwords
                })
            })
            .collect();

        Ok(json!({
            "id": self.uuid,
            "organizationId": self.organization_uuid,
            "name": self.name,
            "accessAll": self.access_all,
            "externalId": self.external_id,
            "collections": collections_groups,
            "object": "groupDetails"
        }))
    }

    pub fn set_external_id(&mut self, external_id: Option<String>) {
        //Check if external id is empty. We don't want to have
        //empty strings in the database
        match external_id {
            Some(external_id) => {
                if external_id.is_empty() {
                    self.external_id = None;
                } else {
                    self.external_id = Some(external_id)
                }
            }
            None => self.external_id = None,
        }
    }
}

impl CollectionGroup {
    pub fn new(collection_uuid: Uuid, group_uuid: Uuid, read_only: bool, hide_passwords: bool) -> Self {
        Self {
            collection_uuid,
            group_uuid,
            read_only,
            hide_passwords,
        }
    }
}

impl GroupUser {
    pub fn new(group_uuid: Uuid, user_uuid: Uuid) -> Self {
        Self {
            group_uuid,
            user_uuid,
        }
    }
}

/// Database methods
impl Group {
    pub async fn save(&mut self, conn: &Conn) -> Result<()> {
        self.revision_date = Utc::now();

        conn.execute(r"INSERT INTO groups (uuid, organization_uuid, name, access_all, external_id, creation_date, revision_date) VALUES ($1, $2, $3, $4, $5, $6, $7) ON CONFLICT (uuid) DO UPDATE
        SET
        organization_uuid = EXCLUDED.organization_uuid,
        name = EXCLUDED.name,
        access_all = EXCLUDED.access_all,
        external_id = EXCLUDED.external_id,
        creation_date = EXCLUDED.creation_date,
        revision_date = EXCLUDED.revision_date", &[
            &self.uuid,
            &self.organization_uuid,
            &self.name,
            &self.access_all,
            &self.external_id,
            &self.creation_date,
            &self.revision_date,
        ]).await.ise()?;
        Self::flag_revision(conn, self.uuid).await.ise()?;
        Ok(())
    }

    pub async fn flag_revision(conn: &Conn, uuid: Uuid) -> Result<()> {
        conn.execute(r"UPDATE user_revisions u SET updated_at = now() FROM group_users gu WHERE gu.group_uuid = $1 AND gu.user_uuid = u.uuid", &[&uuid])
            .await
            .ise()?;
        Ok(())
    }

    pub async fn find_by_organization(conn: &Conn, organization_uuid: Uuid) -> Result<Vec<Self>> {
        Ok(conn
            .query(r"SELECT cu.* FROM groups cu WHERE cu.organization_uuid = $1", &[&organization_uuid])
            .await
            .ise()?
            .into_iter()
            .map(|x| x.into())
            .collect())
    }

    pub async fn count_by_org(conn: &Conn, organization_uuid: Uuid) -> Result<i64> {
        Ok(conn.query_one(r"SELECT count(1) FROM groups WHERE organization_uuid = $1", &[&organization_uuid]).await.ise()?.get(0))
    }

    pub async fn get(conn: &Conn, uuid: Uuid) -> Result<Option<Self>> {
        Ok(conn.query_opt(r"SELECT * FROM groups WHERE uuid = $1", &[&uuid]).await.ise()?.map(Into::into))
    }

    pub async fn get_for_org(conn: &Conn, uuid: Uuid, organization_uuid: Uuid) -> Result<Option<Self>> {
        Ok(conn.query_opt(r"SELECT * FROM groups WHERE uuid = $1 AND organization_uuid = $2", &[&uuid, &organization_uuid]).await.ise()?.map(Into::into))
    }

    pub async fn find_by_external_id(conn: &Conn, id: &str) -> Result<Option<Self>> {
        Ok(conn.query_opt(r"SELECT * FROM groups WHERE external_id = $1", &[&id]).await.ise()?.map(Into::into))
    }

    pub async fn delete(&self, conn: &Conn) -> Result<()> {
        Self::flag_revision(conn, self.uuid).await.ise()?;
        conn.execute(r"DELETE FROM groups WHERE uuid = $1", &[&self.uuid]).await.ise()?;
        Ok(())
    }
}

impl CollectionGroup {
    pub async fn save(&self, conn: &Conn) -> Result<()> {
        conn.execute(r"INSERT INTO collection_groups (collection_uuid, group_uuid, read_only, hide_passwords) VALUES ($1, $2, $3, $4) ON CONFLICT (collection_uuid, group_uuid) DO UPDATE
        SET
        read_only = EXCLUDED.read_only,
        hide_passwords = EXCLUDED.hide_passwords", &[
            &self.collection_uuid,
            &self.group_uuid,
            &self.read_only,
            &self.hide_passwords,
        ]).await.ise()?;
        Group::flag_revision(conn, self.group_uuid).await.ise()?;
        Ok(())
    }

    pub async fn find_by_group(conn: &Conn, group_uuid: Uuid) -> Result<Vec<Self>> {
        Ok(conn.query(r"SELECT * FROM collection_groups WHERE group_uuid = $1", &[&group_uuid]).await.ise()?.into_iter().map(|x| x.into()).collect())
    }

    pub async fn find_by_collection(conn: &Conn, collection_uuid: Uuid) -> Result<Vec<Self>> {
        Ok(conn.query(r"SELECT * FROM collection_groups WHERE collection_uuid = $1", &[&collection_uuid]).await.ise()?.into_iter().map(|x| x.into()).collect())
    }

    pub async fn delete_all_by_group(conn: &Conn, group_uuid: Uuid) -> Result<()> {
        Group::flag_revision(conn, group_uuid).await.ise()?;
        conn.execute(r"DELETE FROM collection_groups WHERE group_uuid = $1", &[&group_uuid]).await.ise()?;
        Ok(())
    }

    pub async fn delete_all_by_collection(conn: &Conn, collection_uuid: Uuid) -> Result<()> {
        Collection::flag_revision(conn, collection_uuid).await.ise()?;
        conn.execute(r"DELETE FROM collection_groups WHERE collection_uuid = $1", &[&collection_uuid]).await.ise()?;
        Ok(())
    }
}

impl GroupUser {
    pub async fn save(&self, conn: &Conn) -> Result<()> {
        conn.execute(
            "INSERT INTO group_users (group_uuid, user_uuid) VALUES ($1, $2) ON CONFLICT (group_uuid, user_uuid) DO NOTHING",
            &[&self.group_uuid, &self.user_uuid],
        )
        .await
        .ise()?;
        User::flag_revision_for(conn, self.user_uuid).await.ise()?;
        Ok(())
    }

    pub async fn find_by_group(conn: &Conn, group_uuid: Uuid) -> Result<Vec<Self>> {
        Ok(conn.query(r"SELECT * FROM group_users WHERE group_uuid = $1", &[&group_uuid]).await.ise()?.into_iter().map(|x| x.into()).collect())
    }

    pub async fn find_by_user(conn: &Conn, user_uuid: Uuid, organization_uuid: Uuid) -> Result<Vec<Self>> {
        Ok(conn
            .query(
                r"SELECT gu.* FROM group_users gu INNER JOIN groups g ON g.uuid = gu.group_uuid WHERE gu.user_uuid = $1 AND g.organization_uuid = $2",
                &[&user_uuid, &organization_uuid],
            )
            .await
            .ise()?
            .into_iter()
            .map(|x| x.into())
            .collect())
    }

    pub async fn delete_by_group_uuid_and_user_id(conn: &Conn, group_uuid: Uuid, user_uuid: Uuid) -> Result<()> {
        User::flag_revision_for(conn, user_uuid).await.ise()?;
        conn.execute(r"DELETE FROM group_users WHERE user_uuid = $1 AND group_uuid = $2", &[&user_uuid, &group_uuid]).await.ise()?;
        Ok(())
    }

    pub async fn delete_all_by_group(conn: &Conn, group_uuid: Uuid) -> Result<()> {
        Group::flag_revision(conn, group_uuid).await.ise()?;
        conn.execute(r"DELETE FROM group_users WHERE group_uuid = $1", &[&group_uuid]).await.ise()?;
        Ok(())
    }

    pub async fn delete_all_by_user(conn: &Conn, user_uuid: Uuid, organization_uuid: Uuid) -> Result<()> {
        User::flag_revision_for(conn, user_uuid).await.ise()?;
        conn.execute(
            r"DELETE FROM group_users gu INNER JOIN groups g ON g.uuid = gu.group_uuid WHERE gu.user_uuid = $1 AND g.organization_uuid = $2",
            &[&user_uuid, &organization_uuid],
        )
        .await
        .ise()?;
        Ok(())
    }
}
