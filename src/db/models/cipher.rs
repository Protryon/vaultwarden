use crate::{api::core::CipherData, db::Conn, CONFIG};
use axum_util::errors::{ApiError, ApiResult};
use chrono::{DateTime, Duration, Utc};
use serde_json::{json, Value};
use serde_repr::{Deserialize_repr, Serialize_repr};
use tokio_postgres::{types::Json, Row};
use uuid::Uuid;

use super::{Attachment, Favorite, FolderCipher, Organization, User};

#[derive(Debug)]
pub struct Cipher {
    pub uuid: Uuid,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,

    pub user_uuid: Option<Uuid>,
    pub organization_uuid: Option<Uuid>,

    pub atype: CipherType,
    pub name: String,
    pub notes: Option<String>,
    pub fields: Option<Value>,

    pub data: Value,

    pub password_history: Option<Value>,
    pub deleted_at: Option<DateTime<Utc>>,
    pub reprompt: Option<RepromptType>,
}

#[allow(dead_code)]
#[derive(Clone, Copy, Debug, strum::FromRepr, Serialize_repr, Deserialize_repr)]
#[repr(i32)]
pub enum RepromptType {
    None = 0,
    Password = 1, // not currently used in server
}

#[derive(Clone, Copy, Debug, strum::FromRepr, PartialEq, Eq, Serialize_repr, Deserialize_repr)]
#[repr(i32)]
pub enum CipherType {
    Login = 1,
    SecureNote = 2,
    Card = 3,
    Identity = 4,
    Fido2Key = 5,
    Unknown = i32::MAX,
}

impl From<Row> for Cipher {
    fn from(row: Row) -> Self {
        let reprompt: Option<i32> = row.get(12);
        Self {
            uuid: row.get(0),
            created_at: row.get(1),
            updated_at: row.get(2),
            user_uuid: row.get(3),
            organization_uuid: row.get(4),
            atype: CipherType::from_repr(row.get(5)).unwrap_or(CipherType::Unknown),
            name: row.get(6),
            notes: row.get(7),
            fields: row.get::<_, Option<Json<_>>>(8).map(|x| x.0),
            data: row.get::<_, Json<_>>(9).0,
            password_history: row.get::<_, Option<Json<_>>>(10).map(|x| x.0),
            deleted_at: row.get(11),
            reprompt: reprompt.and_then(RepromptType::from_repr),
        }
    }
}

/// Local methods
impl Cipher {
    pub fn new(atype: CipherType, name: String) -> Self {
        let now = Utc::now();

        Self {
            uuid: Uuid::new_v4(),
            created_at: now,
            updated_at: now,

            user_uuid: None,
            organization_uuid: None,

            atype,
            name,

            notes: None,
            fields: None,

            data: serde_json::from_str("{}").unwrap(),
            password_history: None,
            deleted_at: None,
            reprompt: None,
        }
    }

    pub fn validate_notes(cipher_data: &[CipherData]) -> ApiResult<()> {
        let mut validation_errors = serde_json::Map::new();
        for (index, cipher) in cipher_data.iter().enumerate() {
            if let Some(note) = &cipher.notes {
                if note.len() > 10_000 {
                    validation_errors.insert(
                        format!("Ciphers[{index}].Notes"),
                        serde_json::to_value(["The field Notes exceeds the maximum encrypted value length of 10000 characters."]).unwrap(),
                    );
                }
            }
        }
        if !validation_errors.is_empty() {
            let err_json = json!({
                "message": "The model state is invalid.",
                "validationErrors" : validation_errors,
                "object": "error"
            });
            err_json!(err_json, "Import validation errors")
        } else {
            Ok(())
        }
    }
}

#[derive(Debug, Default, Clone, Copy)]
pub struct AccessRestrictions {
    pub read_only: bool,
    pub hide_passwords: bool,
}

impl Cipher {
    pub async fn to_json(&self, conn: &Conn, user_uuid: Uuid, for_user: bool) -> ApiResult<Value> {
        use crate::util::format_date;

        let mut attachments_json: Value = Value::Null;
        let attachments = Attachment::find_by_cipher(conn, self.uuid).await?;
        if !attachments.is_empty() {
            attachments_json = attachments.iter().map(|c| c.to_json()).collect();
        }

        // We don't need these values at all for Organizational syncs
        // Skip any other database calls if this is the case and just return false.
        let access = if for_user {
            self.get_access_restrictions(conn, user_uuid).await?.ok_or_else(|| ApiError::BadRequest("Cipher ownership assertion failure".to_string()))?
        } else {
            Default::default()
        };

        let mut data = self.data.clone();

        // NOTE: This was marked as *Backwards Compatibility Code*, but as of January 2021 this is still being used by upstream
        // Set the first element of the Uris array as Uri, this is needed several (mobile) clients.
        if self.atype == CipherType::Login {
            //todo: check if this can panic
            if data["Uris"].is_array() {
                let uri = data["Uris"][0]["Uri"].clone();
                data["Uri"] = uri;
            } else {
                // Upstream always has an Uri key/value
                data["Uri"] = Value::Null;
            }
        }

        let mut data_json = data.clone();

        // NOTE: This was marked as *Backwards Compatibility Code*, but as of January 2021 this is still being used by upstream
        // data_json should always contain the following keys with every atype
        data_json["Fields"] = self.fields.clone().unwrap_or_default();
        data_json["Name"] = Value::String(self.name.clone());
        data_json["Notes"] = Value::String(self.notes.clone().unwrap_or_default());
        data_json["PasswordHistory"] = self.password_history.clone().unwrap_or(Value::Null);

        let collection_ids = self.get_collections(conn, user_uuid).await?;

        // There are three types of cipher response models in upstream
        // Bitwarden: "cipherMini", "cipher", and "cipherDetails" (in order
        // of increasing level of detail). vaultwarden currently only
        // supports the "cipherDetails" type, though it seems like the
        // Bitwarden clients will ignore extra fields.
        //
        // Ref: https://github.com/bitwarden/server/blob/master/src/Core/Models/Api/Response/CipherResponseModel.cs
        let mut json_object = json!({
            "Object": "cipherDetails",
            "Id": self.uuid,
            "Type": self.atype as i32,
            "CreationDate": format_date(&self.created_at),
            "RevisionDate": format_date(&self.updated_at),
            "DeletedDate": self.deleted_at.map_or(Value::Null, |d| Value::String(format_date(&d))),
            "Reprompt": self.reprompt.unwrap_or(RepromptType::None) as i32,
            "OrganizationId": self.organization_uuid,
            "Attachments": attachments_json,
            // We have UseTotp set to true by default within the Organization model.
            // This variable together with UsersGetPremium is used to show or hide the TOTP counter.
            "OrganizationUseTotp": true,

            // This field is specific to the cipherDetails type.
            "CollectionIds": collection_ids,

            "Name": self.name,
            "Notes": self.notes,
            "Fields": self.fields,

            "Data": data_json,

            "PasswordHistory": self.password_history,

            // All Cipher types are included by default as null, but only the matching one will be populated
            "Login": null,
            "SecureNote": null,
            "Card": null,
            "Identity": null,
            "Fido2Key": null,
        });

        // These values are only needed for user/default syncs
        // Not during an organizational sync like `get_org_details`
        // Skip adding these fields in that case
        if for_user {
            json_object["FolderId"] = json!(self.get_folder_uuid(conn, user_uuid).await?);
            json_object["Favorite"] = json!(self.is_favorite(conn, user_uuid).await?);
            // These values are true by default, but can be false if the
            // cipher belongs to a collection or group where the org owner has enabled
            // the "Read Only" or "Hide Passwords" restrictions for the user.
            json_object["Edit"] = json!(!access.read_only);
            json_object["ViewPassword"] = json!(!access.hide_passwords);
        }

        let key = match self.atype {
            CipherType::Login => "Login",
            CipherType::SecureNote => "SecureNote",
            CipherType::Card => "Card",
            CipherType::Identity => "Identity",
            CipherType::Fido2Key => "Fido2Key",
            _ => panic!("Wrong type"),
        };

        json_object[key] = data;
        Ok(json_object)
    }

    pub async fn save(&mut self, conn: &Conn) -> ApiResult<()> {
        self.updated_at = Utc::now();

        conn.execute(r"INSERT INTO ciphers (uuid, created_at, updated_at, user_uuid, organization_uuid, atype, name, notes, fields, data, password_history, deleted_at, reprompt) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13) ON CONFLICT (uuid) DO UPDATE
        SET
        created_at = EXCLUDED.created_at,
        updated_at = EXCLUDED.updated_at,
        user_uuid = EXCLUDED.user_uuid,
        organization_uuid = EXCLUDED.organization_uuid,
        atype = EXCLUDED.atype,
        name = EXCLUDED.name,
        notes = EXCLUDED.notes,
        fields = EXCLUDED.fields,
        data = EXCLUDED.data,
        password_history = EXCLUDED.password_history,
        deleted_at = EXCLUDED.deleted_at,
        reprompt = EXCLUDED.reprompt", &[
            &self.uuid,
            &self.created_at,
            &self.updated_at,
            &self.user_uuid,
            &self.organization_uuid,
            &(self.atype as i32),
            &self.name,
            &self.notes,
            &self.fields,
            &self.data,
            &self.password_history,
            &self.deleted_at,
            &self.reprompt.map(|x| x as i32),
        ]).await?;
        Self::flag_revision(conn, self.uuid).await?;
        Ok(())
    }

    pub async fn flag_revision(conn: &Conn, uuid: Uuid) -> ApiResult<()> {
        conn.execute(r"UPDATE user_revisions u SET updated_at = now() FROM user_cipher_auth uca WHERE uca.cipher_uuid = $1 AND uca.user_uuid = u.uuid", &[&uuid]).await?;
        Ok(())
    }

    pub async fn delete(&self, conn: &Conn) -> ApiResult<()> {
        Self::flag_revision(conn, self.uuid).await?;
        conn.execute(r"DELETE FROM ciphers WHERE uuid = $1", &[&self.uuid]).await?;
        Ok(())
    }

    pub async fn delete_all_by_organization(conn: &Conn, organization_uuid: Uuid) -> ApiResult<()> {
        Organization::flag_revision(conn, organization_uuid).await?;
        conn.execute(r"DELETE FROM ciphers WHERE organization_uuid = $1", &[&organization_uuid]).await?;
        Ok(())
    }

    /// Purge all ciphers that are old enough to be auto-deleted.
    pub async fn purge_trash(conn: &Conn) -> ApiResult<()> {
        if let Some(auto_delete_days) = CONFIG.settings.trash_auto_delete_days {
            let oldest = Utc::now() - Duration::days(auto_delete_days);
            conn.execute(r"DELETE FROM ciphers WHERE deleted_at IS NOT NULL AND deleted_at < $1", &[&oldest]).await?;
        }
        Ok(())
    }

    pub async fn move_to_folder(&self, conn: &Conn, folder_uuid: Option<Uuid>, user_uuid: Uuid) -> ApiResult<()> {
        match (self.get_folder_uuid(conn, user_uuid).await?, folder_uuid) {
            // No changes
            (None, None) => Ok(()),
            (Some(ref old), Some(ref new)) if old == new => Ok(()),

            // Add to folder
            (None, Some(new)) => FolderCipher::new(new, self.uuid).save(conn).await,

            // Remove from folder
            (Some(old), None) => match FolderCipher::find_by_folder_and_cipher(conn, old, self.uuid).await? {
                Some(old) => old.delete(conn).await,
                None => err!("Couldn't move from previous folder"),
            },

            // Move to another folder
            (Some(old), Some(new)) => {
                if let Some(old) = FolderCipher::find_by_folder_and_cipher(conn, old, self.uuid).await? {
                    old.delete(conn).await?;
                }
                FolderCipher::new(new, self.uuid).save(conn).await
            }
        }
    }

    /// Returns the user's access restrictions to this cipher. A return value
    /// of None means that this cipher does not belong to the user, and is
    /// not in any collection the user has access to. Otherwise, the user has
    /// access to this cipher, and Some(read_only, hide_passwords) represents
    /// the access restrictions.
    pub async fn get_access_restrictions(&self, conn: &Conn, user_uuid: Uuid) -> ApiResult<Option<AccessRestrictions>> {
        Ok(conn
            .query_opt(r"SELECT read_only, hide_passwords FROM user_cipher_auth WHERE user_uuid = $1 AND cipher_uuid = $2", &[&user_uuid, &self.uuid])
            .await?
            .map(|x| AccessRestrictions {
                read_only: x.get(0),
                hide_passwords: x.get(1),
            }))
    }

    pub async fn is_write_accessible_to_user(&self, conn: &Conn, user_uuid: Uuid) -> ApiResult<bool> {
        Ok(self.get_access_restrictions(conn, user_uuid).await?.map(|x| !x.read_only).unwrap_or(false))
    }

    // Returns whether this cipher is a favorite of the specified user.
    pub async fn is_favorite(&self, conn: &Conn, user_uuid: Uuid) -> ApiResult<bool> {
        Favorite::is_favorite(conn, self.uuid, user_uuid).await
    }

    // Sets whether this cipher is a favorite of the specified user.
    pub async fn set_favorite(&self, conn: &Conn, favorite: bool, user_uuid: Uuid) -> ApiResult<()> {
        Favorite::set_favorite(conn, favorite, self.uuid, user_uuid).await?;
        Ok(())
    }

    pub async fn get_folder_uuid(&self, conn: &Conn, user_uuid: Uuid) -> ApiResult<Option<Uuid>> {
        Ok(conn
            .query_opt(
                r"
            SELECT fc.folder_uuid
            FROM folder_ciphers fc
            INNER JOIN folders f ON f.uuid = fc.folder_uuid
            WHERE fc.cipher_uuid = $1 AND f.user_uuid = $2
        ",
                &[&self.uuid, &user_uuid],
            )
            .await?
            .map(|x| x.get(0)))
    }

    pub async fn get(conn: &Conn, uuid: Uuid) -> ApiResult<Option<Self>> {
        Ok(conn.query_opt(r"SELECT * FROM ciphers WHERE uuid = $1", &[&uuid]).await?.map(Into::into))
    }

    pub async fn get_for_user(conn: &Conn, user_uuid: Uuid, uuid: Uuid) -> ApiResult<Option<Self>> {
        Ok(conn
            .query_opt(
                r"SELECT c.* FROM ciphers c INNER JOIN user_cipher_auth uca ON uca.cipher_uuid = c.uuid AND uca.user_uuid = $1 WHERE uuid = $2",
                &[&user_uuid, &uuid],
            )
            .await?
            .map(Into::into))
    }

    pub async fn get_for_user_writable(conn: &Conn, user_uuid: Uuid, uuid: Uuid) -> ApiResult<Option<Self>> {
        Ok(conn.query_opt(r"SELECT c.* FROM ciphers c INNER JOIN user_cipher_auth uca ON uca.cipher_uuid = c.uuid AND uca.user_uuid = $1 WHERE uuid = $2 AND NOT uca.read_only", &[&user_uuid, &uuid]).await?.map(Into::into))
    }

    // Find all ciphers accessible or visible to the specified user.
    //
    // "Accessible" means the user has read access to the cipher, either via
    // direct ownership, collection or via group access.
    //
    // "Visible" usually means the same as accessible, except when an org
    // owner/admin sets their account or group to have access to only selected
    // collections in the org (presumably because they aren't interested in
    // the other collections in the org). In this case, if `visible_only` is
    // true, then the non-interesting ciphers will not be returned. As a
    // result, those ciphers will not appear in "My Vault" for the org
    // owner/admin, but they can still be accessed via the org vault view.
    pub async fn find_by_user(conn: &Conn, user_uuid: Uuid, visible_only: bool) -> ApiResult<Vec<Self>> {
        //TODO: what is visibile_only
        Ok(conn
            .query(
                r"
        SELECT c.*
        FROM ciphers c
        INNER JOIN user_cipher_auth uca ON uca.cipher_uuid = c.uuid AND uca.user_uuid = $1
        ",
                &[&user_uuid],
            )
            .await?
            .into_iter()
            .map(|x| x.into())
            .collect())
    }

    // Find all ciphers visible to the specified user.
    pub async fn find_by_user_visible(conn: &Conn, user_uuid: Uuid) -> ApiResult<Vec<Self>> {
        Self::find_by_user(conn, user_uuid, true).await
    }

    // Find all ciphers directly owned by the specified user.
    pub async fn find_owned_by_user(conn: &Conn, user_uuid: Uuid) -> ApiResult<Vec<Self>> {
        Ok(conn
            .query(r"SELECT * FROM ciphers WHERE user_uuid = $1 AND organization_uuid IS NULL", &[&user_uuid])
            .await?
            .into_iter()
            .map(|x| x.into())
            .collect())
    }

    pub async fn delete_owned_by_user(conn: &Conn, user_uuid: Uuid) -> ApiResult<()> {
        User::flag_revision_for(conn, user_uuid).await?;
        conn.execute(r"DELETE FROM ciphers WHERE user_uuid = $1 AND organization_uuid IS NULL", &[&user_uuid]).await?;
        Ok(())
    }

    //TODO: owned semantics differ from find_owned_by_user in source, changed here
    pub async fn count_owned_by_user(conn: &Conn, user_uuid: Uuid) -> ApiResult<i64> {
        Ok(conn.query_one(r"SELECT count(1) FROM ciphers WHERE user_uuid = $1 AND organization_uuid IS NULL", &[&user_uuid]).await?.get(0))
    }

    pub async fn find_by_org(conn: &Conn, organization_uuid: Uuid) -> ApiResult<Vec<Self>> {
        Ok(conn.query(r"SELECT * FROM ciphers WHERE organization_uuid = $1", &[&organization_uuid]).await?.into_iter().map(|x| x.into()).collect())
    }

    pub async fn count_by_org(conn: &Conn, organization_uuid: Uuid) -> ApiResult<i64> {
        Ok(conn.query_one(r"SELECT count(1) FROM ciphers WHERE organization_uuid = $1", &[&organization_uuid]).await?.get(0))
    }

    pub async fn get_collections(&self, conn: &Conn, user_uuid: Uuid) -> ApiResult<Vec<Uuid>> {
        Ok(conn
            .query(
                r"
        SELECT cc.collection_uuid
        FROM ciphers c
        INNER JOIN user_cipher_auth uca ON uca.cipher_uuid = $1 AND uca.user_uuid = $2
        INNER JOIN collection_ciphers cc ON cc.cipher_uuid = c.uuid
        ",
                &[&self.uuid, &user_uuid],
            )
            .await?
            .into_iter()
            .map(|x| x.get(0))
            .collect())
    }

    pub async fn get_auth_users(&self, conn: &Conn) -> ApiResult<Vec<Uuid>> {
        Ok(conn
            .query(
                r"
        SELECT uca.user_uuid
        FROM user_cipher_auth uca
        WHERE uca.cipher_uuid = $1
        ",
                &[&self.uuid],
            )
            .await?
            .into_iter()
            .map(|x| x.get(0))
            .collect())
    }
}
