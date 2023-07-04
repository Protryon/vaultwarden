use std::collections::HashMap;

use crate::{api::core::CipherData, db::Conn, util::RowSlice, CONFIG};
use axum_util::errors::{ApiError, ApiResult};
use chrono::{DateTime, Duration, Utc};
use serde_json::{json, Value};
use serde_repr::{Deserialize_repr, Serialize_repr};
use tokio_postgres::{types::Json, Row};
use uuid::Uuid;

use super::{Attachment, Favorite, FolderCipher, Organization, User};

#[derive(Clone, Debug)]
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

#[derive(Clone, Debug)]
pub struct FullCipher {
    pub cipher: Cipher,
    pub attachments: Vec<Attachment>,
    pub access: AccessRestrictions,
    pub collection_uuids: Vec<Uuid>,
    pub folder_uuid: Option<Uuid>,
    pub is_favorite: bool,
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

impl<'a> From<RowSlice<'a>> for Cipher {
    fn from(row: RowSlice<'a>) -> Self {
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
            fields: row.get::<Option<Json<_>>>(8).map(|x| x.0),
            data: row.get::<Json<_>>(9).0,
            password_history: row.get::<Option<Json<_>>>(10).map(|x| x.0),
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

impl FullCipher {
    fn join(attachments: Vec<Attachment>, ciphers: Vec<Row>) -> Vec<Self> {
        let mut out_attachments: HashMap<Uuid, Vec<Attachment>> = HashMap::new();
        for attachment in attachments {
            out_attachments.entry(attachment.cipher_uuid).or_default().push(attachment);
        }

        ciphers
            .into_iter()
            .map(|row| {
                let cipher: Cipher = RowSlice::new(&row).slice_from(5..).into();
                // double NULL for CDB support
                let collection_uuids: Vec<Uuid> = row.get::<_, Option<Vec<Option<Uuid>>>>(4).unwrap_or_default().into_iter().flatten().collect();
                Self {
                    attachments: out_attachments.remove(&cipher.uuid).unwrap_or_default(),
                    cipher,
                    access: AccessRestrictions {
                        read_only: row.get(0),
                        hide_passwords: row.get(1),
                    },
                    collection_uuids,
                    folder_uuid: row.get(2),
                    is_favorite: row.get(3),
                }
            })
            .collect::<Vec<_>>()
    }

    pub async fn find_by_org(conn: &Conn, user_uuid: Uuid, organization_uuid: Uuid) -> ApiResult<Vec<Self>> {
        let attachments = Attachment::find_by_user(conn, user_uuid);
        let ciphers = async {
            conn.query(
                r"
                SELECT false, false, f.uuid, fav.cipher_uuid IS NOT NULL, coalesce(array_agg(cc.collection_uuid), ARRAY[]::UUID[]), c.*
                FROM ciphers c
                INNER JOIN user_cipher_auth uca ON uca.cipher_uuid = c.uuid AND uca.user_uuid = $1
                LEFT JOIN folder_ciphers fc ON fc.cipher_uuid = c.uuid
                LEFT JOIN folders f ON f.uuid = fc.folder_uuid AND f.user_uuid = $1
                LEFT JOIN favorites fav ON fav.cipher_uuid = c.uuid AND fav.user_uuid = $1
                LEFT JOIN collection_ciphers cc ON cc.cipher_uuid = c.uuid
                WHERE c.organization_uuid = $2
                GROUP BY uca.hide_passwords, fc.folder_uuid, fav.cipher_uuid
                ORDER BY c.created_at ASC
                ",
                &[&user_uuid, &organization_uuid],
            )
            .await
        };
        let (attachments, ciphers) = futures::future::join(attachments, ciphers).await;
        Ok(Self::join(attachments?, ciphers?))
    }

    pub async fn find_by_user(conn: &Conn, user_uuid: Uuid) -> ApiResult<Vec<Self>> {
        let attachments = Attachment::find_by_user(conn, user_uuid);
        let ciphers = async {
            conn.query(
                r"
                SELECT uca.read_only, uca.hide_passwords, f.uuid, fav.cipher_uuid IS NOT NULL, coalesce(array_agg(cc.collection_uuid), ARRAY[]::UUID[]), c.*
                FROM ciphers c
                INNER JOIN user_cipher_auth uca ON uca.cipher_uuid = c.uuid AND uca.user_uuid = $1
                LEFT JOIN folder_ciphers fc ON fc.cipher_uuid = c.uuid
                LEFT JOIN folders f ON f.uuid = fc.folder_uuid AND f.user_uuid = $1
                LEFT JOIN favorites fav ON fav.cipher_uuid = c.uuid AND fav.user_uuid = $1
                LEFT JOIN collection_ciphers cc ON cc.cipher_uuid = c.uuid
                GROUP BY c.uuid, uca.read_only, uca.hide_passwords, fc.folder_uuid, fav.cipher_uuid
                ORDER BY c.created_at ASC
                ",
                &[&user_uuid],
            )
            .await
        };
        let (attachments, ciphers) = futures::future::join(attachments, ciphers).await;
        Ok(Self::join(attachments?, ciphers?))
    }

    pub fn to_json(&self, for_user: bool) -> Value {
        use crate::util::format_date;

        let mut attachments_json: Value = Value::Null;
        if !self.attachments.is_empty() {
            attachments_json = self.attachments.iter().map(|c| c.to_json()).collect();
        }

        // We don't need these values at all for Organizational syncs
        // Skip any other database calls if this is the case and just return false.
        let access = if for_user {
            self.access
        } else {
            Default::default()
        };

        let mut data = self.cipher.data.clone();

        // NOTE: This was marked as *Backwards Compatibility Code*, but as of January 2021 this is still being used by upstream
        // Set the first element of the Uris array as Uri, this is needed several (mobile) clients.
        if self.cipher.atype == CipherType::Login {
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
        data_json["Fields"] = self.cipher.fields.clone().unwrap_or_default();
        data_json["Name"] = Value::String(self.cipher.name.clone());
        data_json["Notes"] = Value::String(self.cipher.notes.clone().unwrap_or_default());
        data_json["PasswordHistory"] = self.cipher.password_history.clone().unwrap_or(Value::Null);

        // There are three types of cipher response models in upstream
        // Bitwarden: "cipherMini", "cipher", and "cipherDetails" (in order
        // of increasing level of detail). vaultwarden currently only
        // supports the "cipherDetails" type, though it seems like the
        // Bitwarden clients will ignore extra fields.
        //
        // Ref: https://github.com/bitwarden/server/blob/master/src/Core/Models/Api/Response/CipherResponseModel.cs
        let mut json_object = json!({
            "Object": "cipherDetails",
            "Id": self.cipher.uuid,
            "Type": self.cipher.atype as i32,
            "CreationDate": format_date(&self.cipher.created_at),
            "RevisionDate": format_date(&self.cipher.updated_at),
            "DeletedDate": self.cipher.deleted_at.map_or(Value::Null, |d| Value::String(format_date(&d))),
            "Reprompt": self.cipher.reprompt.unwrap_or(RepromptType::None) as i32,
            "OrganizationId": self.cipher.organization_uuid,
            "Attachments": attachments_json,
            // We have UseTotp set to true by default within the Organization model.
            // This variable together with UsersGetPremium is used to show or hide the TOTP counter.
            "OrganizationUseTotp": true,

            // This field is specific to the cipherDetails type.
            "CollectionIds": self.collection_uuids,

            "Name": self.cipher.name,
            "Notes": self.cipher.notes,
            "Fields": self.cipher.fields,

            "Data": data_json,

            "PasswordHistory": self.cipher.password_history,

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
            json_object["FolderId"] = json!(self.folder_uuid);
            json_object["Favorite"] = json!(self.is_favorite);
            // These values are true by default, but can be false if the
            // cipher belongs to a collection or group where the org owner has enabled
            // the "Read Only" or "Hide Passwords" restrictions for the user.
            json_object["Edit"] = json!(!access.read_only);
            json_object["ViewPassword"] = json!(!access.hide_passwords);
        }

        let key = match self.cipher.atype {
            CipherType::Login => "Login",
            CipherType::SecureNote => "SecureNote",
            CipherType::Card => "Card",
            CipherType::Identity => "Identity",
            CipherType::Fido2Key => "Fido2Key",
            _ => panic!("Wrong type"),
        };

        json_object[key] = data;
        json_object
    }
}

impl Cipher {
    pub async fn to_json(self, conn: &Conn, user_uuid: Uuid, for_user: bool) -> ApiResult<Value> {
        let attachments = Attachment::find_by_cipher(conn, self.uuid).await?;

        // We don't need these values at all for Organizational syncs
        // Skip any other database calls if this is the case and just return false.
        let access = if for_user {
            self.get_access_restrictions(conn, user_uuid).await?.ok_or_else(|| ApiError::BadRequest("Cipher ownership assertion failure".to_string()))?
        } else {
            Default::default()
        };

        let collection_uuids = self.get_collections(conn, user_uuid).await?;

        let folder_uuid = self.get_folder_uuid(conn, user_uuid).await?;
        let is_favorite = self.is_favorite(conn, user_uuid).await?;

        Ok(FullCipher {
            cipher: self,
            attachments,
            access,
            collection_uuids,
            folder_uuid,
            is_favorite,
        }
        .to_json(for_user))
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
        conn.execute(
            r"UPDATE user_revisions u SET updated_at = now() FROM user_cipher_auth uca WHERE uca.cipher_uuid = $1 AND uca.user_uuid = u.uuid",
            &[&uuid],
        )
        .await?;
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
        Ok(conn.query_opt(r"SELECT * FROM ciphers WHERE uuid = $1", &[&uuid]).await?.as_ref().map(Into::<RowSlice<'_>>::into).map(Into::into))
    }

    pub async fn get_for_user(conn: &Conn, user_uuid: Uuid, uuid: Uuid) -> ApiResult<Option<Self>> {
        Ok(conn
            .query_opt(
                r"SELECT c.* FROM ciphers c INNER JOIN user_cipher_auth uca ON uca.cipher_uuid = c.uuid AND uca.user_uuid = $1 WHERE uuid = $2",
                &[&user_uuid, &uuid],
            )
            .await?
            .as_ref()
            .map(Into::<RowSlice<'_>>::into)
            .map(Into::into))
    }

    pub async fn get_for_user_writable(conn: &Conn, user_uuid: Uuid, uuid: Uuid) -> ApiResult<Option<Self>> {
        Ok(conn.query_opt(r"SELECT c.* FROM ciphers c INNER JOIN user_cipher_auth uca ON uca.cipher_uuid = c.uuid AND uca.user_uuid = $1 WHERE uuid = $2 AND NOT uca.read_only", &[&user_uuid, &uuid]).await?.as_ref().map(Into::<RowSlice<'_>>::into).map(Into::into))
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
