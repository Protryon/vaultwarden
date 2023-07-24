use axol::{ErrorExt, Result};
use serde_json::{json, Value};
use serde_repr::{Deserialize_repr, Serialize_repr};
use tokio_postgres::Row;
use uuid::Uuid;

use crate::{db::Conn, CONFIG};

use chrono::{DateTime, Duration, Utc};

// https://bitwarden.com/help/event-logs/

// Upstream: https://github.com/bitwarden/server/blob/8a22c0479e987e756ce7412c48a732f9002f0a2d/src/Core/Services/Implementations/EventService.cs
// Upstream: https://github.com/bitwarden/server/blob/8a22c0479e987e756ce7412c48a732f9002f0a2d/src/Api/Models/Public/Response/EventResponseModel.cs
// Upstream SQL: https://github.com/bitwarden/server/blob/8a22c0479e987e756ce7412c48a732f9002f0a2d/src/Sql/dbo/Tables/Event.sql
#[derive(Debug)]
pub struct Event {
    pub uuid: Uuid,
    pub event_type: EventType,
    pub user_uuid: Option<Uuid>,
    pub organization_uuid: Option<Uuid>,
    pub cipher_uuid: Option<Uuid>,
    pub collection_uuid: Option<Uuid>,
    pub group_uuid: Option<Uuid>,
    pub act_user_uuid: Option<Uuid>,
    // Upstream enum: https://github.com/bitwarden/server/blob/8a22c0479e987e756ce7412c48a732f9002f0a2d/src/Core/Enums/DeviceType.cs
    pub device_type: Option<i32>,
    pub ip_address: Option<String>,
    pub event_date: DateTime<Utc>,
    pub policy_uuid: Option<Uuid>,
    pub provider_uuid: Option<Uuid>,
    pub provider_user_uuid: Option<Uuid>,
    pub provider_organization_uuid: Option<Uuid>,
}

impl From<Row> for Event {
    fn from(row: Row) -> Self {
        Self {
            uuid: row.get(0),
            event_type: EventType::from_repr(row.get::<_, i32>(1)).unwrap_or(EventType::Unknown),
            user_uuid: row.get(2),
            organization_uuid: row.get(3),
            cipher_uuid: row.get(4),
            collection_uuid: row.get(5),
            group_uuid: row.get(6),
            act_user_uuid: row.get(7),
            device_type: row.get(8),
            ip_address: row.get(9),
            event_date: row.get(10),
            policy_uuid: row.get(11),
            provider_uuid: row.get(12),
            provider_user_uuid: row.get(13),
            provider_organization_uuid: row.get(14),
        }
    }
}

// Upstream enum: https://github.com/bitwarden/server/blob/8a22c0479e987e756ce7412c48a732f9002f0a2d/src/Core/Enums/EventType.cs
#[derive(Debug, Copy, Clone, strum::FromRepr, Serialize_repr, Deserialize_repr)]
#[repr(i32)]
pub enum EventType {
    Unknown = 0,
    // User
    UserLoggedIn = 1000,
    UserChangedPassword = 1001,
    UserUpdated2fa = 1002,
    UserDisabled2fa = 1003,
    UserRecovered2fa = 1004,
    UserFailedLogIn = 1005,
    UserFailedLogIn2fa = 1006,
    UserClientExportedVault = 1007,
    // UserUpdatedTempPassword = 1008, // Not supported
    // UserMigratedKeyToKeyConnector = 1009, // Not supported

    // Cipher
    CipherCreated = 1100,
    CipherUpdated = 1101,
    CipherDeleted = 1102,
    CipherAttachmentCreated = 1103,
    CipherAttachmentDeleted = 1104,
    CipherShared = 1105,
    CipherUpdatedCollections = 1106,
    CipherClientViewed = 1107,
    CipherClientToggledPasswordVisible = 1108,
    CipherClientToggledHiddenFieldVisible = 1109,
    CipherClientToggledCardCodeVisible = 1110,
    CipherClientCopiedPassword = 1111,
    CipherClientCopiedHiddenField = 1112,
    CipherClientCopiedCardCode = 1113,
    CipherClientAutofilled = 1114,
    CipherSoftDeleted = 1115,
    CipherRestored = 1116,
    CipherClientToggledCardNumberVisible = 1117,

    // Collection
    CollectionCreated = 1300,
    CollectionUpdated = 1301,
    CollectionDeleted = 1302,

    // Group
    GroupCreated = 1400,
    GroupUpdated = 1401,
    GroupDeleted = 1402,

    // OrganizationUser
    OrganizationUserInvited = 1500,
    OrganizationUserConfirmed = 1501,
    OrganizationUserUpdated = 1502,
    OrganizationUserRemoved = 1503,
    OrganizationUserUpdatedGroups = 1504,
    // OrganizationUserUnlinkedSso = 1505, // Not supported
    OrganizationUserResetPasswordEnroll = 1506,
    OrganizationUserResetPasswordWithdraw = 1507,
    OrganizationUserAdminResetPassword = 1508,
    // OrganizationUserResetSsoLink = 1509, // Not supported
    // OrganizationUserFirstSsoLogin = 1510, // Not supported
    OrganizationUserRevoked = 1511,
    OrganizationUserRestored = 1512,

    // Organization
    OrganizationUpdated = 1600,
    OrganizationPurgedVault = 1601,
    OrganizationClientExportedVault = 1602,
    // OrganizationVaultAccessed = 1603,
    // OrganizationEnabledSso = 1604, // Not supported
    // OrganizationDisabledSso = 1605, // Not supported
    // OrganizationEnabledKeyConnector = 1606, // Not supported
    // OrganizationDisabledKeyConnector = 1607, // Not supported
    // OrganizationSponsorshipsSynced = 1608, // Not supported

    // Policy
    PolicyUpdated = 1700,
    // Provider (Not yet supported)
    // ProviderUserInvited = 1800, // Not supported
    // ProviderUserConfirmed = 1801, // Not supported
    // ProviderUserUpdated = 1802, // Not supported
    // ProviderUserRemoved = 1803, // Not supported
    // ProviderOrganizationCreated = 1900, // Not supported
    // ProviderOrganizationAdded = 1901, // Not supported
    // ProviderOrganizationRemoved = 1902, // Not supported
    // ProviderOrganizationVaultAccessed = 1903, // Not supported
}

/// Local methods
impl Event {
    pub fn new(event_type: EventType, event_date: Option<DateTime<Utc>>) -> Self {
        let event_date = match event_date {
            Some(d) => d,
            None => Utc::now(),
        };

        Self {
            uuid: Uuid::new_v4(),
            event_type,
            user_uuid: None,
            organization_uuid: None,
            cipher_uuid: None,
            collection_uuid: None,
            group_uuid: None,
            act_user_uuid: None,
            device_type: None,
            ip_address: None,
            event_date,
            policy_uuid: None,
            provider_uuid: None,
            provider_user_uuid: None,
            provider_organization_uuid: None,
        }
    }

    pub fn to_json(&self) -> Value {
        use crate::util::format_date;

        json!({
            "type": self.event_type as i32,
            "userId": self.user_uuid,
            "organizationId": self.organization_uuid,
            "cipherId": self.cipher_uuid,
            "collectionId": self.collection_uuid,
            "groupId": self.group_uuid,
            "organizationUserId": self.user_uuid,
            "actingUserId": self.act_user_uuid,
            "date": format_date(&self.event_date),
            "deviceType": self.device_type,
            "ipAddress": self.ip_address,
            "policyId": self.policy_uuid,
            "providerId": self.provider_uuid,
            "providerUserId": self.provider_user_uuid,
            "providerOrganizationId": self.provider_organization_uuid,
            // "installationId": null, // Not supported
        })
    }

    pub fn with_user_uuid(mut self, uuid: Uuid) -> Self {
        self.user_uuid = Some(uuid);
        self
    }
}

/// https://github.com/bitwarden/server/blob/8a22c0479e987e756ce7412c48a732f9002f0a2d/src/Core/Services/Implementations/EventService.cs
impl Event {
    pub const PAGE_SIZE: i64 = 30;

    pub async fn save(&self, conn: &Conn) -> Result<()> {
        conn.execute(r"INSERT INTO events (uuid, event_type, user_uuid, organization_uuid, cipher_uuid, collection_uuid, group_uuid, act_user_uuid, device_type, ip_address, event_date, policy_uuid, provider_uuid, provider_user_uuid, provider_organization_uuid) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14, $15)", &[
            &self.uuid,
            &(self.event_type as i32),
            &self.user_uuid,
            &self.organization_uuid,
            &self.cipher_uuid,
            &self.collection_uuid,
            &self.group_uuid,
            &self.act_user_uuid,
            &self.device_type,
            &self.ip_address,
            &self.event_date,
            &self.policy_uuid,
            &self.provider_uuid,
            &self.provider_user_uuid,
            &self.provider_organization_uuid,
        ]).await.ise()?;
        Ok(())
    }

    pub async fn save_user_event(conn: &mut Conn, events: impl IntoIterator<Item = &Event>) -> Result<()> {
        let transaction = conn.transaction().await.ise()?;
        for event in events {
            event.save(transaction.client()).await.ise()?;
        }
        transaction.commit().await.ise()?;
        Ok(())
    }

    pub async fn find_by_organization(conn: &Conn, organization_uuid: Uuid, start: DateTime<Utc>, end: DateTime<Utc>) -> Result<Vec<Self>> {
        Ok(conn
            .query(
                r"SELECT * FROM events WHERE organization_uuid = $1 AND event_date BETWEEN $2 AND $3 ORDER BY event_date DESC LIMIT $4",
                &[&organization_uuid, &start, &end, &Self::PAGE_SIZE],
            )
            .await
            .ise()?
            .into_iter()
            .map(|x| x.into())
            .collect())
    }

    pub async fn count_by_organization(conn: &Conn, organization_uuid: Uuid) -> Result<i64> {
        let row = conn
            .query_one(
                r"
            SELECT count(1)
            FROM events
            WHERE events.organization_uuid = $1
        ",
                &[&organization_uuid],
            )
            .await
            .ise()?;
        Ok(row.get(0))
    }

    pub async fn find_by_organization_and_user(
        conn: &Conn,
        organization_uuid: Uuid,
        user_uuid: Uuid,
        start: DateTime<Utc>,
        end: DateTime<Utc>,
    ) -> Result<Vec<Self>> {
        Ok(conn.query(r"SELECT * FROM events WHERE organization_uuid = $1 AND event.user_uuid = $5 OR event.act_user_id = $5 AND event_date BETWEEN $2 AND $3 ORDER BY event_date DESC LIMIT $4", &[&organization_uuid, &start, &end, &Self::PAGE_SIZE, &user_uuid]).await.ise()?.into_iter().map(|x| x.into()).collect())
    }

    pub async fn find_by_cipher(conn: &Conn, cipher_uuid: Uuid, start: DateTime<Utc>, end: DateTime<Utc>) -> Result<Vec<Self>> {
        Ok(conn
            .query(
                r"SELECT * FROM events WHERE cipher_uuid = $1 AND event_date BETWEEN $2 AND $3 ORDER BY event_date DESC LIMIT $4",
                &[&cipher_uuid, &start, &end, &Self::PAGE_SIZE],
            )
            .await
            .ise()?
            .into_iter()
            .map(|x| x.into())
            .collect())
    }

    pub async fn clean_events(conn: &Conn) -> Result<()> {
        let Some(days_to_retain) = CONFIG.settings.events_days_retain else {
            return Ok(());
        };
        let min_date = Utc::now() - Duration::days(days_to_retain);
        conn.execute(r"DELETE FROM events WHERE event_date < $1", &[&min_date]).await.ise()?;
        Ok(())
    }
}
