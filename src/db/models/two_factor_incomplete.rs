use std::net::IpAddr;

use axol::{ErrorExt, Result};
use chrono::{DateTime, Utc};
use tokio_postgres::Row;
use uuid::Uuid;

use crate::{db::Conn, CONFIG};

#[derive(Debug)]
pub struct TwoFactorIncomplete {
    pub uuid: Uuid,
    pub user_uuid: Uuid,
    // This device UUID is simply what's claimed by the device. It doesn't
    // necessarily correspond to any UUID in the devices table, since a device
    // must complete 2FA login before being added into the devices table.
    pub device_uuid: Uuid,
    pub device_name: String,
    pub login_time: DateTime<Utc>,
    pub ip_address: IpAddr,
}

impl From<Row> for TwoFactorIncomplete {
    fn from(row: Row) -> Self {
        Self {
            uuid: row.get(0),
            user_uuid: row.get(1),
            device_uuid: row.get(2),
            device_name: row.get(3),
            login_time: row.get(4),
            ip_address: row.get(5),
        }
    }
}

impl TwoFactorIncomplete {
    pub async fn mark_incomplete(conn: &Conn, user_uuid: Uuid, device_uuid: Uuid, device_name: &str, ip: IpAddr) -> Result<Option<Uuid>> {
        if CONFIG.settings.incomplete_2fa_time_limit <= 0 || !CONFIG.mail_enabled() {
            return Ok(None);
        }

        let uuid = Uuid::new_v4();
        let login_time = Utc::now();

        conn.execute(
            r"INSERT INTO twofactor_incomplete (uuid, user_uuid, device_uuid, device_name, login_time, ip_address) VALUES ($1, $2, $3, $4, $5, $6)",
            &[&uuid, &user_uuid, &device_uuid, &device_name, &login_time, &ip.to_string()],
        )
        .await
        .ise()?;
        Ok(Some(uuid))
    }

    pub async fn mark_complete(conn: &Conn, uuid: Uuid, user_uuid: Uuid, device_uuid: Uuid) -> Result<()> {
        if CONFIG.settings.incomplete_2fa_time_limit <= 0 || !CONFIG.mail_enabled() {
            return Ok(());
        }
        conn.execute(r"DELETE FROM twofactor_incomplete WHERE uuid = $1 AND user_uuid = $2 AND device_uuid = $3", &[&uuid, &user_uuid, &device_uuid])
            .await
            .ise()?;

        Ok(())
    }

    pub async fn find_logins_before(conn: &Conn, when: DateTime<Utc>) -> Result<Vec<Self>> {
        Ok(conn.query(r"SELECT * FROM twofactor_incomplete WHERE login_time < $1", &[&when]).await.ise()?.into_iter().map(|x| x.into()).collect())
    }

    pub async fn delete(&self, conn: &Conn) -> Result<()> {
        conn.execute(r"DELETE FROM twofactor_incomplete WHERE uuid = $1", &[&self.uuid]).await.ise()?;
        Ok(())
    }
}
