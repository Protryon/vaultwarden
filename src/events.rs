use std::net::IpAddr;

use axol::Result;
use chrono::{DateTime, Utc};
use uuid::Uuid;

use crate::{
    db::{Conn, Event, EventType, UserOrganization},
    CONFIG,
};

pub async fn log_user_event(event_type: EventType, user_uuid: Uuid, device_type: i32, event_date: DateTime<Utc>, ip: IpAddr, conn: &mut Conn) -> Result<()> {
    if !CONFIG.settings.org_events_enabled {
        return Ok(());
    }
    _log_user_event(event_type, user_uuid, device_type, event_date, ip, conn).await
}

async fn _log_user_event(event_type: EventType, user_uuid: Uuid, device_type: i32, event_date: DateTime<Utc>, ip: IpAddr, conn: &mut Conn) -> Result<()> {
    let orgs = UserOrganization::get_organization_uuid_by_user(conn, user_uuid).await?;
    let mut events: Vec<Event> = Vec::with_capacity(orgs.len() + 1); // We need an event per org and one without an org

    // Upstream saves the event also without any organization_uuid.
    let mut event = Event::new(event_type, Some(event_date));
    event.user_uuid = Some(user_uuid);
    event.act_user_uuid = Some(user_uuid);
    event.device_type = Some(device_type);
    event.ip_address = Some(ip.to_string());
    events.push(event);

    // For each org a user is a member of store these events per org
    for organization_uuid in orgs {
        let mut event = Event::new(event_type, Some(event_date));
        event.user_uuid = Some(user_uuid);
        event.organization_uuid = Some(organization_uuid);
        event.act_user_uuid = Some(user_uuid);
        event.device_type = Some(device_type);
        event.ip_address = Some(ip.to_string());
        events.push(event);
    }

    Event::save_user_event(conn, &events).await?;
    Ok(())
}

pub async fn log_event(
    event_type: EventType,
    source_uuid: Uuid,
    organization_uuid: Uuid,
    act_user_uuid: Uuid,
    device_type: i32,
    event_date: DateTime<Utc>,
    ip: IpAddr,
    conn: &Conn,
) -> Result<()> {
    if !CONFIG.settings.org_events_enabled {
        return Ok(());
    }
    _log_event(event_type, source_uuid, organization_uuid, act_user_uuid, device_type, event_date, ip, conn).await
}

#[allow(clippy::too_many_arguments)]
async fn _log_event(
    event_type: EventType,
    source_uuid: Uuid,
    organization_uuid: Uuid,
    act_user_uuid: Uuid,
    device_type: i32,
    event_date: DateTime<Utc>,
    ip: IpAddr,
    conn: &Conn,
) -> Result<()> {
    // Create a new empty event
    let mut event = Event::new(event_type, Some(event_date));
    match event_type as i32 {
        // 1000..=1099 Are user events, they need to be logged via log_user_event()
        1000..=1099 => unreachable!(),
        // Collection Events
        1100..=1199 => {
            event.cipher_uuid = Some(source_uuid);
        }
        // Collection Events
        1300..=1399 => {
            event.collection_uuid = Some(source_uuid);
        }
        // Group Events
        1400..=1499 => {
            event.group_uuid = Some(source_uuid);
        }
        // Org User Events
        1500..=1599 => {
            event.user_uuid = Some(source_uuid);
        }
        // 1600..=1699 Are organizational events, and they do not need the source_uuid
        // Policy Events
        1700..=1799 => {
            event.policy_uuid = Some(source_uuid);
        }
        // Ignore others
        _ => {}
    }

    event.organization_uuid = Some(organization_uuid);
    event.act_user_uuid = Some(act_user_uuid);
    event.device_type = Some(device_type);
    event.ip_address = Some(ip.to_string());
    event.save(conn).await?;
    Ok(())
}
