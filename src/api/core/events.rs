use axol::prelude::*;
use chrono::{DateTime, Utc};
use serde::Deserialize;
use serde_json::{json, Value};
use uuid::Uuid;

use crate::{
    auth::{Headers, OrgAdminHeaders},
    db::{Cipher, Event, EventType, UserOrganization, DB},
    events::{log_event, log_user_event},
    util::Upcase,
    CONFIG,
};

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct EventRange {
    start: DateTime<Utc>,
    end: DateTime<Utc>,
    continuation_token: Option<DateTime<Utc>>,
}

// Upstream: https://github.com/bitwarden/server/blob/9ecf69d9cabce732cf2c57976dd9afa5728578fb/src/Api/Controllers/EventsController.cs#LL84C35-L84C41
pub async fn get_org_events(Path(org_uuid): Path<Uuid>, Query(data): Query<EventRange>, _headers: OrgAdminHeaders) -> Result<Json<Value>> {
    // Return an empty vec when we org events are disabled.
    // This prevents client errors
    let events_json: Vec<Value> = if !CONFIG.settings.org_events_enabled {
        Vec::with_capacity(0)
    } else {
        let conn = DB.get().await.ise()?;
        let end_date = if let Some(before_date) = data.continuation_token {
            before_date
        } else {
            data.end
        };

        Event::find_by_organization(&conn, org_uuid, data.start, end_date).await?.iter().map(|e| e.to_json()).collect()
    };

    Ok(Json(json!({
        "Data": events_json,
        "Object": "list",
        "ContinuationToken": get_continuation_token(&events_json),
    })))
}

pub async fn get_cipher_events(Path(cipher_uuid): Path<Uuid>, Query(data): Query<EventRange>, headers: Headers) -> Result<Json<Value>> {
    // Return an empty vec when we org events are disabled.
    // This prevents client errors
    let events_json: Vec<Value> = if !CONFIG.settings.org_events_enabled {
        Vec::with_capacity(0)
    } else {
        let mut events_json = Vec::with_capacity(0);
        let conn = DB.get().await.ise()?;
        if UserOrganization::user_has_ge_admin_access_to_cipher(&conn, headers.user.uuid, cipher_uuid).await? {
            let end_date = if let Some(before_date) = data.continuation_token {
                before_date
            } else {
                data.end
            };

            events_json = Event::find_by_cipher(&conn, cipher_uuid, data.start, end_date).await?.iter().map(|e| e.to_json()).collect()
        }
        events_json
    };

    Ok(Json(json!({
        "Data": events_json,
        "Object": "list",
        "ContinuationToken": get_continuation_token(&events_json),
    })))
}

#[derive(Deserialize)]
pub struct GetUserEventsQuery {
    org_uuid: Uuid,
    user_id: Uuid,
}

pub async fn get_user_events(Path(path): Path<GetUserEventsQuery>, Query(data): Query<EventRange>, _headers: OrgAdminHeaders) -> Result<Json<Value>> {
    // Return an empty vec when we org events are disabled.
    // This prevents client errors
    let events_json: Vec<Value> = if !CONFIG.settings.org_events_enabled {
        Vec::with_capacity(0)
    } else {
        let end_date = if let Some(before_date) = data.continuation_token {
            before_date
        } else {
            data.end
        };
        let conn = DB.get().await.ise()?;

        Event::find_by_organization_and_user(&conn, path.org_uuid, path.user_id, data.start, end_date).await?.iter().map(|e| e.to_json()).collect()
    };

    Ok(Json(json!({
        "Data": events_json,
        "Object": "list",
        "ContinuationToken": get_continuation_token(&events_json),
    })))
}

fn get_continuation_token(events_json: &Vec<Value>) -> Option<&str> {
    // When the length of the vec equals the max page_size there probably is more data
    // When it is less, then all events are loaded.
    if events_json.len() as i64 == Event::PAGE_SIZE {
        if let Some(last_event) = events_json.last() {
            last_event["date"].as_str()
        } else {
            None
        }
    } else {
        None
    }
}

#[derive(Deserialize, Debug)]
#[serde(rename_all = "PascalCase")]
pub struct EventCollection {
    // Mandatory
    r#type: EventType,
    date: DateTime<Utc>,

    // Optional
    cipher_id: Option<Uuid>,
    organization_id: Option<Uuid>,
}

// Upstream:
// https://github.com/bitwarden/server/blob/8a22c0479e987e756ce7412c48a732f9002f0a2d/src/Events/Controllers/CollectController.cs
// https://github.com/bitwarden/server/blob/8a22c0479e987e756ce7412c48a732f9002f0a2d/src/Core/Services/Implementations/EventService.cs
pub async fn post_events_collect(headers: Headers, data: Json<Vec<Upcase<EventCollection>>>) -> Result<()> {
    if !CONFIG.settings.org_events_enabled {
        return Ok(());
    }
    let mut conn = DB.get().await.ise()?;

    for event in data.iter().map(|d| &d.data) {
        match event.r#type as i32 {
            1000..=1099 => {
                log_user_event(event.r#type, headers.user.uuid, headers.device.atype, event.date, headers.ip, &mut conn).await?;
            }
            1600..=1699 => {
                if let Some(org_uuid) = event.organization_id {
                    log_event(event.r#type, org_uuid, org_uuid, headers.user.uuid, headers.device.atype, event.date, headers.ip, &conn).await?;
                }
            }
            _ => {
                if let Some(cipher_uuid) = event.cipher_id {
                    if let Some(cipher) = Cipher::get(&conn, cipher_uuid).await? {
                        if let Some(org_uuid) = cipher.organization_uuid {
                            log_event(event.r#type, cipher_uuid, org_uuid, headers.user.uuid, headers.device.atype, event.date, headers.ip, &conn).await?;
                        }
                    }
                }
            }
        }
    }
    Ok(())
}
