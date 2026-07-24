use axol::prelude::*;
use chrono::{DateTime, Utc};
use serde::Deserialize;
use serde_json::{Value, json};
use uuid::Uuid;

use crate::{
    CONFIG,
    auth::{Headers, OrgAdminHeaders},
    db::{Cipher, DB, Event, EventType, UserOrganization},
    events::{log_event, log_user_event},
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
        "data": events_json,
        "object": "list",
        "continuationToken": get_continuation_token(&events_json),
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
        "data": events_json,
        "object": "list",
        "continuationToken": get_continuation_token(&events_json),
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
        "data": events_json,
        "object": "list",
        "continuationToken": get_continuation_token(&events_json),
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
#[serde(rename_all = "camelCase")]
pub struct EventCollection {
    // Mandatory
    #[serde(deserialize_with = "lenient_event_type")]
    r#type: EventType,
    date: DateTime<Utc>,

    // Optional
    cipher_id: Option<Uuid>,
    organization_id: Option<Uuid>,
}

// Clients push whatever event types their version knows about. A type this server
// doesn't have a variant for must not fail the whole batch (`serde_repr` has no
// catch-all), so map unrecognized values to `Unknown` and skip them individually.
fn lenient_event_type<'de, D: serde::Deserializer<'de>>(deserializer: D) -> Result<EventType, D::Error> {
    let raw = i32::deserialize(deserializer)?;
    Ok(EventType::from_repr(raw).unwrap_or(EventType::Unknown))
}

// Upstream:
// https://github.com/bitwarden/server/blob/8a22c0479e987e756ce7412c48a732f9002f0a2d/src/Events/Controllers/CollectController.cs
// https://github.com/bitwarden/server/blob/8a22c0479e987e756ce7412c48a732f9002f0a2d/src/Core/Services/Implementations/EventService.cs
pub async fn post_events_collect(headers: Headers, data: Json<Vec<EventCollection>>) -> Result<()> {
    if !CONFIG.settings.org_events_enabled {
        return Ok(());
    }
    let mut conn = DB.get().await.ise()?;

    for event in data.iter() {
        // Skip events whose type this server doesn't recognize (see lenient_event_type).
        if matches!(event.r#type, EventType::Unknown) {
            continue;
        }
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

#[cfg(test)]
mod tests {
    use chrono::{Duration, SecondsFormat, Utc};
    use serde_json::json;

    use crate::test_harness::TestClient;

    /// A `?start=..&end=..` range bracketing "now", for the event query endpoints.
    fn range_query() -> String {
        let start = (Utc::now() - Duration::days(1)).to_rfc3339_opts(SecondsFormat::Secs, true);
        let end = (Utc::now() + Duration::days(1)).to_rfc3339_opts(SecondsFormat::Secs, true);
        format!("?start={start}&end={end}")
    }

    /// A fresh owner + org + an org-owned cipher whose creation logs a
    /// `CipherCreated` (1100) event tied to the org, cipher, and acting user.
    async fn org_with_cipher() -> (TestClient, String, String) {
        let owner = TestClient::register_and_login().await;
        let org_id = owner.create_org("Events").await["id"].as_str().unwrap().to_string();
        let cols = owner.get(&format!("/api/organizations/{org_id}/collections")).await;
        let col_id = cols.json()["data"].as_array().unwrap()[0]["id"].as_str().unwrap().to_string();
        let cipher_id = owner.create_org_cipher(&org_id, &col_id, "2.evented|mac").await["id"].as_str().unwrap().to_string();
        (owner, org_id, cipher_id)
    }

    #[tokio::test]
    async fn org_events_lists_logged_actions() {
        let (owner, org_id, _cipher_id) = org_with_cipher().await;

        let resp = owner.get(&format!("/api/organizations/{org_id}/events{}", range_query())).await;
        resp.assert_ok();
        assert_eq!(resp.json()["object"], "list");
        let types: Vec<i64> = resp.json()["data"].as_array().unwrap().iter().filter_map(|e| e["type"].as_i64()).collect();
        assert!(types.contains(&1100), "org events should include CipherCreated (1100): {}", resp.body);
    }

    #[tokio::test]
    async fn cipher_events_lists_its_events() {
        let (owner, _org_id, cipher_id) = org_with_cipher().await;

        let resp = owner.get(&format!("/api/ciphers/{cipher_id}/events{}", range_query())).await;
        resp.assert_ok();
        let types: Vec<i64> = resp.json()["data"].as_array().unwrap().iter().filter_map(|e| e["type"].as_i64()).collect();
        assert!(types.contains(&1100), "cipher events should include CipherCreated (1100): {}", resp.body);
    }

    #[tokio::test]
    async fn user_events_lists_acting_user_events() {
        // Exercises find_by_organization_and_user, which matches on act_user_uuid.
        let (owner, org_id, _cipher_id) = org_with_cipher().await;
        let owner_id = owner.user_id.unwrap();

        let resp = owner.get(&format!("/api/organizations/{org_id}/users/{owner_id}/events{}", range_query())).await;
        resp.assert_ok();
        assert!(!resp.json()["data"].as_array().unwrap().is_empty(), "user events should include the owner's actions: {}", resp.body);
    }

    #[tokio::test]
    async fn collect_client_event_is_recorded() {
        let (owner, _org_id, cipher_id) = org_with_cipher().await;
        let date = Utc::now().to_rfc3339_opts(SecondsFormat::Secs, true);

        // A client-side "viewed" event (1107) for the org cipher, pushed via collect.
        owner.post("/events/collect", json!([{ "type": 1107, "date": date, "cipherId": cipher_id }])).await.assert_ok();

        let resp = owner.get(&format!("/api/ciphers/{cipher_id}/events{}", range_query())).await;
        resp.assert_ok();
        let types: Vec<i64> = resp.json()["data"].as_array().unwrap().iter().filter_map(|e| e["type"].as_i64()).collect();
        assert!(types.contains(&1107), "collected client-viewed event (1107) should be recorded: {}", resp.body);
    }

    // A batch containing an event type this server doesn't know must not 400 the whole
    // batch; the recognized events are still recorded and the unknown one is skipped.
    #[tokio::test]
    async fn collect_tolerates_unknown_event_type() {
        let (owner, _org_id, cipher_id) = org_with_cipher().await;
        let date = Utc::now().to_rfc3339_opts(SecondsFormat::Secs, true);

        // 1119 (Cipher_ClientCopiedBankAccountNumber) is a newer known type; 99999 is unknown.
        let batch = json!([
            { "type": 1119, "date": date, "cipherId": cipher_id },
            { "type": 99999, "date": date, "cipherId": cipher_id },
        ]);
        owner.post("/events/collect", batch).await.assert_ok();

        let resp = owner.get(&format!("/api/ciphers/{cipher_id}/events{}", range_query())).await;
        resp.assert_ok();
        let types: Vec<i64> = resp.json()["data"].as_array().unwrap().iter().filter_map(|e| e["type"].as_i64()).collect();
        assert!(types.contains(&1119), "newer known event (1119) should be recorded alongside an unknown one: {}", resp.body);
        assert!(!types.contains(&99999), "unknown event type should be skipped, not stored: {}", resp.body);
    }

    #[tokio::test]
    async fn org_events_require_admin() {
        let owner = TestClient::register_and_login().await;
        let outsider = TestClient::register_and_login().await;
        let org_id = owner.create_org("Locked").await["id"].as_str().unwrap().to_string();

        let resp = outsider.get(&format!("/api/organizations/{org_id}/events{}", range_query())).await;
        assert!(resp.status >= 400, "non-admin should not read org events, got {}: {}", resp.status, resp.body);
    }
}
