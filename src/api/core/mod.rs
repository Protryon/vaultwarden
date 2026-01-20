pub mod accounts;
mod ciphers;
mod emergency_access;
mod events;
mod folders;
mod organizations;
mod public;
mod sends;
pub mod two_factor;

pub use ciphers::CipherData;

use axol::prelude::*;
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};

pub use events::post_events_collect;

use crate::{
    api::{ws_users, UpdateType},
    auth::Headers,
    config::PUBLIC_NO_TRAILING_SLASH,
    db::DB,
    util::get_reqwest_client,
    CONFIG,
};

pub fn route() -> Router {
    let mut router = Router::new()
        .get("/settings/domains", get_eq_domains)
        .post("/settings/domains", post_eq_domains)
        .put("/settings/domains", post_eq_domains)
        .get("/hibp/breach", hibp_breach)
        .get("/alive", now)
        .get("/now", now)
        .get("/version", version)
        .get("/config", config)
        .get("/organizations/:org_uuid/events", events::get_org_events)
        .get("/ciphers/:uuid/events", events::get_cipher_events)
        .get("/organizations/:org_uuid/users/:user_id/events", events::get_user_events)
        .get("/folders", folders::get_folders)
        .get("/folders/:uuid", folders::get_folder)
        .post("/folders", folders::post_folders)
        .post("/folders/:uuid", folders::put_folder)
        .put("/folders/:uuid", folders::put_folder)
        .delete("/folders/:uuid", folders::delete_folder)
        .post("/folders/:uuid/delete", folders::delete_folder)
        .get("/devices/knowndevice/:email/:uuid", accounts::get_known_device_from_path)
        .get("/devices/knowndevice", accounts::get_known_device)
        .post("/devices/identifier/:uuid/token", accounts::put_device_token)
        .put("/devices/identifier/:uuid/token", accounts::put_device_token)
        .put("/devices/identifier/:uuid/clear-token", accounts::put_clear_device_token)
        .post("/devices/identifier/:uuid/clear-token", accounts::put_clear_device_token)
        .post("/public/organization/import", public::ldap_import);

    router = ciphers::route(router);
    router = accounts::route(router);
    router = two_factor::route(router);
    router = sends::route(router);
    router = organizations::route(router);
    router = emergency_access::route(router);
    router
}

#[derive(Serialize, Deserialize, Debug)]
#[serde(rename_all = "camelCase")]
struct GlobalDomain {
    r#type: i32,
    domains: Vec<String>,
    excluded: bool,
}

const GLOBAL_DOMAINS: &str = include_str!("../../static/global_domains.json");

#[derive(Deserialize)]
struct GlobalDomainQuery {
    #[serde(default)]
    no_excluded: bool,
}

async fn get_eq_domains(headers: Headers, Query(query): Query<GlobalDomainQuery>) -> Json<Value> {
    let user = headers.user;

    let equivalent_domains: Vec<Vec<String>> = serde_json::from_str(&user.equivalent_domains).unwrap();
    let excluded_globals: Vec<i32> = serde_json::from_str(&user.excluded_globals).unwrap();

    let mut globals: Vec<GlobalDomain> = serde_json::from_str(GLOBAL_DOMAINS).unwrap();

    for global in &mut globals {
        global.excluded = excluded_globals.contains(&global.r#type);
    }

    if query.no_excluded {
        globals.retain(|g| !g.excluded);
    }

    Json(json!({
        "equivalentDomains": equivalent_domains,
        "globalEquivalentDomains": globals,
        "object": "domains",
    }))
}

#[derive(Deserialize, Debug)]
#[serde(rename_all = "camelCase")]
struct EquivDomainData {
    excluded_global_equivalent_domains: Option<Vec<i32>>,
    equivalent_domains: Option<Vec<Vec<String>>>,
}

async fn post_eq_domains(headers: Headers, data: Json<EquivDomainData>) -> Result<Json<Value>> {
    let data: EquivDomainData = data.0;

    let excluded_globals = data.excluded_global_equivalent_domains.unwrap_or_default();
    let equivalent_domains = data.equivalent_domains.unwrap_or_default();

    let mut user = headers.user;
    use serde_json::to_string;

    user.excluded_globals = to_string(&excluded_globals).unwrap_or_else(|_| "[]".to_string());
    user.equivalent_domains = to_string(&equivalent_domains).unwrap_or_else(|_| "[]".to_string());

    let conn = DB.get().await.ise()?;
    user.save(&conn).await?;

    ws_users().send_user_update(UpdateType::SyncSettings, &conn, &user).await?;

    Ok(Json(json!({})))
}

#[derive(Deserialize)]
struct HibpQuery {
    username: String,
}

async fn hibp_breach(
    Query(HibpQuery {
        username,
    }): Query<HibpQuery>,
) -> Result<Json<Value>> {
    let url = format!("https://haveibeenpwned.com/api/v3/breachedaccount/{username}?truncateResponse=false&includeUnverified=false");

    if let Some(api_key) = &CONFIG.settings.hibp_api_key {
        let hibp_client = get_reqwest_client();

        let res = hibp_client.get(&url).header("hibp-api-key", api_key).send().await.ise()?;

        // If we get a 404, return a 404, it means no breached accounts
        if res.status() == 404 {
            return Err(Error::NotFound);
        }

        let value: Value = res.error_for_status().ise()?.json().await.ise()?;
        Ok(Json(value))
    } else {
        Ok(Json(json!([{
            "name": "HaveIBeenPwned",
            "title": "Manual HIBP Check",
            "domain": "haveibeenpwned.com",
            "breachDate": "2019-08-18T00:00:00Z",
            "addedDate": "2019-08-18T00:00:00Z",
            "description": format!("Go to: <a href=\"https://haveibeenpwned.com/account/{username}\" target=\"_blank\" rel=\"noreferrer\">https://haveibeenpwned.com/account/{username}</a> for a manual check.<br/><br/>HaveIBeenPwned API key not set!<br/>Go to <a href=\"https://haveibeenpwned.com/API/Key\" target=\"_blank\" rel=\"noreferrer\">https://haveibeenpwned.com/API/Key</a> to purchase an API key from HaveIBeenPwned.<br/><br/>"),
            "logoPath": "vw_static/hibp.png",
            "pwnCount": 0,
            "dataClasses": [
                "Error - No API key set!"
            ]
        }])))
    }
}

async fn now() -> Json<String> {
    Json(crate::util::format_date(&chrono::Utc::now()))
}

const VW_VERSION: &str = "2025.12.0";

async fn version() -> Json<&'static str> {
    Json(VW_VERSION)
}

async fn config() -> Json<Value> {
    let domain = &*PUBLIC_NO_TRAILING_SLASH;
    Json(json!({
        "version": VW_VERSION,
        "gitHash": option_env!("GIT_REV"),
        "server": {
          "name": "Vaultwarden",
          "url": "https://github.com/dani-garcia/vaultwarden"
        },
        "environment": {
          "vault": domain,
          "api": format!("{domain}/api"),
          "identity": format!("{domain}/identity"),
          "notifications": format!("{domain}/notifications"),
          "sso": "", // TODO?
        },
        "object": "config",
    }))
}
