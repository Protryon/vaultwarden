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

use axum::{extract::Query, routing, Json, Router};
use axum_util::errors::{ApiError, ApiResult};
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};

pub use events::post_events_collect;

use crate::{
    api::{ws_users, UpdateType},
    auth::Headers,
    config::PUBLIC_NO_TRAILING_SLASH,
    db::DB,
    util::{get_reqwest_client, Upcase},
    CONFIG,
};

pub fn route() -> Router {
    let mut router = Router::new()
        .route("/settings/domains", routing::get(get_eq_domains))
        .route("/settings/domains", routing::post(post_eq_domains))
        .route("/settings/domains", routing::put(post_eq_domains))
        .route("/hibp/breach", routing::get(hibp_breach))
        .route("/alive", routing::get(now))
        .route("/now", routing::get(now))
        .route("/version", routing::get(version))
        .route("/config", routing::get(config))
        .route("/organizations/:org_uuid/events", routing::get(events::get_org_events))
        .route("/ciphers/:uuid/events", routing::get(events::get_cipher_events))
        .route("/organizations/:org_uuid/users/:user_id/events", routing::get(events::get_user_events))
        .route("/folders", routing::get(folders::get_folders))
        .route("/folders/:uuid", routing::get(folders::get_folder))
        .route("/folders", routing::post(folders::post_folders))
        .route("/folders/:uuid", routing::post(folders::put_folder))
        .route("/folders/:uuid", routing::put(folders::put_folder))
        .route("/folders/:uuid", routing::delete(folders::delete_folder))
        .route("/folders/:uuid/delete", routing::post(folders::delete_folder))
        .route("/devices/knowndevice/:email/:uuid", routing::get(accounts::get_known_device_from_path))
        .route("/devices/knowndevice", routing::get(accounts::get_known_device))
        .route("/devices/identifier/:uuid/token", routing::post(accounts::put_device_token))
        .route("/devices/identifier/:uuid/token", routing::put(accounts::put_device_token))
        .route("/devices/identifier/:uuid/clear-token", routing::put(accounts::put_clear_device_token))
        .route("/devices/identifier/:uuid/clear-token", routing::post(accounts::put_clear_device_token))
        .route("/public/organization/import", routing::post(public::ldap_import));

    router = ciphers::route(router);
    router = accounts::route(router);
    router = two_factor::route(router);
    router = sends::route(router);
    router = organizations::route(router);
    router = emergency_access::route(router);
    router
}

#[derive(Serialize, Deserialize, Debug)]
#[serde(rename_all = "PascalCase")]
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
        "EquivalentDomains": equivalent_domains,
        "GlobalEquivalentDomains": globals,
        "Object": "domains",
    }))
}

#[derive(Deserialize, Debug)]
#[serde(rename_all = "PascalCase")]
struct EquivDomainData {
    excluded_global_equivalent_domains: Option<Vec<i32>>,
    equivalent_domains: Option<Vec<Vec<String>>>,
}

async fn post_eq_domains(headers: Headers, data: Json<Upcase<EquivDomainData>>) -> ApiResult<Json<Value>> {
    let data: EquivDomainData = data.0.data;

    let excluded_globals = data.excluded_global_equivalent_domains.unwrap_or_default();
    let equivalent_domains = data.equivalent_domains.unwrap_or_default();

    let mut user = headers.user;
    use serde_json::to_string;

    user.excluded_globals = to_string(&excluded_globals).unwrap_or_else(|_| "[]".to_string());
    user.equivalent_domains = to_string(&equivalent_domains).unwrap_or_else(|_| "[]".to_string());

    let conn = DB.get().await?;
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
) -> ApiResult<Json<Value>> {
    let url = format!("https://haveibeenpwned.com/api/v3/breachedaccount/{username}?truncateResponse=false&includeUnverified=false");

    if let Some(api_key) = &CONFIG.settings.hibp_api_key {
        let hibp_client = get_reqwest_client();

        let res = hibp_client.get(&url).header("hibp-api-key", api_key).send().await?;

        // If we get a 404, return a 404, it means no breached accounts
        if res.status() == 404 {
            return Err(ApiError::NotFound);
        }

        let value: Value = res.error_for_status()?.json().await?;
        Ok(Json(value))
    } else {
        Ok(Json(json!([{
            "Name": "HaveIBeenPwned",
            "Title": "Manual HIBP Check",
            "Domain": "haveibeenpwned.com",
            "BreachDate": "2019-08-18T00:00:00Z",
            "AddedDate": "2019-08-18T00:00:00Z",
            "Description": format!("Go to: <a href=\"https://haveibeenpwned.com/account/{username}\" target=\"_blank\" rel=\"noreferrer\">https://haveibeenpwned.com/account/{username}</a> for a manual check.<br/><br/>HaveIBeenPwned API key not set!<br/>Go to <a href=\"https://haveibeenpwned.com/API/Key\" target=\"_blank\" rel=\"noreferrer\">https://haveibeenpwned.com/API/Key</a> to purchase an API key from HaveIBeenPwned.<br/><br/>"),
            "LogoPath": "vw_static/hibp.png",
            "PwnCount": 0,
            "DataClasses": [
                "Error - No API key set!"
            ]
        }])))
    }
}

async fn now() -> Json<String> {
    Json(crate::util::format_date(&chrono::Utc::now()))
}

async fn version() -> Json<&'static str> {
    Json(crate::VERSION)
}

async fn config() -> Json<Value> {
    let domain = &*PUBLIC_NO_TRAILING_SLASH;
    Json(json!({
        "version": crate::VERSION,
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
