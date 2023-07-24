mod admin;
pub mod core;
mod icons;
mod identity;
mod notifications;
mod web;

use std::time::Duration;

use axol::{trace::Trace, Logger, RealIp, Result, Router};
use log::{error, info};
use serde::Deserialize;

use crate::{
    util::{app_headers, build_cors},
    CONFIG, REGISTRY,
};

pub use crate::api::notifications::{ws_users, UpdateType};

fn route() -> Router {
    let mut api = web::route(Router::new())
        .nest("/notifications", notifications::route())
        .nest("/icons", icons::route())
        .nest("/identity", identity::route())
        .nest("/admin", admin::route())
        .nest("/api", core::route())
        .post("/events/collect", core::post_events_collect);
    if !CONFIG.advanced.ip_header.is_empty() {
        api = api.request_hook_direct("/", RealIp(CONFIG.advanced.ip_header.clone()));
    }
    api = api.late_response_hook("/", app_headers).plugin("/", build_cors()).plugin("/", Logger::default());
    if CONFIG.opentelemetry.is_some() {
        api = api.plugin("/", Trace::default().registry(REGISTRY.clone()));
    }
    api
}

pub async fn run_api_server() {
    tokio::spawn(async move {
        async fn run() -> anyhow::Result<()> {
            info!("Listening on {}", CONFIG.settings.api_bind);
            axol::Server::bind(CONFIG.settings.api_bind)?.router(route()).serve().await?;
            Ok(())
        }
        loop {
            if let Err(e) = run().await {
                error!("failed to start api server: {:?}", e);
            }
            tokio::time::sleep(Duration::from_secs(1)).await;
        }
    })
    .await
    .unwrap();
}

// Common structs representing JSON data received
#[derive(Deserialize)]
#[serde(rename_all = "PascalCase")]
pub struct PasswordData {
    master_password_hash: String,
}
