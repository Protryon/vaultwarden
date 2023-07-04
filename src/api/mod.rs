mod admin;
pub mod core;
mod icons;
mod identity;
mod notifications;
mod web;

use std::{net::SocketAddr, sync::Arc, time::Duration};

use anyhow::Result;
use axum::{
    headers::Header,
    response::{IntoResponse, IntoResponseParts, ResponseParts},
    routing, Router,
};
use axum_util::{
    errors::ApiResult,
    interceptor::InterceptorLayer,
    logger::{LoggerConfig, LoggerLayer},
};
use http::HeaderValue;
use log::{error, info, Level};
use serde::Deserialize;
use smallvec::SmallVec;

use crate::{
    util::{AppHeaders, Cors},
    CONFIG,
};

pub use crate::api::notifications::{ws_users, UpdateType};

fn route() -> Router {
    let mut api = web::route(Router::new());
    api = api.nest("/notifications", notifications::route());
    api = api.nest("/icons", icons::route());
    api = api.nest("/identity", identity::route());
    api = api.nest("/admin", admin::route());
    api = api.nest("/api", core::route()).route("/events/collect", routing::post(core::post_events_collect));

    api.layer(InterceptorLayer(Arc::new(Cors))).layer(InterceptorLayer(Arc::new(AppHeaders))).layer(LoggerLayer::new(LoggerConfig {
        log_level_filter: Arc::new(|_route| Level::Info),
        honor_xff: true,
        metric_name: "vw_api_call".to_string(),
    }))
}

pub async fn run_api_server() {
    tokio::spawn(async move {
        async fn run() -> Result<()> {
            info!("Listening on {}", CONFIG.settings.api_bind);
            let server = axum::Server::bind(&CONFIG.settings.api_bind);
            server.serve(route().into_make_service_with_connect_info::<SocketAddr>()).await?;
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

pub struct OutHeader<T: Header>(T);

impl<T: Header> IntoResponseParts for OutHeader<T> {
    type Error = ();
    fn into_response_parts(self, mut res: ResponseParts) -> Result<ResponseParts, ()> {
        let mut value_out: SmallVec<[HeaderValue; 1]> = SmallVec::new();
        self.0.encode(&mut value_out);
        if let Some(value) = value_out.into_iter().next() {
            res.headers_mut().insert(<T as Header>::name(), value);
        }
        Ok(res)
    }
}

impl<T: Header> IntoResponse for OutHeader<T> {
    fn into_response(self) -> axum::response::Response {
        (self, ()).into_response()
    }
}

// Common structs representing JSON data received
#[derive(Deserialize)]
#[serde(rename_all = "PascalCase")]
pub struct PasswordData {
    master_password_hash: String,
}

// #[derive(Deserialize, Debug, Clone)]
// #[serde(untagged)]
// enum NumberOrString {
//     Number(i32),
//     String(String),
// }

// impl NumberOrString {
//     fn into_string(self) -> String {
//         match self {
//             NumberOrString::Number(n) => n.to_string(),
//             NumberOrString::String(s) => s,
//         }
//     }

//     #[allow(clippy::wrong_self_convention)]
//     fn into_i32(&self) -> ApiResult<i32> {
//         use std::num::ParseIntError as PIE;
//         match self {
//             NumberOrString::Number(n) => Ok(*n),
//             NumberOrString::String(s) => {
//                 s.parse().map_err(|e: PIE| crate::Error::new("Can't convert to number", e.to_string()))
//             }
//         }
//     }
// }
