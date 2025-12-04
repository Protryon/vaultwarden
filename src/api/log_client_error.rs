use axol::http::{
    request::{Request, RequestPartsRef},
    response::Response,
    Body,
};

use axol::{ConnectInfo, LateResponseHook, Plugin, RequestHook, Result, Router};
use log::warn;

#[derive(Clone, Default)]
pub struct LogClientError;

struct LogInfo {
    copied_body: String,
}

#[async_trait::async_trait]
impl RequestHook for LogClientError {
    async fn handle_request(&self, request: &mut Request) -> Result<Option<Response>> {
        let content = request.headers.get("content-type").unwrap_or_default();
        if !content.starts_with("application/json") {
            return Ok(None);
        }

        let body = std::mem::take(&mut request.body).collect().await?;
        request.extensions.insert(LogInfo {
            copied_body: String::from_utf8_lossy(&body).into_owned(),
        });
        request.body = Body::Bytes(body);

        Ok(None)
    }
}

#[async_trait::async_trait]
impl LateResponseHook for LogClientError {
    async fn handle_response<'a>(&self, request: RequestPartsRef<'a>, response: &mut Response) {
        let Some(log_info) = request.extensions.get::<LogInfo>() else {
            // we got inserted part-way through?
            return;
        };

        let Some(remote) = request.extensions.get::<ConnectInfo>() else {
            // not a remote connection
            return;
        };

        let body = match std::mem::take(&mut response.body).collect().await {
            Ok(x) => x,
            Err(e) => {
                warn!("failed to collect response body for client error logging: {e:?}");
                vec![]
            }
        };
        let raw_body = String::from_utf8_lossy(&body).into_owned();
        response.body = Body::Bytes(body);

        if !response.status.is_client_error() {
            return;
        }
        log::warn!(
            "[{}] {} {} -> {} REQUEST:\n{}\n\nRESPONSE:\n{}\n",
            remote.0,
            request.method,
            request.uri.path_and_query().map(|x| x.as_str()).unwrap_or_default(),
            response.status,
            log_info.copied_body,
            raw_body,
        );
    }
}

impl Plugin for LogClientError {
    fn apply(self, router: Router, path: &str) -> Router {
        router.request_hook_direct(path, self.clone()).late_response_hook_direct(path, self.clone())
    }
}
