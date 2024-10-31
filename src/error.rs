//
// Error generator macro
//
use axol::{Error, Json};
use serde_json::{json, Value};

pub fn api_error(msg: impl AsRef<str>) -> Json<Value> {
    let msg = msg.as_ref();
    let json = json!({
        "message": msg,
        "error": "",
        "error_description": "",
        "validationErrors": {"": [ msg ]},
        "errorModel": {
            "message": msg,
            "object": "error"
        },
        "exceptionMessage": null,
        "exceptionStackTrace": null,
        "innerExceptionMessage": null,
        "object": "error"
    });
    Json(json)
}

pub trait MapResult<S> {
    fn map_res(self, msg: &str) -> Result<S, Error>;
}

impl<S, E: Into<anyhow::Error>> MapResult<S> for Result<S, E> {
    fn map_res(self, msg: &str) -> Result<S, Error> {
        match self {
            Ok(x) => Ok(x),
            Err(e) => {
                let e = e.into();
                log::debug!("{}: {e:?}", msg);
                Err(Error::bad_request(api_error(msg)))
            }
        }
    }
}

impl<E: Into<anyhow::Error>> MapResult<()> for Result<usize, E> {
    fn map_res(self, msg: &str) -> Result<(), Error> {
        self.and(Ok(())).map_res(msg)
    }
}

impl<S> MapResult<S> for Option<S> {
    fn map_res(self, msg: &str) -> Result<S, Error> {
        self.ok_or_else(|| Error::bad_request(api_error(msg)))
    }
}

//
// Error return macros
//
#[macro_export]
macro_rules! err {
    ($msg:expr) => {{
        log::error!("{}", $msg);
        return Err(axol::Error::bad_request(crate::error::api_error($msg)));
    }};
    ($usr_msg:expr, $log_value:expr) => {{
        log::error!("{}. {}", $usr_msg, $log_value);
        return Err(axol::Error::bad_request(crate::error::api_error($usr_msg)));
    }};
}

#[macro_export]
macro_rules! err_silent {
    ($msg:expr) => {{
        return Err(axol::Error::bad_request(crate::error::api_error($msg)));
    }};
    ($usr_msg:expr, $log_value:expr) => {{
        return Err(axol::Error::bad_request(crate::error::api_error($usr_msg)));
    }};
}

#[macro_export]
macro_rules! err_code {
    ($msg:expr, $err_code:expr) => {{
        log::error!("{}", $msg);
        return Err(axol::Error::response(($err_code, crate::error::api_error($msg))));
    }};
    ($usr_msg:expr, $log_value:expr, $err_code:expr) => {{
        log::error!("{}. {}", $usr_msg, $log_value);
        return Err(axol::Error::response(($err_code, crate::error::api_error($usr_msg))));
    }};
}

#[macro_export]
macro_rules! err_json {
    ($expr:expr, $log_value:expr) => {{
        return Err(axol::Error::bad_request(axol::Json($expr)));
    }};
}
