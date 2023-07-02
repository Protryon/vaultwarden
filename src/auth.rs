use axum::extract::{ConnectInfo, FromRequestParts, MatchedPath, Path, Query};
use axum::http::request::Parts;
use axum::response::IntoResponse;
use axum_util::errors::{ApiError, ApiResult};
use chrono::{Duration, Utc};
use log::{error, warn};
use once_cell::sync::Lazy;

use jsonwebtoken::{self, errors::ErrorKind, Algorithm, DecodingKey, EncodingKey, Header};
use serde::Deserialize;
use serde::{de::DeserializeOwned, Serialize};
use uuid::Uuid;

use crate::db::{Collection, Conn, Device, User, UserOrgStatus, UserOrgType, UserOrganization, UserStampException, DB};
use crate::CONFIG;

const JWT_ALGORITHM: Algorithm = Algorithm::RS256;

pub static DEFAULT_VALIDITY: Lazy<Duration> = Lazy::new(|| Duration::hours(2));
static JWT_HEADER: Lazy<Header> = Lazy::new(|| Header::new(JWT_ALGORITHM));

pub static JWT_LOGIN_ISSUER: Lazy<String> = Lazy::new(|| format!("{}|login", CONFIG.settings.public));
static JWT_INVITE_ISSUER: Lazy<String> = Lazy::new(|| format!("{}|invite", CONFIG.settings.public));
static JWT_EMERGENCY_ACCESS_INVITE_ISSUER: Lazy<String> = Lazy::new(|| format!("{}|emergencyaccessinvite", CONFIG.settings.public));
static JWT_SSOTOKEN_ISSUER: Lazy<String> = Lazy::new(|| format!("{}|ssotoken", CONFIG.settings.public));
static JWT_DELETE_ISSUER: Lazy<String> = Lazy::new(|| format!("{}|delete", CONFIG.settings.public));
static JWT_VERIFYEMAIL_ISSUER: Lazy<String> = Lazy::new(|| format!("{}|verifyemail", CONFIG.settings.public));
static JWT_ADMIN_ISSUER: Lazy<String> = Lazy::new(|| format!("{}|admin", CONFIG.settings.public));
static JWT_SEND_ISSUER: Lazy<String> = Lazy::new(|| format!("{}|send", CONFIG.settings.public));
static JWT_ORG_API_KEY_ISSUER: Lazy<String> = Lazy::new(|| format!("{}|api.organization", CONFIG.settings.public));

static PRIVATE_RSA_KEY: Lazy<EncodingKey> = Lazy::new(|| {
    let key = std::fs::read(CONFIG.private_rsa_key()).unwrap_or_else(|e| panic!("Error loading private RSA Key. \n{e}"));
    EncodingKey::from_rsa_pem(&key).unwrap_or_else(|e| panic!("Error decoding private RSA Key.\n{e}"))
});
static PUBLIC_RSA_KEY: Lazy<DecodingKey> = Lazy::new(|| {
    let key = std::fs::read(CONFIG.public_rsa_key()).unwrap_or_else(|e| panic!("Error loading public RSA Key. \n{e}"));
    DecodingKey::from_rsa_pem(&key).unwrap_or_else(|e| panic!("Error decoding public RSA Key.\n{e}"))
});

pub fn load_keys() {
    Lazy::force(&PRIVATE_RSA_KEY);
    Lazy::force(&PUBLIC_RSA_KEY);
}

pub fn encode_jwt<T: Serialize>(claims: &T) -> String {
    match jsonwebtoken::encode(&JWT_HEADER, claims, &PRIVATE_RSA_KEY) {
        Ok(token) => token,
        Err(e) => panic!("Error encoding jwt {e}"),
    }
}

fn decode_jwt<T: DeserializeOwned>(token: &str, issuer: String) -> ApiResult<T> {
    let mut validation = jsonwebtoken::Validation::new(JWT_ALGORITHM);
    validation.leeway = 30; // 30 seconds
    validation.validate_exp = true;
    validation.validate_nbf = true;
    validation.set_issuer(&[issuer]);

    let token = token.replace(char::is_whitespace, "");
    match jsonwebtoken::decode(&token, &PUBLIC_RSA_KEY, &validation) {
        Ok(d) => Ok(d.claims),
        Err(err) => match *err.kind() {
            ErrorKind::InvalidToken => err!("Token is invalid"),
            ErrorKind::InvalidIssuer => err!("Issuer is invalid"),
            ErrorKind::ExpiredSignature => err!("Token has expired"),
            _ => err!("Error decoding JWT"),
        },
    }
}

pub fn decode_login(token: &str) -> ApiResult<LoginJwtClaims> {
    decode_jwt(token, JWT_LOGIN_ISSUER.to_string())
}

pub fn decode_invite(token: &str) -> ApiResult<InviteJwtClaims> {
    decode_jwt(token, JWT_INVITE_ISSUER.to_string())
}

pub fn decode_emergency_access_invite(token: &str) -> ApiResult<EmergencyAccessInviteJwtClaims> {
    decode_jwt(token, JWT_EMERGENCY_ACCESS_INVITE_ISSUER.to_string())
}

pub fn decode_delete(token: &str) -> ApiResult<BasicJwtClaims> {
    decode_jwt(token, JWT_DELETE_ISSUER.to_string())
}

pub fn decode_verify_email(token: &str) -> ApiResult<BasicJwtClaims> {
    decode_jwt(token, JWT_VERIFYEMAIL_ISSUER.to_string())
}

pub fn decode_admin(token: &str) -> ApiResult<BasicJwtClaims> {
    decode_jwt(token, JWT_ADMIN_ISSUER.to_string())
}

pub fn decode_send(token: &str) -> ApiResult<BasicJwtClaims> {
    decode_jwt(token, JWT_SEND_ISSUER.to_string())
}

pub fn decode_api_org(token: &str) -> ApiResult<OrgApiKeyLoginJwtClaims> {
    decode_jwt(token, JWT_ORG_API_KEY_ISSUER.to_string())
}

#[derive(Debug, Serialize, Deserialize)]
pub struct LoginJwtClaims {
    // Not before
    pub nbf: i64,
    // Expiration time
    pub exp: i64,
    // Issuer
    pub iss: String,
    // Subject
    pub sub: Uuid,

    pub premium: bool,
    pub name: String,
    pub email: String,
    pub email_verified: bool,

    pub orgowner: Vec<Uuid>,
    pub orgadmin: Vec<Uuid>,
    pub orguser: Vec<Uuid>,
    pub orgmanager: Vec<Uuid>,

    // user security_stamp
    pub sstamp: Uuid,
    // device uuid
    pub device: Uuid,
    // [ "api", "offline_access" ]
    pub scope: Vec<String>,
    // [ "Application" ]
    pub amr: Vec<String>,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct InviteJwtClaims {
    // Not before
    pub nbf: i64,
    // Expiration time
    pub exp: i64,
    // Issuer
    pub iss: String,
    // Subject (and user_uuid)
    pub sub: Uuid,

    pub email: String,
    pub org_uuid: Option<Uuid>,
    pub invited_by_email: Option<String>,
}

pub fn generate_invite_claims(user_uuid: Uuid, email: String, org_uuid: Option<Uuid>, invited_by_email: Option<String>) -> InviteJwtClaims {
    let time_now = Utc::now();
    let expire_hours = i64::from(CONFIG.settings.invitation_expiration_hours);
    InviteJwtClaims {
        nbf: time_now.timestamp(),
        exp: (time_now + Duration::hours(expire_hours)).timestamp(),
        iss: JWT_INVITE_ISSUER.to_string(),
        sub: user_uuid,
        email,
        org_uuid,
        invited_by_email,
    }
}

#[derive(Debug, Serialize, Deserialize)]
pub struct EmergencyAccessInviteJwtClaims {
    // Not before
    pub nbf: i64,
    // Expiration time
    pub exp: i64,
    // Issuer
    pub iss: String,
    // Subject
    pub sub: String,

    pub email: String,
    pub emer_id: Uuid,
    pub grantor_name: String,
    pub grantor_email: String,
}

pub fn generate_emergency_access_invite_claims(
    uuid: String,
    email: String,
    emer_id: Uuid,
    grantor_name: String,
    grantor_email: String,
) -> EmergencyAccessInviteJwtClaims {
    let time_now = Utc::now();
    let expire_hours = i64::from(CONFIG.settings.invitation_expiration_hours);
    EmergencyAccessInviteJwtClaims {
        nbf: time_now.timestamp(),
        exp: (time_now + Duration::hours(expire_hours)).timestamp(),
        iss: JWT_EMERGENCY_ACCESS_INVITE_ISSUER.to_string(),
        sub: uuid,
        email,
        emer_id,
        grantor_name,
        grantor_email,
    }
}

#[derive(Debug, Serialize, Deserialize)]
pub struct OrgApiKeyLoginJwtClaims {
    // Not before
    pub nbf: i64,
    // Expiration time
    pub exp: i64,
    // Issuer
    pub iss: String,
    // Subject
    pub sub: Uuid,

    pub client_id: String,
    pub client_sub: Uuid,
    pub scope: Vec<String>,
}

pub fn generate_organization_api_key_login_claims(uuid: Uuid, org_id: Uuid) -> OrgApiKeyLoginJwtClaims {
    let time_now = Utc::now();
    OrgApiKeyLoginJwtClaims {
        nbf: time_now.timestamp(),
        exp: (time_now + Duration::hours(1)).timestamp(),
        iss: JWT_ORG_API_KEY_ISSUER.to_string(),
        sub: uuid,
        client_id: format!("organization.{org_id}"),
        client_sub: org_id,
        scope: vec!["api.organization".into()],
    }
}

#[derive(Debug, Serialize, Deserialize)]
pub struct BasicJwtClaims {
    // Not before
    pub nbf: i64,
    // Expiration time
    pub exp: i64,
    // Issuer
    pub iss: String,
    // Subject
    pub sub: String,
}

pub fn generate_delete_claims(uuid: String) -> BasicJwtClaims {
    let time_now = Utc::now();
    let expire_hours = i64::from(CONFIG.settings.invitation_expiration_hours);
    BasicJwtClaims {
        nbf: time_now.timestamp(),
        exp: (time_now + Duration::hours(expire_hours)).timestamp(),
        iss: JWT_DELETE_ISSUER.to_string(),
        sub: uuid,
    }
}

#[derive(Debug, Serialize, Deserialize)]
pub struct SsoTokenJwtClaims {
    // Not before
    pub nbf: i64,
    // Expiration time
    pub exp: i64,
    // Issuer
    pub iss: String,
    // Subject
    pub sub: Uuid,
    pub domainhint: String,
}

pub fn generate_ssotoken_claims(org_id: Uuid, domainhint: String) -> SsoTokenJwtClaims {
    let time_now = Utc::now();
    SsoTokenJwtClaims {
        nbf: time_now.timestamp(),
        exp: (time_now + Duration::minutes(2)).timestamp(),
        iss: JWT_SSOTOKEN_ISSUER.to_string(),
        sub: org_id,
        domainhint,
    }
}

pub fn generate_verify_email_claims(uuid: String) -> BasicJwtClaims {
    let time_now = Utc::now();
    let expire_hours = i64::from(CONFIG.settings.invitation_expiration_hours);
    BasicJwtClaims {
        nbf: time_now.timestamp(),
        exp: (time_now + Duration::hours(expire_hours)).timestamp(),
        iss: JWT_VERIFYEMAIL_ISSUER.to_string(),
        sub: uuid,
    }
}

pub fn generate_admin_claims() -> BasicJwtClaims {
    let time_now = Utc::now();
    BasicJwtClaims {
        nbf: time_now.timestamp(),
        exp: (time_now + Duration::minutes(CONFIG.advanced.admin_session_lifetime)).timestamp(),
        iss: JWT_ADMIN_ISSUER.to_string(),
        sub: "admin_panel".to_string(),
    }
}

pub fn generate_send_claims(send_id: Uuid, file_id: Uuid) -> BasicJwtClaims {
    let time_now = Utc::now();
    BasicJwtClaims {
        nbf: time_now.timestamp(),
        exp: (time_now + Duration::minutes(2)).timestamp(),
        iss: JWT_SEND_ISSUER.to_string(),
        sub: format!("{send_id}/{file_id}"),
    }
}

//
// Bearer token authentication
//

pub struct ClientHeaders {
    pub device_type: i32,
    pub ip: ClientIp,
}

#[async_trait::async_trait]
impl<S: Send + Sync> FromRequestParts<S> for ClientHeaders {
    type Rejection = ApiError;

    async fn from_request_parts(req: &mut Parts, state: &S) -> ApiResult<Self> {
        let ip = ClientIp::from_request_parts(req, state).await?;
        // When unknown or unable to parse, return 14, which is 'Unknown Browser'
        let device_type: i32 = req.headers.get("device-type").and_then(|x| x.to_str().ok()).map(|d| d.parse().unwrap_or(14)).unwrap_or_else(|| 14);

        Ok(ClientHeaders {
            device_type,
            ip,
        })
    }
}

pub struct Headers {
    pub device: Device,
    pub user: User,
    pub ip: IpAddr,
}

#[async_trait::async_trait]
impl<S: Send + Sync> FromRequestParts<S> for Headers {
    type Rejection = ApiError;

    async fn from_request_parts(parts: &mut Parts, state: &S) -> Result<Self, Self::Rejection> {
        let ip = ClientIp::from_request_parts(parts, state).await?.ip;

        let access_token = parts
            .headers
            .get("authorization")
            .and_then(|x| x.to_str().ok())
            .and_then(|x| x.strip_prefix("Bearer "))
            .ok_or(ApiError::Unauthorized("missing authorization header".to_string()))?;

        // Check JWT token is valid and get device and user from it
        let claims = match decode_login(access_token) {
            Ok(claims) => claims,
            Err(_) => return Err(ApiError::Unauthorized("invalid token".to_string())),
        };

        let device_uuid = claims.device;
        let user_uuid = claims.sub;

        let conn = DB.get().await?;

        let device = match Device::find_by_uuid_and_user(&conn, device_uuid, user_uuid).await? {
            Some(device) => device,
            None => return Err(ApiError::Unauthorized("device not found".to_string())),
        };

        let user = match User::get(&conn, user_uuid).await? {
            Some(user) => user,
            None => return Err(ApiError::Unauthorized("user not found".to_string())),
        };

        if user.security_stamp != claims.sstamp {
            if let Some(stamp_exception) = user.stamp_exception.as_deref().and_then(|s| serde_json::from_str::<UserStampException>(s).ok()) {
                let matched_path = MatchedPath::from_request_parts(parts, state).await.map_err(|e| ApiError::Response(e.into_response()))?;

                // Check if the stamp exception has expired first.
                // Then, check if the current route matches any of the allowed routes.
                // After that check the stamp in exception matches the one in the claims.
                if Utc::now().timestamp() > stamp_exception.expire {
                    // If the stamp exception has been expired remove it from the database.
                    // This prevents checking this stamp exception for new requests.
                    let mut user = user;
                    user.reset_stamp_exception();
                    if let Err(e) = user.save(&conn).await {
                        error!("Error updating user: {:#?}", e);
                    }
                    return Err(ApiError::Unauthorized("Stamp exception is expired".to_string()));
                } else if !stamp_exception.routes.iter().any(|x| x == matched_path.as_str()) {
                    return Err(ApiError::Unauthorized("Invalid security stamp: Current route and exception route do not match".to_string()));
                } else if stamp_exception.security_stamp != claims.sstamp {
                    return Err(ApiError::Unauthorized("Invalid security stamp for matched stamp exception".to_string()));
                }
            } else {
                return Err(ApiError::Unauthorized("Invalid security stamp".to_string()));
            }
        }

        Ok(Headers {
            device,
            user,
            ip,
        })
    }
}

pub struct OrgHeaders {
    pub device: Device,
    pub user: User,
    pub org_user_type: UserOrgType,
    pub org_user: UserOrganization,
    pub org_id: Uuid,
    pub ip: IpAddr,
}

#[derive(Deserialize)]
struct OrgIdPath {
    org_uuid: Uuid,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct OrgIdQuery {
    organization_id: Uuid,
}

#[async_trait::async_trait]
impl<S: Send + Sync> FromRequestParts<S> for OrgHeaders {
    type Rejection = ApiError;

    async fn from_request_parts(parts: &mut Parts, state: &S) -> Result<Self, Self::Rejection> {
        let headers = Headers::from_request_parts(parts, state).await?;

        // org_id is usually the second path param ("/organizations/<org_id>"),
        // but there are cases where it is a query value.
        // First check the path, if this is not a valid uuid, try the query values.

        //TODO: this is error prone, and should be _deleted_! REFACTOR THIS AWAY!
        let url_org_id: Option<Uuid> = {
            let mut url_org_id = None;
            if let Some(path) = Path::<OrgIdPath>::from_request_parts(parts, state).await.ok() {
                url_org_id = Some(path.org_uuid);
            }
            if let Some(query) = Query::<OrgIdQuery>::from_request_parts(parts, state).await.ok() {
                url_org_id = Some(query.organization_id);
            }

            url_org_id
        };

        match url_org_id {
            Some(org_id) => {
                let conn = DB.get().await?;

                let user = headers.user;
                let org_user = match UserOrganization::get(&conn, user.uuid, org_id).await? {
                    Some(user) => {
                        if user.status() == UserOrgStatus::Confirmed {
                            user
                        } else {
                            return Err(ApiError::Forbidden("The current user isn't confirmed member of the organization".to_string()));
                        }
                    }
                    None => {
                        return Err(ApiError::Forbidden("The current user isn't member of the organization".to_string()));
                    }
                };

                Ok(Self {
                    device: headers.device,
                    user,
                    org_user_type: org_user.atype,
                    org_user,
                    org_id,
                    ip: headers.ip,
                })
            }
            _ => Err(ApiError::Other(anyhow::anyhow!("Error getting the organization id"))),
        }
    }
}

pub struct OrgAdminHeaders {
    pub device: Device,
    pub user: User,
    pub org_user_type: UserOrgType,
    pub client_version: Option<String>,
    pub ip: IpAddr,
}

#[async_trait::async_trait]
impl<S: Send + Sync> FromRequestParts<S> for OrgAdminHeaders {
    type Rejection = ApiError;

    async fn from_request_parts(parts: &mut Parts, state: &S) -> Result<Self, Self::Rejection> {
        let headers = OrgHeaders::from_request_parts(parts, state).await?;
        let client_version = parts.headers.get("bitwarden-client-version").and_then(|x| x.to_str().ok()).map(|x| x.to_string());
        if headers.org_user_type < UserOrgType::Admin {
            err!("You need to be Admin or Owner to call this endpoint");
        }
        Ok(Self {
            device: headers.device,
            user: headers.user,
            org_user_type: headers.org_user_type,
            client_version,
            ip: headers.ip,
        })
    }
}

impl From<OrgAdminHeaders> for Headers {
    fn from(h: OrgAdminHeaders) -> Headers {
        Headers {
            device: h.device,
            user: h.user,
            ip: h.ip,
        }
    }
}

#[derive(Deserialize)]
struct ColIdPath {
    col_id: Uuid,
}

#[derive(Deserialize)]
struct ColIdQuery {
    #[serde(rename = "collectionId")]
    collection_id: Uuid,
}

// col_id is usually the fourth path param ("/organizations/<org_id>/collections/<col_id>"),
// but there could be cases where it is a query value.
// First check the path, if this is not a valid uuid, try the query values.
async fn get_col_id<S: Send + Sync>(parts: &mut Parts, state: &S) -> Option<Uuid> {
    if let Ok(Path(col_id)) = Path::<ColIdPath>::from_request_parts(parts, state).await {
        return Some(col_id.col_id);
    }

    if let Ok(col_id) = Query::<ColIdQuery>::from_request_parts(parts, state).await {
        return Some(col_id.collection_id);
    }

    None
}

/// The ManagerHeaders are used to check if you are at least a Manager
/// and have access to the specific collection provided via the <col_id>/collections/collectionId.
/// This does strict checking on the collection_id, ManagerHeadersLoose does not.
pub struct ManagerHeaders {
    pub device: Device,
    pub user: User,
    pub org_user_type: UserOrgType,
    pub ip: IpAddr,
}

#[async_trait::async_trait]
impl<S: Send + Sync> FromRequestParts<S> for ManagerHeaders {
    type Rejection = ApiError;

    async fn from_request_parts(parts: &mut Parts, state: &S) -> Result<Self, Self::Rejection> {
        let headers = OrgHeaders::from_request_parts(parts, state).await?;
        if headers.org_user_type < UserOrgType::Manager {
            err!("You need to be Admin or Owner or Manager with sufficient permissions to call this endpoint")
        }
        let conn = DB.get().await?;
        let Some(col_id) = get_col_id(parts, state).await else {
            err!("Error getting the collection id");
        };
        if Collection::find_by_uuid_and_user(&conn, col_id, headers.user.uuid).await?.is_none() {
            err!("Collection not found");
        }
        Ok(Self {
            device: headers.device,
            user: headers.user,
            org_user_type: headers.org_user_type,
            ip: headers.ip,
        })
    }
}

impl From<ManagerHeaders> for Headers {
    fn from(h: ManagerHeaders) -> Headers {
        Headers {
            device: h.device,
            user: h.user,
            ip: h.ip,
        }
    }
}

/// The ManagerHeadersLoose is used when you at least need to be a Manager,
/// but there is no collection_id sent with the request (either in the path or as form data).
pub struct ManagerHeadersLoose {
    pub device: Device,
    pub user: User,
    pub org_user: UserOrganization,
    pub org_user_type: UserOrgType,
    pub ip: IpAddr,
}

#[async_trait::async_trait]
impl<S: Send + Sync> FromRequestParts<S> for ManagerHeadersLoose {
    type Rejection = ApiError;

    async fn from_request_parts(parts: &mut Parts, state: &S) -> Result<Self, Self::Rejection> {
        let headers = OrgHeaders::from_request_parts(parts, state).await?;
        if headers.org_user_type < UserOrgType::Manager {
            err!("You need to be Admin or Owner or Manager to call this endpoint")
        }
        Ok(Self {
            device: headers.device,
            user: headers.user,
            org_user: headers.org_user,
            org_user_type: headers.org_user_type,
            ip: headers.ip,
        })
    }
}

impl From<ManagerHeadersLoose> for Headers {
    fn from(h: ManagerHeadersLoose) -> Headers {
        Headers {
            device: h.device,
            user: h.user,
            ip: h.ip,
        }
    }
}

impl ManagerHeaders {
    pub async fn from_loose(h: ManagerHeadersLoose, collections: &[Uuid], conn: &Conn) -> ApiResult<ManagerHeaders> {
        for col_id in collections {
            if Collection::find_by_uuid_and_user(&conn, *col_id, h.user.uuid).await?.is_none() {
                err!("Collection not found");
            }
        }

        Ok(ManagerHeaders {
            device: h.device,
            user: h.user,
            org_user_type: h.org_user_type,
            ip: h.ip,
        })
    }
}

pub struct OrgOwnerHeaders {
    pub device: Device,
    pub user: User,
    pub ip: IpAddr,
}

#[async_trait::async_trait]
impl<S: Send + Sync> FromRequestParts<S> for OrgOwnerHeaders {
    type Rejection = ApiError;

    async fn from_request_parts(parts: &mut Parts, state: &S) -> Result<Self, Self::Rejection> {
        let headers = OrgHeaders::from_request_parts(parts, state).await?;
        if headers.org_user_type != UserOrgType::Owner {
            err!("You need to be Owner to call this endpoint")
        }
        Ok(Self {
            device: headers.device,
            user: headers.user,
            ip: headers.ip,
        })
    }
}

//
// Client IP address detection
//
use std::net::{IpAddr, SocketAddr};

pub struct ClientIp {
    pub ip: IpAddr,
}

#[async_trait::async_trait]
impl<S: Send + Sync> FromRequestParts<S> for ClientIp {
    type Rejection = ApiError;

    async fn from_request_parts(req: &mut Parts, state: &S) -> ApiResult<Self> {
        let ip = req.headers.get(&CONFIG.advanced.ip_header).and_then(|x| x.to_str().ok()).and_then(|ip| {
            match ip.find(',') {
                Some(idx) => &ip[..idx],
                None => ip,
            }
            .parse()
            .map_err(|_| warn!("'{}' header is malformed: {}", CONFIG.advanced.ip_header, ip))
            .ok()
        });

        if let Some(ip) = ip {
            return Ok(ClientIp {
                ip,
            });
        }

        let info = ConnectInfo::<SocketAddr>::from_request_parts(req, state).await?;

        Ok(ClientIp {
            ip: info.0.ip(),
        })
    }
}
