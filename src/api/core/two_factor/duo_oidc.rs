//! Duo Universal Prompt (OIDC / OAuth2) two-factor flow.
//!
//! Duo shut down the legacy Web SDK v2 iframe (`{Host, Signature}`) this fork previously spoke;
//! modern clients expect an `{AuthUrl}` OIDC redirect. This module ports the Duo Universal flow
//! from upstream Vaultwarden (`dani-garcia/vaultwarden`, `duo_oidc.rs`), adapted to this fork's
//! axol/tokio-postgres stack: it mints the signed authorization-request JWT, stores a short-lived
//! [`TwoFactorDuoContext`] keyed by OAuth2 state, and on redirect-back exchanges the authorization
//! code for a verified ID token.
//!
//! Config reuses the existing Duo keys ([`crate::config::DuoConfig`] / per-user config): the
//! integration key / secret key double as the OIDC `client_id` / `client_secret`.

use std::collections::HashMap;

use axol::prelude::*;
use chrono::Utc;
use data_encoding::HEXLOWER;
use jsonwebtoken::{Algorithm, DecodingKey, EncodingKey, Header, Validation};
use log::{debug, error};
use reqwest::{StatusCode, header};
use ring::digest::{Digest, SHA512_256, digest};
use serde::{Deserialize, Serialize};
use url::Url;
use uuid::Uuid;

use crate::{
    CONFIG,
    api::core::two_factor::duo::get_duo_keys_email,
    crypto,
    db::{Conn, DB, Event, EventType, TwoFactorDuoContext},
    util::get_reqwest_client,
};

// The location on this service that Duo should redirect users to. For us, this is a bridge
// built in to the Bitwarden clients.
// See: https://github.com/bitwarden/clients/blob/main/apps/web/src/connectors/duo-redirect.ts
const DUO_REDIRECT_LOCATION: &str = "duo-redirect-connector.html";

// Number of seconds that a JWT we generate for Duo should be valid for.
const JWT_VALIDITY_SECS: i64 = 300;

// Number of seconds that a Duo context stored in the database should be valid for.
const CTX_VALIDITY_SECS: i64 = 300;

// Expected algorithm used by Duo to sign JWTs.
const DUO_RESP_SIGNATURE_ALG: Algorithm = Algorithm::HS512;

// Signature algorithm we're using to sign JWTs for Duo. Must be either HS512 or HS256.
const JWT_SIGNATURE_ALG: Algorithm = Algorithm::HS512;

// Size of random strings for state and nonce. Must be at least 16 and at most 1024 characters.
const STATE_LENGTH: usize = 64;

// client_assertion payload for health checks and obtaining MFA results.
#[derive(Debug, Serialize, Deserialize)]
struct ClientAssertion {
    pub iss: String,
    pub sub: String,
    pub aud: String,
    pub exp: i64,
    pub jti: String,
    pub iat: i64,
}

// authorization request payload sent with clients to Duo for MFA.
#[derive(Debug, Serialize, Deserialize)]
struct AuthorizationRequest {
    pub response_type: String,
    pub scope: String,
    pub exp: i64,
    pub client_id: String,
    pub redirect_uri: String,
    pub state: String,
    pub duo_uname: String,
    pub iss: String,
    pub aud: String,
    pub nonce: String,
}

// Duo service health check responses.
#[derive(Debug, Serialize, Deserialize)]
#[serde(untagged)]
enum HealthCheckResponse {
    HealthOK {
        stat: String,
    },
    HealthFail {
        message: String,
        message_detail: String,
    },
}

// Outer structure of response when exchanging authz code for MFA results.
#[derive(Debug, Serialize, Deserialize)]
struct IdTokenResponse {
    id_token: String, // IdTokenClaims
    #[allow(dead_code)]
    access_token: String,
    #[allow(dead_code)]
    expires_in: i64,
    #[allow(dead_code)]
    token_type: String,
}

// Inner structure of IdTokenResponse.id_token.
#[derive(Debug, Serialize, Deserialize)]
struct IdTokenClaims {
    preferred_username: String,
    nonce: String,
}

// Duo OIDC Authorization Client. See https://duo.com/docs/oauthapi
struct DuoClient {
    client_id: String,     // Duo Client ID (integration key)
    client_secret: String, // Duo Client Secret (secret key)
    api_host: String,      // Duo API hostname
    redirect_uri: String,  // URL in this application clients should call for MFA verification
}

impl DuoClient {
    fn new(client_id: String, client_secret: String, api_host: String, redirect_uri: String) -> DuoClient {
        DuoClient {
            client_id,
            client_secret,
            api_host,
            redirect_uri,
        }
    }

    // Generate a client assertion for health checks and authorization code exchange.
    fn new_client_assertion(&self, url: &str) -> ClientAssertion {
        let now = Utc::now().timestamp();
        let jwt_id = crypto::get_random_string_alphanum(STATE_LENGTH);

        ClientAssertion {
            iss: self.client_id.clone(),
            sub: self.client_id.clone(),
            aud: url.to_owned(),
            exp: now + JWT_VALIDITY_SECS,
            jti: jwt_id,
            iat: now,
        }
    }

    // Given a serde-serializable struct, attempt to encode it as a JWT.
    fn encode_duo_jwt<T: Serialize>(&self, jwt_payload: T) -> Result<String> {
        match jsonwebtoken::encode(&Header::new(JWT_SIGNATURE_ALG), &jwt_payload, &EncodingKey::from_secret(self.client_secret.as_bytes())) {
            Ok(token) => Ok(token),
            Err(e) => err!(format!("Error encoding Duo JWT: {e:?}")),
        }
    }

    // "required" health check to verify the integration is configured and Duo's services are up.
    // https://duo.com/docs/oauthapi#health-check
    async fn health_check(&self) -> Result<()> {
        let health_check_url: String = format!("https://{}/oauth/v1/health_check", self.api_host);

        let token = self.encode_duo_jwt(self.new_client_assertion(&health_check_url))?;

        let mut post_body = HashMap::new();
        post_body.insert("client_assertion", token);
        post_body.insert("client_id", self.client_id.clone());

        let res = match get_reqwest_client().post(&health_check_url).header(header::USER_AGENT, "vaultwarden:Duo/2.0 (Rust)").form(&post_body).send().await {
            Ok(r) => r,
            Err(e) => err!(format!("Error requesting Duo health check: {e:?}")),
        };

        let response: HealthCheckResponse = match res.json::<HealthCheckResponse>().await {
            Ok(r) => r,
            Err(e) => err!(format!("Duo health check response decode error: {e:?}")),
        };

        let health_stat: String = match response {
            HealthCheckResponse::HealthOK {
                stat,
            } => stat,
            HealthCheckResponse::HealthFail {
                message,
                message_detail,
            } => err!(format!("Duo health check FAIL response, msg: {message}, detail: {message_detail}")),
        };

        if health_stat != "OK" {
            err!(format!("Duo health check failed, got OK-like body with stat {health_stat}"));
        }

        Ok(())
    }

    // Constructs the URL for the authorization request endpoint on Duo's service. Clients are sent
    // here to continue authentication. https://duo.com/docs/oauthapi#authorization-request
    fn make_authz_req_url(&self, duo_username: &str, state: String, nonce: String) -> Result<String> {
        let now = Utc::now().timestamp();

        let jwt_payload = AuthorizationRequest {
            response_type: String::from("code"),
            scope: String::from("openid"),
            exp: now + JWT_VALIDITY_SECS,
            client_id: self.client_id.clone(),
            redirect_uri: self.redirect_uri.clone(),
            state,
            duo_uname: String::from(duo_username),
            iss: self.client_id.clone(),
            aud: format!("https://{}", self.api_host),
            nonce,
        };

        let token = self.encode_duo_jwt(jwt_payload)?;

        let authz_endpoint = format!("https://{}/oauth/v1/authorize", self.api_host);
        let mut auth_url = match Url::parse(authz_endpoint.as_str()) {
            Ok(url) => url,
            Err(e) => err!(format!("Error parsing Duo authorization URL: {e:?}")),
        };

        {
            let mut query_params = auth_url.query_pairs_mut();
            query_params.append_pair("response_type", "code");
            query_params.append_pair("client_id", self.client_id.as_str());
            query_params.append_pair("request", token.as_str());
        }

        Ok(auth_url.to_string())
    }

    // Exchange the authorization code for the result of the MFA and validate it.
    // See: https://duo.com/docs/oauthapi#access-token (under Response Format)
    async fn exchange_authz_code_for_result(&self, duo_code: &str, duo_username: &str, nonce: &str) -> Result<()> {
        if duo_code.is_empty() {
            err!("Empty Duo authorization code")
        }

        let token_url = format!("https://{}/oauth/v1/token", self.api_host);

        let token = self.encode_duo_jwt(self.new_client_assertion(&token_url))?;

        let mut post_body = HashMap::new();
        post_body.insert("grant_type", String::from("authorization_code"));
        post_body.insert("code", String::from(duo_code));

        // Must be the same URL that was supplied in the authorization request for the supplied duo_code.
        post_body.insert("redirect_uri", self.redirect_uri.clone());
        post_body.insert("client_assertion_type", String::from("urn:ietf:params:oauth:client-assertion-type:jwt-bearer"));
        post_body.insert("client_assertion", token);

        let res = match get_reqwest_client().post(&token_url).header(header::USER_AGENT, "vaultwarden:Duo/2.0 (Rust)").form(&post_body).send().await {
            Ok(r) => r,
            Err(e) => err!(format!("Error exchanging Duo code: {e:?}")),
        };

        let status_code = res.status();
        if status_code != StatusCode::OK {
            err!(format!("Failure response from Duo: {status_code}"))
        }

        let response: IdTokenResponse = match res.json::<IdTokenResponse>().await {
            Ok(r) => r,
            Err(e) => err!(format!("Error decoding ID token response: {e:?}")),
        };

        let mut validation = Validation::new(DUO_RESP_SIGNATURE_ALG);
        validation.set_required_spec_claims(&["exp", "aud", "iss"]);
        validation.set_audience(&[&self.client_id]);
        validation.set_issuer(&[token_url.as_str()]);

        let token_data = match jsonwebtoken::decode::<IdTokenClaims>(&response.id_token, &DecodingKey::from_secret(self.client_secret.as_bytes()), &validation)
        {
            Ok(c) => c,
            Err(e) => err!(format!("Failed to decode Duo token {e:?}")),
        };

        let matching_nonces = crypto::ct_eq(nonce, &token_data.claims.nonce);
        let matching_usernames = crypto::ct_eq(duo_username, &token_data.claims.preferred_username);

        if !(matching_nonces && matching_usernames) {
            err!("Error validating Duo authorization, nonce or username mismatch.")
        }

        Ok(())
    }
}

// Given a state string, retrieve the associated Duo auth context and delete it from the database.
async fn extract_context(conn: &Conn, state: &str) -> Result<Option<TwoFactorDuoContext>> {
    let Some(ctx) = TwoFactorDuoContext::find_by_state(conn, state).await? else {
        return Ok(None);
    };

    if ctx.exp < Utc::now().timestamp() {
        ctx.delete(conn).await.ok();
        return Ok(None);
    }

    ctx.delete(conn).await.ok();
    Ok(Some(ctx))
}

// Background job entry point: clean up expired Duo authentication contexts.
pub async fn purge_duo_contexts() {
    debug!("Purging Duo authentication contexts");
    let Ok(conn) = DB.get().await else {
        error!("Failed to get DB connection while purging expired Duo authentications");
        return;
    };
    if let Err(e) = TwoFactorDuoContext::purge_expired(&conn).await {
        error!("failed to purge Duo contexts: {e}");
    }
}

// Construct the url that Duo should redirect users to.
fn make_callback_url(client_name: &str) -> Result<String> {
    // Location of this application (public URL), with a trailing slash so `join` treats it as a base.
    let base = match Url::parse(&format!("{}/", CONFIG.settings.public)) {
        Ok(url) => url,
        Err(e) => err!(format!("Error parsing configured public URL (check your configuration): {e:?}")),
    };

    let mut callback = match base.join(DUO_REDIRECT_LOCATION) {
        Ok(url) => url,
        Err(e) => err!(format!("Error constructing Duo redirect URL (check your configuration): {e:?}")),
    };

    // The callback connector uses `client` to figure out how to handle certain clients.
    callback.query_pairs_mut().append_pair("client", client_name);
    Ok(callback.to_string())
}

// Pre-redirect first stage of the Duo OIDC authentication flow.
// Returns the "AuthUrl" that should be returned to clients for MFA.
pub async fn get_duo_auth_url(conn: &Conn, email: &str, client_id: &str, device_identifier: Uuid) -> Result<String> {
    let (ik, sk, _, host) = get_duo_keys_email(email, conn).await?;

    let callback_url = make_callback_url(client_id)?;

    let client = DuoClient::new(ik, sk, host.host_str().unwrap_or_default().to_string(), callback_url);

    client.health_check().await?;

    // Generate random OAuth2 state and OIDC nonce.
    let state: String = crypto::get_random_string_alphanum(STATE_LENGTH);
    let nonce: String = crypto::get_random_string_alphanum(STATE_LENGTH);

    // Bind the nonce to the authing device by hashing the nonce and device id, sending the result
    // as the OIDC nonce.
    let d: Digest = digest(&SHA512_256, format!("{nonce}{device_identifier}").as_bytes());
    let hash: String = HEXLOWER.encode(d.as_ref());

    TwoFactorDuoContext::save(conn, state.as_str(), email, nonce.as_str(), CTX_VALIDITY_SECS).await?;
    client.make_authz_req_url(email, state, hash)
}

// Post-redirect second stage of the Duo OIDC authentication flow.
// Exchanges an authorization code for the MFA result with Duo's API and validates it.
pub async fn validate_duo_login(conn: &Conn, user_uuid: Uuid, email: &str, two_factor_token: &str, client_id: &str, device_identifier: Uuid) -> Result<()> {
    let email = &email.to_lowercase();

    // Result supplied by clients in the form "<authz code>|<state>".
    let split: Vec<&str> = two_factor_token.split('|').collect();
    if split.len() != 2 {
        Event::new(EventType::UserFailedLogIn2fa, None).with_user_uuid(user_uuid).save(conn).await?;
        err!("Invalid response length");
    }

    let code = split[0];
    let state = split[1];

    let (ik, sk, _, host) = get_duo_keys_email(email, conn).await?;

    // Get and consume the context by the state reported by the client.
    let Some(ctx) = extract_context(conn, state).await? else {
        Event::new(EventType::UserFailedLogIn2fa, None).with_user_uuid(user_uuid).save(conn).await?;
        err!("Error validating duo authentication")
    };

    let matching_usernames = crypto::ct_eq(email, &ctx.user_email);
    let matching_states = crypto::ct_eq(state, &ctx.state);
    let unexpired_context = ctx.exp > Utc::now().timestamp();

    if !(matching_usernames && matching_states && unexpired_context) {
        Event::new(EventType::UserFailedLogIn2fa, None).with_user_uuid(user_uuid).save(conn).await?;
        err!("Error validating duo authentication")
    }

    let callback_url = make_callback_url(client_id)?;
    let client = DuoClient::new(ik, sk, host.host_str().unwrap_or_default().to_string(), callback_url);

    client.health_check().await?;

    let d: Digest = digest(&SHA512_256, format!("{}{device_identifier}", ctx.nonce).as_bytes());
    let hash: String = HEXLOWER.encode(d.as_ref());

    match client.exchange_authz_code_for_result(code, email, hash.as_str()).await {
        Ok(()) => Ok(()),
        Err(_) => {
            Event::new(EventType::UserFailedLogIn2fa, None).with_user_uuid(user_uuid).save(conn).await?;
            err!("Error validating duo authentication")
        }
    }
}
