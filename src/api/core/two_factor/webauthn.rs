use axol::prelude::*;
use chrono::Utc;
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use url::Url;
use uuid::Uuid;
use webauthn_rs::{base64_data::Base64UrlSafeData, proto::*, AuthenticationState, RegistrationState, Webauthn};

use crate::{
    api::PasswordData,
    auth::Headers,
    config::PUBLIC_NO_TRAILING_SLASH,
    db::{Conn, Event, EventType, TwoFactor, TwoFactorType, DB},
    events::log_user_event,
    CONFIG,
};

use super::_generate_recover_code;

struct WebauthnConfig {
    url: Url,
    origin: Url,
    rpid: String,
}

impl WebauthnConfig {
    fn load() -> Webauthn<Self> {
        let domain = CONFIG.settings.public.clone();
        let domain_origin: Url = domain.origin().unicode_serialization().parse().unwrap();
        Webauthn::new(Self {
            rpid: domain.domain().map(str::to_owned).unwrap_or_default(),
            url: domain,
            origin: domain_origin,
        })
    }
}

impl webauthn_rs::WebauthnConfig for WebauthnConfig {
    fn get_relying_party_name(&self) -> &str {
        self.url.as_str()
    }

    fn get_origin(&self) -> &Url {
        &self.origin
    }

    fn get_relying_party_id(&self) -> &str {
        &self.rpid
    }

    /// We have WebAuthn configured to discourage user verification
    /// if we leave this enabled, it will cause verification issues when a keys send UV=1.
    /// Upstream (the library they use) ignores this when set to discouraged, so we should too.
    fn get_require_uv_consistency(&self) -> bool {
        false
    }
}

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct WebauthnRegistration {
    pub id: i32,
    pub name: String,
    pub migrated: bool,

    pub credential: Credential,
}

impl WebauthnRegistration {
    fn to_json(&self) -> Value {
        json!({
            "id": self.id,
            "name": self.name,
            "migrated": self.migrated,
        })
    }
}

pub async fn get_webauthn(headers: Headers, data: Json<PasswordData>) -> Result<Json<Value>> {
    headers.user.check_valid_password_data(&data)?;

    let conn = DB.get().await.ise()?;

    let (enabled, registrations) = get_webauthn_registrations(headers.user.uuid, &conn).await?;
    let registrations_json: Vec<Value> = registrations.iter().map(WebauthnRegistration::to_json).collect();

    Ok(Json(json!({
        "enabled": enabled,
        "keys": registrations_json,
        "object": "twoFactorWebAuthn"
    })))
}

pub async fn generate_webauthn_challenge(headers: Headers, data: Json<PasswordData>) -> Result<Json<Value>> {
    headers.user.check_valid_password_data(&data)?;
    let conn = DB.get().await.ise()?;

    let registrations = get_webauthn_registrations(headers.user.uuid, &conn)
        .await?
        .1
        .into_iter()
        .map(|r| r.credential.cred_id) // We return the credentialIds to the clients to avoid double registering
        .collect();

    let (challenge, state) = WebauthnConfig::load()
        .generate_challenge_register_options(headers.user.uuid.as_bytes().to_vec(), headers.user.email, headers.user.name, Some(registrations), None, None)
        .ise()?;

    let type_ = TwoFactorType::WebauthnRegisterChallenge;
    TwoFactor::new(headers.user.uuid, type_, serde_json::to_value(state).ise()?).save(&conn).await?;

    let mut challenge_value = serde_json::to_value(challenge.public_key).ise()?;
    challenge_value["status"] = "ok".into();
    challenge_value["errorMessage"] = "".into();
    Ok(Json(challenge_value))
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct EnableWebauthnData {
    #[serde(deserialize_with = "serde_aux::field_attributes::deserialize_number_from_string")]
    id: i32, // 1..5
    name: String,
    master_password_hash: String,
    device_response: RegisterPublicKeyCredentialCopy,
}

// This is copied from RegisterPublicKeyCredential to change the Response objects casing
#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
struct RegisterPublicKeyCredentialCopy {
    pub id: String,
    pub raw_id: Base64UrlSafeData,
    pub response: AuthenticatorAttestationResponseRawCopy,
    pub r#type: String,
}

// This is copied from AuthenticatorAttestationResponseRaw to change clientDataJSON to clientDataJson
#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct AuthenticatorAttestationResponseRawCopy {
    #[serde(rename = "AttestationObject", alias = "attestationObject")]
    pub attestation_object: Base64UrlSafeData,
    #[serde(rename = "clientDataJson", alias = "clientDataJSON")]
    pub client_data_json: Base64UrlSafeData,
}

impl From<RegisterPublicKeyCredentialCopy> for RegisterPublicKeyCredential {
    fn from(r: RegisterPublicKeyCredentialCopy) -> Self {
        Self {
            id: r.id,
            raw_id: r.raw_id,
            response: AuthenticatorAttestationResponseRaw {
                attestation_object: r.response.attestation_object,
                client_data_json: r.response.client_data_json,
            },
            type_: r.r#type,
        }
    }
}

// This is copied from PublicKeyCredential to change the Response objects casing
#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct PublicKeyCredentialCopy {
    pub id: String,
    pub raw_id: Base64UrlSafeData,
    pub response: AuthenticatorAssertionResponseRawCopy,
    pub extensions: Option<AuthenticationExtensionsClientOutputsCopy>,
    pub r#type: String,
}

// This is copied from AuthenticatorAssertionResponseRaw to change clientDataJSON to clientDataJson
#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct AuthenticatorAssertionResponseRawCopy {
    pub authenticator_data: Base64UrlSafeData,
    #[serde(rename = "clientDataJson", alias = "clientDataJSON")]
    pub client_data_json: Base64UrlSafeData,
    pub signature: Base64UrlSafeData,
    pub user_handle: Option<Base64UrlSafeData>,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct AuthenticationExtensionsClientOutputsCopy {
    #[serde(default)]
    pub appid: bool,
}

impl From<PublicKeyCredentialCopy> for PublicKeyCredential {
    fn from(r: PublicKeyCredentialCopy) -> Self {
        Self {
            id: r.id,
            raw_id: r.raw_id,
            response: AuthenticatorAssertionResponseRaw {
                authenticator_data: r.response.authenticator_data,
                client_data_json: r.response.client_data_json,
                signature: r.response.signature,
                user_handle: r.response.user_handle,
            },
            extensions: r.extensions.map(|e| AuthenticationExtensionsClientOutputs {
                appid: e.appid,
            }),
            type_: r.r#type,
        }
    }
}

pub async fn activate_webauthn(headers: Headers, data: Json<EnableWebauthnData>) -> Result<Json<Value>> {
    let data: EnableWebauthnData = data.0;
    let mut user = headers.user;

    if !user.check_valid_password(&data.master_password_hash) {
        err!("Invalid password");
    }
    let mut conn = DB.get().await.ise()?;

    // Retrieve and delete the saved challenge state
    let state = match TwoFactor::find_by_user_and_type(&conn, user.uuid, TwoFactorType::WebauthnRegisterChallenge).await? {
        Some(tf) => {
            let state: RegistrationState = serde_json::from_value(tf.data.clone()).ise()?;
            tf.delete(&conn).await?;
            state
        }
        None => err!("Can't recover challenge"),
    };

    // Verify the credentials with the saved state
    let (credential, _data) = WebauthnConfig::load().register_credential(&data.device_response.into(), &state, |_| Ok(false)).ise()?;

    let mut registrations: Vec<_> = get_webauthn_registrations(user.uuid, &conn).await?.1;
    // TODO: Check for repeated ID's
    registrations.push(WebauthnRegistration {
        id: data.id,
        name: data.name,
        migrated: false,

        credential,
    });

    // Save the registrations and return them
    TwoFactor::new(user.uuid.clone(), TwoFactorType::Webauthn, serde_json::to_value(registrations.clone()).ise()?).save(&mut conn).await?;
    _generate_recover_code(&mut user, &conn).await?;

    log_user_event(EventType::UserUpdated2fa, user.uuid, headers.device.atype, Utc::now(), headers.ip, &mut conn).await?;

    let keys_json: Vec<Value> = registrations.iter().map(WebauthnRegistration::to_json).collect();
    Ok(Json(json!({
        "enabled": true,
        "keys": keys_json,
        "object": "twoFactorU2f"
    })))
}

#[derive(Deserialize, Debug)]
#[serde(rename_all = "camelCase")]
pub struct DeleteU2FData {
    #[serde(deserialize_with = "serde_aux::field_attributes::deserialize_number_from_string")]
    id: i32,
    master_password_hash: String,
}

pub async fn delete_webauthn(headers: Headers, data: Json<DeleteU2FData>) -> Result<Json<Value>> {
    let id = data.id;
    if !headers.user.check_valid_password(&data.master_password_hash) {
        err!("Invalid password");
    }
    let conn = DB.get().await.ise()?;

    let mut tf = match TwoFactor::find_by_user_and_type(&conn, headers.user.uuid, TwoFactorType::Webauthn).await? {
        Some(tf) => tf,
        None => err!("Webauthn data not found!"),
    };

    let mut data: Vec<WebauthnRegistration> = serde_json::from_value(tf.data).ise()?;

    let item_pos = match data.iter().position(|r| r.id == id) {
        Some(p) => p,
        None => err!("Webauthn entry not found"),
    };

    data.remove(item_pos);
    tf.data = serde_json::to_value(data.clone()).ise()?;
    tf.save(&conn).await?;
    drop(tf);

    let keys_json: Vec<Value> = data.iter().map(WebauthnRegistration::to_json).collect();

    Ok(Json(json!({
        "enabled": true,
        "keys": keys_json,
        "object": "twoFactorU2f"
    })))
}

pub async fn get_webauthn_registrations(user_uuid: Uuid, conn: &Conn) -> Result<(bool, Vec<WebauthnRegistration>)> {
    match TwoFactor::find_by_user_and_type(conn, user_uuid, TwoFactorType::Webauthn).await? {
        Some(tf) => Ok((tf.enabled, serde_json::from_value(tf.data).ise()?)),
        None => Ok((false, Vec::new())), // If no data, return empty list
    }
}

pub async fn generate_webauthn_login(user_uuid: Uuid, conn: &Conn) -> Result<Json<Value>> {
    // Load saved credentials
    let creds: Vec<Credential> = get_webauthn_registrations(user_uuid, conn).await?.1.into_iter().map(|r| r.credential).collect();

    if creds.is_empty() {
        err!("No Webauthn devices registered")
    }

    // Generate a challenge based on the credentials
    let ext = RequestAuthenticationExtensions::builder().appid(format!("{}/app-id.json", &*PUBLIC_NO_TRAILING_SLASH)).build();
    let (response, state) = WebauthnConfig::load().generate_challenge_authenticate_options(creds, Some(ext)).ise()?;

    // Save the challenge state for later validation
    TwoFactor::new(user_uuid.into(), TwoFactorType::WebauthnLoginChallenge, serde_json::to_value(state).ise()?).save(conn).await?;

    // Return challenge to the clients
    Ok(Json(serde_json::to_value(response.public_key).ise()?))
}

pub async fn validate_webauthn_login(user_uuid: Uuid, response: &str, conn: &Conn) -> Result<()> {
    let state = match TwoFactor::find_by_user_and_type(conn, user_uuid, TwoFactorType::WebauthnLoginChallenge).await? {
        Some(tf) => {
            let state: AuthenticationState = serde_json::from_value(tf.data.clone()).ise()?;
            tf.delete(conn).await?;
            state
        }
        None => {
            Event::new(EventType::UserFailedLogIn2fa, None).with_user_uuid(user_uuid).save(conn).await?;
            err!("Can't recover login challenge")
        }
    };

    let rsp: PublicKeyCredentialCopy = serde_json::from_str(response).ise()?;
    let rsp: PublicKeyCredential = rsp.into();

    let mut registrations = get_webauthn_registrations(user_uuid, conn).await?.1;

    // If the credential we received is migrated from U2F, enable the U2F compatibility
    //let use_u2f = registrations.iter().any(|r| r.migrated && r.credential.cred_id == rsp.raw_id.0);
    let (cred_id, auth_data) = WebauthnConfig::load().authenticate_credential(&rsp, &state).ise()?;

    for reg in &mut registrations {
        if &reg.credential.cred_id == cred_id {
            reg.credential.counter = auth_data.counter;

            TwoFactor::new(user_uuid, TwoFactorType::Webauthn, serde_json::to_value(registrations).ise()?).save(conn).await?;
            return Ok(());
        }
    }

    Event::new(EventType::UserFailedLogIn2fa, None).with_user_uuid(user_uuid).save(conn).await?;
    err!("Credential not present")
}
