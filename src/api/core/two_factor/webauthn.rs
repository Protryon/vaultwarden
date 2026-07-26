use std::sync::LazyLock;
use std::time::Duration;

use axol::prelude::*;
use chrono::Utc;
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use url::Url;
use uuid::Uuid;
use webauthn_rs::{
    Webauthn, WebauthnBuilder,
    prelude::{Base64UrlSafeData, Credential, Passkey, PasskeyAuthentication, PasskeyRegistration},
};
use webauthn_rs_proto::{
    AuthenticationExtensionsClientOutputs, AuthenticatorAssertionResponseRaw, AuthenticatorAttestationResponseRaw, PublicKeyCredential,
    RegisterPublicKeyCredential, RegistrationExtensionsClientOutputs, RequestAuthenticationExtensions, UserVerificationPolicy,
};

use crate::{
    CONFIG,
    api::PasswordData,
    auth::Headers,
    config::PUBLIC_NO_TRAILING_SLASH,
    crypto::ct_eq,
    db::{Conn, DB, Event, EventType, TwoFactor, TwoFactorType},
    events::log_user_event,
};

use super::{_generate_recover_code, UserVerify, disable_twofactor_for_user, mint_user_verification_token};

static WEBAUTHN: LazyLock<Webauthn> = LazyLock::new(|| {
    let domain: Url = CONFIG.settings.public.clone();
    let rp_id = domain.domain().map(str::to_owned).unwrap_or_default();
    let rp_origin: Url = domain.origin().unicode_serialization().parse().expect("Invalid webauthn origin");

    let builder = WebauthnBuilder::new(&rp_id, &rp_origin).expect("Creating WebauthnBuilder failed").rp_name(domain.as_str()).timeout(Duration::from_secs(60));

    builder.build().expect("Building Webauthn failed")
});

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct WebauthnRegistration {
    pub id: i32,
    pub name: String,
    pub migrated: bool,

    pub credential: Passkey,
}

impl WebauthnRegistration {
    fn to_json(&self) -> Value {
        json!({
            "id": self.id,
            "name": self.name,
            "migrated": self.migrated,
        })
    }

    fn set_backup_eligible(&mut self, backup_eligible: bool, backup_state: bool) -> bool {
        let mut changed = false;
        let mut cred: Credential = self.credential.clone().into();

        if cred.backup_state != backup_state {
            cred.backup_state = backup_state;
            changed = true;
        }

        if backup_eligible && !cred.backup_eligible {
            cred.backup_eligible = true;
            changed = true;
        }

        self.credential = cred.into();
        changed
    }
}

pub async fn get_webauthn(headers: Headers, data: Json<PasswordData>) -> Result<Json<Value>> {
    headers.user.check_valid_password_data(&data)?;

    let conn = DB.get().await.ise()?;

    let (enabled, registrations) = get_webauthn_registrations(headers.user.uuid, &conn).await?;
    let registrations_json: Vec<Value> = registrations.iter().map(WebauthnRegistration::to_json).collect();

    Ok(Json(json!({
        "enabled": enabled,
        "keys": registrations_json.clone(),
        "webAuthn": { "enabled": enabled, "keys": registrations_json },
        "userVerificationToken": mint_user_verification_token(headers.user.uuid, TwoFactorType::Webauthn),
        "object": "twoFactorWebAuthn"
    })))
}

pub async fn generate_webauthn_challenge(headers: Headers, data: Json<UserVerify>) -> Result<Json<Value>> {
    data.0.validate(&headers.user, TwoFactorType::Webauthn)?;
    let conn = DB.get().await.ise()?;

    let registrations = get_webauthn_registrations(headers.user.uuid, &conn)
        .await?
        .1
        .into_iter()
        .map(|r| r.credential.cred_id().to_owned()) // We return the credentialIds to the clients to avoid double registering
        .collect();

    let (mut challenge, state) = WEBAUTHN.start_passkey_registration(headers.user.uuid, &headers.user.email, &headers.user.name, Some(registrations)).ise()?;

    // We abuse passkeys as 2FA (more like a security key), so we tweak the state to discourage user verification.
    let mut state = serde_json::to_value(&state).ise()?;
    state["rs"]["policy"] = Value::String("discouraged".to_owned());
    if let Some(extensions) = state["rs"]["extensions"].as_object_mut() {
        extensions.clear();
    }

    let type_ = TwoFactorType::WebauthnRegisterChallenge;
    TwoFactor::new(headers.user.uuid, type_, state).save(&conn).await?;

    // Modify the default settings from `start_passkey_registration()` to match the 2FA use case.
    challenge.public_key.extensions = None;
    if let Some(asc) = challenge.public_key.authenticator_selection.as_mut() {
        asc.user_verification = UserVerificationPolicy::Discouraged_DO_NOT_USE;
    }

    let mut challenge_value = serde_json::to_value(challenge.public_key).ise()?;
    challenge_value["status"] = "ok".into();
    challenge_value["errorMessage"] = "".into();

    // The current web-vault expects the challenge wrapped as `{object, options}` (T9). Keep the
    // legacy flat fields alongside `options` so older clients that read the challenge directly
    // still work.
    let mut result = challenge_value.clone();
    result["object"] = "twoFactorWebAuthnChallenge".into();
    result["options"] = challenge_value;
    Ok(Json(result))
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct EnableWebauthnData {
    #[serde(deserialize_with = "serde_aux::field_attributes::deserialize_number_from_string")]
    id: i32, // 1..5
    name: String,
    #[serde(flatten)]
    verify: UserVerify,
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
                transports: None,
            },
            type_: r.r#type,
            extensions: RegistrationExtensionsClientOutputs::default(),
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
    pub extensions: AuthenticationExtensionsClientOutputs,
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
            extensions: r.extensions,
            type_: r.r#type,
        }
    }
}

pub async fn activate_webauthn(headers: Headers, data: Json<EnableWebauthnData>) -> Result<Json<Value>> {
    let data: EnableWebauthnData = data.0;
    let mut user = headers.user;

    data.verify.validate(&user, TwoFactorType::Webauthn)?;
    let mut conn = DB.get().await.ise()?;

    // Retrieve and delete the saved challenge state
    let state = match TwoFactor::find_by_user_and_type(&conn, user.uuid, TwoFactorType::WebauthnRegisterChallenge).await? {
        Some(tf) => {
            let state: PasskeyRegistration = serde_json::from_value(tf.data.clone()).ise()?;
            tf.delete(&conn).await?;
            state
        }
        None => err!("Can't recover challenge"),
    };

    // Verify the credentials with the saved state
    let credential = WEBAUTHN.finish_passkey_registration(&data.device_response.into(), &state).ise()?;

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
        "keys": keys_json.clone(),
        "webAuthn": { "enabled": true, "keys": keys_json },
        "object": "twoFactorWebAuthn"
    })))
}

#[derive(Deserialize, Debug)]
#[serde(rename_all = "camelCase")]
pub struct DeleteU2FData {
    #[serde(deserialize_with = "serde_aux::field_attributes::deserialize_number_from_string")]
    id: i32,
    #[serde(flatten)]
    verify: UserVerify,
}

pub async fn delete_webauthn(headers: Headers, data: Json<DeleteU2FData>) -> Result<Json<Value>> {
    let id = data.id;
    data.verify.validate(&headers.user, TwoFactorType::Webauthn)?;
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
        "keys": keys_json.clone(),
        "webAuthn": { "enabled": true, "keys": keys_json },
        "object": "twoFactorWebAuthn"
    })))
}

/// `DELETE /two-factor/webauthn/all` — disables the WebAuthn provider entirely (all credentials).
/// The current web-vault uses this to turn the method off, distinct from `DELETE /two-factor/webauthn`
/// which removes a single credential by `id`.
pub async fn delete_webauthn_all(headers: Headers, data: Json<UserVerify>) -> Result<Json<Value>> {
    let user = headers.user;
    data.0.validate(&user, TwoFactorType::Webauthn)?;
    let mut conn = DB.get().await.ise()?;

    disable_twofactor_for_user(&user, TwoFactorType::Webauthn, headers.device.atype, headers.ip, &mut conn).await?;

    Ok(Json(json!({
        "enabled": false,
        "keys": [],
        "webAuthn": { "enabled": false, "keys": [] },
        "object": "twoFactorWebAuthn"
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
    let creds: Vec<Passkey> = get_webauthn_registrations(user_uuid, conn).await?.1.into_iter().map(|r| r.credential).collect();

    if creds.is_empty() {
        err!("No Webauthn devices registered")
    }

    // Generate a challenge based on the credentials
    let (mut response, state) = WEBAUTHN.start_passkey_authentication(&creds).ise()?;

    // Modify to discourage user verification
    let mut state = serde_json::to_value(&state).ise()?;
    state["ast"]["policy"] = Value::String("discouraged".to_owned());

    // Add appid, this is only needed for U2F compatibility
    let app_id = format!("{}/app-id.json", &*PUBLIC_NO_TRAILING_SLASH);
    state["ast"]["appid"] = Value::String(app_id.clone());

    response.public_key.user_verification = UserVerificationPolicy::Discouraged_DO_NOT_USE;
    response
        .public_key
        .extensions
        .get_or_insert(RequestAuthenticationExtensions {
            appid: None,
            uvm: None,
            hmac_get_secret: None,
        })
        .appid = Some(app_id);

    // Save the challenge state for later validation
    TwoFactor::new(user_uuid, TwoFactorType::WebauthnLoginChallenge, state).save(conn).await?;

    // Return challenge to the clients
    Ok(Json(serde_json::to_value(response.public_key).ise()?))
}

pub async fn validate_webauthn_login(user_uuid: Uuid, response: &str, conn: &Conn) -> Result<()> {
    let mut state = match TwoFactor::find_by_user_and_type(conn, user_uuid, TwoFactorType::WebauthnLoginChallenge).await? {
        Some(tf) => {
            let state: PasskeyAuthentication = serde_json::from_value(tf.data.clone()).ise()?;
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

    // We need to check for and update the backup_eligible flag when needed.
    // Vaultwarden did not have knowledge of this flag prior to migrating to webauthn-rs v0.5.x
    let backup_flags_updated = check_and_update_backup_eligible(&rsp, &mut registrations, &mut state).ise()?;

    let authentication_result = WEBAUTHN.finish_passkey_authentication(&rsp, &state).ise()?;

    for reg in &mut registrations {
        if ct_eq(reg.credential.cred_id(), authentication_result.cred_id()) {
            // If the cred id matches and the credential is updated, Some(true) is returned
            let credential_updated = reg.credential.update_credential(&authentication_result) == Some(true);
            if credential_updated || backup_flags_updated {
                TwoFactor::new(user_uuid, TwoFactorType::Webauthn, serde_json::to_value(&registrations).ise()?).save(conn).await?;
            }
            return Ok(());
        }
    }

    Event::new(EventType::UserFailedLogIn2fa, None).with_user_uuid(user_uuid).save(conn).await?;
    err!("Credential not present")
}

fn check_and_update_backup_eligible(
    rsp: &PublicKeyCredential,
    registrations: &mut [WebauthnRegistration],
    state: &mut PasskeyAuthentication,
) -> anyhow::Result<bool> {
    // The feature flags from the response
    // For details see: https://www.w3.org/TR/webauthn-3/#sctn-authenticator-data
    const FLAG_BACKUP_ELIGIBLE: u8 = 0b0000_1000;
    const FLAG_BACKUP_STATE: u8 = 0b0001_0000;

    if let Some(bits) = rsp.response.authenticator_data.get(32) {
        let backup_eligible = 0 != (bits & FLAG_BACKUP_ELIGIBLE);
        let backup_state = 0 != (bits & FLAG_BACKUP_STATE);

        // If the current key is backup eligible, we probably need to update one of the keys already stored in the database.
        if backup_eligible {
            let rsp_id = rsp.raw_id.as_slice();
            for reg in &mut *registrations {
                if ct_eq(reg.credential.cred_id().as_slice(), rsp_id) {
                    if reg.set_backup_eligible(backup_eligible, backup_state) {
                        // We also need to adjust the current state which holds the challenge used to start the authentication verification.
                        let mut raw_state = serde_json::to_value(&state)?;
                        if let Some(credentials) = raw_state.get_mut("ast").and_then(|v| v.get_mut("credentials")).and_then(|v| v.as_array_mut()) {
                            for cred in credentials.iter_mut() {
                                if cred.get("cred_id").is_some_and(|v| {
                                    // Deserialize to a [u8] so it can be compared using `ct_eq` with the `rsp_id`
                                    let cred_id_slice: Base64UrlSafeData = serde_json::from_value(v.clone()).unwrap();
                                    ct_eq(cred_id_slice, rsp_id)
                                }) {
                                    cred["backup_eligible"] = Value::Bool(backup_eligible);
                                    cred["backup_state"] = Value::Bool(backup_state);
                                }
                            }
                        }

                        *state = serde_json::from_value(raw_state)?;
                        return Ok(true);
                    }
                    break;
                }
            }
        }
    }
    Ok(false)
}

#[cfg(test)]
mod tests {
    use serde_json::json;

    use crate::test_harness::TestClient;

    #[tokio::test]
    async fn get_webauthn_mints_token_and_uses_correct_object() {
        let client = TestClient::register_and_login().await;
        let resp = client.post("/api/two-factor/get-webauthn", json!({ "masterPasswordHash": client.master_password_hash })).await;
        resp.assert_ok();
        let body = resp.json();
        assert_eq!(body["object"], "twoFactorWebAuthn", "discriminator: {}", resp.body);
        assert!(body["userVerificationToken"].as_str().is_some_and(|t| !t.is_empty()), "should mint a token: {}", resp.body);
    }

    #[tokio::test]
    async fn webauthn_challenge_is_wrapped_in_envelope() {
        let client = TestClient::register_and_login().await;

        // The current web-vault reads the registration challenge as `{object, options}` (T9).
        let resp = client.post("/api/two-factor/get-webauthn-challenge", json!({ "masterPasswordHash": client.master_password_hash })).await;
        resp.assert_ok();
        let body = resp.json();
        assert_eq!(body["object"], "twoFactorWebAuthnChallenge", "envelope object: {}", resp.body);
        assert!(body["options"].is_object(), "options should be nested: {}", resp.body);
        // The nested options still carry the FIDO2 challenge fields.
        assert!(body["options"]["challenge"].as_str().is_some(), "challenge inside options: {}", resp.body);
    }

    #[tokio::test]
    async fn webauthn_challenge_accepts_user_verification_token() {
        let client = TestClient::register_and_login().await;

        // Mint a WebAuthn-bound token from the setup GET, then use it (no password) on the challenge.
        let get = client.post("/api/two-factor/get-webauthn", json!({ "masterPasswordHash": client.master_password_hash })).await;
        let uvt = get.json()["userVerificationToken"].as_str().unwrap().to_string();

        let resp = client.post("/api/two-factor/get-webauthn-challenge", json!({ "userVerificationToken": uvt })).await;
        resp.assert_ok();
        assert_eq!(resp.json()["object"], "twoFactorWebAuthnChallenge", "envelope via token: {}", resp.body);
    }
}
