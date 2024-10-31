use axol::prelude::*;
use chrono::{Duration, NaiveDateTime, Utc};
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use uuid::Uuid;

use crate::{
    api::PasswordData,
    auth::Headers,
    crypto,
    db::{Conn, Event, EventType, TwoFactor, TwoFactorType, User, DB},
    error::MapResult,
    events::log_user_event,
    mail,
    util::AutoTxn,
    CONFIG,
};

use super::_generate_recover_code;

#[derive(Deserialize)]
#[allow(non_snake_case)]
pub struct SendEmailLoginData {
    Email: String,
    MasterPasswordHash: String,
}

/// User is trying to login and wants to use email 2FA.
/// Does not require Bearer token
pub async fn send_email_login(data: Json<SendEmailLoginData>) -> Result<()> {
    let data: SendEmailLoginData = data.0;
    let conn = DB.get().await.ise()?;

    // Get the user
    let user = match User::find_by_email(&conn, &data.Email).await? {
        Some(user) => user,
        None => err!("Username or password is incorrect. Try again."),
    };

    // Check password
    if !user.check_valid_password(&data.MasterPasswordHash) {
        err!("Username or password is incorrect. Try again.")
    }

    if CONFIG.email_2fa.is_none() {
        err!("Email 2FA is disabled")
    }

    send_token(user.uuid, &conn).await?;

    Ok(())
}

/// Generate the token, save the data for later verification and send email to user
pub async fn send_token(user_uuid: Uuid, conn: &Conn) -> Result<()> {
    let mut twofactor = TwoFactor::find_by_user_and_type(conn, user_uuid, TwoFactorType::Email).await?.map_res("Two factor not found")?;

    let generated_token = crypto::generate_email_token(CONFIG.email_2fa.as_ref().map(|x| x.email_token_size).unwrap_or_default());

    let mut twofactor_data: EmailTokenData = serde_json::from_value(twofactor.data).ise()?;
    twofactor_data.set_token(generated_token);
    twofactor.data = serde_json::to_value(&twofactor_data).ise()?;
    twofactor.save(conn).await?;

    mail::send_token(&twofactor_data.email, &twofactor_data.last_token.map_res("Token is empty")?).await?;

    Ok(())
}

/// When user clicks on Manage email 2FA show the user the related information
pub async fn get_email(headers: Headers, data: Json<PasswordData>) -> Result<Json<Value>> {
    let data: PasswordData = data.0;
    let user = headers.user;

    if !user.check_valid_password(&data.master_password_hash) {
        err!("Invalid password");
    }
    let conn = DB.get().await.ise()?;

    let (enabled, mfa_email) = match TwoFactor::find_by_user_and_type(&conn, user.uuid, TwoFactorType::Email).await? {
        Some(x) => {
            let twofactor_data: EmailTokenData = serde_json::from_value(x.data).ise()?;
            (true, json!(twofactor_data.email))
        }
        _ => (false, serde_json::value::Value::Null),
    };

    Ok(Json(json!({
        "email": mfa_email,
        "enabled": enabled,
        "object": "twoFactorEmail"
    })))
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct SendEmailData {
    /// Email where 2FA codes will be sent to, can be different than user email account.
    email: String,
    master_password_hash: String,
}

/// Send a verification email to the specified email address to check whether it exists/belongs to user.
pub async fn send_email(conn: AutoTxn, headers: Headers, data: Json<SendEmailData>) -> Result<()> {
    let data: SendEmailData = data.0;
    let user = headers.user;

    if !user.check_valid_password(&data.master_password_hash) {
        err!("Invalid password");
    }

    if CONFIG.email_2fa.is_none() {
        err!("Email 2FA is disabled")
    }

    if let Some(tf) = TwoFactor::find_by_user_and_type(&conn, user.uuid, TwoFactorType::Email).await? {
        tf.delete(&conn).await?;
    }

    let generated_token = crypto::generate_email_token(CONFIG.email_2fa.as_ref().map(|x| x.email_token_size).unwrap_or_default());
    let twofactor_data = EmailTokenData::new(data.email, generated_token);

    // Uses EmailVerificationChallenge as type to show that it's not verified yet.
    let twofactor = TwoFactor::new(user.uuid, TwoFactorType::EmailVerificationChallenge, serde_json::to_value(twofactor_data.clone()).ise()?);
    twofactor.save(&conn).await?;

    mail::send_token(&twofactor_data.email, &twofactor_data.last_token.map_res("Token is empty")?).await?;

    conn.commit().await?;

    Ok(())
}

#[derive(Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct EmailData {
    email: String,
    master_password_hash: String,
    token: String,
}

/// Verify email belongs to user and can be used for 2FA email codes.
pub async fn email(headers: Headers, data: Json<EmailData>) -> Result<Json<Value>> {
    let data: EmailData = data.0;
    let mut user = headers.user;

    if !user.check_valid_password(&data.master_password_hash) {
        err!("Invalid password");
    }
    let mut conn = DB.get().await.ise()?;

    let mut twofactor = TwoFactor::find_by_user_and_type(&conn, user.uuid, TwoFactorType::EmailVerificationChallenge).await?.map_res("Two factor not found")?;

    let mut email_data: EmailTokenData = serde_json::from_value(twofactor.data).ise()?;

    let issued_token = match &email_data.last_token {
        Some(t) => t,
        _ => err!("No token available"),
    };

    if !crypto::ct_eq(issued_token, data.token) {
        err!("Token is invalid")
    }

    email_data.reset_token();
    twofactor.atype = TwoFactorType::Email;
    twofactor.data = serde_json::to_value(email_data.clone()).ise()?;
    twofactor.save(&mut conn).await?;

    _generate_recover_code(&mut user, &conn).await?;

    log_user_event(EventType::UserUpdated2fa, user.uuid, headers.device.atype, Utc::now(), headers.ip, &mut conn).await?;

    Ok(Json(json!({
        "email": email_data.email,
        "enabled": "true",
        "object": "twoFactorEmail"
    })))
}

/// Validate the email code when used as TwoFactor token mechanism
pub async fn validate_email_code_str(user_uuid: Uuid, token: &str, data: Value) -> Result<()> {
    let mut email_data: EmailTokenData = serde_json::from_value(data).ise()?;
    let mut conn = DB.get().await.ise()?;
    let txn = conn.transaction().await.ise()?;

    let mut twofactor = TwoFactor::find_by_user_and_type(txn.client(), user_uuid, TwoFactorType::Email).await?.map_res("Two factor not found")?;
    let issued_token = match &email_data.last_token {
        Some(t) => t,
        _ => {
            Event::new(EventType::UserFailedLogIn2fa, None).with_user_uuid(user_uuid).save(txn.client()).await?;
            err!("No token available")
        }
    };

    if !crypto::ct_eq(issued_token, token) {
        email_data.add_attempt();
        if email_data.attempts >= CONFIG.email_2fa.as_ref().map(|x| x.email_attempts_limit).unwrap_or_default() {
            email_data.reset_token();
        }
        twofactor.data = serde_json::to_value(email_data).ise()?;
        twofactor.save(txn.client()).await?;

        txn.commit().await.ise()?;

        Event::new(EventType::UserFailedLogIn2fa, None).with_user_uuid(user_uuid).save(&conn).await?;
        err!("Token is invalid")
    }

    email_data.reset_token();
    twofactor.data = serde_json::to_value(email_data.clone()).ise()?;
    twofactor.save(txn.client()).await?;
    txn.commit().await.ise()?;

    let date = NaiveDateTime::from_timestamp_opt(email_data.token_sent, 0).map_res("invalid timestamp")?.and_utc();
    let max_time = CONFIG.email_2fa.as_ref().map(|x| x.email_expiration_time).unwrap_or_default() as i64;
    if date + Duration::seconds(max_time) < Utc::now() {
        Event::new(EventType::UserFailedLogIn2fa, None).with_user_uuid(user_uuid).save(&conn).await?;
        err!("Token has expired")
    }

    Ok(())
}

/// Data stored in the TwoFactor table in the db
#[derive(Serialize, Deserialize, Clone)]
pub struct EmailTokenData {
    /// Email address where the token will be sent to. Can be different from account email.
    pub email: String,
    /// Some(token): last valid token issued that has not been entered.
    /// None: valid token was used and removed.
    pub last_token: Option<String>,
    /// UNIX timestamp of token issue.
    pub token_sent: i64,
    /// Amount of token entry attempts for last_token.
    pub attempts: u64,
}

impl EmailTokenData {
    pub fn new(email: String, token: String) -> EmailTokenData {
        EmailTokenData {
            email,
            last_token: Some(token),
            token_sent: Utc::now().timestamp(),
            attempts: 0,
        }
    }

    pub fn set_token(&mut self, token: String) {
        self.last_token = Some(token);
        self.token_sent = Utc::now().timestamp();
    }

    pub fn reset_token(&mut self) {
        self.last_token = None;
        self.attempts = 0;
    }

    pub fn add_attempt(&mut self) {
        self.attempts += 1;
    }
}

/// Takes an email address and obscures it by replacing it with asterisks except two characters.
pub fn obscure_email(email: &str) -> String {
    let split: Vec<&str> = email.rsplitn(2, '@').collect();

    let mut name = split[1].to_string();
    let domain = &split[0];

    let name_size = name.chars().count();

    let new_name = match name_size {
        1..=3 => "*".repeat(name_size),
        _ => {
            let stars = "*".repeat(name_size - 2);
            name.truncate(2);
            format!("{name}{stars}")
        }
    };

    format!("{}@{}", new_name, &domain)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_obscure_email_long() {
        let email = "bytes@example.ext";

        let result = obscure_email(email);

        // Only first two characters should be visible.
        assert_eq!(result, "by***@example.ext");
    }

    #[test]
    fn test_obscure_email_short() {
        let email = "byt@example.ext";

        let result = obscure_email(email);

        // If it's smaller than 3 characters it should only show asterisks.
        assert_eq!(result, "***@example.ext");
    }
}
