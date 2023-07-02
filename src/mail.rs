use std::{net::IpAddr, str::FromStr};

use axum_util::errors::ApiResult;
use chrono::{DateTime, Utc};
use log::debug;
use percent_encoding::{percent_encode, NON_ALPHANUMERIC};

use crate::config::{SmtpSecurity, SMTP_IMAGE_SRC};
use lettre::{
    message::{Attachment, Body, Mailbox, Message, MultiPart, SinglePart},
    transport::smtp::authentication::Credentials,
    transport::smtp::client::{Tls, TlsParameters},
    transport::smtp::extension::ClientId,
    Address, AsyncSmtpTransport, AsyncTransport, Tokio1Executor,
};
use serde_json::json;
use std::time::Duration;
use uuid::Uuid;

use crate::{
    auth::{encode_jwt, generate_delete_claims, generate_emergency_access_invite_claims, generate_invite_claims, generate_verify_email_claims},
    CONFIG,
};

lazy_static::lazy_static! {
    static ref SMTP_TRANSPORT: Option<AsyncSmtpTransport<Tokio1Executor>> = {
        let Some(smtp) = &CONFIG.smtp else {
            return None
        };

        let port = smtp.port.unwrap_or_else(|| match smtp.security {
            SmtpSecurity::Starttls | SmtpSecurity::Off => 587,
            SmtpSecurity::ForceTls => 465,
        });

        let smtp_client = AsyncSmtpTransport::<Tokio1Executor>::builder_dangerous(&smtp.host)
            .port(port)
            .timeout(Some(Duration::from_secs(smtp.timeout)));

        // Determine security
        let smtp_client = match smtp.security {
            SmtpSecurity::Off => smtp_client,
            _ => {
                let mut tls_parameters = TlsParameters::builder(smtp.host.clone());
                if smtp.accept_invalid_hostnames {
                    tls_parameters = tls_parameters.dangerous_accept_invalid_hostnames(true);
                }
                if smtp.accept_invalid_certs {
                    tls_parameters = tls_parameters.dangerous_accept_invalid_certs(true);
                }
                let tls_parameters = tls_parameters.build().unwrap();

                if smtp.security == SmtpSecurity::ForceTls {
                    smtp_client.tls(Tls::Wrapper(tls_parameters))
                } else {
                    smtp_client.tls(Tls::Required(tls_parameters))
                }
            },
        };

        let smtp_client = match (&smtp.username, &smtp.password) {
            (Some(user), Some(pass)) => smtp_client.credentials(Credentials::new(user.clone(), pass.clone())),
            _ => smtp_client,
        };

        let smtp_client = match &smtp.helo_name {
            Some(helo_name) => smtp_client.hello_name(ClientId::Domain(helo_name.clone())),
            None => smtp_client,
        };

        Some(smtp_client.build())
    };
}

fn get_text(template_name: &'static str, data: serde_json::Value) -> ApiResult<(String, String, String)> {
    let (subject_html, body_html) = get_template(&format!("{template_name}.html"), &data)?;
    let (_subject_text, body_text) = get_template(template_name, &data)?;
    Ok((subject_html, body_html, body_text))
}

fn get_template(template_name: &str, data: &serde_json::Value) -> ApiResult<(String, String)> {
    let text = crate::templates::render_template(template_name, data)?;
    let mut text_split = text.split("<!---------------->");

    let subject = match text_split.next() {
        Some(s) => s.trim().to_string(),
        None => err!("Template doesn't contain subject"),
    };

    let body = match text_split.next() {
        Some(s) => s.trim().to_string(),
        None => err!("Template doesn't contain body"),
    };

    Ok((subject, body))
}

pub async fn send_password_hint(address: &str, hint: Option<String>) -> ApiResult<()> {
    let template_name = if hint.is_some() {
        "email/pw_hint_some"
    } else {
        "email/pw_hint_none"
    };

    let (subject, body_html, body_text) = get_text(
        template_name,
        json!({
            "url": CONFIG.settings.public.as_str(),
            "img_src": &*SMTP_IMAGE_SRC,
            "hint": hint,
        }),
    )?;

    send_email(address, &subject, body_html, body_text).await
}

pub async fn send_delete_account(address: &str, uuid: Uuid) -> ApiResult<()> {
    let claims = generate_delete_claims(uuid.to_string());
    let delete_token = encode_jwt(&claims);

    let (subject, body_html, body_text) = get_text(
        "email/delete_account",
        json!({
            "url": CONFIG.settings.public.as_str(),
            "img_src": &*SMTP_IMAGE_SRC,
            "user_id": uuid,
            "email": percent_encode(address.as_bytes(), NON_ALPHANUMERIC).to_string(),
            "token": delete_token,
        }),
    )?;

    send_email(address, &subject, body_html, body_text).await
}

pub async fn send_verify_email(address: &str, uuid: Uuid) -> ApiResult<()> {
    let claims = generate_verify_email_claims(uuid.to_string());
    let verify_email_token = encode_jwt(&claims);

    let (subject, body_html, body_text) = get_text(
        "email/verify_email",
        json!({
            "url": CONFIG.settings.public.as_str(),
            "img_src": &*SMTP_IMAGE_SRC,
            "user_id": uuid,
            "email": percent_encode(address.as_bytes(), NON_ALPHANUMERIC).to_string(),
            "token": verify_email_token,
        }),
    )?;

    send_email(address, &subject, body_html, body_text).await
}

pub async fn send_welcome(address: &str) -> ApiResult<()> {
    let (subject, body_html, body_text) = get_text(
        "email/welcome",
        json!({
            "url": CONFIG.settings.public.as_str(),
            "img_src": &*SMTP_IMAGE_SRC,
        }),
    )?;

    send_email(address, &subject, body_html, body_text).await
}

pub async fn send_welcome_must_verify(address: &str, uuid: Uuid) -> ApiResult<()> {
    let claims = generate_verify_email_claims(uuid.to_string());
    let verify_email_token = encode_jwt(&claims);

    let (subject, body_html, body_text) = get_text(
        "email/welcome_must_verify",
        json!({
            "url": CONFIG.settings.public.as_str(),
            "img_src": &*SMTP_IMAGE_SRC,
            "user_id": uuid,
            "token": verify_email_token,
        }),
    )?;

    send_email(address, &subject, body_html, body_text).await
}

pub async fn send_2fa_removed_from_org(address: &str, org_name: &str) -> ApiResult<()> {
    let (subject, body_html, body_text) = get_text(
        "email/send_2fa_removed_from_org",
        json!({
            "url": CONFIG.settings.public.as_str(),
            "img_src": &*SMTP_IMAGE_SRC,
            "org_name": org_name,
        }),
    )?;

    send_email(address, &subject, body_html, body_text).await
}

pub async fn send_single_org_removed_from_org(address: &str, org_name: &str) -> ApiResult<()> {
    let (subject, body_html, body_text) = get_text(
        "email/send_single_org_removed_from_org",
        json!({
            "url": CONFIG.settings.public.as_str(),
            "img_src": &*SMTP_IMAGE_SRC,
            "org_name": org_name,
        }),
    )?;

    send_email(address, &subject, body_html, body_text).await
}

pub async fn send_invite(address: &str, user_uuid: Uuid, org_id: Option<Uuid>, org_name: &str, invited_by_email: Option<String>) -> ApiResult<()> {
    let claims = generate_invite_claims(user_uuid, String::from(address), org_id, invited_by_email);
    let invite_token = encode_jwt(&claims);

    let (subject, body_html, body_text) = get_text(
        "email/send_org_invite",
        json!({
            "url": CONFIG.settings.public.as_str(),
            "img_src": &*SMTP_IMAGE_SRC,
            "org_id": org_id.map(|x| x.to_string()).unwrap_or_else(|| "_".to_string()),
            "email": percent_encode(address.as_bytes(), NON_ALPHANUMERIC).to_string(),
            "org_name_encoded": percent_encode(org_name.as_bytes(), NON_ALPHANUMERIC).to_string(),
            "org_name": org_name,
            "token": invite_token,
        }),
    )?;

    send_email(address, &subject, body_html, body_text).await
}

pub async fn send_emergency_access_invite(address: &str, uuid: Uuid, emer_id: Uuid, grantor_name: &str, grantor_email: &str) -> ApiResult<()> {
    let claims =
        generate_emergency_access_invite_claims(uuid.to_string(), String::from(address), emer_id, String::from(grantor_name), String::from(grantor_email));

    let invite_token = encode_jwt(&claims);

    let (subject, body_html, body_text) = get_text(
        "email/send_emergency_access_invite",
        json!({
            "url": CONFIG.settings.public.as_str(),
            "img_src": &*SMTP_IMAGE_SRC,
            "emer_id": emer_id,
            "email": percent_encode(address.as_bytes(), NON_ALPHANUMERIC).to_string(),
            "grantor_name": grantor_name,
            "token": invite_token,
        }),
    )?;

    send_email(address, &subject, body_html, body_text).await
}

pub async fn send_emergency_access_invite_accepted(address: &str, grantee_email: &str) -> ApiResult<()> {
    let (subject, body_html, body_text) = get_text(
        "email/emergency_access_invite_accepted",
        json!({
            "url": CONFIG.settings.public.as_str(),
            "img_src": &*SMTP_IMAGE_SRC,
            "grantee_email": grantee_email,
        }),
    )?;

    send_email(address, &subject, body_html, body_text).await
}

pub async fn send_emergency_access_invite_confirmed(address: &str, grantor_name: &str) -> ApiResult<()> {
    let (subject, body_html, body_text) = get_text(
        "email/emergency_access_invite_confirmed",
        json!({
            "url": CONFIG.settings.public.as_str(),
            "img_src": &*SMTP_IMAGE_SRC,
            "grantor_name": grantor_name,
        }),
    )?;

    send_email(address, &subject, body_html, body_text).await
}

pub async fn send_emergency_access_recovery_approved(address: &str, grantor_name: &str) -> ApiResult<()> {
    let (subject, body_html, body_text) = get_text(
        "email/emergency_access_recovery_approved",
        json!({
            "url": CONFIG.settings.public.as_str(),
            "img_src": &*SMTP_IMAGE_SRC,
            "grantor_name": grantor_name,
        }),
    )?;

    send_email(address, &subject, body_html, body_text).await
}

pub async fn send_emergency_access_recovery_initiated(address: &str, grantee_name: &str, atype: &str, wait_time_days: &i32) -> ApiResult<()> {
    let (subject, body_html, body_text) = get_text(
        "email/emergency_access_recovery_initiated",
        json!({
            "url": CONFIG.settings.public.as_str(),
            "img_src": &*SMTP_IMAGE_SRC,
            "grantee_name": grantee_name,
            "atype": atype,
            "wait_time_days": wait_time_days,
        }),
    )?;

    send_email(address, &subject, body_html, body_text).await
}

pub async fn send_emergency_access_recovery_reminder(address: &str, grantee_name: &str, atype: &str, days_left: &str) -> ApiResult<()> {
    let (subject, body_html, body_text) = get_text(
        "email/emergency_access_recovery_reminder",
        json!({
            "url": CONFIG.settings.public.as_str(),
            "img_src": &*SMTP_IMAGE_SRC,
            "grantee_name": grantee_name,
            "atype": atype,
            "days_left": days_left,
        }),
    )?;

    send_email(address, &subject, body_html, body_text).await
}

pub async fn send_emergency_access_recovery_rejected(address: &str, grantor_name: &str) -> ApiResult<()> {
    let (subject, body_html, body_text) = get_text(
        "email/emergency_access_recovery_rejected",
        json!({
            "url": CONFIG.settings.public.as_str(),
            "img_src": &*SMTP_IMAGE_SRC,
            "grantor_name": grantor_name,
        }),
    )?;

    send_email(address, &subject, body_html, body_text).await
}

pub async fn send_emergency_access_recovery_timed_out(address: &str, grantee_name: &str, atype: &str) -> ApiResult<()> {
    let (subject, body_html, body_text) = get_text(
        "email/emergency_access_recovery_timed_out",
        json!({
            "url": CONFIG.settings.public.as_str(),
            "img_src": &*SMTP_IMAGE_SRC,
            "grantee_name": grantee_name,
            "atype": atype,
        }),
    )?;

    send_email(address, &subject, body_html, body_text).await
}

pub async fn send_invite_accepted(new_user_email: &str, address: &str, org_name: &str) -> ApiResult<()> {
    let (subject, body_html, body_text) = get_text(
        "email/invite_accepted",
        json!({
            "url": CONFIG.settings.public.as_str(),
            "img_src": &*SMTP_IMAGE_SRC,
            "email": new_user_email,
            "org_name": org_name,
        }),
    )?;

    send_email(address, &subject, body_html, body_text).await
}

pub async fn send_invite_confirmed(address: &str, org_name: &str) -> ApiResult<()> {
    let (subject, body_html, body_text) = get_text(
        "email/invite_confirmed",
        json!({
            "url": CONFIG.settings.public.as_str(),
            "img_src": &*SMTP_IMAGE_SRC,
            "org_name": org_name,
        }),
    )?;

    send_email(address, &subject, body_html, body_text).await
}

pub async fn send_new_device_logged_in(address: &str, ip: IpAddr, dt: DateTime<Utc>, device: &str) -> ApiResult<()> {
    use crate::util::upcase_first;
    let device = upcase_first(device);

    let fmt = "%A, %B %_d, %Y at %r %Z";
    let (subject, body_html, body_text) = get_text(
        "email/new_device_logged_in",
        json!({
            "url": CONFIG.settings.public.as_str(),
            "img_src": &*SMTP_IMAGE_SRC,
            "ip": ip,
            "device": device,
            "datetime": crate::util::format_naive_datetime_local(dt, fmt),
        }),
    )?;

    send_email(address, &subject, body_html, body_text).await
}

pub async fn send_incomplete_2fa_login(address: &str, ip: IpAddr, dt: DateTime<Utc>, device: &str) -> ApiResult<()> {
    use crate::util::upcase_first;
    let device = upcase_first(device);

    let fmt = "%A, %B %_d, %Y at %r %Z";
    let (subject, body_html, body_text) = get_text(
        "email/incomplete_2fa_login",
        json!({
            "url": CONFIG.settings.public.as_str(),
            "img_src": &*SMTP_IMAGE_SRC,
            "ip": ip,
            "device": device,
            "datetime": crate::util::format_naive_datetime_local(dt, fmt),
            "time_limit": CONFIG.settings.incomplete_2fa_time_limit,
        }),
    )?;

    send_email(address, &subject, body_html, body_text).await
}

pub async fn send_token(address: &str, token: &str) -> ApiResult<()> {
    let (subject, body_html, body_text) = get_text(
        "email/twofactor_email",
        json!({
            "url": CONFIG.settings.public.as_str(),
            "img_src": &*SMTP_IMAGE_SRC,
            "token": token,
        }),
    )?;

    send_email(address, &subject, body_html, body_text).await
}

pub async fn send_change_email(address: &str, token: &str) -> ApiResult<()> {
    let (subject, body_html, body_text) = get_text(
        "email/change_email",
        json!({
            "url": CONFIG.settings.public.as_str(),
            "img_src": &*SMTP_IMAGE_SRC,
            "token": token,
        }),
    )?;

    send_email(address, &subject, body_html, body_text).await
}

pub async fn send_set_password(address: &str, user_name: &str) -> ApiResult<()> {
    let (subject, body_html, body_text) = get_text(
        "email/set_password",
        json!({
            "url": CONFIG.settings.public.as_str(),
            "img_src": &*SMTP_IMAGE_SRC,
            "user_name": user_name,
        }),
    )?;
    send_email(address, &subject, body_html, body_text).await
}

pub async fn send_test(address: &str) -> ApiResult<()> {
    let (subject, body_html, body_text) = get_text(
        "email/smtp_test",
        json!({
            "url": CONFIG.settings.public.as_str(),
            "img_src": &*SMTP_IMAGE_SRC,
        }),
    )?;

    send_email(address, &subject, body_html, body_text).await
}

pub async fn send_admin_reset_password(address: &str, user_name: &str, org_name: &str) -> ApiResult<()> {
    let (subject, body_html, body_text) = get_text(
        "email/admin_reset_password",
        json!({
            "url": CONFIG.settings.public.as_str(),
            "img_src": &*SMTP_IMAGE_SRC,
            "user_name": user_name,
            "org_name": org_name,
        }),
    )?;
    send_email(address, &subject, body_html, body_text).await
}

async fn send_with_selected_transport(email: Message) -> ApiResult<()> {
    match SMTP_TRANSPORT.as_ref().unwrap().send(email).await {
        Ok(_) => Ok(()),
        // Match some common errors and make them more user friendly
        Err(e) => {
            if e.is_client() {
                debug!("SMTP client error: {:#?}", e);
                err!(format!("SMTP client error: {e}"));
            } else if e.is_transient() {
                debug!("SMTP 4xx error: {:#?}", e);
                err!(format!("SMTP 4xx error: {e}"));
            } else if e.is_permanent() {
                debug!("SMTP 5xx error: {:#?}", e);
                let mut msg = e.to_string();
                // Add a special check for 535 to add a more descriptive message
                if msg.contains("(535)") {
                    msg = format!("{msg} - Authentication credentials invalid");
                }
                err!(format!("SMTP 5xx error: {msg}"));
            } else if e.is_timeout() {
                debug!("SMTP timeout error: {:#?}", e);
                err!(format!("SMTP timeout error: {e}"));
            } else if e.is_tls() {
                debug!("SMTP encryption error: {:#?}", e);
                err!(format!("SMTP encryption error: {e}"));
            } else {
                debug!("SMTP error: {:#?}", e);
                err!(format!("SMTP error: {e}"));
            }
        }
    }
}

async fn send_email(address: &str, subject: &str, body_html: String, body_text: String) -> ApiResult<()> {
    let Some(smtp) = &CONFIG.smtp else {
        return Ok(());
    };

    let body = if smtp.embed_images {
        let logo_gray_body = Body::new(include_bytes!("./static/images/logo-gray.png").to_vec());
        let mail_github_body = Body::new(include_bytes!("./static/images/mail-github.png").to_vec());
        MultiPart::alternative().singlepart(SinglePart::plain(body_text)).multipart(
            MultiPart::related()
                .singlepart(SinglePart::html(body_html))
                .singlepart(Attachment::new_inline(String::from("logo-gray.png")).body(logo_gray_body, "image/png".parse().unwrap()))
                .singlepart(Attachment::new_inline(String::from("mail-github.png")).body(mail_github_body, "image/png".parse().unwrap())),
        )
    } else {
        MultiPart::alternative_plain_html(body_text, body_html)
    };

    let email = Message::builder()
        .message_id(Some(format!("<{}@{}>", uuid::Uuid::new_v4(), smtp.from_address.split('@').collect::<Vec<&str>>()[1])))
        .to(Mailbox::new(None, Address::from_str(address)?))
        .from(Mailbox::new(Some(smtp.from_name.clone()), Address::from_str(&smtp.from_address)?))
        .subject(subject)
        .multipart(body)?;

    send_with_selected_transport(email).await
}
