use axol::prelude::*;
use chrono::Utc;
use serde::Deserialize;
use serde_json::{json, Value};
use serde_with::serde_as;
use uuid::Uuid;

use crate::{
    auth::{decode_emergency_access_invite, Headers},
    db::{
        Conn, EmergencyAccess, EmergencyAccessStatus, EmergencyAccessType, FullCipher, Invitation, OrganizationPolicy, TwoFactor, User, UserOrgType,
        UserOrganization, DB,
    },
    mail,
    util::AutoTxn,
    CONFIG,
};

pub fn route(router: Router) -> Router {
    router
        .get("/emergency-access/trusted", get_contacts)
        .get("/emergency-access/granted", get_grantees)
        .get("/emergency-access/:emergency_id", get_emergency_access)
        .put("/emergency-access/:emergency_id", post_emergency_access)
        .delete("/emergency-access/:emergency_id", delete_emergency_access)
        .post("/emergency-access/:emergency_id/delete", delete_emergency_access)
        .post("/emergency-access/invite", send_invite)
        .post("/emergency-access/:emergency_id/reinvite", resend_invite)
        .post("/emergency-access/:emergency_id/accept", accept_invite)
        .post("/emergency-access/:emergency_id/confirm", confirm_emergency_access)
        .post("/emergency-access/:emergency_id/initiate", initiate_emergency_access)
        .post("/emergency-access/:emergency_id/approve", approve_emergency_access)
        .post("/emergency-access/:emergency_id/reject", reject_emergency_access)
        .post("/emergency-access/:emergency_id/view", view_emergency_access)
        .post("/emergency-access/:emergency_id/takeover", takeover_emergency_access)
        .post("/emergency-access/:emergency_id/password", password_emergency_access)
        .get("/emergency-access/:emergency_id/policies", policies_emergency_access)
}

async fn get_contacts(headers: Headers) -> Result<Json<Value>> {
    check_emergency_access_allowed()?;
    let conn = DB.get().await.ise()?;

    let emergency_access_list = EmergencyAccess::find_all_by_grantor_uuid(&conn, headers.user.uuid).await?;
    let mut emergency_access_list_json = Vec::with_capacity(emergency_access_list.len());
    for ea in emergency_access_list {
        emergency_access_list_json.push(ea.to_json_grantee_details(&conn).await?);
    }

    Ok(Json(json!({
      "data": emergency_access_list_json,
      "object": "list",
      "continuationToken": null
    })))
}

async fn get_grantees(headers: Headers) -> Result<Json<Value>> {
    check_emergency_access_allowed()?;
    let conn = DB.get().await.ise()?;

    let emergency_access_list = EmergencyAccess::find_all_by_grantee_uuid(&conn, headers.user.uuid).await?;
    let mut emergency_access_list_json = Vec::with_capacity(emergency_access_list.len());
    for ea in emergency_access_list {
        emergency_access_list_json.push(ea.to_json_grantor_details(&conn).await?);
    }

    Ok(Json(json!({
      "data": emergency_access_list_json,
      "object": "list",
      "continuationToken": null
    })))
}

async fn get_emergency_access(Path(emergency_id): Path<Uuid>, headers: Headers) -> Result<Json<Value>> {
    check_emergency_access_allowed()?;
    let conn = DB.get().await.ise()?;

    match EmergencyAccess::get_with_grantor(&conn, emergency_id, headers.user.uuid).await? {
        Some(emergency_access) => Ok(Json(emergency_access.to_json_grantee_details(&conn).await?)),
        None => err!("Emergency access not valid."),
    }
}

#[serde_as]
#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct EmergencyAccessUpdateData {
    #[serde_as(as = "serde_with::PickFirst<(_, serde_with::DisplayFromStr)>")]
    r#type: EmergencyAccessType,
    wait_time_days: i32,
    key_encrypted: Option<String>,
}

async fn post_emergency_access(Path(emergency_id): Path<Uuid>, headers: Headers, data: Json<EmergencyAccessUpdateData>) -> Result<Json<Value>> {
    check_emergency_access_allowed()?;

    let data: EmergencyAccessUpdateData = data.0;
    let conn = DB.get().await.ise()?;

    let mut emergency_access = match EmergencyAccess::get_with_grantor(&conn, emergency_id, headers.user.uuid).await? {
        Some(emergency_access) => emergency_access,
        None => err!("Emergency access not valid."),
    };

    emergency_access.atype = data.r#type;
    emergency_access.wait_time_days = data.wait_time_days;
    if data.key_encrypted.is_some() {
        emergency_access.key_encrypted = data.key_encrypted;
    }

    emergency_access.save(&conn).await?;
    Ok(Json(emergency_access.to_json()))
}

async fn delete_emergency_access(Path(emergency_id): Path<Uuid>, headers: Headers) -> Result<()> {
    check_emergency_access_allowed()?;

    let grantor_user = headers.user;
    let conn = DB.get().await.ise()?;

    let emergency_access = match EmergencyAccess::get_with_grantor(&conn, emergency_id, grantor_user.uuid).await? {
        Some(emer) => {
            if emer.grantor_uuid != grantor_user.uuid && emer.grantee_uuid != Some(grantor_user.uuid) {
                err!("Emergency access not valid.")
            }
            emer
        }
        None => err!("Emergency access not valid."),
    };
    emergency_access.delete(&conn).await?;
    Ok(())
}

#[serde_as]
#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct EmergencyAccessInviteData {
    email: String,
    #[serde_as(as = "serde_with::PickFirst<(_, serde_with::DisplayFromStr)>")]
    r#type: EmergencyAccessType,
    wait_time_days: i32,
}

async fn send_invite(conn: AutoTxn, headers: Headers, data: Json<EmergencyAccessInviteData>) -> Result<()> {
    check_emergency_access_allowed()?;

    let data: EmergencyAccessInviteData = data.0;
    let email = data.email.to_lowercase();
    let wait_time_days = data.wait_time_days;

    let emergency_access_status = EmergencyAccessStatus::Invited;

    let grantor_user = headers.user;

    // avoid setting yourself as emergency contact
    if email == grantor_user.email {
        err!("You can not set yourself as an emergency contact.")
    }

    let grantee_user = match User::find_by_email(&conn, &email).await? {
        None => {
            if !CONFIG.settings.invitations_allowed {
                err!(format!("Grantee user does not exist: {}", &email))
            }

            if !CONFIG.is_email_domain_allowed(&email) {
                err!("Email domain not eligible for invitations")
            }

            if !CONFIG.mail_enabled() {
                let invitation = Invitation::new(&email);
                invitation.save(&conn).await?;
            }

            let mut user = User::new(email.clone());
            user.save(&conn).await?;
            user
        }
        Some(user) => user,
    };

    if EmergencyAccess::find_by_grantor_uuid_and_grantee_uuid_or_email(&conn, grantor_user.uuid, grantee_user.uuid, &grantee_user.email).await?.is_some() {
        err!(format!("Grantee user already invited: {}", &grantee_user.email))
    }

    let mut new_emergency_access = EmergencyAccess::new(grantor_user.uuid, grantee_user.email, emergency_access_status, data.r#type, wait_time_days);
    new_emergency_access.save(&conn).await?;

    if CONFIG.mail_enabled() {
        mail::send_emergency_access_invite(
            &new_emergency_access.email.expect("Grantee email does not exists"),
            grantee_user.uuid,
            new_emergency_access.uuid,
            &grantor_user.name,
            &grantor_user.email,
        )
        .await?;
    } else {
        // Automatically mark user as accepted if no email invites
        match User::find_by_email(&conn, &email).await? {
            Some(user) => accept_invite_process(user.uuid, &mut new_emergency_access, &email, &conn).await?,
            None => err!("Grantee user not found."),
        }
    }

    conn.commit().await?;

    Ok(())
}

async fn resend_invite(Path(emergency_id): Path<Uuid>, headers: Headers) -> Result<()> {
    check_emergency_access_allowed()?;
    let conn = DB.get().await.ise()?;

    let mut emergency_access = match EmergencyAccess::get_with_grantor(&conn, emergency_id, headers.user.uuid).await? {
        Some(emer) => emer,
        None => err!("Emergency access not valid."),
    };

    if emergency_access.grantor_uuid != headers.user.uuid {
        err!("Emergency access not valid.");
    }

    if emergency_access.status != EmergencyAccessStatus::Invited {
        err!("The grantee user is already accepted or confirmed to the organization");
    }

    let email = match emergency_access.email.clone() {
        Some(email) => email,
        None => err!("Email not valid."),
    };

    let grantee_user = match User::find_by_email(&conn, &email).await? {
        Some(user) => user,
        None => err!("Grantee user not found."),
    };

    let grantor_user = headers.user;

    if CONFIG.mail_enabled() {
        mail::send_emergency_access_invite(&email, grantor_user.uuid, emergency_access.uuid, &grantor_user.name, &grantor_user.email).await?;
    } else {
        if Invitation::find_by_email(&conn, &email).await?.is_none() {
            let invitation = Invitation::new(&email);
            invitation.save(&conn).await?;
        }

        // Automatically mark user as accepted if no email invites
        accept_invite_process(grantee_user.uuid, &mut emergency_access, &email, &conn).await?;
    }

    Ok(())
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct AcceptData {
    token: String,
}

async fn accept_invite(Path(emergency_id): Path<Uuid>, headers: Headers, data: Json<AcceptData>) -> Result<()> {
    check_emergency_access_allowed()?;

    let data: AcceptData = data.0;
    let token = &data.token;
    let claims = decode_emergency_access_invite(token)?;

    // This can happen if the user who received the invite used a different email to signup.
    // Since we do not know if this is intented, we error out here and do nothing with the invite.
    if claims.email != headers.user.email {
        err!("Claim email does not match current users email")
    }
    let conn = DB.get().await.ise()?;

    let grantee_user = match User::find_by_email(&conn, &claims.email).await? {
        Some(user) => {
            Invitation::take(&conn, &claims.email).await?;
            user
        }
        None => err!("Invited user not found"),
    };

    let mut emergency_access = match EmergencyAccess::get(&conn, emergency_id).await? {
        Some(emer) => emer,
        None => err!("Emergency access not valid."),
    };

    // get grantor user to send Accepted email
    let grantor_user = match User::get(&conn, emergency_access.grantor_uuid).await? {
        Some(user) => user,
        None => err!("Grantor user not found."),
    };

    if emergency_id == claims.emer_id && grantor_user.name == claims.grantor_name && grantor_user.email == claims.grantor_email {
        accept_invite_process(grantee_user.uuid, &mut emergency_access, &grantee_user.email, &conn).await?;

        if CONFIG.mail_enabled() {
            mail::send_emergency_access_invite_accepted(&grantor_user.email, &grantee_user.email).await?;
        }

        Ok(())
    } else {
        err!("Emergency access invitation error.")
    }
}

async fn accept_invite_process(grantee_uuid: Uuid, emergency_access: &mut EmergencyAccess, grantee_email: &str, conn: &Conn) -> Result<()> {
    if emergency_access.email.is_none() || emergency_access.email.as_ref().unwrap() != grantee_email {
        err!("User email does not match invite.");
    }

    if emergency_access.status == EmergencyAccessStatus::Accepted {
        err!("Emergency contact already accepted.");
    }

    emergency_access.status = EmergencyAccessStatus::Accepted;
    emergency_access.grantee_uuid = Some(grantee_uuid);
    emergency_access.email = None;
    emergency_access.save(conn).await
}

#[derive(Deserialize)]
#[allow(non_snake_case)]
struct ConfirmData {
    Key: String,
}

async fn confirm_emergency_access(Path(emergency_id): Path<Uuid>, headers: Headers, data: Json<ConfirmData>) -> Result<Json<Value>> {
    check_emergency_access_allowed()?;

    let confirming_user = headers.user;
    let data: ConfirmData = data.0;
    let key = data.Key;
    let conn = DB.get().await.ise()?;

    let mut emergency_access = match EmergencyAccess::get_with_grantor(&conn, emergency_id, confirming_user.uuid).await? {
        Some(emer) => emer,
        None => err!("Emergency access not valid."),
    };

    if emergency_access.status != EmergencyAccessStatus::Accepted || emergency_access.grantor_uuid != confirming_user.uuid {
        err!("Emergency access not valid.")
    }

    let grantor_user = match User::get(&conn, confirming_user.uuid).await? {
        Some(user) => user,
        None => err!("Grantor user not found."),
    };

    if let Some(grantee_uuid) = emergency_access.grantee_uuid {
        let grantee_user = match User::get(&conn, grantee_uuid).await? {
            Some(user) => user,
            None => err!("Grantee user not found."),
        };

        emergency_access.status = EmergencyAccessStatus::Confirmed;
        emergency_access.key_encrypted = Some(key);
        emergency_access.email = None;

        emergency_access.save(&conn).await?;

        if CONFIG.mail_enabled() {
            mail::send_emergency_access_invite_confirmed(&grantee_user.email, &grantor_user.name).await?;
        }
        Ok(Json(emergency_access.to_json()))
    } else {
        err!("Grantee user not found.")
    }
}

async fn initiate_emergency_access(Path(emergency_id): Path<Uuid>, headers: Headers) -> Result<Json<Value>> {
    check_emergency_access_allowed()?;

    let initiating_user = headers.user;
    let conn = DB.get().await.ise()?;

    let mut emergency_access = match EmergencyAccess::get_with_grantee(&conn, emergency_id, initiating_user.uuid).await? {
        Some(emer) => emer,
        None => err!("Emergency access not valid."),
    };

    if emergency_access.status != EmergencyAccessStatus::Confirmed || emergency_access.grantee_uuid != Some(initiating_user.uuid) {
        err!("Emergency access not valid.")
    }

    let grantor_user = match User::get(&conn, emergency_access.grantor_uuid).await? {
        Some(user) => user,
        None => err!("Grantor user not found."),
    };

    let now = Utc::now();
    emergency_access.status = EmergencyAccessStatus::RecoveryInitiated;
    emergency_access.updated_at = now;
    emergency_access.recovery_initiated_at = Some(now);
    emergency_access.last_notification_at = Some(now);
    emergency_access.save(&conn).await?;

    if CONFIG.mail_enabled() {
        mail::send_emergency_access_recovery_initiated(
            &grantor_user.email,
            &initiating_user.name,
            emergency_access.get_type_as_str(),
            &emergency_access.wait_time_days,
        )
        .await?;
    }
    Ok(Json(emergency_access.to_json()))
}

async fn approve_emergency_access(Path(emergency_id): Path<Uuid>, headers: Headers) -> Result<Json<Value>> {
    check_emergency_access_allowed()?;
    let conn = DB.get().await.ise()?;

    let mut emergency_access = match EmergencyAccess::get_with_grantor(&conn, emergency_id, headers.user.uuid).await? {
        Some(emer) => emer,
        None => err!("Emergency access not valid."),
    };

    if emergency_access.status != EmergencyAccessStatus::RecoveryInitiated || emergency_access.grantor_uuid != headers.user.uuid {
        err!("Emergency access not valid.")
    }

    let grantor_user = match User::get(&conn, headers.user.uuid).await? {
        Some(user) => user,
        None => err!("Grantor user not found."),
    };

    if let Some(grantee_uuid) = emergency_access.grantee_uuid {
        let grantee_user = match User::get(&conn, grantee_uuid).await? {
            Some(user) => user,
            None => err!("Grantee user not found."),
        };

        emergency_access.status = EmergencyAccessStatus::RecoveryApproved;
        emergency_access.save(&conn).await?;

        if CONFIG.mail_enabled() {
            mail::send_emergency_access_recovery_approved(&grantee_user.email, &grantor_user.name).await?;
        }
        Ok(Json(emergency_access.to_json()))
    } else {
        err!("Grantee user not found.")
    }
}

async fn reject_emergency_access(Path(emergency_id): Path<Uuid>, headers: Headers) -> Result<Json<Value>> {
    check_emergency_access_allowed()?;
    let conn = DB.get().await.ise()?;

    let mut emergency_access = match EmergencyAccess::get_with_grantor(&conn, emergency_id, headers.user.uuid).await? {
        Some(emer) => emer,
        None => err!("Emergency access not valid."),
    };

    if (emergency_access.status != EmergencyAccessStatus::RecoveryInitiated && emergency_access.status != EmergencyAccessStatus::RecoveryApproved)
        || emergency_access.grantor_uuid != headers.user.uuid
    {
        err!("Emergency access not valid.")
    }

    let grantor_user = match User::get(&conn, headers.user.uuid).await? {
        Some(user) => user,
        None => err!("Grantor user not found."),
    };

    if let Some(grantee_uuid) = emergency_access.grantee_uuid {
        let grantee_user = match User::get(&conn, grantee_uuid).await? {
            Some(user) => user,
            None => err!("Grantee user not found."),
        };

        emergency_access.status = EmergencyAccessStatus::Confirmed;
        emergency_access.save(&conn).await?;

        if CONFIG.mail_enabled() {
            mail::send_emergency_access_recovery_rejected(&grantee_user.email, &grantor_user.name).await?;
        }
        Ok(Json(emergency_access.to_json()))
    } else {
        err!("Grantee user not found.")
    }
}

async fn view_emergency_access(Path(emergency_id): Path<Uuid>, headers: Headers) -> Result<Json<Value>> {
    check_emergency_access_allowed()?;
    let conn = DB.get().await.ise()?;

    let emergency_access = match EmergencyAccess::get_with_grantee(&conn, emergency_id, headers.user.uuid).await? {
        Some(emer) => emer,
        None => err!("Emergency access not valid."),
    };

    if !is_valid_request(&emergency_access, headers.user.uuid, EmergencyAccessType::View) {
        err!("Emergency access not valid.")
    }

    let ciphers_json = FullCipher::find_by_user(&conn, headers.user.uuid).await?.iter().map(|x| x.to_json(true)).collect::<Vec<_>>();

    Ok(Json(json!({
      "ciphers": ciphers_json,
      "keyEncrypted": &emergency_access.key_encrypted,
      "object": "emergencyAccessView",
    })))
}

async fn takeover_emergency_access(Path(emergency_id): Path<Uuid>, headers: Headers) -> Result<Json<Value>> {
    check_emergency_access_allowed()?;
    let conn = DB.get().await.ise()?;

    let requesting_user = headers.user;
    let emergency_access = match EmergencyAccess::get_with_grantee(&conn, emergency_id, requesting_user.uuid).await? {
        Some(emer) => emer,
        None => err!("Emergency access not valid."),
    };

    if !is_valid_request(&emergency_access, requesting_user.uuid, EmergencyAccessType::Takeover) {
        err!("Emergency access not valid.")
    }

    let grantor_user = match User::get(&conn, emergency_access.grantor_uuid).await? {
        Some(user) => user,
        None => err!("Grantor user not found."),
    };

    let result = json!({
        "kdf": grantor_user.client_kdf_type,
        "kdfIterations": grantor_user.client_kdf_iter,
        "kdfMemory": grantor_user.client_kdf_memory,
        "kdfParallelism": grantor_user.client_kdf_parallelism,
        "keyEncrypted": &emergency_access.key_encrypted,
        "object": "emergencyAccessTakeover",
    });

    Ok(Json(result))
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct EmergencyAccessPasswordData {
    new_master_password_hash: String,
    key: String,
}

async fn password_emergency_access(conn: AutoTxn, Path(emergency_id): Path<Uuid>, headers: Headers, data: Json<EmergencyAccessPasswordData>) -> Result<()> {
    check_emergency_access_allowed()?;

    let data: EmergencyAccessPasswordData = data.0;
    let new_master_password_hash = &data.new_master_password_hash;

    let requesting_user = headers.user;
    let emergency_access = match EmergencyAccess::get_with_grantee(&conn, emergency_id, requesting_user.uuid).await? {
        Some(emer) => emer,
        None => err!("Emergency access not valid."),
    };

    if !is_valid_request(&emergency_access, requesting_user.uuid, EmergencyAccessType::Takeover) {
        err!("Emergency access not valid.")
    }

    let mut grantor_user = match User::get(&conn, emergency_access.grantor_uuid).await? {
        Some(user) => user,
        None => err!("Grantor user not found."),
    };

    // change grantor_user password
    grantor_user.set_password(new_master_password_hash, Some(data.key), true, None);
    grantor_user.save(&conn).await?;

    // Disable TwoFactor providers since they will otherwise block logins
    TwoFactor::delete_all_by_user(&conn, grantor_user.uuid).await?;

    // Remove grantor from all organisations unless Owner
    for user_org in UserOrganization::find_by_user(&conn, grantor_user.uuid).await? {
        if user_org.atype != UserOrgType::Owner {
            user_org.delete(&conn).await?;
        }
    }
    conn.commit().await?;
    Ok(())
}

async fn policies_emergency_access(Path(emergency_id): Path<Uuid>, headers: Headers) -> Result<Json<Value>> {
    let requesting_user = headers.user;
    let conn = DB.get().await.ise()?;

    let emergency_access = match EmergencyAccess::get_with_grantee(&conn, emergency_id, requesting_user.uuid).await? {
        Some(emer) => emer,
        None => err!("Emergency access not valid."),
    };

    if !is_valid_request(&emergency_access, requesting_user.uuid, EmergencyAccessType::Takeover) {
        err!("Emergency access not valid.")
    }

    let grantor_user = match User::get(&conn, emergency_access.grantor_uuid).await? {
        Some(user) => user,
        None => err!("Grantor user not found."),
    };

    let policies = OrganizationPolicy::find_confirmed_by_user(&conn, grantor_user.uuid).await?;
    let policies_json: Vec<Value> = policies.iter().map(OrganizationPolicy::to_json).collect();

    Ok(Json(json!({
        "data": policies_json,
        "object": "list",
        "continuationToken": null
    })))
}

fn is_valid_request(emergency_access: &EmergencyAccess, requesting_user_uuid: Uuid, requested_access_type: EmergencyAccessType) -> bool {
    emergency_access.grantee_uuid.is_some()
        && emergency_access.grantee_uuid == Some(requesting_user_uuid)
        && emergency_access.status == EmergencyAccessStatus::RecoveryApproved
        && emergency_access.atype == requested_access_type
}

fn check_emergency_access_allowed() -> Result<()> {
    if !CONFIG.settings.emergency_access_allowed {
        err!("Emergency access is not allowed.")
    }
    Ok(())
}
