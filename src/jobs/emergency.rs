use axum_util::errors::{ApiError, ApiResult};
use chrono::{Duration, Utc};
use log::{debug, error};

use crate::{
    db::{EmergencyAccess, EmergencyAccessStatus, User, DB},
    CONFIG,
};

pub async fn emergency_request_timeout_job() -> ApiResult<()> {
    debug!("Start emergency_request_timeout_job");
    if !CONFIG.settings.emergency_access_allowed {
        return Ok(());
    }

    let Ok(conn) = DB.get().await else {
        error!("Failed to get DB connection while searching emergency request timed out");
        return Ok(());
    };

    let emergency_access_list = EmergencyAccess::find_all_recoveries_initiated(&conn).await?;

    if emergency_access_list.is_empty() {
        debug!("No emergency request timeout to approve");
    }

    let now = Utc::now();
    for mut emer in emergency_access_list {
        // The find_all_recoveries_initiated already checks if the recovery_initiated_at is not null (None)
        let recovery_allowed_at = emer.recovery_initiated_at.unwrap() + Duration::days(i64::from(emer.wait_time_days));
        if recovery_allowed_at <= now {
            // Only update the access status
            // Updating the whole record could cause issues when the emergency_notification_reminder_job is also active
            emer.update_access_status_and_save(&conn, EmergencyAccessStatus::RecoveryApproved, now).await?;

            if CONFIG.mail_enabled() {
                // get grantor user to send Accepted email
                let grantor_user = User::get(&conn, emer.grantor_uuid).await?.ok_or(ApiError::NotFound)?;

                // get grantee user to send Accepted email
                let grantee_user = User::get(&conn, emer.grantee_uuid.ok_or(ApiError::NotFound)?).await?.ok_or(ApiError::NotFound)?;

                crate::mail::send_emergency_access_recovery_timed_out(&grantor_user.email, &grantee_user.name, emer.get_type_as_str()).await?;

                crate::mail::send_emergency_access_recovery_approved(&grantee_user.email, &grantor_user.name).await?;
            }
        }
    }
    Ok(())
}

pub async fn emergency_notification_reminder_job() -> ApiResult<()> {
    debug!("Start emergency_notification_reminder_job");
    if !CONFIG.settings.emergency_access_allowed {
        return Ok(());
    }
    let Ok(conn) = DB.get().await else {
        error!("Failed to get DB connection while searching emergency notification reminder");
        return Ok(());
    };

    let emergency_access_list = EmergencyAccess::find_all_recoveries_initiated(&conn).await?;

    if emergency_access_list.is_empty() {
        debug!("No emergency request reminder notification to send");
    }

    let now = Utc::now();
    for mut emer in emergency_access_list {
        // The find_all_recoveries_initiated already checks if the recovery_initiated_at is not null (None)
        // Calculate the day before the recovery will become active
        let final_recovery_reminder_at = emer.recovery_initiated_at.unwrap() + Duration::days(i64::from(emer.wait_time_days - 1));
        // Calculate if a day has passed since the previous notification, else no notification has been sent before
        let next_recovery_reminder_at = if let Some(last_notification_at) = emer.last_notification_at {
            last_notification_at + Duration::days(1)
        } else {
            now
        };
        if final_recovery_reminder_at <= now && next_recovery_reminder_at <= now {
            // Only update the last notification date
            // Updating the whole record could cause issues when the emergency_request_timeout_job is also active
            emer.update_last_notification_date_and_save(&conn, now).await?;

            if CONFIG.mail_enabled() {
                // get grantor user to send Accepted email
                let grantor_user = User::get(&conn, emer.grantor_uuid).await?.ok_or(ApiError::NotFound)?;

                // get grantee user to send Accepted email
                let grantee_user = User::get(&conn, emer.grantee_uuid.ok_or(ApiError::NotFound)?).await?.ok_or(ApiError::NotFound)?;

                crate::mail::send_emergency_access_recovery_reminder(
                    &grantor_user.email,
                    &grantee_user.name,
                    emer.get_type_as_str(),
                    "1", // This notification is only triggered one day before the activation
                )
                .await?;
            }
        }
    }
    Ok(())
}
