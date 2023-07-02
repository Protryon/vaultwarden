mod emergency;

use std::thread;

use axum_util::errors::{ApiError, ApiResult};
use chrono::{Duration, Utc};
use log::{debug, error, info};

use crate::{
    db::{Cipher, Event, SsoNonce, TwoFactorIncomplete, User, DB},
    CONFIG,
};

pub fn schedule_jobs() {
    if CONFIG.jobs.job_poll_interval_ms == 0 {
        info!("Job scheduler disabled.");
        return;
    }

    let runtime = tokio::runtime::Runtime::new().unwrap();

    thread::Builder::new()
        .name("job-scheduler".to_string())
        .spawn(move || {
            use job_scheduler_ng::{Job, JobScheduler};
            let _runtime_guard = runtime.enter();

            let mut sched = JobScheduler::new();

            //TODO: make this configurable i guess
            // every 15 min on the 3rd minute of the hour
            sched.add(Job::new("0 3,18,33,48 * * * *".parse().unwrap(), || {
                runtime.spawn(purge_sso_nonce());
            }));

            // Purge sends that are past their deletion date.
            sched.add(Job::new(CONFIG.jobs.send_purge_schedule.clone(), || {
                runtime.spawn(purge_sends());
            }));

            // Purge trashed items that are old enough to be auto-deleted.
            sched.add(Job::new(CONFIG.jobs.trash_purge_schedule.clone(), || {
                runtime.spawn(purge_trashed_ciphers());
            }));

            // Send email notifications about incomplete 2FA logins, which potentially
            // indicates that a user's master password has been compromised.
            sched.add(Job::new(CONFIG.jobs.incomplete_2fa_schedule.clone(), || {
                runtime.spawn(async move {
                    if let Err(e) = send_incomplete_2fa_notifications().await {
                        error!("failed to run send_incomplete_2fa_notifications: {e}");
                    }
                });
            }));

            // Grant emergency access requests that have met the required wait time.
            // This job should run before the emergency access reminders job to avoid
            // sending reminders for requests that are about to be granted anyway.
            sched.add(Job::new(CONFIG.jobs.emergency_request_timeout_schedule.clone(), || {
                runtime.spawn(async move {
                    if let Err(e) = emergency::emergency_request_timeout_job().await {
                        error!("failed to run emergency_request_timeout_job: {e}");
                    }
                });
            }));

            // Send reminders to emergency access grantors that there are pending
            // emergency access requests.
            sched.add(Job::new(CONFIG.jobs.emergency_notification_reminder_schedule.clone(), || {
                runtime.spawn(async move {
                    if let Err(e) = emergency::emergency_notification_reminder_job().await {
                        error!("failed to run emergency_notification_reminder_job: {e}");
                    }
                });
            }));

            // Cleanup the event table of records x days old.
            if CONFIG.settings.org_events_enabled && CONFIG.settings.events_days_retain.is_some() {
                sched.add(Job::new(CONFIG.jobs.event_cleanup_schedule.clone(), || {
                    runtime.spawn(event_cleanup_job());
                }));
            }

            // Periodically check for jobs to run. We probably won't need any
            // jobs that run more often than once a minute, so a default poll
            // interval of 30 seconds should be sufficient. Users who want to
            // schedule jobs to run more frequently for some reason can reduce
            // the poll interval accordingly.
            //
            // Note that the scheduler checks jobs in the order in which they
            // were added, so if two jobs are both eligible to run at a given
            // tick, the one that was added earlier will run first.
            loop {
                sched.tick();
                runtime.block_on(tokio::time::sleep(tokio::time::Duration::from_millis(CONFIG.jobs.job_poll_interval_ms)));
            }
        })
        .expect("Error spawning job scheduler thread");
}

async fn purge_sso_nonce() {
    debug!("Purging SSO Nonces");
    let Ok(conn) = DB.get().await else {
        error!("Failed to get DB connection while purging SSO Nonces");
        return;
    };
    //TODO: make this configurable i guess
    if let Err(e) = SsoNonce::purge_expired(&conn, Utc::now() - chrono::Duration::minutes(15)).await {
        error!("failed to purge sso nonces: {e}");
    }
}

async fn purge_sends() {
    debug!("Purging sends");
    let Ok(mut conn) = DB.get().await else {
        error!("Failed to get DB connection while purging sends");
        return;
    };
    if let Err(e) = crate::db::Send::purge(&mut conn).await {
        error!("failed to purge sends: {e}");
    }
}

async fn purge_trashed_ciphers() {
    debug!("Purging trashed ciphers");
    let Ok(mut conn) = DB.get().await else {
        error!("Failed to get DB connection while purging trashed ciphers");
        return;
    };
    if let Err(e) = Cipher::purge_trash(&mut conn).await {
        error!("failed to purge expired ciphers: {e}");
    }
}

async fn send_incomplete_2fa_notifications() -> ApiResult<()> {
    debug!("Sending notifications for incomplete 2FA logins");

    if CONFIG.settings.incomplete_2fa_time_limit <= 0 || !CONFIG.mail_enabled() {
        return Ok(());
    }

    let Ok(conn) = DB.get().await else {
        error!("Failed to get DB connection in send_incomplete_2fa_notifications()");
        return Ok(());
    };

    let now = Utc::now();
    let time_limit = Duration::minutes(CONFIG.settings.incomplete_2fa_time_limit);
    let time_before = now - time_limit;
    let incomplete_logins = TwoFactorIncomplete::find_logins_before(&conn, time_before).await?;
    for login in incomplete_logins {
        let user = User::get(&conn, login.user_uuid).await?.ok_or(ApiError::NotFound)?;
        info!("User {} did not complete a 2FA login within the configured time limit. IP: {}", user.email, login.ip_address);
        crate::mail::send_incomplete_2fa_login(&user.email, login.ip_address, login.login_time, &login.device_name).await?;
        login.delete(&conn).await?;
    }
    Ok(())
}

async fn event_cleanup_job() {
    debug!("Start events cleanup job");
    if CONFIG.settings.events_days_retain.is_none() {
        debug!("events_days_retain is not configured, abort");
        return;
    }
    let Ok(conn) = DB.get().await else {
        error!("Failed to get DB connection while cleaning up the events table");
        return;
    };

    if let Err(e) = Event::clean_events(&conn).await {
        error!("failed to clean expired events: {e}");
    }
}
