//! Test harness for exercising database-backed logic against a real Postgres.
//!
//! This module is only compiled under `cfg(test)`. It expects the Postgres
//! instance defined in `testing/docker-compose.yml` to be running:
//!
//! ```text
//! docker compose -f testing/docker-compose.yml up -d
//! cargo test
//! ```
//!
//! Each test gets its own throwaway database. [`run_db_test`] handles the full
//! lifecycle: it (1) creates a uniquely named database, (2) runs the same
//! migrations `main.rs` runs at startup and installs the global `CONFIG`, (3)
//! runs the test body against a connection to that database, and (4) drops the
//! database afterwards — awaiting the drop even if the test body panics, so no
//! stray databases are left behind.

use std::panic::AssertUnwindSafe;
use std::sync::atomic::{AtomicU64, Ordering};

use futures::future::FutureExt;
use tokio::sync::OnceCell;
use tokio::task::JoinHandle;
use tokio_postgres::{Client, NoTls, config::SslMode};

use crate::db::Conn;

// These are hardcoded to match `testing/docker-compose.yml`. The harness talks
// to a disposable local Postgres, so there are no secrets here.
const DB_HOST: &str = "127.0.0.1";
const DB_PORT: u16 = 5433;
const DB_USER: &str = "vaultwarden";
const DB_PASSWORD: &str = "vaultwarden";
/// Database used only to issue `CREATE DATABASE` / `DROP DATABASE`, since those
/// cannot run against the database being created or dropped.
const MAINTENANCE_DB: &str = "postgres";

/// The config installed into the global `CONFIG` for the duration of the test
/// binary. Embedded so it does not depend on the process working directory.
const TEST_CONFIG_YAML: &str = include_str!("../testing/test-config.yaml");

/// Ensures the one-time, process-global startup steps (`CONFIG`, RSA JWT keys)
/// happen exactly once no matter how many tests run.
static GLOBAL_INIT: OnceCell<()> = OnceCell::const_new();

/// Monotonic counter so concurrently-running tests never collide on a name.
static DB_COUNTER: AtomicU64 = AtomicU64::new(0);

/// Perform the process-wide startup that `main.rs` does before serving: install
/// the global `CONFIG` and make sure the RSA JWT keys exist. Runs once.
async fn global_init() {
    GLOBAL_INIT
        .get_or_init(|| async {
            if !always_cell::AlwaysCell::is_set(&crate::config::CONFIG) {
                crate::config::load_str(TEST_CONFIG_YAML).expect("failed to load test config");
            }
            ensure_rsa_keys().await.expect("failed to create RSA keys for tests");
        })
        .await;
}

/// Mirror of `main::check_rsa_keys`: create the data dir and generate the RSA
/// keypair the JWT layer loads lazily, so tests that mint/verify tokens work.
async fn ensure_rsa_keys() -> anyhow::Result<()> {
    tokio::fs::create_dir_all(&crate::CONFIG.folders.data).await?;

    let priv_path = crate::CONFIG.private_rsa_key();
    let pub_path = crate::CONFIG.public_rsa_key();

    if !tokio::fs::try_exists(&priv_path).await? {
        let rsa_key = openssl::rsa::Rsa::generate(2048)?;
        crate::util::write_file(&priv_path, &rsa_key.private_key_to_pem()?).await?;
    }
    if !tokio::fs::try_exists(&pub_path).await? {
        let rsa_key = openssl::rsa::Rsa::private_key_from_pem(&tokio::fs::read(&priv_path).await?)?;
        crate::util::write_file(&pub_path, &rsa_key.public_key_to_pem()?).await?;
    }

    crate::auth::load_keys();
    Ok(())
}

/// Connect to `dbname` on the test server, spawning the connection driver task.
/// The returned handle is aborted by the caller once the client is dropped.
async fn connect(dbname: &str) -> anyhow::Result<(Client, JoinHandle<()>)> {
    let mut config = tokio_postgres::Config::new();
    config.host(DB_HOST).port(DB_PORT).user(DB_USER).password(DB_PASSWORD).dbname(dbname).ssl_mode(SslMode::Disable);

    let (client, connection) = config.connect(NoTls).await?;
    let handle = tokio::spawn(async move {
        // Ends when the client is dropped; log-only on error since teardown races
        // between dropping the client and the connection noticing are expected.
        if let Err(e) = connection.await {
            log::debug!("test db connection closed: {e}");
        }
    });
    Ok((client, handle))
}

/// A throwaway database plus a live connection to it. Obtain one via
/// [`run_db_test`], which guarantees [`cleanup`](TestDb::cleanup) is awaited.
pub struct TestDb {
    name: String,
    client: Client,
    conn_task: JoinHandle<()>,
}

impl TestDb {
    /// Create a fresh database, connect to it, and run migrations — the database
    /// half of `main.rs` startup.
    async fn setup() -> anyhow::Result<TestDb> {
        global_init().await;

        // Unique across threads in this process and across separate test binaries.
        let name = format!("vw_test_{}_{}", std::process::id(), DB_COUNTER.fetch_add(1, Ordering::Relaxed));

        // Create the database from the maintenance connection, then drop it.
        let (admin, admin_task) = connect(MAINTENANCE_DB).await?;
        admin.batch_execute(&format!("CREATE DATABASE \"{name}\"")).await?;
        drop(admin);
        admin_task.abort();

        let (mut client, conn_task) = connect(&name).await?;
        crate::db::run_migrations(&mut client).await?;

        Ok(TestDb {
            name,
            client,
            conn_task,
        })
    }

    /// A shared connection handle, for the many model methods taking `&Conn`.
    pub fn conn(&self) -> &Conn {
        &self.client
    }

    /// A mutable connection handle, for model methods taking `&mut Conn`
    /// (those that open a transaction).
    #[allow(dead_code, reason = "part of the harness API; not every test needs it")]
    pub fn conn_mut(&mut self) -> &mut Conn {
        &mut self.client
    }

    /// Drop the database. Consumes `self` and must be `.await`ed — teardown is
    /// never left to `Drop`, so a database is never leaked and cleanup errors
    /// are surfaced rather than swallowed.
    pub async fn cleanup(self) -> anyhow::Result<()> {
        let TestDb {
            name,
            client,
            conn_task,
        } = self;

        // Close our connection so `DROP DATABASE` isn't blocked by it.
        drop(client);
        conn_task.abort();

        let (admin, admin_task) = connect(MAINTENANCE_DB).await?;
        // WITH (FORCE) terminates any other lingering backends (Postgres 13+).
        admin.batch_execute(&format!("DROP DATABASE IF EXISTS \"{name}\" WITH (FORCE)")).await?;
        drop(admin);
        admin_task.abort();
        Ok(())
    }
}

/// Run `test` against a fresh, migrated database, then reliably drop it.
///
/// The database is torn down whether the test returns or panics: a panic (e.g.
/// a failed `assert!`) is caught, `cleanup` is awaited, and only then is the
/// panic resumed so the test still fails. This is why teardown is a real
/// awaited call rather than fire-and-forget work in a `Drop` impl.
///
/// ```ignore
/// #[tokio::test]
/// async fn my_test() {
///     run_db_test(async |db| {
///         let mut user = User::new("a@b.test".into());
///         user.save(db.conn()).await.unwrap();
///     })
///     .await;
/// }
/// ```
pub async fn run_db_test<T, F>(test: F) -> T
where
    F: AsyncFnOnce(&mut TestDb) -> T,
{
    let mut db = TestDb::setup().await.expect("failed to set up test database");

    let result = AssertUnwindSafe(test(&mut db)).catch_unwind().await;

    db.cleanup().await.expect("failed to clean up test database");

    match result {
        Ok(value) => value,
        Err(panic) => std::panic::resume_unwind(panic),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::db::User;

    #[tokio::test]
    #[should_panic(expected = "intentional")]
    async fn cleanup_runs_even_when_test_panics() {
        run_db_test(async |db| {
            let mut user = User::new("panic@example.test".to_string());
            user.save(db.conn()).await.unwrap();
            panic!("intentional");
        })
        .await;
    }

    #[tokio::test]
    async fn create_and_find_user() {
        run_db_test(async |db| {
            let mut user = User::new("harness@example.test".to_string());
            user.save(db.conn()).await.unwrap();

            let found = User::find_by_email(db.conn(), "harness@example.test").await.unwrap();
            assert_eq!(found.expect("user should exist").uuid, user.uuid);
        })
        .await;
    }
}
