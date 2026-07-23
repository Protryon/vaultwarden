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
//! There are two layers of harness here:
//!
//! * [`run_db_test`] — a throwaway database per test with a direct connection,
//!   for unit-testing model/query logic. It (1) creates a uniquely named
//!   database, (2) runs migrations and installs the global `CONFIG`, (3) runs
//!   the body against a connection, and (4) drops the database afterwards,
//!   awaiting the drop even if the body panics so nothing is leaked.
//!
//! * [`TestClient`] — an HTTP client against the real axol server booted once
//!   per test binary against a dedicated `vw_integration` database, for
//!   end-to-end endpoint tests. Isolation between tests comes from each test
//!   registering its own randomly-named user; the API scopes data per user, so
//!   tests do not collide and can run in parallel.

use std::net::SocketAddr;
use std::panic::AssertUnwindSafe;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::Duration;

use futures::future::FutureExt;
use serde_json::{Value, json};
use tokio::sync::OnceCell;
use tokio::task::JoinHandle;
use tokio_postgres::{Client, NoTls, config::SslMode};
use uuid::Uuid;

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
            // Surface server-side errors (500s show up as empty bodies over HTTP)
            // to stderr. Off unless VW_TEST_LOG is set, so normal runs stay quiet.
            if std::env::var_os("VW_TEST_LOG").is_some() {
                let _ = fern::Dispatch::new().level(log::LevelFilter::Debug).chain(std::io::stderr()).apply();
            }
            ensure_rsa_keys().await.expect("failed to create RSA keys for tests");
        })
        .await;
}

/// Mirror of `main::check_rsa_keys`: create the data dir and generate the RSA
/// keypair the JWT layer loads lazily, so tests that mint/verify tokens work.
async fn ensure_rsa_keys() -> anyhow::Result<()> {
    tokio::fs::create_dir_all(&crate::CONFIG.folders.data).await?;
    // Same data subfolders main.rs creates at startup, so handlers that write
    // files (attachments, sends) don't 500 on a missing directory.
    tokio::fs::create_dir_all(crate::CONFIG.folders.attachments()).await?;
    tokio::fs::create_dir_all(crate::CONFIG.folders.sends()).await?;
    tokio::fs::create_dir_all(crate::CONFIG.folders.tmp()).await?;

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

// ===========================================================================
// HTTP integration harness
// ===========================================================================

/// Booted once per test binary: recreates the integration database, runs the
/// same `db::init` startup `main.rs` runs, boots the axol server, and yields its
/// base URL (e.g. `http://127.0.0.1:10899`).
static SERVER: OnceCell<String> = OnceCell::const_new();

/// Boot the API server (once) and return its base URL.
///
/// The server runs on its own dedicated thread and runtime, independent of the
/// per-test `#[tokio::test]` runtimes. That is essential: each `#[tokio::test]`
/// spins up and tears down its own runtime, so a server (and its connection
/// pool) spawned onto a test's runtime would die when that test finishes.
async fn ensure_server() -> &'static str {
    SERVER
        .get_or_init(|| async {
            // CONFIG + RSA keys are process globals; fine to set from here.
            global_init().await;

            let (ready_tx, ready_rx) = tokio::sync::oneshot::channel::<String>();

            std::thread::Builder::new()
                .name("integration-server".to_string())
                .spawn(move || {
                    let rt = tokio::runtime::Builder::new_multi_thread().enable_all().build().expect("build server runtime");
                    rt.block_on(async move {
                        // Recreate the dedicated integration database from scratch so each
                        // `cargo test` run starts clean. Name comes from the test config.
                        let db_name = crate::CONFIG.db.database.clone();
                        let (admin, admin_task) = connect(MAINTENANCE_DB).await.expect("connect to maintenance db");
                        admin.batch_execute(&format!("DROP DATABASE IF EXISTS \"{db_name}\" WITH (FORCE)")).await.expect("drop integration db");
                        admin.batch_execute(&format!("CREATE DATABASE \"{db_name}\"")).await.expect("create integration db");
                        drop(admin);
                        admin_task.abort();

                        // Same startup path as main.rs: build the global pool + run migrations.
                        // Done on this runtime so the pool lives as long as the server.
                        crate::db::init().await.expect("db::init for integration server");

                        let addr = crate::CONFIG.settings.api_bind;
                        let server = axol::Server::bind(addr, crate::api::route()).await.expect("bind integration server");
                        tokio::spawn(async move {
                            if let Err(e) = server.serve().await {
                                log::error!("integration test server exited: {e}");
                            }
                        });

                        wait_until_ready(addr).await;
                        ready_tx.send(format!("http://{addr}")).expect("signal server ready");

                        // Keep this runtime (and the server) alive for the whole test binary.
                        std::future::pending::<()>().await;
                    });
                })
                .expect("spawn integration server thread");

            ready_rx.await.expect("integration server failed to start")
        })
        .await
        .as_str()
}

/// Poll until the server accepts TCP connections, so tests don't race the boot.
async fn wait_until_ready(addr: SocketAddr) {
    for _ in 0..200 {
        if tokio::net::TcpStream::connect(addr).await.is_ok() {
            return;
        }
        tokio::time::sleep(Duration::from_millis(25)).await;
    }
    panic!("integration test server did not become ready at {addr}");
}

/// The outcome of an HTTP request: status plus raw body, with JSON helpers.
pub struct TestResponse {
    pub status: u16,
    pub body: String,
}

impl TestResponse {
    /// Parse the body as JSON (panics if it isn't valid JSON).
    pub fn json(&self) -> Value {
        serde_json::from_str(&self.body).unwrap_or_else(|e| panic!("response body was not JSON ({e}): {}", self.body))
    }

    /// Assert a 2xx status, returning `self` for chaining. Includes the body in
    /// the failure message so test output is actionable.
    pub fn assert_ok(&self) -> &Self {
        assert!((200..300).contains(&self.status), "expected 2xx, got {}: {}", self.status, self.body);
        self
    }

    /// Assert an exact status code.
    pub fn assert_status(&self, status: u16) -> &Self {
        assert_eq!(self.status, status, "unexpected status; body: {}", self.body);
        self
    }
}

/// An HTTP client bound to the integration server. Construct an authenticated
/// one with [`TestClient::register_and_login`], which creates a fresh user.
pub struct TestClient {
    http: reqwest::Client,
    base: &'static str,
    token: Option<String>,
    pub email: String,
    pub master_password_hash: String,
    pub akey: String,
    pub public_key: String,
    pub private_key: String,
    pub device_id: String,
    pub user_id: Option<Uuid>,
}

impl TestClient {
    /// An unauthenticated client with a fresh, unique identity prepared but not
    /// yet registered.
    pub async fn new() -> TestClient {
        let base = ensure_server().await;
        let n = DB_COUNTER.fetch_add(1, Ordering::Relaxed);
        TestClient {
            http: reqwest::Client::new(),
            base,
            token: None,
            email: format!("user_{}_{n}@test.example", std::process::id()),
            // The server treats this as an opaque credential (it hashes it
            // again server-side), so any stable string works — no client-side
            // Bitwarden crypto is required.
            master_password_hash: Uuid::new_v4().simple().to_string(),
            akey: "0.testkey|testmac".to_string(),
            public_key: "testpublickey".to_string(),
            private_key: "2.testprivatekey|testmac".to_string(),
            device_id: Uuid::new_v4().to_string(),
            user_id: None,
        }
    }

    /// Register the prepared identity via `/identity/accounts/register`.
    pub async fn register(&mut self) -> &mut Self {
        let body = json!({
            "email": self.email,
            "kdf": 0,
            "kdfIterations": 600_000,
            "key": self.akey,
            "keys": { "encryptedPrivateKey": self.private_key, "publicKey": self.public_key },
            "masterPasswordHash": self.master_password_hash,
            "name": "Test User",
        });
        self.post("/identity/accounts/register", body).await.assert_ok();
        self
    }

    /// Log in via `/identity/connect/token`, storing the access token for
    /// subsequent authenticated requests, and capturing the user id.
    pub async fn login(&mut self) -> &mut Self {
        let form = [
            ("grant_type", "password"),
            ("username", self.email.as_str()),
            ("password", self.master_password_hash.as_str()),
            ("scope", "api offline_access"),
            ("client_id", "web"),
            ("device_identifier", self.device_id.as_str()),
            ("device_name", "test-harness"),
            ("device_type", "14"),
        ];
        let resp = self.send(self.request(reqwest::Method::POST, "/identity/connect/token").form(&form)).await;
        resp.assert_ok();
        let token = resp.json()["access_token"].as_str().expect("login response had no access_token").to_string();
        self.token = Some(token);

        // Capture the user id from the profile for tests that need it.
        let profile = self.get("/api/accounts/profile").await;
        profile.assert_ok();
        self.user_id = profile.json()["id"].as_str().and_then(|s| s.parse().ok());
        self
    }

    /// Convenience: a fully registered and authenticated client.
    pub async fn register_and_login() -> TestClient {
        let mut client = TestClient::new().await;
        client.register().await;
        client.login().await;
        client
    }

    fn request(&self, method: reqwest::Method, path: &str) -> reqwest::RequestBuilder {
        let mut builder = self.http.request(method, format!("{}{path}", self.base)).header("x-real-ip", "127.0.0.1");
        if let Some(token) = &self.token {
            builder = builder.bearer_auth(token);
        }
        builder
    }

    async fn send(&self, builder: reqwest::RequestBuilder) -> TestResponse {
        let resp = builder.send().await.expect("HTTP request failed");
        let status = resp.status().as_u16();
        let body = resp.text().await.unwrap_or_default();
        TestResponse {
            status,
            body,
        }
    }

    pub async fn get(&self, path: &str) -> TestResponse {
        self.send(self.request(reqwest::Method::GET, path)).await
    }

    pub async fn post(&self, path: &str, body: Value) -> TestResponse {
        self.send(self.request(reqwest::Method::POST, path).json(&body)).await
    }

    /// POST a URL-encoded form (e.g. the OAuth token endpoint).
    pub async fn post_form(&self, path: &str, form: &[(&str, &str)]) -> TestResponse {
        self.send(self.request(reqwest::Method::POST, path).form(form)).await
    }

    /// POST a `multipart/form-data` body assembled by hand (reqwest's multipart
    /// feature is not enabled). Each field is `(name, optional_filename, bytes)`;
    /// a filename makes it a file part. Used for attachment / file-send uploads.
    pub async fn post_multipart(&self, path: &str, fields: &[(&str, Option<&str>, &[u8])]) -> TestResponse {
        let boundary = format!("----vwtest{}", Uuid::new_v4().simple());
        let mut body: Vec<u8> = Vec::new();
        for (name, filename, data) in fields {
            body.extend_from_slice(format!("--{boundary}\r\n").as_bytes());
            match filename {
                Some(fname) => body.extend_from_slice(format!("Content-Disposition: form-data; name=\"{name}\"; filename=\"{fname}\"\r\n\r\n").as_bytes()),
                None => body.extend_from_slice(format!("Content-Disposition: form-data; name=\"{name}\"\r\n\r\n").as_bytes()),
            }
            body.extend_from_slice(data);
            body.extend_from_slice(b"\r\n");
        }
        body.extend_from_slice(format!("--{boundary}--\r\n").as_bytes());

        let builder = self.request(reqwest::Method::POST, path).header("content-type", format!("multipart/form-data; boundary={boundary}")).body(body);
        self.send(builder).await
    }

    pub async fn put(&self, path: &str, body: Value) -> TestResponse {
        self.send(self.request(reqwest::Method::PUT, path).json(&body)).await
    }

    pub async fn delete(&self, path: &str) -> TestResponse {
        self.send(self.request(reqwest::Method::DELETE, path)).await
    }

    /// DELETE with a JSON body (several bulk-delete endpoints require one).
    pub async fn delete_json(&self, path: &str, body: Value) -> TestResponse {
        self.send(self.request(reqwest::Method::DELETE, path).json(&body)).await
    }

    // --- fixtures -----------------------------------------------------------
    // Convenience builders returning the created object's JSON. All values are
    // opaque "encrypted" strings — the server never decrypts them.

    /// Create a personal folder, returning its id.
    pub async fn create_folder(&self, name: &str) -> String {
        let resp = self.post("/api/folders", json!({ "name": name })).await;
        resp.assert_ok();
        resp.json()["id"].as_str().expect("folder id").to_string()
    }

    /// Create a personal login cipher, returning the full cipher JSON.
    pub async fn create_login_cipher(&self, name: &str) -> Value {
        let body = json!({
            "type": 1, // Login
            "name": name,
            "login": { "username": "2.user|mac", "password": "2.pass|mac" },
            "lastKnownRevisionDate": null,
        });
        let resp = self.post("/api/ciphers", body).await;
        resp.assert_ok();
        resp.json()
    }

    /// Create an organization owned by this user (Owner, access-all, one
    /// collection), returning the full organization JSON.
    pub async fn create_org(&self, name: &str) -> Value {
        let body = json!({
            "name": name,
            "billingEmail": self.email,
            "collectionName": "2.collection|mac",
            "key": "0.orgkey|mac",
            "keys": { "encryptedPrivateKey": "2.orgpriv|mac", "publicKey": "orgpub" },
        });
        let resp = self.post("/api/organizations", body).await;
        resp.assert_ok();
        resp.json()
    }

    /// Invite `member` into `org_id` (which this client owns) and confirm them,
    /// yielding a Confirmed member with access to all collections. Returns the
    /// member's user id.
    ///
    /// Mail is disabled in tests, so an already-registered invitee is
    /// auto-accepted on invite (see `send_invite`) and only needs confirming.
    pub async fn add_org_member(&self, org_id: &str, member: &TestClient) -> Uuid {
        let member_id = member.user_id.expect("member must be registered and logged in first");

        let invite = json!({
            "emails": [member.email],
            "type": 2, // User
            "accessAll": true,
            "groups": [],
            "collections": null,
        });
        self.post(&format!("/api/organizations/{org_id}/users/invite"), invite).await.assert_ok();

        self.confirm_org_member(org_id, member_id).await;
        member_id
    }

    /// Like [`add_org_member`](Self::add_org_member) but scoped: the member is
    /// invited with `accessAll = false` and granted only the given collections,
    /// each as `(collection_id, read_only, hide_passwords)`. Returns the
    /// member's user id.
    pub async fn add_org_member_scoped(&self, org_id: &str, member: &TestClient, collections: &[(&str, bool, bool)]) -> Uuid {
        let member_id = member.user_id.expect("member must be registered and logged in first");

        let cols: Vec<Value> = collections.iter().map(|(id, read_only, hide_passwords)| json!({ "id": id, "readOnly": read_only, "hidePasswords": hide_passwords })).collect();
        let invite = json!({
            "emails": [member.email],
            "type": 2, // User
            "accessAll": false,
            "groups": [],
            "collections": cols,
        });
        self.post(&format!("/api/organizations/{org_id}/users/invite"), invite).await.assert_ok();

        self.confirm_org_member(org_id, member_id).await;
        member_id
    }

    /// Invite `grantee` as an emergency-access contact of this user (the
    /// grantor) and confirm them, yielding a Confirmed emergency access.
    /// `atype` is 0 (View) or 1 (Takeover). Returns the emergency access id.
    ///
    /// Mail is disabled, so the invite auto-accepts; only confirmation remains.
    pub async fn add_emergency_contact(&self, grantee: &TestClient, atype: i32) -> Uuid {
        let invite = json!({ "email": grantee.email, "type": atype, "waitTimeDays": 1 });
        self.post("/api/emergency-access/invite", invite).await.assert_ok();

        // Each fresh grantor has exactly one contact; grab its id.
        let trusted = self.get("/api/emergency-access/trusted").await;
        trusted.assert_ok();
        let id = trusted.json()["data"].as_array().expect("trusted list")[0]["id"].as_str().expect("emergency access id").to_string();

        self.post(&format!("/api/emergency-access/{id}/confirm"), json!({ "Key": "2.eakey|mac" })).await.assert_ok();
        id.parse().expect("emergency access uuid")
    }

    /// Confirm an already-invited (auto-accepted) member. The wrapped org key is
    /// opaque to the server, so any stable string works.
    async fn confirm_org_member(&self, org_id: &str, member_id: Uuid) {
        let confirm = json!({ "key": "2.memberorgkey|mac", "Key": "2.memberorgkey|mac" });
        self.post(&format!("/api/organizations/{org_id}/users/{member_id}/confirm"), confirm).await.assert_ok();
    }

    /// Create an organization collection, returning its id.
    pub async fn create_org_collection(&self, org_id: &str, name: &str) -> String {
        let body = json!({ "name": name, "groups": [], "users": [] });
        let resp = self.post(&format!("/api/organizations/{org_id}/collections"), body).await;
        resp.assert_ok();
        resp.json()["id"].as_str().expect("collection id").to_string()
    }

    /// Create a personal text Send (deletion date 7 days out), returning its JSON.
    pub async fn create_text_send(&self, name: &str) -> Value {
        let deletion = (chrono::Utc::now() + chrono::Duration::days(7)).to_rfc3339();
        let body = json!({
            "type": 0, // Text
            "key": "2.sendkey|mac",
            "name": name,
            "text": { "text": "2.secret|mac", "hidden": false },
            "deletionDate": deletion,
            "disabled": false,
        });
        let resp = self.post("/api/sends", body).await;
        resp.assert_ok();
        resp.json()
    }

    /// Enable TOTP (authenticator) 2FA for this user, returning the base32 shared
    /// secret. Drives the real two-step get-authenticator → activate flow with a
    /// freshly computed code, so the account genuinely requires 2FA afterwards.
    pub async fn enable_totp(&self) -> String {
        let gen_resp = self.post("/api/two-factor/get-authenticator", json!({ "masterPasswordHash": self.master_password_hash })).await;
        gen_resp.assert_ok();
        let secret = gen_resp.json()["key"].as_str().expect("totp key").to_string();

        let activate = self
            .post(
                "/api/two-factor/authenticator",
                json!({ "masterPasswordHash": self.master_password_hash, "key": secret, "token": totp_code(&secret, 0) }),
            )
            .await;
        activate.assert_ok();
        secret
    }

    /// Create an org-owned login cipher in `col_id`, returning the cipher JSON.
    pub async fn create_org_cipher(&self, org_id: &str, col_id: &str, name: &str) -> Value {
        let body = json!({
            "cipher": {
                "type": 1,
                "name": name,
                "organizationId": org_id,
                "login": { "username": "2.u|mac", "password": "2.p|mac" },
                "lastKnownRevisionDate": null,
            },
            "collectionIds": [col_id],
        });
        let resp = self.post("/api/ciphers/create", body).await;
        resp.assert_ok();
        resp.json()
    }
}

/// Compute a 6-digit TOTP code for a base32 secret, `step_offset` 30-second
/// windows from now (0 = current window). Mirrors the server's
/// `totp_custom::<Sha1>(30, 6, ...)`, letting tests produce codes the server
/// accepts. Offsetting by +1 avoids the server's replay guard when a code for
/// the current window was already consumed (e.g. during activation).
pub fn totp_code(secret_b32: &str, step_offset: i64) -> String {
    use totp_lite::{Sha1, totp_custom};
    let decoded = data_encoding::BASE32.decode(secret_b32.as_bytes()).expect("valid base32 secret");
    let time = (chrono::Utc::now().timestamp() + step_offset * 30) as u64;
    totp_custom::<Sha1>(30, 6, &decoded, time)
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
