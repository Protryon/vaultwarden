# Test harness

Tests run against a real Postgres from [`../src/test_harness.rs`](../src/test_harness.rs).
There are two layers:

- **Model/query tests** — `run_db_test` gives each test its own throwaway
  database and a direct connection.
- **Endpoint tests** — `TestClient` drives the real axol HTTP server (booted
  once per `cargo test` run against a dedicated `vw_integration` database).
  Colocated with the handlers they cover, in `#[cfg(test)] mod tests` blocks at
  the bottom of the relevant `src/api/**` files.

Both need the Postgres below running.

## 1. Start Postgres

```bash
docker-compose -f testing/docker-compose.yml up -d
# (Docker Compose v2 plugin: `docker compose -f testing/docker-compose.yml up -d`)
```

This runs Postgres on `127.0.0.1:5433` with user/password `vaultwarden`/`vaultwarden`.
Data lives in a tmpfs, so it is fast and wiped when the container stops. These
values are hardcoded to match the constants in [`../src/test_harness.rs`](../src/test_harness.rs).

## 2. Run the tests

```bash
cargo test
```

## 3. Tear down

```bash
docker-compose -f testing/docker-compose.yml down -v
```

## Writing a model/query test

Use `run_db_test`, which creates a fresh migrated database, runs the body, and
**awaits** the database drop afterwards — even if the body panics, so failed
assertions never leak databases:

```rust
use crate::test_harness::run_db_test;
use crate::db::User;

#[tokio::test]
async fn my_test() {
    run_db_test(async |db| {
        let mut user = User::new("a@b.test".to_string());
        user.save(db.conn()).await.unwrap();          // &Conn
        // db.conn_mut() gives &mut Conn for methods that open a transaction
    })
    .await;
}
```

Setup performs the same startup steps as `main.rs`: it installs the global
`CONFIG` (from [`test-config.yaml`](test-config.yaml), embedded into the test
binary), ensures the RSA JWT keys exist, then runs the embedded migrations
against the new database.

## Writing an endpoint test

Use `TestClient`. Each test registers its own random user, so tests are
isolated (the API scopes data per user) and can run in parallel against the one
shared server:

```rust
#[cfg(test)]
mod tests {
    use serde_json::json;
    use crate::test_harness::TestClient;

    #[tokio::test]
    async fn create_folder() {
        let client = TestClient::register_and_login().await;
        let resp = client.post("/api/folders", json!({ "name": "2.enc|mac" })).await;
        resp.assert_ok();
        assert_eq!(resp.json()["object"], "folder");
    }
}
```

The client sends the master password hash as an opaque credential (the server
re-hashes it), so no client-side Bitwarden crypto is needed. `TestClient`
exposes `get`/`post`/`put`/`delete`/`post_form`; responses have `assert_ok`,
`assert_status`, and `json` helpers.
