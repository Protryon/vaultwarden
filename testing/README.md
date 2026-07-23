# Test harness

Integration tests run against a real Postgres. Each test gets its own
throwaway database, created and dropped around the test body.

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

## Writing a test

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
