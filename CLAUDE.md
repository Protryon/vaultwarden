# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## What this project is

This is a partial rewrite/hard fork of **dani-garcia's Vaultwarden**, which is itself an
unofficial reimplementation of the **Bitwarden server** API in Rust. The client apps
(browser extension, mobile, desktop, web-vault) are the real Bitwarden clients, so the
server's job is to speak the Bitwarden API faithfully.

Three codebases are relevant, two of them present locally as read-only references:

- This repo — the fork. Diverges substantially from upstream Vaultwarden (see below).
- `~/vaultwarden-dani` — upstream dani-garcia/vaultwarden. **Primary source of bug fixes.**
- `~/bitwarden/server` — the official Bitwarden server (C#). **Source of truth for API
  conformance / correct behavior.**

**Working model:** current maintenance is porting bug fixes from upstream Vaultwarden
(`~/vaultwarden-dani`). Future direction is improved conformance with upstream Bitwarden
(`~/bitwarden/server`) plus continued bug fixes. When implementing a fix or a behavior
change, consult those two references to see how the same endpoint/logic is handled there —
but note the architectural divergences below mean upstream code cannot be copied verbatim.

## Major divergences from upstream Vaultwarden

These change how nearly every file works, so keep them in mind before porting anything:

- **Persistence:** `diesel` ORM (mysql/postgres/sqlite) → raw `tokio-postgres`. **Only
  Postgres and CockroachDB are supported; MySQL and SQLite are gone.** SQL is hand-written.
- **Web framework:** `rocket` → **`axol`** (an axum-like framework, git dependency at
  `github.com/Protryon/axol`). Request extractors, routing, and error handling all use axol
  idioms, not Rocket's.
- **Configuration:** environment variables → a single **`config.yaml`** (see `config.rs`).
- **Authorization via SQL views:** access control for collections and ciphers is computed
  in the database through the `user_collection_auth` and `user_cipher_auth` views
  (`migrations/V1__init.sql`), not in Rust. Queries join against these views to determine
  `read_only` / `hide_passwords`.
- **`UserOrganization` is no longer a first-class entity** — a user's membership in an org
  is the compound primary key `(user_uuid, organization_uuid)` in `user_organizations`.

## Build, run, format

```bash
cargo build                 # debug build
cargo build --release       # release build (what Docker ships)
cargo run                   # run the server (reads ./config.yaml)
cargo fmt                   # rustfmt; config in rustfmt.toml (max_width = 160)
cargo clippy                # lints — main.rs has a strict deny() list, keep it clean
```

**Running requires a Postgres or CockroachDB instance and a `config.yaml`.** The committed
`config.yaml` points at a local DB (`127.0.0.2`, user `p`) and sets `api_bind`, `data`,
`public`, and an `admin_token` (argon2 hash of the admin password). Migrations run
automatically on startup via `refinery` (embedded from `migrations/`); there is no separate
migrate step. RSA JWT keys and data subfolders are created on first launch if missing.

### Tests

There is an integration test suite, but it needs a running Postgres. Bring up the throwaway
DB (Postgres on `127.0.0.1:5433`, user/pass `vaultwarden`, hardcoded to match the harness)
before running anything:

```bash
docker-compose -f testing/docker-compose.yml up -d   # v1 CLI on this box; v2 plugin is `docker compose ...`
cargo test                                            # whole suite (needs the DB above)
cargo test <name>                                     # a single test
VW_TEST_LOG=1 cargo test <name> -- --nocapture        # surface server-side 500s (bodies are otherwise empty)
```

Tests live in `#[cfg(test)] mod tests` blocks **colocated at the bottom of the relevant
`src/api/**` file**, driven by the harness in [`src/test_harness.rs`](src/test_harness.rs).
Two layers:

- **Model/query tests** — `run_db_test(async |db| { ... })` gives each test its own throwaway
  database and a direct connection (`db.conn()` / `db.conn_mut()`), and **awaits** the DB drop
  even on panic. Use for exercising `db/models/*` SQL directly.
- **Endpoint tests** — `TestClient` drives the real axol server (booted once per `cargo test`
  run against a `vw_integration` DB recreated each run). `TestClient::register_and_login()`
  yields a fresh authenticated user; the API scopes data per user, so tests self-isolate and
  run in parallel.

`TestClient` request helpers: `get`/`post`/`put`/`delete`/`post_form`/`post_multipart`
(attachments, file sends)/`delete_json` (bulk-delete bodies). Responses expose `assert_ok()`,
`assert_status(u16)`, and `json()`. Fixtures build the boilerplate and return ids/JSON:
`create_folder`, `create_login_cipher`, `create_org`, `create_org_collection`,
`create_org_cipher`, `add_org_member`(`_scoped`), `add_emergency_contact`, `enable_totp`, plus
the `totp_code(secret, step)` free fn. The master-password hash is an **opaque credential**
(the server re-hashes it) and all encrypted fields are opaque strings, so no client-side
Bitwarden crypto is needed. Mail is disabled in the test config, so org/emergency invites to
existing users auto-accept and only need confirming.

Gotchas: this crate is **edition 2024** — `gen` is a reserved word, don't use it as an
identifier. Some wire-format behavior is still only verifiable against real Bitwarden clients,
but new work should add harness tests where it can. Full walkthrough and examples:
[`testing/README.md`](testing/README.md).

### Docker / release

`./publish.sh <tag>` builds and pushes `protryon/vaultwarden:<tag>` using the multi-stage
`Dockerfile` (cargo-chef + a pinned `vaultwarden/web-vault` image).

## Architecture

Entry point is `src/main.rs`: loads `config.yaml` into the global `CONFIG`, initializes
logging (optionally OpenTelemetry/OTLP), ensures data dirs + RSA keys + web-vault exist,
runs DB migrations, schedules background jobs, then starts the API server.

- **`config.rs`** — YAML config deserialized into `Config`, exposed as a global
  `CONFIG` (`AlwaysCell`, set once at startup). Sub-structs are `#[serde(flatten)]`-ed, so
  many keys live at the top level of the YAML.
- **`db/`** — `db/mod.rs` sets up the `bb8` connection pool over `tokio-postgres`
  (global `DB` `AlwaysCell`) and runs refinery migrations. `db/models/*` are structs that
  map to tables (`user`, `cipher`, `collection`, `organization`, `device`, `send`, etc.),
  each with hand-written SQL query methods. Schema and the authorization views live in
  `migrations/V1__init.sql`. Target dialect must stay CockroachDB-compatible.
- **`api/`** — HTTP surface, composed as nested axol `Router`s in `api/mod.rs`:
  - `api/core/` — the bulk of the Bitwarden API: `accounts`, `ciphers`, `folders`,
    `organizations`, `sends`, `emergency_access`, `events`, `public`, and `two_factor/`
    (authenticator, email, duo, webauthn, yubikey).
  - `api/identity/` — login / token endpoints (OAuth-style, mounted at `/identity`).
  - `api/notifications/` — WebSocket push to clients (`ws_users`, `UpdateType`).
  - `api/icons/` — website icon fetching/caching. `api/web/` — serves the web-vault.
    `api/admin/` — admin panel.
- **`auth.rs`** (currently open in the IDE) — JWT (RS256) encode/decode with per-purpose
  issuers (login, invite, admin, send, …), and the axol extractors (`Headers` and friends)
  that authenticate requests and load the user/device/org context handlers depend on.
- **`crypto.rs`** — hashing / key derivation / random. **`events.rs`, `jobs/`** — event
  logging and scheduled background jobs. **`push/`** — mobile push notifications.
  **`mail.rs`, `templates.rs`** — SMTP email and its templates. **`ratelimit.rs`,
  `error.rs`, `util.rs`** — support.

## Conventions

- Keep the API wire format (JSON field names, casing, response shapes) matching what
  Bitwarden clients expect — handlers lean heavily on `#[serde(rename_all = "camelCase")]`
  and `alias` attributes for PascalCase compatibility with older clients.
- `main.rs` forbids `unsafe`/non-ASCII idents and enables a strict clippy `deny` list;
  new code must satisfy it.
- Author/license metadata in `Cargo.toml` and `LICENSE.txt` remains dani-garcia /
  AGPL-3.0-only.
