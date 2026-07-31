# Endpoint test tracking

Local, non-committed tracker for integration-test coverage of the API surface.
See [`testing/README.md`](testing/README.md) for how the harness works.

**Legend:** `[x]` covered · `[~]` partial · `[ ]` not started · `[-]` skip (see notes)

Tests live in `#[cfg(test)] mod tests` blocks at the bottom of the relevant
`src/api/**` file, driven by `crate::test_harness::TestClient`.

## Progress summary

| Area | File | Done | Total | Status |
|------|------|-----:|------:|--------|
| Identity / auth | `identity/mod.rs` | 7 | 8 | ~ |
| Accounts | `core/accounts.rs` | 19 | ~30 | ~ |
| Folders | `core/folders.rs` | 6 | 6 | ✅ |
| Ciphers | `core/ciphers.rs` | 21 | ~55 | ~ |
| Organizations | `core/organizations.rs` | 16 | ~70 | ~ |
| Collections | `core/organizations.rs` | 10 | ~12 | ~ |
| Groups | `core/organizations.rs` | 7 | ~14 | ~ |
| Org policies | `core/organizations.rs` | 1 | 5 | ~ |
| Sends | `core/sends.rs` | 7 | 12 | ~ |
| Emergency access | `core/emergency_access.rs` | 5 | 17 | ~ |
| Two-factor | `core/two_factor/*` | 5 | ~25 | ~ |
| Events | `core/events.rs` | 5 | 6 | ~ |
| Devices / auth requests | `core/mod.rs`, `accounts.rs` | 1 | ~10 | ~ |
| Misc (settings/config/etc.) | `core/mod.rs` | 4 | ~8 | ~ |
| Web / icons / notifications | `web`, `icons`, `notifications` | 0 | — | ☐ |
| Admin panel | `admin.rs` | 0 | — | ☐ |

**Total so far: 109 tests passing** (incl. 2 harness self-tests).

**Bugs found by these tests:**
- `GroupUser::delete_all_by_user` used MySQL `DELETE ... INNER JOIN` syntax,
  which Postgres rejects → every member edit (`PUT .../users/:id`) 500'd.
  Fixed to `DELETE ... USING`. Set `VW_TEST_LOG=1` to surface server errors.
- `Cipher::get_collections` selected `FROM ciphers c` with no `WHERE c.uuid = $1`;
  the `user_cipher_auth` join only referenced the constant `$1`, so once the user
  had access to the target cipher the query returned the collection IDs of *every*
  cipher in the database. This polluted every cipher's `collectionIds` and broke
  `PUT /ciphers/:uuid/collections` (rejected collections leaked in from other
  ciphers). Fixed to select `FROM collection_ciphers WHERE cipher_uuid = $1`.
  Only reproduces when other org ciphers exist, so it hid until the full suite ran.
- `delete_all` (`POST /ciphers/purge`) used `Query<Option<OrganizationId>>`;
  serde_urlencoded can't deserialize an empty query string into an `Option`, so
  purging the *personal* vault (no `organizationId`) 400'd. Fixed by making the
  field `Option<Uuid>` on a plain `Query<OrganizationId>`. Upstream avoids this by
  routing org vs personal purge separately.
- 2FA storage was completely broken (no 2FA method could be enabled). Three
  compounding bugs in `TwoFactor`, all surfaced enabling the authenticator:
  1. `TwoFactor::save` had 5 target columns but `VALUES ($1..$6)` — Postgres
     rejected every insert ("more expressions than target columns").
  2. `TwoFactor.data` is a `serde_json::Value` but the `twofactor.data` column is
     `TEXT`; tokio_postgres can't bridge them, so read and write both errored.
     Fixed by serializing to / parsing from JSON text in `save` / `From<Row>`.
  3. `activate_authenticator` stored the secret as `Value::String(secret.to_string())`,
     JSON-encoding the base32 key a second time (`"ABC"` → `"\"ABC\""`), which
     then failed base32 decode at login. Fixed to store the `Value` as-is.
- `Event::find_by_organization_and_user` (backs `GET /organizations/:id/users/:user/events`)
  had a query that referenced a nonexistent `event.` table alias and column
  `act_user_id` (real column is `act_user_uuid`), and had unparenthesized
  `AND ... OR ... AND` precedence. Every user-events query 500'd. Fixed to
  `WHERE organization_uuid = $1 AND (user_uuid = $5 OR act_user_uuid = $5) AND event_date BETWEEN ...`.

## Fixtures available on `TestClient`

- `register_and_login()` — fresh authenticated user.
- `create_folder(name) -> id`
- `create_login_cipher(name) -> Value`
- `create_org(name) -> Value` (creator becomes confirmed Owner, access-all, seed collection)
- `create_org_collection(org_id, name) -> id`
- `create_org_cipher(org_id, col_id, name) -> Value`
- `add_org_member(org_id, &member) -> Uuid` (access-all Confirmed member)
- `add_org_member_scoped(org_id, &member, &[(col_id, read_only, hide_passwords)]) -> Uuid`
  (Confirmed member limited to specific collections)
- `add_emergency_contact(&grantee, atype) -> Uuid` (invite + confirm a Confirmed
  emergency-access contact; 0 = View, 1 = Takeover)

The member fixtures rely on mail being disabled (existing invitees auto-accept).

## Harness gaps still to build

- **2FA / WebAuthn / Duo / Yubico** — need external mocks or secrets; likely
  `[-]` for now except the authenticator (TOTP) path.
- **Email flows** (verify-email, email-token, emergency invite) — need an SMTP
  capture; `mail_enabled()` is currently false in the test config.
- **Admin panel** — uses `admin_token` cookie auth, not Bearer; needs its own
  login helper.

---

## Identity / auth — `identity/mod.rs`
- [x] `POST /identity/connect/token` (password grant) — via `accounts.rs` login tests
- [x] `POST /identity/accounts/prelogin`
- [x] `POST /identity/accounts/register`
- [x] `POST /identity/connect/token` (refresh_token grant)
- [x] `POST /identity/connect/token` (client_credentials / api-key grant)
- [x] `POST /identity/connect/token` (invalid grant type rejected)
- [x] `POST /identity/connect/token` (password grant via approved auth request) — see accounts
- [x] `GET /identity/account/prevalidate`
- [-] `GET /identity/connect/oidc-signin`, `GET /identity/connect/authorize` — SSO, needs IdP

## Accounts — `core/accounts.rs`
- [x] `POST /accounts/register` (+ duplicate rejected)
- [x] `POST /connect/token` login (+ wrong password rejected)
- [x] `GET /accounts/profile`
- [x] `POST /accounts/prelogin`
- [x] `POST /accounts/profile` (update name + overlong rejected)
- [x] `PUT /accounts/avatar` (+ bad color length rejected)
- [x] `GET /users/:uuid/public-key`
- [x] `POST /accounts/keys`
- [x] `POST /accounts/password` (+ wrong current password rejected; old/new login checked)
- [x] `POST /accounts/kdf` (+ prelogin reflects new iterations; new login works)
- [x] `POST /accounts/security-stamp` (invalidates existing token)
- [x] `POST /accounts/delete` (+ wrong password rejected; login fails after)
- [x] `GET /accounts/revision-date`
- [x] `POST /accounts/api-key`, `rotate-api-key` (+ wrong password rejected)
- [x] auth-requests: `POST /auth-requests`, `GET /auth-requests/pending`, `GET/PUT /auth-requests/:uuid`, `GET /auth-requests/:uuid/response` (approve→login + deny→delete)
- [ ] `POST /accounts/set-password` (needs a passwordless/SSO user)
- [ ] `POST /accounts/key` (full key rotation)
- [ ] `POST /accounts/verify-email`, `verify-email-token`
- [ ] `POST /accounts/email-token`, `email` (needs SMTP for token)
- [ ] `POST /accounts/delete-recover`, `delete-recover-token`
- [ ] `POST /accounts/password-hint` (needs SMTP or show_password_hint)
- [ ] `GET /tasks` (stub, empty list)

## Folders — `core/folders.rs` ✅
- [x] `POST /folders` (create)
- [x] `GET /folders` (list)
- [x] `GET /folders/:uuid`
- [x] `PUT /folders/:uuid` (rename)
- [x] `DELETE /folders/:uuid`
- [x] per-user isolation + auth required

## Ciphers — `core/ciphers.rs`
- [x] `GET /sync`
- [x] `GET /ciphers/:uuid` (+ per-user isolation, auth required)
- [x] `POST /ciphers` (create personal login)
- [x] `POST /ciphers/create` (create org-owned, via org test)
- [x] `PUT /ciphers/:uuid` (update)
- [x] `DELETE /ciphers/:uuid` (hard delete)
- [x] `PUT /ciphers/:uuid/delete` (soft) + `/restore`
- [x] bulk soft delete + restore (`PUT /ciphers/delete`, `/ciphers/restore`)
- [x] bulk hard delete (`POST /ciphers/delete`)
- [x] archive/unarchive single (`/ciphers/:uuid/archive`, `/unarchive`)
- [x] bulk archive/unarchive (`PUT /ciphers/archive`, `/ciphers/unarchive`)
- [x] move: `POST /ciphers/move`
- [x] favorites (via update)
- [x] `GET /ciphers`, `/ciphers/:uuid/details`
- [x] `PUT /ciphers/:uuid/partial` (folder + favorite)
- [x] create SecureNote (type 2)
- [x] stale `lastKnownRevisionDate` rejected
- [x] import: `POST /ciphers/import` (ciphers + folders + relationships)
- [x] attachments v2: create + upload + get + delete
- [x] attachment legacy: `POST /ciphers/:uuid/attachment`
- [x] sharing: `PUT /ciphers/:uuid/share` (personal → org)
- [x] `PUT /ciphers/:uuid/collections` (org cipher collection assignment)
- [x] `POST /ciphers/purge` (personal vault; wrong password rejected)
- [ ] attachment share (`/attachment/:id/share`)
- [ ] bulk share (`PUT /ciphers/share`)
- [ ] purge org vault (`POST /ciphers/purge?organizationId=`)
- [ ] admin variants (`/admin`, `-admin`) — need org admin fixture

## Organizations — `core/organizations.rs`
- [x] create (creator becomes Owner) + get
- [x] non-member cannot read org
- [x] members: invite + confirm (via `add_org_member`); member listed Confirmed
- [x] confirmed access-all member sees org ciphers in sync
- [x] promote member role (edit_user) + get member details
- [x] revoke + restore member
- [x] remove member
- [x] update org (`PUT /organizations/:id`)
- [x] delete org (`DELETE /organizations/:id`, + wrong password rejected)
- [x] leave org (member leaves; last owner can't leave)
- [x] bulk revoke + restore (`PUT .../users/revoke|restore`, PascalCase `Ids`)
- [x] bulk remove (`DELETE .../users`, lowercase `ids`)
- [x] bulk member public-keys (`POST .../users/public-keys`)
- [x] reinvite (single 400 + bulk per-user error; SMTP disabled in tests)
- [ ] reset-password enrollment / admin recovery (needs ResetPassword policy)

## Groups — `core/organizations.rs`
- [x] create / get / list / delete group
- [x] assign member to group (`PUT .../groups/:id/users`) + list group users
- [x] update group (`PUT .../groups/:id`, name + accessAll)
- [x] group details (`GET .../groups/:id/details`, collections listed)
- [x] user's groups get + put (`.../users/:id/groups`)
- [x] remove single user from group (`DELETE .../groups/:id/users/:user`)
- [x] bulk delete groups (`DELETE .../groups`)

## Org policies — `core/organizations.rs`
- [x] enable + read a policy (`PUT`/`GET .../policies/:type`)
- [ ] list policies / policies token / invited-user
- [ ] revoke / restore / (de)activate
- [ ] keys, api-key, rotate-api-key, public-keys
- [ ] import (org), export
- [ ] reset-password (enrollment + admin recovery)
- [ ] plans / tax / billing warnings (mostly static responses)

## Collections — `core/organizations.rs`
- [x] list org collections (`GET /organizations/:org/collections`) — seed collection present
- [x] create (`POST /organizations/:org/collections`, via fixture)
- [x] scoped member sees only assigned collection (authz view)
- [x] read-only member cannot edit cipher in collection (authz view)
- [x] `GET /collections` (user's collections)
- [x] update (`PUT .../collections/:id`) + detail (`.../collections/:id/details`)
- [x] delete (`DELETE .../collections/:id`)
- [x] bulk delete (`DELETE .../collections`)
- [x] collection users: get / put / remove (`.../collections/:id/users`, `.../user/:user`)
- [ ] `GET /collections/details` (all-with-details variant)
- [ ] users on collection via `put_collection_users` edge cases (access-all skipped)

## Sends — `core/sends.rs`
- [x] `POST /sends` (text) + `GET /sends` + `GET /sends/:uuid`
- [x] `PUT /sends/:uuid` (update) + `DELETE /sends/:uuid`
- [x] `POST /sends/access/:id` (anonymous access)
- [x] `PUT /sends/:uuid/remove-password`
- [x] per-user isolation + auth required
- [x] `POST /sends/file` (legacy single-shot multipart upload)
- [x] `POST /sends/file/v2` + upload + anonymous access + token download (round-trip)

## Emergency access — `core/emergency_access.rs`
- [x] invite + confirm (via `add_emergency_contact`); trusted + granted lists
- [x] recovery initiate + approve
- [x] recovery reject
- [x] delete contact
- [x] auth required
- [ ] view / takeover / password (recovery data)
- [ ] reinvite / update wait-time / policies
- [-] flows requiring email delivery

## Two-factor — `core/two_factor/*` (tests in `authenticator.rs`)
- [x] `GET /two-factor` (provider list reflects enable/disable)
- [x] authenticator (TOTP): get-authenticator + activate (+ bad token rejected)
- [x] login requires TOTP, then succeeds with a valid code (real code generation)
- [x] `POST /two-factor/disable` (type 0)
- [x] recover: `get-recover` + `recover` (clears all 2FA)
- [-] email 2FA — needs SMTP
- [-] yubikey / duo / webauthn — need external services / secrets

## Devices & misc — `core/mod.rs`
- [x] `GET /devices/knowndevice/:email/:uuid` (known + unknown)
- [x] `GET /settings/domains` (auth required + shape)
- [x] `GET /config`, `/version`, `/now`, `/alive`
- [ ] `GET /devices/knowndevice` (header variant)
- [ ] device push token register/clear
- [ ] `POST/PUT /settings/domains` (update)
- [-] `GET /hibp/breach` (needs API key)
- [x] events: org events, cipher events, user events, collect, admin-required (`core/events.rs`)
- [ ] `POST /public/organization/import` (needs org api key)

## Not planned (for now)
- [-] Web vault static serving (`web/`)
- [-] Icons proxy (`icons/`) — external network
- [-] WebSocket notifications (`notifications/`) — separate harness
- [-] Admin panel (`admin.rs`) — cookie auth; revisit with an admin login helper
