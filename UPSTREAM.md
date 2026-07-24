# UPSTREAM.md — API wire-format conformance audit

Audit of where **this fork's HTTP/JSON API schema** diverges from what Bitwarden clients
expect. "Schema" here means the **wire format** — request DTOs, response shapes, field
names/casing, enum values — **not** the database schema.

## Sources of truth

- **`~/bitwarden/server`** (official C#) — canonical wire format. Request DTOs in
  `src/Api/**/Models/Request`, responses in `src/Api/**/Models/Response`, shared data/enum
  models in `src/Core/**`.
- **`~/vaultwarden-dani`** (upstream Vaultwarden, Rust) — our fork's parent. The **`dani status`**
  on each finding says whether dani already handles it, which tells us whether a gap is
  *"we're stale vs dani"* (portable fix) or *"both are behind Bitwarden"* (new work).

## How to read this

Each finding: **severity**, the endpoint/model, our code (`file:line`), the Bitwarden model,
the precise mismatch, client impact, and dani status. Severity is about *client breakage*, not
effort:

- **HIGH** — a current client flow fails, silently drops data, or a value is rejected/panics.
- **MED** — degraded behavior, missing fields newer clients read, or type coercion issues.
- **LOW** — cosmetic / forward-compat / conformance-only; current pinned web-vault tolerates it.

This is a **starting map to iterate on**, not a fix list. Line numbers are from the audit
snapshot (2026-07-24) and drift as files change — re-anchor before acting.

---

## Cross-cutting themes

1. **Enum truncation → hard deserialize failures.** Several enums use `serde_repr`/
   `Deserialize_repr`, which has **no catch-all variant**, so an out-of-range value from a
   modern client is a 400/422 for the *whole request*, not a graceful "unknown". This bites
   `CipherType` (6/7/8), `EventType` (`/events/collect` batch), `PolicyType` (17–21),
   `TwoFactorType` (RecoveryCode=8), `OrganizationUserType` (Custom=4), and `UpdateType`.
   **Status: addressed (2026-07-24) for CipherType, EventType, PolicyType, TwoFactorType, and
   OrganizationUserType** — missing variants added, and the two genuinely open-ended inbound
   paths (`/events/collect`, org-user role) got lenient number-or-string deserializers that
   fold unknowns to a safe value instead of 400ing. `UpdateType` (push) is outbound-only and
   left as-is. There is still no single generic `#[serde(other)]` helper; each enum was handled
   on its merits.

2. **"v2 modernization" gaps.** Bitwarden reworked several flows into new routes + bodies;
   the fork still carries the pre-v2 shape. Biggest ones: **key rotation**
   (`key-management/rotate-user-account-keys`), **two-step registration** (`register/finish`),
   **Duo Universal Prompt** (OIDC `AuthUrl`), and the **2FA `userVerificationToken`** setup
   flow. dani has already ported the first three.

3. **Flexible-collections `manage` permission** is dropped end-to-end (no DB column, no
   request parsing, no response emission). dani implements it fully — this is the single most
   pervasive org-side gap.

4. **Pure typo bugs** (not upstream drift — fork-local regressions). These are the cheapest,
   highest-value fixes and are broken out below.

---

## Confirmed fork-local bugs (quick wins)

These are self-contained defects — typos or wrong literals — independent of upstream drift.

**Status: B1, B3, B4, B5, B6, B7 fixed (2026-07-24). B2 deferred to the enum-leniency work
(C1) — it's not a typo; it requires deciding what an unknown cipher type should render as.**

| # | Bug | Location | Fix | Status |
|---|-----|----------|-----|--------|
| B1 | Legacy file-send writes file id under key `"od"` instead of `"id"` — recipient can't resolve the file for download. v2 path is correct. | [sends.rs:290](src/api/core/sends.rs#L290) | `"od"` → `"id"` | ✅ fixed |
| B2 | Unknown/unsupported `CipherType` **panics** the response builder (`panic!("Wrong type")`) instead of erroring. | [cipher.rs:417](src/db/models/cipher.rs#L417) | handle gracefully (see C1) | ✅ fixed (with C1) |
| B3 | `GET /organizations/:id/keys` emits discriminator `"pbject"` instead of `"object"`. Sibling `post_org_keys` spells it right. | [organizations.rs:2451](src/api/core/organizations.rs#L2451) | `"pbject"` → `"object"` | ✅ fixed |
| B4 | Public import group data field `member_external_ds` (→ `memberExternalDs`) misspells `memberExternalIds`; group memberships silently dropped on import. | [public.rs:21](src/api/core/public.rs#L21) | rename to `member_external_ids` + serde | ✅ fixed |
| B5 | `PUT /two-factor/email` returns `"enabled": "true"` (string), while `get_email` returns a real bool — the two disagree. (Shared with dani.) | [email.rs:172](src/api/core/two_factor/email.rs#L172) | emit boolean | ✅ fixed |
| B6 | Members-grid embedded `collections` array uses PascalCase `Id/ReadOnly/HidePasswords` while every other collection payload is camelCase. | [organization.rs:398](src/db/models/organization.rs#L398) | camelCase keys | ✅ fixed |
| B7 | Attachment-v2 upload response keys `CipherResponse`/`CipherMiniResponse` are PascalCase; clients read `cipherResponse`/`cipherMiniResponse`. | [ciphers.rs:822](src/api/core/ciphers.rs#L822) | camelCase keys | ✅ fixed |

---

## Ciphers + Folders

- **[HIGH] ✅ C1 — Cipher types 6/7/8 rejected.** *(fixed 2026-07-24: added `BankAccount=6`/
  `DriversLicense=7`/`Passport=8`; write path routes them through the `data` fallback, response
  emits their obsolete-but-present sub-object keys, and the `Unknown` panic (B2) is now a safe
  skip. Test: `ciphers::tests::newer_cipher_types_round_trip_via_data`.)* `CipherType` stops at `SshKey=5` (+`Unknown`);
  Bitwarden has `BankAccount=6, DriversLicense=7, Passport=8`. `Deserialize_repr` makes
  `"type":6/7/8` a hard 400, and even if parsed the response builder panics (B2). Users can't
  create/import those items. Ours: [cipher.rs:63](src/db/models/cipher.rs#L63),
  [ciphers.rs:445](src/api/core/ciphers.rs#L445). BW: `Core/Vault/Enums/CipherType.cs`.
  **dani: no** (dani also stops at 5).
- **[HIGH] C2 — Cipher `permissions` object missing.** Response emits `edit`/`viewPassword`
  but not `permissions: { delete, restore }`; clients since ~v2025.6 gate delete/restore on
  it. Ours: [cipher.rs:400](src/db/models/cipher.rs#L400). BW:
  `CipherPermissionsResponseModel.cs`. **dani: yes** (`cipher.rs:383`) — portable.
- **[MED] C3 — `/ciphers/:uuid/collections_v2` route missing.** Only `/collections` (returns
  `204`, empty) and `/collections-admin` exist; clients POSTing `collections_v2` expect
  `{ object:"optionalCipherDetails", unavailable, cipher }` and get 404. Ours:
  [ciphers.rs:44](src/api/core/ciphers.rs#L44). **dani: yes** (`ciphers.rs:757`).
- **[MED] C4 — Attachment-v2 upload PascalCase keys.** See B7. **dani: yes (correct)**.
- **[LOW] C5 — `encryptedFor` (cipher request) silently dropped.** BW `CipherRequestModel.cs:18`.
  No consumer today. **dani: no**.
- **[LOW] C6 — Attachment `fileSize` is `i32`, no `lastKnownRevisionDate`.** BW uses `long` +
  optional stale-check date; single attachments >2 GiB fail to reserve. Ours:
  [ciphers.rs:791](src/api/core/ciphers.rs#L791). **dani: partial** (i64 sizes, no date guard).
- **[LOW] C7 — `data`-vs-structured precedence reversed.** When a client sends both, BW honors
  `data`; we honor the structured object. Ours: [ciphers.rs:439](src/api/core/ciphers.rs#L439).
- **[LOW] C8 — Response `object` always `"cipherDetails"`.** BW distinguishes `cipher`/
  `cipherDetails`/`cipherMini`/`cipherMiniDetails`; org syncs mislabeled. Ours:
  [cipher.rs:364](src/db/models/cipher.rs#L364). **dani: no** (dani emits `cipherMiniDetails`).

> Note: per-type sub-bodies (login URIs, fido2, card, identity, sshkey, linked fields,
> passwordHistory) are stored/echoed as an opaque `data` blob, so individual sub-fields
> pass through intact **as long as the enclosing `type` is accepted** (see C1).

---

## Accounts + Identity / Token

- **[HIGH] A1 — Key-rotation is the pre-v2 route + body.** We expose `POST /accounts/key` with
  `{ciphers,folders,key,privateKey,masterPasswordHash}`. Bitwarden moved to
  `POST /accounts/key-management/rotate-user-account-keys` with `accountUnlockData` /
  `accountKeys` / `accountData` / `oldMasterKeyAuthenticationHash` (and rotates Sends, which we
  never do). Current web-vault → 404/deserialize failure; rotation broken. Ours:
  [accounts.rs:610](src/api/core/accounts.rs#L610). **dani: yes** (ported route + v2 body).
- **[MED] A2 — Two-step registration missing.** No `register/finish` or
  `register/send-verification-email`; only the legacy single-shot `/accounts/register`. Email-
  verified signup (and invite-token variants) can't complete. Ours:
  [accounts.rs:200](src/api/core/accounts.rs#L200). **dani: yes**.
- **[MED] A3 — `client_credentials` (CLI/API-key) token response is legacy-only.**
  `password_login` was modernized (`UserDecryptionOptions`, `AccountKeys`,
  `MasterPasswordPolicy`, `ForcePasswordReset`) but `user_api_key_login` still returns only
  `Key`/`PrivateKey`/`Kdf*`/`ResetMasterPassword`. Ours:
  [identity/mod.rs:553](src/api/identity/mod.rs#L553). **dani: yes** (shared response builder).
- **[MED] A4 — `RegisterData`/`SetPasswordData` accept only legacy credential fields.** BW v2
  adds `masterPasswordAuthentication`, `masterPasswordUnlock` (kdf + wrapped key + salt),
  structured `accountKeys`. A v2-only body would persist empty key material. Masked today
  because web-vault still sends legacy fields. Ours:
  [accounts.rs:200](src/api/core/accounts.rs#L200). **dani: partial** (compat enum).
- **[LOW] A5 — Prelogin omits nested `kdfSettings` + `salt`.** Flat fields only. Ours:
  [accounts.rs:975](src/api/core/accounts.rs#L975). **dani: no**.
- **[LOW] A6 — Profile omits `accountKeys`, `verifyDevices`, `organizationsNew`.** (Also emits
  extra `masterPasswordHint`/`_status`, harmless.) Ours: [user.rs:306](src/db/models/user.rs#L306). **dani: no**.
- **[LOW] A7 — `POST /accounts/keys` omits `key` + `accountKeys`.** Ours:
  [accounts.rs:491](src/api/core/accounts.rs#L491). **dani: no**.
- **[LOW] A8 — `refresh_token` grant returns legacy body; failure not `invalid_grant` JSON.**
  dani slimmed refresh to tokens-only and returns `{"error":"invalid_grant"}` (400) that
  clients key on for silent re-login. Ours: [identity/mod.rs:145](src/api/identity/mod.rs#L145).
  **dani: yes**.
- **[LOW] A9 — SSO `authorization_code` response omits `UserDecryptionOptions`/`AccountKeys`/
  `MasterPasswordUnlock`.** TDE/KeyConnector unlock relies on these. Partly fork-specific (our
  SSO stack differs). Ours: [identity/mod.rs:248](src/api/identity/mod.rs#L248). **dani: yes**.
- **[LOW] A10 — 2FA challenge never emits OrganizationDuo (type 6).** Enum defines it
  ([two_factor.rs:44](src/db/models/two_factor.rs#L44)) but `json_err_twofactor` skips it.
  Ours: [identity/mod.rs:688](src/api/identity/mod.rs#L688). **dani: partial**.
- **[LOW] A11 — `forcePasswordReset`/`ResetMasterPassword` hardcoded.** BW drives
  `ForcePasswordReset` from a stored flag and `ResetMasterPassword` from has-no-password; we
  return constant `false` almost everywhere (admin-forced reset / JIT-provisioned prompts
  won't fire). Ours: [user.rs:323](src/db/models/user.rs#L323),
  [identity/mod.rs:156](src/api/identity/mod.rs#L156). **dani: partial**.

> `password_login` ([identity/mod.rs:454](src/api/identity/mod.rs#L454)) is fully modernized —
> it's the template to bring the other grants up to.

---

## Organizations + Public

- **[HIGH] O1 — Collection `manage` permission dropped end-to-end.** Every collection-access
  request DTO accepts only `id/readOnly/hidePasswords`; `manage` is deserialized-away, never
  persisted (no DB column), never emitted. Affects invite/edit-user, collection & group
  create/update, collection-users, details. The web-vault "can manage" toggle no-ops. Ours:
  [organizations.rs:2052](src/api/core/organizations.rs#L2052),
  [collection.rs:24](src/db/models/collection.rs#L24), [group.rs:35](src/db/models/group.rs#L35).
  BW: `SelectionReadOnly{Request,Response}Model.cs`. **dani: yes** (full end-to-end incl. DB
  column) — this needs a migration + query changes, largest single item.
- **[HIGH] ✅ O2 — `Custom` org role (type 4) unsupported; `Manager` (3) still emitted.**
  *(fixed 2026-07-24: ported dani's shim — `FromStr` + a new number-or-string
  `deserialize_membership_type` fold `4|"Custom" → Manager` on invite/edit/admin input, and
  `UserOrganization::type_manager_as_custom()` emits `Manager` back as `4` in all three member
  response builders. Custom permissions themselves are still not implemented — a Custom member
  renders with an empty permissions set, same partial as dani. Test:
  `organizations::tests::custom_role_round_trips_as_type_4`.)* BW
  permanently removed `Manager=3` and uses `Custom=4`. Sending `type:4`/`"Custom"` → 400; we
  still hand out `type:3`. Ours: [organization.rs:54](src/db/models/organization.rs#L54).
  **dani: no** but dani maps `4|Custom → Manager` on input and back out via
  `type_manager_as_custom()`, so Custom round-trips — port that shim.
- **[MED] O3 — `to_json_user_details` missing member fields.** Omits `externalId`,
  `avatarColor`, `ssoBound`, `permissions`, `accessSecretsManager`, `hasMasterPassword`,
  `usesKeyConnector`, `managedByOrganization`/`claimedByOrganization`, `creationDate`,
  `revocationReason`; embedded `collections` are PascalCase (B6) and lack `manage`. Ours:
  [organization.rs:375](src/db/models/organization.rs#L375). **dani: no** (dani emits most).
- **[MED] O4 — Collection response missing `type`, `manage`, `unmanaged`, real `externalId`.**
  `externalId` is hardcoded null (no DB column); `type` (shared/default-user), `manage`,
  `unmanaged` never emitted. Ours: [collection.rs:84](src/db/models/collection.rs#L84),
  [organizations.rs:346](src/api/core/organizations.rs#L346). **dani: partial** (real
  `externalId` + `manage`; no `type`).
- **[MED] O5 — Collection-users list omits `manage`.** `GET .../collections/:cid/users`. Ours:
  [organization.rs:427](src/db/models/organization.rs#L427). **dani: no**.
- **[MED] O6 — `GET /organizations/:id/keys` discriminator typo `pbject`.** See B3.
- **[LOW] O7 — Public/directory-connector API largely unimplemented.** Only `ldap_import`
  exists; no public members/groups/collections/policies CRUD, and the import group-members
  field is misspelled (B4). Ours: [public.rs](src/api/core/public.rs). **dani: partial**
  (dani implements the full public API; the typo is fork-specific).
- **[LOW] ✅ O8 — `PolicyType` stops at 16.** *(fixed 2026-07-24: added variants 17–21 so
  `GET/PUT .../policies/17..21` no longer 400. The `PersonalOwnership`→`OrganizationDataOwnership`
  rename is wire-invisible (int 5 unchanged) and left as-is; enforcement of the new policies is
  separate/out of scope.)* BW adds 17–21 (`AutotypeDefaultSetting`,
  `AutomaticUserConfirmation`, `BlockClaimedDomainAccountCreation`,
  `OrganizationUserNotification`, `SendControls`) and renames `PersonalOwnership`→
  `OrganizationDataOwnership` (same int 5). `GET/PUT .../policies/17..21` → 400. Ours:
  [org_policy.rs:25](src/db/models/org_policy.rs#L25). **dani: no** (both behind Bitwarden).
- **[LOW] O9 — Profile-org object gaps.** Omits `userIsClaimedByOrganization`,
  `isAdminInitiated`; sets `useCustomPermissions:false`; uses single
  `limitCollectionCreationDeletion` where BW/dani split
  `limitCollectionCreation`/`limitCollectionDeletion`. Ours:
  [organization.rs:293](src/db/models/organization.rs#L293). **dani: partial**.
- **[LOW] O10 — `resetPasswordEnrolled` = `is_some()` not key-validity.** Empty-string reset
  key reports enrolled. BW checks non-whitespace. Ours:
  [organization.rs:314](src/db/models/organization.rs#L314). **dani: no**.

---

## Sends + Emergency Access

- **[HIGH] S1 — Legacy file-send file-id key `"od"`.** See B1. **dani: no** (dani uses `"id"`).
- **[HIGH] S2 — Send `emails` (email-restricted access) silently dropped.** `SendData` has no
  `emails` field; serde ignores it, so an email-restricted Send is created with **no**
  restriction (security-relevant — user thinks access is limited but it's public). dani at
  least hard-rejects with "not supported". Ours: [sends.rs:44](src/api/core/sends.rs#L44).
  **dani: partial** (rejects). Minimum bar: reject like dani.
- **[MED] S3 — `authType` missing from Send response.** BW/dani emit `authType`
  (Email=0/Password=1/None=2). Ours: [send.rs:157](src/db/models/send.rs#L157). **dani: no**
  (dani emits it; we're stale vs dani).
- **[MED] S4 — `authType` missing from Send-access response.** Anonymous access payload can't
  advertise which challenge is required. Ours: [send.rs:191](src/db/models/send.rs#L191).
  **dani: no** (both omit).
- **[MED] S5 — Emergency-access takeover response missing `salt`.** BW returns grantor MP
  `salt` alongside kdf/`keyEncrypted` for the master-password-unlock flow. (Careful: our
  `User.salt` is a server hashing salt, not BW's email-derived MP salt.) Ours:
  [emergency_access.rs:525](src/api/core/emergency_access.rs#L525). **dani: no**.
- **[LOW] S6 — Grantee/grantor details omit `avatarColor`.** We already store `avatar_color`.
  Ours: [emergency_access.rs:90](src/db/models/emergency_access.rs#L90). **dani: no** (emits it).
- **[LOW] S7 — Grantee details emit zero-UUID/empty strings instead of null when absent.**
  Ours: [emergency_access.rs:116](src/db/models/emergency_access.rs#L116). **dani: no** (omits row).
- **[LOW] S8 — Send-access `id` is raw UUID, not base64 accessId.** Internally consistent with
  our file-access routes; matches dani, differs from Bitwarden. **dani: no**.
- **[LOW] S9 — File-send `validated` field never emitted.** BW `SendFileData.Validated`
  (default true). (`sizeName` is a vaultwarden extension, not in BW.) **dani: no**.
- **[LOW] S10 — Request validation gaps.** `max_access_count`/`wait_time_days` accept
  0/negative/oversized values BW rejects (`[Range]`); invite `Type` not `[Required]`. Ours:
  [sends.rs:50](src/api/core/sends.rs#L50). **dani: partial**.
- **[LOW] S11 — Send request ignores `id` (key-rotation) and `authType`.** Ours:
  [sends.rs:44](src/api/core/sends.rs#L44). **dani: partial**.

> Correct & confirmed: all `object` discriminators (send/send-access/send-fileUpload/etc.),
> the v2 two-step file-upload flow, `SendType`, `EmergencyAccessType`/`Status` enums.

---

## Two-Factor

- **[HIGH] T1 — Duo Universal Prompt (v4/OIDC) entirely missing.** We only implement the dead
  legacy Duo Web SDK v2 iframe; login challenge emits `{Host,Signature}` where BW/dani emit
  `{AuthUrl}` (OIDC redirect). No `duo_oidc` module, no Duo context storage. Duo shut down the
  legacy SDK, so configured Duo is effectively broken on modern clients. Ours:
  [duo.rs:254](src/api/core/two_factor/duo.rs#L254),
  [identity/mod.rs:718](src/api/identity/mod.rs#L718). **dani: yes** (`duo_oidc.rs`) — portable.
- **[HIGH] T2 — Duo config uses `integrationKey`/`secretKey`, not Universal `clientId`/
  `clientSecret`.** Field names differ, BW validates 20/40-char lengths and nests details
  under a `Duo` object + `UserVerificationToken`; ours is flat. Web-vault Duo setup posts
  `clientId`/`clientSecret` → rejected. Ours: [duo.rs:122](src/api/core/two_factor/duo.rs#L122).
  **dani: yes**.
- **[MED] ✅ T3 — `TwoFactorType` missing `RecoveryCode = 8`.** *(fixed 2026-07-24: added the
  variant.)* `from_repr(8)` → `Unknown`. Ours:
  [two_factor.rs:37](src/db/models/two_factor.rs#L37). **dani: yes** — stale vs dani.
- **[MED] T4 — Email activation returns `"enabled":"true"` (string).** See B5. `get_email`
  disagrees (bool). **dani: yes** (same string bug upstream).
- **[MED] T5 — `userVerificationToken` absent; details not nested under provider key.** Newer
  BW mints a UV token on the 2FA GET and nests details under `authenticator`/`duo`/`email`/
  `webAuthn`/`yubiKey`; the matching updates require that token instead of `masterPasswordHash`.
  Ours are flat and password-based. Benign with pinned web-vault. Ours:
  [authenticator.rs:38](src/api/core/two_factor/authenticator.rs#L38) et al. **dani: no**.
- **[MED] T6 — Per-provider DELETE endpoints not implemented.** BW moved to
  `DELETE /two-factor/{authenticator,duo,yubikey,webauthn,email}` (UV-token auth); we keep only
  the generic `POST/PUT /two-factor/disable` + `DELETE /two-factor/webauthn`. Ours:
  [two_factor/mod.rs:28](src/api/core/two_factor/mod.rs#L28). **dani: no**.
- **[LOW] T7 — WebAuthn/YubiKey response `object` is `twoFactorU2f`** instead of
  `twoFactorWebAuthn`/`twoFactorYubiKey` (`get_webauthn` already uses the correct one —
  inconsistent). Ours: [webauthn.rs:255](src/api/core/two_factor/webauthn.rs#L255),
  [yubikey.rs:95](src/api/core/two_factor/yubikey.rs#L95). **dani: yes** (same strings).
- **[LOW] T8 — `send-email-login` missing `AuthRequestId`/`SsoEmail2FaSessionToken`.** Only
  master-password auth; can't send OTP during passwordless/SSO/device-approval login. Ours:
  [email.rs:21](src/api/core/two_factor/email.rs#L21). **dani: no**.
- **[LOW] T9 — `get-webauthn-challenge` not wrapped as `{object,options}`.** Returns a flat
  challenge; BW wraps in `{object:"twoFactorWebAuthnChallenge", options}`. Matches pinned
  web-vault. Ours: [webauthn.rs:122](src/api/core/two_factor/webauthn.rs#L122). **dani: yes**.

---

## Events + Notifications / Push + Sync

- **[HIGH] ✅ E1 — `/events/collect` 400s the whole batch on any unknown EventType.**
  *(fixed 2026-07-24: added the missing cipher client events 1118–1132, and gave the collect
  endpoint a lenient `lenient_event_type` deserializer that maps unrecognized values to
  `Unknown` and skips them per-event so the rest of the batch still records. Test:
  `events::tests::collect_tolerates_unknown_event_type`.)* Enum stops
  at `1117`; BW defines client cipher events `1118–1132` (toggled TOTP seed, copied bank
  account / license / passport / SWIFT / IBAN / national-id, and toggle-visible pairs). A
  single unknown discriminant fails the entire array via `serde_repr`; modern clients silently
  lose org event-log entries. Ours: [event.rs:59](src/db/models/event.rs#L59),
  [events.rs:120](src/api/core/events.rs#L120). **dani: no** (both stop at 1117).
- **[MED] ◐ E2 — EventType stale vs dani.** Missing `1010` (device-approval requested), `1505`,
  `1513–1516` (org-user auth-request approved/rejected, deleted, left). Unknown DB values
  render as `type:0` (blank rows). Ours: [event.rs:64](src/db/models/event.rs#L64). **dani: yes**.
  *(enum part fixed 2026-07-24: all these variants added. The related `organizationUserId`
  issue (E4) is separate and still open — it needs a membership-id column.)*
- **[MED] E3 — `UpdateType`/PushType truncated at 16.** Missing 17–27, notably `Notification=20`
  / `NotificationStatus=21` (notification center), `RefreshSecurityTasks=22`, `PolicyChanged=25`,
  `SyncOrganizations=17`. Clients get no live pushes for these; only picked up on next full
  sync. Ours: [notifications/mod.rs:560](src/api/notifications/mod.rs#L560). **dani: partial**
  (documents 17–22 as commented placeholders; neither implements).
- **[MED] E4 — Event `organizationUserId` returns the user UUID, not the membership id.** Our
  `Event` has no membership column, so `userId` and `organizationUserId` are the same value;
  member-scoped log filtering mismatches. Ours: [event.rs:181](src/db/models/event.rs#L181).
  **dani: yes** (stores a distinct `org_user_uuid`).
- **[LOW] E5 — Event items omit `object:"event"` and optional ids** (`installationId`,
  `systemUser`, `domainName`, `sendId`, `secretId`, …). List wrapper sets `object:"list"` but
  items lack per-item `object`. Ours: [event.rs:171](src/db/models/event.rs#L171). **dani: no**.
- **[LOW] E6 — Sync envelope missing `policiesNew`.** BW added it (Confirmed **or** Accepted
  status; new clients prefer it, fall back to `policies`). Accepted-not-confirmed members may
  miss policies. (`unofficialServer:true` is a correct vaultwarden extension.) Ours:
  [ciphers.rs:142](src/api/core/ciphers.rs#L142). **dani: no**.
- **[LOW] E7 — Notification-center REST endpoints absent.** No `GET /notifications` or
  mark-read/delete; combined with E3 the whole feature is missing (config doc still advertises
  a `notifications` URL). Ours: [notifications/mod.rs:107](src/api/notifications/mod.rs#L107).
  **dani: no**.
- **[LOW] E8 — Logout push payload `{userId,date}` vs BW `{userId, reason?}`.** Inert today
  (clients re-auth on userId); forward-compat gap on logout-reason. Ours:
  [push/mod.rs:201](src/push/mod.rs#L201). **dani: partial** (same `{userId,date}`).

> Correct & confirmed: SignalR envelope shape, auth-request push types 15/16 + payloads, sync
> `userDecryption.masterPasswordUnlock` KDF block (salt = email). The anonymous-hub
> `AuthRequestResponseRecieved` misspelling intentionally matches Bitwarden/clients.

---

## Suggested triage order

1. **Typo bugs B1–B7** — trivial, self-contained, several are outright breakage (`od`, `pbject`,
   `member_external_ids`, attachment PascalCase, cipher-type panic).
2. **Lenient inbound enums** (theme 1) — one pattern kills the worst failure mode across C1,
   E1, O2, O8, T3: a modern client value no longer 400s the whole request.
3. **Port stale-vs-dani wins** — C2 (cipher permissions), A1/A2/A3 (key-rotation, register,
   CLI token), T1/T2 (Duo Universal), E2/E4 (event types + org-user id). dani has the code.
4. **Flexible-collections `manage`** (O1) — highest-value but needs a migration + query work.
5. **New-vs-both-behind-Bitwarden** items (policiesNew, notification center, v2 credential
   bodies, userVerificationToken) — genuinely new work; prioritize by client version targets.
