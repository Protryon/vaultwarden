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

> **Bundled web-vault:** as of 2026-07-25 the Dockerfile ships web-vault **v2026.6.2** (bumped
> from v2025.12.1 to reach parity with dani). Several findings below were rated "benign with the
> pinned web-vault" — that assumption is now weaker. The client-reachable un-ported surfaces to
> watch are **T5/T6** (2FA `userVerificationToken` setup + per-provider `DELETE`) and **T1/T2**
> (Duo Universal Prompt). Verify 2FA enable/disable in the bundled UI against v2026.6.2.

---

## Cross-cutting themes

1. **"v2 modernization" gaps.** Bitwarden reworked several flows into new routes + bodies;
   the fork still carries the pre-v2 shape. The remaining open ones are the **Duo Universal
   Prompt** (OIDC `AuthUrl`) and the **2FA `userVerificationToken`** setup flow. dani has
   already ported both.

---

## Ciphers + Folders

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
> pass through intact **as long as the enclosing `type` is accepted**.

---

## Accounts + Identity / Token

- **[LOW] A10 — 2FA challenge never emits OrganizationDuo (type 6).** Enum defines it
  ([two_factor.rs:44](src/db/models/two_factor.rs#L44)) but `json_err_twofactor` skips it.
  Blocked on the Duo Universal work (T1/T2): `OrganizationDuo` only reaches the challenge
  builder if org-level Duo enforcement exists (it doesn't here), and the current catch-all
  already skips it gracefully, matching dani. Ours:
  [identity/mod.rs:688](src/api/identity/mod.rs#L688). **dani: partial** (also a graceful skip).

> `password_login` ([identity/mod.rs:454](src/api/identity/mod.rs#L454)) and the shared
> `user_auth_response_fields` helper are the modernized template; the password, API-key,
> refresh, and SSO (`authorization_code`) grants all route through it.

---

## Organizations + Public

- **[MED] O3 — `to_json_user_details` missing member fields.** Omits `externalId`,
  `avatarColor`, `ssoBound`, `permissions`, `accessSecretsManager`, `hasMasterPassword`,
  `usesKeyConnector`, `managedByOrganization`/`claimedByOrganization`, `creationDate`,
  `revocationReason`; embedded `collections` lack `manage`. Ours:
  [organization.rs:375](src/db/models/organization.rs#L375). **dani: no** (dani emits most).
- **[MED] O4 — Collection response missing `type`, `manage`, `unmanaged`, real `externalId`.**
  `externalId` is hardcoded null (no DB column); `type` (shared/default-user), `manage`,
  `unmanaged` never emitted. Ours: [collection.rs:84](src/db/models/collection.rs#L84),
  [organizations.rs:346](src/api/core/organizations.rs#L346). **dani: partial** (real
  `externalId` + `manage`; no `type`).
- **[LOW] O7 — Public/directory-connector API largely unimplemented.** Only `ldap_import`
  exists; no public members/groups/collections/policies CRUD. Ours:
  [public.rs](src/api/core/public.rs). **dani: partial** (dani implements the full public API).
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

- **[HIGH] S2 — Send `emails` (email-restricted access) silently dropped.** `SendData` has no
  `emails` field; serde ignores it, so an email-restricted Send is created with **no**
  restriction (security-relevant — user thinks access is limited but it's public). dani at
  least hard-rejects with "not supported". Ours: [sends.rs:44](src/api/core/sends.rs#L44).
  **dani: partial** (rejects). Minimum bar: reject like dani.
- **[MED] S4 — `authType` missing from Send-access response.** Anonymous access payload can't
  advertise which challenge is required. Ours: [send.rs:191](src/db/models/send.rs#L191).
  **dani: no** (both omit).
- **[MED] S5 — Emergency-access takeover response missing `salt`.** BW returns grantor MP
  `salt` alongside kdf/`keyEncrypted` for the master-password-unlock flow. (Careful: our
  `User.salt` is a server hashing salt, not BW's email-derived MP salt.) Ours:
  [emergency_access.rs:525](src/api/core/emergency_access.rs#L525). **dani: no**.
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

1. **Port remaining stale-vs-dani wins** — T1/T2 (Duo Universal), E4 (event org-user id),
   S2 (reject email-restricted sends like dani), T7/T9. dani has the code.
2. **New-vs-both-behind-Bitwarden** items — `policiesNew` (E6), notification center (E3/E7),
   `userVerificationToken` + per-provider DELETE (T5/T6). Genuinely new work; prioritize by
   client version targets.
