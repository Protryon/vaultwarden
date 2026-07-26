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
- **LOW** — cosmetic / conformance / forward-compat; the client works without it.

Severities assume the web-vault the Dockerfile bundles, **v2026.6.2**.

**This file tracks pending work only.** Findings are removed once implemented — the code and
git history are the record of what was fixed, so an item's absence here means it is either done
or was never a gap. Line numbers are from the audit snapshot (2026-07-24) and drift as files
change — re-anchor before acting.

---

## Cross-cutting themes

1. **"v2 modernization" gaps.** Bitwarden reworked several flows into new routes + bodies; the
   fork still carries the pre-v2 shape in a couple of places. What's left is lower-stakes: the
   account key/credential v2 bodies (largely done) and the notification-center REST surface (E7).

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
  Blocked on the real gap: there is no org-level 2FA provider storage, so org-enforced Duo can't
  exist to be emitted. Harmless until then (the catch-all skips it gracefully, as dani does).
  Ours: [identity/mod.rs](src/api/identity/mod.rs). **dani: partial** (also a graceful skip).

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

- **[LOW] S3 — Email-restricted Sends unimplemented.** A non-blank `emails` is refused rather
  than silently dropped, so nothing is unsafe, but the feature itself — per-recipient emailed
  OTP, `emails` stored and round-tripped on the Send — doesn't exist. Ours:
  [sends.rs](src/api/core/sends.rs). **dani: no** (also refuses).
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

---

## Two-Factor

- **[LOW] T8 — `send-email-login` missing `AuthRequestId`/`SsoEmail2FaSessionToken`.** Only
  master-password auth; can't send OTP during passwordless/SSO/device-approval login. Ours:
  [email.rs:30](src/api/core/two_factor/email.rs#L30). **dani: no**.

---

## Events + Notifications / Push + Sync

- **[MED] E3 — `UpdateType`/PushType truncated at 16.** Missing 17–27, notably `Notification=20`
  / `NotificationStatus=21` (notification center), `RefreshSecurityTasks=22`, `PolicyChanged=25`,
  `SyncOrganizations=17`. Clients get no live pushes for these; only picked up on next full
  sync. Ours: [notifications/mod.rs:560](src/api/notifications/mod.rs#L560). **dani: partial**
  (documents 17–22 as commented placeholders; neither implements).
- **[LOW] E5 — Event items omit `object:"event"` and optional ids** (`installationId`,
  `systemUser`, `domainName`, `sendId`, `secretId`, …). List wrapper sets `object:"list"` but
  items lack per-item `object`. Ours: [event.rs:171](src/db/models/event.rs#L171). **dani: no**.
- **[LOW] E6 — Sync envelope missing `policiesNew`.** BW added it (Confirmed **or** Accepted
  status; new clients prefer it, fall back to `policies`). Accepted-not-confirmed members may
  miss policies. (`unofficialServer:true` is a correct vaultwarden extension.) Ours:
  [ciphers.rs:142](src/api/core/ciphers.rs#L142). **dani: no**.
- **[MED] E7 — Notification-center REST endpoints absent.** No `GET /notifications` or
  mark-read/delete; v2026.6.2 ships a notification-center UI, so it surfaces empty/erroring
  (compounded by E3, and the config doc still advertises a `notifications` URL). Ours:
  [notifications/mod.rs:107](src/api/notifications/mod.rs#L107). **dani: no**.
- **[LOW] E8 — Logout push payload `{userId,date}` vs BW `{userId, reason?}`.** Inert today
  (clients re-auth on userId); forward-compat gap on logout-reason. Ours:
  [push/mod.rs:201](src/push/mod.rs#L201). **dani: partial** (same `{userId,date}`).

---

## Suggested triage order

Last re-triaged 2026-07-26 for web-vault **v2026.6.2**.

1. **Visible feature/field gaps on the new client** — notification center (**E3/E7**), member/
   collection fields (**O3/O4**), sync `policiesNew` (**E6**, though the `policies` fallback
   still works).
2. **Remaining conformance/forward-compat** — the LOW two-factor/cipher/send/org/event items
   (**T8**, C5–C8, S3/S7–S11, O9/O10, E5/E8, A10). Batch as cleanup.
