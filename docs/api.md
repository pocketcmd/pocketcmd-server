# PocketCmd Server HTTP API (v1.0)

This is the complete wire contract of the standing server, derived from the
route table in `internal/server/server.go` and the handlers it registers.
The executable authority for the auth posture of every route is
`internal/server/endpoint_matrix_test.go`.

## Conventions

- **Base URL:** `https://<host>:<port>` (default port 8767). TLS 1.3 only; the
  server certificate is self-signed and pinned by fingerprint at pairing time.
- **Bodies** are JSON (`Content-Type: application/json`). Fields marked `?`
  are optional.
- **Errors** are always `{"error": "<code>"}` with a status code. Codes are
  stable snake_case identifiers. Only `api_version_mismatch` carries an
  extra field (`server_api_version`).
- **List fields are always arrays, never `null`.** A response field that is
  documented as a list (`records`, `accepted`, `rejected`, `devices`,
  `members`, `metrics`, `points`, `entries`, `hosts`, `keys`,
  `fingerprints`, `ssh_host_keys`, and the top-level arrays of the user,
  device and invite listings) is `[]` when nothing matches.
- **Timestamps:** RFC 3339 strings unless a field is documented as epoch
  milliseconds (`updated_at`, `server_updated`, `timestamp`, `expires_at` on
  push registrations).
- **Rate limiting:** 60 requests per minute per authenticated device, or per
  client IP on the public routes; exceeding it is `429 rate_limited`.
  `/api/cert/challenge` additionally allows 10 per minute per public key.
- **Body caps:** 64 KiB on every JSON endpoint except `POST /api/sync/push`
  (10 MiB, 1 MiB per record field, 10 000 records), `POST /api/sync/pull`
  (1 MiB, 10 000 ids), and `POST /api/cert/challenge` (16 KiB). An
  over-cap body is `400 invalid_body` (sync: `413 payload_too_large`).

### API version header

Every request to `/api/*` **except** `GET /api/health` and
`GET /api/capabilities` must carry

```
X-PocketCmd-Api-Version: 1.0
```

Only the major is compared: `1`, `1.0` and `1.7` all pass a `1.0` server. A
missing value, or one with another major, is rejected before authentication
and rate limiting:

```
400 {"error":"api_version_mismatch","server_api_version":"1.0"}
```

The value is the `APIVersion` constant in `internal/server/server.go`
(`internal/server.APIVersionHeader` names the header). Read it from
`GET /api/capabilities` first; that route tolerates the header but does not
require it. On a mismatch the client compares majors to tell which side is
behind: a lower server major means the server needs updating, a higher one
means the client does.

`APIVersion` is always `"<major>.0"`, where major is the server's own major
version: every `v1.x.y` release speaks `1.0`. A wire change that breaks either
side bumps both to the next major. Within a major, changes are additive in
both directions: clients ignore fields they do not know, and a client that
relies on something a later minor added checks the server's `version` from
`GET /api/capabilities` first.
for the release order this relies on.

### Authentication tiers

| Tier | Meaning |
|------|---------|
| **public** | No credentials. Rate-limited by client IP. |
| **mTLS** | TLS client certificate of a registered, active device whose owning user is active; the certificate must have been issued by this server and be inside its lifetime + 10 min grace. Failures: `401 client_cert_required`, `403 device_not_registered`, `401 client_cert_expired`, `401 client_cert_invalid`. |
| **authed** | mTLS **plus** `Authorization: Bearer <session JWT>` from `POST /api/session`. The token must be ES256, carry `exp`, and its `cnf.x5t#S256` must equal the presented certificate's SHA-256 fingerprint. Failures add `401 authorization_required`, `401 invalid_token`, and `403 forbidden` (device or its user no longer active). |
| **member / admin / owner / grant** | Authed, plus the role or permission grant named on the route. Role failures are `403 forbidden`; a missing grant is `403 permission_required`; owner-only routes answer `403 owner_required`. |

Roles: `member`, `admin`; exactly one admin is the **owner** (`owner: true`).
The owner implicitly holds every permission grant. Admins implicitly hold
every grant except the owner-granted `metrics.commands.create`, which an admin
or a member holds only when the owner granted it (it approves commands that
run on the host). Members hold the grants in their `permissions` map (keys:
`metrics.commands.create`,
`metrics.commands.update`, `metrics.commands.delete`, `metrics.commands.read`,
`metrics.read`, `alerts.create`, `alerts.update`, `alerts.delete`,
`alerts.read`, `sshkeys.sync`, `users.manage`, `invites.manage`,
`invites.device`). New members start with `metrics.commands.read`,
`metrics.read`, `alerts.read`, `sshkeys.sync`, `invites.device`.

### Length caps

Enforced server-side with a `400`; values are never truncated. Lengths are in
Unicode code points (runes).

| Field | Max | Error | Where |
|-------|-----|-------|-------|
| `display_name` | 64 | `display_name_too_long` | `POST /api/pair` (bootstrap, new-user invite), `PATCH /api/users/{id}` |
| `device_name`, `device_label` | 128 | `name_too_long` | `POST /api/pair`, `PATCH /api/devices/{id}` |
| invite `label` | 128 | `label_too_long` | `POST /api/invites` |

### Device status values

Every device object carries `"status"` and `"removed_at"`:

| `status` | Meaning | `removed_at` |
|----------|---------|--------------|
| `active` | Paired and authenticating. | `null` |
| `revoked` | Removed by someone else (admin, the user from another device, the CLI, or a user-removal cascade). Permanent; the key can never pair again. | RFC 3339 |
| `left` | The device unpaired itself. Blocked like `revoked`, but the same key may re-join through a new invite. | RFC 3339 |

---

## Public routes

### `GET /api/health` (public, no version header required)

Liveness probe. Pings `state.db`.

- `200 {"status":"ok","checks":{"devices":"ok","tls":"ok","db":"ok"}}`
  (`devices` is present once the registry is wired; `tls` is
  `"not configured"` on a plain-HTTP test server.)
- `503 {"status":"degraded","error":"db_unavailable","checks":{...}}` when
  the database ping fails.

### `GET /api/capabilities` (public, no version header required)

```
200 {"version":"<binary version>","api_version":"1.0"}
```

Exactly these two fields. There is no feature map and no vault-key
generation field: per-device vault keys are the only scheme.

### `GET /api/config` (public)

```
200 {"pollIntervalMs": 2000}
```

### `POST /api/pair` (public)

Pairs a device. Body:

```json
{
  "device_public_key": "<PEM, ECDSA P-256>",
  "device_name": "string",
  "device_label": "string?",
  "csr": "<PEM certificate request signed by the device key>",
  "credential": {"kind": "bootstrap" | "invite", "token": "<pairing token | invite code>"},
  "display_name": "string?"
}
```

- `bootstrap`: the one-time token from the first-run QR. Only works while
  no active user exists; creates the owner (role `admin`, `owner: true`).
  `display_name` required.
- `invite`: an invite code. A new-user invite requires `display_name` and
  creates the user with the invite's role; a second-device invite
  (`target_user_id` set at creation) binds the device to that user and
  ignores `display_name`.

The CSR's public key must equal `device_public_key` (proof of possession).
The issued certificate's subject is always `CN=<device_id>`; the CSR's own
subject is ignored. A key that is already registered and active re-pairs
(fresh certificate for its existing user; the token/invite is not required
to be valid for the bootstrap path, and a second-device invite for the same
user is consumed).

```
200 {
  "device_id": "<16 hex>", "client_cert": "<PEM>", "expires_at": "<RFC3339>",
  "server_url": "https://host:port", "server_fingerprint": "<sha256 hex>",
  "hostname": "string", "user_id": "...", "user_display_name": "...",
  "user_role": "admin"|"member", "user_owner": bool,
  "ssh_host_keys": ["<unpadded base64 sha256>", ...]?
}
```

Errors: `400 invalid_body`, `400 credential_kind_required`,
`400 invalid_public_key` (malformed or not ECDSA P-256), `400 invalid_csr`,
`400 csr_key_mismatch`, `400 name_too_long`, `400 display_name_required`,
`400 display_name_too_long`, `401 invalid_pairing_token`,
`403 bootstrap_not_allowed`, `403 device_revoked`, `403 device_left`
(bootstrap with a key that left; redeem an invite instead),
`403 device_pin_mismatch`, `403 target_user_not_found`,
`404 invite_not_found`, `409 invite_consumed`, `409 device_already_paired`
(active key redeeming an invite meant for another user), `410 invite_revoked`,
`410 invite_expired`, `429 rate_limited`, `405 method_not_allowed`,
`500 store_error`, `500 registration_failed`, `500 cert_signing_failed`.

### `POST /api/cert/challenge` (public)

Issues a single-use nonce for expired-certificate recovery. Body
`{"public_key": "<PEM>"}`.

```
200 {"nonce": "<64 hex>", "expires_at": "<RFC3339Nano, +30 s>"}
```

The response is identical for every syntactically valid key. The nonce is
stored (and therefore usable) only when the key belongs to an active
device of an active user; otherwise it is a decoy and the renewal that
follows fails with `401 unauthorized`. See [security-internals.md](security-internals.md#certificate-renewal),
"No key-liveness oracle".

Errors: `400 public_key_required`, `400 invalid_public_key`,
`429 rate_limited` (per IP and per key), `500 server_not_configured`,
`500 internal_error`.

### `POST /api/cert/renew` (public; authenticates itself)

Two paths, chosen by the body:

- **mTLS path**: `{"csr": "<PEM>"}` over a connection with a valid client
  certificate (inside lifetime + grace). The CSR key must equal the peer
  certificate's key.
- **Challenge path**: `{"signed_challenge": "<base64 ASN.1 ECDSA signature>",
  "public_key": "<PEM>", "csr": "<PEM>", "nonce": "<from /challenge>"}`, no
  client certificate needed. The signature is over
  `SHA-256("<nonce>:<server_fingerprint>")`. Body wins: when
  `signed_challenge` is present the challenge path runs even over mTLS.

```
200 {"cert": "<PEM, 30 min>", "expires_at": "<RFC3339>"}
```

Errors: `400 invalid_body`, `400 csr_required` (mTLS path),
`400 missing_fields` (challenge path), `400 invalid_csr`,
`400 csr_key_mismatch`, `401 unauthorized` (no client certificate on the mTLS
path; unknown, expired, or spent nonce or bad signature on the challenge
path), `401 client_cert_expired`, `401 client_cert_invalid`, `403 forbidden`
(device unknown, revoked, left, or its user revoked),
`500 invalid_certificate`, `500 cert_signing_failed`.

### `POST /api/session` (mTLS)

Issues a session JWT bound to the presented certificate. Empty body.

```
200 {"token": "<JWT>", "expires_in": 300}
```

Errors: `403 client_cert_required`, `403 device_not_registered`,
`401 client_cert_expired`, `401 client_cert_invalid`, `403 forbidden` (device
or its owning user not active), `500 invalid_certificate`,
`500 internal_error`.

---

## Authenticated routes

### `GET /api/host-keys` (authed)

```
200 {"fingerprints": ["<unpadded base64 sha256>", ...]}
```

The host machine's SSH host-key fingerprints: the SHA-256 digest of each
public key as unpadded base64, the value OpenSSH prints after `SHA256:`,
without that prefix (`[]` when the host has none readable under
`/etc/ssh`). `ssh_host_keys` in the pair response uses the same form.

### `POST /api/push/register` (authed)

Registers (or replaces) the calling device's push credentials.

```json
{"device_id": "string?", "device_token": "string", "platform": "string",
 "signed_token": "string", "expires_at": <epoch ms>}
```

`device_id`, when present, must equal the caller's device id.
`200 {"status":"ok"}`. Registered means notified: the server pushes to
every registration it holds, and a device registers only after its user
allowed notifications in the app; there is no server-side switch. The
relay itself is fixed: the app registers its device token with the hosted
relay, and the server sends through that same relay. Errors:
`400 invalid_body`, `400 missing_fields`, `403 forbidden`,
`403 device_id_mismatch`, `503 push_unavailable` (this server keeps no push
registrations at all, i.e. the ephemeral `pcmd sync` server), `500 store_error`.

### `GET /api/ssh-configs` (admin; one-shot server only)

Not registered on the standing server; served only by the ephemeral server
`pcmd sync` starts, and at most once there (`409 already_fetched`).

```
200 {"hosts":[{"name","hostname","username"?,"port","key_ref"?}],
     "keys":[{"path","content","encrypted"}]}
```

---

## Sync

Records are opaque to the server except for the routing fields below.
Supported `type` values: `task`, `ssh_key`, `task_group`, `task_tag`,
`sftp_bookmark`, `workspace`, `snippet`, `snippet_folder`, `command_template`,
`layout_config`, `port_forward_rule`, `alert_config`, `settings`,
`monitoring_config`, `dashboard`, `secret_item`, `vault_wrap`, `vault_meta`,
`device_vault_key`, `enroll_request`, `device_revocation`, `files_enrollment`.

Record object:

```json
{"id": "[a-zA-Z0-9:_-]+", "type": "...", "schema_version": 1,
 "updated_at": <epoch ms>, "device_id": "<server-stamped>", "deleted": false,
 "data": <any JSON>, "credentials": "string?", "user_id": "<server-stamped>",
 "vault_id": "string?"}
```

`vault_id` empty or `"personal"` is the caller's private scope; any other
value is a team vault governed by the vault ACL (`view` to read, `edit` to
write records, `manage` to write `vault_wrap` / `vault_meta`).
`monitoring_config` is a team-wide singleton (`id` must be
`"monitoring_config"`). `device_vault_key` and `device_revocation` are
readable by every member; writing a device-scoped record (id = a device id)
requires owning that device or being an admin. `device_revocation` records
are permanent and cannot be tombstoned.

A `device_vault_key` record's `data` is the device's published key material:

```json
{"device_id": "<device id>", "dvk_pub": "<base64>", "kind": "p256" | "x25519",
 "mtls_spki": "<base64 DER>", "backing": "hardware" | "software",
 "sig": "<base64>", "label": "string?", "attestation": <JSON object>?,
 "created_at": <epoch ms>, "version": 2}
```

The server stores it verbatim and serves it through `GET /api/vault/pubkeys`
under the same field names.

### `GET /api/sync/manifest` (authed)

```
200 {"version": 1, "last_updated": <epoch ms>,
     "records": [{"id","type","updated_at","deleted"}]}
```

Lists every record visible to the caller (own records, team-visible types,
team-vault records the caller holds at least `view` on, and `vault_wrap`
records addressed to the caller's devices).

### `POST /api/sync/pull` (authed)

Body `{"ids": ["..."]}` (≤ 10 000). `200 {"records": [<record>...]}`, only
the visible matches; an id may match one record per type. Errors:
`400 invalid_body`, `413 too_many_ids`, `500 store_error`.

### `POST /api/sync/push` (authed)

Body `{"records": [<record>...]}` (≤ 10 000 records, ≤ 1 MiB each for `data`
and `credentials`). The server overwrites `device_id` with the calling
device's id and `user_id` with the caller's user id; client values are
ignored. Last-writer-wins on `updated_at`; `0` is replaced by the server
time.

```
200 {"accepted": ["id", ...],
     "rejected": [{"id": "...", "reason": "<reason>"}, ...],
     "server_updated": <epoch ms>}
```

Both arrays are always present (possibly empty). Errors: `400 invalid_body`,
`413 payload_too_large`, `413 too_many_records`, `413 record_too_large`,
`500 store_error`.

#### Push rejection reasons

Defined as the `Reject*` constants in `internal/datasync/store.go`.
**Transient** reasons may succeed on a later retry without any client-side
change; every other reason is **permanent** for the record as pushed.

| Reason | Kind | Meaning |
|--------|------|---------|
| `superseded` | transient | The server holds a newer or equal `updated_at`; pull it and re-apply. |
| `monitoring_apply_failed` | transient | The monitoring config could not be applied (storage error); retry. |
| `write_failed` | transient | Storage error writing the record; retry. |
| `invalid_id_or_type` | permanent | `id` has characters outside `[a-zA-Z0-9:_-]`, or `type` is unknown. |
| `invalid_vault_record_id` | permanent | A `vault_wrap` id is not `<vaultId>:<deviceId>` / a `vault_meta` id is empty. |
| `vault_id_mismatch` | permanent | `vault_id` contradicts the vault encoded in the record id. |
| `vault_acl_denied` | permanent | Caller lacks `edit` (records) or `manage` (`vault_wrap`, `vault_meta`) on the team vault. |
| `vault_moved_on_live_record` | permanent | A live record may not change `vault_id`; tombstone and re-create. |
| `device_scope_denied` | permanent | Device-scoped record for a device the caller neither owns nor administers. |
| `cross_user_owner` | permanent | The `(type, id)` already exists under another user. |
| `policy_denied` | permanent | A permission grant is missing (e.g. `sshkeys.sync`, or adding or changing a monitoring command without `metrics.commands.create`). |
| `monitoring_unsupported` | permanent | `monitoring_config` under any id but `"monitoring_config"`, or no monitoring store. |
| `revocation_delete_forbidden` | permanent | `device_revocation` records are never tombstoned. |
| `future_timestamp` | permanent | `updated_at` is more than 5 minutes ahead of the server clock. |

---

## Metrics

### `GET /api/metrics/available` (grant `metrics.read`)

```
200 {"metrics": [{"id": "custom:<request-id>", "label": "Containers", "unit": ""}, ...]}
```

Exactly the approved custom commands in the monitoring config, in config order.
There is no built-in catalog: a server nobody has added a command to answers
`{"metrics": []}`.

```
```

### `GET /api/metrics/latest` (grant `metrics.read`)

```
200 {"metrics": {"<id>": {"metric_id", "value", "timestamp", "unit"}, ...}}
```

Error: `500 store_error`.

### `GET /api/metrics/series?metric=<id>&range=<r>` (grant `metrics.read`)

`range` ∈ `1m`, `1h` (raw), `6h` (1-min buckets), `24h` (5-min), `7d`
(1-h), `30d` (6-h), `1y` (1-day).

```
200 {"metric": "<id>", "unit": "...", "points": [{"metric_id","value","timestamp","unit"}]}
```

Errors: `400 missing_params`, `400 invalid_range`, `500 store_error`.

### Metric-command requests

A request proposes a custom host command; nothing runs until a holder of
`metrics.commands.create` (the owner, or an admin or member the owner granted
it) approves. Request object:

```json
{"id": "req-<hex>", "label": "...", "command": "...", "interval_override": <s>?,
 "requested_by": "<user id>", "created_at": "<RFC3339>",
 "status": "pending"|"approved"|"declined", "decided_by": "...", "decided_at": "..."}
```

| Route | Auth | Result |
|-------|------|--------|
| `POST /api/metrics/requests` body `{"label","command","interval_override"?}` | member | `200 <request>`; `400 invalid_body`, `400 invalid_request` (empty/over-long fields, invalid command, interval outside 5–21600 s) |
| `GET /api/metrics/requests` | member | `200 [<request>...]`; holders of `metrics.commands.create` or `metrics.commands.delete` (every admin) see all, others their own |
| `POST /api/metrics/requests/{id}/approve` | grant `metrics.commands.create` | `200 <request>`; `403 permission_required`, `404 request_not_found`, `409 already_decided`, `500 config_update_failed` |
| `POST /api/metrics/requests/{id}/decline` | grant `metrics.commands.create` | `200 <request>`; `403 permission_required`, `404 request_not_found`, `409 already_decided` |
| `DELETE /api/metrics/requests/{id}` | grant `metrics.commands.delete`, or the requester while pending | `200 {"status":"ok"}` (an approved request's command is removed); `403 permission_required`, `404 request_not_found`, `500 config_update_failed` |

Decided requests older than 30 days are pruned automatically (approved ones
only once their command no longer exists).

---

## Team

### Invites

Invite summary (listing):

```json
{"code": "<full code, creator only>", "code_prefix": "<8 chars>", "role": "admin"|"member",
 "expires_at": "<RFC3339>", "target_user_id": "...", "label": "...", "has_pin": bool,
 "created_by": "<user id>", "created_by_name": "..."}
```

#### `POST /api/invites` (member; rules below)

```json
{"role": "admin"|"member", "expires_in_seconds": <int, ≤ 2592000>,
 "target_user_id": "string?", "pinned_fingerprint": "string?", "label": "string?"}
```

- New-user invite (`target_user_id` absent): admin or grant `invites.manage`;
  `role: "admin"` is owner-only.
- Second-device invite for yourself: grant `invites.device`; for anyone else:
  owner-only. The role is inherited from the target.
- `expires_in_seconds` ≤ 0 defaults to 86400; larger than 30 days is clamped.

```
200 {"code": "<16 chars>", "expires_at": "<RFC3339>", "qr_url": "pocketcmd://invite?host=..&port=..&code=..#<server fp>"}
```

Errors: `400 invalid_body`, `400 label_too_long`, `400 invalid_invite_params`,
`403 forbidden`, `403 owner_required`, `404 target_user_not_found`,
`500 store_error`.

#### `GET /api/invites` (member)

`200 [<invite summary>...]`: active invites; admins and `invites.manage`
holders see all, others only the ones they created. The full `code` appears
only on invites the caller created.

#### `DELETE /api/invites/{code}` (member)

`{code}` is the full code or an unambiguous prefix of 8–16 characters from
the code alphabet (`a-z`, `2-7`). Admins and `invites.manage` holders may
revoke any invite, others only their own. `200 {"status":"ok"}`
(idempotent). Errors: `400 invalid_code`, `403 forbidden`,
`404 invite_not_found`, `409 ambiguous_prefix`, `409 invite_already_consumed`,
`500 store_error`.

### Users

User summary:

```json
{"user_id": "...", "display_name": "...", "role": "admin"|"member", "owner": true?,
 "device_count": <active devices>, "permissions": {"<key>": {"granted": bool, "metrics": [..]?}}?}
```

`permissions` is included for admins and for the user themself.

#### `GET /api/users` (member)

`200 [<user summary>...]`: active users.

#### `PATCH /api/users/{id}` (member; rules below)

```json
{"display_name": "string?", "role": "admin"|"member"?, "permissions": {<set>}?}
```

- `display_name`: self always; member targets need admin or `users.manage`;
  admin targets are owner-only. ≤ 64 runes.
- `role`: owner-only; the owner is immutable; the last admin cannot be
  demoted.
- `permissions`: admin-only, keys must be known, never on the owner
  (`409 owner_immutable`). Evaluated against the role the request leaves the
  target with:
  - a member target's set is replaced by the request;
  - an admin target is owner-only and takes owner-granted keys
    (`metrics.commands.create`) only, merged into its stored set; any other
    key is `400 target_not_member` (admins hold it already).
  - Granting or revoking `metrics.commands.create` needs the owner
    (`403 owner_required`); an admin may resend it with its current value,
    and the stored grant stays as the owner set it. When an admin's request
    omits it, the stored value is kept, so an admin editing a member's other
    grants never drops the owner's grant. The owner's request is
    authoritative: omitting it (or sending `{}`) revokes it, on members and
    admins alike.

All guards run before anything is applied. The permission set is written
only if the target's stored set is still the one the request was evaluated
against; a concurrent edit of the same user answers `409 permissions_changed`
(reload the member and retry). `200 {"status":"ok"}`. Errors:
`400 invalid_body`, `400 no_fields`, `400 display_name_required`,
`400 display_name_too_long`, `400 invalid_role`, `400 invalid_permissions`
(unknown key), `400 target_not_member`, `403 forbidden`, `403 owner_required`,
`404 user_not_found`, `409 owner_immutable`, `409 last_admin`,
`409 permissions_changed`, `500 store_error`.

#### `POST /api/users/{id}/transfer-ownership` (owner)

Empty body. The target becomes owner + admin; the caller stays an admin
without the owner flag, and keeps `metrics.commands.create` only if it was
granted explicitly. Atomic (one transaction, exactly one owner). Every
owner-derived privilege (owner-only routes, implicit `manage` on every vault,
admin management) follows the flag immediately.

```
200 {"status":"ok","new_owner":"<id>","previous_owner":"<id>"}
```

Errors: `400 self_transfer`, `403 owner_required`, `404 user_not_found`,
`409 target_not_active`, `500 store_error`. Audit event: `owner_transferred`.

#### `DELETE /api/users/{id}[?purge_data=true]` (member; rules below)

Revokes the user and cascades: every active device is revoked (the caller's
own device *leaves* when a member removes themself), vault ACL rows are
dropped and key wraps tombstoned, outstanding invites targeting or created by
the user are revoked. Self-removal is always allowed; member targets need
admin or `users.manage`; admin targets are owner-only. The owner and the last
admin cannot be removed. With `purge_data=true` the user's personal-scope
sync records are hard-deleted (tombstoned with content cleared) and personal
identifiers scrubbed.

```
200 {"status":"ok"}                       // or
200 {"status":"ok","purged_records":<n>}  // with purge_data=true
```

Errors: `403 forbidden`, `403 owner_required`, `404 user_not_found`,
`409 owner_immutable`, `409 last_admin`, `500 store_error`,
`500 purge_failed`, `500 revoke_incomplete` (the user is revoked but at least
one device could not be cut off; see the server log).

### Devices

Device object:

```json
{"device_id": "<16 hex>", "device_name": "...", "device_label": "..."?,
 "user_id": "...", "display_name": "<owner's name>"?, "status": "active"|"revoked"|"left",
 "paired_at": "<RFC3339>", "removed_at": "<RFC3339>"|null, "last_seen_at": "..."?, "self": true?}
```

#### `GET /api/devices[?include=all]` (member)

`200 [<device>...]`. Admins see every device, members only their own. By
default only `active` devices are listed; `include=all` adds `revoked` and
`left` ones. The caller's device is flagged `self` and sorted first.

#### `PATCH /api/devices/{id}` (member; rules below)

`{id}` is a device id or the literal `self`. Body
`{"device_name": "string?", "device_label": "string?"}` with at least one
field, each ≤ 128 runes. Allowed for the calling device itself and for
callers with the admin role or the `users.manage` grant.

`200 <device object>`. Errors: `400 invalid_body`, `400 no_fields`,
`400 name_too_long`, `403 forbidden`, `404 device_not_found`,
`500 store_error`. Audit event: `device_renamed`.

#### `DELETE /api/devices/{id}` (member; rules below)

`{id}` is a device id or `self`. Own devices: always allowed, except the
owner's last active device. Member users' devices: admin or `users.manage`.
Admin users' devices: owner-only. The calling device itself *leaves*; any
other device is *revoked* permanently. Idempotent.

`200 {"status":"ok"}`. Errors: `403 forbidden`, `403 owner_required`,
`404 device_not_found`, `409 last_device`, `500 store_error`.

---

## Vaults

Vault ids match `^[a-zA-Z0-9_-]{1,64}$` and may not be `personal`. Levels:
`view` < `edit` < `manage`. The owner implicitly holds `manage` on every
vault.

### `GET /api/vault/pubkeys` (member)

```
200 {"devices": [{"device_id","user_id","display_name","label"?,"dvk_pub","kind"?,
                  "mtls_spki"?,"sig"?,"backing"?,"attestation"?,"created_at"?,"updated_at"}]}
```

One entry per active device (of an active user) that published a
`device_vault_key` record. The entry carries the record's fields under the
same names the device wrote them (`dvk_pub`, `kind`, `mtls_spki`, `sig`,
`backing`, `created_at`, `label`); `attestation` is the record's attestation
JSON object passed through verbatim, omitted when the record has none. A
record whose `dvk_pub` is empty is not listed. `user_id`, `display_name` and
`updated_at` come from the registry and the sync row. Error:
`500 store_error`.

### `GET /api/vault/members?vault_id=<id>` (member with ≥ `view`)

`200 {"members": [{"user_id","level"}]}`. Errors: `400 invalid_vault_id`,
`403 forbidden`, `500 store_error`.

### `POST /api/vault/create` (admin or owner)

Body `{"vault_id": "<id>"}`. Creates the vault with the caller as its first
`manage` holder, atomically. `200 {"vault_id": "<id>"}`. Errors:
`400 invalid_vault_id`, `403 forbidden`, `403 owner_or_admin_required`,
`409 vault_exists`, `500 store_error`.

### `POST /api/vault/grant` (member with `manage` on the vault)

Body `{"vault_id": "...", "user_id": "...", "level": "view"|"edit"|"manage"}`.
Upserts the target's level. `204`. Errors: `400 invalid_request`,
`403 forbidden`, `403 manage_required`, `404 user_not_found` (target missing
or revoked), `409 last_manager` (would demote the vault's only `manage`
holder), `500 store_error`.

### `POST /api/vault/revoke` (member with `manage` on the vault)

Body `{"vault_id": "...", "user_id": "..."}`. Drops the target's ACL row and
tombstones every `vault_wrap` addressed to their devices. `204`. Errors:
`400 invalid_request`, `403 forbidden`, `403 manage_required`,
`409 cannot_revoke_owner` (the owner's access is a role, not a grant),
`409 last_manager` (the vault's only `manage` holder), `500 store_error`.

---

## Server administration

### `GET /api/server/status` (admin)

```
200 {"version","started_at","uptime_seconds","state_dir_bytes","active_devices","total_devices","active_users"}
```

### `GET /api/server/config` (admin)

`200 {"service_mode": "background"|"foreground"}`. Nothing in it is
writable over the API (there is no `PATCH`): the service mode is chosen on
the first run, and push notifications have no server-side switch; every
device whose user allowed notifications in the app is notified.
Error: `500 config_unreadable` (config.json written by a newer binary or
malformed).

### `GET /api/audit?limit=&offset=&from=&to=` (owner)

Newest-first tail of `audit.log`. `limit` 1–200 (default 50), `offset`
counts already-consumed entries from the newest end; `from`/`to` are RFC 3339
bounds on each entry's `time` (years 2000–3000).

`200 {"entries": [<audit record>...], "total": <n>}`. Errors:
`400 invalid_time`, `400 invalid_time_range`, `403 owner_required`.

### `GET /api/logs?limit=&before_id=&user_id=&from=&to=` (owner)

Newest-first tail of the request/event log (last ~10 000 entries).
Cursor-paged: pass the response's `next_before_id` as `before_id` for the
next older page. `user_id` filters to one member; `from`/`to` as for
`/api/audit`.

`200 {"entries": [{"id": <row id>, ...slog fields}], "total": <n>, "next_before_id": <id>?}`.
Errors: `400 invalid_time`, `400 invalid_time_range`, `403 owner_required`.

---

## Audit events

Written to `~/.pocketcmd/audit.log` (served by `GET /api/audit`):
`user_created`, `user_renamed`, `role_changed`, `permission_changed`,
`user_revoked`, `user_revoke_incomplete`, `user_data_purge_requested`,
`user_data_purged`, `owner_transferred`, `device_registered`,
`device_reactivated`, `device_key_records_reset`, `device_renamed`,
`device_revoked`, `device_left`, `invite_created`, `invite_revoked`,
`invite_consumed`, `invite_pair_blocked_revoked_device`,
`invite_pair_blocked_already_paired`, `invite_pair_reused_registration`,
`bootstrap_pair_blocked_inactive_device`, `cert_challenge`, `cert_renew`,
`session_denied`, `user_resolve_denied`, `sync_write_denied`,
`vault_created`, `vault_granted`, `vault_revoked`, `metric_request_created`,
`metric_request_approved`, `metric_request_declined`,
`metric_request_deleted`, `server_config_changed`, `ssh_configs_export`.
