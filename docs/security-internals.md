# Security internals

Protocol-level detail and the invariants a maintainer must not relax. The reader-facing model, threat model and reporting policy are in [SECURITY.md](../SECURITY.md); the wire contract of every route is in [api.md](api.md).

## Client-cert trust model

TLS is configured with `RequestClientCert`, not `RequireAndVerifyClientCert`, so the handshake performs no chain verification. `RequireAndVerifyClientCert` would break the unauthenticated recovery endpoints. Verification happens per request instead: the presented certificate's public key must match a registered active device, the certificate must have been issued by this server's key, and `now` must be within `[NotBefore, NotAfter + 10 min]`. The handshake proves possession of the private key. A certificate outside the window answers `401 client_cert_expired` (or `client_cert_invalid` when not issued by this server), and the only way back is the challenge path below. The 10-minute server grace is deliberately wider than the app's 5-minute renewal window so a phone whose clock trails the server still lands in standard renewal.

## Pairing

1. `pcmd` on the first run generates a one-time pairing token (32 hex chars, 60-second TTL) and prints a QR code: `pocketcmd://<ip>:<port>/<pairing_token>#<server_fingerprint>`. The first run waits up to 5 minutes and replaces the token and QR each time it expires; only one token is active at a time. Later devices and members join through `pcmd invite` or an invite from the app.
2. The device connects to `/api/pair` over HTTPS, pinning the fingerprint from the QR, and sends the pairing token (or invite code), its public key, a CSR for that key, and a device name.
3. The server validates the token (one-time, not expired) **and that the CSR's public key equals the sent device public key**. A self-signed CSR whose key matches proves possession of the private key.
4. The server signs the CSR into a 30-minute client cert, stores the device identity, and responds with the cert PEM, server URL, server fingerprint and hostname.

**Proof of possession.** The CSR-key/device-key match gates *every* credential-issuing path, including the idempotent re-pair of an already-registered key. Without it, knowing a device's public key (never a secret) would be enough to obtain a signed cert and leak that device's user identity. Do not relax this check.

**Idempotent pairing.** A pairing request whose public key is already registered **and active** gets its client cert re-issued without consuming a token. This covers partial failures where the client never received the response. A registered key that is not active never pairs through the bootstrap token (`device_revoked` / `device_left`), and through an invite only when it `left`.

**Re-pairing after `pcmd rotate-server-cert`.** The command replaces the server certificate, restarts the service on it, and prints a QR with the new fingerprint. Each device re-pairs through the idempotent path: the token in that QR is filler the server never stores. An unknown key gets nothing from it, and a revoked or left key is refused.

**Rate limiting.** After 3 failed pairing attempts from one IP, pairing refuses that IP until 60 seconds have passed since its first failure. A successful bootstrap pairing clears the counter.

## Device removal: revoked vs left

Both states are blocked identically everywhere: mTLS/JWT routes (every request re-checks the registry), `POST /api/session`, both `/api/cert/renew` paths, `/api/cert/challenge` (decoy nonce, see below), sync, push registration (deleted on the spot), and the vault key directory (`/api/vault/pubkeys` lists active devices only). The same gates require the device's **owning user** to be active, so revoking a user cuts every one of their devices off at `/api/session` and both renewal paths, not only at the JWT layer. Key grants and vault ACL rows are left as they are in both cases; the cryptographic cut is the surviving devices' key rotation.

| Status | Set when | Pairing again with the same key |
|--------|----------|---------------------------------|
| `revoked` | Someone else removed the device: an admin or the owner (`DELETE /api/devices/{id}`), the member from another of their devices, `pcmd revoke-device`, or the user-removal cascade (`DELETE /api/users/{id}`, `pcmd revoke-user`) | **Never.** Refused with `403 device_revoked` before any state change (the invite stays valid). The app has to be reinstalled (new key) to join again. |
| `left` | The device removed **itself**: the app's unpair (`DELETE /api/devices/self`), or the calling device when its member leaves the team (`DELETE /api/users/{own id}`) | **Only through a valid invite redemption.** The key is re-activated under that invite's normal rules and the invite is consumed. The bootstrap path refuses it (`403 device_left`). |

Revoking a `left` device escalates it to `revoked`; a `revoked` device never becomes `left`. The audit log records `device_left`, `device_revoked`, `device_reactivated` (with `previous_user_id`), and `outcome=left`/`outcome=revoked` on refused renewals and challenges.

**Re-joining as a different user starts from a clean vault slate.** When a left key is re-bound to a different user, the per-device vault records of its previous binding (every `vault_wrap` addressed to the device, its `device_vault_key` entry, and any `enroll_request`) are deleted in the same transaction that re-activates it (`device_key_records_reset` in the audit log). Permanent `device_revocation` records are never touched. Independently, a live `vault_wrap` is delivered to its recipient device's *current* owner only if that owner is entitled to the key: view access on the team vault, or, for a personal-vault wrap, being the user who wrote it. Tombstones always reach the recipient. A grant made to a device is therefore never a grant to whoever owns that device later.

## Certificate renewal

**Standard path** (cert valid or within grace): `POST /api/cert/renew` with `{"csr": "<PEM>"}` over a live mTLS connection. The server checks that the CSR key matches the stored public key, the device and its user are active, and the presented cert was issued by this server and is inside lifetime plus grace.

**Challenge path** (cert expired beyond grace):

1. `POST /api/cert/challenge` with `{"public_key": "..."}` returns `{"nonce", "expires_at"}` (30 seconds).
2. The client signs `<nonce>:<server_fingerprint>` with its device identity key.
3. `POST /api/cert/renew` with `{"signed_challenge", "public_key", "csr"}`; the server verifies the nonce and the signature against the stored key and issues a new cert.

**Dispatch rule (body wins).** If a request to `/api/cert/renew` presents both a valid mTLS peer cert and a `signed_challenge`, the challenge path runs and the cert is ignored. The challenge path is the only recovery for expired certs, so body-wins ensures it is never silently bypassed. Do not change this to prefer mTLS.

**CSR public-key binding.** Both paths require the CSR's `SubjectPublicKeyInfo` to equal the registered public key; a mismatch returns 400. Key rotation is not supported through this flow; re-pairing is required. Accepting a different key would let a forged CSR replace the registered identity. The CSR's *subject* is ignored: every issued certificate carries `CN=<device_id>`, so a client cannot put another device's name into a certificate this server signs. Only ECDSA P-256 keys are accepted, at pairing (`400 invalid_public_key`) and at signing.

**Nonce store invariants.** The nonce is consumed atomically: a single mutex-guarded lookup-and-delete (`TakeByPublicKey`) runs before any signature verification, so a 400 or a malformed signature still burns the nonce and the client must request a fresh challenge. The store is in-memory; nonces do not survive a restart. Do not move the take to after the key-binding check; that would open a TOCTOU window.

**No key-liveness oracle on `/api/cert/challenge`.** The endpoint is unauthenticated, so its response must not reveal whether a key belongs to a paired device. It answers *every* syntactically valid key with `200 {"nonce", "expires_at"}` and a fresh random nonce, but stores the nonce only for a registered, active device of an active user. Otherwise the nonce is a decoy and the renewal that follows fails with `401 unauthorized`, exactly as a stale nonce would. Only the audit log (`cert_challenge` with `outcome=unknown_device|revoked|left|user_inactive`) records what happened. Do not reintroduce a distinguishable status code.

**Rate limiting on `/api/cert/challenge`.** Two independent buckets: per IP (60 req/min, the standard `RateLimitMiddleware`) and per public key (10 req/min, keyed on the key's SHA-256 fingerprint so PEM re-framing cannot mint fresh buckets). Both answer 429 independently. The per-IP bucket also fronts every other pre-JWT route (`/api/health`, `/api/config`, `/api/capabilities`, `/api/pair`, `/api/cert/renew`, `/api/session`), so none of them is a free probe or signing oracle.

**Error taxonomy.** `400`: CSR key does not match the registered key (both paths). `401`: any nonce or signature failure, with one body for all cases so nonce-store state cannot be told apart. `403`: device not active, or its user not active, same body for all. `500`: signing or storage failure. Do not add status codes without updating both paths consistently.

## Session JWT

`POST /api/session` issues a 5-minute ES256 token:

```json
{
  "sub": "<device_id>",
  "iss": "pocketcmd",
  "exp": "<now+300>",
  "iat": "<now>",
  "cnf": { "x5t#S256": "<cert_fingerprint>" }
}
```

Validation accepts ES256 only (an allow-list enforced before the key is looked up, so `alg=none` and HMAC-with-the-public-key tokens never reach signature verification) and requires `exp`. Every request checks the signature, the expiry, and that `cnf.x5t#S256` matches the fingerprint of the TLS client cert on the connection.

**Key separation.** The persistent ECDSA P-256 server key is both the TLS key and the client-cert issuing key. The JWT signing key is derived from it with HKDF-SHA256 (`crypto/hkdf`, distinct info label), so the token-signing role is separate from the CA role and neither key discloses the other. The derivation is deterministic, so tokens survive restarts without an extra key file.

## Vault key wrapping

Records are AES-256-GCM ciphertext under per-vault 256-bit keys with key generations; removing a device or member rotates the key and re-encrypts. Each vault key is wrapped separately to every device that may read it: ECDH on P-256 between a fresh sender key and the recipient's device vault key, HKDF-SHA256, then AES-256-GCM with the vault ID, device ID and key generation as associated data, so a wrap cannot be replayed into another slot. Wraps a device addresses to itself additionally mix in the Argon2id-stretched app password. The server stores the public device vault keys (`device_vault_key`) and the wraps (`vault_wrap`); it never holds a password-derived key.

**Enrolling your own second device.** Adding another of the same user's devices to their vault needs an enrolled device's approval. The approving device shows a 6-digit code that the user types into the new device; the enrollment wrap folds a hash of that code into its key derivation, so a wrap minted without the code (by the server included) does not open, and the joining device allows 3 attempts per wrap. The server only relays `enroll_request` and `vault_wrap` records. There is no recovery path: losing every enrolled device loses the vault.

**Team vault grants.** Sharing a team vault with a member is a separate flow with no code. A member with `manage` on the vault picks the member and a level (`view`, `edit`, `manage`) in the app; the candidate's devices come from the signature-verified device directory and count only if this server lists them as active under that user. The granting user confirms the devices' fingerprints out of band (read from Settings, Security on each device), the app calls `POST /api/vault/grant`, and then wraps the vault key to each of those devices. If any wrap fails, the app rolls the grant back. Revoking a member rotates the vault key and re-pushes the vault's records.

**Metadata rules.** Device and user IDs on sync records are stamped by the server from the authenticated session; the values a client sends are ignored. An update timestamp more than 5 minutes ahead of the server clock is rejected (`future_timestamp`), so a wrong clock cannot plant a record nobody else can overwrite. Rejected records are reported with a reason (see [Push rejection reasons](api.md#push-rejection-reasons)).

## Host command execution

Approved commands run under `sh -c` with a stripped environment, a 10-second timeout, a 64 KB output cap, and process-group kill. Only the first numeric value in stdout is parsed. Commands are capped at 4096 characters and are not otherwise validated: whoever approves a command is trusted to have read it. `metrics.commands.create` gates the approval endpoint and the equivalent direct monitoring-config write, and the sync policy enforces it too, so there is no path around the approval flow. In the API only the owner can grant or revoke it; `pcmd grant` on the host can grant it too.

## Logs

- **Request/event log** (`server_logs`, `GET /api/logs`, owner-only): every API request with method, path, status, latency, source IP, and the calling device ID, user ID and display name when authenticated. Bounded to roughly the last 10,000 entries, survives restarts, and a user's entries are deleted when that user is purged.
- **Audit log** (`~/.pocketcmd/audit.log`, `GET /api/audit`, owner-only): pairing, revocations, role and permission changes, invite lifecycle, vault grants, metric-command decisions, SSH-config exports (paths only), and denied writes. Written regardless of `--debug-log`, `0600`, size-rotated (100 MB, 3 files). Append-only by design; it is not rewritten when a user is deleted.
- `--debug-log` mirrors the full request/event stream to a rotating file.

## Data deletion

`DELETE /api/users/{id}?purge_data=true` (the app's "remove member and delete their data"):

- **Hard-deleted:** the member's sync records (tombstoned immediately, rows removed by tombstone cleanup), push registrations, and request/event log entries.
- **Scrubbed:** the display name, and their devices' names, labels and last-seen stamps.
- **Retained deliberately:** the bare `user_id` and device rows (they anchor the audit trail and prevent identifier reuse), device public keys (so a revoked or left device presents as such rather than "unknown", and a revoked key can never re-pair), the audit-log record of the membership and the deletion, and already-collected metric samples (no user attribution; they age out by retention).

Without `purge_data`, revocation only flips status; data written by the member stays until purged.

## Push tokens

`push_registrations` holds `signed_token` values (HMAC-SHA256 of `device_token:platform`). A `signed_token` is bearer-equivalent for the relay's `/notify` endpoint: anyone holding it can send arbitrary pushes to that device until its FCM/APNs token rotates. Registrations are deleted the moment a device is revoked or unpairs. A server compromise would let an attacker spoof alert pushes to every paired device. This is deliberate: the relay is stateless and cannot store device-to-token mappings, so the server holds that state.

Alert notifications are composed server-side in cleartext (server name, metric label, value, threshold) and transit the hosted relay at `push.pocketcmd.com` and then FCM/APNs. The relay is not configurable: the app obtains its signed push token from the hosted relay, so the server can only send through it. End-to-end encrypted push payloads are a possible future hardening.
