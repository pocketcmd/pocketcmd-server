# Security

## Reporting a vulnerability

Do not open a public GitHub issue. Email **security@pocketcmd.com** with a description and, if possible, steps to reproduce. We acknowledge within 48 hours and provide a timeline for a fix.

Only the latest minor release line (`1.x`) receives security fixes. Confirm the issue reproduces on the current release before reporting.

**In scope:** mTLS or JWT bypass, the certificate renewal protocol, the pairing flow (token reuse, fingerprint spoofing), command injection via custom metric commands, path traversal in the sync store, device registry manipulation, TLS configuration, and sync data confidentiality.

**Out of scope:** denial of service (the server is designed for personal and small-team use), issues requiring physical access to the server machine, and social engineering.

## Model

| Layer | Mechanism |
|-------|-----------|
| Device identity key | Per-device ECDSA P-256 key. Where the device has a secure element (Secure Enclave on iOS, iPadOS and macOS; StrongBox or TEE on Android; TPM 2.0 on Windows and Linux) the key is generated inside it and cannot be exported. Otherwise it is a software key sealed under the device vault key in platform secure storage. Only the public key ever leaves the device. |
| App password | Mandatory, at least 12 characters with mixed case, a digit and a symbol. Stretched with Argon2id (64 MiB, 3 passes) and mixed into every vault-key wrap a device addresses to itself, so opening the vault takes the device **and** the password. Never stored or sent. |
| Biometric | Face ID, Touch ID or fingerprint releases the same password-derived factor from a biometric-gated hardware key. A change to the biometric enrollment invalidates it; the password remains the fallback. |
| Client certificate | 30-minute mTLS cert, renewed by signing a CSR with the device identity key. |
| Session JWT | 5-minute ES256 token bound to the client cert fingerprint through the `cnf` claim. A stolen token without the cert and its private key is useless. |
| Device registry | The server stores device public keys; only registered, active devices of active users can renew certs or open sessions. |
| Revocation | Revoking a device or user fails cert renewal immediately, and every request re-checks the registry, so live sessions die on the next call rather than at token expiry. |

The device's identity is its public key. Certificates are disposable; the keypair is permanent and never leaves the device.

## Transport

TLS 1.3 only. On first run the server generates a persistent self-signed ECDSA P-256 certificate (`~/.pocketcmd/tls/`) that clients pin by fingerprint at QR-scan time. It is the server's identity, not rotatable TLS material: `pcmd rotate-server-cert` replaces it and every device must re-pair.

The handshake requests a client certificate but does not verify a chain. Authorization is checked per request instead: the presented key must belong to a registered active device, and the cert must have been issued by this server and be within its lifetime plus a 10-minute grace. The only endpoints reachable without a client cert are `/api/pair`, `/api/cert/challenge`, the challenge path of `/api/cert/renew`, and three read-only routes that return nothing secret (`/api/health`, `/api/config`, `/api/capabilities`). All of them are rate-limited per IP. Every route except `/api/health` and `/api/capabilities` must name the server's API version in the `X-PocketCmd-Api-Version` header or is refused with `400 api_version_mismatch` before authentication.

## Pairing

The first `pcmd` run prints a QR code carrying a one-time pairing token (60-second TTL) and the server fingerprint. The device connects over HTTPS pinning that fingerprint and sends the token, its public key and a CSR for that key. The server checks the token and that the CSR key equals the device key (proof of possession), then signs a 30-minute client cert. Later devices and members join through `pcmd invite`. Three failed pairings from one IP block it for 60 seconds.

A device that is removed is either **revoked** (someone else removed it: the key can never pair again, the control for a lost or stolen device) or **left** (it unpaired itself: the key can rejoin only through a valid invite). Both are blocked identically everywhere. Details, including how a left key re-joining another user starts from a clean vault slate, are in [docs/security-internals.md](docs/security-internals.md#device-removal-revoked-vs-left).

## End-to-end encrypted sync

Sync record content is encrypted on the device before upload and the server cannot decrypt it. Records are AES-256-GCM under per-vault keys; each vault key is wrapped separately to every device that may read it (ECDH P-256, HKDF-SHA256, AES-256-GCM), and removing a device or member rotates the key. The server never holds a password-derived key, so a copy of its database gives nothing to guess a password against. Enrolling another of your own devices needs approval from a device that already holds the vault: the approving device shows a six-digit code that is typed into the joining device and mixed into the wrap's key derivation. Sharing a team vault with a member is a manage-level action in the app: the vault key is wrapped to each of that member's active enrolled devices after their fingerprints are verified out of band, and the server records the ACL. There is no recovery path if every enrolled device is lost.

We deliberately do not call this "zero-knowledge" without qualification, because the server does see:

- **Sync metadata:** record type, ID, size, update timestamp, writing device, owning user, and vault membership. The server routes, authorizes and resolves conflicts on these fields. An operator with disk access learns *that* you have 14 SSH keys and *when* they changed, never their contents.
- **Monitoring config:** the one record type stored in cleartext, because the scheduler must execute those commands and evaluate alert rules. Never put secrets in metric commands or labels.
- **Team directory:** display names, device names, roles and permission grants.

The server can never read task contents, hostnames inside records, SSH key material, snippet bodies or secret items.

## Host commands

The metrics scheduler can run shell commands on the host. This is the product's highest-privilege feature: any member may propose a command, but only holders of `metrics.commands.create` may approve one. The owner holds it implicitly and alone can grant it; granting it to an admin or member hands them code execution on the host. Approved commands run under `sh -c` with a stripped environment, a 10-second timeout and a 64 KB output cap, and are not otherwise validated.

## Data at rest

Everything relational lives in `~/.pocketcmd/state.db`; metric samples live in `metrics.db`. Neither SQLite database is encrypted at rest. Protection is filesystem permissions (`0700` directory, `0600` files) plus the fact that sync content is client-side ciphertext. The server's disk holds:

| Data | Plaintext? | Where |
|------|-----------|-------|
| Sync record content (tasks, keys, snippets, secrets) | **No, client-side AES-256-GCM** | `sync_records.data` / `.credentials` |
| Sync metadata (types, ids, timestamps, device/user ids, vault ACL) | Yes | `sync_records`, `vault_acl` |
| Monitoring commands and labels | Yes (the server executes them) | `custom_metrics`, `metric_requests`, `alert_rules` |
| Team directory (display names, roles, permissions) | Yes | `users` |
| Device registry (public keys, device names, last-seen) | Yes | `devices` |
| Push registration (`device_token`, `signed_token`) | Yes (bearer-equivalent for the relay) | `push_registrations` |
| Request/event log tail (paths, status, latency, caller, source IPs) | Yes | `server_logs` (about the last 10,000 entries) |
| Metric samples (metric id, value, timestamp; no user attribution) | Yes | `metrics.db`, pruned by retention (1 to 30 days) |
| Audit events | Yes | `~/.pocketcmd/audit.log` |

## Logs and team visibility

The request/event log (`GET /api/logs`) records every API request with its caller, source IP and latency. The audit log (`~/.pocketcmd/audit.log`, `GET /api/audit`) records pairings, revocations, role and permission changes, invites, vault grants, metric-command decisions and denied writes, and is append-only. Both feeds are **owner-only**. If you are a member of a team server, its owner can see your source IPs, device names and request activity; admins and members cannot.

Removing a member with `purge_data` hard-deletes their sync records, push registrations and log entries and scrubs their names. Their bare user and device rows, device public keys and audit entries are retained so the audit trail stays intact and a revoked key can never re-pair.

## Push notifications

A push is only sent to a device whose user allowed notifications in the app; there is no server-side switch. Alerts are composed in cleartext (server name, metric label, value, threshold) and transit the open-source relay at `push.pocketcmd.com`, then FCM or APNs. The relay is not configurable. The server's push tokens are bearer-equivalent for the relay, so a server compromise would let an attacker spoof alert pushes to paired devices; registrations are deleted the moment a device is removed.

## Threat model

| Attack | Mitigation |
|--------|-----------|
| Steal the phone | App password required; vault keys need the device key and the password |
| Root or jailbreak the phone | Hardware-backed keys cannot be exported; instant server-side revocation limits exposure |
| Clone app data to another device | Hardware keys stay in the secure element; a software key is sealed under the device vault key and the copy still needs the password at Argon2id cost |
| Shoulder-surf the app password | Still needs the physical device |
| Intercept the QR code | Token expires in 60 s and is one-time; a re-pair QR only re-issues certs to registered, active keys that prove possession |
| Steal a cert without the private key | Expires in 30 min, cannot renew |
| Steal a JWT without the cert | Useless (channel binding) |
| MITM during pairing | Server fingerprint in the QR prevents it |
| Server filesystem access | Sync **content** stays ciphertext; the attacker gets metadata, team directory, monitoring commands, logs and push tokens (see Data at rest) |
| Phone and password both compromised | Full access, as with any auth system |

## Deliberate trade-offs

- **Key separation.** The server key is both the TLS key and the client-cert issuer. The JWT signing key is derived from it with HKDF-SHA256, so the two roles are cryptographically separate, but a host compromise still compromises everything.
- **100-year self-signed server cert.** It is the pinned identity; replacing it invalidates every pairing by design.
- **No chain verification in the TLS handshake.** Authorization is registry membership of the presented key, proven by the handshake.
- **Invite redemption is not constant-time.** Distinct consumed, revoked and expired responses improve the joining UX; 80-bit invite entropy plus per-IP rate limiting make state probing impractical.
- **Denial of service is out of scope**, though request bodies are size-capped and timeouts are set everywhere.

The protocol-level invariants behind all of this (dispatch rules, nonce handling, the no-oracle rule on the challenge endpoint, CSR binding, rate-limit buckets, error taxonomy) are in [docs/security-internals.md](docs/security-internals.md).
