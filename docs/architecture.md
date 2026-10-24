# Architecture

How the mobile app and the server talk to each other, which endpoints are reachable without a device key, and what stays compatible across releases. The request and response contract of every route is in [api.md](api.md); the security model is in [SECURITY.md](../SECURITY.md).

## Overview

```
Mobile app                          Server (pcmd)
+-----------+                       +---------------------+
| PocketCmd |--- POST /api/pair --->| pairing + PKI       |  one-time, QR-bootstrapped
|           |<-- client cert -------|                     |
|           |--- POST /cert/renew ->| cert issuer         |  every 30 min
|           |<-- new cert ----------|                     |
|           |--- POST /session ---->| JWT issuer          |  every 5 min (cert-bound)
|           |<-- session JWT -------|                     |
|           |                       |                     |
|           |<== /api/sync/* ======>| sync store (E2E)    |  mTLS + JWT
|           |<== /api/metrics/* ===>| metrics + scheduler |  mTLS + JWT
+-----------+                       +----------+----------+
      ^                                        |
      | QR scan (pairing token                 | systemd / launchd
      |  + pinned server fingerprint)          v
      +------------------------------  background service, always running
```

Everything relational (identity, devices, invites, monitoring config, and sync records) lives in a single SQLite database, `~/.pocketcmd/state.db`. Time-series samples are kept in a separate `metrics.db`.

## API surface

The **unauthenticated** endpoints are the entire surface reachable without a device key, and every one of them is rate-limited per client IP:

| Endpoint | Purpose |
|----------|---------|
| `GET /api/health` | Liveness check. |
| `GET /api/config` | Client poll-interval hint. |
| `GET /api/capabilities` | Server version and wire-protocol (API) version. |
| `POST /api/pair` | Device pairing with a one-time pairing token or a team invite; the CSR key must match the device key (proof of possession). |
| `POST /api/cert/challenge` | Issue a single-use nonce for expired-cert recovery. |
| `POST /api/cert/renew` | Renew a client cert via mTLS, or via a signed challenge when the cert has expired. |
| `POST /api/session` | Issue a session JWT (requires mTLS). |

Every request except `GET /api/health` and `GET /api/capabilities` must carry the wire-protocol version header `X-PocketCmd-Api-Version: 1.0`; anything else is refused with `400 api_version_mismatch` before authentication.

Everything else requires **mTLS + JWT** and is further gated by role or permission on the server:

| Area | Routes |
|------|--------|
| Sync | `/api/sync/*` |
| Metrics reads | `/api/metrics/*` |
| Custom-command requests and approval | `/api/metrics/requests/*` |
| E2E vault ACLs | `/api/vault/*` |
| Team management | `/api/invites`, `/api/users`, `/api/devices` |
| Push registration | `/api/push/register` |
| SSH host-key fingerprints of the machine | `/api/host-keys` |
| Server status and config (admin) | `/api/server/*` |
| Audit and log feeds (owner) | `/api/audit`, `/api/logs` |

SSH config export (`/api/ssh-configs`, admin-only) is not served by the standing server at all. It exists only on the short-lived server that `pcmd sync` starts, for one fetch.

The complete route table and its auth posture are pinned by an executable test, `internal/server/endpoint_matrix_test.go`.

## Project layout

See [Project Structure in CONTRIBUTING.md](../CONTRIBUTING.md#project-structure).

## Compatibility

- **Versioning.** The `pcmd` binary follows [semantic versioning](https://semver.org). Breaking changes to the CLI, the config file, or the wire protocol only ship in a new major version.
- **API version.** `GET /api/capabilities` exposes `api_version` (currently `"1.0"`, the `APIVersion` constant in `internal/server/server.go`), and every other request must send the same value in the `X-PocketCmd-Api-Version` header. A mismatched app is told so (`400 api_version_mismatch`, with `server_api_version` in the body) before anything else happens. Check this value first when a newer app and an older server disagree.
- **Data directory.** `state.db` migrates forward only. Before a release migrates it, the server copies it to `state.db.v<N>.bak` (N = the schema it had; only the newest copy is kept, and `pcmd backup` leaves it out), which the previous release can open again. An older binary refuses to start over a `state.db` or `config.json` written by a newer release (`state.db was written by a newer pcmd; upgrade the binary or restore an older backup`) rather than guessing at the newer schema.
- **Platforms.** Linux (systemd user units, or OpenRC where systemd is absent) and macOS (launchd), on amd64 and arm64. Windows binaries build but service install is unsupported; run with `--foreground` there.
- **Build provenance.** `go install` builds report version `1.0.0-dev`. Only binaries built by the release pipeline carry the real version, commit, and build date.
