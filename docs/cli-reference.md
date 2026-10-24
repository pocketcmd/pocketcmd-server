# PocketCmd CLI Reference

## Overview

`pcmd` is a single binary that runs an mTLS + JWT secured server exposing monitoring and config sync APIs to your mobile device. On first run it pairs a device, installs as a background service, and exits. Later runs start the server in the mode chosen on the first run and show its status.

---

## Usage

```
pcmd [flags]
pcmd <command> [args] [flags]
```

Every command answers `--help` with a description and examples. Commands that list things accept `--json` for scripts; commands that change or remove something ask for confirmation and accept `-y`/`--yes` to skip it.

---

## First Run

Running `pcmd` with no arguments on a fresh install:

1. Generates a persistent server TLS certificate at `~/.pocketcmd/tls/`
2. Starts the server on port 8767 (or `--port`)
3. Generates a one-time pairing token (60-second TTL)
4. Displays a QR code and pairing URL
5. Waits up to 5 minutes (`--pair-timeout`) for a device to connect to `/api/pair`. Each time the token expires, a new token and QR code are printed (`The pairing code expired. Scan the new code:`)
6. Device pairs (exchanges keys, receives client cert)
7. Writes `~/.pocketcmd/config.json`
8. Installs as a systemd or OpenRC (Linux) or launchd (macOS) background service, unless `--foreground` was given
9. Prints success and exits (service continues in background)

`config.json` is written only after a device has paired. If the run times out, is cancelled with Ctrl+C (exit code 130), or fails, no config is left behind and running `pcmd` again repeats the first run.

On later runs `pcmd` follows the saved `service_mode`: in `background` mode it installs or starts the service if needed and prints its status; in `foreground` mode (or with `--foreground`) it serves until Ctrl+C.

**Headless hosts.** With `--non-interactive` there are no prompts: the first run prints the pairing URL (and the QR code unless `--no-qr`) and waits `--pair-timeout` (default `5m`; `0` waits forever) for a device. Scan or paste the URL from another machine.

**Run as yourself, not root.** The service is installed per user (a systemd user unit or a launchd agent) and the state lives in that user's `~/.pocketcmd`. `pcmd` and `pcmd install` refuse to run as root or under `sudo` on those paths; log in as the user who should own the server. On Linux run `loginctl enable-linger <user>` afterwards so the service keeps running after logout (`pcmd status` reports whether it is set). The OpenRC path (Linux without systemd) is a system service and is the one case that needs `sudo pcmd install`.

---

## Exit codes

| Code | Meaning |
|------|---------|
| `0` | Success. |
| `1` | Error (printed on stderr as `Error: ...`). |
| `2` | `pcmd status`: the service is installed but not running. |
| `3` | `pcmd status`: no service is installed. |
| `4` | `pcmd restart`: the service restarted but failed its health check within 10 seconds. |
| `130` | Interrupted with Ctrl+C while waiting (first run, `sync`, `logs -f`, `audit -f`). |

---

## Commands

### `pcmd` (default)

First run: starts server, shows QR code, waits for pairing, installs as background service.
Later runs in background mode: installs or starts the service if it is not running, then shows its status (PID, port, paired devices). In foreground mode: runs the server until Ctrl+C.

Only the first run pairs a device without an invite. Add further devices and members with `pcmd invite` (with `--for <user>` to add a device for an existing user, or without it to invite a new member) or from the app.

| Flag | Type | Default | Description |
|------|------|---------|-------------|
| `--foreground` | bool | `false` | Run the server in the foreground instead of installing it as a service. Useful for debugging or inside a container. |
| `--pair-timeout` | duration | `5m` | How long the first run waits for a device to pair; `0` waits forever. |
| `--advertise-ip` | string | the bind address | IP address or hostname to put in the QR/pairing URL instead of the bind address (the first LAN address when the server listens on every interface), e.g. a public IP or a dynamic-DNS name behind NAT. Must be an IP address or a hostname; anything else is rejected. |
| `--debug-log` | path | none | Also write the structured JSON log to this file (rotated at the standard size cap). Without it the log is kept only in `state.db` (see `pcmd logs`). |
| `--non-interactive` | bool | `false` | Never prompt: take the defaults (listen on the first LAN address) and wait for a device without a wizard. |

```
pcmd
pcmd --port 9000 --host 10.8.0.1
pcmd --non-interactive --no-qr --pair-timeout 0
pcmd --foreground --debug-log /tmp/pocketcmd.log
```

### `pcmd status`

Show the service status. Prints the banner with the binary version (only when stdout is a terminal), then: whether the service is running (with its PID) or stopped, the port, the number of paired devices, the configured service mode, on Linux whether `loginctl` lingering is enabled, and the paths of `config.json`, the data directory, and the stdout/stderr file (`server.log`, macOS only, when it exists). If no service is installed it prints `Status:   not installed` and suggests running `pcmd`. It does not report uptime or a monitoring summary; monitoring is viewed from the app.

The exit code says the same thing for scripts: `0` running, `2` stopped, `3` not installed.

| Flag | Type | Default | Description |
|------|------|---------|-------------|
| `--json` | bool | `false` | Print one JSON object (`version`, `installed`, `running`, `pid`, `port`, `paired_devices`, `service_mode`, `config_path`, `data_dir`, `stdout_log`, `linger`, `service_state`). |

```
pcmd status
pcmd status --json | jq .paired_devices
```

### `pcmd install`

Install and start the background service. Called automatically by the first-run flow; needed by hand after `pcmd uninstall` or on a restored data directory. Detects the OS and init system and writes the appropriate service file:

- **Linux with systemd:** `~/.config/systemd/user/pocketcmd.service` (a user unit; no root needed)
- **Linux without systemd, with OpenRC:** `/etc/init.d/pocketcmd`, registered in the `default` runlevel with `rc-update` (needs root)
- **macOS:** `~/Library/LaunchAgents/com.pocketcmd.server.plist`

On Linux with neither init system the command fails; run `pcmd --foreground` under your own process manager instead.

On a host where no device has paired yet the command refuses with `pair a device first`: the unit would start a server that prints pairing codes nobody sees. Run `pcmd` first, or pass `--allow-unpaired`. Like the first run, it refuses to run as root or under `sudo` on the per-user paths.

| Flag | Type | Default | Description |
|------|------|---------|-------------|
| `--allow-unpaired` | bool | `false` | Install even though no device has paired yet. |

```
pcmd install
pcmd install --port 9000
```

### `pcmd uninstall`

Stop and remove the background service (the systemd unit, OpenRC script, or launchd plist). Asks for confirmation; `-y`/`--yes` skips the question and is required under `--non-interactive` (or when stdin is not a terminal). The `~/.pocketcmd/` data directory is left in place; delete it yourself if you want the devices, certificates, and sync data gone.

| Flag | Type | Default | Description |
|------|------|---------|-------------|
| `-y`, `--yes` | bool | `false` | Skip the confirmation prompt. |
| `--non-interactive` | bool | `false` | Never prompt; refuse unless `--yes` is given. |

```
pcmd uninstall
pcmd uninstall --yes
```

### `pcmd start`

Start the installed background service (after `pcmd stop`) and wait for it to answer `/api/health`. Fails if no service is installed.

```
pcmd start
```

### `pcmd stop`

Stop the background service without uninstalling it: the service definition stays registered and `pcmd start` (or the next plain `pcmd`) brings it back. Use this before `pcmd restore`.

```
pcmd stop
```

### `pcmd restart`

Stop and start the background service. The service definition is rewritten (uninstall + install) only when the file on disk no longer matches what this binary, port, and bind address would produce, that is, after the binary moved or `--port`/`--host` changed; otherwise the registered unit is kept as it is. Exits with code `4` when the restarted service does not pass its health check within 10 seconds.

```
pcmd restart
pcmd restart --port 9000
```

### `pcmd logs`

Show the server's structured log: the same entries the app's log screen (`GET /api/logs`) shows, kept in `~/.pocketcmd/state.db` (roughly the last 10,000). Entries are printed oldest first as `time LEVEL message key=value ...`.

The process's own stdout/stderr (crash output, startup errors) is not part of it. On systemd it goes to the journal (the command prints a hint: `journalctl --user -u pocketcmd`); on macOS it is in `~/.pocketcmd/server.log`.

| Flag | Type | Default | Description |
|------|------|---------|-------------|
| `-f`, `--follow` | bool | `false` | Keep printing new entries (polling the store) until Ctrl+C. |
| `-n`, `--lines` | int | `50` | Number of recent entries to show. |
| `--since` | duration | none | Only entries newer than this (`30m`, `2h`, `24h`). |
| `--level` | string | none | Only entries at this level or above: `debug`, `info`, `warn`, `error`. |
| `--json` | bool | `false` | Print the raw JSON entries, one per line. |
| `--file` | path | none | Read a `--debug-log` file (JSON lines) instead of the log store; `-f` follows it and copes with rotation. |

```
pcmd logs
pcmd logs -f --level warn
pcmd logs --since 2h --json
pcmd logs --file /tmp/pocketcmd.log -f
```

### `pcmd list-devices`

List the active paired devices under a header row: the public key fingerprint (truncated), owning user, device name, status, and pairing date. Prints `No active devices.` when there are none. With `--all` the removed devices are listed too, with a `REMOVED` column: status `revoked` (removed by an admin, the owner, the member from another device, or this CLI; permanent) or `left` (the device unpaired itself from the app; blocked like `revoked`, but the same device may re-join with a new invite). This mirrors `GET /api/devices?include=all`.

| Flag | Type | Default | Description |
|------|------|---------|-------------|
| `--all` | bool | `false` | Also list revoked and left devices, with the time they were removed. |
| `--json` | bool | `false` | Print a JSON array (`device_id`, `fingerprint` (full), `user_id`, `user_name`, `device_name`, `device_label`, `status`, `paired_at`, `removed_at` (removed devices only), `last_seen_at`). |

```
pcmd list-devices
pcmd list-devices --all
pcmd list-devices --json
```

Example output:

```
FINGERPRINT      USER                  DEVICE                          STATUS    PAIRED                REMOVED
a1b2c3d4e5f6...  alice                 iPhone 15                       active    2026-03-15T10:30:00Z  -
f6e5d4c3b2a1...  bob                   iPad Pro                        left      2026-03-20T14:45:00Z  2026-04-02T09:12:00Z
```

### `pcmd revoke-device [pubkey-fp]`

Revoke a paired device by its public key fingerprint prefix (or device ID prefix). The prefix must be at least 8 characters; the first matching device wins, so use enough characters to be unambiguous. With no argument, an interactive picker lists the devices (without a terminal, or under `--non-interactive`, the argument is required). Either way the command asks for confirmation unless `--yes` is given. The device is marked revoked in the registry (its public key is retained so it presents as "revoked", not "unknown"). Cert renewal fails immediately and every request re-checks the registry, so active sessions die on the next call, with no waiting for JWT expiry. Revocation is permanent for that device key: it is refused on every later pairing attempt (`device_revoked`), so the device only comes back after the app is reinstalled (new key) and joins with a new invite. Revoking a device whose status is `left` (it unpaired itself) makes it permanent the same way; use this for a lost or stolen device.

| Flag | Type | Default | Description |
|------|------|---------|-------------|
| `-y`, `--yes` | bool | `false` | Skip the confirmation prompt. |
| `--non-interactive` | bool | `false` | Never prompt; requires the argument and `--yes`. |

```
pcmd revoke-device a1b2c3d4
pcmd revoke-device a1b2c3d4 --yes
pcmd revoke-device
```

### `pcmd rename-device <fingerprint-prefix>`

Change a paired device's name and/or label. The argument is a prefix (8+ characters) of the device's public key fingerprint or device ID as shown by `pcmd list-devices`, resolved like `revoke-device`. At least one of `--name` and `--label` is required; each value is at most 128 characters (never truncated; a longer value is refused). The change is written to the audit log (`device_renamed`) and is what the app shows on its next device listing.

| Flag | Type | Default | Description |
|------|------|---------|-------------|
| `--name` | string | none | New device name (must not be empty). |
| `--label` | string | none | New device label; an empty value clears it. |

```
pcmd rename-device a1b2c3d4 --name "Alice's iPhone"
pcmd rename-device a1b2c3d4 --label pocket
pcmd rename-device a1b2c3d4 --name "Work phone" --label ""
```

### `pcmd rotate-server-cert`

Regenerate the server's TLS certificate. Every paired device pinned the old fingerprint, so each must re-pair; the command asks for confirmation first (`--yes` skips it). It restarts the installed background service on the new certificate (a foreground server has to be restarted by hand), then prints a QR code and URL with the new fingerprint. Scan it in the app on every paired device: registered, active devices re-pair with it and keep their user and role. It pairs no new devices.

| Flag | Type | Default | Description |
|------|------|---------|-------------|
| `-y`, `--yes` | bool | `false` | Skip the confirmation prompt. |
| `--non-interactive` | bool | `false` | Never prompt; refuse unless `--yes` is given. |
| `--advertise-ip` | string | saved / auto-detected | IP address or hostname for the re-pair URL. |

```
pcmd rotate-server-cert
pcmd rotate-server-cert --yes --no-qr
```

### `pcmd sync`

One-shot SSH config sync: starts an ephemeral server and immediately prints a one-time QR code. Scanning it enrolls the device (if new) and pulls `/api/ssh-configs` once; the command exits after the first successful fetch. The hosts are read from `~/.ssh/config` with ssh_config semantics: `Include` files, `Host` patterns (`*`, `?`, `!`), first value wins (so `Host *` fills in unset values), HostName defaulting to the alias, User to the local user and Port to 22, and the first `IdentityFile` that exists. `Match` blocks are skipped. Already-paired devices can fetch without scanning. The ephemeral server binds a random free port so it never clashes with a simultaneously running standing server; pass `--port` to pin one explicitly. Ctrl+C exits with code 130.

| Flag | Type | Default | Description |
|------|------|---------|-------------|
| `--timeout` | duration | `60s` | Max time to wait for a device to fetch. |
| `--advertise-ip` | string | saved / auto-detected | IP address or hostname for the sync URL. |
| `--debug-log` | path | none | Also write the ephemeral server's structured log to this file. |

```
pcmd sync
pcmd sync --timeout 2m --advertise-ip 10.0.0.5
```

### `pcmd backup [output-path]`

Create a tar.gz backup of `~/.pocketcmd` (config, certs, devices, sync data, metrics, audit log). The SQLite databases are snapshotted consistently, so the server may keep running. The archive holds the server key and the device registry and is written owner-only (`0600`). The default name is `pocketcmd-backup-<date>.tar.gz` in the current directory.

```
pcmd backup
pcmd backup ~/pocketcmd-backup.tar.gz
```

### `pcmd restore <backup-path>`

Restore `~/.pocketcmd` from a backup archive. In this order: the archive is validated (it must be a gzip tarball with every entry under `.pocketcmd/` (no `../`, no symlinks) that contains `state.db` and `tls/server.key`); then the command refuses while the background service is running (`pcmd stop` first) or while any server answers `/api/health` on the configured port (a foreground run: Ctrl+C it); then it asks before overwriting an existing data directory. File modes are clamped to `0600` regardless of the archive.

| Flag | Type | Default | Description |
|------|------|---------|-------------|
| `-y`, `--yes` | bool | `false` | Overwrite an existing `~/.pocketcmd` without prompting. |
| `--force` | bool | `false` | Alias of `--yes`. |
| `--non-interactive` | bool | `false` | Never prompt; refuse to overwrite unless `--yes` is given. |

```
pcmd stop
pcmd restore ~/pocketcmd-backup.tar.gz --yes
pcmd start
```

---

## Team Commands

The following commands are available on team installs (after the first user has been created via first-run pairing).

### `pcmd invite`

Create an invite code for a new team member or for an additional device belonging to an existing user. Prints the invite code, a scannable QR code (see [QR codes](#qr-codes)), and a `pocketcmd://invite?...` deep-link URL. Refuses with `no owner yet; run pcmd first to pair the owner device` until the first run has paired the owner.

**Synopsis:**

```
pcmd invite [--for <user>] [--role admin|member] [--pin-device <fingerprint>] [--expires <duration>] [--label <text>]
```

**Flags:**

| Flag | Type | Default | Description |
|------|------|---------|-------------|
| `--for` | string | none | User ID or display name to add a device for. When set, `--role` is ignored (user keeps their existing role). Omit to create a new user. |
| `--role` | string | `member` | Role for the new user (`admin` or `member`). Ignored when `--for` is set. |
| `--pin-device` | string | none | Require this pubkey fingerprint at redemption. Ties the invite to a specific device. |
| `--expires` | duration | `24h` | How long the invite is valid. Clamped to 30 days; a note is printed when the value was reduced. |
| `--label` | string | none | Free-text note stored server-side (not sent to the recipient). |
| `--advertise-ip` | string | saved / auto-detected | IP address or hostname for the invite URL. |

**Examples:**

```bash
# Create a 24-hour member invite
pcmd invite --label "Alice's iPhone"

# Create a 48-hour admin invite
pcmd invite --role admin --expires 48h --label "Bob (backup admin)"

# Add a second device for an existing user
pcmd invite --for alice --label "Alice's iPad"
```

---

### `pcmd list-invites`

List all outstanding (unredeemed, non-expired) invites. Shows the code, role, expiry (RFC 3339), target (the user ID for second-device invites, `(new user)` otherwise), and label. Prints `No active invites.` when there are none. `invites` remains as an alias.

| Flag | Type | Default | Description |
|------|------|---------|-------------|
| `--json` | bool | `false` | Print a JSON array of the invite records. |

**Example:**

```bash
pcmd list-invites
# CODE              ROLE    EXPIRES               TARGET          LABEL
# a1b2c3d4e5f6g7h8  member  2026-04-24T10:00:00Z  (new user)      Alice's iPhone
# f6e5d4c3b2a19887  admin   2026-04-25T08:30:00Z  (new user)      Bob (backup admin)
# 9f8e7d6c5b4a3210  member  2026-04-25T09:00:00Z  k7f3m9q2w8xz    Alice's iPad
```

---

### `pcmd revoke-invite <code-or-prefix>`

Revoke an outstanding invite before it is redeemed. Accepts the full invite code or a unique prefix. Asks for confirmation unless `--yes` is given.

| Flag | Type | Default | Description |
|------|------|---------|-------------|
| `-y`, `--yes` | bool | `false` | Skip the confirmation prompt. |
| `--non-interactive` | bool | `false` | Never prompt; refuse unless `--yes` is given. |

**Example:**

```bash
pcmd revoke-invite a1b2c3d4
pcmd revoke-invite a1b2 --yes   # prefix is fine if unambiguous
```

---

### `pcmd list-users`

List all team members. Shows user ID, display name, role (`owner`, `admin`, or `member`), status, and active device count.

| Flag | Type | Default | Description |
|------|------|---------|-------------|
| `--json` | bool | `false` | Print a JSON array (`user_id`, `display_name`, `role`, `owner`, `status`, `active_devices`, `permissions`). |

**Example:**

```bash
pcmd list-users
# USER_ID         NAME    ROLE    STATUS    DEVICES
# k7f3m9q2w8xz    Alice   owner   active    2
# p4n8r2t6y1vb    Bob     member  active    1
```

---

### `pcmd revoke-user <user-or-name>`

Revoke a team member. Cascades to all of their active paired devices and to any outstanding invites created for them or by them. Revocation takes effect on the next request: cert renewal fails immediately and every authenticated request re-checks the registry, so live sessions die on their next call rather than at JWT expiry. The owner cannot be revoked, and neither can the last active admin. Asks for confirmation (the question says whether data will be purged) unless `--yes` is given.

**Synopsis:**

```
pcmd revoke-user <user-or-name> [--purge-data] [--yes]
```

**Flags:**

| Flag | Type | Default | Description |
|------|------|---------|-------------|
| `--purge-data` | bool | `false` | Also hard-delete the sync data written by the user's devices. Records are tombstoned with their content and credentials cleared, so remaining devices sync the deletion. |
| `-y`, `--yes` | bool | `false` | Skip the confirmation prompt. |
| `--non-interactive` | bool | `false` | Never prompt; refuse unless `--yes` is given. |

**Examples:**

```bash
pcmd revoke-user bob
pcmd revoke-user usr_def --purge-data --yes
```

---

### `pcmd promote <user-or-name>`

Promote a member to admin. Accepts a user ID or display name. The promoted user immediately gains admin capabilities (every permission except `metrics.commands.create`, which they keep only if it was granted; other member grants no longer apply).

**Example:**

```bash
pcmd promote bob
pcmd promote usr_def
```

---

### `pcmd demote <user-or-name>`

Demote an admin to member. Accepts a user ID or display name. Cannot demote the owner or the last remaining admin. Asks for confirmation unless `--yes` is given.

| Flag | Type | Default | Description |
|------|------|---------|-------------|
| `-y`, `--yes` | bool | `false` | Skip the confirmation prompt. |
| `--non-interactive` | bool | `false` | Never prompt; refuse unless `--yes` is given. |

**Example:**

```bash
pcmd demote bob
pcmd demote usr_def --yes
```

---

### `pcmd transfer-ownership <user-or-name>`

Hand the owner role to another active team member, the same operation as `POST /api/users/{id}/transfer-ownership` in the app. The new owner becomes an admin with the owner flag and the previous owner stays an admin; the swap is atomic, so there is always exactly one owner, and the running service applies it at once (owner-only routes and the vault access override resolve the flag per request). Refused when the target is already the owner or is not active (revoked). Asks for confirmation unless `--yes` is given. Written to the audit log as `owner_transferred`.

| Flag | Type | Default | Description |
|------|------|---------|-------------|
| `-y`, `--yes` | bool | `false` | Skip the confirmation prompt. |
| `--non-interactive` | bool | `false` | Never prompt; requires `--yes`. |

**Example:**

```bash
pcmd transfer-ownership bob
pcmd transfer-ownership k7f3m9q2w8xz --yes
```

---

### `pcmd rename-user <user-or-name> <new-display-name>`

Change a team member's display name, as shown in the app and in this CLI. The change is written to the audit log (`user_renamed`).

**Example:**

```bash
pcmd rename-user bob "Bob Smith"
```

---

### `pcmd grant <user-or-name> <permission>`

Grant one permission. The owner holds every permission and admins every one except `metrics.commands.create`, so other grants apply to members only (granting them to an admin, or anything to the owner, is refused). `metrics.commands.create` is owner-granted: it can be granted to admins and members, and in the app only the owner can grant or revoke it. Permission keys:

| Key | Allows |
|-----|--------|
| `metrics.read` | Read metric values and history. |
| `metrics.commands.read` | See the configured custom commands. |
| `metrics.commands.create` | Approve metric command requests (make a command run on the host). Owner-granted: admins hold it only through a grant. |
| `metrics.commands.update` | Edit custom commands. |
| `metrics.commands.delete` | Remove custom commands (revoke a running one). |
| `alerts.read` | Receive alert notifications; may be scoped to metrics with `--metrics`. |
| `alerts.create`, `alerts.update`, `alerts.delete` | Manage alert rules. |
| `sshkeys.sync` | Sync the member's own SSH keys. |
| `users.manage` | Rename other members and manage their devices. |
| `invites.manage` | Create and revoke invites for new members. |
| `invites.device` | Create second-device invites for the member's own user. |

New members start with `metrics.read`, `metrics.commands.read`, `alerts.read` (all metrics), `sshkeys.sync`, and `invites.device`. Changes are written to the audit log (`permission_changed`).

| Flag | Type | Default | Description |
|------|------|---------|-------------|
| `--metrics` | list | none | For `alerts.read` only: limit the grant to these metric IDs (comma-separated). Without it the member receives alerts for every metric. |

**Examples:**

```bash
pcmd grant bob invites.manage
pcmd grant bob alerts.read --metrics custom:req-1a2b3c4d5e6f7a8b
pcmd grant alice metrics.commands.create
```

---

### `pcmd revoke-permission <user-or-name> <permission>`

Take one permission away from a member, or `metrics.commands.create` from an admin (keys as for `grant`). Written to the audit log.

**Example:**

```bash
pcmd revoke-permission bob invites.manage
```

---

### `pcmd vaults`

List the shared vaults the server knows about (through their access lists; the contents are ciphertext the server cannot read) with the number of members holding access. Prints `No shared vaults.` when there are none.

| Flag | Type | Default | Description |
|------|------|---------|-------------|
| `--json` | bool | `false` | Print a JSON array (`vault_id`, `members`). |

**Example:**

```bash
pcmd vaults
# VAULT_ID                                  MEMBERS
# 3f9c1e2a-...                              3
```

---

### `pcmd vault-members <vault-id>`

List who has access to a vault and at which level: `view`, `edit`, or `manage` (manage includes granting access and changing membership).

| Flag | Type | Default | Description |
|------|------|---------|-------------|
| `--json` | bool | `false` | Print a JSON array (`user_id`, `display_name`, `role`, `level`). |

**Example:**

```bash
pcmd vault-members 3f9c1e2a-...
# USER_ID         NAME                  ROLE      LEVEL
# k7f3m9q2w8xz    Alice                 owner     manage
# p4n8r2t6y1vb    Bob                   member    view
```

---

### `pcmd requests`

List the custom-command metric requests members have filed from the app: ID, status (`pending`, `approved`, `declined`), label, requester, creation time, and the command. A request is a proposal: nothing runs until it is approved, and approving it makes the server execute the command on this host on a schedule. In the app, the owner and the admins and members the owner granted `metrics.commands.create` approve; this CLI acts as the operator (shell access already owns the host). Every decision is written to the audit log (`metric_request_approved` / `metric_request_declined`, `decided_by: cli`).

| Flag | Type | Default | Description |
|------|------|---------|-------------|
| `--json` | bool | `false` | Print a JSON array of the request records. |

**Example:**

```bash
pcmd requests
pcmd requests --json
```

### `pcmd requests approve <request-id>`

Approve a pending request. The command is added to the monitoring config and the running service starts collecting it on its next config reload. Already-decided requests are refused.

```bash
pcmd requests approve req-1a2b3c4d5e6f7a8b
```

### `pcmd requests decline <request-id>`

Decline a pending request. The requester sees the decision in the app; nothing runs.

```bash
pcmd requests decline req-1a2b3c4d5e6f7a8b
```

---

## Configuration and audit

### `pcmd config`

Read `~/.pocketcmd/config.json`. Without a subcommand it prints its help. Nothing in the file is settable from the CLI: the values are chosen on the first run, and push notifications have no server-side switch (every device whose user allowed notifications in the app is notified).

```bash
pcmd config get
```

### `pcmd config get`

Print the saved configuration: `service_mode`, `port`, `host`, and `advertise_ip` (defaults are shown when a value is unset).

| Flag | Type | Default | Description |
|------|------|---------|-------------|
| `--json` | bool | `false` | Print the config file as JSON. |

```bash
pcmd config get
pcmd config get --json
```

### `pcmd audit`

Print the newest entries of `~/.pocketcmd/audit.log` (pairings, invites, role and permission changes, device removals, metric command approvals, SSH config exports), oldest first, in the same `time LEVEL event key=value ...` form as `logs`. Prints `No audit log yet.` when nothing has been recorded.

| Flag | Type | Default | Description |
|------|------|---------|-------------|
| `-f`, `--follow` | bool | `false` | Keep printing new entries until Ctrl+C. |
| `-n`, `--lines` | int | `50` | Number of recent entries to show. |
| `--since` | duration | none | Only entries newer than this. |
| `--json` | bool | `false` | Print the raw JSON entries, one per line. |

```bash
pcmd audit
pcmd audit -f
pcmd audit --since 24h --json
```

---

## Flags

### `pcmd` global flags

These flags are accepted by every command.

#### `-p, --port <int>`

Server listen port. The value chosen on the first run is saved in `config.json` and used by every later command unless the flag is passed again.

- **Default:** `8767`
- **Example:** `pcmd --port 9000`

#### `--host <string>`

Bind address for the HTTPS server: an IP address of this machine, or `0.0.0.0` / `::` for every interface; hostnames are rejected. The server never listens on every interface unless asked to. Saved on the first run like `--port`; the QR code carries this address unless `--advertise-ip` overrides it.

- **Default:** the interface picked on the first run (the wizard asks when there is more than one; `--non-interactive` takes the first LAN address)
- **Example:** `pcmd --host 10.8.0.1`, or `pcmd --host 0.0.0.0` for every interface

#### `--no-qr`

Never draw QR codes; print the pairing/invite URL only. For logs, scripts, and terminals that cannot show one.

- **Default:** `false`
- **Example:** `pcmd invite --no-qr`

#### `--qr-invert`

Swap the dark and light modules of the QR code. Only needed on a dark terminal without colour support, where the code would otherwise appear inverted (see [QR codes](#qr-codes)).

- **Default:** `false`
- **Example:** `pcmd --qr-invert`

### Per-command flags

`--foreground`, `--pair-timeout`, `--advertise-ip`, `--debug-log`, and `--non-interactive` belong to the commands that use them (the first run, `sync`, `invite`, `rotate-server-cert`, and the confirming commands) and are listed in their sections. `--json` and `-y`/`--yes` likewise.

### Development overrides

Not user settings; they exist for working on the server and its tests.

| Variable | Purpose |
|----------|---------|
| `PCMD_PUSH_RELAY_URL` | Point the push client at a relay other than the hosted `https://push.pocketcmd.com` (an absolute `https` URL, or `http` on localhost; no credentials, query, or fragment). Read once at startup; the server logs a warning while a non-default relay is in use, and ignores an override that fails the rule. The relay is not configurable for real installs: the app registers its device token with the hosted relay, so no other relay can deliver a push. |

---

## QR codes

Every QR code is drawn on the terminal with half-block characters and, when stdout is a colour terminal (`NO_COLOR` unset, `TERM` not `dumb`), with an explicit black-on-white colour pair so that it reads correctly on light and dark terminal themes alike. Over SSH (`SSH_TTY` set) or in a locale that is not UTF-8 (`LC_ALL`/`LC_CTYPE`/`LANG`) the code is drawn in plain ASCII (`##` per module) instead. On a terminal too narrow for the code the URL is printed with a one-line note instead of a wrapped, unscannable code. `--no-qr` always prints the URL only.

---

## Pairing Flow

The QR code encodes a `pocketcmd://` deep link:

```
pocketcmd://<host>:<port>/<pairing_token>#<server_fingerprint>
```

- `host` -- the advertised address; IPv6 literals are bracketed (`[fd00::1]`), both here and in the `?host=` form of the invite and sync URLs
- `pairing_token` -- 32 hex chars, one-time use, 60-second TTL
- `server_fingerprint` -- SHA-256 of server cert (for pinning during pairing)

Three ways to pair:

1. **QR scan** -- Scan from the PocketCmd app's camera (primary method)
2. **Copy-paste URL** -- Copy the `pocketcmd://` URL and paste into the app's "Add Server" screen
3. **Deep link tap** -- Tap the `pocketcmd://` URL if the terminal supports clickable links

After pairing, the device has a device-bound key identity registered on the server (the app stores its EC key in the platform keystore). Certificates auto-renew every 30 minutes. JWTs auto-renew every 5 minutes.

The interfaces the first run offers are the machine's IPv4 addresses followed by its global-unicast IPv6 addresses (link-local addresses are skipped); the server listens on the one picked.

---

## Certificate Renewal

Certificates are short-lived (30-minute TTL) and auto-renewed by the mobile app.

**Standard renewal** (cert still valid or within the 10-minute grace period):
1. Device sends `POST /api/cert/renew` with a CSR signed by its device identity key
2. Server verifies CSR signature matches stored public key
3. Server issues a new 30-minute cert

**Challenge-response fallback** (cert expired beyond grace period):
1. Device sends `POST /api/cert/challenge` with its public key
2. Server responds with a 30-second nonce
3. Device signs the nonce with its device identity key
4. Device sends `POST /api/cert/renew` with the signed challenge and CSR
5. Server verifies and issues a new cert

---

## JWT Sessions

Session JWTs are issued via `POST /api/session` (requires valid mTLS cert). JWTs are channel-bound to the client certificate fingerprint via the `cnf` claim. A stolen JWT without the corresponding cert is useless.

- **TTL:** 5 minutes
- **Transport:** `Authorization: Bearer <jwt>` header
- **Claims:** `sub` (device ID), `iss` (pocketcmd), `exp`, `iat`, `cnf` (cert fingerprint)

---

## Monitoring

The server collects metrics, evaluates alert rules, and sends push notifications when thresholds are breached. It has **no built-in metrics**: every metric is a command somebody on the team added and an approver accepted, and a server with no approved commands runs nothing and stores nothing. Monitoring is configured per-server from the mobile app.

### Custom Metrics

A metric executes a shell command and parses the first numeric value from stdout; its ID is `custom:<request-id>`. Members propose commands from the mobile app; the owner, or an admin or member the owner granted `metrics.commands.create`, approves them in the app, or the operator with `pcmd requests approve`. Commands are subject to a 10-second timeout and 64KB output limit.

### Alert Rules

Each metric can have alert rules with `greater` or `less` operators and a numeric threshold. A rule pushes when a sample first crosses its threshold, then at most once an hour while the breach lasts. When the value returns to normal the rule re-arms, but it never pushes twice within 10 minutes, so a metric that flaps around its threshold sends at most one notification every 10 minutes.

---

## Files

| Path | Purpose |
|------|---------|
| `~/.pocketcmd/state.db` | Consolidated SQLite database: devices, users, invites, metric requests, push registrations, monitoring config, encrypted sync records, and the structured log tail (`pcmd logs`) |
| `~/.pocketcmd/metrics.db` | SQLite time-series metric storage |
| `~/.pocketcmd/audit.log` | Audit log, JSON lines (`pcmd audit`) |
| `~/.pocketcmd/server.log` | stdout/stderr of the launchd service (macOS); on systemd that output is in the journal |
| `~/.pocketcmd/tls/server.crt` | Persistent server TLS certificate |
| `~/.pocketcmd/tls/server.key` | Server TLS private key (ECDSA P-256) |
| `~/.pocketcmd/config.json` | Server config: `service_mode`, `port`, `host`, and `advertise_ip` |
| `~/.config/systemd/user/pocketcmd.service` | Linux systemd service file |
| `/etc/init.d/pocketcmd` | Linux OpenRC init script (only when systemd is absent; written as root) |
| `~/Library/LaunchAgents/com.pocketcmd.server.plist` | macOS launchd service file |
