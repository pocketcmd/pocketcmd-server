// Package state owns the server's consolidated SQLite database (state.db).
package state

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"os"
	"path/filepath"

	_ "modernc.org/sqlite"
)

var ErrSchemaTooNew = errors.New("state.db was written by a newer pcmd; upgrade the binary or restore an older backup")

const DBFileName = "state.db"

func Open(dir string) (*sql.DB, error) {
	if err := os.MkdirAll(dir, 0700); err != nil {
		return nil, fmt.Errorf("state dir: %w", err)
	}
	dbPath := filepath.Join(dir, DBFileName)
	dsn := "file:" + dbPath +
		"?_txlock=immediate" +
		"&_pragma=journal_mode(WAL)&_pragma=busy_timeout(5000)&_pragma=foreign_keys(1)"
	db, err := sql.Open("sqlite", dsn)
	if err != nil {
		return nil, fmt.Errorf("open state.db: %w", err)
	}
	// A sync push holds a transaction while its hooks read through the same handle, so the pool must be larger than one.
	db.SetMaxOpenConns(4)
	if err := migrate(db, dbPath); err != nil {
		db.Close()
		return nil, err
	}
	if err := restrictDBPerms(dbPath); err != nil {
		db.Close()
		return nil, err
	}
	return db, nil
}

func restrictDBPerms(dbPath string) error {
	if err := os.Chmod(dbPath, 0600); err != nil {
		return fmt.Errorf("chmod %s: %w", dbPath, err)
	}
	for _, sibling := range []string{dbPath + "-wal", dbPath + "-shm"} {
		if err := os.Chmod(sibling, 0600); err != nil && !os.IsNotExist(err) {
			return fmt.Errorf("chmod %s: %w", sibling, err)
		}
	}
	return nil
}

// Foreign keys are off for the whole run so table rebuilds do not cascade; foreignKeyCheck guards each commit.
func migrate(db *sql.DB, dbPath string) (retErr error) {
	ctx := context.Background()
	conn, err := db.Conn(ctx)
	if err != nil {
		return fmt.Errorf("migrate: acquire connection: %w", err)
	}
	defer conn.Close()
	if _, err := conn.ExecContext(ctx, "PRAGMA foreign_keys = OFF"); err != nil {
		return fmt.Errorf("migrate: disable foreign keys: %w", err)
	}
	defer func() {
		if _, err := conn.ExecContext(ctx, "PRAGMA foreign_keys = ON"); err != nil && retErr == nil {
			retErr = fmt.Errorf("migrate: re-enable foreign keys: %w", err)
		}
	}()

	var current int
	if err := conn.QueryRowContext(ctx, "PRAGMA user_version").Scan(&current); err != nil {
		return fmt.Errorf("read schema version: %w", err)
	}
	if current > len(migrations) {
		return fmt.Errorf("%w (schema v%d, this binary knows v%d)", ErrSchemaTooNew, current, len(migrations))
	}
	if current > 0 && current < len(migrations) {
		if err := snapshotBeforeMigrate(ctx, conn, dbPath, current); err != nil {
			return fmt.Errorf("migrate: snapshot v%d: %w", current, err)
		}
	}
	for v := current; v < len(migrations); v++ {
		tx, err := conn.BeginTx(ctx, nil)
		if err != nil {
			return fmt.Errorf("migrate to v%d: begin: %w", v+1, err)
		}
		if err := migrations[v](tx); err != nil {
			tx.Rollback()
			return fmt.Errorf("migrate to v%d: %w", v+1, err)
		}
		if err := foreignKeyCheck(tx); err != nil {
			tx.Rollback()
			return fmt.Errorf("migrate to v%d: %w", v+1, err)
		}
		if _, err := tx.Exec(fmt.Sprintf("PRAGMA user_version = %d", v+1)); err != nil {
			tx.Rollback()
			return fmt.Errorf("migrate to v%d: set version: %w", v+1, err)
		}
		if err := tx.Commit(); err != nil {
			return fmt.Errorf("migrate to v%d: commit: %w", v+1, err)
		}
	}
	return nil
}

// snapshotBeforeMigrate keeps state.db.v<N>.bak, readable by the release that
// wrote schema vN, so a failed update can roll back to it. Only the newest
// snapshot is kept.
func snapshotBeforeMigrate(ctx context.Context, conn *sql.Conn, dbPath string, version int) error {
	snap := fmt.Sprintf("%s.v%d.bak", dbPath, version)
	tmp := snap + ".tmp"
	os.Remove(tmp)
	// VACUUM INTO accepts an existing empty file; creating it first keeps it 0600.
	f, err := os.OpenFile(tmp, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0600)
	if err != nil {
		return err
	}
	f.Close()
	if _, err := conn.ExecContext(ctx, "VACUUM INTO ?", tmp); err != nil {
		os.Remove(tmp)
		return err
	}
	if err := os.Rename(tmp, snap); err != nil {
		os.Remove(tmp)
		return err
	}
	old, _ := filepath.Glob(dbPath + ".v*.bak")
	for _, p := range old {
		if p != snap {
			os.Remove(p)
		}
	}
	return nil
}

func foreignKeyCheck(tx *sql.Tx) error {
	rows, err := tx.Query("PRAGMA foreign_key_check")
	if err != nil {
		return fmt.Errorf("foreign_key_check: %w", err)
	}
	defer rows.Close()
	if rows.Next() {
		var table string
		var rowid sql.NullInt64
		var parent string
		var fkid int
		if err := rows.Scan(&table, &rowid, &parent, &fkid); err != nil {
			return fmt.Errorf("foreign_key_check: %w", err)
		}
		return fmt.Errorf("foreign key violation: %s row %d references missing %s", table, rowid.Int64, parent)
	}
	return rows.Err()
}

// Index i applies version i+1; never reorder or edit a released entry.
var migrations = []func(*sql.Tx) error{
	func(tx *sql.Tx) error {
		for _, stmt := range schemaV1 {
			if _, err := tx.Exec(stmt); err != nil {
				return fmt.Errorf("schema (%.40s...): %w", stmt, err)
			}
		}
		return nil
	},
	// v2: server_logs gains the ts column; the table is a disposable buffer, so it is dropped and recreated.
	func(tx *sql.Tx) error {
		if _, err := tx.Exec(`DROP TABLE IF EXISTS server_logs`); err != nil {
			return fmt.Errorf("drop server_logs: %w", err)
		}
		if _, err := tx.Exec(serverLogsDDL); err != nil {
			return fmt.Errorf("recreate server_logs: %w", err)
		}
		return nil
	},
	// v3: index sync_records(id) for pulls, which carry only ids.
	func(tx *sql.Tx) error {
		if _, err := tx.Exec(`CREATE INDEX IF NOT EXISTS idx_sync_id ON sync_records(id)`); err != nil {
			return fmt.Errorf("index sync_records(id): %w", err)
		}
		return nil
	},
	// v4: devices.status gains 'left'; the CHECK constraint forces a table rebuild.
	func(tx *sql.Tx) error {
		stmts := []string{
			`CREATE TABLE devices_v4 (` + devicesColumnsV4 + `)`,
			`INSERT INTO devices_v4 (` + devicesColumnList + `)
				SELECT ` + devicesColumnList + ` FROM devices`,
			`DROP TABLE devices`,
			`ALTER TABLE devices_v4 RENAME TO devices`,
			`CREATE INDEX IF NOT EXISTS idx_devices_user ON devices(user_id)`,
		}
		for _, stmt := range stmts {
			if _, err := tx.Exec(stmt); err != nil {
				return fmt.Errorf("rebuild devices (%.40s...): %w", stmt, err)
			}
		}
		return nil
	},
	// v5: alert_state persists the alert evaluator's per-rule episode and cooldown state.
	func(tx *sql.Tx) error {
		if _, err := tx.Exec(alertStateDDL); err != nil {
			return fmt.Errorf("create alert_state: %w", err)
		}
		return nil
	},
	// v6: drop the built-in metric catalog and rebuild alert_rules with custom_id NOT NULL.
	func(tx *sql.Tx) error {
		stmts := []string{
			`CREATE TABLE alert_rules_v6 (` + alertRulesColumnsV6 + `)`,
			`INSERT INTO alert_rules_v6 (id, custom_id, metric_id_pin, threshold, operator, position)
				SELECT id, custom_id, metric_id_pin, threshold, operator, position
				FROM alert_rules WHERE custom_id IS NOT NULL`,
			`DROP TABLE alert_rules`,
			`ALTER TABLE alert_rules_v6 RENAME TO alert_rules`,
			`DROP TABLE IF EXISTS monitored_builtins`,
		}
		for _, stmt := range stmts {
			if _, err := tx.Exec(stmt); err != nil {
				return fmt.Errorf("rebuild alert_rules (%.40s...): %w", stmt, err)
			}
		}
		return nil
	},
	// v7: strip metrics.commands.create from every non-owner user; it is now owner-granted.
	func(tx *sql.Tx) error {
		const key = `$."metrics.commands.create"`
		if _, err := tx.Exec(`UPDATE users SET permissions = json_remove(permissions, '` + key + `')
			WHERE owner = 0 AND json_type(permissions, '` + key + `') IS NOT NULL`); err != nil {
			return fmt.Errorf("strip metrics.commands.create from non-owner users: %w", err)
		}
		return nil
	},
}

const alertRulesColumnsV6 = `
		id            TEXT PRIMARY KEY,
		custom_id     TEXT NOT NULL REFERENCES custom_metrics(id) ON DELETE CASCADE,
		metric_id_pin TEXT NOT NULL DEFAULT '',
		threshold     REAL NOT NULL,
		operator      TEXT NOT NULL CHECK (operator IN ('greater','less')),
		position      INTEGER NOT NULL DEFAULT 0`

const alertStateDDL = `CREATE TABLE IF NOT EXISTS alert_state (
	rule_id       TEXT PRIMARY KEY,
	last_fired    INTEGER NOT NULL DEFAULT 0,
	episode_fired INTEGER NOT NULL DEFAULT 0,
	breached      INTEGER NOT NULL DEFAULT 0,
	updated_at    INTEGER NOT NULL
)`

const devicesColumnList = `device_id, public_key, device_name, device_label,
	status, user_id, paired_at, revoked_at, last_seen_at`

const devicesColumnsV4 = `
		device_id    TEXT PRIMARY KEY,
		public_key   TEXT NOT NULL,
		device_name  TEXT NOT NULL DEFAULT '',
		device_label TEXT NOT NULL DEFAULT '',
		status       TEXT NOT NULL DEFAULT 'active' CHECK (status IN ('active','revoked','left')),
		user_id      TEXT NOT NULL,
		paired_at    TEXT NOT NULL,
		revoked_at   TEXT NOT NULL DEFAULT '',
		last_seen_at TEXT NOT NULL DEFAULT ''`

const serverLogsDDL = `CREATE TABLE IF NOT EXISTS server_logs (
	id    INTEGER PRIMARY KEY AUTOINCREMENT,
	ts    INTEGER NOT NULL,
	entry TEXT NOT NULL
)`

var schemaV1 = []string{
	`CREATE TABLE IF NOT EXISTS users (
		user_id      TEXT PRIMARY KEY,
		display_name TEXT NOT NULL,
		role         TEXT NOT NULL CHECK (role IN ('admin','member')),
		status       TEXT NOT NULL DEFAULT 'active' CHECK (status IN ('active','revoked')),
		owner        INTEGER NOT NULL DEFAULT 0,
		permissions  TEXT NOT NULL DEFAULT '{}',
		created_at   TEXT NOT NULL,
		created_by   TEXT NOT NULL DEFAULT '',
		revoked_at   TEXT NOT NULL DEFAULT ''
	)`,
	// No FK to users: users are soft-deleted, so a cascade would never fire.
	`CREATE TABLE IF NOT EXISTS devices (
		device_id    TEXT PRIMARY KEY,
		public_key   TEXT NOT NULL,
		device_name  TEXT NOT NULL DEFAULT '',
		device_label TEXT NOT NULL DEFAULT '',
		status       TEXT NOT NULL DEFAULT 'active' CHECK (status IN ('active','revoked')),
		user_id      TEXT NOT NULL,
		paired_at    TEXT NOT NULL,
		revoked_at   TEXT NOT NULL DEFAULT '',
		last_seen_at TEXT NOT NULL DEFAULT ''
	)`,
	`CREATE INDEX IF NOT EXISTS idx_devices_user ON devices(user_id)`,
	`CREATE TABLE IF NOT EXISTS invites (
		code                  TEXT PRIMARY KEY,
		role                  TEXT NOT NULL,
		label                 TEXT NOT NULL DEFAULT '',
		target_user_id        TEXT NOT NULL DEFAULT '',
		pinned_fingerprint    TEXT NOT NULL DEFAULT '',
		created_by            TEXT NOT NULL DEFAULT '',
		created_at            TEXT NOT NULL,
		expires_at            TEXT NOT NULL,
		consumed_at           TEXT NOT NULL DEFAULT '',
		consumed_by_device_id TEXT NOT NULL DEFAULT '',
		expired_at            TEXT NOT NULL DEFAULT '',
		revoked_at            TEXT NOT NULL DEFAULT '',
		revoked_by            TEXT NOT NULL DEFAULT ''
	)`,

	`CREATE TABLE IF NOT EXISTS metric_requests (
		id                TEXT PRIMARY KEY,
		label             TEXT NOT NULL,
		command           TEXT NOT NULL,
		interval_override INTEGER,
		requested_by      TEXT NOT NULL DEFAULT '',
		status            TEXT NOT NULL DEFAULT 'pending' CHECK (status IN ('pending','approved','declined')),
		created_at        TEXT NOT NULL,
		decided_by        TEXT NOT NULL DEFAULT '',
		decided_at        TEXT NOT NULL DEFAULT ''
	)`,
	`CREATE TABLE IF NOT EXISTS monitoring_settings (
		id                       INTEGER PRIMARY KEY CHECK (id = 1),
		default_interval_seconds INTEGER NOT NULL,
		retention_days           INTEGER NOT NULL,
		server_id                TEXT NOT NULL DEFAULT '',
		schema_version           INTEGER NOT NULL DEFAULT 1,
		device_id                TEXT NOT NULL DEFAULT '',
		updated_at               INTEGER NOT NULL
	)`,
	`CREATE TABLE IF NOT EXISTS monitored_builtins (
		type              TEXT PRIMARY KEY,
		enabled           INTEGER NOT NULL DEFAULT 0,
		interval_override INTEGER,
		position          INTEGER NOT NULL DEFAULT 0
	)`,
	`CREATE TABLE IF NOT EXISTS custom_metrics (
		id                TEXT PRIMARY KEY,
		label             TEXT NOT NULL,
		command           TEXT NOT NULL,
		interval_override INTEGER,
		position          INTEGER NOT NULL DEFAULT 0,
		request_id        TEXT REFERENCES metric_requests(id) ON DELETE CASCADE
	)`,
	`CREATE TABLE IF NOT EXISTS alert_rules (
		id            TEXT PRIMARY KEY,
		builtin_type  TEXT REFERENCES monitored_builtins(type) ON DELETE CASCADE,
		custom_id     TEXT REFERENCES custom_metrics(id)      ON DELETE CASCADE,
		metric_id_pin TEXT NOT NULL DEFAULT '',
		threshold     REAL NOT NULL,
		operator      TEXT NOT NULL CHECK (operator IN ('greater','less')),
		position      INTEGER NOT NULL DEFAULT 0,
		CHECK ((builtin_type IS NULL) <> (custom_id IS NULL))
	)`,

	`CREATE TABLE IF NOT EXISTS push_registrations (
		device_id    TEXT PRIMARY KEY REFERENCES devices(device_id) ON DELETE CASCADE,
		device_token TEXT NOT NULL,
		platform     TEXT NOT NULL,
		signed_token TEXT NOT NULL,
		expires_at   INTEGER NOT NULL,
		updated_at   INTEGER NOT NULL
	)`,

	`CREATE TABLE IF NOT EXISTS sync_records (
		id TEXT NOT NULL,
		type TEXT NOT NULL,
		schema_version INTEGER DEFAULT 1,
		updated_at INTEGER NOT NULL,
		device_id TEXT DEFAULT '',
		deleted INTEGER DEFAULT 0,
		data TEXT DEFAULT '{}',
		credentials TEXT DEFAULT '',
		user_id TEXT NOT NULL DEFAULT '',
		vault_id TEXT NOT NULL DEFAULT '',
		PRIMARY KEY (type, id)
	)`,
	`CREATE INDEX IF NOT EXISTS idx_sync_updated_at ON sync_records(updated_at)`,
	`CREATE TABLE IF NOT EXISTS vault_acl (
		vault_id TEXT NOT NULL,
		user_id TEXT NOT NULL,
		level INTEGER NOT NULL,
		updated_at INTEGER NOT NULL,
		PRIMARY KEY (vault_id, user_id)
	)`,

	serverLogsDDL,
}

func BoolInt(b bool) int {
	if b {
		return 1
	}
	return 0
}
