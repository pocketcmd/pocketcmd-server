package state

import (
	"database/sql"
	"errors"
	"fmt"
	"path/filepath"
	"strings"
	"testing"
)

func TestMigrate_FreshDBReachesLatest(t *testing.T) {
	dir := t.TempDir()
	db, err := Open(dir)
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	if snaps, _ := filepath.Glob(filepath.Join(dir, "*.bak")); len(snaps) != 0 {
		t.Fatalf("a fresh database has nothing to snapshot, got %v", snaps)
	}
	var v int
	if err := db.QueryRow("PRAGMA user_version").Scan(&v); err != nil {
		t.Fatal(err)
	}
	if v != len(migrations) {
		t.Fatalf("user_version=%d, want %d", v, len(migrations))
	}
	if v != 7 {
		t.Fatalf("user_version=%d, want 7 (v2 = server_logs ts rebuild, v3 = idx_sync_id, v4 = devices.status 'left', v5 = alert_state, v6 = no built-in metrics, v7 = owner-granted create)", v)
	}
	if _, err := db.Exec(`SELECT 1 FROM monitored_builtins`); err == nil {
		t.Fatal("monitored_builtins must be gone after v6")
	}
	if _, err := db.Exec(`INSERT INTO alert_rules (id, custom_id, threshold, operator)
		VALUES ('orphan', NULL, 1, 'greater')`); err == nil {
		t.Fatal("alert_rules.custom_id must be NOT NULL after v6")
	}
	if _, err := db.Exec(`INSERT INTO alert_state (rule_id, last_fired, episode_fired, breached, updated_at)
		VALUES ('r1', 1, 1, 1, 1)`); err != nil {
		t.Fatalf("alert_state missing after Open: %v", err)
	}
	var idx string
	if err := db.QueryRow(`SELECT name FROM sqlite_master WHERE type='index' AND name='idx_sync_id'`).Scan(&idx); err != nil {
		t.Fatalf("idx_sync_id missing after Open: %v", err)
	}
	if _, err := db.Exec(
		`INSERT INTO server_logs (ts, entry) VALUES (1650000000000, '{"msg":"x"}')`); err != nil {
		t.Fatalf("insert with ts after fresh migrate: %v", err)
	}
}

func TestMigrate_Idempotent(t *testing.T) {
	dir := t.TempDir()
	for i := 0; i < 3; i++ {
		db, err := Open(dir)
		if err != nil {
			t.Fatalf("open #%d: %v", i+1, err)
		}
		db.Close()
	}
}

func TestMigrate_V1ServerLogsGainsTs(t *testing.T) {
	dir := t.TempDir()

	raw, err := sql.Open("sqlite", "file:"+filepath.Join(dir, DBFileName))
	if err != nil {
		t.Fatal(err)
	}
	for _, stmt := range schemaV1 {
		if stmt == serverLogsDDL {
			stmt = `CREATE TABLE IF NOT EXISTS server_logs (
				id    INTEGER PRIMARY KEY AUTOINCREMENT,
				entry TEXT NOT NULL
			)`
		}
		if _, err := raw.Exec(stmt); err != nil {
			t.Fatalf("v1 schema (%.40s...): %v", stmt, err)
		}
	}
	seed := []string{
		`INSERT INTO server_logs (entry) VALUES ('{"msg":"pre-ts"}')`,
		`INSERT INTO users (user_id, display_name, role, created_at)
			VALUES ('u1', 'alice', 'admin', '2026-01-01T00:00:00Z')`,
		`PRAGMA user_version = 1`,
	}
	for _, stmt := range seed {
		if _, err := raw.Exec(stmt); err != nil {
			t.Fatalf("seed (%.40s...): %v", stmt, err)
		}
	}
	if err := raw.Close(); err != nil {
		t.Fatal(err)
	}

	db, err := Open(dir)
	if err != nil {
		t.Fatalf("Open on v1 database: %v", err)
	}
	defer db.Close()
	var v int
	if err := db.QueryRow("PRAGMA user_version").Scan(&v); err != nil {
		t.Fatal(err)
	}
	if v != len(migrations) {
		t.Fatalf("user_version=%d, want %d", v, len(migrations))
	}

	var users int
	if err := db.QueryRow(`SELECT COUNT(*) FROM users`).Scan(&users); err != nil || users != 1 {
		t.Fatalf("users after migrate: n=%d err=%v", users, err)
	}

	var logs int
	if err := db.QueryRow(`SELECT COUNT(*) FROM server_logs`).Scan(&logs); err != nil || logs != 0 {
		t.Fatalf("server_logs after rebuild: n=%d err=%v", logs, err)
	}
	if _, err := db.Exec(
		`INSERT INTO server_logs (ts, entry) VALUES (1650000000000, '{"msg":"post-ts"}')`); err != nil {
		t.Fatalf("insert with ts after migrate: %v", err)
	}
	if _, err := db.Exec(
		`INSERT INTO server_logs (entry) VALUES ('{"msg":"no-ts"}')`); err == nil {
		t.Fatal("insert without ts must fail (ts NOT NULL)")
	}
}

func TestMigrate_V5DropsBuiltinRules(t *testing.T) {
	dir := t.TempDir()
	raw, err := sql.Open("sqlite", "file:"+filepath.Join(dir, DBFileName))
	if err != nil {
		t.Fatal(err)
	}
	for _, stmt := range schemaV1 {
		if _, err := raw.Exec(stmt); err != nil {
			t.Fatalf("v1 schema (%.40s...): %v", stmt, err)
		}
	}
	seed := []string{
		alertStateDDL,
		`INSERT INTO monitoring_settings (id, default_interval_seconds, retention_days, updated_at)
			VALUES (1, 30, 7, 1650000000000)`,
		`INSERT INTO monitored_builtins (type, enabled) VALUES ('cpu', 1)`,
		`INSERT INTO custom_metrics (id, label, command) VALUES ('req-1', 'Conns', 'ss -t | wc -l')`,
		`INSERT INTO alert_rules (id, builtin_type, custom_id, threshold, operator)
			VALUES ('b-rule', 'cpu', NULL, 90, 'greater')`,
		`INSERT INTO alert_rules (id, builtin_type, custom_id, metric_id_pin, threshold, operator)
			VALUES ('c-rule', NULL, 'req-1', 'custom:req-1', 100, 'less')`,
		`PRAGMA user_version = 5`,
	}
	for _, stmt := range seed {
		if _, err := raw.Exec(stmt); err != nil {
			t.Fatalf("seed (%.40s...): %v", stmt, err)
		}
	}
	if err := raw.Close(); err != nil {
		t.Fatal(err)
	}

	db, err := Open(dir)
	if err != nil {
		t.Fatalf("Open on v5 database: %v", err)
	}
	defer db.Close()

	var ids string
	if err := db.QueryRow(`SELECT group_concat(id || ':' || custom_id || ':' || metric_id_pin) FROM alert_rules`).Scan(&ids); err != nil {
		t.Fatal(err)
	}
	if ids != "c-rule:req-1:custom:req-1" {
		t.Fatalf("expected only the custom rule to survive, got %q", ids)
	}
	var n int
	if err := db.QueryRow(`SELECT COUNT(*) FROM custom_metrics`).Scan(&n); err != nil || n != 1 {
		t.Fatalf("custom_metrics after migrate: n=%d err=%v", n, err)
	}
	if err := db.QueryRow(`SELECT COUNT(*) FROM monitoring_settings`).Scan(&n); err != nil || n != 1 {
		t.Fatalf("monitoring_settings after migrate: n=%d err=%v", n, err)
	}
	if _, err := db.Exec(`DELETE FROM custom_metrics WHERE id='req-1'`); err != nil {
		t.Fatal(err)
	}
	if err := db.QueryRow(`SELECT COUNT(*) FROM alert_rules`).Scan(&n); err != nil || n != 0 {
		t.Fatalf("alert rule survived its metric's deletion: n=%d err=%v", n, err)
	}
}

func TestMigrate_V6StripsCreateGrants(t *testing.T) {
	dir := t.TempDir()
	raw, err := sql.Open("sqlite", "file:"+filepath.Join(dir, DBFileName))
	if err != nil {
		t.Fatal(err)
	}
	for _, stmt := range schemaV1 {
		if _, err := raw.Exec(stmt); err != nil {
			t.Fatalf("v1 schema (%.40s...): %v", stmt, err)
		}
	}
	seed := []string{
		`INSERT INTO users (user_id, display_name, role, owner, permissions, created_at) VALUES
			('owner1', 'Owner', 'admin', 1, '{"metrics.commands.create":{"granted":true}}', 't'),
			('admin1', 'Admin', 'admin', 0, '{"metrics.commands.create":{"granted":true},"alerts.read":{"granted":true,"metrics":["custom:a"]}}', 't'),
			('member1', 'Member', 'member', 0, '{"metrics.commands.create":{"granted":true},"invites.manage":{"granted":true}}', 't'),
			('member2', 'Plain', 'member', 0, '{"metrics.read":{"granted":true}}', 't'),
			('member3', 'Fresh', 'member', 0, '{}', 't')`,
		`PRAGMA user_version = 6`,
	}
	for _, stmt := range seed {
		if _, err := raw.Exec(stmt); err != nil {
			t.Fatalf("seed (%.40s...): %v", stmt, err)
		}
	}
	if err := raw.Close(); err != nil {
		t.Fatal(err)
	}

	db, err := Open(dir)
	if err != nil {
		t.Fatalf("Open on v6 database: %v", err)
	}
	defer db.Close()

	want := map[string]string{
		"owner1":  `{"metrics.commands.create":{"granted":true}}`,
		"admin1":  `{"alerts.read":{"granted":true,"metrics":["custom:a"]}}`,
		"member1": `{"invites.manage":{"granted":true}}`,
		"member2": `{"metrics.read":{"granted":true}}`,
		"member3": `{}`,
	}
	for id, exp := range want {
		var got string
		if err := db.QueryRow(`SELECT permissions FROM users WHERE user_id=?`, id).Scan(&got); err != nil {
			t.Fatal(err)
		}
		if got != exp {
			t.Errorf("%s: permissions after migrate = %s, want %s", id, got, exp)
		}
	}
}

func TestMigrate_NewerSchemaRefused(t *testing.T) {
	dir := t.TempDir()
	db, err := Open(dir)
	if err != nil {
		t.Fatal(err)
	}
	future := len(migrations) + 1
	if _, err := db.Exec("PRAGMA user_version = " + itoa(future)); err != nil {
		t.Fatal(err)
	}
	db.Close()

	_, err = Open(dir)
	if !errors.Is(err, ErrSchemaTooNew) {
		t.Fatalf("expected ErrSchemaTooNew, got %v", err)
	}
	if !strings.Contains(err.Error(), "newer pcmd") {
		t.Fatalf("error must tell the operator what to do: %v", err)
	}
	raw, err := sql.Open("sqlite", "file:"+filepath.Join(dir, DBFileName))
	if err != nil {
		t.Fatal(err)
	}
	defer raw.Close()
	var v int
	if err := raw.QueryRow("PRAGMA user_version").Scan(&v); err != nil || v != future {
		t.Fatalf("user_version=%d (%v), want %d", v, err, future)
	}
}

func itoa(n int) string { return fmt.Sprint(n) }
