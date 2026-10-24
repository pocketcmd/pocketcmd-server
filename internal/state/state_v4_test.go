package state

import (
	"context"
	"database/sql"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func openRawV3(t *testing.T, dir string) *sql.DB {
	t.Helper()
	raw, err := sql.Open("sqlite", "file:"+filepath.Join(dir, DBFileName)+
		"?_txlock=immediate&_pragma=busy_timeout(5000)&_pragma=foreign_keys(1)")
	if err != nil {
		t.Fatal(err)
	}
	for v := 0; v < 3; v++ {
		tx, err := raw.Begin()
		if err != nil {
			t.Fatal(err)
		}
		if err := migrations[v](tx); err != nil {
			t.Fatalf("apply v%d: %v", v+1, err)
		}
		if err := tx.Commit(); err != nil {
			t.Fatal(err)
		}
	}
	if _, err := raw.Exec(`PRAGMA user_version = 3`); err != nil {
		t.Fatal(err)
	}
	return raw
}

func TestMigrate_V4DevicesAdmitLeft(t *testing.T) {
	dir := t.TempDir()
	raw := openRawV3(t, dir)

	if _, err := raw.Exec(`UPDATE devices SET status='left'`); err != nil {
		t.Fatalf("no-op update on empty v3 table: %v", err)
	}
	seed := []string{
		`INSERT INTO users (user_id, display_name, role, created_at)
			VALUES ('u1', 'alice', 'admin', '2026-01-01T00:00:00Z')`,
		`INSERT INTO devices (device_id, public_key, device_name, device_label, status,
			user_id, paired_at, revoked_at, last_seen_at)
			VALUES ('d-active', 'PEM-A', 'phone', 'Alice phone', 'active',
			'u1', '2026-01-02T00:00:00Z', '', '2026-01-03T00:00:00Z')`,
		`INSERT INTO devices (device_id, public_key, device_name, device_label, status,
			user_id, paired_at, revoked_at, last_seen_at)
			VALUES ('d-revoked', 'PEM-R', 'tablet', '', 'revoked',
			'u1', '2026-01-02T00:00:00Z', '2026-01-04T00:00:00Z', '')`,
		`INSERT INTO push_registrations (device_id, device_token, platform, signed_token,
			expires_at, updated_at) VALUES ('d-active', 'tok', 'android', 'sig', 1, 1)`,
	}
	for _, stmt := range seed {
		if _, err := raw.Exec(stmt); err != nil {
			t.Fatalf("seed (%.40s...): %v", stmt, err)
		}
	}
	if _, err := raw.Exec(`UPDATE devices SET status='left' WHERE device_id='d-active'`); err == nil {
		t.Fatal("v3 schema must reject status 'left' (otherwise this test proves nothing)")
	}
	if err := raw.Close(); err != nil {
		t.Fatal(err)
	}

	db, err := Open(dir)
	if err != nil {
		t.Fatalf("Open on v3 database: %v", err)
	}
	defer db.Close()

	var v int
	if err := db.QueryRow("PRAGMA user_version").Scan(&v); err != nil {
		t.Fatal(err)
	}
	if v != len(migrations) || v < 4 {
		t.Fatalf("user_version=%d, want %d (>=4)", v, len(migrations))
	}

	type devRow struct{ id, pub, name, label, status, user, paired, revoked, seen string }
	rows, err := db.Query(`SELECT ` + devicesColumnList + ` FROM devices ORDER BY device_id`)
	if err != nil {
		t.Fatal(err)
	}
	var got []devRow
	for rows.Next() {
		var d devRow
		if err := rows.Scan(&d.id, &d.pub, &d.name, &d.label, &d.status, &d.user,
			&d.paired, &d.revoked, &d.seen); err != nil {
			t.Fatal(err)
		}
		got = append(got, d)
	}
	rows.Close()
	want := []devRow{
		{"d-active", "PEM-A", "phone", "Alice phone", "active", "u1", "2026-01-02T00:00:00Z", "", "2026-01-03T00:00:00Z"},
		{"d-revoked", "PEM-R", "tablet", "", "revoked", "u1", "2026-01-02T00:00:00Z", "2026-01-04T00:00:00Z", ""},
	}
	if len(got) != len(want) {
		t.Fatalf("devices after migrate: %+v", got)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Errorf("device %d: got %+v, want %+v", i, got[i], want[i])
		}
	}

	var regs int
	if err := db.QueryRow(`SELECT COUNT(*) FROM push_registrations`).Scan(&regs); err != nil || regs != 1 {
		t.Fatalf("push_registrations after migrate: n=%d err=%v (the devices rebuild cascaded)", regs, err)
	}

	if _, err := db.Exec(`UPDATE devices SET status='left' WHERE device_id='d-active'`); err != nil {
		t.Fatalf("status 'left' rejected after v4: %v", err)
	}
	if _, err := db.Exec(`UPDATE devices SET status='bogus' WHERE device_id='d-active'`); err == nil {
		t.Fatal("the CHECK constraint must still reject unknown statuses")
	}

	var idx string
	if err := db.QueryRow(`SELECT name FROM sqlite_master WHERE type='index' AND name='idx_devices_user'`).Scan(&idx); err != nil {
		t.Fatalf("idx_devices_user missing after v4: %v", err)
	}

	ctx := context.Background()
	conns := make([]*sql.Conn, 0, 4)
	for i := 0; i < 4; i++ {
		c, err := db.Conn(ctx)
		if err != nil {
			t.Fatal(err)
		}
		conns = append(conns, c)
		var on int
		if err := c.QueryRowContext(ctx, "PRAGMA foreign_keys").Scan(&on); err != nil || on != 1 {
			t.Fatalf("connection %d: foreign_keys=%d err=%v", i, on, err)
		}
	}
	for _, c := range conns {
		c.Close()
	}

	if _, err := db.Exec(`INSERT INTO push_registrations (device_id, device_token, platform,
		signed_token, expires_at, updated_at) VALUES ('nope', 't', 'ios', 's', 1, 1)`); err == nil {
		t.Fatal("push registration for an unknown device must violate the FK")
	}
	if _, err := db.Exec(`DELETE FROM devices WHERE device_id='d-active'`); err != nil {
		t.Fatal(err)
	}
	if err := db.QueryRow(`SELECT COUNT(*) FROM push_registrations`).Scan(&regs); err != nil || regs != 0 {
		t.Fatalf("hard delete must cascade to push_registrations: n=%d err=%v", regs, err)
	}
}

func TestMigrate_FreshDBDevicesAdmitLeft(t *testing.T) {
	db, err := Open(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	if _, err := db.Exec(`INSERT INTO devices (device_id, public_key, status, user_id, paired_at)
		VALUES ('d1', 'PEM', 'left', 'u1', '2026-01-01T00:00:00Z')`); err != nil {
		t.Fatalf("fresh devices table rejects 'left': %v", err)
	}
}

func TestForeignKeyCheck_FlagsDanglingRows(t *testing.T) {
	db, err := Open(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	ctx := context.Background()
	conn, err := db.Conn(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	if _, err := conn.ExecContext(ctx, "PRAGMA foreign_keys = OFF"); err != nil {
		t.Fatal(err)
	}
	defer conn.ExecContext(ctx, "PRAGMA foreign_keys = ON")
	tx, err := conn.BeginTx(ctx, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer tx.Rollback()
	if err := foreignKeyCheck(tx); err != nil {
		t.Fatalf("clean database flagged: %v", err)
	}
	if _, err := tx.Exec(`INSERT INTO push_registrations (device_id, device_token, platform,
		signed_token, expires_at, updated_at) VALUES ('ghost', 't', 'ios', 's', 1, 1)`); err != nil {
		t.Fatal(err)
	}
	err = foreignKeyCheck(tx)
	if err == nil || !strings.Contains(err.Error(), "push_registrations") {
		t.Fatalf("dangling push registration not flagged: %v", err)
	}
}

func TestMigrate_SnapshotsBeforeUpgrade(t *testing.T) {
	dir := t.TempDir()
	dbPath := filepath.Join(dir, DBFileName)
	raw := openRawV3(t, dir)
	if _, err := raw.Exec(`INSERT INTO users (user_id, display_name, role, created_at)
		VALUES ('u1', 'alice', 'admin', '2026-01-01T00:00:00Z')`); err != nil {
		t.Fatal(err)
	}
	if err := raw.Close(); err != nil {
		t.Fatal(err)
	}
	stale := dbPath + ".v1.bak"
	if err := os.WriteFile(stale, []byte("old"), 0600); err != nil {
		t.Fatal(err)
	}

	db, err := Open(dir)
	if err != nil {
		t.Fatal(err)
	}
	db.Close()

	snap := dbPath + ".v3.bak"
	info, err := os.Stat(snap)
	if err != nil {
		t.Fatalf("no snapshot before migrating from v3: %v", err)
	}
	if perm := info.Mode().Perm(); perm != 0600 {
		t.Errorf("snapshot mode %o, want 600", perm)
	}
	if _, err := os.Stat(stale); !os.IsNotExist(err) {
		t.Errorf("older snapshot not pruned: %v", err)
	}
	snapDB, err := sql.Open("sqlite", "file:"+snap+"?mode=ro")
	if err != nil {
		t.Fatal(err)
	}
	defer snapDB.Close()
	var v, users int
	if err := snapDB.QueryRow("PRAGMA user_version").Scan(&v); err != nil || v != 3 {
		t.Fatalf("snapshot user_version=%d err=%v, want 3", v, err)
	}
	if err := snapDB.QueryRow("SELECT COUNT(*) FROM users").Scan(&users); err != nil || users != 1 {
		t.Fatalf("snapshot users=%d err=%v, want 1", users, err)
	}

	if err := os.Remove(snap); err != nil {
		t.Fatal(err)
	}
	db, err = Open(dir)
	if err != nil {
		t.Fatal(err)
	}
	db.Close()
	if _, err := os.Stat(snap); !os.IsNotExist(err) {
		t.Errorf("a database already at the latest schema must not be snapshotted: %v", err)
	}
}
