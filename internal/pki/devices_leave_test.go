package pki

import (
	"database/sql"
	"errors"
	"io/fs"
	"testing"

	"github.com/pocketcmd/pocketcmd-server/internal/testutil"
)

func pushRegCount(t *testing.T, db *sql.DB, deviceID string) int {
	t.Helper()
	var n int
	if err := db.QueryRow(`SELECT COUNT(*) FROM push_registrations WHERE device_id=?`, deviceID).Scan(&n); err != nil {
		t.Fatal(err)
	}
	return n
}

func addPushReg(t *testing.T, db *sql.DB, deviceID string) {
	t.Helper()
	if _, err := db.Exec(`INSERT INTO push_registrations (device_id, device_token, platform,
		signed_token, expires_at, updated_at) VALUES (?, 'tok', 'android', 'sig', 1, 1)`, deviceID); err != nil {
		t.Fatal(err)
	}
}

func TestDeviceRegistry_Leave(t *testing.T) {
	db := testStateDB(t)
	reg := NewDeviceRegistry(db)
	pub := testutil.ECDSAPubKeyPEM(t)
	id, err := reg.RegisterDeviceForUser(pub, "phone", "u1", "")
	if err != nil {
		t.Fatal(err)
	}
	addPushReg(t, db, id)

	if err := reg.Leave(id); err != nil {
		t.Fatalf("leave: %v", err)
	}
	rec, _ := reg.FindByID(id)
	if rec.Status != DeviceStatusLeft || rec.RevokedAt == "" {
		t.Fatalf("leave didn't stick: %+v", rec)
	}
	if reg.IsAllowedByPubKey(pub) {
		t.Fatal("a left device must not pass the registry gate")
	}
	if n := pushRegCount(t, db, id); n != 0 {
		t.Fatalf("leave must drop the push registration, %d left", n)
	}
	if err := reg.Leave(id); err != nil {
		t.Fatalf("idempotent leave must succeed: %v", err)
	}
	if err := reg.Leave("ffffffffffffffff"); err != nil {
		t.Fatalf("leave of an unknown device must be a no-op: %v", err)
	}
}

func TestDeviceRegistry_LeaveNeverDowngradesRevoked(t *testing.T) {
	reg := NewDeviceRegistry(testStateDB(t))
	id, _ := reg.RegisterDeviceForUser(testutil.ECDSAPubKeyPEM(t), "d", "u1", "")
	if err := reg.Revoke(id); err != nil {
		t.Fatal(err)
	}
	if err := reg.Leave(id); err != nil {
		t.Fatal(err)
	}
	if rec, _ := reg.FindByID(id); rec.Status != DeviceStatusRevoked {
		t.Fatalf("leave turned a revoked device into %q", rec.Status)
	}
}

func TestDeviceRegistry_RevokeEscalatesLeft(t *testing.T) {
	reg := NewDeviceRegistry(testStateDB(t))
	id, _ := reg.RegisterDeviceForUser(testutil.ECDSAPubKeyPEM(t), "d", "u1", "")
	if err := reg.Leave(id); err != nil {
		t.Fatal(err)
	}
	if err := reg.Revoke(id); err != nil {
		t.Fatal(err)
	}
	if rec, _ := reg.FindByID(id); rec.Status != DeviceStatusRevoked {
		t.Fatalf("revoke of a left device: status %q, want revoked", rec.Status)
	}
	err := reg.Reactivate(id, "u2", "x", "", nil)
	if !errors.Is(err, ErrDeviceNotLeft) {
		t.Fatalf("a revoked device must never reactivate, got %v", err)
	}
}

func TestDeviceRegistry_Reactivate(t *testing.T) {
	db := testStateDB(t)
	reg := NewDeviceRegistry(db)
	pub := testutil.ECDSAPubKeyPEM(t)
	id, _ := reg.RegisterDeviceForUser(pub, "old-name", "u-old", "old-label")
	if err := reg.TouchLastSeen(id, 0); err != nil {
		t.Fatal(err)
	}
	if err := reg.Leave(id); err != nil {
		t.Fatal(err)
	}

	other, _ := reg.RegisterDeviceForUser(testutil.ECDSAPubKeyPEM(t), "o", "u-old", "")
	if err := reg.Reactivate(other, "u-new", "n", "", nil); !errors.Is(err, ErrDeviceNotLeft) {
		t.Fatalf("active device: got %v, want ErrDeviceNotLeft", err)
	}
	if err := reg.Reactivate("ffffffffffffffff", "u-new", "n", "", nil); !errors.Is(err, fs.ErrNotExist) {
		t.Fatalf("unknown device: got %v, want fs.ErrNotExist", err)
	}

	boom := errors.New("boom")
	if err := reg.Reactivate(id, "u-new", "n", "", func(*sql.Tx, string) error { return boom }); !errors.Is(err, boom) {
		t.Fatalf("prepare error not propagated: %v", err)
	}
	if rec, _ := reg.FindByID(id); rec.Status != DeviceStatusLeft || rec.UserID != "u-old" {
		t.Fatalf("failed prepare must leave the device untouched: %+v", rec)
	}

	var sawPrevious string
	err := reg.Reactivate(id, "u-new", "new-name", "new-label", func(tx *sql.Tx, prev string) error {
		sawPrevious = prev
		var status string
		if err := tx.QueryRow(`SELECT status FROM devices WHERE device_id=?`, id).Scan(&status); err != nil {
			return err
		}
		if status != DeviceStatusLeft {
			t.Errorf("prepare saw status %q, want left", status)
		}
		return nil
	})
	if err != nil {
		t.Fatalf("reactivate: %v", err)
	}
	if sawPrevious != "u-old" {
		t.Fatalf("prepare got previous user %q, want u-old", sawPrevious)
	}
	rec, _ := reg.FindByID(id)
	if rec.Status != DeviceStatusActive || rec.UserID != "u-new" ||
		rec.DeviceName != "new-name" || rec.DeviceLabel != "new-label" ||
		rec.RevokedAt != "" || rec.LastSeenAt != "" {
		t.Fatalf("reactivated record: %+v", rec)
	}
	if !reg.IsAllowedByPubKey(pub) {
		t.Fatal("a reactivated device must pass the registry gate again")
	}
	if err := reg.Reactivate(id, "u-third", "n", "", nil); !errors.Is(err, ErrDeviceNotLeft) {
		t.Fatalf("second reactivation: got %v, want ErrDeviceNotLeft", err)
	}
}

func TestDeviceRegistry_ScrubUserDevicesCoversLeft(t *testing.T) {
	reg := NewDeviceRegistry(testStateDB(t))
	left, _ := reg.RegisterDeviceForUser(testutil.ECDSAPubKeyPEM(t), "left-phone", "u1", "L")
	active, _ := reg.RegisterDeviceForUser(testutil.ECDSAPubKeyPEM(t), "active-tab", "u1", "A")
	if err := reg.Leave(left); err != nil {
		t.Fatal(err)
	}
	if err := reg.ScrubUserDevices("u1"); err != nil {
		t.Fatal(err)
	}
	if rec, _ := reg.FindByID(left); rec.DeviceName != "" || rec.DeviceLabel != "" {
		t.Fatalf("left device not scrubbed: %+v", rec)
	}
	if rec, _ := reg.FindByID(active); rec.DeviceName != "active-tab" {
		t.Fatalf("active device must not be scrubbed: %+v", rec)
	}
}
