package main

import (
	"encoding/json"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/pocketcmd/pocketcmd-server/internal/pki"
	"github.com/pocketcmd/pocketcmd-server/internal/testutil"
)

func TestRevokeDeviceEmptyRegistryExitsCleanly(t *testing.T) {
	testutil.TempHome(t)

	err := revokeDeviceCore(io.Discard, nil, false, true /* nonInteractive */)
	if err != nil {
		t.Fatalf("expected nil error on empty registry, got: %v", err)
	}
}

func TestRestoreNonInteractiveWithoutForceErrors(t *testing.T) {
	tmp := testutil.TempHome(t)
	noServer(t)
	if err := os.MkdirAll(filepath.Join(tmp, ".pocketcmd"), 0700); err != nil {
		t.Fatal(err)
	}

	archive := writeArchive(t, minimalBackup, nil)
	err := restoreCore(io.Discard, archive, 8767, "127.0.0.1", false /* yes */, true /* nonInteractive */)
	if err == nil {
		t.Fatal("expected error when non-interactive and --yes not passed")
	}
	if !strings.Contains(err.Error(), "--yes") {
		t.Fatalf("expected error mentioning --yes, got: %v", err)
	}
}

func TestRevokeDeviceNoArgNonInteractiveErrors(t *testing.T) {
	testutil.TempHome(t)

	users := pki.NewUserRegistry(testStateDB(t))
	u, err := users.Create("deviceowner", "admin", "")
	if err != nil {
		t.Fatal(err)
	}
	registry := pki.NewDeviceRegistry(testStateDB(t))
	if _, err := registry.RegisterDeviceForUser(testutil.ECDSAPubKeyPEM(t), "Test Device", u.UserID, ""); err != nil {
		t.Fatal(err)
	}

	if err := revokeDeviceCore(io.Discard, nil, false, true /* nonInteractive */); err == nil {
		t.Fatal("expected non-interactive error when no arg provided and devices exist")
	}
}

func TestUninstallYesBypassesConfirm(t *testing.T) {
	err := uninstallCore(io.Discard, true /* yes */, true /* nonInteractive */)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestListDevices_ShowsUserColumn(t *testing.T) {
	testutil.TempHome(t)

	users := pki.NewUserRegistry(testStateDB(t))
	u, err := users.Create("Alice", "admin", "")
	if err != nil {
		t.Fatal(err)
	}

	pubKeyPEM := testutil.ECDSAPubKeyPEM(t)
	registry := pki.NewDeviceRegistry(testStateDB(t))
	deviceID, err := registry.RegisterDeviceForUser(pubKeyPEM, "Alice's iPhone", u.UserID, "")
	if err != nil {
		t.Fatal(err)
	}
	_ = deviceID

	var buf strings.Builder
	if err := listDevicesCore(&buf, false, false); err != nil {
		t.Fatalf("listDevicesCore failed: %v", err)
	}
	out := buf.String()
	if !strings.Contains(out, "Alice") {
		t.Errorf("expected display_name 'Alice' in output, got:\n%s", out)
	}
	if !strings.Contains(out, "Alice's iPhone") {
		t.Errorf("expected device name in output, got:\n%s", out)
	}
}

func TestListDevices_AllIncludesRemovedWithRemovedTime(t *testing.T) {
	testutil.TempHome(t)
	db := testStateDB(t)
	u, err := pki.NewUserRegistry(db).Create("alice", "admin", "")
	if err != nil {
		t.Fatal(err)
	}
	devices := pki.NewDeviceRegistry(db)
	active, err := devices.RegisterDeviceForUser(testutil.ECDSAPubKeyPEM(t), "Active", u.UserID, "")
	if err != nil {
		t.Fatal(err)
	}
	revoked, err := devices.RegisterDeviceForUser(testutil.ECDSAPubKeyPEM(t), "Revoked", u.UserID, "")
	if err != nil {
		t.Fatal(err)
	}
	left, err := devices.RegisterDeviceForUser(testutil.ECDSAPubKeyPEM(t), "Left", u.UserID, "")
	if err != nil {
		t.Fatal(err)
	}
	if err := devices.Revoke(revoked); err != nil {
		t.Fatal(err)
	}
	if err := devices.Leave(left); err != nil {
		t.Fatal(err)
	}

	var buf strings.Builder
	if err := listDevicesCore(&buf, false, false); err != nil {
		t.Fatal(err)
	}
	out := buf.String()
	if !strings.Contains(out, "Active") || strings.Contains(out, "Revoked") || strings.Contains(out, "Left") || strings.Contains(out, "REMOVED") {
		t.Fatalf("default listing must be active-only without a REMOVED column:\n%s", out)
	}

	buf.Reset()
	if err := listDevicesCore(&buf, false, true); err != nil {
		t.Fatal(err)
	}
	out = buf.String()
	if !strings.Contains(out, "REMOVED") || !strings.Contains(out, "revoked") || !strings.Contains(out, "left") {
		t.Fatalf("--all listing:\n%s", out)
	}

	buf.Reset()
	if err := listDevicesCore(&buf, true, true); err != nil {
		t.Fatal(err)
	}
	var rows []deviceRow
	if err := json.Unmarshal([]byte(buf.String()), &rows); err != nil {
		t.Fatal(err)
	}
	byID := map[string]deviceRow{}
	for _, r := range rows {
		byID[r.DeviceID] = r
	}
	if len(rows) != 3 || byID[active].RemovedAt != "" || byID[active].Status != "active" {
		t.Fatalf("rows = %+v", rows)
	}
	if byID[revoked].Status != "revoked" || byID[revoked].RemovedAt == "" || byID[left].Status != "left" || byID[left].RemovedAt == "" {
		t.Fatalf("removed rows = %+v %+v", byID[revoked], byID[left])
	}

	buf.Reset()
	if err := listDevicesCore(&buf, true, false); err != nil {
		t.Fatal(err)
	}
	rows = nil
	if err := json.Unmarshal([]byte(buf.String()), &rows); err != nil {
		t.Fatal(err)
	}
	if len(rows) != 1 || rows[0].DeviceID != active {
		t.Fatalf("default JSON rows = %+v", rows)
	}

	if err := devices.Revoke(active); err != nil {
		t.Fatal(err)
	}
	buf.Reset()
	if err := listDevicesCore(&buf, false, false); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(buf.String(), "No active devices.") {
		t.Fatalf("out = %q", buf.String())
	}
}
