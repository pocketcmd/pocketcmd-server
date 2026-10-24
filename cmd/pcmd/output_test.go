package main

import (
	"bytes"
	"encoding/json"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/pocketcmd/pocketcmd-server/internal/pki"
	"github.com/pocketcmd/pocketcmd-server/internal/testutil"
)

func TestStatus_ExitCodesAndJSON(t *testing.T) {
	testutil.TempHome(t)
	f := &fakeService{}
	f.bind(t)
	withTerm(t, false, 0)

	var out bytes.Buffer
	err := statusCore(&out, 8767, false)
	var ec *exitCodeError
	if !errors.As(err, &ec) || ec.code != exitNotInstalled || !ec.silent {
		t.Fatalf("not installed must exit %d silently, got %v", exitNotInstalled, err)
	}
	if !strings.Contains(out.String(), "not installed") || strings.Contains(out.String(), "POCKETCMD") {
		t.Fatalf("output (no banner off a TTY): %q", out.String())
	}

	f.installed = true
	out.Reset()
	err = statusCore(&out, 8767, false)
	if !errors.As(err, &ec) || ec.code != exitServiceStopped {
		t.Fatalf("stopped must exit %d, got %v", exitServiceStopped, err)
	}
	if !strings.Contains(out.String(), "stopped") {
		t.Fatalf("output: %q", out.String())
	}

	f.running = true
	out.Reset()
	if err := statusCore(&out, 9000, true); err != nil {
		t.Fatalf("running must exit 0: %v", err)
	}
	var r statusReport
	if err := json.Unmarshal(out.Bytes(), &r); err != nil {
		t.Fatalf("invalid JSON %q: %v", out.String(), err)
	}
	if !r.Installed || !r.Running || r.PID != 4242 || r.Port != 9000 || r.ServiceState != "running" || r.Devices != 0 {
		t.Fatalf("report = %+v", r)
	}

	f.installed, f.running = true, false
	_, _, err = runCLI(t, "status", "--json")
	if code, _ := exitCodeFor(err); code != exitServiceStopped {
		t.Fatalf("exit code = %d, err=%v", code, err)
	}
}

func TestStatus_LingerLine(t *testing.T) {
	testutil.TempHome(t)
	f := &fakeService{installed: true, running: true}
	f.bind(t)
	withTerm(t, true, 100)
	orig := svc.lingerStatus
	svc.lingerStatus = func() (bool, bool) { return false, true }
	t.Cleanup(func() { svc.lingerStatus = orig })

	var out bytes.Buffer
	if err := statusCore(&out, 8767, false); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(out.String(), "loginctl enable-linger") || !strings.Contains(out.String(), "POCKETCMD") {
		t.Fatalf("output: %q", out.String())
	}
	out.Reset()
	if err := statusCore(&out, 8767, true); err != nil {
		t.Fatal(err)
	}
	var r statusReport
	if err := json.Unmarshal(out.Bytes(), &r); err != nil || r.Linger == nil || *r.Linger {
		t.Fatalf("json linger: %q err=%v", out.String(), err)
	}
}

func TestListDevices_HeaderAndJSON(t *testing.T) {
	testutil.TempHome(t)
	db := testStateDB(t)
	users := pki.NewUserRegistry(db)
	u, err := users.Create("alice", "admin", "")
	if err != nil {
		t.Fatal(err)
	}
	id, err := pki.NewDeviceRegistry(db).RegisterDeviceForUser(testutil.ECDSAPubKeyPEM(t), "Pixel 9", u.UserID, "")
	if err != nil {
		t.Fatal(err)
	}

	stdout, _, err := runCLI(t, "list-devices")
	if err != nil {
		t.Fatal(err)
	}
	lines := strings.Split(strings.TrimSpace(stdout.String()), "\n")
	if len(lines) != 2 || !strings.HasPrefix(lines[0], "FINGERPRINT") || !strings.Contains(lines[0], "PAIRED") {
		t.Fatalf("expected a header row and one device, got %q", stdout.String())
	}

	stdout, _, err = runCLI(t, "list-devices", "--json")
	if err != nil {
		t.Fatal(err)
	}
	var rows []deviceRow
	if err := json.Unmarshal(stdout.Bytes(), &rows); err != nil {
		t.Fatalf("invalid JSON %q: %v", stdout.String(), err)
	}
	if len(rows) != 1 || rows[0].DeviceID != id || rows[0].UserName != "alice" || rows[0].DeviceName != "Pixel 9" || len(rows[0].Fingerprint) != 64 {
		t.Fatalf("rows = %+v", rows)
	}

	testutil.TempHome(t)
	stdout, _, _ = runCLI(t, "list-devices", "--json")
	if strings.TrimSpace(stdout.String()) != "[]" {
		t.Fatalf("empty list = %q", stdout.String())
	}
}

func TestListUsersAndInvites_JSON(t *testing.T) {
	testutil.TempHome(t)
	db := testStateDB(t)
	owner := seedOwner(t)
	if _, err := pki.NewUserRegistry(db).Create("bob", "member", owner.UserID); err != nil {
		t.Fatal(err)
	}
	inv, err := pki.NewInviteStore(db).Create(pki.CreateInviteParams{Role: "member", ExpiresIn: time.Hour, CreatedByUID: "cli", Label: "bob's tablet"})
	if err != nil {
		t.Fatal(err)
	}

	stdout, _, err := runCLI(t, "list-users", "--json")
	if err != nil {
		t.Fatal(err)
	}
	var users []userRow
	if err := json.Unmarshal(stdout.Bytes(), &users); err != nil {
		t.Fatalf("invalid JSON %q: %v", stdout.String(), err)
	}
	if len(users) != 2 || users[0].Role != "owner" || !users[0].Owner || users[1].Role != "member" || users[1].DisplayName != "bob" {
		t.Fatalf("users = %+v", users)
	}

	stdout, _, err = runCLI(t, "invites", "--json")
	if err != nil {
		t.Fatal(err)
	}
	var invites []pki.InviteRecord
	if err := json.Unmarshal(stdout.Bytes(), &invites); err != nil {
		t.Fatalf("invalid JSON %q: %v", stdout.String(), err)
	}
	if len(invites) != 1 || invites[0].Code != inv.Code || invites[0].Label != "bob's tablet" {
		t.Fatalf("invites = %+v", invites)
	}
}

func TestPrintBanner_OnlyOnTTY(t *testing.T) {
	var out bytes.Buffer
	withTerm(t, false, 0)
	printBanner(&out)
	if out.Len() != 0 {
		t.Fatalf("banner printed off a TTY: %q", out.String())
	}
	withTerm(t, true, 80)
	printBanner(&out)
	if !strings.Contains(out.String(), "POCKETCMD") {
		t.Fatalf("banner missing on a TTY: %q", out.String())
	}
}
