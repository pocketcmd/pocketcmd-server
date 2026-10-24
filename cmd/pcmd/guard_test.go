package main

import (
	"io"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/pocketcmd/pocketcmd-server/internal/config"
	"github.com/pocketcmd/pocketcmd-server/internal/pki"
	"github.com/pocketcmd/pocketcmd-server/internal/testutil"
)

func TestConfirmDestructive(t *testing.T) {
	ok, err := confirmDestructive(io.Discard, "x", "x?", true, true)
	if err != nil || !ok {
		t.Fatalf("--yes must pass without a prompt: ok=%v err=%v", ok, err)
	}
	ok, err = confirmDestructive(io.Discard, "revoke the user", "x?", false, true)
	if err == nil || ok || !strings.Contains(err.Error(), "--yes") || !strings.Contains(err.Error(), "revoke the user") {
		t.Fatalf("non-interactive without --yes must refuse naming the flag: ok=%v err=%v", ok, err)
	}
	if _, err := confirmDestructive(io.Discard, "x", "x?", false, false); err == nil {
		t.Fatal("expected refusal when stdin is not a TTY")
	}
}

func TestDestructiveCommands_RefuseNonInteractiveWithoutYes(t *testing.T) {
	testutil.TempHome(t)
	os.MkdirAll(config.TLSDir(), 0700)
	db := testStateDB(t)
	users := pki.NewUserRegistry(db)
	admin1, err := users.Create("admin1", "admin", "cli")
	if err != nil {
		t.Fatal(err)
	}
	if err := users.SetOwner(admin1.UserID, true); err != nil {
		t.Fatal(err)
	}
	admin2, err := users.Create("admin2", "admin", "cli")
	if err != nil {
		t.Fatal(err)
	}
	member, err := users.Create("bob", "member", "cli")
	if err != nil {
		t.Fatal(err)
	}
	devices := pki.NewDeviceRegistry(db)
	if _, err := devices.RegisterDeviceForUser(testutil.ECDSAPubKeyPEM(t), "Phone", member.UserID, ""); err != nil {
		t.Fatal(err)
	}
	devs, _ := devices.List()
	fp, _ := pki.PubKeyFingerprint(devs[0].PublicKey)
	inv, err := pki.NewInviteStore(db).Create(pki.CreateInviteParams{Role: "member", ExpiresIn: time.Hour, CreatedByUID: "cli"})
	if err != nil {
		t.Fatal(err)
	}

	cases := [][]string{
		{"revoke-invite", inv.Code},
		{"revoke-user", member.UserID},
		{"revoke-user", member.UserID, "--purge-data"},
		{"demote", admin2.UserID},
		{"rotate-server-cert"},
		{"revoke-device", fp[:12]},
		{"transfer-ownership", admin2.UserID},
	}
	for _, args := range cases {
		args = append(args, "--non-interactive")
		_, _, err := runCLI(t, args...)
		if err == nil || !strings.Contains(err.Error(), "--yes") {
			t.Errorf("%v: expected a refusal naming --yes, got %v", args, err)
		}
	}

	if u, _ := users.FindByID(member.UserID); u.Status != "active" {
		t.Error("member was revoked despite the refusal")
	}
	if u, _ := users.FindByID(admin2.UserID); u.Role != "admin" || u.Owner {
		t.Error("admin was demoted or made owner despite the refusal")
	}
	if d, _ := devices.FindByID(devs[0].DeviceID); d.Status != "active" {
		t.Error("device was revoked despite the refusal")
	}
	if active, _ := pki.NewInviteStore(db).ListActive(); len(active) != 1 {
		t.Error("invite was revoked despite the refusal")
	}
	if pki.ServerCertExists(config.TLSDir()) {
		t.Error("a server cert was generated despite the refusal")
	}
}

func TestRevokeDevice_WithYesRevokesByPrefix(t *testing.T) {
	testutil.TempHome(t)
	db := testStateDB(t)
	users := pki.NewUserRegistry(db)
	u, err := users.Create("bob", "member", "cli")
	if err != nil {
		t.Fatal(err)
	}
	devices := pki.NewDeviceRegistry(db)
	id, err := devices.RegisterDeviceForUser(testutil.ECDSAPubKeyPEM(t), "Phone", u.UserID, "")
	if err != nil {
		t.Fatal(err)
	}
	d, _ := devices.FindByID(id)
	fp, _ := pki.PubKeyFingerprint(d.PublicKey)

	stdout, _, err := runCLI(t, "revoke-device", fp[:12], "--yes")
	if err != nil {
		t.Fatalf("revoke-device: %v", err)
	}
	if !strings.Contains(stdout.String(), "Revoked device: Phone") {
		t.Fatalf("unexpected output: %q", stdout.String())
	}
	if d, _ := devices.FindByID(id); d.Status != "revoked" {
		t.Fatalf("device status = %q", d.Status)
	}
}
