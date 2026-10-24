package main

import (
	"strings"
	"testing"

	"github.com/pocketcmd/pocketcmd-server/internal/pki"
	"github.com/pocketcmd/pocketcmd-server/internal/testutil"
)

func TestCheckPrivileges(t *testing.T) {
	cases := []struct {
		name string
		pc   privilegeContext
		want string
	}{
		{"linux user systemd", privilegeContext{euid: 1000, goos: "linux", initSystem: "systemd"}, ""},
		{"linux root systemd", privilegeContext{euid: 0, goos: "linux", initSystem: "systemd"}, "loginctl enable-linger"},
		{"linux sudo systemd", privilegeContext{euid: 0, sudoUser: "alice", goos: "linux", initSystem: "systemd"}, "as alice without sudo"},
		{"linux root openrc", privilegeContext{euid: 0, sudoUser: "alice", goos: "linux", initSystem: "openrc"}, ""},
		{"linux root no init", privilegeContext{euid: 0, goos: "linux", initSystem: "none"}, ""},
		{"darwin user", privilegeContext{euid: 501, goos: "darwin"}, ""},
		{"darwin root", privilegeContext{euid: 0, goos: "darwin"}, "launchd agent"},
		{"darwin sudo", privilegeContext{euid: 0, sudoUser: "bob", goos: "darwin"}, "sudo"},
	}
	for _, c := range cases {
		err := checkPrivileges(c.pc)
		switch {
		case c.want == "" && err != nil:
			t.Errorf("%s: unexpected error %v", c.name, err)
		case c.want != "" && (err == nil || !strings.Contains(err.Error(), c.want)):
			t.Errorf("%s: want error containing %q, got %v", c.name, c.want, err)
		}
	}
}

func TestInstall_RefusesUnpairedHost(t *testing.T) {
	testutil.TempHome(t)
	f := &fakeService{}
	f.bind(t)
	user := privilegeContext{euid: 1000, goos: "linux", initSystem: "systemd"}

	err := installCore(discard(), 8767, "0.0.0.0", false, user)
	if err == nil || !strings.Contains(err.Error(), "pair a device first") {
		t.Fatalf("expected the unpaired refusal, got %v", err)
	}
	if len(f.calls) != 0 {
		t.Fatalf("nothing may be installed: %v", f.calls)
	}

	if err := installCore(discard(), 8767, "0.0.0.0", true, user); err != nil {
		t.Fatalf("--allow-unpaired must install: %v", err)
	}
	if strings.Join(f.calls, ",") != "install" {
		t.Fatalf("calls = %v", f.calls)
	}

	if err := installCore(discard(), 8767, "0.0.0.0", false, privilegeContext{euid: 0, goos: "darwin"}); err == nil || !strings.Contains(err.Error(), "root") {
		t.Fatalf("root must be refused before the device check: %v", err)
	}
}

func TestInstall_InstallsWhenPaired(t *testing.T) {
	testutil.TempHome(t)
	f := &fakeService{}
	f.bind(t)
	db := testStateDB(t)
	u, err := pki.NewUserRegistry(db).Create("owner", "admin", "")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := pki.NewDeviceRegistry(db).RegisterDeviceForUser(testutil.ECDSAPubKeyPEM(t), "Phone", u.UserID, ""); err != nil {
		t.Fatal(err)
	}
	stdout, _, err := runCLI(t, "install")
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(stdout.String(), "installed and started") || !f.installed {
		t.Fatalf("out=%q installed=%v", stdout.String(), f.installed)
	}
}
