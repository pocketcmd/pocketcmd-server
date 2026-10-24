package main

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/pocketcmd/pocketcmd-server/internal/authz"
	"github.com/pocketcmd/pocketcmd-server/internal/config"
	"github.com/pocketcmd/pocketcmd-server/internal/datasync"
	"github.com/pocketcmd/pocketcmd-server/internal/metrics"
	"github.com/pocketcmd/pocketcmd-server/internal/pki"
	"github.com/pocketcmd/pocketcmd-server/internal/testutil"
)

func auditLog(t *testing.T) string {
	t.Helper()
	b, _ := os.ReadFile(filepath.Join(config.PocketCmdDir(), "audit.log"))
	return string(b)
}

func TestVaultsAndVaultMembers(t *testing.T) {
	testutil.TempHome(t)
	db := testStateDB(t)
	owner := seedOwner(t)
	bob, err := pki.NewUserRegistry(db).Create("bob", "member", owner.UserID)
	if err != nil {
		t.Fatal(err)
	}

	stdout, _, err := runCLI(t, "vaults")
	if err != nil || !strings.Contains(stdout.String(), "No shared vaults.") {
		t.Fatalf("empty: err=%v out=%q", err, stdout.String())
	}
	stdout, _, _ = runCLI(t, "vaults", "--json")
	if strings.TrimSpace(stdout.String()) != "[]" {
		t.Fatalf("empty json = %q", stdout.String())
	}

	store := datasync.NewSyncStore(db, nil)
	for _, g := range []struct {
		vault, user string
		level       int
	}{
		{"vault-team", owner.UserID, datasync.LevelManage},
		{"vault-team", bob.UserID, datasync.LevelView},
		{"vault-solo", bob.UserID, datasync.LevelManage},
	} {
		if err := store.GrantVault(g.vault, g.user, g.level); err != nil {
			t.Fatal(err)
		}
	}

	stdout, _, err = runCLI(t, "vaults")
	if err != nil {
		t.Fatal(err)
	}
	lines := strings.Split(strings.TrimSpace(stdout.String()), "\n")
	if len(lines) != 3 || !strings.HasPrefix(lines[0], "VAULT_ID") || !strings.Contains(lines[1], "vault-solo") || !strings.HasSuffix(strings.TrimSpace(lines[2]), "2") {
		t.Fatalf("vaults table: %q", stdout.String())
	}
	stdout, _, _ = runCLI(t, "vaults", "--json")
	var summaries []datasync.VaultSummary
	if err := json.Unmarshal(stdout.Bytes(), &summaries); err != nil || len(summaries) != 2 || summaries[1].Members != 2 {
		t.Fatalf("vaults json: %q (%v)", stdout.String(), err)
	}

	stdout, _, err = runCLI(t, "vault-members", "vault-team")
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(stdout.String(), "owner") || !strings.Contains(stdout.String(), "manage") || !strings.Contains(stdout.String(), "bob") || !strings.Contains(stdout.String(), "view") {
		t.Fatalf("vault-members: %q", stdout.String())
	}
	stdout, _, _ = runCLI(t, "vault-members", "vault-team", "--json")
	var members []vaultMemberRow
	if err := json.Unmarshal(stdout.Bytes(), &members); err != nil || len(members) != 2 {
		t.Fatalf("vault-members json: %q (%v)", stdout.String(), err)
	}
	for _, m := range members {
		if m.UserID == bob.UserID && (m.DisplayName != "bob" || m.Level != "view" || m.Role != "member") {
			t.Fatalf("bob row = %+v", m)
		}
		if m.UserID == owner.UserID && m.Role != "owner" {
			t.Fatalf("owner row = %+v", m)
		}
	}
	if _, _, err := runCLI(t, "vault-members", "nope"); err == nil || !strings.Contains(err.Error(), "not found") {
		t.Fatalf("unknown vault: %v", err)
	}
}

func TestRenameUser(t *testing.T) {
	testutil.TempHome(t)
	users := pki.NewUserRegistry(testStateDB(t))
	bob, err := users.Create("bob", "member", "")
	if err != nil {
		t.Fatal(err)
	}
	stdout, _, err := runCLI(t, "rename-user", "bob", "Robert")
	if err != nil || !strings.Contains(stdout.String(), "Renamed bob to Robert.") {
		t.Fatalf("err=%v out=%q", err, stdout.String())
	}
	if u, _ := users.FindByID(bob.UserID); u.DisplayName != "Robert" {
		t.Fatalf("name not stored: %+v", u)
	}
	if log := auditLog(t); !strings.Contains(log, `"msg":"user_renamed"`) || !strings.Contains(log, `"new_name":"Robert"`) || !strings.Contains(log, `"changed_by":"cli"`) {
		t.Fatalf("audit entry missing: %q", log)
	}
	stdout, _, err = runCLI(t, "rename-user", bob.UserID, "Robert")
	if err != nil || !strings.Contains(stdout.String(), "already named") {
		t.Fatalf("no-op rename: err=%v out=%q", err, stdout.String())
	}
	if _, _, err := runCLI(t, "rename-user", "bob", "x"); err == nil {
		t.Fatal("the old name must no longer resolve")
	}
	if _, _, err := runCLI(t, "rename-user", "Robert", "  "); err == nil || !strings.Contains(err.Error(), "empty") {
		t.Fatalf("blank name: %v", err)
	}
}

func TestGrantAndRevokePermission(t *testing.T) {
	testutil.TempHome(t)
	users := pki.NewUserRegistry(testStateDB(t))
	bob, err := users.Create("bob", "member", "")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := users.Create("ann", "admin", ""); err != nil {
		t.Fatal(err)
	}

	stdout, _, err := runCLI(t, "grant", "bob", authz.PermInvitesManage)
	if err != nil || !strings.Contains(stdout.String(), "Granted invites.manage to bob.") {
		t.Fatalf("err=%v out=%q", err, stdout.String())
	}
	u, _ := users.FindByID(bob.UserID)
	if !authz.Allowed(u, authz.PermInvitesManage) {
		t.Fatalf("grant not stored: %+v", u.Permissions)
	}
	if log := auditLog(t); !strings.Contains(log, `"msg":"permission_changed"`) || !strings.Contains(log, `"granted":["invites.manage"]`) {
		t.Fatalf("audit entry missing: %q", log)
	}

	stdout, _, err = runCLI(t, "grant", bob.UserID, authz.PermAlertsRead, "--metrics", "custom:cpu,custom:load1")
	if err != nil || !strings.Contains(stdout.String(), "for metrics custom:cpu, custom:load1") {
		t.Fatalf("scoped grant: err=%v out=%q", err, stdout.String())
	}
	u, _ = users.FindByID(bob.UserID)
	if !authz.AlertMetricAllowed(u, "custom:cpu") || authz.AlertMetricAllowed(u, "custom:mem") {
		t.Fatalf("scope not applied: %+v", u.Permissions[authz.PermAlertsRead])
	}
	if !authz.Allowed(u, authz.PermInvitesManage) {
		t.Fatal("an earlier grant must survive a later one")
	}

	for _, args := range [][]string{
		{"grant", "bob", "metrics.fly"},
		{"grant", "ann", authz.PermInvitesManage},
		{"grant", "bob", authz.PermInvitesManage, "--metrics", "x"},
		{"grant", "nobody", authz.PermInvitesManage},
		{"revoke-permission", "ann", authz.PermInvitesManage},
		{"revoke-permission", "bob", "bogus.key"},
	} {
		if _, _, err := runCLI(t, args...); err == nil {
			t.Errorf("%v must fail", args)
		}
	}

	stdout, _, err = runCLI(t, "revoke-permission", "bob", authz.PermInvitesManage)
	if err != nil || !strings.Contains(stdout.String(), "Revoked invites.manage from bob.") {
		t.Fatalf("revoke: err=%v out=%q", err, stdout.String())
	}
	u, _ = users.FindByID(bob.UserID)
	if authz.Allowed(u, authz.PermInvitesManage) || !authz.AlertMetricAllowed(u, "custom:cpu") {
		t.Fatalf("revoke must remove only that key: %+v", u.Permissions)
	}
	stdout, _, err = runCLI(t, "revoke-permission", "bob", authz.PermInvitesManage)
	if err != nil || !strings.Contains(stdout.String(), "does not hold") {
		t.Fatalf("revoke twice: err=%v out=%q", err, stdout.String())
	}
}

func TestRequests_ListApproveDecline(t *testing.T) {
	testutil.TempHome(t)
	db := testStateDB(t)
	bob, err := pki.NewUserRegistry(db).Create("bob", "member", "")
	if err != nil {
		t.Fatal(err)
	}
	stdout, _, err := runCLI(t, "requests")
	if err != nil || !strings.Contains(stdout.String(), "No metric command requests.") {
		t.Fatalf("empty: err=%v out=%q", err, stdout.String())
	}

	store := metrics.NewRequestStore(db)
	r1, err := store.Create("Disk temp", "smartctl -A /dev/sda", nil, bob.UserID)
	if err != nil {
		t.Fatal(err)
	}
	r2, err := store.Create("Uptime", "uptime", nil, bob.UserID)
	if err != nil {
		t.Fatal(err)
	}

	stdout, _, err = runCLI(t, "requests")
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(stdout.String(), "REQUEST_ID") || !strings.Contains(stdout.String(), r1.ID) || !strings.Contains(stdout.String(), "pending") || !strings.Contains(stdout.String(), "bob") {
		t.Fatalf("list: %q", stdout.String())
	}
	stdout, _, _ = runCLI(t, "requests", "--json")
	var listed []metrics.MetricRequest
	if err := json.Unmarshal(stdout.Bytes(), &listed); err != nil || len(listed) != 2 {
		t.Fatalf("json: %q (%v)", stdout.String(), err)
	}

	stdout, _, err = runCLI(t, "requests", "approve", r1.ID)
	if err != nil || !strings.Contains(stdout.String(), "Approved "+r1.ID) {
		t.Fatalf("approve: err=%v out=%q", err, stdout.String())
	}
	if got, _ := store.FindByID(r1.ID); got.Status != "approved" || got.DecidedBy != "cli" {
		t.Fatalf("request after approve: %+v", got)
	}
	var n int
	if err := db.QueryRow("SELECT COUNT(*) FROM custom_metrics WHERE request_id=?", r1.ID).Scan(&n); err != nil || n != 1 {
		t.Fatalf("approval must add the command to the monitoring config: n=%d err=%v", n, err)
	}
	if log := auditLog(t); !strings.Contains(log, `"msg":"metric_request_approved"`) || !strings.Contains(log, `"decided_by":"cli"`) {
		t.Fatalf("audit entry missing: %q", log)
	}

	stdout, _, err = runCLI(t, "requests", "decline", r2.ID)
	if err != nil || !strings.Contains(stdout.String(), "Declined "+r2.ID) {
		t.Fatalf("decline: err=%v out=%q", err, stdout.String())
	}
	if got, _ := store.FindByID(r2.ID); got.Status != "declined" {
		t.Fatalf("request after decline: %+v", got)
	}
	if err := db.QueryRow("SELECT COUNT(*) FROM custom_metrics WHERE request_id=?", r2.ID).Scan(&n); err != nil || n != 0 {
		t.Fatalf("a declined command must not run: n=%d", n)
	}
	if !strings.Contains(auditLog(t), `"msg":"metric_request_declined"`) {
		t.Fatal("decline audit entry missing")
	}

	if _, _, err := runCLI(t, "requests", "approve", r1.ID); err == nil || !strings.Contains(err.Error(), "already approved") {
		t.Fatalf("second decision: %v", err)
	}
	if _, _, err := runCLI(t, "requests", "decline", "req-nope"); err == nil || !strings.Contains(err.Error(), "not found") {
		t.Fatalf("unknown id: %v", err)
	}
}

func TestConfigGet(t *testing.T) {
	testutil.TempHome(t)

	stdout, _, err := runCLI(t, "config", "get")
	if err != nil || !strings.Contains(stdout.String(), "service_mode     background") || strings.Contains(stdout.String(), "push") {
		t.Fatalf("defaults: err=%v out=%q", err, stdout.String())
	}
	stdout, _, _ = runCLI(t, "config", "get", "--json")
	var back config.FeatureConfig
	if err := json.Unmarshal(stdout.Bytes(), &back); err != nil || back.ServiceMode != "background" {
		t.Fatalf("get --json: %q (%v)", stdout.String(), err)
	}
	if strings.Contains(stdout.String(), "push_enabled") {
		t.Fatalf("push_enabled is gone from config.json: %q", stdout.String())
	}
	if _, _, err := runCLI(t, "config", "set", "push_enabled", "true"); err == nil {
		t.Fatal("config set must be gone")
	}
	if _, _, err := runCLI(t, "config"); err != nil {
		t.Fatalf("bare config prints help: %v", err)
	}
}

func TestAuditCommand(t *testing.T) {
	testutil.TempHome(t)
	stdout, _, err := runCLI(t, "audit")
	if err != nil || !strings.Contains(stdout.String(), "No audit log yet.") {
		t.Fatalf("no file: err=%v out=%q", err, stdout.String())
	}
	users := pki.NewUserRegistry(testStateDB(t))
	if _, err := users.Create("bob", "member", ""); err != nil {
		t.Fatal(err)
	}
	if _, _, err := runCLI(t, "rename-user", "bob", "Bobby"); err != nil {
		t.Fatal(err)
	}
	stdout, _, err = runCLI(t, "audit")
	if err != nil || !strings.Contains(stdout.String(), "user_renamed") || !strings.Contains(stdout.String(), "new_name=Bobby") {
		t.Fatalf("audit: err=%v out=%q", err, stdout.String())
	}
	stdout, _, _ = runCLI(t, "audit", "--json", "-n", "1")
	var m map[string]any
	if err := json.Unmarshal(stdout.Bytes(), &m); err != nil || m["msg"] != "user_renamed" {
		t.Fatalf("audit --json: %q (%v)", stdout.String(), err)
	}
}

func TestTruncate(t *testing.T) {
	if truncate("abcdef", 10) != "abcdef" || truncate("abcdef", 4) != "abc…" || truncate("abcdef", 1) != "a" {
		t.Fatal("truncate is wrong")
	}
}

func TestTransferOwnership(t *testing.T) {
	testutil.TempHome(t)
	db := testStateDB(t)
	users := pki.NewUserRegistry(db)
	owner := seedOwner(t)
	bob, err := users.Create("bob", "member", owner.UserID)
	if err != nil {
		t.Fatal(err)
	}
	gone, err := users.Create("gone", "member", owner.UserID)
	if err != nil {
		t.Fatal(err)
	}
	if err := users.Revoke(gone.UserID); err != nil {
		t.Fatal(err)
	}

	if _, _, err := runCLI(t, "transfer-ownership", "owner", "--yes"); err == nil || !strings.Contains(err.Error(), "already the owner") {
		t.Fatalf("self transfer: %v", err)
	}
	if _, _, err := runCLI(t, "transfer-ownership", gone.UserID, "--yes"); err == nil || !strings.Contains(err.Error(), "revoked") {
		t.Fatalf("inactive target: %v", err)
	}
	if _, _, err := runCLI(t, "transfer-ownership", "nobody", "--yes"); err == nil || !strings.Contains(err.Error(), "not found") {
		t.Fatalf("unknown target: %v", err)
	}
	if _, _, err := runCLI(t, "transfer-ownership", "bob", "--non-interactive"); err == nil || !strings.Contains(err.Error(), "--yes") {
		t.Fatalf("non-interactive without --yes: %v", err)
	}
	if u, _ := users.FindByID(owner.UserID); !u.Owner {
		t.Fatal("ownership moved despite the refusals")
	}

	stdout, _, err := runCLI(t, "transfer-ownership", "bob", "--yes")
	if err != nil || !strings.Contains(stdout.String(), "Transferred ownership from owner to bob") {
		t.Fatalf("err=%v out=%q", err, stdout.String())
	}
	if u, _ := users.FindByID(bob.UserID); !u.Owner || u.Role != "admin" {
		t.Fatalf("new owner = %+v", u)
	}
	if u, _ := users.FindByID(owner.UserID); u.Owner || u.Role != "admin" {
		t.Fatalf("previous owner = %+v", u)
	}
	log := auditLog(t)
	for _, want := range []string{`"msg":"owner_transferred"`, `"previous_owner":"` + owner.UserID + `"`, `"new_owner":"` + bob.UserID + `"`, `"changed_by":"cli"`} {
		if !strings.Contains(log, want) {
			t.Errorf("audit entry missing %s: %q", want, log)
		}
	}

	stdout, _, _ = runCLI(t, "list-users", "--json")
	var rows []userRow
	if err := json.Unmarshal(stdout.Bytes(), &rows); err != nil {
		t.Fatal(err)
	}
	for _, r := range rows {
		if (r.UserID == bob.UserID) != (r.Role == "owner") {
			t.Errorf("list-users row %+v", r)
		}
	}
	if _, _, err := runCLI(t, "transfer-ownership", owner.UserID, "-y"); err != nil {
		t.Fatal(err)
	}
	if u, _ := users.FindByID(owner.UserID); !u.Owner {
		t.Fatal("ownership not restored")
	}

	testutil.TempHome(t)
	if _, err := pki.NewUserRegistry(testStateDB(t)).Create("solo", "admin", ""); err != nil {
		t.Fatal(err)
	}
	if _, _, err := runCLI(t, "transfer-ownership", "solo", "--yes"); err == nil || !strings.Contains(err.Error(), "no owner") {
		t.Fatalf("no owner: %v", err)
	}
}

func TestRenameDevice(t *testing.T) {
	testutil.TempHome(t)
	db := testStateDB(t)
	owner := seedOwner(t)
	devices := pki.NewDeviceRegistry(db)
	id, err := devices.RegisterDeviceForUser(testutil.ECDSAPubKeyPEM(t), "Phone", owner.UserID, "old label")
	if err != nil {
		t.Fatal(err)
	}
	d, _ := devices.FindByID(id)
	fp, _ := pki.PubKeyFingerprint(d.PublicKey)
	prefix := fp[:12]

	if _, _, err := runCLI(t, "rename-device", prefix); err == nil || !strings.Contains(err.Error(), "--name") {
		t.Fatalf("no flags: %v", err)
	}
	if _, _, err := runCLI(t, "rename-device", prefix, "--name", " "); err == nil || !strings.Contains(err.Error(), "empty") {
		t.Fatalf("blank name: %v", err)
	}
	long := strings.Repeat("x", pki.MaxDeviceNameLen+1)
	if _, _, err := runCLI(t, "rename-device", prefix, "--label", long); err == nil || !strings.Contains(err.Error(), "128") {
		t.Fatalf("over-long label: %v", err)
	}
	if _, _, err := runCLI(t, "rename-device", "0000000000", "--name", "x"); err == nil || !strings.Contains(err.Error(), "no device") {
		t.Fatalf("unknown prefix: %v", err)
	}
	if _, _, err := runCLI(t, "rename-device", "abc", "--name", "x"); err == nil || !strings.Contains(err.Error(), "at least") {
		t.Fatalf("short prefix: %v", err)
	}
	if d, _ := devices.FindByID(id); d.DeviceName != "Phone" || d.DeviceLabel != "old label" {
		t.Fatalf("device changed despite the refusals: %+v", d)
	}

	stdout, _, err := runCLI(t, "rename-device", id[:8], "--name", "Alice's iPhone")
	if err != nil || !strings.Contains(stdout.String(), `Renamed device `+id+` to "Alice's iPhone" (label "old label").`) {
		t.Fatalf("err=%v out=%q", err, stdout.String())
	}
	if d, _ := devices.FindByID(id); d.DeviceName != "Alice's iPhone" || d.DeviceLabel != "old label" {
		t.Fatalf("name-only rename: %+v", d)
	}
	stdout, _, err = runCLI(t, "rename-device", prefix, "--label", "")
	if err != nil || !strings.Contains(stdout.String(), `to "Alice's iPhone".`) {
		t.Fatalf("err=%v out=%q", err, stdout.String())
	}
	if d, _ := devices.FindByID(id); d.DeviceLabel != "" {
		t.Fatalf("label not cleared: %+v", d)
	}
	exact := strings.Repeat("ü", pki.MaxDeviceNameLen)
	if _, _, err := runCLI(t, "rename-device", prefix, "--name", exact, "--label", "pocket"); err != nil {
		t.Fatal(err)
	}
	if d, _ := devices.FindByID(id); d.DeviceName != exact || d.DeviceLabel != "pocket" {
		t.Fatalf("both fields: %+v", d)
	}

	log := auditLog(t)
	for _, want := range []string{`"msg":"device_renamed"`, `"device_id":"` + id + `"`, `"user_id":"` + owner.UserID + `"`,
		`"old_name":"Phone"`, `"new_name":"Alice's iPhone"`, `"old_label":"old label"`, `"new_label":""`, `"changed_by":"cli"`} {
		if !strings.Contains(log, want) {
			t.Errorf("audit entry missing %s: %q", want, log)
		}
	}
}

func TestGrantOwnerGrantedPermissionToAdmin(t *testing.T) {
	testutil.TempHome(t)
	users := pki.NewUserRegistry(testStateDB(t))
	ann, err := users.Create("ann", "admin", "")
	if err != nil {
		t.Fatal(err)
	}
	olga, err := users.Create("olga", "admin", "")
	if err != nil {
		t.Fatal(err)
	}
	if err := users.SetOwner(olga.UserID, true); err != nil {
		t.Fatal(err)
	}

	u, _ := users.FindByID(ann.UserID)
	if authz.Allowed(u, authz.PermMetricsCommandsCreate) {
		t.Fatal("an admin must not hold metrics.commands.create before the grant")
	}
	stdout, _, err := runCLI(t, "grant", "ann", authz.PermMetricsCommandsCreate)
	if err != nil || !strings.Contains(stdout.String(), "Granted metrics.commands.create to ann.") {
		t.Fatalf("grant to admin: err=%v out=%q", err, stdout.String())
	}
	u, _ = users.FindByID(ann.UserID)
	if !authz.Allowed(u, authz.PermMetricsCommandsCreate) {
		t.Fatalf("grant not stored: %+v", u.Permissions)
	}
	if _, _, err := runCLI(t, "grant", "olga", authz.PermMetricsCommandsCreate); err == nil {
		t.Error("granting to the owner must fail")
	}
	stdout, _, err = runCLI(t, "revoke-permission", "ann", authz.PermMetricsCommandsCreate)
	if err != nil || !strings.Contains(stdout.String(), "Revoked metrics.commands.create from ann.") {
		t.Fatalf("revoke from admin: err=%v out=%q", err, stdout.String())
	}
	u, _ = users.FindByID(ann.UserID)
	if authz.Allowed(u, authz.PermMetricsCommandsCreate) {
		t.Fatal("revoke not stored")
	}
}
