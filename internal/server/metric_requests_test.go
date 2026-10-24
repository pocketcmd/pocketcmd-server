package server

import (
	"encoding/json"
	"net/http"
	"strings"
	"testing"

	"github.com/pocketcmd/pocketcmd-server/internal/datasync"
	"github.com/pocketcmd/pocketcmd-server/internal/metrics"
	"github.com/pocketcmd/pocketcmd-server/internal/monitoring"
	"github.com/pocketcmd/pocketcmd-server/internal/pki"
)

func requestFixture(t *testing.T) (*teamTestFixture, *datasync.SyncStore) {
	t.Helper()
	f := newTeamTestFixture(t)
	// The request store, monitoring tables and sync store must share one state.db.
	db := testStateDB(t)
	mon := monitoring.NewStore(db)
	store := datasync.NewSyncStore(db, mon)
	f.srv.RegisterSyncRoutes(store)
	f.srv.RegisterMetricRequestRoutes(metrics.NewRequestStore(db), mon)
	return f, store
}

func TestMetricRequests_MemberFilesAdminApproves(t *testing.T) {
	f, store := requestFixture(t)

	body := `{"label":"Docker containers","command":"docker ps -q | wc -l","interval_override":60}`
	w := f.do("POST", "/api/metrics/requests", body, f.memberToken, f.memberCert)
	if w.Code != http.StatusOK {
		t.Fatalf("file request: expected 200, got %d: %s", w.Code, w.Body.String())
	}
	var req metrics.MetricRequest
	json.NewDecoder(w.Body).Decode(&req)
	if req.Status != "pending" || req.ID == "" {
		t.Fatalf("unexpected request: %+v", req)
	}

	w = f.do("POST", "/api/metrics/requests/"+req.ID+"/approve", "", f.memberToken, f.memberCert)
	if w.Code != http.StatusForbidden {
		t.Fatalf("member approve: expected 403, got %d", w.Code)
	}

	w = f.do("POST", "/api/metrics/requests/"+req.ID+"/approve", "", f.adminToken, f.adminCert)
	if w.Code != http.StatusOK {
		t.Fatalf("admin approve: expected 200, got %d: %s", w.Code, w.Body.String())
	}
	recs, err := store.PullRecords("", []string{"monitoring_config"})
	if err != nil || len(recs) != 1 {
		t.Fatalf("expected monitoring_config record after approval, got %v err=%v", recs, err)
	}
	var cfg metrics.MonitoringConfig
	if err := json.Unmarshal(recs[0].Data, &cfg); err != nil {
		t.Fatal(err)
	}
	found := false
	for _, c := range cfg.Custom {
		if c.ID == req.ID && c.Command == "docker ps -q | wc -l" &&
			c.IntervalOverride != nil && *c.IntervalOverride == 60 {
			found = true
		}
	}
	if !found {
		t.Fatalf("approved command missing from config: %+v", cfg.Custom)
	}

	w = f.do("POST", "/api/metrics/requests/"+req.ID+"/approve", "", f.adminToken, f.adminCert)
	if w.Code != http.StatusConflict {
		t.Fatalf("re-approve: expected 409, got %d", w.Code)
	}
}

func TestMetricRequests_DeleteRevokesApprovedCommand(t *testing.T) {
	f, store := requestFixture(t)

	w := f.do("POST", "/api/metrics/requests",
		`{"label":"Docker","command":"docker ps -q | wc -l"}`,
		f.memberToken, f.memberCert)
	if w.Code != http.StatusOK {
		t.Fatalf("file: expected 200, got %d", w.Code)
	}
	var req metrics.MetricRequest
	json.NewDecoder(w.Body).Decode(&req)
	w = f.do("POST", "/api/metrics/requests/"+req.ID+"/approve", "",
		f.adminToken, f.adminCert)
	if w.Code != http.StatusOK {
		t.Fatalf("approve: expected 200, got %d", w.Code)
	}

	w = f.do("DELETE", "/api/metrics/requests/"+req.ID, "",
		f.memberToken, f.memberCert)
	if w.Code != http.StatusForbidden {
		t.Fatalf("member delete: expected 403, got %d", w.Code)
	}

	w = f.do("DELETE", "/api/metrics/requests/"+req.ID, "",
		f.adminToken, f.adminCert)
	if w.Code != http.StatusOK {
		t.Fatalf("admin delete: expected 200, got %d: %s", w.Code, w.Body.String())
	}
	recs, err := store.PullRecords("", []string{"monitoring_config"})
	if err != nil || len(recs) != 1 {
		t.Fatalf("expected monitoring_config record, got %v err=%v", recs, err)
	}
	var cfg metrics.MonitoringConfig
	if err := json.Unmarshal(recs[0].Data, &cfg); err != nil {
		t.Fatal(err)
	}
	for _, c := range cfg.Custom {
		if c.ID == req.ID {
			t.Fatalf("custom command still present after delete: %+v", c)
		}
	}
	w = f.do("GET", "/api/metrics/requests", "", f.adminToken, f.adminCert)
	var list []metrics.MetricRequest
	json.NewDecoder(w.Body).Decode(&list)
	for _, r := range list {
		if r.ID == req.ID {
			t.Fatalf("request row still listed after delete")
		}
	}

	w = f.do("DELETE", "/api/metrics/requests/req-nope", "",
		f.adminToken, f.adminCert)
	if w.Code != http.StatusNotFound {
		t.Fatalf("unknown id: expected 404, got %d", w.Code)
	}
}

func TestMetricRequests_DeclineDoesNotTouchConfig(t *testing.T) {
	f, store := requestFixture(t)
	w := f.do("POST", "/api/metrics/requests",
		`{"label":"X","command":"echo 1"}`, f.memberToken, f.memberCert)
	var req metrics.MetricRequest
	json.NewDecoder(w.Body).Decode(&req)

	w = f.do("POST", "/api/metrics/requests/"+req.ID+"/decline", "", f.adminToken, f.adminCert)
	if w.Code != http.StatusOK {
		t.Fatalf("decline: expected 200, got %d: %s", w.Code, w.Body.String())
	}
	recs, _ := store.PullRecords("", []string{"monitoring_config"})
	if len(recs) != 0 {
		t.Fatalf("decline must not create a monitoring_config record, got %v", recs)
	}
}

func TestMetricRequests_ListScoping(t *testing.T) {
	f, _ := requestFixture(t)
	f.do("POST", "/api/metrics/requests",
		`{"label":"Mine","command":"echo 1"}`, f.memberToken, f.memberCert)
	carolCert, carolToken, _ := newTeamUserDevice(t, f.devices, f.users, f.mgr, f.serverKey, "carol", "member")
	f.do("POST", "/api/metrics/requests",
		`{"label":"Carols","command":"echo 2"}`, carolToken, carolCert)

	w := f.do("GET", "/api/metrics/requests", "", f.memberToken, f.memberCert)
	var list []metrics.MetricRequest
	json.NewDecoder(w.Body).Decode(&list)
	if len(list) != 1 || list[0].Label != "Mine" {
		t.Fatalf("member scoping broken: %+v", list)
	}
	w = f.do("GET", "/api/metrics/requests", "", f.adminToken, f.adminCert)
	json.NewDecoder(w.Body).Decode(&list)
	if len(list) != 2 {
		t.Fatalf("admin should see all requests, got %+v", list)
	}
	erinCert, erinToken, _ := newTeamUserDevice(t, f.devices, f.users, f.mgr, f.serverKey, "erin", "admin")
	w = f.do("GET", "/api/metrics/requests", "", erinToken, erinCert)
	json.NewDecoder(w.Body).Decode(&list)
	if len(list) != 2 {
		t.Fatalf("non-owner admin should see all requests, got %+v", list)
	}
	daveCert, daveToken, dave := newTeamUserDevice(t, f.devices, f.users, f.mgr, f.serverKey, "dave", "member")
	if err := f.users.SetPermissions(dave.UserID, pki.PermissionSet{
		"metrics.commands.create": {Granted: true},
	}); err != nil {
		t.Fatal(err)
	}
	w = f.do("GET", "/api/metrics/requests", "", daveToken, daveCert)
	json.NewDecoder(w.Body).Decode(&list)
	if len(list) != 2 {
		t.Fatalf("create-holder should see all requests, got %+v", list)
	}
	if err := f.users.SetPermissions(dave.UserID, pki.PermissionSet{
		"metrics.commands.delete": {Granted: true},
	}); err != nil {
		t.Fatal(err)
	}
	w = f.do("GET", "/api/metrics/requests", "", daveToken, daveCert)
	json.NewDecoder(w.Body).Decode(&list)
	if len(list) != 2 {
		t.Fatalf("delete-holder should see all requests, got %+v", list)
	}
}

func TestMetricRequests_AdminNeedsOwnerGrant(t *testing.T) {
	f, _ := requestFixture(t)
	w := f.do("POST", "/api/metrics/requests",
		`{"label":"X","command":"echo 1"}`, f.memberToken, f.memberCert)
	var req metrics.MetricRequest
	json.NewDecoder(w.Body).Decode(&req)

	admin2Cert, admin2Token, admin2 := newTeamUserDevice(t, f.devices, f.users, f.mgr, f.serverKey, "erin", "admin")
	w = f.do("POST", "/api/metrics/requests/"+req.ID+"/approve", "", admin2Token, admin2Cert)
	if w.Code != http.StatusForbidden || !strings.Contains(w.Body.String(), "permission_required") {
		t.Fatalf("ungranted admin approve: expected 403 permission_required, got %d: %s", w.Code, w.Body.String())
	}

	w = f.do("PATCH", "/api/users/"+admin2.UserID,
		`{"permissions":{"metrics.commands.create":{"granted":true}}}`, f.adminToken, f.adminCert)
	if w.Code != http.StatusOK {
		t.Fatalf("owner grant to admin: expected 200, got %d: %s", w.Code, w.Body.String())
	}
	w = f.do("POST", "/api/metrics/requests/"+req.ID+"/approve", "", admin2Token, admin2Cert)
	if w.Code != http.StatusOK {
		t.Fatalf("granted admin approve: expected 200, got %d: %s", w.Code, w.Body.String())
	}
	var decided metrics.MetricRequest
	json.NewDecoder(w.Body).Decode(&decided)
	if decided.Status != "approved" || decided.DecidedBy != admin2.UserID {
		t.Fatalf("unexpected decision: %+v", decided)
	}
}

func TestMetricRequests_CreateGrantDecides(t *testing.T) {
	f, store := requestFixture(t)
	file := func(label string) metrics.MetricRequest {
		w := f.do("POST", "/api/metrics/requests",
			`{"label":"`+label+`","command":"echo 1"}`, f.memberToken, f.memberCert)
		var req metrics.MetricRequest
		json.NewDecoder(w.Body).Decode(&req)
		return req
	}
	reqA, reqB := file("A"), file("B")

	daveCert, daveToken, dave := newTeamUserDevice(t, f.devices, f.users, f.mgr, f.serverKey, "dave", "member")
	w := f.do("POST", "/api/metrics/requests/"+reqA.ID+"/approve", "", daveToken, daveCert)
	if w.Code != http.StatusForbidden {
		t.Fatalf("ungranted member approve: expected 403, got %d", w.Code)
	}

	if err := f.users.SetPermissions(dave.UserID, pki.PermissionSet{
		"metrics.commands.create": {Granted: true},
	}); err != nil {
		t.Fatal(err)
	}
	w = f.do("POST", "/api/metrics/requests/"+reqA.ID+"/approve", "", daveToken, daveCert)
	if w.Code != http.StatusOK {
		t.Fatalf("granted member approve: expected 200, got %d: %s", w.Code, w.Body.String())
	}
	w = f.do("POST", "/api/metrics/requests/"+reqB.ID+"/decline", "", daveToken, daveCert)
	if w.Code != http.StatusOK {
		t.Fatalf("granted member decline: expected 200, got %d: %s", w.Code, w.Body.String())
	}

	recs, err := store.PullRecords("", []string{"monitoring_config"})
	if err != nil || len(recs) != 1 {
		t.Fatalf("expected monitoring_config after approval, got %v err=%v", recs, err)
	}
	var cfg metrics.MonitoringConfig
	if err := json.Unmarshal(recs[0].Data, &cfg); err != nil {
		t.Fatal(err)
	}
	if len(cfg.Custom) != 1 || cfg.Custom[0].Label != "A" {
		t.Fatalf("only the approved command should run, got %+v", cfg.Custom)
	}
}

func TestMetricRequests_RequesterWithdrawsOwnPending(t *testing.T) {
	f, _ := requestFixture(t)
	w := f.do("POST", "/api/metrics/requests",
		`{"label":"Mine","command":"echo 1"}`, f.memberToken, f.memberCert)
	var req metrics.MetricRequest
	json.NewDecoder(w.Body).Decode(&req)

	w = f.do("DELETE", "/api/metrics/requests/"+req.ID, "", f.memberToken, f.memberCert)
	if w.Code != http.StatusOK {
		t.Fatalf("withdraw own pending: expected 200, got %d: %s", w.Code, w.Body.String())
	}
	w = f.do("GET", "/api/metrics/requests", "", f.memberToken, f.memberCert)
	var list []metrics.MetricRequest
	json.NewDecoder(w.Body).Decode(&list)
	for _, r := range list {
		if r.ID == req.ID {
			t.Fatalf("withdrawn request still listed")
		}
	}
}

func TestMetricRequests_RequesterCannotDeleteOwnApproved(t *testing.T) {
	f, _ := requestFixture(t)
	w := f.do("POST", "/api/metrics/requests",
		`{"label":"Mine","command":"echo 1"}`, f.memberToken, f.memberCert)
	var req metrics.MetricRequest
	json.NewDecoder(w.Body).Decode(&req)
	w = f.do("POST", "/api/metrics/requests/"+req.ID+"/approve", "", f.adminToken, f.adminCert)
	if w.Code != http.StatusOK {
		t.Fatalf("approve: expected 200, got %d", w.Code)
	}

	w = f.do("DELETE", "/api/metrics/requests/"+req.ID, "", f.memberToken, f.memberCert)
	if w.Code != http.StatusForbidden {
		t.Fatalf("delete own approved without grant: expected 403, got %d: %s", w.Code, w.Body.String())
	}
}

func TestMetricRequests_StrangerCannotWithdrawOthersPending(t *testing.T) {
	f, _ := requestFixture(t)
	w := f.do("POST", "/api/metrics/requests",
		`{"label":"Bobs","command":"echo 1"}`, f.memberToken, f.memberCert)
	var req metrics.MetricRequest
	json.NewDecoder(w.Body).Decode(&req)

	carolCert, carolToken, _ := newTeamUserDevice(t, f.devices, f.users, f.mgr, f.serverKey, "carol", "member")
	w = f.do("DELETE", "/api/metrics/requests/"+req.ID, "", carolToken, carolCert)
	if w.Code != http.StatusForbidden {
		t.Fatalf("stranger delete: expected 403, got %d: %s", w.Code, w.Body.String())
	}
}

func TestMetricRequests_RejectsDangerousOrInvalid(t *testing.T) {
	f, _ := requestFixture(t)
	for _, body := range []string{
		`{"label":"","command":"echo 1"}`,
		`{"label":"x","command":""}`,
		`{"label":"x","command":"echo 1","interval_override":1}`,
	} {
		w := f.do("POST", "/api/metrics/requests", body, f.memberToken, f.memberCert)
		if w.Code != http.StatusBadRequest {
			t.Fatalf("expected 400 for %s, got %d", body, w.Code)
		}
	}
}

func TestHostKeys_FingerprintFormat(t *testing.T) {
	// ssh-keygen -t ed25519 test vector; the fingerprint is OpenSSH's unpadded base64 after "SHA256:".
	line := "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIGJl56z2GcCO0nDXVL7rD36gGDVe1VLwv2wLwr7dQ2zD test@host"
	fp, ok := pki.FingerprintAuthorizedKey(line)
	if !ok {
		t.Fatal("failed to fingerprint valid key line")
	}
	if len(fp) != 43 {
		t.Fatalf("expected 43-char unpadded base64, got %d (%s)", len(fp), fp)
	}
	if _, ok := pki.FingerprintAuthorizedKey("garbage"); ok {
		t.Fatal("garbage line must not fingerprint")
	}
}
