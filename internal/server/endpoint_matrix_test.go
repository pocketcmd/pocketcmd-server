package server

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"fmt"
	"math/big"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/pocketcmd/pocketcmd-server/internal/authz"
	"github.com/pocketcmd/pocketcmd-server/internal/config"
	"github.com/pocketcmd/pocketcmd-server/internal/datasync"
	"github.com/pocketcmd/pocketcmd-server/internal/metrics"
	"github.com/pocketcmd/pocketcmd-server/internal/monitoring"
	"github.com/pocketcmd/pocketcmd-server/internal/pair"
	"github.com/pocketcmd/pocketcmd-server/internal/pki"
	"github.com/pocketcmd/pocketcmd-server/internal/push"
)

type matrixFixture struct {
	*teamTestFixture
	admin2Cert  *x509.Certificate
	admin2Token string
	admin2User  *pki.UserRecord
	syncStore   *datasync.SyncStore
	requests    *metrics.RequestStore
}

func newMatrixFixture(t *testing.T) *matrixFixture {
	t.Helper()
	// Config writes and the status walk must stay inside the test sandbox.
	config.SetPocketCmdDir(t.TempDir())
	t.Cleanup(func() { config.SetPocketCmdDir("") })
	// /api/ssh-configs parses $HOME/.ssh, so point it at an empty home.
	t.Setenv("HOME", t.TempDir())

	f := newTeamTestFixture(t)

	// The push store's device foreign key requires the shared state.db.
	mon := monitoring.NewStore(f.db)
	syncStore := datasync.NewSyncStore(f.db, mon)
	requests := metrics.NewRequestStore(f.db)
	f.srv.RegisterSyncRoutes(syncStore)
	f.srv.RegisterMetricRequestRoutes(requests, mon)
	f.srv.RegisterVaultRoutes(syncStore)
	f.srv.RegisterAdminRoutes("test-version")
	f.srv.RegisterSSHRoutes()

	mstore, err := metrics.NewMetricStore(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(mstore.Close)
	f.srv.RegisterMetricRoutes(metrics.NewMetricAPI(mstore, nil))

	f.srv.SetPushStore(push.NewStore(f.db))
	f.srv.SetPairingFingerprint("ab:cd:ef")

	pairKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	f.srv.RegisterPairRoute(pair.NewPairingHandler(
		f.devices, f.users, f.invites, pairKey, "fp", "localhost", "https://localhost:8443"))

	admin2Cert, admin2Token, admin2User := newTeamUserDevice(t, f.devices, f.users, f.mgr, f.serverKey, "carol", "admin")
	return &matrixFixture{
		teamTestFixture: f,
		admin2Cert:      admin2Cert,
		admin2Token:     admin2Token,
		admin2User:      admin2User,
		syncStore:       syncStore,
		requests:        requests,
	}
}

func (f *matrixFixture) doAs(method, path, body, token string, cert *x509.Certificate) *httptest.ResponseRecorder {
	return f.do(method, path, body, token, cert)
}

func (f *matrixFixture) grantedMember(t *testing.T, perms ...string) (string, *x509.Certificate) {
	t.Helper()
	cert, token, u := newTeamUserDevice(t, f.devices, f.users, f.mgr, f.serverKey, "dave", "member")
	set := pki.PermissionSet{}
	for _, p := range perms {
		set[p] = pki.Grant{Granted: true}
	}
	if err := f.users.SetPermissions(u.UserID, set); err != nil {
		t.Fatal(err)
	}
	return token, cert
}

func deviceOf(t *testing.T, f *matrixFixture, userID string) string {
	t.Helper()
	devs, err := f.devices.DevicesByUserID(userID)
	if err != nil || len(devs) == 0 {
		t.Fatalf("no device for user %s: %v", userID, err)
	}
	return devs[0].DeviceID
}

func newUnregisteredCert(t *testing.T) *x509.Certificate {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	serial, _ := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	tmpl := &x509.Certificate{
		SerialNumber: serial,
		Subject:      pkix.Name{CommonName: "stranger"},
		NotBefore:    time.Now().Add(-time.Minute),
		NotAfter:     time.Now().Add(time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatal(err)
	}
	return cert
}

var publicRoutes = []string{
	"GET /api/health",
	"GET /api/config",
	"GET /api/capabilities",
	"POST /api/cert/challenge",
	"POST /api/cert/renew",
	"POST /api/pair",
	"POST /api/session",
}

var authSweepRoutes = []struct {
	pattern string
	method  string
	url     string
}{
	{"GET /api/host-keys", "GET", "/api/host-keys"},
	{"POST /api/push/register", "POST", "/api/push/register"},
	{"GET /api/ssh-configs", "GET", "/api/ssh-configs"},
	{"POST /api/invites", "POST", "/api/invites"},
	{"GET /api/invites", "GET", "/api/invites"},
	{"DELETE /api/invites/{code}", "DELETE", "/api/invites/somecode"},
	{"GET /api/users", "GET", "/api/users"},
	{"PATCH /api/users/{id}", "PATCH", "/api/users/u1"},
	{"DELETE /api/users/{id}", "DELETE", "/api/users/u1"},
	{"POST /api/users/{id}/transfer-ownership", "POST", "/api/users/u1/transfer-ownership"},
	{"GET /api/devices", "GET", "/api/devices"},
	{"PATCH /api/devices/{id}", "PATCH", "/api/devices/d1"},
	{"DELETE /api/devices/{id}", "DELETE", "/api/devices/d1"},
	{"GET /api/sync/manifest", "GET", "/api/sync/manifest"},
	{"POST /api/sync/pull", "POST", "/api/sync/pull"},
	{"POST /api/sync/push", "POST", "/api/sync/push"},
	{"GET /api/metrics/available", "GET", "/api/metrics/available"},
	{"GET /api/metrics/latest", "GET", "/api/metrics/latest"},
	{"GET /api/metrics/series", "GET", "/api/metrics/series?metric=custom:cpu&range=1h"},
	{"POST /api/metrics/requests", "POST", "/api/metrics/requests"},
	{"GET /api/metrics/requests", "GET", "/api/metrics/requests"},
	{"POST /api/metrics/requests/{id}/approve", "POST", "/api/metrics/requests/r1/approve"},
	{"POST /api/metrics/requests/{id}/decline", "POST", "/api/metrics/requests/r1/decline"},
	{"DELETE /api/metrics/requests/{id}", "DELETE", "/api/metrics/requests/r1"},
	{"GET /api/vault/pubkeys", "GET", "/api/vault/pubkeys"},
	{"GET /api/vault/members", "GET", "/api/vault/members?vault_id=infra"},
	{"POST /api/vault/create", "POST", "/api/vault/create"},
	{"POST /api/vault/grant", "POST", "/api/vault/grant"},
	{"POST /api/vault/revoke", "POST", "/api/vault/revoke"},
	{"GET /api/server/status", "GET", "/api/server/status"},
	{"GET /api/server/config", "GET", "/api/server/config"},
	{"GET /api/audit", "GET", "/api/audit"},
	{"GET /api/logs", "GET", "/api/logs"},
}

func TestRouteInventory_AllRoutesClassified(t *testing.T) {
	f := newMatrixFixture(t)

	classified := map[string]bool{}
	for _, p := range publicRoutes {
		classified[p] = true
	}
	for _, r := range authSweepRoutes {
		classified[r.pattern] = true
	}

	seen := map[string]bool{}
	for _, p := range f.srv.routePatterns {
		seen[p] = true
		if !classified[p] {
			t.Errorf("route %q is registered but not classified in endpoint_matrix_test.go: add it to publicRoutes or authSweepRoutes (+ role matrix)", p)
		}
	}
	for p := range classified {
		if !seen[p] {
			t.Errorf("route %q is classified in endpoint_matrix_test.go but not registered: remove it or fix the fixture wiring", p)
		}
	}
}

func TestEndpointAuthMatrix(t *testing.T) {
	f := newMatrixFixture(t)

	strangerCert := newUnregisteredCert(t)

	revDevCert, revDevToken, erin := newTeamUserDevice(t, f.devices, f.users, f.mgr, f.serverKey, "erin", "member")
	if err := f.devices.Revoke(deviceOf(t, f, erin.UserID)); err != nil {
		t.Fatal(err)
	}
	revUserCert, revUserToken, frank := newTeamUserDevice(t, f.devices, f.users, f.mgr, f.serverKey, "frank", "member")
	if err := f.users.Revoke(frank.UserID); err != nil {
		t.Fatal(err)
	}

	scenarios := []struct {
		name  string
		cert  *x509.Certificate
		token string
		want  int
	}{
		{"no_client_cert", nil, "", http.StatusUnauthorized},
		{"unregistered_cert", strangerCert, "whatever", http.StatusForbidden},
		{"no_token", f.memberCert, "", http.StatusUnauthorized},
		{"garbage_token", f.memberCert, "garbage.token.here", http.StatusUnauthorized},
		// bob's token over carol's TLS channel must fail the cnf binding.
		{"token_bound_to_other_cert", f.admin2Cert, f.memberToken, http.StatusUnauthorized},
		{"revoked_device", revDevCert, revDevToken, http.StatusForbidden},
		{"revoked_user", revUserCert, revUserToken, http.StatusForbidden},
	}

	for _, sc := range scenarios {
		t.Run(sc.name, func(t *testing.T) {
			for _, rt := range authSweepRoutes {
				w := f.doAs(rt.method, rt.url, "", sc.token, sc.cert)
				if w.Code != sc.want {
					t.Errorf("%s %s: expected %d, got %d: %s",
						rt.method, rt.url, sc.want, w.Code, w.Body.String())
				}
			}
		})
	}
}

func TestPublicEndpoints_ReachableWithoutCredentials(t *testing.T) {
	f := newMatrixFixture(t)
	cases := []struct {
		method, url, body string
		want              int
	}{
		{"GET", "/api/health", "", http.StatusOK},
		{"GET", "/api/config", "", http.StatusOK},
		{"GET", "/api/capabilities", "", http.StatusOK},
		{"POST", "/api/cert/challenge", "{}", http.StatusBadRequest},
		{"POST", "/api/cert/renew", "{}", http.StatusBadRequest},
		{"POST", "/api/pair", "{}", http.StatusBadRequest},
		{"POST", "/api/session", "", http.StatusForbidden},
	}
	for _, c := range cases {
		w := f.doAs(c.method, c.url, c.body, "", nil)
		if w.Code != c.want {
			t.Errorf("%s %s anon: expected %d, got %d: %s", c.method, c.url, c.want, w.Code, w.Body.String())
		}
	}
}

const (
	asMember  = "member"  // bob: member, zero grants
	asGranted = "granted" // dave: member holding exactly roleCase.grants
	asAdmin   = "admin"   // carol: admin, NOT the owner
	asOwner   = "owner"   // alice: admin + owner
)

var callerOrder = []string{asMember, asGranted, asAdmin, asOwner}

type roleCase struct {
	name   string
	grants []string
	setup  func(t *testing.T, f *matrixFixture) (method, path, body string)
	want   map[string]int
}

func static(method, path, body string) func(*testing.T, *matrixFixture) (string, string, string) {
	return func(*testing.T, *matrixFixture) (string, string, string) { return method, path, body }
}

func newExtraMember(t *testing.T, f *matrixFixture, name string) *pki.UserRecord {
	t.Helper()
	_, _, u := newTeamUserDevice(t, f.devices, f.users, f.mgr, f.serverKey, name, "member")
	return u
}

func newExtraAdmin(t *testing.T, f *matrixFixture, name string) *pki.UserRecord {
	t.Helper()
	_, _, u := newTeamUserDevice(t, f.devices, f.users, f.mgr, f.serverKey, name, "admin")
	return u
}

func pendingMetricRequest(t *testing.T, f *matrixFixture) string {
	t.Helper()
	return pendingMetricRequestBy(t, f, f.memberUser.UserID)
}

func pendingMetricRequestBy(t *testing.T, f *matrixFixture, userID string) string {
	t.Helper()
	req, err := f.requests.Create("Uptime", "uptime", nil, userID)
	if err != nil {
		t.Fatal(err)
	}
	return req.ID
}

func ownerInvite(t *testing.T, f *matrixFixture) string {
	t.Helper()
	w := f.do("POST", "/api/invites", `{"role":"member"}`, f.adminToken, f.adminCert)
	if w.Code != http.StatusOK {
		t.Fatalf("owner invite: %d %s", w.Code, w.Body.String())
	}
	var resp struct {
		Code string `json:"code"`
	}
	if err := json.NewDecoder(w.Body).Decode(&resp); err != nil || resp.Code == "" {
		t.Fatalf("owner invite: bad response %v %q", err, resp.Code)
	}
	return resp.Code
}

var roleMatrixCases = []roleCase{
	{
		name:  "host-keys/get",
		setup: static("GET", "/api/host-keys", ""),
		want:  map[string]int{asMember: 200, asAdmin: 200, asOwner: 200},
	},
	{
		name: "push-register/post",
		setup: static("POST", "/api/push/register",
			`{"device_token":"tok","platform":"ios","signed_token":"sig","expires_at":9999999999}`),
		want: map[string]int{asMember: 200, asAdmin: 200, asOwner: 200},
	},

	{
		name:   "ssh-configs/get",
		grants: []string{authz.PermUsersManage, authz.PermSSHKeysSync},
		setup:  static("GET", "/api/ssh-configs", ""),
		want:   map[string]int{asMember: 403, asGranted: 403, asAdmin: 200, asOwner: 200},
	},

	{
		name:   "invites/create-member-invite",
		grants: []string{authz.PermInvitesManage},
		setup:  static("POST", "/api/invites", `{"role":"member"}`),
		want:   map[string]int{asMember: 403, asGranted: 200, asAdmin: 200, asOwner: 200},
	},
	{
		name:   "invites/create-admin-invite-owner-only",
		grants: []string{authz.PermInvitesManage},
		setup:  static("POST", "/api/invites", `{"role":"admin"}`),
		want:   map[string]int{asMember: 403, asGranted: 403, asAdmin: 403, asOwner: 200},
	},
	{
		name:   "invites/create-second-device-for-other-owner-only",
		grants: []string{authz.PermInvitesManage, authz.PermInvitesDevice},
		setup: func(t *testing.T, f *matrixFixture) (string, string, string) {
			eve := newExtraMember(t, f, "eve")
			return "POST", "/api/invites", fmt.Sprintf(`{"target_user_id":%q}`, eve.UserID)
		},
		want: map[string]int{asMember: 403, asGranted: 403, asAdmin: 403, asOwner: 200},
	},
	{
		name:  "invites/list",
		setup: static("GET", "/api/invites", ""),
		want:  map[string]int{asMember: 200, asAdmin: 200, asOwner: 200},
	},
	{
		name:   "invites/delete-foreign-invite",
		grants: []string{authz.PermInvitesManage},
		setup: func(t *testing.T, f *matrixFixture) (string, string, string) {
			return "DELETE", "/api/invites/" + ownerInvite(t, f), ""
		},
		want: map[string]int{asMember: 403, asGranted: 200, asAdmin: 200, asOwner: 200},
	},

	{
		name:  "users/list",
		setup: static("GET", "/api/users", ""),
		want:  map[string]int{asMember: 200, asAdmin: 200, asOwner: 200},
	},
	{
		name:   "users/patch-role-owner-only",
		grants: []string{authz.PermUsersManage},
		setup: func(t *testing.T, f *matrixFixture) (string, string, string) {
			eve := newExtraMember(t, f, "eve")
			return "PATCH", "/api/users/" + eve.UserID, `{"role":"admin"}`
		},
		want: map[string]int{asMember: 403, asGranted: 403, asAdmin: 403, asOwner: 200},
	},
	{
		name:   "users/patch-rename-member",
		grants: []string{authz.PermUsersManage},
		setup: func(t *testing.T, f *matrixFixture) (string, string, string) {
			eve := newExtraMember(t, f, "eve")
			return "PATCH", "/api/users/" + eve.UserID, `{"display_name":"evelyn"}`
		},
		want: map[string]int{asMember: 403, asGranted: 200, asAdmin: 200, asOwner: 200},
	},
	{
		name:   "users/patch-permissions-admin-only",
		grants: []string{authz.PermUsersManage},
		setup: func(t *testing.T, f *matrixFixture) (string, string, string) {
			eve := newExtraMember(t, f, "eve")
			return "PATCH", "/api/users/" + eve.UserID, `{"permissions":{"metrics.read":{"granted":true}}}`
		},
		want: map[string]int{asMember: 403, asGranted: 403, asAdmin: 200, asOwner: 200},
	},
	{
		name:   "users/delete-member",
		grants: []string{authz.PermUsersManage},
		setup: func(t *testing.T, f *matrixFixture) (string, string, string) {
			eve := newExtraMember(t, f, "eve")
			return "DELETE", "/api/users/" + eve.UserID, ""
		},
		want: map[string]int{asMember: 403, asGranted: 200, asAdmin: 200, asOwner: 200},
	},
	{
		name:   "users/delete-admin-owner-only",
		grants: []string{authz.PermUsersManage},
		setup: func(t *testing.T, f *matrixFixture) (string, string, string) {
			gina := newExtraAdmin(t, f, "gina")
			return "DELETE", "/api/users/" + gina.UserID, ""
		},
		want: map[string]int{asMember: 403, asGranted: 403, asAdmin: 403, asOwner: 200},
	},
	{
		name: "users/delete-owner-immutable",
		setup: func(t *testing.T, f *matrixFixture) (string, string, string) {
			return "DELETE", "/api/users/" + f.adminUser.UserID, ""
		},
		want: map[string]int{asMember: 409, asAdmin: 409, asOwner: 409},
	},
	{
		name: "users/patch-owner-role-immutable",
		setup: func(t *testing.T, f *matrixFixture) (string, string, string) {
			return "PATCH", "/api/users/" + f.adminUser.UserID, `{"role":"member"}`
		},
		want: map[string]int{asMember: 403, asAdmin: 403, asOwner: 409},
	},

	{
		name:   "users/transfer-ownership-owner-only",
		grants: []string{authz.PermUsersManage},
		setup: func(t *testing.T, f *matrixFixture) (string, string, string) {
			eve := newExtraMember(t, f, "eve")
			return "POST", "/api/users/" + eve.UserID + "/transfer-ownership", ""
		},
		want: map[string]int{asMember: 403, asGranted: 403, asAdmin: 403, asOwner: 200},
	},

	{
		name:  "devices/list",
		setup: static("GET", "/api/devices", ""),
		want:  map[string]int{asMember: 200, asAdmin: 200, asOwner: 200},
	},
	{
		name:  "devices/patch-self",
		setup: static("PATCH", "/api/devices/self", `{"device_name":"mine"}`),
		want:  map[string]int{asMember: 200, asAdmin: 200, asOwner: 200},
	},
	{
		name:   "devices/patch-other-needs-users-manage",
		grants: []string{authz.PermUsersManage},
		setup: func(t *testing.T, f *matrixFixture) (string, string, string) {
			eve := newExtraMember(t, f, "eve")
			return "PATCH", "/api/devices/" + deviceOf(t, f, eve.UserID), `{"device_label":"eve's"}`
		},
		want: map[string]int{asMember: 403, asGranted: 200, asAdmin: 200, asOwner: 200},
	},
	{
		name:   "devices/delete-member-device",
		grants: []string{authz.PermUsersManage},
		setup: func(t *testing.T, f *matrixFixture) (string, string, string) {
			eve := newExtraMember(t, f, "eve")
			return "DELETE", "/api/devices/" + deviceOf(t, f, eve.UserID), ""
		},
		want: map[string]int{asMember: 403, asGranted: 200, asAdmin: 200, asOwner: 200},
	},
	{
		name:   "devices/delete-admin-device-owner-only",
		grants: []string{authz.PermUsersManage},
		setup: func(t *testing.T, f *matrixFixture) (string, string, string) {
			gina := newExtraAdmin(t, f, "gina")
			return "DELETE", "/api/devices/" + deviceOf(t, f, gina.UserID), ""
		},
		want: map[string]int{asMember: 403, asGranted: 403, asAdmin: 403, asOwner: 200},
	},
	{
		// The fixture owner has exactly one device, so unpairing it would lock the owner out.
		name:  "devices/delete-self",
		setup: static("DELETE", "/api/devices/self", ""),
		want:  map[string]int{asMember: 200, asAdmin: 200, asOwner: 409},
	},

	{
		name:  "sync/manifest",
		setup: static("GET", "/api/sync/manifest", ""),
		want:  map[string]int{asMember: 200, asAdmin: 200, asOwner: 200},
	},
	{
		name:  "sync/pull",
		setup: static("POST", "/api/sync/pull", `{"ids":["nothing"]}`),
		want:  map[string]int{asMember: 200, asAdmin: 200, asOwner: 200},
	},
	{
		name: "sync/push-personal-record",
		setup: static("POST", "/api/sync/push",
			`{"records":[{"id":"n1","type":"note","updated_at":1000,"data":{"v":1}}]}`),
		want: map[string]int{asMember: 200, asAdmin: 200, asOwner: 200},
	},

	{
		name:   "metrics/available",
		grants: []string{authz.PermMetricsRead},
		setup:  static("GET", "/api/metrics/available", ""),
		want:   map[string]int{asMember: 403, asGranted: 200, asAdmin: 200, asOwner: 200},
	},
	{
		name:   "metrics/latest",
		grants: []string{authz.PermMetricsRead},
		setup:  static("GET", "/api/metrics/latest", ""),
		want:   map[string]int{asMember: 403, asGranted: 200, asAdmin: 200, asOwner: 200},
	},
	{
		name:   "metrics/series",
		grants: []string{authz.PermMetricsRead},
		setup:  static("GET", "/api/metrics/series?metric=custom:cpu&range=1h", ""),
		want:   map[string]int{asMember: 403, asGranted: 200, asAdmin: 200, asOwner: 200},
	},

	{
		name:  "metric-requests/create",
		setup: static("POST", "/api/metrics/requests", `{"label":"Uptime","command":"uptime"}`),
		want:  map[string]int{asMember: 200, asAdmin: 200, asOwner: 200},
	},
	{
		name:  "metric-requests/list",
		setup: static("GET", "/api/metrics/requests", ""),
		want:  map[string]int{asMember: 200, asAdmin: 200, asOwner: 200},
	},
	{
		name:   "metric-requests/approve-needs-create-grant",
		grants: []string{authz.PermMetricsCommandsCreate},
		setup: func(t *testing.T, f *matrixFixture) (string, string, string) {
			return "POST", "/api/metrics/requests/" + pendingMetricRequest(t, f) + "/approve", ""
		},
		want: map[string]int{asMember: 403, asGranted: 200, asAdmin: 403, asOwner: 200},
	},
	{
		name:   "metric-requests/decline-needs-create-grant",
		grants: []string{authz.PermMetricsCommandsCreate},
		setup: func(t *testing.T, f *matrixFixture) (string, string, string) {
			return "POST", "/api/metrics/requests/" + pendingMetricRequest(t, f) + "/decline", ""
		},
		want: map[string]int{asMember: 403, asGranted: 200, asAdmin: 403, asOwner: 200},
	},
	{
		name:   "metric-requests/approve-update-grant-is-not-enough",
		grants: []string{authz.PermMetricsCommandsUpdate, authz.PermMetricsCommandsDelete},
		setup: func(t *testing.T, f *matrixFixture) (string, string, string) {
			return "POST", "/api/metrics/requests/" + pendingMetricRequest(t, f) + "/approve", ""
		},
		want: map[string]int{asMember: 403, asGranted: 403, asAdmin: 403, asOwner: 200},
	},
	{
		name:   "metric-requests/delete-needs-grant",
		grants: []string{authz.PermMetricsCommandsDelete},
		setup: func(t *testing.T, f *matrixFixture) (string, string, string) {
			// Filed by the owner so the member column hits the grant gate, not the withdraw-own path.
			return "DELETE", "/api/metrics/requests/" + pendingMetricRequestBy(t, f, f.adminUser.UserID), ""
		},
		want: map[string]int{asMember: 403, asGranted: 200, asAdmin: 200, asOwner: 200},
	},
	{
		name:   "metric-requests/withdraw-own-pending",
		grants: []string{authz.PermMetricsCommandsDelete},
		setup: func(t *testing.T, f *matrixFixture) (string, string, string) {
			return "DELETE", "/api/metrics/requests/" + pendingMetricRequest(t, f), ""
		},
		want: map[string]int{asMember: 200, asGranted: 200, asAdmin: 200, asOwner: 200},
	},

	{
		name:  "vault/pubkeys",
		setup: static("GET", "/api/vault/pubkeys", ""),
		want:  map[string]int{asMember: 200, asAdmin: 200, asOwner: 200},
	},
	{
		name:   "vault/members-needs-vault-level",
		grants: []string{authz.PermUsersManage},
		setup: func(t *testing.T, f *matrixFixture) (string, string, string) {
			eve := newExtraMember(t, f, "eve")
			if err := f.syncStore.GrantVault("infra", eve.UserID, datasync.LevelManage); err != nil {
				t.Fatal(err)
			}
			return "GET", "/api/vault/members?vault_id=infra", ""
		},
		want: map[string]int{asMember: 403, asGranted: 403, asAdmin: 403, asOwner: 200},
	},
	{
		name:   "vault/create-admin-or-owner",
		grants: []string{authz.PermUsersManage},
		setup:  static("POST", "/api/vault/create", `{"vault_id":"infra"}`),
		want:   map[string]int{asMember: 403, asGranted: 403, asAdmin: 200, asOwner: 200},
	},
	{
		name:   "vault/grant-needs-manage-level",
		grants: []string{authz.PermUsersManage},
		setup: func(t *testing.T, f *matrixFixture) (string, string, string) {
			eve := newExtraMember(t, f, "eve")
			if err := f.syncStore.GrantVault("infra", eve.UserID, datasync.LevelManage); err != nil {
				t.Fatal(err)
			}
			body := fmt.Sprintf(`{"vault_id":"infra","user_id":%q,"level":"view"}`, f.memberUser.UserID)
			return "POST", "/api/vault/grant", body
		},
		want: map[string]int{asMember: 403, asGranted: 403, asAdmin: 403, asOwner: 204},
	},
	{
		name:   "vault/revoke-needs-manage-level",
		grants: []string{authz.PermUsersManage},
		setup: func(t *testing.T, f *matrixFixture) (string, string, string) {
			eve := newExtraMember(t, f, "eve")
			if err := f.syncStore.GrantVault("infra", eve.UserID, datasync.LevelManage); err != nil {
				t.Fatal(err)
			}
			// A second manager so revoking eve exercises the manage gate, not the last-manager guard.
			frank := newExtraMember(t, f, "frank")
			if err := f.syncStore.GrantVault("infra", frank.UserID, datasync.LevelManage); err != nil {
				t.Fatal(err)
			}
			body := fmt.Sprintf(`{"vault_id":"infra","user_id":%q}`, eve.UserID)
			return "POST", "/api/vault/revoke", body
		},
		want: map[string]int{asMember: 403, asGranted: 403, asAdmin: 403, asOwner: 204},
	},

	{
		name:   "server/status-admin-only",
		grants: []string{authz.PermUsersManage},
		setup:  static("GET", "/api/server/status", ""),
		want:   map[string]int{asMember: 403, asGranted: 403, asAdmin: 200, asOwner: 200},
	},
	{
		name:  "server/config-read-admin-only",
		setup: static("GET", "/api/server/config", ""),
		want:  map[string]int{asMember: 403, asAdmin: 200, asOwner: 200},
	},
	{
		name:  "audit/owner-only",
		setup: static("GET", "/api/audit", ""),
		want:  map[string]int{asMember: 403, asAdmin: 403, asOwner: 200},
	},
	{
		name:  "logs/owner-only",
		setup: static("GET", "/api/logs", ""),
		want:  map[string]int{asMember: 403, asAdmin: 403, asOwner: 200},
	},
}

func TestEndpointRoleMatrix(t *testing.T) {
	for _, tc := range roleMatrixCases {
		for _, caller := range callerOrder {
			want, ok := tc.want[caller]
			if !ok {
				continue
			}
			t.Run(tc.name+"/"+caller, func(t *testing.T) {
				f := newMatrixFixture(t)
				method, path, body := tc.setup(t, f)

				var token string
				var cert *x509.Certificate
				switch caller {
				case asMember:
					token, cert = f.memberToken, f.memberCert
				case asGranted:
					token, cert = f.grantedMember(t, tc.grants...)
				case asAdmin:
					token, cert = f.admin2Token, f.admin2Cert
				case asOwner:
					token, cert = f.adminToken, f.adminCert
				}

				w := f.doAs(method, path, body, token, cert)
				if w.Code != want {
					t.Fatalf("%s %s as %s: expected %d, got %d: %s",
						method, path, caller, want, w.Code, w.Body.String())
				}
			})
		}
	}
}

func TestRoleMatrixCoversAllAuthedRoutes(t *testing.T) {
	f := newMatrixFixture(t)

	covered := map[string]bool{}
	for _, tc := range roleMatrixCases {
		method, path, _ := tc.setup(t, f)
		path = strings.SplitN(path, "?", 2)[0]
		req := apiRequest(method, path, nil)
		_, pattern := f.srv.mux.Handler(req)
		if pattern != "" {
			covered[pattern] = true
		}
	}

	for _, r := range authSweepRoutes {
		if !covered[r.pattern] {
			t.Errorf("authenticated route %q has no TestEndpointRoleMatrix entry", r.pattern)
		}
	}
}
