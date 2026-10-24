package server

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"database/sql"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/pocketcmd/pocketcmd-server/internal/config"
	"github.com/pocketcmd/pocketcmd-server/internal/datasync"
	"github.com/pocketcmd/pocketcmd-server/internal/pki"
	"github.com/pocketcmd/pocketcmd-server/internal/session"
)

func testAuditLogger(buf *bytes.Buffer) *slog.Logger {
	h := slog.NewTextHandler(buf, &slog.HandlerOptions{Level: slog.LevelDebug})
	return slog.New(h)
}

func newTeamTestFixtureWithAudit(t *testing.T) (*teamTestFixture, *bytes.Buffer) {
	t.Helper()

	var buf bytes.Buffer

	serverKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}

	db := testStateDB(t)
	devices := testDeviceRegistryOn(db)
	users := pki.NewUserRegistry(db)
	invites := pki.NewInviteStore(db)
	mgr := session.NewManager(serverKey)

	cfg := &config.ServerConfig{Host: "127.0.0.1", Port: 8767}
	srv := NewServer(cfg)
	srv.SetSecurityServices(mgr, devices, users, serverKey)
	srv.SetAuditLogger(testAuditLogger(&buf))
	srv.RegisterTeamRoutes(users, devices, invites)

	adminCert, adminToken, adminUser := newTeamUserDevice(t, devices, users, mgr, serverKey, "alice", "admin")
	if err := users.SetOwner(adminUser.UserID, true); err != nil {
		t.Fatal(err)
	}
	adminUser.Owner = true
	memberCert, memberToken, memberUser := newTeamUserDevice(t, devices, users, mgr, serverKey, "bob", "member")

	return &teamTestFixture{
		srv:         srv,
		db:          db,
		adminToken:  adminToken,
		adminCert:   adminCert,
		memberToken: memberToken,
		memberCert:  memberCert,
		adminUser:   adminUser,
		memberUser:  memberUser,
		invites:     invites,
		users:       users,
		mgr:         mgr,
		devices:     devices,
		serverKey:   serverKey,
	}, &buf
}

type teamTestFixture struct {
	srv         *Server
	db          *sql.DB
	adminToken  string
	adminCert   *x509.Certificate
	memberToken string
	memberCert  *x509.Certificate
	adminUser   *pki.UserRecord
	memberUser  *pki.UserRecord
	invites     *pki.InviteStore
	users       *pki.UserRegistry
	devices     *pki.DeviceRegistry
	mgr         *session.Manager
	serverKey   *ecdsa.PrivateKey
}

func newTeamTestFixture(t *testing.T) *teamTestFixture {
	t.Helper()
	f, _ := newTeamTestFixtureWithAudit(t)
	return f
}

func newTeamUserDevice(
	t *testing.T,
	devices *pki.DeviceRegistry,
	users *pki.UserRegistry,
	mgr *session.Manager,
	serverKey *ecdsa.PrivateKey,
	displayName, role string,
) (*x509.Certificate, string, *pki.UserRecord) {
	t.Helper()

	deviceKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}

	pubDER, err := x509.MarshalPKIXPublicKey(&deviceKey.PublicKey)
	if err != nil {
		t.Fatal(err)
	}
	pubPEM := string(pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: pubDER}))

	user, err := users.Create(displayName, role, "")
	if err != nil {
		t.Fatalf("create user %s: %v", displayName, err)
	}

	deviceID, err := devices.RegisterDeviceForUser(pubPEM, displayName+"-device", user.UserID, "")
	if err != nil {
		t.Fatal(err)
	}

	cert := issueTestClientCert(t, serverKey, &deviceKey.PublicKey, 30*time.Minute)

	certFP := pki.CertFingerprint(cert.Raw)
	token, err := mgr.Issue(deviceID, certFP)
	if err != nil {
		t.Fatal(err)
	}

	return cert, token, user
}

func (f *teamTestFixture) do(method, path, body, token string, cert *x509.Certificate) *httptest.ResponseRecorder {
	var req *http.Request
	if body != "" {
		req = apiRequest(method, path, strings.NewReader(body))
		req.Header.Set("Content-Type", "application/json")
	} else {
		req = apiRequest(method, path, nil)
	}
	if cert != nil {
		req.TLS = &tls.ConnectionState{
			PeerCertificates: []*x509.Certificate{cert},
		}
	}
	if token != "" {
		req.Header.Set("Authorization", "Bearer "+token)
	}
	w := httptest.NewRecorder()
	f.srv.ServeHTTP(w, req)
	return w
}

func TestInvites_Create_Admin200(t *testing.T) {
	f := newTeamTestFixture(t)
	body := `{"role":"member","expires_in_seconds":3600}`
	w := f.do("POST", "/api/invites", body, f.adminToken, f.adminCert)
	if w.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", w.Code, w.Body.String())
	}
	var resp map[string]string
	if err := json.NewDecoder(w.Body).Decode(&resp); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if resp["code"] == "" {
		t.Error("expected non-empty code")
	}
	if resp["expires_at"] == "" {
		t.Error("expected non-empty expires_at")
	}
	if !strings.HasPrefix(resp["qr_url"], "pocketcmd://invite?") {
		t.Errorf("expected qr_url to start with pocketcmd://invite?, got %s", resp["qr_url"])
	}
}

func TestInvites_Create_TargetUserInheritsRole(t *testing.T) {
	f := newTeamTestFixture(t)

	body := fmt.Sprintf(`{"expires_in_seconds":3600,"target_user_id":%q}`, f.memberUser.UserID)
	w := f.do("POST", "/api/invites", body, f.adminToken, f.adminCert)
	if w.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", w.Code, w.Body.String())
	}
	var resp map[string]string
	if err := json.NewDecoder(w.Body).Decode(&resp); err != nil {
		t.Fatalf("decode: %v", err)
	}
	inv, err := f.invites.FindByCode(resp["code"])
	if err != nil || inv == nil {
		t.Fatalf("invite lookup: %v", err)
	}
	if inv.Role != f.memberUser.Role {
		t.Errorf("expected inherited role %q, got %q", f.memberUser.Role, inv.Role)
	}
	if inv.TargetUserID != f.memberUser.UserID {
		t.Errorf("expected target_user_id %q, got %q", f.memberUser.UserID, inv.TargetUserID)
	}
}

func TestInvites_Create_UnknownTargetUser404(t *testing.T) {
	f := newTeamTestFixture(t)
	body := `{"expires_in_seconds":3600,"target_user_id":"nosuchuser123"}`
	w := f.do("POST", "/api/invites", body, f.adminToken, f.adminCert)
	if w.Code != http.StatusNotFound {
		t.Fatalf("expected 404, got %d: %s", w.Code, w.Body.String())
	}
	var resp map[string]string
	json.NewDecoder(w.Body).Decode(&resp)
	if resp["error"] != "target_user_not_found" {
		t.Errorf("expected error 'target_user_not_found', got %q", resp["error"])
	}
}

func TestInvites_Create_Member403(t *testing.T) {
	f := newTeamTestFixture(t)
	body := `{"role":"member","expires_in_seconds":3600}`
	w := f.do("POST", "/api/invites", body, f.memberToken, f.memberCert)
	if w.Code != http.StatusForbidden {
		t.Fatalf("expected 403, got %d: %s", w.Code, w.Body.String())
	}
	var resp map[string]string
	if err := json.NewDecoder(w.Body).Decode(&resp); err != nil {
		t.Fatalf("expected JSON body, got decode error: %v", err)
	}
	if resp["error"] != "forbidden" {
		t.Errorf("expected error 'forbidden', got %q", resp["error"])
	}
}

func TestInvites_Create_BadRole400(t *testing.T) {
	f := newTeamTestFixture(t)
	body := `{"role":"superuser","expires_in_seconds":3600}`
	w := f.do("POST", "/api/invites", body, f.adminToken, f.adminCert)
	if w.Code != http.StatusBadRequest {
		t.Fatalf("expected 400, got %d: %s", w.Code, w.Body.String())
	}
	var resp map[string]string
	json.NewDecoder(w.Body).Decode(&resp)
	if resp["error"] == "" {
		t.Error("expected error field in response")
	}
}

func TestInvites_List_AdminReturnsActive(t *testing.T) {
	f := newTeamTestFixture(t)

	f.do("POST", "/api/invites", `{"role":"member","expires_in_seconds":3600}`, f.adminToken, f.adminCert)
	f.do("POST", "/api/invites", `{"role":"admin","expires_in_seconds":7200}`, f.adminToken, f.adminCert)

	w := f.do("GET", "/api/invites", "", f.adminToken, f.adminCert)
	if w.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", w.Code, w.Body.String())
	}
	var list []map[string]interface{}
	if err := json.NewDecoder(w.Body).Decode(&list); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if len(list) != 2 {
		t.Fatalf("expected 2 active invites, got %d", len(list))
	}
	for _, inv := range list {
		if inv["code"] == nil || inv["code"] == "" {
			t.Error("expected non-empty code in list item")
		}
		if inv["role"] == nil {
			t.Error("expected role in list item")
		}
	}
}

func grantInvitesDevice(t *testing.T, f *teamTestFixture, userID string) {
	t.Helper()
	if err := f.users.SetPermissions(userID, pki.PermissionSet{
		"invites.device": {Granted: true},
	}); err != nil {
		t.Fatal(err)
	}
}

func TestInvites_List_MemberSeesOnlyOwn(t *testing.T) {
	f := newTeamTestFixture(t)
	grantInvitesDevice(t, f, f.memberUser.UserID)

	aw := f.do("POST", "/api/invites", `{"role":"member","expires_in_seconds":3600}`, f.adminToken, f.adminCert)
	if aw.Code != http.StatusOK {
		t.Fatalf("admin create: %d %s", aw.Code, aw.Body.String())
	}
	var adminInvite map[string]string
	json.NewDecoder(aw.Body).Decode(&adminInvite)

	body := fmt.Sprintf(`{"expires_in_seconds":3600,"target_user_id":%q}`, f.memberUser.UserID)
	mw := f.do("POST", "/api/invites", body, f.memberToken, f.memberCert)
	if mw.Code != http.StatusOK {
		t.Fatalf("member self-invite: %d %s", mw.Code, mw.Body.String())
	}
	var memberInvite map[string]string
	json.NewDecoder(mw.Body).Decode(&memberInvite)

	lw := f.do("GET", "/api/invites", "", f.memberToken, f.memberCert)
	if lw.Code != http.StatusOK {
		t.Fatalf("member list: %d %s", lw.Code, lw.Body.String())
	}
	var memberList []map[string]interface{}
	json.NewDecoder(lw.Body).Decode(&memberList)
	if len(memberList) != 1 || memberList[0]["code"] != memberInvite["code"] {
		t.Fatalf("member should see exactly their own invite, got %v", memberList)
	}

	alw := f.do("GET", "/api/invites", "", f.adminToken, f.adminCert)
	var adminList []map[string]interface{}
	json.NewDecoder(alw.Body).Decode(&adminList)
	if len(adminList) != 2 {
		t.Fatalf("admin should see both invites, got %v", adminList)
	}
}

func TestInvites_Create_MemberSelfService(t *testing.T) {
	f := newTeamTestFixture(t)
	grantInvitesDevice(t, f, f.memberUser.UserID)

	body := fmt.Sprintf(`{"expires_in_seconds":3600,"target_user_id":%q}`, f.memberUser.UserID)
	w := f.do("POST", "/api/invites", body, f.memberToken, f.memberCert)
	if w.Code != http.StatusOK {
		t.Fatalf("expected 200 for self-invite, got %d: %s", w.Code, w.Body.String())
	}
	var resp map[string]string
	json.NewDecoder(w.Body).Decode(&resp)
	inv, err := f.invites.FindByCode(resp["code"])
	if err != nil || inv == nil {
		t.Fatalf("invite lookup: %v", err)
	}
	if inv.Role != "member" || inv.TargetUserID != f.memberUser.UserID {
		t.Fatalf("self-invite wrong shape: %+v", inv)
	}

	body = fmt.Sprintf(`{"expires_in_seconds":3600,"target_user_id":%q}`, f.adminUser.UserID)
	w = f.do("POST", "/api/invites", body, f.memberToken, f.memberCert)
	if w.Code != http.StatusForbidden {
		t.Fatalf("expected 403 for cross-user target, got %d: %s", w.Code, w.Body.String())
	}
}

func TestInvites_Delete_MemberOwnOnly(t *testing.T) {
	f := newTeamTestFixture(t)
	grantInvitesDevice(t, f, f.memberUser.UserID)

	aw := f.do("POST", "/api/invites", `{"role":"member","expires_in_seconds":3600}`, f.adminToken, f.adminCert)
	var adminInvite map[string]string
	json.NewDecoder(aw.Body).Decode(&adminInvite)
	w := f.do("DELETE", "/api/invites/"+adminInvite["code"], "", f.memberToken, f.memberCert)
	if w.Code != http.StatusForbidden {
		t.Fatalf("expected 403 revoking admin invite, got %d: %s", w.Code, w.Body.String())
	}

	body := fmt.Sprintf(`{"expires_in_seconds":3600,"target_user_id":%q}`, f.memberUser.UserID)
	mw := f.do("POST", "/api/invites", body, f.memberToken, f.memberCert)
	var memberInvite map[string]string
	json.NewDecoder(mw.Body).Decode(&memberInvite)
	w = f.do("DELETE", "/api/invites/"+memberInvite["code"], "", f.memberToken, f.memberCert)
	if w.Code != http.StatusOK {
		t.Fatalf("expected 200 revoking own invite, got %d: %s", w.Code, w.Body.String())
	}
}

func TestInvites_Delete_AdminRevokes(t *testing.T) {
	f := newTeamTestFixture(t)

	cw := f.do("POST", "/api/invites", `{"role":"member","expires_in_seconds":3600}`, f.adminToken, f.adminCert)
	var created map[string]string
	json.NewDecoder(cw.Body).Decode(&created)
	code := created["code"]

	w := f.do("DELETE", "/api/invites/"+code, "", f.adminToken, f.adminCert)
	if w.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", w.Code, w.Body.String())
	}

	lw := f.do("GET", "/api/invites", "", f.adminToken, f.adminCert)
	var list []map[string]interface{}
	json.NewDecoder(lw.Body).Decode(&list)
	if len(list) != 0 {
		t.Fatalf("expected 0 active invites after revoke, got %d", len(list))
	}
}

func TestInvites_Delete_AdminUnknownCode404(t *testing.T) {
	f := newTeamTestFixture(t)
	w := f.do("DELETE", "/api/invites/nosuchcode234567", "", f.adminToken, f.adminCert)
	if w.Code != http.StatusNotFound {
		t.Fatalf("expected 404, got %d: %s", w.Code, w.Body.String())
	}
}

func TestInvites_Delete_InvalidCode400(t *testing.T) {
	f := newTeamTestFixture(t)
	for _, bad := range []string{"abc", "nosuchcode1234", "%25%25%25%25%25%25%25%25", "________", "abcdefghijklmnopq"} {
		w := f.do("DELETE", "/api/invites/"+bad, "", f.adminToken, f.adminCert)
		if w.Code != http.StatusBadRequest || !strings.Contains(w.Body.String(), "invalid_code") {
			t.Fatalf("code %q: expected 400 invalid_code, got %d: %s", bad, w.Code, w.Body.String())
		}
	}
}

func TestInvites_Delete_ConsumedInvite409(t *testing.T) {
	f := newTeamTestFixture(t)

	cw := f.do("POST", "/api/invites", `{"role":"member","expires_in_seconds":3600}`, f.adminToken, f.adminCert)
	var created map[string]string
	json.NewDecoder(cw.Body).Decode(&created)
	code := created["code"]

	if err := f.invites.MarkConsumed(code, "some-device-id"); err != nil {
		t.Fatalf("mark consumed: %v", err)
	}

	w := f.do("DELETE", "/api/invites/"+code, "", f.adminToken, f.adminCert)
	if w.Code != http.StatusConflict {
		t.Fatalf("expected 409, got %d: %s", w.Code, w.Body.String())
	}
}

func TestInvites_Delete_Member403(t *testing.T) {
	f := newTeamTestFixture(t)

	cw := f.do("POST", "/api/invites", `{"role":"member","expires_in_seconds":3600}`, f.adminToken, f.adminCert)
	var created map[string]string
	json.NewDecoder(cw.Body).Decode(&created)
	code := created["code"]

	w := f.do("DELETE", "/api/invites/"+code, "", f.memberToken, f.memberCert)
	if w.Code != http.StatusForbidden {
		t.Fatalf("expected 403, got %d: %s", w.Code, w.Body.String())
	}
	var resp map[string]string
	if err := json.NewDecoder(w.Body).Decode(&resp); err != nil {
		t.Fatalf("expected JSON body, got decode error: %v", err)
	}
	if resp["error"] != "forbidden" {
		t.Errorf("expected error 'forbidden', got %q", resp["error"])
	}
}

func TestUsers_List_Admin200(t *testing.T) {
	f := newTeamTestFixture(t)
	w := f.do("GET", "/api/users", "", f.adminToken, f.adminCert)
	if w.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", w.Code, w.Body.String())
	}
	var list []map[string]interface{}
	if err := json.NewDecoder(w.Body).Decode(&list); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if len(list) != 2 {
		t.Fatalf("expected 2 users, got %d", len(list))
	}
	for _, u := range list {
		if u["user_id"] == nil || u["user_id"] == "" {
			t.Error("expected user_id in list item")
		}
		if u["role"] == nil {
			t.Error("expected role in list item")
		}
	}
}

func TestUsers_List_Member200(t *testing.T) {
	f := newTeamTestFixture(t)
	w := f.do("GET", "/api/users", "", f.memberToken, f.memberCert)
	if w.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", w.Code, w.Body.String())
	}
	var list []map[string]interface{}
	if err := json.NewDecoder(w.Body).Decode(&list); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if len(list) != 2 {
		t.Fatalf("expected 2 users, got %d", len(list))
	}
}

func TestUsers_Patch_AdminChangesRole(t *testing.T) {
	f := newTeamTestFixture(t)
	targetID := f.memberUser.UserID

	body := `{"role":"admin"}`
	w := f.do("PATCH", "/api/users/"+targetID, body, f.adminToken, f.adminCert)
	if w.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", w.Code, w.Body.String())
	}

	updated, err := f.users.FindByID(targetID)
	if err != nil || updated == nil {
		t.Fatalf("lookup after patch: %v", err)
	}
	if updated.Role != "admin" {
		t.Errorf("expected role admin, got %s", updated.Role)
	}
}

func TestUsers_Patch_SelfRenameAllowed(t *testing.T) {
	f := newTeamTestFixture(t)
	targetID := f.memberUser.UserID

	body := `{"display_name":"Bob Renamed"}`
	w := f.do("PATCH", "/api/users/"+targetID, body, f.memberToken, f.memberCert)
	if w.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", w.Code, w.Body.String())
	}

	updated, err := f.users.FindByID(targetID)
	if err != nil || updated == nil {
		t.Fatalf("lookup after patch: %v", err)
	}
	if updated.DisplayName != "Bob Renamed" {
		t.Errorf("expected display_name 'Bob Renamed', got %s", updated.DisplayName)
	}
}

func TestUsers_Patch_MemberRenamesOther403(t *testing.T) {
	f := newTeamTestFixture(t)
	targetID := f.adminUser.UserID

	body := `{"display_name":"Alice Renamed"}`
	w := f.do("PATCH", "/api/users/"+targetID, body, f.memberToken, f.memberCert)
	if w.Code != http.StatusForbidden {
		t.Fatalf("expected 403, got %d: %s", w.Code, w.Body.String())
	}
}

func TestUsers_Patch_DemotingLastAdmin409(t *testing.T) {
	f := newTeamTestFixture(t)
	targetID := f.adminUser.UserID

	body := `{"role":"member"}`
	w := f.do("PATCH", "/api/users/"+targetID, body, f.adminToken, f.adminCert)
	if w.Code != http.StatusConflict {
		t.Fatalf("expected 409, got %d: %s", w.Code, w.Body.String())
	}
	var resp map[string]string
	json.NewDecoder(w.Body).Decode(&resp)
	if resp["error"] != "owner_immutable" {
		t.Errorf("expected error 'owner_immutable', got %q", resp["error"])
	}
}

func TestUsers_Delete_AdminCascades(t *testing.T) {
	f := newTeamTestFixture(t)
	targetID := f.memberUser.UserID

	inv, err := f.invites.Create(pki.CreateInviteParams{
		Role:         "member",
		TargetUserID: targetID,
		ExpiresIn:    time.Hour,
	})
	if err != nil {
		t.Fatalf("create targeted invite: %v", err)
	}

	w := f.do("DELETE", "/api/users/"+targetID, "", f.adminToken, f.adminCert)
	if w.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", w.Code, w.Body.String())
	}

	u, err2 := f.users.FindByID(targetID)
	if err2 != nil || u == nil {
		t.Fatalf("lookup after delete: %v", err2)
	}
	if u.Status != "revoked" {
		t.Errorf("expected status revoked, got %s", u.Status)
	}

	devs, _ := f.devices.DevicesByUserID(targetID)
	for _, d := range devs {
		if d.Status != "revoked" {
			t.Errorf("device %s not revoked after user delete", d.DeviceID)
		}
	}

	storedInv, err3 := f.invites.FindByCode(inv.Code)
	if err3 != nil || storedInv == nil {
		t.Fatalf("lookup invite after delete: %v", err3)
	}
	if storedInv.RevokedAt == "" {
		t.Errorf("expected invite %s to be revoked after user delete, RevokedAt is empty", inv.Code)
	}
}

func TestUsers_Delete_DeletingLastAdmin409(t *testing.T) {
	f := newTeamTestFixture(t)
	targetID := f.adminUser.UserID

	w := f.do("DELETE", "/api/users/"+targetID, "", f.adminToken, f.adminCert)
	if w.Code != http.StatusConflict {
		t.Fatalf("expected 409, got %d: %s", w.Code, w.Body.String())
	}
	var resp map[string]string
	json.NewDecoder(w.Body).Decode(&resp)
	if resp["error"] != "owner_immutable" {
		t.Errorf("expected error 'owner_immutable', got %q", resp["error"])
	}
}

func TestInvites_Create_QRURLUsesAdvertisedHost(t *testing.T) {
	serverKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	devices := testDeviceRegistry(t)
	users := pki.NewUserRegistry(testStateDB(t))
	invites := pki.NewInviteStore(testStateDB(t))
	mgr := session.NewManager(serverKey)

	cfg := &config.ServerConfig{Host: "0.0.0.0", Port: 8767}
	srv := NewServer(cfg)
	srv.SetSecurityServices(mgr, devices, users, serverKey)
	srv.SetAdvertisedHost("192.168.1.10")
	srv.RegisterTeamRoutes(users, devices, invites)

	adminCert, adminToken, _ := newTeamUserDevice(t, devices, users, mgr, serverKey, "alice", "admin")

	f := &teamTestFixture{srv: srv, adminToken: adminToken, adminCert: adminCert}
	body := `{"role":"member","expires_in_seconds":3600}`
	w := f.do("POST", "/api/invites", body, f.adminToken, f.adminCert)
	if w.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", w.Code, w.Body.String())
	}
	var resp map[string]string
	if err := json.NewDecoder(w.Body).Decode(&resp); err != nil {
		t.Fatalf("decode: %v", err)
	}
	qrURL := resp["qr_url"]
	if !strings.Contains(qrURL, "host=192.168.1.10") {
		t.Errorf("expected qr_url to contain host=192.168.1.10, got %s", qrURL)
	}
	if strings.Contains(qrURL, "0.0.0.0") {
		t.Errorf("expected qr_url NOT to contain 0.0.0.0 (bind address), got %s", qrURL)
	}
}

func TestUsers_Delete_PurgeData(t *testing.T) {
	f := newTeamTestFixture(t)
	targetID := f.memberUser.UserID

	memberDevs, err := f.devices.DevicesByUserID(targetID)
	if err != nil || len(memberDevs) == 0 {
		t.Fatalf("member device lookup failed: %v (%d devices)", err, len(memberDevs))
	}
	adminDevs, err := f.devices.DevicesByUserID(f.adminUser.UserID)
	if err != nil || len(adminDevs) == 0 {
		t.Fatalf("admin device lookup failed: %v (%d devices)", err, len(adminDevs))
	}

	store := newTestSyncStore(t)
	f.srv.RegisterSyncRoutes(store)
	_, err = store.PushRecords("", []datasync.SyncRecord{
		{ID: "member-task", Type: "task", UpdatedAt: 1, DeviceID: memberDevs[0].DeviceID,
			Data: json.RawMessage(`{"secret":"member"}`), Credentials: "s3cret"},
		{ID: "admin-task", Type: "task", UpdatedAt: 1, DeviceID: adminDevs[0].DeviceID,
			Data: json.RawMessage(`{"keep":"admin"}`)},
	})
	if err != nil {
		t.Fatal(err)
	}

	logStore := NewLogStore(testStateDB(t), 100)
	f.srv.SetLogSource(logStore)
	logStore.Append(json.RawMessage(
		`{"msg":"request","user_id":"` + targetID + `","path":"/member"}`))
	logStore.Append(json.RawMessage(
		`{"msg":"request","user_id":"` + f.adminUser.UserID + `","path":"/admin"}`))

	w := f.do("DELETE", "/api/users/"+targetID+"?purge_data=true", "", f.adminToken, f.adminCert)
	if w.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", w.Code, w.Body.String())
	}
	var resp map[string]interface{}
	if err := json.NewDecoder(w.Body).Decode(&resp); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if resp["status"] != "ok" {
		t.Errorf("expected status 'ok', got %v", resp["status"])
	}
	if resp["purged_records"] != float64(1) {
		t.Errorf("expected purged_records 1, got %v", resp["purged_records"])
	}

	recs, err := store.PullRecords("", []string{"member-task", "admin-task"})
	if err != nil || len(recs) != 2 {
		t.Fatalf("pull after purge: %v (%d records)", err, len(recs))
	}
	for _, rec := range recs {
		switch rec.ID {
		case "member-task":
			if !rec.Deleted || string(rec.Data) != "{}" || rec.Credentials != "" {
				t.Errorf("member record not purged: deleted=%v data=%s creds=%q",
					rec.Deleted, rec.Data, rec.Credentials)
			}
		case "admin-task":
			if rec.Deleted || string(rec.Data) != `{"keep":"admin"}` {
				t.Errorf("admin record must be untouched: deleted=%v data=%s", rec.Deleted, rec.Data)
			}
		}
	}

	scrubbed, err := f.users.FindByID(targetID)
	if err != nil || scrubbed == nil {
		t.Fatalf("purged user row must be retained: %v", err)
	}
	if scrubbed.Status != "revoked" || scrubbed.DisplayName != "" {
		t.Errorf("expected revoked user with blank display name, got status=%q name=%q",
			scrubbed.Status, scrubbed.DisplayName)
	}
	scrubbedDevs, _ := f.devices.DevicesByUserID(targetID)
	for _, d := range scrubbedDevs {
		if d.DeviceName != "" || d.DeviceLabel != "" || d.LastSeenAt != "" {
			t.Errorf("device metadata not scrubbed: %+v", d)
		}
		if d.PublicKey == "" {
			t.Errorf("device public key must be retained for the mTLS gate")
		}
	}

	entries, total, _ := logStore.Query(LogQuery{Limit: 10})
	if total != 1 || len(entries) != 1 {
		t.Fatalf("expected exactly the admin log entry to survive, got %d", total)
	}
	if !strings.Contains(string(entries[0].Entry), f.adminUser.UserID) {
		t.Errorf("surviving log entry should be the admin's: %s", entries[0].Entry)
	}
}

func TestUsers_Delete_PurgeData_SyncDisabled(t *testing.T) {
	f := newTeamTestFixture(t)
	targetID := f.memberUser.UserID

	w := f.do("DELETE", "/api/users/"+targetID+"?purge_data=true", "", f.adminToken, f.adminCert)
	if w.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", w.Code, w.Body.String())
	}
	var resp map[string]interface{}
	if err := json.NewDecoder(w.Body).Decode(&resp); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if resp["purged_records"] != float64(0) {
		t.Errorf("expected purged_records 0 without sync store, got %v", resp["purged_records"])
	}
}

func TestUsers_Delete_NoPurgeDataOmitsCount(t *testing.T) {
	f := newTeamTestFixture(t)
	targetID := f.memberUser.UserID

	w := f.do("DELETE", "/api/users/"+targetID, "", f.adminToken, f.adminCert)
	if w.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", w.Code, w.Body.String())
	}
	var resp map[string]interface{}
	if err := json.NewDecoder(w.Body).Decode(&resp); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if resp["status"] != "ok" {
		t.Errorf("expected status 'ok', got %v", resp["status"])
	}
	if _, ok := resp["purged_records"]; ok {
		t.Errorf("expected purged_records field to be absent, got %v", resp["purged_records"])
	}
}

func TestInvites_Delete_ShortCode_NoPanic(t *testing.T) {
	f := newTeamTestFixture(t)
	// "abc" is shorter than 8 bytes and would panic on code[:8] without the guard.
	w := f.do("DELETE", "/api/invites/abc", "", f.adminToken, f.adminCert)
	if w.Code != http.StatusBadRequest {
		t.Fatalf("expected 400 for short code, got %d: %s", w.Code, w.Body.String())
	}
}

func TestAudit_UserRenamed(t *testing.T) {
	f, buf := newTeamTestFixtureWithAudit(t)
	targetID := f.memberUser.UserID

	w := f.do("PATCH", "/api/users/"+targetID, `{"display_name":"Bob Renamed"}`, f.adminToken, f.adminCert)
	if w.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", w.Code, w.Body.String())
	}

	out := buf.String()
	if !strings.Contains(out, "msg=user_renamed") {
		t.Errorf("expected audit event 'user_renamed' in output, got:\n%s", out)
	}
	if !strings.Contains(out, "old_name=bob") {
		t.Errorf("expected old_name=bob in audit output, got:\n%s", out)
	}
	if !strings.Contains(out, "new_name=") {
		t.Errorf("expected new_name field in audit output, got:\n%s", out)
	}
	if !strings.Contains(out, "Bob Renamed") {
		t.Errorf("expected 'Bob Renamed' in audit output, got:\n%s", out)
	}
	if !strings.Contains(out, "user_id="+targetID) {
		t.Errorf("expected user_id=%s in audit output, got:\n%s", targetID, out)
	}
	if !strings.Contains(out, "changed_by=") {
		t.Errorf("expected changed_by field in audit output, got:\n%s", out)
	}
}

func TestAudit_RoleChanged(t *testing.T) {
	f, buf := newTeamTestFixtureWithAudit(t)
	targetID := f.memberUser.UserID

	w := f.do("PATCH", "/api/users/"+targetID, `{"role":"admin"}`, f.adminToken, f.adminCert)
	if w.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", w.Code, w.Body.String())
	}

	out := buf.String()
	if !strings.Contains(out, "msg=role_changed") {
		t.Errorf("expected audit event 'role_changed' in output, got:\n%s", out)
	}
	if strings.Contains(out, "user_role_changed") {
		t.Errorf("old event name 'user_role_changed' must not appear in audit output, got:\n%s", out)
	}
	if !strings.Contains(out, "from=member") {
		t.Errorf("expected from=member in audit output, got:\n%s", out)
	}
	if !strings.Contains(out, "to=admin") {
		t.Errorf("expected to=admin in audit output, got:\n%s", out)
	}
	if !strings.Contains(out, "changed_by=") {
		t.Errorf("expected changed_by field in audit output, got:\n%s", out)
	}
}

func TestAudit_UserRevoked(t *testing.T) {
	f, buf := newTeamTestFixtureWithAudit(t)
	targetID := f.memberUser.UserID

	w := f.do("DELETE", "/api/users/"+targetID+"?purge_data=true", "", f.adminToken, f.adminCert)
	if w.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", w.Code, w.Body.String())
	}

	out := buf.String()
	if !strings.Contains(out, "msg=user_revoked") {
		t.Errorf("expected audit event 'user_revoked' in output, got:\n%s", out)
	}
	if !strings.Contains(out, "user_id="+targetID) {
		t.Errorf("expected user_id=%s in audit output, got:\n%s", targetID, out)
	}
	if !strings.Contains(out, "revoked_by=") {
		t.Errorf("expected revoked_by field in audit output, got:\n%s", out)
	}
	if !strings.Contains(out, "purge_data=true") {
		t.Errorf("expected purge_data=true in audit output, got:\n%s", out)
	}
}

func TestInvites_List_MasksForeignCodes(t *testing.T) {
	f := newTeamTestFixture(t)

	cw := f.do("POST", "/api/invites", `{"role":"admin"}`, f.adminToken, f.adminCert)
	if cw.Code != http.StatusOK {
		t.Fatalf("owner create: %d %s", cw.Code, cw.Body.String())
	}
	var created map[string]string
	json.NewDecoder(cw.Body).Decode(&created)

	admin2Cert, admin2Token, _ := newTeamUserDevice(t, f.devices, f.users, f.mgr, f.serverKey, "carol", "admin")
	lw := f.do("GET", "/api/invites", "", admin2Token, admin2Cert)
	if lw.Code != http.StatusOK {
		t.Fatalf("admin2 list: %d %s", lw.Code, lw.Body.String())
	}
	var list []map[string]interface{}
	json.NewDecoder(lw.Body).Decode(&list)
	if len(list) != 1 {
		t.Fatalf("expected 1 invite, got %d", len(list))
	}
	if code, ok := list[0]["code"]; ok && code != "" {
		t.Errorf("non-creator admin must not see the full code, got %v", code)
	}
	if list[0]["code_prefix"] != created["code"][:8] {
		t.Errorf("expected code_prefix %q, got %v", created["code"][:8], list[0]["code_prefix"])
	}

	ow := f.do("GET", "/api/invites", "", f.adminToken, f.adminCert)
	var ownerList []map[string]interface{}
	json.NewDecoder(ow.Body).Decode(&ownerList)
	if len(ownerList) != 1 || ownerList[0]["code"] != created["code"] {
		t.Fatalf("creator should see the full code, got %v", ownerList)
	}
	if ownerList[0]["code_prefix"] != created["code"][:8] {
		t.Errorf("creator listing should still carry code_prefix, got %v", ownerList[0])
	}
}

func TestInvites_Revoke_ByPrefix(t *testing.T) {
	f := newTeamTestFixture(t)

	cw := f.do("POST", "/api/invites", `{"role":"member"}`, f.adminToken, f.adminCert)
	var created map[string]string
	json.NewDecoder(cw.Body).Decode(&created)

	admin2Cert, admin2Token, _ := newTeamUserDevice(t, f.devices, f.users, f.mgr, f.serverKey, "carol", "admin")
	w := f.do("DELETE", "/api/invites/"+created["code"][:8], "", admin2Token, admin2Cert)
	if w.Code != http.StatusOK {
		t.Fatalf("revoke by prefix: expected 200, got %d: %s", w.Code, w.Body.String())
	}
	inv, err := f.invites.FindByCode(created["code"])
	if err != nil || inv == nil || inv.RevokedAt == "" {
		t.Fatalf("invite not revoked after prefix revoke: %+v err=%v", inv, err)
	}
}

func TestInvites_Revoke_AmbiguousPrefix409(t *testing.T) {
	f := newTeamTestFixture(t)

	// Codes are random via the store API, so seed the collision directly.
	for _, code := range []string{"aaaabbbbcccc0001", "aaaabbbbcccc0002"} {
		if _, err := f.db.Exec(`INSERT INTO invites (code, role, created_at, expires_at)
			VALUES (?, 'member', ?, ?)`,
			code,
			time.Now().UTC().Format(time.RFC3339),
			time.Now().Add(time.Hour).UTC().Format(time.RFC3339)); err != nil {
			t.Fatalf("seed invite: %v", err)
		}
	}

	w := f.do("DELETE", "/api/invites/aaaabbbbcccc", "", f.adminToken, f.adminCert)
	if w.Code != http.StatusConflict {
		t.Fatalf("expected 409 for ambiguous prefix, got %d: %s", w.Code, w.Body.String())
	}
	var resp map[string]string
	json.NewDecoder(w.Body).Decode(&resp)
	if resp["error"] != "ambiguous_prefix" {
		t.Errorf("expected error 'ambiguous_prefix', got %q", resp["error"])
	}
}

func TestInvites_List_CreatorAttribution(t *testing.T) {
	f := newTeamTestFixture(t)

	f.do("POST", "/api/invites", `{"role":"member"}`, f.adminToken, f.adminCert)

	admin2Cert, admin2Token, _ := newTeamUserDevice(t, f.devices, f.users, f.mgr, f.serverKey, "carol", "admin")
	w := f.do("GET", "/api/invites", "", admin2Token, admin2Cert)
	var list []map[string]interface{}
	json.NewDecoder(w.Body).Decode(&list)
	if len(list) != 1 {
		t.Fatalf("expected 1 invite, got %d", len(list))
	}
	if list[0]["created_by"] != f.adminUser.UserID {
		t.Errorf("expected created_by %q, got %v", f.adminUser.UserID, list[0]["created_by"])
	}
	if list[0]["created_by_name"] != f.adminUser.DisplayName {
		t.Errorf("expected created_by_name %q, got %v", f.adminUser.DisplayName, list[0]["created_by_name"])
	}
}

func TestInvites_Create_LifetimeClamped(t *testing.T) {
	f := newTeamTestFixture(t)

	w := f.do("POST", "/api/invites", `{"role":"member","expires_in_seconds":1000000000}`,
		f.adminToken, f.adminCert)
	if w.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", w.Code, w.Body.String())
	}
	var resp map[string]string
	json.NewDecoder(w.Body).Decode(&resp)
	expires, err := time.Parse(time.RFC3339, resp["expires_at"])
	if err != nil {
		t.Fatalf("parse expires_at %q: %v", resp["expires_at"], err)
	}
	maxExpiry := time.Now().Add(30*24*time.Hour + time.Minute)
	if expires.After(maxExpiry) {
		t.Fatalf("expiry %v exceeds the 30-day cap %v", expires, maxExpiry)
	}
}

func TestInvites_SecondDevice_AdminCannotTargetOwner(t *testing.T) {
	f := newTeamTestFixture(t)
	admin2Cert, admin2Token, _ := newTeamUserDevice(t, f.devices, f.users, f.mgr, f.serverKey, "carol", "admin")

	body := fmt.Sprintf(`{"target_user_id":%q}`, f.adminUser.UserID)
	w := f.do("POST", "/api/invites", body, admin2Token, admin2Cert)
	if w.Code != http.StatusForbidden {
		t.Fatalf("expected 403, got %d: %s", w.Code, w.Body.String())
	}
	var resp map[string]string
	json.NewDecoder(w.Body).Decode(&resp)
	if resp["error"] != "owner_required" {
		t.Errorf("expected error 'owner_required', got %q", resp["error"])
	}
}

func TestInvites_SecondDevice_AdminCannotTargetOtherMember(t *testing.T) {
	f := newTeamTestFixture(t)
	admin2Cert, admin2Token, _ := newTeamUserDevice(t, f.devices, f.users, f.mgr, f.serverKey, "carol", "admin")

	body := fmt.Sprintf(`{"target_user_id":%q}`, f.memberUser.UserID)
	w := f.do("POST", "/api/invites", body, admin2Token, admin2Cert)
	if w.Code != http.StatusForbidden {
		t.Fatalf("expected 403, got %d: %s", w.Code, w.Body.String())
	}
}

func TestInvites_SecondDevice_OwnerCanTargetOthers(t *testing.T) {
	f := newTeamTestFixture(t)
	_, _, admin2 := newTeamUserDevice(t, f.devices, f.users, f.mgr, f.serverKey, "carol", "admin")

	for _, targetID := range []string{f.memberUser.UserID, admin2.UserID} {
		body := fmt.Sprintf(`{"target_user_id":%q}`, targetID)
		w := f.do("POST", "/api/invites", body, f.adminToken, f.adminCert)
		if w.Code != http.StatusOK {
			t.Fatalf("owner second-device for %s: expected 200, got %d: %s",
				targetID, w.Code, w.Body.String())
		}
	}
}

func TestInvites_SecondDevice_MemberNeedsInvitesDevice(t *testing.T) {
	f := newTeamTestFixture(t)
	body := fmt.Sprintf(`{"target_user_id":%q}`, f.memberUser.UserID)

	w := f.do("POST", "/api/invites", body, f.memberToken, f.memberCert)
	if w.Code != http.StatusForbidden {
		t.Fatalf("ungranted self-invite: expected 403, got %d: %s", w.Code, w.Body.String())
	}

	grantInvitesDevice(t, f, f.memberUser.UserID)
	w = f.do("POST", "/api/invites", body, f.memberToken, f.memberCert)
	if w.Code != http.StatusOK {
		t.Fatalf("granted self-invite: expected 200, got %d: %s", w.Code, w.Body.String())
	}

	if err := f.users.SetPermissions(f.memberUser.UserID, pki.PermissionSet{
		"invites.device": {Granted: false},
	}); err != nil {
		t.Fatal(err)
	}
	w = f.do("POST", "/api/invites", body, f.memberToken, f.memberCert)
	if w.Code != http.StatusForbidden {
		t.Fatalf("revoked self-invite: expected 403, got %d: %s", w.Code, w.Body.String())
	}
}

func TestInvites_SecondDevice_InvitesManageCrossUser403(t *testing.T) {
	f := newTeamTestFixture(t)
	daveCert, daveToken, dave := newTeamUserDevice(t, f.devices, f.users, f.mgr, f.serverKey, "dave", "member")
	if err := f.users.SetPermissions(dave.UserID, pki.PermissionSet{
		"invites.manage": {Granted: true},
	}); err != nil {
		t.Fatal(err)
	}

	body := fmt.Sprintf(`{"target_user_id":%q}`, f.memberUser.UserID)
	w := f.do("POST", "/api/invites", body, daveToken, daveCert)
	if w.Code != http.StatusForbidden {
		t.Fatalf("expected 403, got %d: %s", w.Code, w.Body.String())
	}
}

func TestUsers_Delete_CascadesInvitesCreatedByUser(t *testing.T) {
	f := newTeamTestFixture(t)
	targetID := f.memberUser.UserID

	created, err := f.invites.Create(pki.CreateInviteParams{
		Role:         "member",
		ExpiresIn:    time.Hour,
		CreatedByUID: targetID,
	})
	if err != nil {
		t.Fatalf("create invite: %v", err)
	}
	other, err := f.invites.Create(pki.CreateInviteParams{
		Role:         "member",
		ExpiresIn:    time.Hour,
		CreatedByUID: f.adminUser.UserID,
	})
	if err != nil {
		t.Fatalf("create control invite: %v", err)
	}

	w := f.do("DELETE", "/api/users/"+targetID, "", f.adminToken, f.adminCert)
	if w.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", w.Code, w.Body.String())
	}

	got, _ := f.invites.FindByCode(created.Code)
	if got == nil || got.RevokedAt == "" {
		t.Errorf("invite created by the removed user must be revoked, got %+v", got)
	}
	kept, _ := f.invites.FindByCode(other.Code)
	if kept == nil || kept.RevokedAt != "" {
		t.Errorf("admin's invite must survive the cascade, got %+v", kept)
	}
}

func TestUsers_Delete_SelfLeaveTeam(t *testing.T) {
	f := newTeamTestFixture(t)
	targetID := f.memberUser.UserID
	callerDevice := deviceIDFor(t, f, targetID)
	otherDevice := registerExtraDevice(t, f, targetID, "bob-tablet")

	w := f.do("DELETE", "/api/users/"+targetID, "", f.memberToken, f.memberCert)
	if w.Code != http.StatusOK {
		t.Fatalf("self-delete: expected 200, got %d: %s", w.Code, w.Body.String())
	}

	u, err := f.users.FindByID(targetID)
	if err != nil || u == nil || u.Status != "revoked" {
		t.Fatalf("expected revoked user, got %+v err=%v", u, err)
	}
	for id, want := range map[string]string{callerDevice: "left", otherDevice: "revoked"} {
		d, err := f.devices.FindByID(id)
		if err != nil {
			t.Fatal(err)
		}
		if d.Status != want {
			t.Errorf("device %s: status %q after self-delete, want %q", id, d.Status, want)
		}
	}

	w = f.do("GET", "/api/users", "", f.memberToken, f.memberCert)
	if w.Code != http.StatusForbidden {
		t.Fatalf("expected 403 after leaving, got %d: %s", w.Code, w.Body.String())
	}
}

func TestUsers_Delete_SelfOwner409(t *testing.T) {
	f := newTeamTestFixture(t)

	w := f.do("DELETE", "/api/users/"+f.adminUser.UserID, "", f.adminToken, f.adminCert)
	if w.Code != http.StatusConflict {
		t.Fatalf("expected 409, got %d: %s", w.Code, w.Body.String())
	}
	var resp map[string]string
	json.NewDecoder(w.Body).Decode(&resp)
	if resp["error"] != "owner_immutable" {
		t.Errorf("expected error 'owner_immutable', got %q", resp["error"])
	}
}

func TestAudit_DeviceRevokedOnUserDelete(t *testing.T) {
	f, buf := newTeamTestFixtureWithAudit(t)
	targetID := f.memberUser.UserID

	w := f.do("DELETE", "/api/users/"+targetID, "", f.adminToken, f.adminCert)
	if w.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", w.Code, w.Body.String())
	}

	out := buf.String()
	if !strings.Contains(out, "msg=device_revoked") {
		t.Errorf("expected audit event 'device_revoked' in output, got:\n%s", out)
	}
}

func TestUsers_TransferOwnership(t *testing.T) {
	f, audit := newTeamTestFixtureWithAudit(t)
	syncStore := newTestSyncStore(t)
	f.srv.RegisterVaultRoutes(syncStore)

	w := f.do("POST", "/api/users/"+f.memberUser.UserID+"/transfer-ownership", "", f.memberToken, f.memberCert)
	if w.Code != http.StatusForbidden {
		t.Fatalf("member: expected 403, got %d: %s", w.Code, w.Body.String())
	}
	w = f.do("POST", "/api/users/"+f.adminUser.UserID+"/transfer-ownership", "", f.adminToken, f.adminCert)
	if w.Code != http.StatusBadRequest || !strings.Contains(w.Body.String(), "self_transfer") {
		t.Fatalf("self: expected 400 self_transfer, got %d: %s", w.Code, w.Body.String())
	}
	w = f.do("POST", "/api/users/nope/transfer-ownership", "", f.adminToken, f.adminCert)
	if w.Code != http.StatusNotFound || !strings.Contains(w.Body.String(), "user_not_found") {
		t.Fatalf("unknown: expected 404, got %d: %s", w.Code, w.Body.String())
	}
	_, _, gone := newTeamUserDevice(t, f.devices, f.users, f.mgr, f.serverKey, "gone", "member")
	if err := f.users.Revoke(gone.UserID); err != nil {
		t.Fatal(err)
	}
	w = f.do("POST", "/api/users/"+gone.UserID+"/transfer-ownership", "", f.adminToken, f.adminCert)
	if w.Code != http.StatusConflict || !strings.Contains(w.Body.String(), "target_not_active") {
		t.Fatalf("revoked: expected 409, got %d: %s", w.Code, w.Body.String())
	}
	if u, _ := f.users.FindByID(f.adminUser.UserID); !u.Owner {
		t.Fatal("failed transfers must not move the owner flag")
	}

	if lvl := syncStore.VaultLevel(f.memberUser.UserID, "infra"); lvl != datasync.LevelNone {
		t.Fatalf("member vault level before transfer: %d", lvl)
	}

	w = f.do("POST", "/api/users/"+f.memberUser.UserID+"/transfer-ownership", "", f.adminToken, f.adminCert)
	if w.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", w.Code, w.Body.String())
	}
	var resp map[string]string
	if err := json.NewDecoder(w.Body).Decode(&resp); err != nil {
		t.Fatal(err)
	}
	if resp["status"] != "ok" || resp["new_owner"] != f.memberUser.UserID || resp["previous_owner"] != f.adminUser.UserID {
		t.Fatalf("unexpected body %v", resp)
	}
	newOwner, _ := f.users.FindByID(f.memberUser.UserID)
	if !newOwner.Owner || newOwner.Role != "admin" {
		t.Fatalf("target must be owner+admin, got %+v", newOwner)
	}
	old, _ := f.users.FindByID(f.adminUser.UserID)
	if old.Owner || old.Role != "admin" {
		t.Fatalf("caller must be a plain admin, got %+v", old)
	}
	if !strings.Contains(audit.String(), "owner_transferred") {
		t.Fatalf("expected owner_transferred audit event, got %s", audit.String())
	}

	if lvl := syncStore.VaultLevel(f.memberUser.UserID, "infra"); lvl != datasync.LevelManage {
		t.Fatalf("new owner vault level: %d, want manage", lvl)
	}
	if lvl := syncStore.VaultLevel(f.adminUser.UserID, "infra"); lvl != datasync.LevelNone {
		t.Fatalf("previous owner vault level: %d, want none", lvl)
	}

	w = f.do("POST", "/api/users/"+f.adminUser.UserID+"/transfer-ownership", "", f.adminToken, f.adminCert)
	if w.Code != http.StatusForbidden {
		t.Fatalf("previous owner: expected 403, got %d: %s", w.Code, w.Body.String())
	}
	w = f.do("POST", "/api/users/"+f.adminUser.UserID+"/transfer-ownership", "", f.memberToken, f.memberCert)
	if w.Code != http.StatusOK {
		t.Fatalf("new owner transferring back: expected 200, got %d: %s", w.Code, w.Body.String())
	}
}

func TestLengthCaps_UsersAndInvites(t *testing.T) {
	f := newTeamTestFixture(t)
	long := strings.Repeat("ä", pki.MaxDisplayNameLen+1)
	w := f.do("PATCH", "/api/users/"+f.memberUser.UserID, `{"display_name":"`+long+`"}`, f.memberToken, f.memberCert)
	if w.Code != http.StatusBadRequest || !strings.Contains(w.Body.String(), "display_name_too_long") {
		t.Fatalf("over-long display name: %d %s", w.Code, w.Body.String())
	}
	atCap := strings.Repeat("ä", pki.MaxDisplayNameLen)
	w = f.do("PATCH", "/api/users/"+f.memberUser.UserID, `{"display_name":"`+atCap+`"}`, f.memberToken, f.memberCert)
	if w.Code != http.StatusOK {
		t.Fatalf("at-cap display name: %d %s", w.Code, w.Body.String())
	}
	if u, _ := f.users.FindByID(f.memberUser.UserID); u.DisplayName != atCap {
		t.Fatalf("display name must be stored verbatim, got %q", u.DisplayName)
	}

	longLabel := strings.Repeat("ä", pki.MaxInviteLabelLen+1)
	w = f.do("POST", "/api/invites", `{"role":"member","label":"`+longLabel+`"}`, f.adminToken, f.adminCert)
	if w.Code != http.StatusBadRequest || !strings.Contains(w.Body.String(), "label_too_long") {
		t.Fatalf("over-long label: %d %s", w.Code, w.Body.String())
	}
	w = f.do("POST", "/api/invites", `{"role":"member","label":"`+strings.Repeat("ä", pki.MaxInviteLabelLen)+`"}`, f.adminToken, f.adminCert)
	if w.Code != http.StatusOK {
		t.Fatalf("at-cap label: %d %s", w.Code, w.Body.String())
	}
}

func TestUsers_Delete_RevokeIncomplete(t *testing.T) {
	f, audit := newTeamTestFixtureWithAudit(t)
	// Dropping the table makes Revoke fail after the status flip, the partial-failure shape under test.
	if _, err := f.db.Exec("DROP TABLE push_registrations"); err != nil {
		t.Fatal(err)
	}
	w := f.do("DELETE", "/api/users/"+f.memberUser.UserID, "", f.adminToken, f.adminCert)
	if w.Code != http.StatusInternalServerError || !strings.Contains(w.Body.String(), "revoke_incomplete") {
		t.Fatalf("expected 500 revoke_incomplete, got %d: %s", w.Code, w.Body.String())
	}
	if u, _ := f.users.FindByID(f.memberUser.UserID); u.Status != "revoked" {
		t.Fatalf("user must stay revoked, got %s", u.Status)
	}
	if strings.Contains(audit.String(), "device_revoked") || strings.Contains(audit.String(), "msg=user_revoked") {
		t.Fatalf("no success audit lines may be written for a failed cascade: %s", audit.String())
	}
	if !strings.Contains(audit.String(), "user_revoke_incomplete") {
		t.Fatalf("expected user_revoke_incomplete audit line: %s", audit.String())
	}
}
