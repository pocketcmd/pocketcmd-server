package server

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/pocketcmd/pocketcmd-server/internal/datasync"
	"github.com/pocketcmd/pocketcmd-server/internal/monitoring"
	"github.com/pocketcmd/pocketcmd-server/internal/pair"
	"github.com/pocketcmd/pocketcmd-server/internal/pki"
)

const leaveTestFP = "aa:bb:cc:dd:ee:ff"

func leaveFixture(t *testing.T) (*teamTestFixture, *datasync.SyncStore, *bytes.Buffer) {
	t.Helper()
	f, audit := newTeamTestFixtureWithAudit(t)
	store := datasync.NewSyncStore(f.db, monitoring.NewStore(f.db))
	f.srv.RegisterSyncRoutes(store)
	f.srv.RegisterVaultRoutes(store)
	f.srv.SetPairingFingerprint(leaveTestFP)
	ph := pair.NewPairingHandler(f.devices, f.users, f.invites, f.serverKey,
		leaveTestFP, "testhost", "https://127.0.0.1:8767")
	ph.SetAuditLogger(f.srv.auditLogger)
	f.srv.RegisterPairRoute(ph)
	return f, store, audit
}

type keyedDevice struct {
	key      *ecdsa.PrivateKey
	pubPEM   string
	cert     *x509.Certificate
	token    string
	userID   string
	deviceID string
}

func newKeyedMember(t *testing.T, f *teamTestFixture, name string) *keyedDevice {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	pubDER, _ := x509.MarshalPKIXPublicKey(&key.PublicKey)
	pubPEM := string(pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: pubDER}))
	user, err := f.users.Create(name, "member", "")
	if err != nil {
		t.Fatal(err)
	}
	deviceID, err := f.devices.RegisterDeviceForUser(pubPEM, name+"-phone", user.UserID, "")
	if err != nil {
		t.Fatal(err)
	}
	d := &keyedDevice{key: key, pubPEM: pubPEM, userID: user.UserID, deviceID: deviceID}
	d.refreshCredentials(t, f)
	return d
}

func (d *keyedDevice) refreshCredentials(t *testing.T, f *teamTestFixture) {
	t.Helper()
	d.cert = issueTestClientCert(t, f.serverKey, &d.key.PublicKey, 30*time.Minute)
	tok, err := f.mgr.Issue(d.deviceID, pki.CertFingerprint(d.cert.Raw))
	if err != nil {
		t.Fatal(err)
	}
	d.token = tok
}

func addPushRegistration(t *testing.T, f *teamTestFixture, deviceID string) {
	t.Helper()
	if _, err := f.db.Exec(`INSERT INTO push_registrations (device_id, device_token, platform,
		signed_token, expires_at, updated_at) VALUES (?, 'tok', 'android', 'sig', 1, 1)`, deviceID); err != nil {
		t.Fatal(err)
	}
}

func pushRegistered(t *testing.T, f *teamTestFixture, deviceID string) bool {
	t.Helper()
	var n int
	if err := f.db.QueryRow(`SELECT COUNT(*) FROM push_registrations WHERE device_id=?`, deviceID).Scan(&n); err != nil {
		t.Fatal(err)
	}
	return n > 0
}

func invitePair(t *testing.T, f *teamTestFixture, d *keyedDevice, code, displayName string) (int, pair.PairResponse, string) {
	t.Helper()
	body, _ := json.Marshal(pair.PairRequest{
		DevicePublicKey: d.pubPEM,
		DeviceName:      "rejoined-phone",
		CSR:             buildCSR(t, d.key),
		Credential:      pair.PairCredential{Kind: "invite", Token: code},
		DisplayName:     displayName,
	})
	w := f.do("POST", "/api/pair", string(body), "", nil)
	var resp pair.PairResponse
	if w.Code == http.StatusOK {
		if err := json.Unmarshal(w.Body.Bytes(), &resp); err != nil {
			t.Fatal(err)
		}
	}
	return w.Code, resp, w.Body.String()
}

func adminInvite(t *testing.T, f *teamTestFixture) string {
	t.Helper()
	w := f.do("POST", "/api/invites", `{"role":"member"}`, f.adminToken, f.adminCert)
	if w.Code != http.StatusOK {
		t.Fatalf("create invite: %d %s", w.Code, w.Body.String())
	}
	var out map[string]string
	json.Unmarshal(w.Body.Bytes(), &out)
	if out["code"] == "" {
		t.Fatalf("no invite code: %s", w.Body.String())
	}
	return out["code"]
}

func directoryDeviceIDs(t *testing.T, f *teamTestFixture) map[string]string {
	t.Helper()
	w := f.do("GET", "/api/vault/pubkeys", "", f.adminToken, f.adminCert)
	if w.Code != http.StatusOK {
		t.Fatalf("pubkeys: %d %s", w.Code, w.Body.String())
	}
	var out struct {
		Devices []deviceEntry `json:"devices"`
	}
	json.Unmarshal(w.Body.Bytes(), &out)
	ids := map[string]string{}
	for _, d := range out.Devices {
		ids[d.DeviceID] = d.UserID
	}
	return ids
}

func dvkRecord(deviceID string, updatedAt int64) datasync.SyncRecord {
	return datasync.SyncRecord{ID: deviceID, Type: "device_vault_key", UpdatedAt: updatedAt,
		DeviceID: deviceID, Data: json.RawMessage(`{"dvk_pub":"DVK","kind":"p256"}`)}
}

func TestSelfUnpair_LeftDeviceBlockedEverywhere(t *testing.T) {
	f, _, audit := leaveFixture(t)
	carol := newKeyedMember(t, f, "carol")
	addPushRegistration(t, f, carol.deviceID)

	if w := f.do("DELETE", "/api/devices/self", "", carol.token, carol.cert); w.Code != http.StatusOK {
		t.Fatalf("self-unpair: %d %s", w.Code, w.Body.String())
	}
	dev, _ := f.devices.FindByID(carol.deviceID)
	if dev.Status != pki.DeviceStatusLeft {
		t.Fatalf("status %q, want left", dev.Status)
	}
	if u, _ := f.users.FindByID(carol.userID); u == nil || u.Status != "active" {
		t.Fatal("unpairing a device keeps the membership")
	}
	out := audit.String()
	if !strings.Contains(out, "msg=device_left") || strings.Contains(out, "msg=device_revoked") {
		t.Fatalf("expected device_left (and no device_revoked) in the audit log:\n%s", out)
	}

	if pushRegistered(t, f, carol.deviceID) {
		t.Fatal("a left device must lose its push registration")
	}
	for _, rt := range []struct{ method, path, body string }{
		{"GET", "/api/devices", ""},
		{"GET", "/api/sync/manifest", ""},
		{"POST", "/api/sync/pull", `{"ids":["x"]}`},
		{"POST", "/api/push/register", `{"device_token":"t","platform":"android"}`},
	} {
		if w := f.do(rt.method, rt.path, rt.body, carol.token, carol.cert); w.Code != http.StatusForbidden {
			t.Errorf("%s %s with a left device: %d, want 403", rt.method, rt.path, w.Code)
		}
	}
	carol.refreshCredentials(t, f)
	if w := f.do("POST", "/api/session", "", "", carol.cert); w.Code != http.StatusForbidden {
		t.Errorf("/api/session with a left device: %d, want 403", w.Code)
	}

	csr := buildCSR(t, carol.key)
	body, _ := json.Marshal(map[string]string{"csr": csr})
	if w := f.do("POST", "/api/cert/renew", string(body), "", carol.cert); w.Code != http.StatusForbidden {
		t.Errorf("mTLS renew for a left device: %d, want 403", w.Code)
	}
	chal, _ := json.Marshal(map[string]string{"public_key": carol.pubPEM})
	w := f.do("POST", "/api/cert/challenge", string(chal), "", nil)
	var decoy map[string]string
	_ = json.Unmarshal(w.Body.Bytes(), &decoy)
	if w.Code != http.StatusOK || len(decoy["nonce"]) != 64 {
		t.Errorf("challenge for a left device: %d %s, want a 200 decoy", w.Code, w.Body.String())
	}
	if _, found := f.srv.nonces.Take(decoy["nonce"]); found {
		t.Error("decoy nonce for a left device must not be stored")
	}
	nonce := "0123456789abcdef0123456789abcdef"
	f.srv.nonces.Put(nonce, pki.NonceEntry{PublicKeyPEM: carol.pubPEM,
		ServerFingerprint: leaveTestFP, ExpiresAt: time.Now().Add(30 * time.Second)})
	renew, _ := json.Marshal(map[string]string{
		"signed_challenge": signChallengeForRenew(t, carol.key, nonce, leaveTestFP),
		"public_key":       carol.pubPEM,
		"csr":              csr,
		"nonce":            nonce,
	})
	if w := f.do("POST", "/api/cert/renew", string(renew), "", nil); w.Code != http.StatusForbidden {
		t.Errorf("challenge renew for a left device: %d %s, want 403", w.Code, w.Body.String())
	}
	out = audit.String()
	for _, want := range []string{"msg=cert_challenge outcome=left", "msg=cert_renew outcome=left"} {
		if !strings.Contains(out, want) {
			t.Errorf("audit log lacks %q", want)
		}
	}
}

func TestSelfUnpair_InviteRepairWorks(t *testing.T) {
	f, _, audit := leaveFixture(t)
	carol := newKeyedMember(t, f, "carol")
	if w := f.do("DELETE", "/api/devices/self", "", carol.token, carol.cert); w.Code != http.StatusOK {
		t.Fatalf("self-unpair: %d %s", w.Code, w.Body.String())
	}

	code, resp, body := invitePair(t, f, carol, adminInvite(t, f), "Carol (again)")
	if code != http.StatusOK {
		t.Fatalf("re-pair through a new invite: %d %s", code, body)
	}
	if resp.DeviceID != carol.deviceID || resp.UserRole != "member" {
		t.Fatalf("unexpected pair response: %+v", resp)
	}
	if resp.UserID == carol.userID {
		t.Fatal("a new-member invite must not restore the old binding")
	}

	block, _ := pem.Decode([]byte(resp.ClientCert))
	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		t.Fatal(err)
	}
	w := f.do("POST", "/api/session", "", "", cert)
	if w.Code != http.StatusOK {
		t.Fatalf("session after re-pair: %d %s", w.Code, w.Body.String())
	}
	var sess struct {
		Token string `json:"token"`
	}
	json.Unmarshal(w.Body.Bytes(), &sess)
	w = f.do("GET", "/api/devices", "", sess.Token, cert)
	if w.Code != http.StatusOK {
		t.Fatalf("authenticated request after re-pair: %d %s", w.Code, w.Body.String())
	}
	list := decodeDeviceList(t, w.Body.String())
	if len(list) != 1 || !list[0].Self || list[0].UserID != resp.UserID {
		t.Fatalf("re-paired device must list itself under its new user: %+v", list)
	}
	if !strings.Contains(audit.String(), "msg=device_reactivated") {
		t.Fatalf("expected device_reactivated in the audit log:\n%s", audit.String())
	}
}

func TestAdminRevoke_InviteRepairRefused(t *testing.T) {
	f, _, _ := leaveFixture(t)
	carol := newKeyedMember(t, f, "carol")
	if w := f.do("DELETE", "/api/devices/"+carol.deviceID, "", f.adminToken, f.adminCert); w.Code != http.StatusOK {
		t.Fatalf("admin revoke: %d %s", w.Code, w.Body.String())
	}
	if dev, _ := f.devices.FindByID(carol.deviceID); dev.Status != pki.DeviceStatusRevoked {
		t.Fatalf("status %q, want revoked", dev.Status)
	}

	invite := adminInvite(t, f)
	code, _, body := invitePair(t, f, carol, invite, "Carol")
	if code != http.StatusForbidden || !strings.Contains(body, `"error":"device_revoked"`) {
		t.Fatalf("re-pair of a revoked key: %d %s, want 403 device_revoked", code, body)
	}
	inv, _ := f.invites.FindByCode(invite)
	if inv.ConsumedAt != "" {
		t.Fatal("the refused re-pair burned the invite")
	}
	if dev, _ := f.devices.FindByID(carol.deviceID); dev.Status != pki.DeviceStatusRevoked {
		t.Fatalf("a revoked key was re-admitted: %+v", dev)
	}
}

func TestAdminRevoke_OfLeftDeviceIsFinal(t *testing.T) {
	f, _, audit := leaveFixture(t)
	carol := newKeyedMember(t, f, "carol")
	f.do("DELETE", "/api/devices/self", "", carol.token, carol.cert)
	if w := f.do("DELETE", "/api/devices/"+carol.deviceID, "", f.adminToken, f.adminCert); w.Code != http.StatusOK {
		t.Fatalf("admin revoke of a left device: %d %s", w.Code, w.Body.String())
	}
	if dev, _ := f.devices.FindByID(carol.deviceID); dev.Status != pki.DeviceStatusRevoked {
		t.Fatalf("status %q, want revoked", dev.Status)
	}
	if !strings.Contains(audit.String(), "previous_status=left") {
		t.Fatalf("the escalation must be attributable in the audit log:\n%s", audit.String())
	}
	code, _, body := invitePair(t, f, carol, adminInvite(t, f), "Carol")
	if code != http.StatusForbidden || !strings.Contains(body, "device_revoked") {
		t.Fatalf("re-pair after escalation: %d %s", code, body)
	}
}

func TestDevices_RevokingOwnOtherDeviceIsPermanent(t *testing.T) {
	f, _, _ := leaveFixture(t)
	carol := newKeyedMember(t, f, "carol")
	tablet := registerExtraDevice(t, f, carol.userID, "carol-tablet")
	if w := f.do("DELETE", "/api/devices/"+tablet, "", carol.token, carol.cert); w.Code != http.StatusOK {
		t.Fatalf("revoke own other device: %d %s", w.Code, w.Body.String())
	}
	if dev, _ := f.devices.FindByID(tablet); dev.Status != pki.DeviceStatusRevoked {
		t.Fatalf("own other device: status %q, want revoked", dev.Status)
	}
}

func TestSelfUnpair_VaultConsequencesMatchRevoke(t *testing.T) {
	f, store, _ := leaveFixture(t)
	left := newKeyedMember(t, f, "carol")
	revoked := newKeyedMember(t, f, "dave")
	adminDev := deviceIDFor(t, f, f.adminUser.UserID)

	if w := f.do("POST", "/api/vault/create", `{"vault_id":"infra"}`, f.adminToken, f.adminCert); w.Code != http.StatusOK {
		t.Fatalf("create vault: %d %s", w.Code, w.Body.String())
	}
	now := time.Now().UnixMilli()
	for _, d := range []*keyedDevice{left, revoked} {
		grant := fmt.Sprintf(`{"vault_id":"infra","user_id":"%s","level":"edit"}`, d.userID)
		if w := f.do("POST", "/api/vault/grant", grant, f.adminToken, f.adminCert); w.Code != http.StatusNoContent {
			t.Fatalf("grant: %d %s", w.Code, w.Body.String())
		}
		if res, err := store.PushRecords(d.userID, []datasync.SyncRecord{dvkRecord(d.deviceID, now)}); err != nil || len(res.Accepted) != 1 {
			t.Fatalf("dvk push: %+v %v", res, err)
		}
		if res, err := store.PushRecords(f.adminUser.UserID, []datasync.SyncRecord{perDeviceWrap("infra", d.deviceID, now)}); err != nil || len(res.Accepted) != 1 {
			t.Fatalf("wrap push: %+v %v", res, err)
		}
		addPushRegistration(t, f, d.deviceID)
	}
	if dir := directoryDeviceIDs(t, f); dir[left.deviceID] == "" || dir[revoked.deviceID] == "" {
		t.Fatalf("precondition: both devices in the key directory: %v", dir)
	}

	if w := f.do("DELETE", "/api/devices/self", "", left.token, left.cert); w.Code != http.StatusOK {
		t.Fatalf("self-unpair: %d %s", w.Code, w.Body.String())
	}
	if w := f.do("DELETE", "/api/devices/"+revoked.deviceID, "", f.adminToken, f.adminCert); w.Code != http.StatusOK {
		t.Fatalf("admin revoke: %d %s", w.Code, w.Body.String())
	}

	type consequences struct {
		inDirectory, pushRegistered, wrapLive, wrapPresent bool
		vaultLevel                                         int
		manifestCode                                       int
	}
	observe := func(d *keyedDevice) consequences {
		var c consequences
		_, c.inDirectory = directoryDeviceIDs(t, f)[d.deviceID]
		c.pushRegistered = pushRegistered(t, f, d.deviceID)
		recs, _ := store.PullRecords("", []string{"infra:" + d.deviceID})
		for _, r := range recs {
			c.wrapPresent = true
			c.wrapLive = !r.Deleted
		}
		c.vaultLevel = store.VaultLevel(d.userID, "infra")
		c.manifestCode = f.do("GET", "/api/sync/manifest", "", d.token, d.cert).Code
		return c
	}
	gotLeft, gotRevoked := observe(left), observe(revoked)
	if gotLeft != gotRevoked {
		t.Fatalf("leaving must have a revocation's consequences:\n left:    %+v\n revoked: %+v", gotLeft, gotRevoked)
	}
	if gotLeft.inDirectory || gotLeft.pushRegistered || gotLeft.manifestCode != http.StatusForbidden {
		t.Fatalf("a removed device must leave the directory, push and sync: %+v", gotLeft)
	}
	if !gotLeft.wrapPresent || gotLeft.vaultLevel != datasync.LevelEdit {
		t.Fatalf("membership (ACL) and existing grants stay as a revocation leaves them: %+v", gotLeft)
	}
	if recs, _ := store.PullRecords("", []string{"infra:" + adminDev}); len(recs) != 0 && recs[0].Deleted {
		t.Fatal("an untouched device's grant must not be swept")
	}
}

func TestSelfUnpair_RejoinAsNewUserGetsCleanVaultSlate(t *testing.T) {
	f, store, _ := leaveFixture(t)
	carol := newKeyedMember(t, f, "carol")
	if w := f.do("POST", "/api/vault/create", `{"vault_id":"infra"}`, f.adminToken, f.adminCert); w.Code != http.StatusOK {
		t.Fatalf("create vault: %d %s", w.Code, w.Body.String())
	}
	grant := fmt.Sprintf(`{"vault_id":"infra","user_id":"%s","level":"edit"}`, carol.userID)
	if w := f.do("POST", "/api/vault/grant", grant, f.adminToken, f.adminCert); w.Code != http.StatusNoContent {
		t.Fatalf("grant: %d %s", w.Code, w.Body.String())
	}
	const dvkCreatedAt = 1700000000000
	now := time.Now().UnixMilli()
	personal := perDeviceWrap("personal", carol.deviceID, now)
	personal.VaultID = ""
	if res, err := store.PushRecords(carol.userID, []datasync.SyncRecord{dvkRecord(carol.deviceID, dvkCreatedAt), personal}); err != nil || len(res.Accepted) != 2 {
		t.Fatalf("carol's records: %+v %v", res, err)
	}
	if res, err := store.PushRecords(f.adminUser.UserID, []datasync.SyncRecord{perDeviceWrap("infra", carol.deviceID, now)}); err != nil || len(res.Accepted) != 1 {
		t.Fatalf("team wrap: %+v %v", res, err)
	}

	if w := f.do("DELETE", "/api/devices/self", "", carol.token, carol.cert); w.Code != http.StatusOK {
		t.Fatalf("self-unpair: %d %s", w.Code, w.Body.String())
	}
	code, resp, body := invitePair(t, f, carol, adminInvite(t, f), "Someone else")
	if code != http.StatusOK {
		t.Fatalf("re-pair: %d %s", code, body)
	}
	carol.userID = resp.UserID
	carol.refreshCredentials(t, f)

	ids := manifestIDs(t, f, carol.token, carol.cert)
	for _, id := range []string{"infra:" + carol.deviceID, "personal:" + carol.deviceID} {
		if ids[id] {
			t.Errorf("%s from the previous binding reached the device's new owner", id)
		}
	}
	recs, _ := store.PullRecords("", []string{"infra:" + carol.deviceID, "personal:" + carol.deviceID, carol.deviceID})
	for _, r := range recs {
		if r.Type != "device_revocation" {
			t.Errorf("%s %s survived the re-bind", r.Type, r.ID)
		}
	}
	if res, err := store.PushRecords(carol.userID, []datasync.SyncRecord{dvkRecord(carol.deviceID, dvkCreatedAt)}); err != nil || len(res.Accepted) != 1 {
		t.Fatalf("new owner republishes the directory entry: %+v %v", res, err)
	}
	if owner := directoryDeviceIDs(t, f)[carol.deviceID]; owner != carol.userID {
		t.Fatalf("directory must list the device under its new owner, got %q", owner)
	}

	if res, err := store.PushRecords(f.adminUser.UserID, []datasync.SyncRecord{perDeviceWrap("infra", carol.deviceID, now+5)}); err != nil || len(res.Accepted) != 1 {
		t.Fatalf("late top-up: %+v %v", res, err)
	}
	if manifestIDs(t, f, carol.token, carol.cert)["infra:"+carol.deviceID] {
		t.Fatal("a grant to the device is not a grant to its new owner")
	}
}
