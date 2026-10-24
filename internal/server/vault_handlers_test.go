package server

import (
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

	"github.com/pocketcmd/pocketcmd-server/internal/datasync"
	"github.com/pocketcmd/pocketcmd-server/internal/pki"
)

func vaultFixture(t *testing.T) (*teamTestFixture, *datasync.SyncStore) {
	t.Helper()
	f := newTeamTestFixture(t)
	store := newTestSyncStore(t)
	f.srv.RegisterSyncRoutes(store)
	f.srv.RegisterVaultRoutes(store)
	return f, store
}

func pushBody(records ...map[string]any) string {
	b, _ := json.Marshal(map[string]any{"records": records})
	return string(b)
}

func vaultRecord(id, recType, vaultID string, updatedAt int64, data map[string]any) map[string]any {
	return map[string]any{
		"id":         id,
		"type":       recType,
		"updated_at": updatedAt,
		"device_id":  "dev",
		"data":       data,
		"vault_id":   vaultID,
	}
}

func manifestIDs(t *testing.T, f *teamTestFixture, token string, cert *x509.Certificate) map[string]bool {
	t.Helper()
	w := f.do("GET", "/api/sync/manifest", "", token, cert)
	if w.Code != http.StatusOK {
		t.Fatalf("manifest: %d %s", w.Code, w.Body.String())
	}
	var m struct {
		Records []struct {
			ID string `json:"id"`
		} `json:"records"`
	}
	json.NewDecoder(w.Body).Decode(&m)
	ids := map[string]bool{}
	for _, r := range m.Records {
		ids[r.ID] = true
	}
	return ids
}

func TestVault_CreateRequiresAdminOrOwner(t *testing.T) {
	f, _ := vaultFixture(t)

	w := f.do("POST", "/api/vault/create", `{"vault_id":"infra"}`, f.memberToken, f.memberCert)
	if w.Code != http.StatusForbidden {
		t.Fatalf("member create: expected 403, got %d: %s", w.Code, w.Body.String())
	}
	w = f.do("POST", "/api/vault/create", `{"vault_id":"infra"}`, f.adminToken, f.adminCert)
	if w.Code != http.StatusOK {
		t.Fatalf("owner create: expected 200, got %d: %s", w.Code, w.Body.String())
	}
	w = f.do("POST", "/api/vault/create", `{"vault_id":"infra"}`, f.adminToken, f.adminCert)
	if w.Code != http.StatusConflict {
		t.Fatalf("dup create: expected 409, got %d", w.Code)
	}
	w = f.do("POST", "/api/vault/create", `{"vault_id":"personal"}`, f.adminToken, f.adminCert)
	if w.Code != http.StatusBadRequest {
		t.Fatalf("reserved id: expected 400, got %d", w.Code)
	}
}

func TestVault_ACLGatesPushPullAndManifest(t *testing.T) {
	f, _ := vaultFixture(t)
	f.do("POST", "/api/vault/create", `{"vault_id":"infra"}`, f.adminToken, f.adminCert)

	rec := vaultRecord("sec-1", "secret_item", "infra", 1000, map[string]any{"_enc": "AAAA", "kg": 0})

	w := f.do("POST", "/api/sync/push", pushBody(rec), f.memberToken, f.memberCert)
	var res datasync.PushResult
	json.NewDecoder(w.Body).Decode(&res)
	if len(res.Accepted) != 0 {
		t.Fatalf("ungranted push must be rejected: %+v", res)
	}

	w = f.do("POST", "/api/sync/push", pushBody(rec), f.adminToken, f.adminCert)
	res = datasync.PushResult{}
	json.NewDecoder(w.Body).Decode(&res)
	if len(res.Accepted) != 1 {
		t.Fatalf("owner push: %+v body=%s", res, w.Body.String())
	}

	if manifestIDs(t, f, f.memberToken, f.memberCert)["sec-1"] {
		t.Fatal("ungranted member must not see vault record in manifest")
	}

	grant := fmt.Sprintf(`{"vault_id":"infra","user_id":"%s","level":"view"}`, f.memberUser.UserID)
	if w = f.do("POST", "/api/vault/grant", grant, f.adminToken, f.adminCert); w.Code != http.StatusNoContent {
		t.Fatalf("grant view: %d %s", w.Code, w.Body.String())
	}
	if !manifestIDs(t, f, f.memberToken, f.memberCert)["sec-1"] {
		t.Fatal("viewer must see vault record in manifest")
	}
	w = f.do("POST", "/api/sync/pull", `{"ids":["sec-1"]}`, f.memberToken, f.memberCert)
	var pull struct {
		Records []datasync.SyncRecord `json:"records"`
	}
	json.NewDecoder(w.Body).Decode(&pull)
	if len(pull.Records) != 1 {
		t.Fatalf("viewer pull: got %d records", len(pull.Records))
	}
	rec["updated_at"] = 2000
	w = f.do("POST", "/api/sync/push", pushBody(rec), f.memberToken, f.memberCert)
	res = datasync.PushResult{}
	json.NewDecoder(w.Body).Decode(&res)
	if len(res.Accepted) != 0 {
		t.Fatal("viewer push must be rejected (edit required)")
	}

	grant = fmt.Sprintf(`{"vault_id":"infra","user_id":"%s","level":"edit"}`, f.memberUser.UserID)
	f.do("POST", "/api/vault/grant", grant, f.adminToken, f.adminCert)
	w = f.do("POST", "/api/sync/push", pushBody(rec), f.memberToken, f.memberCert)
	res = datasync.PushResult{}
	json.NewDecoder(w.Body).Decode(&res)
	if len(res.Accepted) != 1 {
		t.Fatalf("editor push: %+v", res)
	}

	wrap := vaultRecord("infra:someone", "vault_wrap", "infra", 3000,
		map[string]any{"vault_id": "infra", "recipient_device": "someone", "wrapped_key": "BBBB"})
	w = f.do("POST", "/api/sync/push", pushBody(wrap), f.memberToken, f.memberCert)
	res = datasync.PushResult{}
	json.NewDecoder(w.Body).Decode(&res)
	if len(res.Accepted) != 0 {
		t.Fatal("editor wrap push must be rejected (manage required)")
	}
}

func registerDeviceFor(
	t *testing.T, devices *pki.DeviceRegistry, userID, label string,
) string {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	pubDER, err := x509.MarshalPKIXPublicKey(&key.PublicKey)
	if err != nil {
		t.Fatal(err)
	}
	pubPEM := string(pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: pubDER}))
	id, err := devices.RegisterDeviceForUser(pubPEM, label, userID, "")
	if err != nil {
		t.Fatal(err)
	}
	return id
}

func TestVault_WrapVisibleOnlyToRecipientAndManagers(t *testing.T) {
	f, _ := vaultFixture(t)
	f.do("POST", "/api/vault/create", `{"vault_id":"infra"}`, f.adminToken, f.adminCert)
	carolCert, carolToken, _ := newTeamUserDevice(t, f.devices, f.users, f.mgr, f.serverKey, "carol", "member")

	memberDev := registerDeviceFor(t, f.devices, f.memberUser.UserID, "member-extra")
	wrap := vaultRecord("infra:"+memberDev, "vault_wrap", "infra", 1000,
		map[string]any{
			"vault_id":         "infra",
			"recipient_device": memberDev,
			"wrapped_key":      "BBBB",
		})
	w := f.do("POST", "/api/sync/push", pushBody(wrap), f.adminToken, f.adminCert)
	var res datasync.PushResult
	json.NewDecoder(w.Body).Decode(&res)
	if len(res.Accepted) != 1 {
		t.Fatalf("owner wrap push: %+v %s", res, w.Body.String())
	}

	if manifestIDs(t, f, f.memberToken, f.memberCert)["infra:"+memberDev] {
		t.Fatal("a live wrap must not reach a recipient who holds no grant on the vault")
	}
	grant := fmt.Sprintf(`{"vault_id":"infra","user_id":"%s","level":"view"}`, f.memberUser.UserID)
	if w := f.do("POST", "/api/vault/grant", grant, f.adminToken, f.adminCert); w.Code != http.StatusNoContent {
		t.Fatalf("grant: %d %s", w.Code, w.Body.String())
	}
	if !manifestIDs(t, f, f.memberToken, f.memberCert)["infra:"+memberDev] {
		t.Fatal("recipient must see their wrap once granted")
	}
	if manifestIDs(t, f, carolToken, carolCert)["infra:"+memberDev] {
		t.Fatal("non-recipient must not see someone else's wrap")
	}
}

func TestVault_RevokeCutsAccessAndTombstonesWrap(t *testing.T) {
	f, store := vaultFixture(t)
	f.do("POST", "/api/vault/create", `{"vault_id":"infra"}`, f.adminToken, f.adminCert)
	grant := fmt.Sprintf(`{"vault_id":"infra","user_id":"%s","level":"edit"}`, f.memberUser.UserID)
	f.do("POST", "/api/vault/grant", grant, f.adminToken, f.adminCert)

	memberDev := registerDeviceFor(t, f.devices, f.memberUser.UserID, "member-revoke")
	wrap := vaultRecord("infra:"+memberDev, "vault_wrap", "infra", 1000,
		map[string]any{"vault_id": "infra", "recipient_device": memberDev, "wrapped_key": "BBBB"})
	rec := vaultRecord("sec-1", "secret_item", "infra", 1000, map[string]any{"_enc": "AAAA"})
	f.do("POST", "/api/sync/push", pushBody(wrap, rec), f.adminToken, f.adminCert)

	revoke := fmt.Sprintf(`{"vault_id":"infra","user_id":"%s"}`, f.memberUser.UserID)
	if w := f.do("POST", "/api/vault/revoke", revoke, f.adminToken, f.adminCert); w.Code != http.StatusNoContent {
		t.Fatalf("revoke: %d %s", w.Code, w.Body.String())
	}

	if manifestIDs(t, f, f.memberToken, f.memberCert)["sec-1"] {
		t.Fatal("revoked member must not see vault records")
	}
	if store.VaultLevel(f.memberUser.UserID, "infra") != datasync.LevelNone {
		t.Fatal("ACL row must be gone")
	}
	recs, _ := store.RecordsByType("vault_wrap")
	for _, r := range recs {
		if r.ID == "infra:"+memberDev && !r.Deleted {
			t.Fatal("wrap must be tombstoned on revoke")
		}
	}
	w := f.do("GET", "/api/vault/members?vault_id=infra", "", f.adminToken, f.adminCert)
	if w.Code != http.StatusOK {
		t.Fatalf("members: %d", w.Code)
	}
	var members struct {
		Members []datasync.VaultMember `json:"members"`
	}
	json.NewDecoder(w.Body).Decode(&members)
	for _, m := range members.Members {
		if m.UserID == f.memberUser.UserID {
			t.Fatal("revoked member still listed")
		}
	}
}

func TestVault_RecordCannotSwitchVaults(t *testing.T) {
	f, _ := vaultFixture(t)
	f.do("POST", "/api/vault/create", `{"vault_id":"infra"}`, f.adminToken, f.adminCert)

	rec := vaultRecord("sec-1", "secret_item", "personal", 1000, map[string]any{"_enc": "AAAA"})
	f.do("POST", "/api/sync/push", pushBody(rec), f.adminToken, f.adminCert)

	moved := vaultRecord("sec-1", "secret_item", "infra", 2000, map[string]any{"_enc": "AAAA"})
	w := f.do("POST", "/api/sync/push", pushBody(moved), f.adminToken, f.adminCert)
	var res datasync.PushResult
	json.NewDecoder(w.Body).Decode(&res)
	if len(res.Accepted) != 0 {
		t.Fatal("vault reassignment of an existing record must be rejected")
	}
}

func TestVault_RevokeGuards(t *testing.T) {
	f, store := vaultFixture(t)
	carolCert, carolToken, carol := newTeamUserDevice(t, f.devices, f.users, f.mgr, f.serverKey, "carol", "admin")
	if w := f.do("POST", "/api/vault/create", `{"vault_id":"infra"}`, carolToken, carolCert); w.Code != http.StatusOK {
		t.Fatalf("create: %d %s", w.Code, w.Body.String())
	}

	revokeOwner := fmt.Sprintf(`{"vault_id":"infra","user_id":"%s"}`, f.adminUser.UserID)
	if w := f.do("POST", "/api/vault/revoke", revokeOwner, f.adminToken, f.adminCert); w.Code != http.StatusConflict ||
		!strings.Contains(w.Body.String(), "cannot_revoke_owner") {
		t.Fatalf("revoke owner: %d %s", w.Code, w.Body.String())
	}

	revokeCarol := fmt.Sprintf(`{"vault_id":"infra","user_id":"%s"}`, carol.UserID)
	if w := f.do("POST", "/api/vault/revoke", revokeCarol, f.adminToken, f.adminCert); w.Code != http.StatusConflict ||
		!strings.Contains(w.Body.String(), "last_manager") {
		t.Fatalf("revoke sole manager: %d %s", w.Code, w.Body.String())
	}
	demoteCarol := fmt.Sprintf(`{"vault_id":"infra","user_id":"%s","level":"view"}`, carol.UserID)
	if w := f.do("POST", "/api/vault/grant", demoteCarol, f.adminToken, f.adminCert); w.Code != http.StatusConflict ||
		!strings.Contains(w.Body.String(), "last_manager") {
		t.Fatalf("demote sole manager: %d %s", w.Code, w.Body.String())
	}
	if store.VaultLevel(carol.UserID, "infra") != datasync.LevelManage {
		t.Fatal("refused changes must not apply")
	}

	promoteBob := fmt.Sprintf(`{"vault_id":"infra","user_id":"%s","level":"manage"}`, f.memberUser.UserID)
	if w := f.do("POST", "/api/vault/grant", promoteBob, carolToken, carolCert); w.Code != http.StatusNoContent {
		t.Fatalf("promote bob: %d %s", w.Code, w.Body.String())
	}
	if w := f.do("POST", "/api/vault/revoke", revokeCarol, f.adminToken, f.adminCert); w.Code != http.StatusNoContent {
		t.Fatalf("revoke carol with bob managing: %d %s", w.Code, w.Body.String())
	}
	revokeBob := fmt.Sprintf(`{"vault_id":"infra","user_id":"%s"}`, f.memberUser.UserID)
	if w := f.do("POST", "/api/vault/revoke", revokeBob, f.adminToken, f.adminCert); w.Code != http.StatusConflict {
		t.Fatalf("revoke bob as new sole manager: %d %s", w.Code, w.Body.String())
	}

	if w := f.do("POST", "/api/vault/create", `{"vault_id":"infra"}`, carolToken, carolCert); w.Code != http.StatusConflict {
		t.Fatalf("re-create: %d %s", w.Code, w.Body.String())
	}
	if store.VaultLevel(carol.UserID, "infra") != datasync.LevelNone {
		t.Fatal("a refused create must not grant")
	}
}
