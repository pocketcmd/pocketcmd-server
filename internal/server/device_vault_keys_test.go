package server

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"net/http"
	"reflect"
	"testing"
	"time"

	"github.com/pocketcmd/pocketcmd-server/internal/datasync"
)

func registerExtraDevice(t *testing.T, f *teamTestFixture, userID, name string) string {
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
	id, err := f.devices.RegisterDeviceForUser(pubPEM, name, userID, "")
	if err != nil {
		t.Fatal(err)
	}
	return id
}

func perDeviceWrap(vaultID, deviceID string, updatedAt int64) datasync.SyncRecord {
	data, _ := json.Marshal(map[string]string{"recipient_device": deviceID})
	return datasync.SyncRecord{
		ID: vaultID + ":" + deviceID, Type: "vault_wrap", UpdatedAt: updatedAt,
		VaultID: vaultID, DeviceID: deviceID, Credentials: "sealed",
		Data: json.RawMessage(data),
	}
}

func TestUsers_Delete_CascadesToVaultWraps(t *testing.T) {
	f, store := vaultFixture(t)
	targetID := f.memberUser.UserID
	memberDevice := deviceIDFor(t, f, targetID)
	adminDevice := deviceIDFor(t, f, f.adminUser.UserID)

	if err := store.GrantVault("team1", targetID, datasync.LevelEdit); err != nil {
		t.Fatal(err)
	}
	if err := store.GrantVault("team1", f.adminUser.UserID, datasync.LevelManage); err != nil {
		t.Fatal(err)
	}

	now := time.Now().UnixMilli()
	if _, err := store.PushRecords("", []datasync.SyncRecord{
		perDeviceWrap("team1", memberDevice, now),
		perDeviceWrap("team1", adminDevice, now),
	}); err != nil {
		t.Fatal(err)
	}

	w := f.do("DELETE", "/api/users/"+targetID, "", f.adminToken, f.adminCert)
	if w.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", w.Code, w.Body.String())
	}

	recs, err := store.PullRecords("", []string{
		"team1:" + memberDevice, "team1:" + adminDevice})
	if err != nil {
		t.Fatal(err)
	}
	byID := map[string]datasync.SyncRecord{}
	for _, rec := range recs {
		byID[rec.ID] = rec
	}

	for _, id := range []string{"team1:" + memberDevice} {
		rec, ok := byID[id]
		if !ok {
			t.Fatalf("%s missing after delete", id)
		}
		if !rec.Deleted {
			t.Errorf("%s must be tombstoned by the delete cascade", id)
		}
		if rec.Credentials != "" {
			t.Errorf("%s must have its sealed key material wiped", id)
		}
	}
	if byID["team1:"+adminDevice].Deleted {
		t.Error("the surviving member's wrap must not be swept")
	}
	if got := store.VaultLevel(targetID, "team1"); got != datasync.LevelNone {
		t.Errorf("expected no vault level after delete, got %s", datasync.LevelString(got))
	}
	if got := store.VaultLevel(f.adminUser.UserID, "team1"); got != datasync.LevelManage {
		t.Errorf("the admin's own grant must survive, got %s", datasync.LevelString(got))
	}
}

func TestUsers_Delete_VaultCascadeSyncDisabled(t *testing.T) {
	f := newTeamTestFixture(t)
	w := f.do("DELETE", "/api/users/"+f.memberUser.UserID, "", f.adminToken, f.adminCert)
	if w.Code != http.StatusOK {
		t.Fatalf("expected 200 with no sync store, got %d: %s", w.Code, w.Body.String())
	}
}

func TestCapabilities_Shape(t *testing.T) {
	f := newTeamTestFixture(t)
	w := f.do("GET", "/api/capabilities", "", "", nil)
	if w.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d", w.Code)
	}
	var resp map[string]interface{}
	if err := json.NewDecoder(w.Body).Decode(&resp); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if _, ok := resp["vault_keys"]; ok {
		t.Errorf("vault_keys must not be advertised, got %v", resp["vault_keys"])
	}
	if _, ok := resp["features"]; ok {
		t.Errorf("features must not be advertised, got %v", resp["features"])
	}
	if resp["api_version"] != APIVersion {
		t.Errorf("api_version regressed: %v", resp["api_version"])
	}
	if len(resp) != 2 {
		t.Errorf("expected exactly version + api_version, got %v", resp)
	}
}

type pubkeysResponse struct {
	Devices []deviceEntry `json:"devices"`
}

func getPubkeys(t *testing.T, f *teamTestFixture) pubkeysResponse {
	t.Helper()
	w := f.do("GET", "/api/vault/pubkeys", "", f.adminToken, f.adminCert)
	if w.Code != http.StatusOK {
		t.Fatalf("pubkeys: %d %s", w.Code, w.Body.String())
	}
	var resp pubkeysResponse
	if err := json.NewDecoder(w.Body).Decode(&resp); err != nil {
		t.Fatalf("decode: %v", err)
	}
	return resp
}

func TestVaultPubkeys_DeviceDirectory(t *testing.T) {
	f, store := vaultFixture(t)
	memberDevice := deviceIDFor(t, f, f.memberUser.UserID)
	adminDevice := deviceIDFor(t, f, f.adminUser.UserID)

	now := time.Now().UnixMilli()
	dvk := func(id, pub string) datasync.SyncRecord {
		return datasync.SyncRecord{
			ID: id, Type: "device_vault_key", UpdatedAt: now, DeviceID: id,
			Data: json.RawMessage(`{"device_id":"` + id + `","dvk_pub":"` + pub + `","kind":"p256",` +
				`"mtls_spki":"SPKI-` + pub + `","sig":"SIG-` + pub + `",` +
				`"backing":"hardware","created_at":123,"version":2}`),
		}
	}
	if _, err := store.PushRecords(f.memberUser.UserID,
		[]datasync.SyncRecord{dvk(memberDevice, "MEMBER")}); err != nil {
		t.Fatal(err)
	}
	if _, err := store.PushRecords(f.adminUser.UserID,
		[]datasync.SyncRecord{dvk(adminDevice, "ADMIN")}); err != nil {
		t.Fatal(err)
	}
	if _, err := store.PushRecords("",
		[]datasync.SyncRecord{dvk("deadbeefdeadbeef", "GHOST")}); err != nil {
		t.Fatal(err)
	}

	resp := getPubkeys(t, f)
	byDevice := map[string]deviceEntry{}
	for _, e := range resp.Devices {
		byDevice[e.DeviceID] = e
	}
	if len(byDevice) != 2 {
		t.Fatalf("expected exactly the two registered devices, got %+v", resp.Devices)
	}
	m, ok := byDevice[memberDevice]
	if !ok {
		t.Fatalf("member device missing from directory: %+v", resp.Devices)
	}
	if m.UserID != f.memberUser.UserID || m.DvkPub != "MEMBER" || m.Kind != "p256" {
		t.Errorf("unexpected member entry: %+v", m)
	}
	if m.MTLSSPKI != "SPKI-MEMBER" || m.Sig != "SIG-MEMBER" {
		t.Errorf("SPKI/signature must ride along for the R4 binding: %+v", m)
	}
	if m.Backing != "hardware" || m.CreatedAt != 123 {
		t.Errorf("backing/created_at missing: %+v", m)
	}
	if len(m.Attestation) != 0 {
		t.Errorf("a record without attestation must not grow one: %s", m.Attestation)
	}
	if m.DisplayName != f.memberUser.DisplayName {
		t.Errorf("expected display name %q, got %q", f.memberUser.DisplayName, m.DisplayName)
	}
	if _, ok := byDevice["deadbeefdeadbeef"]; ok {
		t.Error("an entry for an unregistered device must be dropped")
	}
}

func TestVaultPubkeys_AttestationObjectPassthrough(t *testing.T) {
	f, store := vaultFixture(t)
	memberDevice := deviceIDFor(t, f, f.memberUser.UserID)

	const attestation = `{"platform":"android","status":"verified","nonce":"abc"}`
	if _, err := store.PushRecords(f.memberUser.UserID, []datasync.SyncRecord{{
		ID: memberDevice, Type: "device_vault_key", UpdatedAt: time.Now().UnixMilli(),
		DeviceID: memberDevice,
		Data: json.RawMessage(`{"device_id":"` + memberDevice + `","dvk_pub":"MEMBER",` +
			`"kind":"p256","mtls_spki":"SPKI","backing":"hardware","sig":"SIG",` +
			`"label":"Pixel","attestation":` + attestation + `,"created_at":7,"version":2}`),
	}}); err != nil {
		t.Fatal(err)
	}

	w := f.do("GET", "/api/vault/pubkeys", "", f.memberToken, f.memberCert)
	if w.Code != http.StatusOK {
		t.Fatalf("pubkeys: %d %s", w.Code, w.Body.String())
	}
	var raw struct {
		Devices []map[string]json.RawMessage `json:"devices"`
	}
	if err := json.Unmarshal(w.Body.Bytes(), &raw); err != nil {
		t.Fatalf("decode: %v", err)
	}
	var entry map[string]json.RawMessage
	for _, d := range raw.Devices {
		if string(d["device_id"]) == `"`+memberDevice+`"` {
			entry = d
		}
	}
	if entry == nil {
		t.Fatalf("record with an attestation object was not listed: %s", w.Body.String())
	}
	var got, want any
	if err := json.Unmarshal(entry["attestation"], &got); err != nil {
		t.Fatalf("attestation is not an object: %s", entry["attestation"])
	}
	_ = json.Unmarshal([]byte(attestation), &want)
	if !reflect.DeepEqual(got, want) {
		t.Errorf("attestation not passed through: got %s", entry["attestation"])
	}
	for k, v := range map[string]string{
		"dvk_pub": `"MEMBER"`, "sig": `"SIG"`, "mtls_spki": `"SPKI"`,
		"backing": `"hardware"`, "kind": `"p256"`, "created_at": `7`,
	} {
		if string(entry[k]) != v {
			t.Errorf("%s: got %s, want %s", k, entry[k], v)
		}
	}
	for _, legacy := range []string{"public_key", "signature"} {
		if _, ok := entry[legacy]; ok {
			t.Errorf("legacy field %q must not be emitted", legacy)
		}
	}
}

func TestVaultPubkeys_RejectsSquattedDeviceEntry(t *testing.T) {
	f, store := vaultFixture(t)
	adminDevice := deviceIDFor(t, f, f.adminUser.UserID)

	res, err := store.PushRecords(f.memberUser.UserID, []datasync.SyncRecord{{
		ID: adminDevice, Type: "device_vault_key", UpdatedAt: time.Now().UnixMilli(),
		Data: json.RawMessage(`{"dvk_pub":"ATTACKER","kind":"p256"}`),
	}})
	if err != nil {
		t.Fatal(err)
	}
	if len(res.Rejected) != 1 {
		t.Fatalf("cross-user device_vault_key write must be rejected, got %+v", res)
	}

	orig := store.ResolveDeviceUser
	store.ResolveDeviceUser = func(string) (string, bool) { return f.memberUser.UserID, true }
	res, err = store.PushRecords(f.memberUser.UserID, []datasync.SyncRecord{{
		ID: adminDevice, Type: "device_vault_key", UpdatedAt: time.Now().UnixMilli(),
		Data: json.RawMessage(`{"dvk_pub":"ATTACKER","kind":"p256"}`),
	}})
	store.ResolveDeviceUser = orig
	if err != nil {
		t.Fatal(err)
	}
	if len(res.Accepted) != 1 {
		t.Fatalf("test setup: squatted row must land via the lying resolver, got %+v", res)
	}

	for _, e := range getPubkeys(t, f).Devices {
		if e.DeviceID == adminDevice {
			t.Fatalf("squatted directory entry served: %+v", e)
		}
	}
}

func TestVaultPubkeys_RevokedDeviceDropped(t *testing.T) {
	f, store := vaultFixture(t)
	memberDevice := deviceIDFor(t, f, f.memberUser.UserID)
	if _, err := store.PushRecords(f.memberUser.UserID, []datasync.SyncRecord{{
		ID: memberDevice, Type: "device_vault_key", UpdatedAt: time.Now().UnixMilli(),
		Data: json.RawMessage(`{"dvk_pub":"MEMBER","kind":"p256"}`),
	}}); err != nil {
		t.Fatal(err)
	}
	if len(getPubkeys(t, f).Devices) == 0 {
		t.Fatal("precondition: the device should be listed before revocation")
	}

	if err := f.devices.Revoke(memberDevice); err != nil {
		t.Fatal(err)
	}
	for _, e := range getPubkeys(t, f).Devices {
		if e.DeviceID == memberDevice {
			t.Fatalf("revoked device still in the grant directory: %+v", e)
		}
	}
}

func TestVaultPubkeys_IdentitiesRetired(t *testing.T) {
	f, store := vaultFixture(t)

	res, err := store.PushRecords(f.memberUser.UserID, []datasync.SyncRecord{{
		ID: "fp-member", Type: "vault_identity", UpdatedAt: time.Now().UnixMilli(),
		Data: json.RawMessage(`{"public_key":"V1PUB","updated_at":5}`),
	}})
	if err != nil {
		t.Fatal(err)
	}
	if len(res.Rejected) != 1 {
		t.Fatalf("vault_identity must be rejected as unsupported after cutover, got %+v", res)
	}

	w := f.do("GET", "/api/vault/pubkeys", "", f.adminToken, f.adminCert)
	if w.Code != http.StatusOK {
		t.Fatalf("pubkeys: %d %s", w.Code, w.Body.String())
	}
	var raw map[string]json.RawMessage
	if err := json.NewDecoder(w.Body).Decode(&raw); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if _, ok := raw["identities"]; ok {
		t.Fatal("the v1 identities shape must be gone from /api/vault/pubkeys")
	}
	if _, ok := raw["devices"]; !ok {
		t.Fatal("the v2 devices shape must be present")
	}
}

func TestSyncPush_DeviceRevocationScopedByWiring(t *testing.T) {
	f, store := vaultFixture(t)
	memberDevice := deviceIDFor(t, f, f.memberUser.UserID)
	adminDevice := deviceIDFor(t, f, f.adminUser.UserID)

	ts := time.Now().UnixMilli()
	body := func(id string, updatedAt int64) string {
		return pushBody(map[string]any{
			"id": id, "type": "device_revocation", "updated_at": updatedAt,
			"data": map[string]any{"revoked_at": updatedAt},
		})
	}

	w := f.do("POST", "/api/sync/push", body(memberDevice, ts+1), f.memberToken, f.memberCert)
	if w.Code != http.StatusOK {
		t.Fatalf("member self-revocation: %d %s", w.Code, w.Body.String())
	}
	var res datasync.PushResult
	json.NewDecoder(w.Body).Decode(&res)
	if len(res.Accepted) != 1 {
		t.Fatalf("member must be able to revoke their own device, got %+v", res)
	}

	w = f.do("POST", "/api/sync/push", body(adminDevice, ts+2), f.memberToken, f.memberCert)
	json.NewDecoder(w.Body).Decode(&res)
	if len(res.Rejected) != 1 {
		t.Fatalf("cross-user device_revocation must be rejected, got %+v", res)
	}

	memberDevice2 := registerExtraDevice(t, f, f.memberUser.UserID, "bob-tablet")
	res = datasync.PushResult{}
	w = f.do("POST", "/api/sync/push", body(memberDevice2, ts+3), f.adminToken, f.adminCert)
	json.NewDecoder(w.Body).Decode(&res)
	if len(res.Accepted) != 1 {
		t.Fatalf("admin must be able to revoke a member's device, got %+v", res)
	}

	recs, _ := store.PullRecords("", []string{adminDevice})
	for _, rec := range recs {
		if rec.Type == "device_revocation" {
			t.Fatalf("rejected revocation was stored anyway: %+v", rec.ID)
		}
	}
}
