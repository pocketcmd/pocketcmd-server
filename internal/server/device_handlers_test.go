package server

import (
	"encoding/json"
	"net/http"
	"strings"
	"testing"
)

func deviceIDFor(t *testing.T, f *teamTestFixture, userID string) string {
	t.Helper()
	devs, err := f.devices.DevicesByUserID(userID)
	if err != nil || len(devs) == 0 {
		t.Fatalf("no device for user %s: %v", userID, err)
	}
	return devs[0].DeviceID
}

func decodeDeviceList(t *testing.T, body string) []deviceSummary {
	t.Helper()
	var out []deviceSummary
	if err := json.NewDecoder(strings.NewReader(body)).Decode(&out); err != nil {
		t.Fatalf("decode device list: %v", err)
	}
	return out
}

func TestDevices_List_MemberSeesOwnOnly(t *testing.T) {
	f := newTeamTestFixture(t)
	w := f.do("GET", "/api/devices", "", f.memberToken, f.memberCert)
	if w.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", w.Code, w.Body.String())
	}
	list := decodeDeviceList(t, w.Body.String())
	if len(list) != 1 {
		t.Fatalf("expected 1 device, got %d", len(list))
	}
	if list[0].UserID != f.memberUser.UserID {
		t.Errorf("expected own device, got user %s", list[0].UserID)
	}
	if !list[0].Self {
		t.Error("expected calling device to be flagged self")
	}
	if list[0].DisplayName != "bob" {
		t.Errorf("expected display_name bob, got %q", list[0].DisplayName)
	}
}

func TestDevices_List_AdminSeesAll(t *testing.T) {
	f := newTeamTestFixture(t)
	w := f.do("GET", "/api/devices", "", f.adminToken, f.adminCert)
	if w.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", w.Code, w.Body.String())
	}
	list := decodeDeviceList(t, w.Body.String())
	if len(list) != 2 {
		t.Fatalf("expected 2 devices, got %d", len(list))
	}
	if !list[0].Self || list[0].UserID != f.adminUser.UserID {
		t.Errorf("expected admin's own device first, got %+v", list[0])
	}
	if list[1].Self {
		t.Error("member device must not be flagged self for the admin")
	}
}

func TestDevices_SelfRevoke_ThenLockedOut(t *testing.T) {
	f := newTeamTestFixture(t)
	w := f.do("DELETE", "/api/devices/self", "", f.memberToken, f.memberCert)
	if w.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", w.Code, w.Body.String())
	}
	rec, err := f.devices.FindByID(deviceIDFor(t, f, f.memberUser.UserID))
	if err != nil {
		t.Fatal(err)
	}
	if rec.Status != "left" {
		t.Fatalf("expected left, got %s", rec.Status)
	}
	u, err := f.users.FindByID(f.memberUser.UserID)
	if err != nil || u == nil || u.Status != "active" {
		t.Fatalf("expected user still active, got %+v (%v)", u, err)
	}
	w = f.do("GET", "/api/devices", "", f.memberToken, f.memberCert)
	if w.Code != http.StatusForbidden {
		t.Fatalf("expected 403 after self-revoke, got %d", w.Code)
	}
}

func TestDevices_MemberCannotRevokeOthers(t *testing.T) {
	f := newTeamTestFixture(t)
	adminDevice := deviceIDFor(t, f, f.adminUser.UserID)
	w := f.do("DELETE", "/api/devices/"+adminDevice, "", f.memberToken, f.memberCert)
	if w.Code != http.StatusForbidden {
		t.Fatalf("expected 403, got %d: %s", w.Code, w.Body.String())
	}
}

func TestDevices_AdminRevokesMemberDevice_Idempotent(t *testing.T) {
	f := newTeamTestFixture(t)
	memberDevice := deviceIDFor(t, f, f.memberUser.UserID)
	for i := 0; i < 2; i++ {
		w := f.do("DELETE", "/api/devices/"+memberDevice, "", f.adminToken, f.adminCert)
		if w.Code != http.StatusOK {
			t.Fatalf("attempt %d: expected 200, got %d: %s", i+1, w.Code, w.Body.String())
		}
	}
	w := f.do("GET", "/api/devices", "", f.adminToken, f.adminCert)
	list := decodeDeviceList(t, w.Body.String())
	if len(list) != 1 {
		t.Fatalf("expected 1 device after revoke, got %d", len(list))
	}
}

func TestDevices_AdminDevices_OwnerOnly(t *testing.T) {
	f := newTeamTestFixture(t)
	admin2Cert, admin2Token, _ := newTeamUserDevice(t, f.devices, f.users, f.mgr, f.serverKey, "carol", "admin")
	ownerDevice := deviceIDFor(t, f, f.adminUser.UserID)

	w := f.do("DELETE", "/api/devices/"+ownerDevice, "", admin2Token, admin2Cert)
	if w.Code != http.StatusForbidden {
		t.Fatalf("expected 403 for non-owner admin, got %d: %s", w.Code, w.Body.String())
	}

	carolDevice := deviceIDFor(t, f, findUserID(t, f, "carol"))
	w = f.do("DELETE", "/api/devices/"+carolDevice, "", f.adminToken, f.adminCert)
	if w.Code != http.StatusOK {
		t.Fatalf("expected 200 for owner, got %d: %s", w.Code, w.Body.String())
	}
}

func TestDevices_Revoke_NotFound(t *testing.T) {
	f := newTeamTestFixture(t)
	w := f.do("DELETE", "/api/devices/ffffffffffffffff", "", f.adminToken, f.adminCert)
	if w.Code != http.StatusNotFound {
		t.Fatalf("expected 404, got %d: %s", w.Code, w.Body.String())
	}
}

func findUserID(t *testing.T, f *teamTestFixture, displayName string) string {
	t.Helper()
	users, err := f.users.List()
	if err != nil {
		t.Fatal(err)
	}
	for _, u := range users {
		if u.DisplayName == displayName {
			return u.UserID
		}
	}
	t.Fatalf("no user named %s", displayName)
	return ""
}

func TestDevices_List_IncludeAll(t *testing.T) {
	f := newTeamTestFixture(t)
	memberDev := deviceIDFor(t, f, f.memberUser.UserID)
	if err := f.devices.Leave(memberDev); err != nil {
		t.Fatal(err)
	}

	w := f.do("GET", "/api/devices", "", f.adminToken, f.adminCert)
	list := decodeDeviceList(t, w.Body.String())
	if len(list) != 1 || list[0].Status != "active" || list[0].RemovedAt != nil {
		t.Fatalf("default listing must show active devices only, got %+v", list)
	}

	w = f.do("GET", "/api/devices?include=all", "", f.adminToken, f.adminCert)
	list = decodeDeviceList(t, w.Body.String())
	if len(list) != 2 {
		t.Fatalf("include=all: expected 2 devices, got %+v", list)
	}
	var left *deviceSummary
	for i := range list {
		if list[i].DeviceID == memberDev {
			left = &list[i]
		}
	}
	if left == nil || left.Status != "left" || left.RemovedAt == nil || *left.RemovedAt == "" {
		t.Fatalf("expected the left device with status/removed_at, got %+v", left)
	}
	if !strings.Contains(w.Body.String(), `"removed_at":null`) {
		t.Fatalf("active device must serialise removed_at as null: %s", w.Body.String())
	}

	w = f.do("GET", "/api/devices?include=all", "", f.memberToken, f.memberCert)
	if w.Code != http.StatusForbidden {
		t.Fatalf("left member: expected 403, got %d", w.Code)
	}
}

func TestDevices_Patch(t *testing.T) {
	f, audit := newTeamTestFixtureWithAudit(t)
	memberDev := deviceIDFor(t, f, f.memberUser.UserID)
	adminDev := deviceIDFor(t, f, f.adminUser.UserID)

	w := f.do("PATCH", "/api/devices/self", `{"device_name":"bob phone","device_label":"work"}`, f.memberToken, f.memberCert)
	if w.Code != http.StatusOK {
		t.Fatalf("self rename: expected 200, got %d: %s", w.Code, w.Body.String())
	}
	var got deviceSummary
	if err := json.NewDecoder(w.Body).Decode(&got); err != nil {
		t.Fatal(err)
	}
	if got.DeviceID != memberDev || got.DeviceName != "bob phone" || got.DeviceLabel != "work" || !got.Self || got.Status != "active" {
		t.Fatalf("unexpected device object %+v", got)
	}
	if !strings.Contains(audit.String(), "device_renamed") {
		t.Fatal("expected device_renamed audit event")
	}

	w = f.do("PATCH", "/api/devices/"+memberDev, `{"device_label":"home"}`, f.memberToken, f.memberCert)
	if w.Code != http.StatusOK {
		t.Fatalf("partial: expected 200, got %d: %s", w.Code, w.Body.String())
	}
	rec, _ := f.devices.FindByID(memberDev)
	if rec.DeviceName != "bob phone" || rec.DeviceLabel != "home" {
		t.Fatalf("partial update mangled fields: %+v", rec)
	}

	w = f.do("PATCH", "/api/devices/"+adminDev, `{"device_name":"x"}`, f.memberToken, f.memberCert)
	if w.Code != http.StatusForbidden {
		t.Fatalf("member on admin device: expected 403, got %d", w.Code)
	}
	w = f.do("PATCH", "/api/devices/"+memberDev, `{"device_name":"renamed by admin"}`, f.adminToken, f.adminCert)
	if w.Code != http.StatusOK {
		t.Fatalf("admin on member device: expected 200, got %d: %s", w.Code, w.Body.String())
	}

	w = f.do("PATCH", "/api/devices/"+memberDev, `{}`, f.memberToken, f.memberCert)
	if w.Code != http.StatusBadRequest || !strings.Contains(w.Body.String(), "no_fields") {
		t.Fatalf("no fields: got %d %s", w.Code, w.Body.String())
	}
	w = f.do("PATCH", "/api/devices/"+memberDev, `{"device_name":"`+strings.Repeat("é", 129)+`"}`, f.memberToken, f.memberCert)
	if w.Code != http.StatusBadRequest || !strings.Contains(w.Body.String(), "name_too_long") {
		t.Fatalf("too long: got %d %s", w.Code, w.Body.String())
	}
	w = f.do("PATCH", "/api/devices/"+memberDev, `{"device_name":"`+strings.Repeat("é", 128)+`"}`, f.memberToken, f.memberCert)
	if w.Code != http.StatusOK {
		t.Fatalf("128 runes must be accepted: got %d %s", w.Code, w.Body.String())
	}
	w = f.do("PATCH", "/api/devices/nope", `{"device_name":"x"}`, f.adminToken, f.adminCert)
	if w.Code != http.StatusNotFound || !strings.Contains(w.Body.String(), "device_not_found") {
		t.Fatalf("unknown: got %d %s", w.Code, w.Body.String())
	}
	w = f.do("PATCH", "/api/devices/"+memberDev, `not json`, f.memberToken, f.memberCert)
	if w.Code != http.StatusBadRequest || !strings.Contains(w.Body.String(), "invalid_body") {
		t.Fatalf("bad body: got %d %s", w.Code, w.Body.String())
	}
}
