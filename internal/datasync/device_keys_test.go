package datasync

import (
	"encoding/json"
	"testing"
	"time"
)

func deviceOwners(store *SyncStore, owners map[string]string) {
	store.ResolveDeviceUser = func(deviceID string) (string, bool) {
		u, ok := owners[deviceID]
		return u, ok
	}
}

func deviceWrap(vaultID, deviceID string, updatedAt int64) SyncRecord {
	data, _ := json.Marshal(map[string]string{"recipient_device": deviceID})
	return SyncRecord{
		ID: vaultID + ":" + deviceID, Type: "vault_wrap", SchemaVersion: 1,
		UpdatedAt: updatedAt, DeviceID: deviceID, VaultID: vaultID,
		Data: json.RawMessage(data),
	}
}

func pulledIDs(t *testing.T, store *SyncStore, userID string, ids ...string) map[string]bool {
	t.Helper()
	recs, err := store.PullRecords(userID, ids)
	if err != nil {
		t.Fatalf("pull as %q: %v", userID, err)
	}
	got := map[string]bool{}
	for _, r := range recs {
		got[r.ID] = true
	}
	return got
}

func TestDeviceWrap_VisibleToRecipientDeviceOwner(t *testing.T) {
	store := newTestStore(t)
	deviceOwners(store, map[string]string{
		"aa11": "alice",
		"aa22": "alice",
		"bb11": "bob",
	})
	store.GrantVault("team1", "alice", LevelView)
	store.GrantVault("team1", "bob", LevelView)
	store.GrantVault("team1", "mallory", LevelManage)

	now := time.Now().UnixMilli()
	if _, err := store.PushRecords("", []SyncRecord{
		deviceWrap("team1", "aa11", now),
		deviceWrap("team1", "aa22", now),
		deviceWrap("team1", "bb11", now),
		deviceWrap("team1", "zz99", now),
	}); err != nil {
		t.Fatal(err)
	}
	ids := []string{"team1:aa11", "team1:aa22", "team1:bb11", "team1:zz99"}

	alice := pulledIDs(t, store, "alice", ids...)
	if !alice["team1:aa11"] || !alice["team1:aa22"] {
		t.Errorf("alice must see wraps for both her devices, got %v", alice)
	}
	if alice["team1:bb11"] {
		t.Error("alice must NOT see a wrap addressed to bob's device")
	}
	if alice["team1:zz99"] {
		t.Error("an unresolvable recipient device must not be visible (fail closed)")
	}

	bob := pulledIDs(t, store, "bob", ids...)
	if !bob["team1:bb11"] {
		t.Errorf("bob must see the wrap for his device, got %v", bob)
	}
	if bob["team1:aa11"] || bob["team1:aa22"] {
		t.Error("bob must NOT see wraps addressed to alice's devices")
	}

	mgr := pulledIDs(t, store, "mallory", ids...)
	for _, id := range ids {
		if !mgr[id] {
			t.Errorf("vault manager must see %s, got %v", id, mgr)
		}
	}
}

func TestDeviceWrap_FailsClosedWithoutResolver(t *testing.T) {
	store := newTestStore(t)
	store.GrantVault("team1", "alice", LevelEdit)
	now := time.Now().UnixMilli()
	store.PushRecords("", []SyncRecord{deviceWrap("team1", "aa11", now)})

	if pulledIDs(t, store, "alice", "team1:aa11")["team1:aa11"] {
		t.Error("without ResolveDeviceUser a per-device wrap must not be visible")
	}
	if !pulledIDs(t, store, "", "team1:aa11")["team1:aa11"] {
		t.Error("unscoped operator must still see the wrap")
	}
}

func TestDeviceDirectory_VisibleToCoMemberNotToOutsider(t *testing.T) {
	store := newTestStore(t)
	deviceOwners(store, map[string]string{"aa11": "alice"})
	now := time.Now().UnixMilli()

	if _, err := store.PushRecords("alice", []SyncRecord{
		{ID: "aa11", Type: "device_vault_key", UpdatedAt: now, DeviceID: "aa11",
			Data: json.RawMessage(`{"dvk_pub":"PUB","kind":"p256"}`)},
		{ID: "aa11", Type: "enroll_request", UpdatedAt: now, DeviceID: "aa11",
			Data: json.RawMessage(`{"label":"alice-phone"}`)},
		{ID: "aa11", Type: "device_revocation", UpdatedAt: now, DeviceID: "aa11",
			Data: json.RawMessage(`{"revoked_at":1}`)},
	}); err != nil {
		t.Fatal(err)
	}

	bob := pulledIDs(t, store, "bob", "aa11")
	seen := map[string]bool{}
	recs, _ := store.PullRecords("bob", []string{"aa11"})
	for _, r := range recs {
		seen[r.Type] = true
	}
	if !seen["device_vault_key"] {
		t.Errorf("co-member must see the device directory entry, got %v (%v)", seen, bob)
	}
	if !seen["device_revocation"] {
		t.Errorf("co-member must see device_revocation, got %v", seen)
	}
	if seen["enroll_request"] {
		t.Error("enroll_request is own-user-only and must not reach a co-member")
	}

	ownSeen := map[string]bool{}
	ownRecs, _ := store.PullRecords("alice", []string{"aa11"})
	for _, r := range ownRecs {
		ownSeen[r.Type] = true
	}
	for _, want := range []string{"device_vault_key", "enroll_request", "device_revocation"} {
		if !ownSeen[want] {
			t.Errorf("owner must see own %s, got %v", want, ownSeen)
		}
	}

	store.AuthorizeRead = func(userID, recType string) bool {
		return !(userID == "carol" && recType == "device_vault_key")
	}
	carol := map[string]bool{}
	carolRecs, _ := store.PullRecords("carol", []string{"aa11"})
	for _, r := range carolRecs {
		carol[r.Type] = true
	}
	if carol["device_vault_key"] {
		t.Error("AuthorizeRead denial must still hide the directory entry")
	}
}

func TestDeviceDirectory_InManifest(t *testing.T) {
	store := newTestStore(t)
	deviceOwners(store, map[string]string{"aa11": "alice"})
	now := time.Now().UnixMilli()
	store.PushRecords("alice", []SyncRecord{
		{ID: "aa11", Type: "device_vault_key", UpdatedAt: now, Data: json.RawMessage(`{"dvk_pub":"PUB"}`)},
		{ID: "aa11", Type: "enroll_request", UpdatedAt: now, Data: json.RawMessage(`{}`)},
	})
	m, err := store.GetManifest("bob")
	if err != nil {
		t.Fatal(err)
	}
	types := map[string]bool{}
	for _, e := range m.Records {
		types[e.Type] = true
	}
	if !types["device_vault_key"] {
		t.Error("co-member manifest must list device_vault_key")
	}
	if types["enroll_request"] {
		t.Error("co-member manifest must not list another user's enroll_request")
	}
}

func TestPurgeUserData_KeepsDeviceRevocation(t *testing.T) {
	store := newTestStore(t)
	deviceOwners(store, map[string]string{"aa11": "alice"})
	now := time.Now().UnixMilli()
	if _, err := store.PushRecords("alice", []SyncRecord{
		{ID: "task-1", Type: "task", UpdatedAt: now, DeviceID: "aa11",
			Data: json.RawMessage(`{"host":"h"}`), Credentials: "sealed"},
		{ID: "aa11", Type: "device_revocation", UpdatedAt: now, DeviceID: "aa11",
			Data: json.RawMessage(`{"revoked_at":1}`)},
		{ID: "aa11", Type: "device_vault_key", UpdatedAt: now, DeviceID: "aa11",
			Data: json.RawMessage(`{"dvk_pub":"PUB"}`)},
	}); err != nil {
		t.Fatal(err)
	}

	n, err := store.PurgeUserData("alice", []string{"aa11"})
	if err != nil {
		t.Fatal(err)
	}
	if n != 1 {
		t.Errorf("only the task should be purged, got %d records", n)
	}

	recs, _ := store.PullRecords("", []string{"task-1", "aa11"})
	byType := map[string]SyncRecord{}
	for _, r := range recs {
		byType[r.Type] = r
	}
	if !byType["task"].Deleted {
		t.Error("the ordinary personal record should have been purged")
	}
	rev := byType["device_revocation"]
	if rev.Deleted || string(rev.Data) != `{"revoked_at":1}` {
		t.Errorf("device_revocation must survive purge intact, got deleted=%v data=%s",
			rev.Deleted, rev.Data)
	}
	dvk := byType["device_vault_key"]
	if dvk.Deleted || string(dvk.Data) != `{"dvk_pub":"PUB"}` {
		t.Errorf("device_vault_key must survive purge intact, got deleted=%v data=%s",
			dvk.Deleted, dvk.Data)
	}
}

func TestDeviceRevocation_NeverTombstoned(t *testing.T) {
	store := newTestStore(t)
	deviceOwners(store, map[string]string{"aa11": "alice"})
	now := time.Now().UnixMilli()
	store.PushRecords("alice", []SyncRecord{
		{ID: "aa11", Type: "device_revocation", UpdatedAt: now, Data: json.RawMessage(`{"revoked_at":1}`)},
	})

	for _, caller := range []string{"alice", ""} {
		res, err := store.PushRecords(caller, []SyncRecord{
			{ID: "aa11", Type: "device_revocation", UpdatedAt: now + 1000, Deleted: true,
				Data: json.RawMessage(`{}`)},
		})
		if err != nil {
			t.Fatal(err)
		}
		if len(res.Rejected) != 1 {
			t.Fatalf("delete of device_revocation must be rejected for caller %q, got %+v", caller, res)
		}
	}

	recs, _ := store.PullRecords("", []string{"aa11"})
	if len(recs) != 1 || recs[0].Deleted {
		t.Fatalf("device_revocation must still be live, got %+v", recs)
	}

	if err := store.CleanupTombstones(0); err != nil {
		t.Fatal(err)
	}
	if recs, _ := store.PullRecords("", []string{"aa11"}); len(recs) != 1 {
		t.Fatal("CleanupTombstones must not remove a live device_revocation")
	}
}

func TestDeviceRecords_WriteScoping(t *testing.T) {
	for _, recType := range []string{"device_vault_key", "enroll_request", "device_revocation"} {
		t.Run(recType, func(t *testing.T) {
			store := newTestStore(t)
			deviceOwners(store, map[string]string{"aa11": "alice", "bb11": "bob"})
			store.IsTeamAdmin = func(userID string) bool { return userID == "root" }

			ts := time.Now().UnixMilli()
			next := func() int64 { ts += 1000; return ts }

			cases := []struct {
				name     string
				caller   string
				deviceID string
				accepted bool
			}{
				{"owner writes own device", "alice", "aa11", true},
				{"member writes another member's device", "bob", "aa11", false},
				{"admin writes on a member's behalf", "root", "bb11", true},
				{"unknown device fails closed", "alice", "cc99", false},
				{"unscoped operator", "", "bb11", true},
			}
			for _, tc := range cases {
				res, err := store.PushRecords(tc.caller, []SyncRecord{{
					ID: tc.deviceID, Type: recType, UpdatedAt: next(),
					Data: json.RawMessage(`{"k":1}`),
				}})
				if err != nil {
					t.Fatalf("%s: %v", tc.name, err)
				}
				got := len(res.Accepted) == 1
				if got != tc.accepted {
					t.Errorf("%s: accepted=%v, want %v (%+v)", tc.name, got, tc.accepted, res)
				}
			}

			store.ResolveDeviceUser = nil
			res, _ := store.PushRecords("alice", []SyncRecord{{
				ID: "aa11", Type: recType, UpdatedAt: next(),
				Data: json.RawMessage(`{"k":2}`),
			}})
			if len(res.Rejected) != 1 {
				t.Errorf("missing resolver must fail closed, got %+v", res)
			}
		})
	}
}

func TestVaultIdentity_RetiredAtCutover(t *testing.T) {
	store := newTestStore(t)
	for _, caller := range []string{"alice", ""} {
		res, err := store.PushRecords(caller, []SyncRecord{{
			ID: "fp-1", Type: "vault_identity", UpdatedAt: time.Now().UnixMilli(),
			Data: json.RawMessage(`{"dvk_pub":"PUB"}`),
		}})
		if err != nil {
			t.Fatal(err)
		}
		if len(res.Rejected) != 1 || len(res.Accepted) != 0 {
			t.Fatalf("vault_identity must be rejected for caller %q, got %+v", caller, res)
		}
	}
}

func TestRevokeVault_TombstonesAllDeviceWraps(t *testing.T) {
	store := newTestStore(t)
	deviceOwners(store, map[string]string{
		"aa11": "alice", "aa22": "alice", "bb11": "bob",
	})
	store.GrantVault("team1", "alice", LevelEdit)
	store.GrantVault("team1", "bob", LevelEdit)
	store.GrantVault("other", "alice", LevelEdit)

	now := time.Now().UnixMilli()
	if _, err := store.PushRecords("", []SyncRecord{
		deviceWrap("team1", "aa11", now),
		deviceWrap("team1", "aa22", now),
		deviceWrap("team1", "bb11", now),
		deviceWrap("other", "aa11", now),
	}); err != nil {
		t.Fatal(err)
	}

	if err := store.RevokeVault("team1", "alice"); err != nil {
		t.Fatal(err)
	}

	recs, _ := store.PullRecords("", []string{
		"team1:aa11", "team1:aa22", "team1:bb11", "other:aa11"})
	byID := map[string]SyncRecord{}
	for _, r := range recs {
		byID[r.ID] = r
	}

	for _, id := range []string{"team1:aa11", "team1:aa22"} {
		rec, ok := byID[id]
		if !ok {
			t.Fatalf("%s missing", id)
		}
		if !rec.Deleted {
			t.Errorf("%s must be tombstoned", id)
		}
		if rec.Credentials != "" {
			t.Errorf("%s must have its sealed material wiped", id)
		}
		if wrapRecipientDevice(rec.Data) == "" {
			t.Errorf("%s tombstone must keep recipient_device, got %s", id, rec.Data)
		}
	}
	if got := wrapRecipientDevice(byID["team1:aa11"].Data); got != "aa11" {
		t.Errorf("per-device tombstone must keep recipient_device, got %q", got)
	}

	if byID["team1:bb11"].Deleted {
		t.Error("bob's wrap must survive alice's revocation")
	}
	if byID["other:aa11"].Deleted {
		t.Error("alice's wrap in another vault must survive")
	}

	if got := store.VaultLevel("alice", "team1"); got != LevelNone {
		t.Errorf("ACL row must be gone, got %s", LevelString(got))
	}

	if !pulledIDs(t, store, "alice", "team1:aa11")["team1:aa11"] {
		t.Error("revoked member must still see the wrap tombstone")
	}
}

func TestRevokeVault_VaultIDWithUnderscore(t *testing.T) {
	store := newTestStore(t)
	deviceOwners(store, map[string]string{"aa11": "alice"})
	now := time.Now().UnixMilli()
	store.PushRecords("", []SyncRecord{
		deviceWrap("team_a", "aa11", now),
		deviceWrap("teamXa", "aa11", now),
	})

	if err := store.RevokeVault("team_a", "alice"); err != nil {
		t.Fatal(err)
	}
	recs, _ := store.PullRecords("", []string{"team_a:aa11", "teamXa:aa11"})
	for _, r := range recs {
		switch r.ID {
		case "team_a:aa11":
			if !r.Deleted {
				t.Error("team_a wrap must be tombstoned")
			}
		case "teamXa:aa11":
			if r.Deleted {
				t.Error("teamXa wrap must NOT be swept by a '_' wildcard match")
			}
		}
	}
}

func TestVaultsForUser(t *testing.T) {
	store := newTestStore(t)
	store.GrantVault("v-b", "alice", LevelEdit)
	store.GrantVault("v-a", "alice", LevelManage)
	store.GrantVault("v-c", "bob", LevelEdit)

	got, err := store.VaultsForUser("alice")
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 2 || got[0] != "v-a" || got[1] != "v-b" {
		t.Fatalf("expected [v-a v-b], got %v", got)
	}
	if got, _ := store.VaultsForUser("nobody"); len(got) != 0 {
		t.Fatalf("expected no vaults, got %v", got)
	}
}

func TestSupportedTypes_V2Records(t *testing.T) {
	store := newTestStore(t)
	now := time.Now().UnixMilli()
	res, err := store.PushRecords("", []SyncRecord{
		{ID: "0a1b2c3d4e5f6071", Type: "device_vault_key", UpdatedAt: now, Data: json.RawMessage(`{}`)},
		{ID: "0a1b2c3d4e5f6071", Type: "enroll_request", UpdatedAt: now, Data: json.RawMessage(`{}`)},
		{ID: "0a1b2c3d4e5f6071", Type: "device_revocation", UpdatedAt: now, Data: json.RawMessage(`{}`)},
		{ID: "team_1:0a1b2c3d4e5f6071", Type: "vault_wrap", UpdatedAt: now, Data: json.RawMessage(`{}`)},
	})
	if err != nil {
		t.Fatal(err)
	}
	if len(res.Accepted) != 4 || len(res.Rejected) != 0 {
		t.Fatalf("all v2 records should be accepted, got %+v", res)
	}
}
