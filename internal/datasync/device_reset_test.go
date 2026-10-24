package datasync

import (
	"encoding/json"
	"testing"
	"time"
)

func personalWrap(deviceID string, updatedAt int64) SyncRecord {
	data, _ := json.Marshal(map[string]string{"recipient_device": deviceID})
	return SyncRecord{
		ID: "personal:" + deviceID, Type: "vault_wrap", UpdatedAt: updatedAt,
		DeviceID: deviceID, Data: json.RawMessage(data), Credentials: "sealed",
	}
}

func existingIDs(t *testing.T, store *SyncStore, recType string) map[string]bool {
	t.Helper()
	recs, err := store.RecordsByType(recType)
	if err != nil {
		t.Fatal(err)
	}
	out := map[string]bool{}
	for _, r := range recs {
		out[r.ID] = true
	}
	return out
}

func TestResetDeviceKeyRecords_ClearsOnlyTheDevicesKeyRecords(t *testing.T) {
	store := newTestStore(t)
	deviceOwners(store, map[string]string{"dd11": "alice", "ee22": "alice"})
	store.GrantVault("team_1", "alice", LevelManage)
	now := time.Now().UnixMilli()

	if _, err := store.PushRecords("alice", []SyncRecord{
		deviceWrap("team_1", "dd11", now),
		deviceWrap("team_1", "ee22", now),
		personalWrap("dd11", now),
		personalWrap("ee22", now),
		{ID: "dd11", Type: "device_vault_key", UpdatedAt: now, DeviceID: "dd11",
			Data: json.RawMessage(`{"dvk_pub":"P"}`)},
		{ID: "dd11", Type: "enroll_request", UpdatedAt: now, DeviceID: "dd11",
			Data: json.RawMessage(`{}`)},
		{ID: "ee22", Type: "device_vault_key", UpdatedAt: now, DeviceID: "ee22",
			Data: json.RawMessage(`{"dvk_pub":"Q"}`)},
		{ID: "dd11", Type: "device_revocation", UpdatedAt: now, DeviceID: "ee22",
			Data: json.RawMessage(`{"revoked_at":1}`)},
		{ID: "task-1", Type: "task", UpdatedAt: now, DeviceID: "dd11",
			Data: json.RawMessage(`{}`)},
	}); err != nil {
		t.Fatal(err)
	}
	if _, err := store.db.Exec(`INSERT INTO sync_records (id, type, updated_at, data, user_id, vault_id)
		VALUES ('team_2:dd11', 'vault_wrap', ?, '{}', 'alice', 'team_2')`, now); err != nil {
		t.Fatal(err)
	}

	tx, err := store.db.Begin()
	if err != nil {
		t.Fatal(err)
	}
	n, err := ResetDeviceKeyRecords(tx, "dd11")
	if err != nil {
		tx.Rollback()
		t.Fatal(err)
	}
	if err := tx.Commit(); err != nil {
		t.Fatal(err)
	}
	if n != 5 {
		t.Errorf("removed %d rows, want 5 (3 wraps + device_vault_key + enroll_request)", n)
	}

	wraps := existingIDs(t, store, "vault_wrap")
	for _, gone := range []string{"team_1:dd11", "personal:dd11", "team_2:dd11"} {
		if wraps[gone] {
			t.Errorf("%s must be removed by the reset", gone)
		}
	}
	for _, kept := range []string{"team_1:ee22", "personal:ee22"} {
		if !wraps[kept] {
			t.Errorf("%s (another device's grant) must survive", kept)
		}
	}
	if existingIDs(t, store, "device_vault_key")["dd11"] {
		t.Error("the device's directory entry must be removed")
	}
	if !existingIDs(t, store, "device_vault_key")["ee22"] {
		t.Error("a sibling's directory entry must survive")
	}
	if existingIDs(t, store, "enroll_request")["dd11"] {
		t.Error("the device's enrollment request must be removed")
	}
	if !existingIDs(t, store, "device_revocation")["dd11"] {
		t.Error("device_revocation is permanent; a reset must never retract it")
	}
	if !existingIDs(t, store, "task")["task-1"] {
		t.Error("records the device wrote stay with their owner")
	}
}

func TestResetDeviceKeyRecords_NewOwnerCanRepublishDirectoryEntry(t *testing.T) {
	store := newTestStore(t)
	owners := map[string]string{"dd11": "alice"}
	deviceOwners(store, owners)
	const createdAt = 1700000000000
	dvk := SyncRecord{ID: "dd11", Type: "device_vault_key", UpdatedAt: createdAt,
		DeviceID: "dd11", Data: json.RawMessage(`{"dvk_pub":"P"}`)}
	if res, err := store.PushRecords("alice", []SyncRecord{dvk}); err != nil || len(res.Accepted) != 1 {
		t.Fatalf("alice publishes: %+v %v", res, err)
	}

	owners["dd11"] = "carol"
	res, err := store.PushRecords("carol", []SyncRecord{dvk})
	if err != nil {
		t.Fatal(err)
	}
	if len(res.Accepted) != 0 {
		t.Fatal("precondition: without a reset the previous owner's row blocks the new owner")
	}

	tx, _ := store.db.Begin()
	if _, err := ResetDeviceKeyRecords(tx, "dd11"); err != nil {
		tx.Rollback()
		t.Fatal(err)
	}
	tx.Commit()

	res, err = store.PushRecords("carol", []SyncRecord{dvk})
	if err != nil {
		t.Fatal(err)
	}
	if len(res.Accepted) != 1 {
		t.Fatalf("after the reset carol must be able to publish the entry: %+v", res)
	}
	recs, _ := store.RecordsByType("device_vault_key")
	if len(recs) != 1 || recs[0].UserID != "carol" {
		t.Fatalf("directory entry must now be carol's: %+v", recs)
	}
}

func TestDeviceWrap_RecipientRuleRequiresCurrentEntitlement(t *testing.T) {
	store := newTestStore(t)
	owners := map[string]string{"dd11": "alice"}
	deviceOwners(store, owners)
	store.GrantVault("team_a", "alice", LevelManage)
	store.GrantVault("team_b", "alice", LevelManage)
	now := time.Now().UnixMilli()
	if _, err := store.PushRecords("alice", []SyncRecord{
		deviceWrap("team_a", "dd11", now),
		deviceWrap("team_b", "dd11", now),
		personalWrap("dd11", now),
	}); err != nil {
		t.Fatal(err)
	}
	tomb := deviceWrap("team_b", "dd11", now+1)
	tomb.Deleted = true
	if _, err := store.PushRecords("alice", []SyncRecord{tomb}); err != nil {
		t.Fatal(err)
	}
	ids := []string{"team_a:dd11", "team_b:dd11", "personal:dd11"}

	if got := pulledIDs(t, store, "alice", ids...); !got["team_a:dd11"] || !got["personal:dd11"] {
		t.Fatalf("alice must see the grants to her device, got %v", got)
	}

	owners["dd11"] = "carol"
	got := pulledIDs(t, store, "carol", ids...)
	if got["team_a:dd11"] {
		t.Error("a live team grant made under alice must not reach carol (no ACL)")
	}
	if got["personal:dd11"] {
		t.Error("alice's personal-vault wrap must never reach carol's device")
	}
	if !got["team_b:dd11"] {
		t.Error("a tombstone addressed to the device must still reach its owner")
	}
	m, err := store.GetManifest("carol")
	if err != nil {
		t.Fatal(err)
	}
	for _, e := range m.Records {
		if e.ID == "team_a:dd11" || e.ID == "personal:dd11" {
			t.Errorf("manifest leaked %s to the device's new owner", e.ID)
		}
	}

	store.GrantVault("team_a", "carol", LevelView)
	if !pulledIDs(t, store, "carol", "team_a:dd11")["team_a:dd11"] {
		t.Error("with her own view grant carol is entitled to the wrap")
	}
	owners["ee22"] = "carol"
	if _, err := store.PushRecords("carol", []SyncRecord{personalWrap("ee22", now)}); err != nil {
		t.Fatal(err)
	}
	if !pulledIDs(t, store, "carol", "personal:ee22")["personal:ee22"] {
		t.Error("carol must see the personal wrap she wrote")
	}
}
