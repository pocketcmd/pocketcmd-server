package datasync

import (
	"encoding/json"
	"testing"
	"time"
)

func newTestStore(t *testing.T) *SyncStore {
	t.Helper()
	store := NewSyncStoreAt(t.TempDir())
	t.Cleanup(func() { store.Close() })
	return store
}

func TestSyncStore_PushAndPull(t *testing.T) {
	store := newTestStore(t)

	record := SyncRecord{
		ID: "task-1", Type: "task", SchemaVersion: 1,
		UpdatedAt: time.Now().UnixMilli(), DeviceID: "device-a",
		Data: json.RawMessage(`{"name":"my server","host":"192.168.1.1"}`),
	}

	result, err := store.PushRecords("", []SyncRecord{record})
	if err != nil {
		t.Fatal(err)
	}
	if len(result.Accepted) != 1 || result.Accepted[0] != "task-1" {
		t.Fatal("expected task-1 to be accepted")
	}

	records, err := store.PullRecords("", []string{"task-1"})
	if err != nil {
		t.Fatal(err)
	}
	if len(records) != 1 || records[0].ID != "task-1" {
		t.Fatalf("expected task-1, got %d records", len(records))
	}
}

func TestSyncStore_LastWriteWins(t *testing.T) {
	store := newTestStore(t)
	now := time.Now().UnixMilli()

	store.PushRecords("", []SyncRecord{{
		ID: "task-1", Type: "task", SchemaVersion: 1,
		UpdatedAt: now, DeviceID: "dev-a",
		Data: json.RawMessage(`{"name":"v1"}`),
	}})

	result, _ := store.PushRecords("", []SyncRecord{{
		ID: "task-1", Type: "task", SchemaVersion: 1,
		UpdatedAt: now + 1000, DeviceID: "dev-b",
		Data: json.RawMessage(`{"name":"v2"}`),
	}})
	if len(result.Accepted) != 1 {
		t.Fatal("newer version should be accepted")
	}

	result, _ = store.PushRecords("", []SyncRecord{{
		ID: "task-1", Type: "task", SchemaVersion: 1,
		UpdatedAt: now - 1000, DeviceID: "dev-c",
		Data: json.RawMessage(`{"name":"v0"}`),
	}})
	if len(result.Rejected) != 1 {
		t.Fatal("older version should be rejected")
	}

	records, _ := store.PullRecords("", []string{"task-1"})
	var data map[string]string
	json.Unmarshal(records[0].Data, &data)
	if data["name"] != "v2" {
		t.Fatalf("expected v2, got %s", data["name"])
	}
}

func TestSyncStore_Manifest(t *testing.T) {
	store := newTestStore(t)
	now := time.Now().UnixMilli()

	store.PushRecords("", []SyncRecord{
		{ID: "task-1", Type: "task", SchemaVersion: 1, UpdatedAt: now, DeviceID: "dev-a", Data: json.RawMessage(`{}`)},
		{ID: "snip-1", Type: "snippet", SchemaVersion: 1, UpdatedAt: now, DeviceID: "dev-a", Data: json.RawMessage(`{}`)},
	})

	manifest, err := store.GetManifest("")
	if err != nil {
		t.Fatal(err)
	}
	if len(manifest.Records) != 2 {
		t.Fatalf("expected 2 records, got %d", len(manifest.Records))
	}
}

func TestSyncStore_Tombstone(t *testing.T) {
	store := newTestStore(t)
	now := time.Now().UnixMilli()

	store.PushRecords("", []SyncRecord{
		{ID: "task-1", Type: "task", SchemaVersion: 1, UpdatedAt: now, DeviceID: "dev-a", Data: json.RawMessage(`{}`)},
	})
	store.PushRecords("", []SyncRecord{
		{ID: "task-1", Type: "task", SchemaVersion: 1, UpdatedAt: now + 1000, DeviceID: "dev-a", Deleted: true, Data: json.RawMessage(`{}`)},
	})

	manifest, _ := store.GetManifest("")
	for _, r := range manifest.Records {
		if r.ID == "task-1" && !r.Deleted {
			t.Fatal("expected deleted flag")
		}
	}
}

func TestSyncStore_CleanupTombstones(t *testing.T) {
	store := newTestStore(t)

	oldTime := time.Now().Add(-31 * 24 * time.Hour).UnixMilli()
	store.PushRecords("", []SyncRecord{
		{ID: "task-old", Type: "task", SchemaVersion: 1, UpdatedAt: oldTime, DeviceID: "dev-a", Deleted: true, Data: json.RawMessage(`{}`)},
	})
	store.PushRecords("", []SyncRecord{
		{ID: "task-new", Type: "task", SchemaVersion: 1, UpdatedAt: time.Now().UnixMilli(), DeviceID: "dev-a", Deleted: true, Data: json.RawMessage(`{}`)},
	})

	store.CleanupTombstones(30 * 24 * time.Hour)

	manifest, _ := store.GetManifest("")
	if len(manifest.Records) != 1 {
		t.Fatalf("expected 1 record, got %d", len(manifest.Records))
	}
	if manifest.Records[0].ID != "task-new" {
		t.Fatal("expected task-new to remain")
	}
}

func TestSyncStore_PullNonexistent(t *testing.T) {
	store := newTestStore(t)
	records, err := store.PullRecords("", []string{"does-not-exist"})
	if err != nil {
		t.Fatal(err)
	}
	if len(records) != 0 {
		t.Fatal("expected empty result")
	}
}

func TestSyncStore_FutureTimestampRejected(t *testing.T) {
	store := newTestStore(t)
	farFuture := time.Now().Add(10 * time.Minute).UnixMilli()

	res, err := store.PushRecords("", []SyncRecord{
		{ID: "task-1", Type: "task", SchemaVersion: 1, UpdatedAt: farFuture, DeviceID: "dev-a", Data: json.RawMessage(`{}`)},
	})
	if err != nil {
		t.Fatal(err)
	}
	if len(res.Rejected) != 1 || res.Rejected[0].Reason != RejectFutureTimestamp {
		t.Fatalf("expected future_timestamp rejection, got %+v", res)
	}
	if records, _ := store.PullRecords("", []string{"task-1"}); len(records) != 0 {
		t.Fatalf("rejected record must not be stored, got %+v", records)
	}
}

func TestSyncStore_PushMultipleTypes(t *testing.T) {
	store := newTestStore(t)
	now := time.Now().UnixMilli()

	store.PushRecords("", []SyncRecord{
		{ID: "task-1", Type: "task", SchemaVersion: 1, UpdatedAt: now, DeviceID: "dev", Data: json.RawMessage(`{}`)},
		{ID: "key-1", Type: "ssh_key", SchemaVersion: 1, UpdatedAt: now, DeviceID: "dev", Data: json.RawMessage(`{}`)},
		{ID: "snip-1", Type: "snippet", SchemaVersion: 1, UpdatedAt: now, DeviceID: "dev", Data: json.RawMessage(`{}`)},
	})

	manifest, _ := store.GetManifest("")
	if len(manifest.Records) != 3 {
		t.Fatalf("expected 3 records, got %d", len(manifest.Records))
	}
}

func TestSyncStore_PushWithCredentials(t *testing.T) {
	store := newTestStore(t)
	now := time.Now().UnixMilli()

	store.PushRecords("", []SyncRecord{
		{ID: "task-1", Type: "task", SchemaVersion: 1, UpdatedAt: now, DeviceID: "dev",
			Data: json.RawMessage(`{"name":"test"}`), Credentials: "base64-encrypted-blob"},
	})

	records, _ := store.PullRecords("", []string{"task-1"})
	if records[0].Credentials != "base64-encrypted-blob" {
		t.Fatal("credentials should be preserved")
	}
}

func TestSyncStore_EmptyManifest(t *testing.T) {
	store := newTestStore(t)
	manifest, err := store.GetManifest("")
	if err != nil {
		t.Fatal(err)
	}
	if manifest.Version != 1 {
		t.Fatal("expected version 1")
	}
	if len(manifest.Records) != 0 {
		t.Fatal("expected empty records")
	}
}

func TestSyncStore_ManifestDBError(t *testing.T) {
	store := newTestStore(t)
	store.db.Close()
	if _, err := store.GetManifest(""); err == nil {
		t.Fatal("expected error from closed database")
	}
}

func TestSyncStore_AcceptsEveryClientRecordType(t *testing.T) {
	store := newTestStore(t)
	now := time.Now().UnixMilli()

	clientTypes := []string{
		"task", "ssh_key", "secret_item", "settings", "task_group", "task_tag",
		"sftp_bookmark", "workspace", "snippet", "snippet_folder",
		"command_template", "layout_config", "port_forward_rule",
		"alert_config", "dashboard",
	}

	records := make([]SyncRecord, 0, len(clientTypes))
	typeOfID := make(map[string]string, len(clientTypes))
	for _, typ := range clientTypes {
		id := "rec-" + typ
		typeOfID[id] = typ
		records = append(records, SyncRecord{
			ID:            id,
			Type:          typ,
			SchemaVersion: 1,
			UpdatedAt:     now,
			DeviceID:      "dev",
			Data:          json.RawMessage(`{}`),
		})
	}

	result, err := store.PushRecords("", records)
	if err != nil {
		t.Fatal(err)
	}
	for _, rej := range result.Rejected {
		t.Errorf("client record type %q rejected (id %s, reason %s)", typeOfID[rej.ID], rej.ID, rej.Reason)
	}
	if len(result.Accepted) != len(clientTypes) {
		t.Fatalf("expected %d accepted, got %d", len(clientTypes), len(result.Accepted))
	}
}

func TestSyncStore_PushUnknownType(t *testing.T) {
	store := newTestStore(t)
	now := time.Now().UnixMilli()

	result, err := store.PushRecords("", []SyncRecord{
		{ID: "x1", Type: "unknown_type", SchemaVersion: 1, UpdatedAt: now, DeviceID: "dev", Data: json.RawMessage(`{}`)},
	})
	if err != nil {
		t.Fatal(err)
	}
	if len(result.Rejected) != 1 {
		t.Fatal("unknown type should be rejected")
	}
	if len(result.Accepted) != 0 {
		t.Fatal("unknown type should not be accepted")
	}
}

func TestSyncStore_PurgeUserData_ByDevices(t *testing.T) {
	store := newTestStore(t)
	now := time.Now().UnixMilli()

	_, err := store.PushRecords("", []SyncRecord{
		{ID: "a1", Type: "task", SchemaVersion: 1, UpdatedAt: now, DeviceID: "dev-a",
			Data: json.RawMessage(`{"secret":1}`), Credentials: "cred-a"},
		{ID: "a2", Type: "snippet", SchemaVersion: 1, UpdatedAt: now, DeviceID: "dev-a",
			Data: json.RawMessage(`{"secret":2}`)},
		{ID: "b1", Type: "task", SchemaVersion: 1, UpdatedAt: now, DeviceID: "dev-b",
			Data: json.RawMessage(`{"keep":true}`)},
	})
	if err != nil {
		t.Fatal(err)
	}

	n, err := store.PurgeUserData("", []string{"dev-a", "dev-unknown"})
	if err != nil {
		t.Fatal(err)
	}
	if n != 2 {
		t.Fatalf("expected 2 purged records, got %d", n)
	}

	recs, err := store.PullRecords("", []string{"a1", "a2", "b1"})
	if err != nil || len(recs) != 3 {
		t.Fatalf("pull: %v (%d records)", err, len(recs))
	}
	for _, rec := range recs {
		if rec.DeviceID == "dev-a" {
			if !rec.Deleted || string(rec.Data) != "{}" || rec.Credentials != "" {
				t.Errorf("record %s not purged: deleted=%v data=%s creds=%q",
					rec.ID, rec.Deleted, rec.Data, rec.Credentials)
			}
			if rec.UpdatedAt < now {
				t.Errorf("record %s should have a bumped updated_at for sync propagation", rec.ID)
			}
		} else if rec.Deleted {
			t.Errorf("record %s from another device must be untouched", rec.ID)
		}
	}

	n, err = store.PurgeUserData("", []string{"dev-a"})
	if err != nil {
		t.Fatal(err)
	}
	if n != 0 {
		t.Fatalf("second purge should affect 0 records, got %d", n)
	}
}

func TestSyncStore_PurgeUserData_ByDevices_Empty(t *testing.T) {
	store := newTestStore(t)
	n, err := store.PurgeUserData("", nil)
	if err != nil || n != 0 {
		t.Fatalf("empty purge should be a no-op, got n=%d err=%v", n, err)
	}
}

func TestSyncStore_PerUserScoping(t *testing.T) {
	store := newTestStore(t)
	now := time.Now().UnixMilli()

	res, err := store.PushRecords("alice", []SyncRecord{
		{ID: "a-task", Type: "task", SchemaVersion: 1, UpdatedAt: now, DeviceID: "dev-a", Data: json.RawMessage(`{}`)},
	})
	if err != nil || len(res.Accepted) != 1 {
		t.Fatalf("alice push: %v %+v", err, res)
	}
	res, _ = store.PushRecords("bob", []SyncRecord{
		{ID: "b-task", Type: "task", SchemaVersion: 1, UpdatedAt: now, DeviceID: "dev-b", Data: json.RawMessage(`{}`)},
		{ID: "monitoring_config", Type: "monitoring_config", SchemaVersion: 1, UpdatedAt: now, DeviceID: "dev-b", Data: json.RawMessage(`{}`)},
	})
	if len(res.Accepted) != 2 {
		t.Fatalf("bob push: %+v", res)
	}
	store.PushRecords("", []SyncRecord{
		{ID: "legacy", Type: "task", SchemaVersion: 1, UpdatedAt: now, DeviceID: "dev-x", Data: json.RawMessage(`{}`)},
	})

	manifestIDs := func(userID string) map[string]bool {
		m, err := store.GetManifest(userID)
		if err != nil {
			t.Fatal(err)
		}
		ids := map[string]bool{}
		for _, e := range m.Records {
			ids[e.ID] = true
		}
		return ids
	}

	alice := manifestIDs("alice")
	if !alice["a-task"] || alice["b-task"] {
		t.Fatalf("alice manifest wrong: %v", alice)
	}
	if !alice["monitoring_config"] || alice["legacy"] {
		t.Fatalf("alice should see team-scoped but not ownerless records: %v", alice)
	}

	bob := manifestIDs("bob")
	if !bob["b-task"] || bob["a-task"] || bob["legacy"] {
		t.Fatalf("bob manifest wrong (must not see ownerless legacy): %v", bob)
	}

	all := manifestIDs("")
	if len(all) != 4 {
		t.Fatalf("unscoped caller should see all 4, got %v", all)
	}

	recs, _ := store.PullRecords("bob", []string{"a-task", "b-task", "monitoring_config", "legacy"})
	got := map[string]bool{}
	for _, r := range recs {
		got[r.ID] = true
	}
	if got["a-task"] || !got["b-task"] || !got["monitoring_config"] || got["legacy"] {
		t.Fatalf("bob pull wrong: %v", got)
	}

	aRecs, _ := store.PullRecords("alice", []string{"a-task"})
	if len(aRecs) != 1 || aRecs[0].UserID != "alice" {
		t.Fatalf("expected owner alice on a-task, got %+v", aRecs)
	}
}

func TestSyncStore_OwnershipConflictRejected(t *testing.T) {
	store := newTestStore(t)
	now := time.Now().UnixMilli()

	store.PushRecords("alice", []SyncRecord{
		{ID: "shared-id", Type: "task", SchemaVersion: 1, UpdatedAt: now, DeviceID: "dev-a", Data: json.RawMessage(`{"v":1}`)},
	})

	res, err := store.PushRecords("bob", []SyncRecord{
		{ID: "shared-id", Type: "task", SchemaVersion: 1, UpdatedAt: now + 1000, DeviceID: "dev-b", Data: json.RawMessage(`{"v":2}`)},
	})
	if err != nil {
		t.Fatal(err)
	}
	if len(res.Rejected) != 1 || len(res.Accepted) != 0 {
		t.Fatalf("cross-user overwrite must be rejected: %+v", res)
	}

	recs, _ := store.PullRecords("alice", []string{"shared-id"})
	if len(recs) != 1 || string(recs[0].Data) != `{"v":1}` {
		t.Fatalf("alice's record was modified: %+v", recs)
	}

	store.PushRecords("alice", []SyncRecord{
		{ID: "monitoring_config", Type: "monitoring_config", SchemaVersion: 1, UpdatedAt: now, DeviceID: "dev-a", Data: json.RawMessage(`{"v":1}`)},
	})
	res, _ = store.PushRecords("bob", []SyncRecord{
		{ID: "monitoring_config", Type: "monitoring_config", SchemaVersion: 1, UpdatedAt: now + 1000, DeviceID: "dev-b", Data: json.RawMessage(`{"v":2}`)},
	})
	if len(res.Accepted) != 1 {
		t.Fatalf("team-scoped overwrite must be accepted: %+v", res)
	}
}

func TestSyncStore_PurgeUserData_ByOwner(t *testing.T) {
	store := newTestStore(t)
	now := time.Now().UnixMilli()

	store.PushRecords("alice", []SyncRecord{
		{ID: "a1", Type: "task", SchemaVersion: 1, UpdatedAt: now, DeviceID: "dev-new", Data: json.RawMessage(`{"secret":1}`)},
	})
	store.PushRecords("", []SyncRecord{
		{ID: "a2", Type: "task", SchemaVersion: 1, UpdatedAt: now, DeviceID: "dev-old", Data: json.RawMessage(`{"secret":2}`)},
	})
	store.PushRecords("bob", []SyncRecord{
		{ID: "b1", Type: "task", SchemaVersion: 1, UpdatedAt: now, DeviceID: "dev-bob", Data: json.RawMessage(`{"keep":true}`)},
	})

	n, err := store.PurgeUserData("alice", []string{"dev-old"})
	if err != nil {
		t.Fatal(err)
	}
	if n != 2 {
		t.Fatalf("expected 2 purged, got %d", n)
	}

	recs, _ := store.PullRecords("", []string{"a1", "a2", "b1"})
	for _, rec := range recs {
		switch rec.ID {
		case "a1", "a2":
			if !rec.Deleted || string(rec.Data) != "{}" {
				t.Fatalf("record %s not purged: %+v", rec.ID, rec)
			}
		case "b1":
			if rec.Deleted {
				t.Fatal("bob's record must survive")
			}
		}
	}
}

func TestSyncStore_PurgeUserData_ReusedDeviceKeepsPreviousOwner(t *testing.T) {
	store := newTestStore(t)
	now := time.Now().UnixMilli()

	store.PushRecords("alice", []SyncRecord{
		{ID: "a1", Type: "task", SchemaVersion: 1, UpdatedAt: now, DeviceID: "dev-shared", Data: json.RawMessage(`{"alice":1}`)},
	})
	store.PushRecords("bob", []SyncRecord{
		{ID: "b1", Type: "task", SchemaVersion: 1, UpdatedAt: now, DeviceID: "dev-shared", Data: json.RawMessage(`{"bob":1}`)},
	})
	store.PushRecords("", []SyncRecord{
		{ID: "o1", Type: "task", SchemaVersion: 1, UpdatedAt: now, DeviceID: "dev-shared", Data: json.RawMessage(`{"ownerless":1}`)},
	})

	n, err := store.PurgeUserData("bob", []string{"dev-shared"})
	if err != nil {
		t.Fatal(err)
	}
	if n != 2 {
		t.Fatalf("expected bob's row + the ownerless row (2), got %d", n)
	}

	recs, _ := store.PullRecords("", []string{"a1", "b1", "o1"})
	for _, rec := range recs {
		switch rec.ID {
		case "a1":
			if rec.Deleted || string(rec.Data) != `{"alice":1}` {
				t.Fatalf("alice's record purged through a reused device id: %+v", rec)
			}
		case "b1", "o1":
			if !rec.Deleted || string(rec.Data) != "{}" {
				t.Fatalf("record %s not purged: %+v", rec.ID, rec)
			}
		}
	}
}

func TestSyncStore_VaultMove_TombstoneThenRecreate(t *testing.T) {
	store := newTestStore(t)

	base := time.Now().UnixMilli()
	live := SyncRecord{
		ID: "task-1", Type: "task", SchemaVersion: 1,
		UpdatedAt: base, DeviceID: "device-a",
		Data: json.RawMessage(`{"name":"prod"}`),
	}
	if res, err := store.PushRecords("", []SyncRecord{live}); err != nil || len(res.Accepted) != 1 {
		t.Fatalf("seed push: %v %+v", err, res)
	}

	moved := live
	moved.UpdatedAt = base + 1
	moved.VaultID = "vteam1"
	res, err := store.PushRecords("", []SyncRecord{moved})
	if err != nil {
		t.Fatal(err)
	}
	if len(res.Rejected) != 1 {
		t.Fatalf("expected in-place vault change rejected, got %+v", res)
	}

	tomb := live
	tomb.UpdatedAt = base + 2
	tomb.Deleted = true
	if res, err = store.PushRecords("", []SyncRecord{tomb}); err != nil || len(res.Accepted) != 1 {
		t.Fatalf("tombstone push: %v %+v", err, res)
	}

	recreate := live
	recreate.UpdatedAt = base + 3
	recreate.VaultID = "vteam1"
	if res, err = store.PushRecords("", []SyncRecord{recreate}); err != nil || len(res.Accepted) != 1 {
		t.Fatalf("recreate push: %v %+v", err, res)
	}

	records, err := store.PullRecords("", []string{"task-1"})
	if err != nil || len(records) != 1 {
		t.Fatalf("pull: %v (%d records)", err, len(records))
	}
	if records[0].VaultID != "vteam1" || records[0].Deleted {
		t.Fatalf("expected live record in vteam1, got %+v", records[0])
	}
}

func TestSyncStore_PushRejectionReasons(t *testing.T) {
	store := newTestStore(t)
	now := time.Now().UnixMilli()

	res, err := store.PushRecords("u1", []SyncRecord{
		{ID: "bad id", Type: "task", UpdatedAt: now, Data: json.RawMessage(`{}`)},
		{ID: "t1", Type: "nope", UpdatedAt: now, Data: json.RawMessage(`{}`)},
		{ID: "t2", Type: "task", UpdatedAt: now + MaxClockSkew.Milliseconds() + 1000, Data: json.RawMessage(`{}`)},
		{ID: "t3", Type: "task", UpdatedAt: now + MaxClockSkew.Milliseconds() - 1000, Data: json.RawMessage(`{}`)},
	})
	if err != nil {
		t.Fatal(err)
	}
	want := map[string]string{
		"bad id": RejectInvalidIDOrType,
		"t1":     RejectInvalidIDOrType,
		"t2":     RejectFutureTimestamp,
	}
	if len(res.Rejected) != len(want) {
		t.Fatalf("expected %d rejections, got %+v", len(want), res.Rejected)
	}
	for _, rej := range res.Rejected {
		if want[rej.ID] != rej.Reason {
			t.Errorf("record %s: reason %q, want %q", rej.ID, rej.Reason, want[rej.ID])
		}
	}
	if len(res.Accepted) != 1 || res.Accepted[0] != "t3" {
		t.Fatalf("a stamp inside the skew window must be accepted, got %+v", res.Accepted)
	}

	res, err = store.PushRecords("u1", []SyncRecord{
		{ID: "t3", Type: "task", UpdatedAt: now - 1, Data: json.RawMessage(`{}`)},
	})
	if err != nil {
		t.Fatal(err)
	}
	if len(res.Rejected) != 1 || res.Rejected[0].Reason != RejectSuperseded || !TransientRejectReasons[res.Rejected[0].Reason] {
		t.Fatalf("expected transient superseded rejection, got %+v", res.Rejected)
	}

	res, err = store.PushRecords("u1", nil)
	if err != nil {
		t.Fatal(err)
	}
	if res.Accepted == nil || res.Rejected == nil {
		t.Fatalf("accepted/rejected must be non-nil slices, got %+v", res)
	}
}
