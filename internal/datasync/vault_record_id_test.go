package datasync

import (
	"encoding/json"
	"testing"
	"time"
)

func TestVaultACL_WrapGateKeysOnRecordID(t *testing.T) {
	store := newTestStore(t)
	deviceOwners(store, map[string]string{"victim-dev": "victim", "intruder-dev": "intruder"})
	now := time.Now().UnixMilli()
	store.GrantVault("v1", "manager", LevelManage)
	store.GrantVault("v1", "victim", LevelView)

	wrap := func(vaultField string, updatedAt int64) SyncRecord {
		return SyncRecord{
			ID: "v1:victim-dev", Type: "vault_wrap", SchemaVersion: 1, UpdatedAt: updatedAt,
			DeviceID: "intruder-dev", VaultID: vaultField,
			Data:        json.RawMessage(`{"recipient_device":"victim-dev"}`),
			Credentials: "forged",
		}
	}

	res, err := store.PushRecords("intruder", []SyncRecord{wrap("", now)})
	if err != nil || len(res.Rejected) != 1 {
		t.Fatalf("forged wrap with empty vault_id must be rejected: %v %+v", err, res)
	}
	store.GrantVault("other", "intruder", LevelManage)
	res, _ = store.PushRecords("intruder", []SyncRecord{wrap("other", now)})
	if len(res.Rejected) != 1 {
		t.Fatalf("wrap whose vault_id contradicts its id must be rejected: %+v", res)
	}
	if recs, _ := store.PullRecords("victim", []string{"v1:victim-dev"}); len(recs) != 0 {
		t.Fatalf("victim must not receive a forged wrap: %+v", recs)
	}

	res, _ = store.PushRecords("manager", []SyncRecord{{
		ID: "v1:victim-dev", Type: "vault_wrap", SchemaVersion: 1, UpdatedAt: now,
		DeviceID: "mgr-dev", VaultID: "",
		Data: json.RawMessage(`{"recipient_device":"victim-dev"}`), Credentials: "sealed",
	}})
	if len(res.Accepted) != 1 {
		t.Fatalf("manager wrap must be accepted: %+v", res)
	}
	recs, _ := store.PullRecords("manager", []string{"v1:victim-dev"})
	if len(recs) != 1 || recs[0].VaultID != "v1" {
		t.Fatalf("stored vault_id must be derived from the id, got %+v", recs)
	}
	if recs, _ := store.PullRecords("victim", []string{"v1:victim-dev"}); len(recs) != 1 {
		t.Fatal("recipient must see the legitimate wrap")
	}

	meta := SyncRecord{ID: "v1", Type: "vault_meta", SchemaVersion: 1, UpdatedAt: now,
		DeviceID: "intruder-dev", Data: json.RawMessage(`{"_enc":"x"}`)}
	if res, _ := store.PushRecords("intruder", []SyncRecord{meta}); len(res.Rejected) != 1 {
		t.Fatalf("meta from a non-manager must be rejected: %+v", res)
	}
	meta.DeviceID = "mgr-dev"
	if res, _ := store.PushRecords("manager", []SyncRecord{meta}); len(res.Accepted) != 1 {
		t.Fatalf("meta from a manager must be accepted: %+v", res)
	}

	for _, id := range []string{"nocolon", ":dev", "v1:"} {
		res, _ := store.PushRecords("manager", []SyncRecord{{
			ID: id, Type: "vault_wrap", SchemaVersion: 1, UpdatedAt: now, DeviceID: "mgr-dev",
			Data: json.RawMessage(`{}`),
		}})
		if len(res.Rejected) != 1 {
			t.Fatalf("wrap id %q must be rejected: %+v", id, res)
		}
	}
}

func TestVaultACL_PersonalWrapKeepsPersonalScope(t *testing.T) {
	store := newTestStore(t)
	deviceOwners(store, map[string]string{"dev-a": "alice"})
	now := time.Now().UnixMilli()

	res, err := store.PushRecords("alice", []SyncRecord{{
		ID: PersonalVaultID + ":dev-a", Type: "vault_wrap", SchemaVersion: 1, UpdatedAt: now,
		DeviceID: "dev-a", VaultID: "", Data: json.RawMessage(`{"recipient_device":"dev-a"}`),
	}})
	if err != nil || len(res.Accepted) != 1 {
		t.Fatalf("personal wrap: %v %+v", err, res)
	}
	recs, _ := store.PullRecords("alice", []string{PersonalVaultID + ":dev-a"})
	if len(recs) != 1 || recs[0].VaultID != "" {
		t.Fatalf("personal wrap must stay in the personal scope, got %+v", recs)
	}
	res, _ = store.PushRecords("alice", []SyncRecord{{
		ID: PersonalVaultID + ":dev-a", Type: "vault_wrap", SchemaVersion: 1, UpdatedAt: now + 1,
		DeviceID: "dev-a", VaultID: "team_x", Data: json.RawMessage(`{"recipient_device":"dev-a"}`),
	}})
	if len(res.Rejected) != 1 {
		t.Fatalf("personal id with a team vault_id must be rejected: %+v", res)
	}
}
