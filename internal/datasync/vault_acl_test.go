package datasync

import (
	"encoding/json"
	"errors"
	"testing"
	"time"
)

func TestVaultACL_GrantRevokeLevels(t *testing.T) {
	store := newTestStore(t)

	if got := store.VaultLevel("alice", "v1"); got != LevelNone {
		t.Fatalf("expected none before grant, got %s", LevelString(got))
	}

	if err := store.GrantVault("v1", "alice", LevelView); err != nil {
		t.Fatal(err)
	}
	if got := store.VaultLevel("alice", "v1"); got != LevelView {
		t.Fatalf("expected view, got %s", LevelString(got))
	}

	if err := store.GrantVault("v1", "alice", LevelEdit); err != nil {
		t.Fatal(err)
	}
	if got := store.VaultLevel("alice", "v1"); got != LevelEdit {
		t.Fatalf("expected edit after upsert, got %s", LevelString(got))
	}

	if got := store.VaultLevel("alice", "v2"); got != LevelNone {
		t.Fatalf("expected none on other vault, got %s", LevelString(got))
	}

	if err := store.RevokeVault("v1", "alice"); err != nil {
		t.Fatal(err)
	}
	if got := store.VaultLevel("alice", "v1"); got != LevelNone {
		t.Fatalf("expected none after revoke, got %s", LevelString(got))
	}
}

func TestVaultACL_MembersAndExists(t *testing.T) {
	store := newTestStore(t)

	if store.VaultExists("v1") {
		t.Fatal("vault must not exist before any grant")
	}

	store.GrantVault("v1", "bob", LevelManage)
	store.GrantVault("v1", "alice", LevelView)

	if !store.VaultExists("v1") {
		t.Fatal("vault must exist after grants")
	}

	members, err := store.VaultMembers("v1")
	if err != nil {
		t.Fatal(err)
	}
	if len(members) != 2 || members[0].UserID != "alice" || members[0].Level != "view" ||
		members[1].UserID != "bob" || members[1].Level != "manage" {
		t.Fatalf("unexpected members: %+v", members)
	}

	store.RevokeVault("v1", "alice")
	members, _ = store.VaultMembers("v1")
	if len(members) != 1 || members[0].UserID != "bob" {
		t.Fatalf("expected only bob after revoke, got %+v", members)
	}
}

func TestVaultACL_AdminOverride(t *testing.T) {
	store := newTestStore(t)
	store.VaultAdminOverride = func(userID string) bool { return userID == "owner" }

	if got := store.VaultLevel("owner", "never-granted"); got != LevelManage {
		t.Fatalf("override must grant manage everywhere, got %s", LevelString(got))
	}
	if got := store.VaultLevel("member", "never-granted"); got != LevelNone {
		t.Fatalf("non-owner must not be elevated, got %s", LevelString(got))
	}
}

func TestVaultACL_TeamVaultVisibility(t *testing.T) {
	store := newTestStore(t)
	now := time.Now().UnixMilli()

	store.GrantVault("v1", "editor", LevelEdit)
	store.GrantVault("v1", "viewer", LevelView)

	res, err := store.PushRecords("editor", []SyncRecord{{
		ID: "sec-1", Type: "secret_item", SchemaVersion: 1, UpdatedAt: now,
		DeviceID: "dev-e", VaultID: "v1", Data: json.RawMessage(`{}`),
	}})
	if err != nil || len(res.Accepted) != 1 {
		t.Fatalf("editor push: %v %+v", err, res)
	}

	res, _ = store.PushRecords("viewer", []SyncRecord{{
		ID: "sec-2", Type: "secret_item", SchemaVersion: 1, UpdatedAt: now,
		DeviceID: "dev-v", VaultID: "v1", Data: json.RawMessage(`{}`),
	}})
	if len(res.Rejected) != 1 {
		t.Fatalf("viewer write must be rejected: %+v", res)
	}

	sees := func(userID string) bool {
		m, err := store.GetManifest(userID)
		if err != nil {
			t.Fatal(err)
		}
		inManifest := false
		for _, e := range m.Records {
			if e.ID == "sec-1" {
				inManifest = true
			}
		}
		recs, err := store.PullRecords(userID, []string{"sec-1"})
		if err != nil {
			t.Fatal(err)
		}
		if inManifest != (len(recs) == 1) {
			t.Fatalf("manifest and pull disagree for %q", userID)
		}
		return inManifest
	}
	if !sees("viewer") {
		t.Fatal("viewer must see team-vault record")
	}
	if !sees("editor") {
		t.Fatal("editor must see team-vault record")
	}
	if sees("outsider") {
		t.Fatal("non-member must not see team-vault record")
	}
}

func TestVaultACL_RevokeKeepsWrapRecipient(t *testing.T) {
	store := newTestStore(t)
	deviceOwners(store, map[string]string{"mem-dev": "member"})
	now := time.Now().UnixMilli()

	store.GrantVault("v1", "manager", LevelManage)
	store.GrantVault("v1", "member", LevelView)

	res, err := store.PushRecords("manager", []SyncRecord{{
		ID: "v1:mem-dev", Type: "vault_wrap", SchemaVersion: 1, UpdatedAt: now,
		DeviceID: "dev-m", VaultID: "v1",
		Data:        json.RawMessage(`{"recipient_device":"mem-dev"}`),
		Credentials: "sealed-key-blob",
	}})
	if err != nil || len(res.Accepted) != 1 {
		t.Fatalf("wrap push: %v %+v", err, res)
	}

	recs, _ := store.PullRecords("member", []string{"v1:mem-dev"})
	if len(recs) != 1 {
		t.Fatal("recipient must see their wrap")
	}

	if err := store.RevokeVault("v1", "member"); err != nil {
		t.Fatal(err)
	}
	if got := store.VaultLevel("member", "v1"); got != LevelNone {
		t.Fatalf("expected none after revoke, got %s", LevelString(got))
	}

	recs, err = store.PullRecords("member", []string{"v1:mem-dev"})
	if err != nil || len(recs) != 1 {
		t.Fatalf("revoked member must still see the wrap tombstone: %v (%d records)", err, len(recs))
	}
	tomb := recs[0]
	if !tomb.Deleted {
		t.Fatal("wrap must be tombstoned")
	}
	if tomb.Credentials != "" {
		t.Fatal("sealed key material must be wiped")
	}
	if wrapRecipientDevice(tomb.Data) != "mem-dev" {
		t.Fatalf("recipient_device must survive in the tombstone, got %s", tomb.Data)
	}
}

func TestVaultACL_CreateAndLastManagerGuards(t *testing.T) {
	store := newTestStore(t)

	created, err := store.CreateVault("infra", "alice")
	if err != nil || !created {
		t.Fatalf("first create: created=%v err=%v", created, err)
	}
	if store.VaultLevel("alice", "infra") != LevelManage {
		t.Fatal("creator must hold manage")
	}
	for _, who := range []string{"alice", "bob"} {
		created, err = store.CreateVault("infra", who)
		if err != nil || created {
			t.Fatalf("re-create by %s: created=%v err=%v", who, created, err)
		}
	}
	if store.VaultLevel("bob", "infra") != LevelNone {
		t.Fatal("a failed create must not grant anything")
	}

	if err := store.GrantVaultGuarded("infra", "alice", LevelEdit); !errors.Is(err, ErrLastManager) {
		t.Fatalf("demote sole manager: got %v", err)
	}
	if err := store.RevokeVaultGuarded("infra", "alice"); !errors.Is(err, ErrLastManager) {
		t.Fatalf("revoke sole manager: got %v", err)
	}
	if store.VaultLevel("alice", "infra") != LevelManage {
		t.Fatal("refused changes must not apply")
	}
	if err := store.GrantVaultGuarded("infra", "bob", LevelView); err != nil {
		t.Fatal(err)
	}
	if err := store.RevokeVaultGuarded("infra", "bob"); err != nil {
		t.Fatal(err)
	}
	if err := store.GrantVaultGuarded("infra", "carol", LevelManage); err != nil {
		t.Fatal(err)
	}
	if err := store.GrantVaultGuarded("infra", "alice", LevelView); err != nil {
		t.Fatal(err)
	}
	if err := store.RevokeVaultGuarded("infra", "carol"); !errors.Is(err, ErrLastManager) {
		t.Fatalf("revoke new sole manager: got %v", err)
	}
	if err := store.RevokeVault("infra", "carol"); err != nil {
		t.Fatalf("unguarded cascade revoke: %v", err)
	}
	if store.VaultLevel("carol", "infra") != LevelNone {
		t.Fatal("cascade revoke must apply")
	}
}
