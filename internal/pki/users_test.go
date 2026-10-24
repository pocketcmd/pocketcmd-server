package pki

import (
	"errors"
	"testing"

	"github.com/pocketcmd/pocketcmd-server/internal/state"
)

func TestUserRegistry_CreateAndList(t *testing.T) {
	reg := NewUserRegistry(testStateDB(t))
	u, err := reg.Create("Alice", "admin", "")
	if err != nil {
		t.Fatalf("create: %v", err)
	}
	if u.Role != "admin" || u.Status != "active" || u.DisplayName != "Alice" {
		t.Fatalf("bad user: %+v", u)
	}
	if u.UserID == "" || len(u.UserID) != 12 {
		t.Fatalf("want 12-char user_id, got %q", u.UserID)
	}
	all, err := reg.List()
	if err != nil {
		t.Fatalf("list: %v", err)
	}
	if len(all) != 1 || all[0].UserID != u.UserID {
		t.Fatalf("list mismatch")
	}
}

func TestUserRegistry_FindByIDAndName(t *testing.T) {
	reg := NewUserRegistry(testStateDB(t))
	u, _ := reg.Create("Bob", "member", "")
	got, err := reg.FindByID(u.UserID)
	if err != nil || got == nil || got.UserID != u.UserID {
		t.Fatalf("FindByID")
	}
	got, err = reg.FindByDisplayName("bob")
	if err != nil || got == nil || got.UserID != u.UserID {
		t.Fatalf("FindByDisplayName")
	}
}

func TestUserRegistry_DuplicateDisplayNameAllowed(t *testing.T) {
	reg := NewUserRegistry(testStateDB(t))
	_, _ = reg.Create("Bob", "member", "")
	_, err := reg.Create("Bob", "member", "")
	if err != nil {
		t.Fatalf("duplicate display names must be allowed: %v", err)
	}
}

func TestUserRegistry_SetRoleAndRevoke(t *testing.T) {
	reg := NewUserRegistry(testStateDB(t))
	u, _ := reg.Create("Alice", "member", "")
	if err := reg.SetRole(u.UserID, "admin"); err != nil {
		t.Fatalf("SetRole: %v", err)
	}
	got, _ := reg.FindByID(u.UserID)
	if got.Role != "admin" {
		t.Fatalf("want admin, got %s", got.Role)
	}
	if err := reg.Revoke(u.UserID); err != nil {
		t.Fatalf("Revoke: %v", err)
	}
	got, _ = reg.FindByID(u.UserID)
	if got.Status != "revoked" || got.RevokedAt == "" {
		t.Fatalf("revoke didn't stick: %+v", got)
	}
}

func TestUserRegistry_SetRoleGuarded_RefusesLastAdmin(t *testing.T) {
	reg := NewUserRegistry(testStateDB(t))
	solo, _ := reg.Create("Solo", "admin", "")
	_, _ = reg.Create("Member", "member", "")

	applied, err := reg.SetRoleGuarded(solo.UserID, "member")
	if err != nil {
		t.Fatalf("SetRoleGuarded: %v", err)
	}
	if applied {
		t.Fatal("demoting the last active admin must not apply")
	}
	got, _ := reg.FindByID(solo.UserID)
	if got.Role != "admin" {
		t.Fatalf("role changed despite guard: %s", got.Role)
	}

	_, _ = reg.Create("Second", "admin", "")
	applied, err = reg.SetRoleGuarded(solo.UserID, "member")
	if err != nil || !applied {
		t.Fatalf("demotion with a second admin must apply: applied=%v err=%v", applied, err)
	}

	if applied, err := reg.SetRoleGuarded(solo.UserID, "admin"); err != nil || !applied {
		t.Fatalf("promotion must apply: applied=%v err=%v", applied, err)
	}
	if _, err := reg.SetRoleGuarded("nope", "member"); err == nil {
		t.Fatal("unknown user must error")
	}
}

func TestUserRegistry_RevokeGuarded_RefusesLastAdmin(t *testing.T) {
	reg := NewUserRegistry(testStateDB(t))
	solo, _ := reg.Create("Solo", "admin", "")
	member, _ := reg.Create("Member", "member", "")

	applied, err := reg.RevokeGuarded(solo.UserID)
	if err != nil {
		t.Fatalf("RevokeGuarded: %v", err)
	}
	if applied {
		t.Fatal("revoking the last active admin must not apply")
	}
	got, _ := reg.FindByID(solo.UserID)
	if got.Status != "active" {
		t.Fatalf("status changed despite guard: %s", got.Status)
	}

	if applied, err := reg.RevokeGuarded(member.UserID); err != nil || !applied {
		t.Fatalf("member revoke must apply: applied=%v err=%v", applied, err)
	}
	if applied, err := reg.RevokeGuarded(member.UserID); err != nil || !applied {
		t.Fatalf("re-revoke must be an idempotent success: applied=%v err=%v", applied, err)
	}
	if _, err := reg.RevokeGuarded("nope"); err == nil {
		t.Fatal("unknown user must error")
	}

	_, _ = reg.Create("Second", "admin", "")
	if applied, err := reg.RevokeGuarded(solo.UserID); err != nil || !applied {
		t.Fatalf("revoke with a second admin must apply: applied=%v err=%v", applied, err)
	}
}

func TestUserRegistry_CountAdmins(t *testing.T) {
	reg := NewUserRegistry(testStateDB(t))
	_, _ = reg.Create("A", "admin", "")
	_, _ = reg.Create("B", "admin", "")
	_, _ = reg.Create("C", "member", "")
	n, err := reg.CountActiveAdmins()
	if err != nil || n != 2 {
		t.Fatalf("want 2 admins, got %d (err=%v)", n, err)
	}
}

func TestUserRegistry_Persistence(t *testing.T) {
	dir := t.TempDir()
	db1, err := state.Open(dir)
	if err != nil {
		t.Fatal(err)
	}
	defer db1.Close()
	u, _ := NewUserRegistry(db1).Create("Alice", "admin", "")

	db2, err := state.Open(dir)
	if err != nil {
		t.Fatal(err)
	}
	defer db2.Close()
	got, _ := NewUserRegistry(db2).FindByID(u.UserID)
	if got == nil || got.DisplayName != "Alice" {
		t.Fatalf("persistence failed")
	}
}

func TestUserRegistry_TransferOwnership(t *testing.T) {
	r := NewUserRegistry(testStateDB(t))
	owner, _ := r.Create("alice", "admin", "")
	if err := r.SetOwner(owner.UserID, true); err != nil {
		t.Fatal(err)
	}
	member, _ := r.Create("bob", "member", "")
	revoked, _ := r.Create("carol", "member", "")
	if err := r.Revoke(revoked.UserID); err != nil {
		t.Fatal(err)
	}

	if err := r.TransferOwnership(owner.UserID, owner.UserID); !errors.Is(err, ErrSelfTransfer) {
		t.Fatalf("self transfer: got %v", err)
	}
	if err := r.TransferOwnership(owner.UserID, "nope"); !errors.Is(err, ErrUserNotFound) {
		t.Fatalf("unknown target: got %v", err)
	}
	if err := r.TransferOwnership(owner.UserID, revoked.UserID); !errors.Is(err, ErrUserNotActive) {
		t.Fatalf("revoked target: got %v", err)
	}
	if err := r.TransferOwnership(member.UserID, owner.UserID); !errors.Is(err, ErrNotOwner) {
		t.Fatalf("non-owner source: got %v", err)
	}

	if err := r.TransferOwnership(owner.UserID, member.UserID); err != nil {
		t.Fatal(err)
	}
	newOwner, _ := r.FindByID(member.UserID)
	if !newOwner.Owner || newOwner.Role != "admin" {
		t.Fatalf("target must be owner+admin, got %+v", newOwner)
	}
	old, _ := r.FindByID(owner.UserID)
	if old.Owner || old.Role != "admin" {
		t.Fatalf("previous owner must stay admin without the flag, got %+v", old)
	}
	owners := 0
	all, _ := r.List()
	for _, u := range all {
		if u.Owner {
			owners++
		}
	}
	if owners != 1 {
		t.Fatalf("expected exactly one owner, got %d", owners)
	}
	if err := r.TransferOwnership(owner.UserID, member.UserID); !errors.Is(err, ErrNotOwner) {
		t.Fatalf("stale owner: got %v", err)
	}
}

func TestUserRegistry_SetPermissionsGuarded_RefusesStaleSnapshot(t *testing.T) {
	reg := NewUserRegistry(testStateDB(t))
	u, err := reg.Create("Bob", "member", "")
	if err != nil {
		t.Fatal(err)
	}
	a, _ := reg.FindByID(u.UserID)
	b, _ := reg.FindByID(u.UserID)

	applied, err := reg.SetPermissionsGuarded(a, PermissionSet{"metrics.commands.create": {Granted: true}})
	if err != nil || !applied {
		t.Fatalf("first guarded write: applied=%v err=%v", applied, err)
	}
	applied, err = reg.SetPermissionsGuarded(b, PermissionSet{"invites.manage": {Granted: true}})
	if err != nil {
		t.Fatalf("second guarded write: %v", err)
	}
	if applied {
		t.Fatal("a stale snapshot must not overwrite the first write")
	}
	got, _ := reg.FindByID(u.UserID)
	if !got.Permissions["metrics.commands.create"].Granted || got.Permissions["invites.manage"].Granted {
		t.Fatalf("stored set after the refused write: %+v", got.Permissions)
	}

	b, _ = reg.FindByID(u.UserID)
	if applied, err := reg.SetPermissionsGuarded(b, nil); err != nil || !applied {
		t.Fatalf("fresh snapshot: applied=%v err=%v", applied, err)
	}
	synthetic := &UserRecord{UserID: u.UserID}
	if applied, err := reg.SetPermissionsGuarded(synthetic, PermissionSet{"alerts.read": {Granted: true}}); err != nil || !applied {
		t.Fatalf("synthetic empty record against '{}': applied=%v err=%v", applied, err)
	}
	if _, err := reg.SetPermissionsGuarded(&UserRecord{UserID: "nobody"}, nil); err == nil {
		t.Fatal("unknown user should be an error, not a stale snapshot")
	}
}

func TestUserRegistry_Guarded_RefuseOwner(t *testing.T) {
	reg := NewUserRegistry(testStateDB(t))
	owner, _ := reg.Create("Owner", "admin", "")
	_, _ = reg.Create("Second", "admin", "")
	if err := reg.SetOwner(owner.UserID, true); err != nil {
		t.Fatal(err)
	}
	if applied, err := reg.SetRoleGuarded(owner.UserID, "member"); applied || !errors.Is(err, ErrOwnerImmutable) {
		t.Fatalf("demoting the owner: applied=%v err=%v", applied, err)
	}
	if applied, err := reg.RevokeGuarded(owner.UserID); applied || !errors.Is(err, ErrOwnerImmutable) {
		t.Fatalf("revoking the owner: applied=%v err=%v", applied, err)
	}
	got, _ := reg.FindByID(owner.UserID)
	if got.Role != "admin" || got.Status != "active" {
		t.Fatalf("owner row changed: %+v", got)
	}
}
