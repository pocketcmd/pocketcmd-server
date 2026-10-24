package main

import (
	"bytes"
	"database/sql"
	"encoding/json"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/pocketcmd/pocketcmd-server/internal/config"
	"github.com/pocketcmd/pocketcmd-server/internal/datasync"
	"github.com/pocketcmd/pocketcmd-server/internal/monitoring"
	"github.com/pocketcmd/pocketcmd-server/internal/pki"
	"github.com/pocketcmd/pocketcmd-server/internal/testutil"
)

func testStateDB(t *testing.T) *sql.DB {
	t.Helper()
	db, err := stateDB()
	if err != nil {
		t.Fatal(err)
	}
	return db
}

func runCLI(t *testing.T, args ...string) (stdout, stderr bytes.Buffer, err error) {
	t.Helper()
	root := newRootCmd()
	root.SetArgs(args)
	root.SetOut(&stdout)
	root.SetErr(&stderr)
	root.SilenceErrors = true
	err = root.Execute()
	return
}

func seedOwner(t *testing.T) *pki.UserRecord {
	t.Helper()
	users := pki.NewUserRegistry(testStateDB(t))
	owner, err := users.Create("owner", "admin", "")
	if err != nil {
		t.Fatal(err)
	}
	if err := users.SetOwner(owner.UserID, true); err != nil {
		t.Fatal(err)
	}
	return owner
}

func TestInviteCommand_RefusesWithoutOwner(t *testing.T) {
	testutil.TempHome(t)
	os.MkdirAll(config.TLSDir(), 0700)
	if _, err := pki.NewUserRegistry(testStateDB(t)).Create("admin", "admin", ""); err != nil {
		t.Fatal(err)
	}
	_, _, err := runCLI(t, "invite")
	if err == nil || !strings.Contains(err.Error(), "no owner yet") {
		t.Fatalf("expected the no-owner refusal, got %v", err)
	}
	if active, _ := pki.NewInviteStore(testStateDB(t)).ListActive(); len(active) != 0 {
		t.Fatal("no invite may be created without an owner")
	}
}

func TestInviteCommand_CreatesAndWritesStore(t *testing.T) {
	testutil.TempHome(t)
	os.MkdirAll(config.TLSDir(), 0700)
	seedOwner(t)

	stdout, _, err := runCLI(t, "invite", "--role", "member", "--expires", "1h")
	if err != nil {
		t.Fatalf("invite command failed: %v", err)
	}

	out := stdout.String()
	if !strings.Contains(out, "Invite code:") {
		t.Fatalf("expected 'Invite code:' in output, got: %q", out)
	}

	var code string
	for _, line := range strings.Split(out, "\n") {
		if strings.HasPrefix(line, "Invite code:") {
			code = strings.TrimSpace(strings.TrimPrefix(line, "Invite code:"))
			break
		}
	}
	if len(code) != 16 {
		t.Fatalf("expected 16-char invite code, got %q (len=%d)", code, len(code))
	}

	if !strings.Contains(out, "Invite URL:  pocketcmd://invite?") {
		t.Fatalf("expected 'Invite URL:  pocketcmd://invite?' in output, got: %q", out)
	}
	if !strings.Contains(out, code) {
		t.Fatalf("expected invite code %q in URL line, got: %q", code, out)
	}

	active, err := pki.NewInviteStore(testStateDB(t)).ListActive()
	if err != nil {
		t.Fatalf("list invites: %v", err)
	}
	if len(active) != 1 || active[0].Code != code {
		t.Fatalf("expected 1 stored invite with code %q, got %+v", code, active)
	}
}

func TestInvitesCommand_ListsOnlyActive(t *testing.T) {
	testutil.TempHome(t)

	store := pki.NewInviteStore(testStateDB(t))

	active, err := store.Create(pki.CreateInviteParams{
		Role:         "member",
		ExpiresIn:    24 * time.Hour,
		CreatedByUID: "cli",
	})
	if err != nil {
		t.Fatalf("create active invite: %v", err)
	}

	consumed, err := store.Create(pki.CreateInviteParams{
		Role:         "member",
		ExpiresIn:    24 * time.Hour,
		CreatedByUID: "cli",
	})
	if err != nil {
		t.Fatalf("create consumed invite: %v", err)
	}
	if err := store.MarkConsumed(consumed.Code, "device-001"); err != nil {
		t.Fatalf("mark consumed: %v", err)
	}

	revoked, err := store.Create(pki.CreateInviteParams{
		Role:         "member",
		ExpiresIn:    24 * time.Hour,
		CreatedByUID: "cli",
	})
	if err != nil {
		t.Fatalf("create revoked invite: %v", err)
	}
	if err := store.Revoke(revoked.Code, "cli"); err != nil {
		t.Fatalf("revoke invite: %v", err)
	}

	stdout, _, err := runCLI(t, "invites")
	if err != nil {
		t.Fatalf("invites command failed: %v", err)
	}

	out := stdout.String()
	if !strings.Contains(out, active.Code) {
		t.Errorf("expected active code %q in output, got: %q", active.Code, out)
	}
	if strings.Contains(out, consumed.Code) {
		t.Errorf("consumed code %q should NOT appear in output, got: %q", consumed.Code, out)
	}
	if strings.Contains(out, revoked.Code) {
		t.Errorf("revoked code %q should NOT appear in output, got: %q", revoked.Code, out)
	}
}

func TestRevokeInviteCommand_ByPrefix(t *testing.T) {
	testutil.TempHome(t)

	store := pki.NewInviteStore(testStateDB(t))
	inv, err := store.Create(pki.CreateInviteParams{
		Role:         "member",
		ExpiresIn:    24 * time.Hour,
		CreatedByUID: "cli",
	})
	if err != nil {
		t.Fatalf("create invite: %v", err)
	}

	prefix := inv.Code[:6]
	stdout, _, err := runCLI(t, "revoke-invite", prefix, "--yes")
	if err != nil {
		t.Fatalf("revoke-invite command failed: %v", err)
	}
	if !strings.Contains(stdout.String(), "Revoked invite") {
		t.Fatalf("expected 'Revoked invite' in output, got: %q", stdout.String())
	}

	updated, err := store.FindByCode(inv.Code)
	if err != nil {
		t.Fatalf("find invite: %v", err)
	}
	if updated.RevokedAt == "" {
		t.Fatal("expected RevokedAt to be set after revoke-invite")
	}
}

func TestRevokeInviteCommand_AmbiguousPrefix(t *testing.T) {
	testutil.TempHome(t)

	sharedPrefix := "aaaa"
	codes := []string{sharedPrefix + "bbbbbbbbbbbb", sharedPrefix + "cccccccccccc"}
	db := testStateDB(t)
	for _, code := range codes {
		if _, err := db.Exec(`INSERT INTO invites (code, role, created_at, expires_at)
			VALUES (?, 'member', ?, ?)`,
			code,
			time.Now().UTC().Format(time.RFC3339),
			time.Now().Add(24*time.Hour).UTC().Format(time.RFC3339)); err != nil {
			t.Fatalf("seed invite: %v", err)
		}
	}

	_, stderr, err := runCLI(t, "revoke-invite", sharedPrefix, "--yes")
	if err == nil {
		t.Fatal("expected non-zero exit for ambiguous prefix, got nil error")
	}
	combined := stderr.String() + err.Error()
	if !strings.Contains(combined, "ambiguous") {
		t.Fatalf("expected 'ambiguous' in error output, got stderr=%q err=%v", stderr.String(), err)
	}
}

func TestInviteCommand_ForExistingUser(t *testing.T) {
	testutil.TempHome(t)
	os.MkdirAll(config.TLSDir(), 0700)

	seedOwner(t)
	users := pki.NewUserRegistry(testStateDB(t))
	alice, err := users.Create("alice", "member", "cli")
	if err != nil {
		t.Fatalf("create user: %v", err)
	}

	stdout, _, err := runCLI(t, "invite", "--for", "alice", "--role", "admin")
	if err != nil {
		t.Fatalf("invite --for alice --role admin: %v", err)
	}

	out := stdout.String()
	if !strings.Contains(out, "Invite code:") {
		t.Fatalf("expected 'Invite code:' in output, got: %q", out)
	}
	if !strings.Contains(out, "For user:") {
		t.Fatalf("expected 'For user:' in output, got: %q", out)
	}

	store := pki.NewInviteStore(testStateDB(t))
	all, err := store.ListActive()
	if err != nil {
		t.Fatalf("list active: %v", err)
	}
	if len(all) != 1 {
		t.Fatalf("want 1 invite, got %d", len(all))
	}
	if all[0].Role != "member" {
		t.Fatalf("invite role must inherit target user's (member), got %q", all[0].Role)
	}
	if all[0].TargetUserID != alice.UserID {
		t.Fatalf("invite target_user_id mismatch: got %q want %q", all[0].TargetUserID, alice.UserID)
	}
}

func TestListUsersCommand_PrintsTable(t *testing.T) {
	testutil.TempHome(t)

	users := pki.NewUserRegistry(testStateDB(t))
	devs := pki.NewDeviceRegistry(testStateDB(t))

	alice, err := users.Create("alice", "admin", "cli")
	if err != nil {
		t.Fatalf("create alice: %v", err)
	}
	bob, err := users.Create("bob", "member", "cli")
	if err != nil {
		t.Fatalf("create bob: %v", err)
	}

	d3id, err := devs.RegisterDeviceForUser(testutil.ECDSAPubKeyPEM(t), "device1", alice.UserID, "")
	if err != nil {
		t.Fatalf("add device1: %v", err)
	}
	_, err = devs.RegisterDeviceForUser(testutil.ECDSAPubKeyPEM(t), "device2", alice.UserID, "")
	if err != nil {
		t.Fatalf("add device2: %v", err)
	}
	d3id2, err := devs.RegisterDeviceForUser(testutil.ECDSAPubKeyPEM(t), "device3", alice.UserID, "")
	if err != nil {
		t.Fatalf("add device3: %v", err)
	}
	if err := devs.Revoke(d3id2); err != nil {
		t.Fatalf("revoke device3: %v", err)
	}
	_ = d3id

	_, err = devs.RegisterDeviceForUser(testutil.ECDSAPubKeyPEM(t), "device4", bob.UserID, "")
	if err != nil {
		t.Fatalf("add device4: %v", err)
	}

	stdout, _, err := runCLI(t, "list-users")
	if err != nil {
		t.Fatalf("list-users failed: %v", err)
	}

	out := stdout.String()
	if !strings.Contains(out, alice.UserID) {
		t.Errorf("expected alice's user_id %q in output, got:\n%s", alice.UserID, out)
	}
	if !strings.Contains(out, bob.UserID) {
		t.Errorf("expected bob's user_id %q in output, got:\n%s", bob.UserID, out)
	}
	if !strings.Contains(out, "2") {
		t.Errorf("expected device count '2' for alice in output, got:\n%s", out)
	}
	if !strings.Contains(out, "1") {
		t.Errorf("expected device count '1' for bob in output, got:\n%s", out)
	}
}

func TestRevokeUserCommand_CascadesUserAndDevices(t *testing.T) {
	testutil.TempHome(t)

	users := pki.NewUserRegistry(testStateDB(t))
	devs := pki.NewDeviceRegistry(testStateDB(t))
	invites := pki.NewInviteStore(testStateDB(t))

	admin, err := users.Create("adminuser", "admin", "cli")
	if err != nil {
		t.Fatalf("create admin: %v", err)
	}
	member, err := users.Create("memberuser", "member", "cli")
	if err != nil {
		t.Fatalf("create member: %v", err)
	}

	adminDevID, err := devs.RegisterDeviceForUser(testutil.ECDSAPubKeyPEM(t), "admindev", admin.UserID, "")
	if err != nil {
		t.Fatalf("add admin device: %v", err)
	}

	md1ID, err := devs.RegisterDeviceForUser(testutil.ECDSAPubKeyPEM(t), "memberdev1", member.UserID, "")
	if err != nil {
		t.Fatalf("add member device1: %v", err)
	}
	md2ID, err := devs.RegisterDeviceForUser(testutil.ECDSAPubKeyPEM(t), "memberdev2", member.UserID, "")
	if err != nil {
		t.Fatalf("add member device2: %v", err)
	}

	inv, err := invites.Create(pki.CreateInviteParams{
		Role:         "member",
		ExpiresIn:    24 * time.Hour,
		TargetUserID: member.UserID,
		CreatedByUID: "cli",
	})
	if err != nil {
		t.Fatalf("create invite: %v", err)
	}

	stdout, _, err := runCLI(t, "revoke-user", member.UserID, "--yes")
	if err != nil {
		t.Fatalf("revoke-user failed: %v", err)
	}
	if !strings.Contains(stdout.String(), "Revoked user") {
		t.Fatalf("expected 'Revoked user' in output, got: %q", stdout.String())
	}

	updatedMember, _ := users.FindByID(member.UserID)
	if updatedMember.Status != "revoked" {
		t.Errorf("expected member status=revoked, got %q", updatedMember.Status)
	}

	updatedMD1, _ := devs.FindByID(md1ID)
	if updatedMD1.Status != "revoked" {
		t.Errorf("expected member device1 status=revoked, got %q", updatedMD1.Status)
	}
	updatedMD2, _ := devs.FindByID(md2ID)
	if updatedMD2.Status != "revoked" {
		t.Errorf("expected member device2 status=revoked, got %q", updatedMD2.Status)
	}

	updatedInv, _ := invites.FindByCode(inv.Code)
	if updatedInv.RevokedAt == "" {
		t.Error("expected invite revoked_at to be set after revoke-user cascade")
	}

	updatedAdmin, _ := users.FindByID(admin.UserID)
	if updatedAdmin.Status != "active" {
		t.Errorf("expected admin status=active, got %q", updatedAdmin.Status)
	}
	updatedAdminDev, _ := devs.FindByID(adminDevID)
	if updatedAdminDev.Status != "active" {
		t.Errorf("expected admin device status=active, got %q", updatedAdminDev.Status)
	}
}

func TestRevokeUserCommand_RefusesLastAdmin(t *testing.T) {
	testutil.TempHome(t)

	users := pki.NewUserRegistry(testStateDB(t))
	admin, err := users.Create("soloadmin", "admin", "cli")
	if err != nil {
		t.Fatalf("create admin: %v", err)
	}

	_, stderr, err := runCLI(t, "revoke-user", admin.UserID, "--yes")
	if err == nil {
		t.Fatal("expected non-zero exit when revoking last admin, got nil")
	}
	combined := stderr.String() + err.Error()
	if !strings.Contains(combined, "last active admin") {
		t.Fatalf("expected 'last active admin' in error, got stderr=%q err=%v", stderr.String(), err)
	}

	updated, _ := users.FindByID(admin.UserID)
	if updated.Status != "active" {
		t.Errorf("expected admin still active after refusal, got %q", updated.Status)
	}
}

func TestRevokeUserCommand_PurgeDataFlag(t *testing.T) {
	testutil.TempHome(t)

	users := pki.NewUserRegistry(testStateDB(t))
	devs := pki.NewDeviceRegistry(testStateDB(t))
	_, err := users.Create("adminuser", "admin", "cli")
	if err != nil {
		t.Fatalf("create admin: %v", err)
	}
	member, err := users.Create("memberuser", "member", "cli")
	if err != nil {
		t.Fatalf("create member: %v", err)
	}
	memberDevID, err := devs.RegisterDeviceForUser(testutil.ECDSAPubKeyPEM(t), "memberdev", member.UserID, "")
	if err != nil {
		t.Fatalf("register member device: %v", err)
	}

	seedDB := testStateDB(t)
	seedStore := datasync.NewSyncStore(seedDB, monitoring.NewStore(seedDB))
	_, err = seedStore.PushRecords("", []datasync.SyncRecord{
		{ID: "member-task", Type: "task", UpdatedAt: 1, DeviceID: memberDevID,
			Data: json.RawMessage(`{"secret":"member"}`)},
		{ID: "other-task", Type: "task", UpdatedAt: 1, DeviceID: "other-device",
			Data: json.RawMessage(`{"keep":true}`)},
	})
	if err != nil {
		t.Fatalf("seed sync records: %v", err)
	}

	stdout, _, err := runCLI(t, "revoke-user", member.UserID, "--purge-data", "--yes")
	if err != nil {
		t.Fatalf("revoke-user --purge-data failed: %v", err)
	}

	out := stdout.String()
	if !strings.Contains(out, "Revoked user") {
		t.Fatalf("expected 'Revoked user' in output, got: %q", out)
	}
	if !strings.Contains(out, "Purged 1 sync record(s)") {
		t.Fatalf("expected 'Purged 1 sync record(s)' in output, got: %q", out)
	}

	updated, _ := users.FindByID(member.UserID)
	if updated.Status != "revoked" {
		t.Errorf("expected member revoked, got %q", updated.Status)
	}

	checkDB := testStateDB(t)
	store := datasync.NewSyncStore(checkDB, monitoring.NewStore(checkDB))
	recs, err := store.PullRecords("", []string{"member-task", "other-task"})
	if err != nil || len(recs) != 2 {
		t.Fatalf("pull after purge: %v (%d records)", err, len(recs))
	}
	for _, rec := range recs {
		if rec.ID == "member-task" && (!rec.Deleted || string(rec.Data) != "{}") {
			t.Errorf("member record not purged: deleted=%v data=%s", rec.Deleted, rec.Data)
		}
		if rec.ID == "other-task" && rec.Deleted {
			t.Errorf("other device's record must be untouched")
		}
	}
}

func TestRevokeUserCommand_ByDisplayName(t *testing.T) {
	testutil.TempHome(t)

	users := pki.NewUserRegistry(testStateDB(t))
	_, err := users.Create("adminuser", "admin", "cli")
	if err != nil {
		t.Fatalf("create admin: %v", err)
	}
	bob, err := users.Create("bob", "member", "cli")
	if err != nil {
		t.Fatalf("create bob: %v", err)
	}

	stdout, _, err := runCLI(t, "revoke-user", "bob", "--yes")
	if err != nil {
		t.Fatalf("revoke-user bob failed: %v", err)
	}
	if !strings.Contains(stdout.String(), "Revoked user") {
		t.Fatalf("expected 'Revoked user' in output, got: %q", stdout.String())
	}

	updated, _ := users.FindByID(bob.UserID)
	if updated.Status != "revoked" {
		t.Errorf("expected bob revoked, got %q", updated.Status)
	}
}

func TestPromoteCommand_MemberBecomesAdmin(t *testing.T) {
	testutil.TempHome(t)

	users := pki.NewUserRegistry(testStateDB(t))
	_, err := users.Create("adminuser", "admin", "cli")
	if err != nil {
		t.Fatalf("create admin: %v", err)
	}
	member, err := users.Create("alice", "member", "cli")
	if err != nil {
		t.Fatalf("create member: %v", err)
	}

	stdout, _, err := runCLI(t, "promote", member.UserID)
	if err != nil {
		t.Fatalf("promote command failed: %v", err)
	}
	if !strings.Contains(stdout.String(), "Promoted") {
		t.Fatalf("expected 'Promoted' in output, got: %q", stdout.String())
	}

	updated, _ := users.FindByID(member.UserID)
	if updated.Role != "admin" {
		t.Errorf("expected role=admin after promote, got %q", updated.Role)
	}
}

func TestDemoteCommand_AdminBecomesMember(t *testing.T) {
	testutil.TempHome(t)

	users := pki.NewUserRegistry(testStateDB(t))
	_, err := users.Create("admin1", "admin", "cli")
	if err != nil {
		t.Fatalf("create admin1: %v", err)
	}
	admin2, err := users.Create("admin2", "admin", "cli")
	if err != nil {
		t.Fatalf("create admin2: %v", err)
	}

	stdout, _, err := runCLI(t, "demote", admin2.UserID, "--yes")
	if err != nil {
		t.Fatalf("demote command failed: %v", err)
	}
	if !strings.Contains(stdout.String(), "Demoted") {
		t.Fatalf("expected 'Demoted' in output, got: %q", stdout.String())
	}

	updated, _ := users.FindByID(admin2.UserID)
	if updated.Role != "member" {
		t.Errorf("expected role=member after demote, got %q", updated.Role)
	}
}

func TestDemoteCommand_RefusesLastAdmin(t *testing.T) {
	testutil.TempHome(t)

	users := pki.NewUserRegistry(testStateDB(t))
	admin, err := users.Create("soloadmin", "admin", "cli")
	if err != nil {
		t.Fatalf("create admin: %v", err)
	}
	_, err = users.Create("member1", "member", "cli")
	if err != nil {
		t.Fatalf("create member: %v", err)
	}

	_, stderr, err := runCLI(t, "demote", admin.UserID, "--yes")
	if err == nil {
		t.Fatal("expected non-zero exit when demoting last admin, got nil")
	}
	combined := stderr.String() + err.Error()
	if !strings.Contains(combined, "last active admin") {
		t.Fatalf("expected 'last active admin' in error, got stderr=%q err=%v", stderr.String(), err)
	}

	updated, _ := users.FindByID(admin.UserID)
	if updated.Role != "admin" {
		t.Errorf("expected admin still admin after refusal, got %q", updated.Role)
	}
}

func TestPromoteCommand_AlreadyAdminNoOp(t *testing.T) {
	testutil.TempHome(t)

	users := pki.NewUserRegistry(testStateDB(t))
	admin, err := users.Create("adminuser", "admin", "cli")
	if err != nil {
		t.Fatalf("create admin: %v", err)
	}

	stdout, _, err := runCLI(t, "promote", admin.UserID)
	if err != nil {
		t.Fatalf("promote already-admin should succeed, got: %v", err)
	}
	if !strings.Contains(stdout.String(), "already an admin") {
		t.Fatalf("expected 'already an admin' in output, got: %q", stdout.String())
	}

	updated, _ := users.FindByID(admin.UserID)
	if updated.Role != "admin" {
		t.Errorf("expected role=admin (unchanged), got %q", updated.Role)
	}
}

func TestDemoteCommand_AlreadyMemberNoOp(t *testing.T) {
	testutil.TempHome(t)

	users := pki.NewUserRegistry(testStateDB(t))
	_, err := users.Create("adminuser", "admin", "cli")
	if err != nil {
		t.Fatalf("create admin: %v", err)
	}
	member, err := users.Create("memberuser", "member", "cli")
	if err != nil {
		t.Fatalf("create member: %v", err)
	}

	stdout, _, err := runCLI(t, "demote", member.UserID, "--yes")
	if err != nil {
		t.Fatalf("demote already-member should succeed, got: %v", err)
	}
	if !strings.Contains(stdout.String(), "already a member") {
		t.Fatalf("expected 'already a member' in output, got: %q", stdout.String())
	}

	updated, _ := users.FindByID(member.UserID)
	if updated.Role != "member" {
		t.Errorf("expected role=member (unchanged), got %q", updated.Role)
	}
}

func TestInviteCommand_ExpiresClamped(t *testing.T) {
	testutil.TempHome(t)
	os.MkdirAll(config.TLSDir(), 0700)

	seedOwner(t)

	stdout, _, err := runCLI(t, "invite", "--role", "member", "--expires", "1000000000s")
	if err != nil {
		t.Fatalf("invite with huge --expires must succeed (clamped): %v", err)
	}
	if !strings.Contains(stdout.String(), "Note: --expires") {
		t.Fatalf("a clamped --expires must print a note, got %q", stdout.String())
	}

	active, err := pki.NewInviteStore(testStateDB(t)).ListActive()
	if err != nil || len(active) != 1 {
		t.Fatalf("list invites: %v (%d)", err, len(active))
	}
	expires, err := time.Parse(time.RFC3339, active[0].ExpiresAt)
	if err != nil {
		t.Fatalf("parse expiry %q: %v", active[0].ExpiresAt, err)
	}
	if expires.After(time.Now().Add(30*24*time.Hour + time.Minute)) {
		t.Fatalf("expiry %v exceeds the 30-day cap", expires)
	}
}

func TestDemoteCommand_RefusesOwner(t *testing.T) {
	testutil.TempHome(t)

	users := pki.NewUserRegistry(testStateDB(t))
	owner, err := users.Create("bigboss", "admin", "cli")
	if err != nil {
		t.Fatalf("create owner: %v", err)
	}
	if err := users.SetOwner(owner.UserID, true); err != nil {
		t.Fatalf("set owner: %v", err)
	}
	// A second admin so the refusal is attributable to the owner guard, not the last-admin guard.
	if _, err := users.Create("admin2", "admin", "cli"); err != nil {
		t.Fatalf("create admin2: %v", err)
	}

	_, stderr, err := runCLI(t, "demote", owner.UserID, "--yes")
	if err == nil {
		t.Fatal("expected non-zero exit when demoting the owner, got nil")
	}
	combined := stderr.String() + err.Error()
	if !strings.Contains(combined, "owner cannot be demoted") {
		t.Fatalf("expected 'owner cannot be demoted' in error, got stderr=%q err=%v", stderr.String(), err)
	}
	updated, _ := users.FindByID(owner.UserID)
	if updated.Role != "admin" {
		t.Errorf("expected owner still admin after refusal, got %q", updated.Role)
	}
}

func TestRevokeUserCommand_RefusesOwner(t *testing.T) {
	testutil.TempHome(t)

	users := pki.NewUserRegistry(testStateDB(t))
	owner, err := users.Create("bigboss", "admin", "cli")
	if err != nil {
		t.Fatalf("create owner: %v", err)
	}
	if err := users.SetOwner(owner.UserID, true); err != nil {
		t.Fatalf("set owner: %v", err)
	}
	if _, err := users.Create("admin2", "admin", "cli"); err != nil {
		t.Fatalf("create admin2: %v", err)
	}

	_, stderr, err := runCLI(t, "revoke-user", owner.UserID, "--yes")
	if err == nil {
		t.Fatal("expected non-zero exit when revoking the owner, got nil")
	}
	combined := stderr.String() + err.Error()
	if !strings.Contains(combined, "owner cannot be removed") {
		t.Fatalf("expected 'owner cannot be removed' in error, got stderr=%q err=%v", stderr.String(), err)
	}
	updated, _ := users.FindByID(owner.UserID)
	if updated.Status != "active" {
		t.Errorf("expected owner still active after refusal, got %q", updated.Status)
	}
}

func TestRevokeUserCommand_CascadesInvitesCreatedByUser(t *testing.T) {
	testutil.TempHome(t)

	users := pki.NewUserRegistry(testStateDB(t))
	invites := pki.NewInviteStore(testStateDB(t))

	if _, err := users.Create("adminuser", "admin", "cli"); err != nil {
		t.Fatalf("create admin: %v", err)
	}
	member, err := users.Create("memberuser", "member", "cli")
	if err != nil {
		t.Fatalf("create member: %v", err)
	}

	created, err := invites.Create(pki.CreateInviteParams{
		Role:         "member",
		ExpiresIn:    24 * time.Hour,
		CreatedByUID: member.UserID,
	})
	if err != nil {
		t.Fatalf("create invite: %v", err)
	}
	control, err := invites.Create(pki.CreateInviteParams{
		Role:         "member",
		ExpiresIn:    24 * time.Hour,
		CreatedByUID: "cli",
	})
	if err != nil {
		t.Fatalf("create control invite: %v", err)
	}

	if _, _, err := runCLI(t, "revoke-user", member.UserID, "--yes"); err != nil {
		t.Fatalf("revoke-user failed: %v", err)
	}

	got, _ := invites.FindByCode(created.Code)
	if got.RevokedAt == "" {
		t.Error("invite created by the revoked user must be cascade-revoked")
	}
	kept, _ := invites.FindByCode(control.Code)
	if kept.RevokedAt != "" {
		t.Error("operator's invite must survive the cascade")
	}
}

func TestRevokeUserCommand_Ambiguous(t *testing.T) {
	testutil.TempHome(t)

	db := testStateDB(t)
	for _, uid := range []string{"uid000000001", "uid000000002"} {
		if _, err := db.Exec(`INSERT INTO users (user_id, display_name, role, status, created_at)
			VALUES (?, 'bob', 'member', 'active', '2024-01-01T00:00:00Z')`, uid); err != nil {
			t.Fatalf("seed user: %v", err)
		}
	}

	_, stderr, err := runCLI(t, "revoke-user", "bob", "--yes")
	if err == nil {
		t.Fatal("expected non-zero exit for ambiguous display name, got nil")
	}
	combined := stderr.String() + err.Error()
	if !strings.Contains(combined, "ambiguous") {
		t.Fatalf("expected 'ambiguous' in error, got stderr=%q err=%v", stderr.String(), err)
	}
}
