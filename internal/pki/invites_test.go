package pki

import (
	"errors"
	"strings"
	"testing"
	"time"
)

func TestInviteStore_CreateAndLookup(t *testing.T) {
	s := NewInviteStore(testStateDB(t))
	inv, err := s.Create(CreateInviteParams{
		Role:         "member",
		ExpiresIn:    time.Hour,
		CreatedByUID: "admin-1",
	})
	if err != nil {
		t.Fatalf("create: %v", err)
	}
	if len(inv.Code) != 16 {
		t.Fatalf("want 16-char code, got %d", len(inv.Code))
	}
	if inv.Code != strings.ToLower(inv.Code) {
		t.Fatalf("code must be lowercase")
	}
	got, err := s.FindByCode(inv.Code)
	if err != nil || got == nil || got.Code != inv.Code {
		t.Fatalf("lookup failed")
	}
	got, err = s.FindByCode(strings.ToUpper(inv.Code))
	if err != nil || got == nil || got.Code != inv.Code {
		t.Fatalf("case-insensitive lookup failed")
	}
}

func TestInviteStore_RedeemAtomicity(t *testing.T) {
	s := NewInviteStore(testStateDB(t))
	inv, _ := s.Create(CreateInviteParams{Role: "member", ExpiresIn: time.Hour})
	if err := s.MarkConsumed(inv.Code, "dev-abc"); err != nil {
		t.Fatalf("first consume: %v", err)
	}
	err := s.MarkConsumed(inv.Code, "dev-xyz")
	if err == nil {
		t.Fatalf("second consume must fail")
	}
}

func TestInviteStore_Revoke(t *testing.T) {
	s := NewInviteStore(testStateDB(t))
	inv, _ := s.Create(CreateInviteParams{Role: "member", ExpiresIn: time.Hour})
	if err := s.Revoke(inv.Code, "admin-1"); err != nil {
		t.Fatalf("revoke: %v", err)
	}
	got, _ := s.FindByCode(inv.Code)
	if got.RevokedAt == "" {
		t.Fatalf("revoked_at not set")
	}
	if err := s.MarkConsumed(inv.Code, "dev-abc"); err == nil {
		t.Fatalf("must not consume revoked invite")
	}
}

func TestInviteStore_Sweep(t *testing.T) {
	s := NewInviteStore(testStateDB(t))
	expired, _ := s.Create(CreateInviteParams{Role: "member", ExpiresIn: -time.Second})
	fresh, _ := s.Create(CreateInviteParams{Role: "member", ExpiresIn: time.Hour})
	s.Sweep(time.Now())
	e, _ := s.FindByCode(expired.Code)
	f, _ := s.FindByCode(fresh.Code)
	if e.ExpiredAt == "" {
		t.Fatalf("expired invite not marked")
	}
	if f.ExpiredAt != "" {
		t.Fatalf("fresh invite wrongly marked expired")
	}
}

func TestInviteStore_ListActive(t *testing.T) {
	s := NewInviteStore(testStateDB(t))
	a, _ := s.Create(CreateInviteParams{Role: "member", ExpiresIn: time.Hour})
	b, _ := s.Create(CreateInviteParams{Role: "admin", ExpiresIn: time.Hour})
	_ = s.MarkConsumed(a.Code, "dev-abc")
	_ = s.Revoke(b.Code, "admin-1")
	c, _ := s.Create(CreateInviteParams{Role: "member", ExpiresIn: time.Hour})
	active, err := s.ListActive()
	if err != nil || len(active) != 1 || active[0].Code != c.Code {
		t.Fatalf("want only c active; got %v (err=%v)", active, err)
	}
}

func TestInviteStore_FindByPrefix(t *testing.T) {
	s := NewInviteStore(testStateDB(t))
	inv, _ := s.Create(CreateInviteParams{Role: "member", ExpiresIn: time.Hour})
	got, err := s.FindByPrefix(inv.Code[:8])
	if err != nil || got == nil || got.Code != inv.Code {
		t.Fatalf("prefix lookup failed: %v %v", err, got)
	}
	if got, err := s.FindByPrefix(strings.ToUpper(inv.Code[:10])); err != nil || got == nil {
		t.Fatalf("upper-case prefix lookup failed: %v", err)
	}
	if got, err := s.FindByPrefix(inv.Code[:4]); err != nil || got == nil {
		t.Fatalf("short store prefix: %v %v", err, got)
	}
	for _, short := range []string{"", inv.Code[:4], inv.Code[:7], "abcdefg1"} {
		if ValidInvitePrefix(short) {
			t.Fatalf("API prefix %q must be refused", short)
		}
	}
	if !ValidInvitePrefix(strings.ToUpper(inv.Code[:8])) || !ValidInvitePrefix(inv.Code) {
		t.Fatal("8–16 code-alphabet chars must pass the API check")
	}
	for _, bad := range []string{"", "%%%%%%%%", "%", "_", "________", inv.Code[:7] + "%", "abcdefg1", inv.Code + "a"} {
		if _, err := s.FindByPrefix(bad); !errors.Is(err, ErrInvalidInvitePrefix) {
			t.Fatalf("prefix %q: want ErrInvalidInvitePrefix, got %v", bad, err)
		}
		if ValidInvitePrefix(bad) {
			t.Fatalf("API prefix %q must be refused", bad)
		}
	}
	if got, err := s.FindByPrefix("zzzzzzzz"); err != nil || got != nil {
		t.Fatalf("no match: want (nil, nil), got %v %v", got, err)
	}
}

func TestInviteRecord_IsActiveMalformedExpiry(t *testing.T) {
	rec := InviteRecord{ExpiresAt: ""}
	if rec.IsActive(time.Now()) {
		t.Fatalf("empty ExpiresAt must not be active")
	}
	rec = InviteRecord{ExpiresAt: "not-a-date"}
	if rec.IsActive(time.Now()) {
		t.Fatalf("malformed ExpiresAt must not be active")
	}
}

func TestInviteStore_RevokeRejectsExpired(t *testing.T) {
	s := NewInviteStore(testStateDB(t))
	inv, _ := s.Create(CreateInviteParams{Role: "member", ExpiresIn: -time.Second})
	s.Sweep(time.Now())
	err := s.Revoke(inv.Code, "admin-1")
	if err == nil {
		t.Fatalf("expected error when revoking expired invite")
	}
}

func TestInviteStore_RevokeUnknownCode(t *testing.T) {
	s := NewInviteStore(testStateDB(t))
	if err := s.Revoke("nonexistent-code", "admin-1"); err == nil {
		t.Fatalf("expected error for unknown code")
	}
}

func TestInviteStore_MarkConsumedUnknownCode(t *testing.T) {
	s := NewInviteStore(testStateDB(t))
	if err := s.MarkConsumed("nonexistent-code", "dev-1"); err == nil {
		t.Fatalf("expected error for unknown code")
	}
}

func TestInviteStore_MarkConsumedSentinelErrors(t *testing.T) {
	s := NewInviteStore(testStateDB(t))
	if err := s.MarkConsumed("nonexistent-code", "dev-1"); !errors.Is(err, ErrInviteNotFound) {
		t.Fatalf("want ErrInviteNotFound, got %v", err)
	}
	inv, _ := s.Create(CreateInviteParams{Role: "member", ExpiresIn: time.Hour})
	_ = s.MarkConsumed(inv.Code, "dev-1")
	if err := s.MarkConsumed(inv.Code, "dev-2"); !errors.Is(err, ErrInviteNotRedeemable) {
		t.Fatalf("want ErrInviteNotRedeemable, got %v", err)
	}
}

func TestInviteStore_UnmarkConsumed(t *testing.T) {
	s := NewInviteStore(testStateDB(t))
	inv, _ := s.Create(CreateInviteParams{Role: "member", ExpiresIn: time.Hour})
	if err := s.MarkConsumed(inv.Code, "dev-abc"); err != nil {
		t.Fatalf("consume: %v", err)
	}

	if err := s.UnmarkConsumed(inv.Code, "dev-other"); err != nil {
		t.Fatalf("foreign unmark: %v", err)
	}
	got, _ := s.FindByCode(inv.Code)
	if got.ConsumedAt == "" {
		t.Fatalf("foreign device must not release the claim")
	}

	if err := s.UnmarkConsumed(inv.Code, "dev-abc"); err != nil {
		t.Fatalf("unmark: %v", err)
	}
	got, _ = s.FindByCode(inv.Code)
	if got.ConsumedAt != "" || got.ConsumedByDeviceID != "" {
		t.Fatalf("claim not released: %+v", got)
	}
	if err := s.MarkConsumed(inv.Code, "dev-xyz"); err != nil {
		t.Fatalf("re-consume after rollback: %v", err)
	}
}

func TestInviteStore_FindByPrefixAmbiguousSentinel(t *testing.T) {
	s := NewInviteStore(testStateDB(t))
	_, _ = s.Create(CreateInviteParams{Role: "member", ExpiresIn: time.Hour})
	_, _ = s.Create(CreateInviteParams{Role: "member", ExpiresIn: time.Hour})
	if _, err := s.FindByPrefix(""); err == nil {
		t.Fatalf("empty prefix must error")
	}
	db := s.db
	for _, code := range []string{"zzzzyyyyxxxx0001", "zzzzyyyyxxxx0002"} {
		if _, err := db.Exec(`INSERT INTO invites (code, role, created_at, expires_at)
			VALUES (?, 'member', ?, ?)`,
			code,
			time.Now().UTC().Format(time.RFC3339),
			time.Now().Add(time.Hour).UTC().Format(time.RFC3339)); err != nil {
			t.Fatalf("seed invite: %v", err)
		}
	}
	if _, err := s.FindByPrefix("zzzzyyyy"); !errors.Is(err, ErrAmbiguousInvitePrefix) {
		t.Fatalf("want ErrAmbiguousInvitePrefix, got %v", err)
	}
}

func TestInviteStore_Prune(t *testing.T) {
	s := NewInviteStore(testStateDB(t))
	now := time.Now().UTC()
	old := now.Add(-8 * 24 * time.Hour).Format(time.RFC3339)
	recent := now.Add(-time.Hour).Format(time.RFC3339)
	seed := func(code, consumed, expired, revoked string) {
		if _, err := s.db.Exec(`INSERT INTO invites (code, role, created_at, expires_at, consumed_at, expired_at, revoked_at)
			VALUES (?, 'member', ?, ?, ?, ?, ?)`, code, old, now.Add(time.Hour).Format(time.RFC3339), consumed, expired, revoked); err != nil {
			t.Fatal(err)
		}
	}
	seed("oldconsumed12345", old, "", "")
	seed("oldexpired123456", "", old, "")
	seed("oldrevoked123456", "", "", old)
	seed("newconsumed12345", recent, "", "")
	seed("stillactive12345", "", "", "")

	n, err := s.Prune(now, 7*24*time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	if n != 3 {
		t.Fatalf("pruned %d, want 3", n)
	}
	for _, code := range []string{"newconsumed12345", "stillactive12345"} {
		if rec, _ := s.FindByCode(code); rec == nil {
			t.Fatalf("%s must survive", code)
		}
	}
	if rec, _ := s.FindByCode("oldconsumed12345"); rec != nil {
		t.Fatal("old consumed invite must be gone")
	}
}
