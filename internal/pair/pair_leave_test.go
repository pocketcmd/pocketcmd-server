package pair

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"database/sql"
	"encoding/json"
	"log/slog"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/pocketcmd/pocketcmd-server/internal/datasync"
	"github.com/pocketcmd/pocketcmd-server/internal/pki"
	"github.com/pocketcmd/pocketcmd-server/internal/state"
)

func newLeaveTestHandler(t *testing.T) (*PairingHandler, *sql.DB, *bytes.Buffer) {
	t.Helper()
	db, err := state.Open(t.TempDir())
	if err != nil {
		t.Fatalf("state.Open: %v", err)
	}
	t.Cleanup(func() { db.Close() })
	serverKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	h := NewPairingHandler(pki.NewDeviceRegistry(db), pki.NewUserRegistry(db), pki.NewInviteStore(db),
		serverKey, "abcdef123456", "testhost", "https://192.168.1.10:8767")
	var buf bytes.Buffer
	h.SetAuditLogger(slog.New(slog.NewTextHandler(&buf, nil)))
	return h, db, &buf
}

func pairedThenLeft(t *testing.T, h *PairingHandler, name string) (pubPEM string, priv *ecdsa.PrivateKey, dev *pki.DeviceRecord) {
	t.Helper()
	inv, err := h.inviteStore.Create(pki.CreateInviteParams{Role: "member", ExpiresIn: time.Hour})
	if err != nil {
		t.Fatal(err)
	}
	csrPEM, priv := makeCSR(t)
	pubPEM = makePubKeyPEM(t, priv)
	if w := invitePairWithKey(t, h, pubPEM, csrPEM, inv.Code, name); w.Code != 200 {
		t.Fatalf("initial pair: %d %s", w.Code, w.Body.String())
	}
	dev, ok := h.registry.LookupByPublicKeyPEM(pubPEM)
	if !ok {
		t.Fatal("device not registered")
	}
	if err := h.registry.Leave(dev.DeviceID); err != nil {
		t.Fatal(err)
	}
	dev, _ = h.registry.FindByID(dev.DeviceID)
	if dev.Status != pki.DeviceStatusLeft {
		t.Fatalf("precondition: status %q", dev.Status)
	}
	return pubPEM, priv, dev
}

func TestPair_Invite_LeftDeviceRejoinsUnderInvitesRules(t *testing.T) {
	h, _, audit := newLeaveTestHandler(t)
	owner, _ := h.userRegistry.Create("Owner", "admin", "")
	pubPEM, priv, dev := pairedThenLeft(t, h, "Grace")

	inv, err := h.inviteStore.Create(pki.CreateInviteParams{
		Role: "admin", ExpiresIn: time.Hour, CreatedByUID: owner.UserID})
	if err != nil {
		t.Fatal(err)
	}
	w := invitePairWithKey(t, h, pubPEM, makeCSRForKey(t, priv), inv.Code, "Grace again")
	if w.Code != 200 {
		t.Fatalf("rejoin: expected 200, got %d: %s", w.Code, w.Body.String())
	}
	resp := decodePairResponse(t, w)
	if resp.DeviceID != dev.DeviceID {
		t.Fatalf("same key must keep its device id: %s vs %s", resp.DeviceID, dev.DeviceID)
	}
	if resp.UserID == dev.UserID {
		t.Fatal("a new-member invite must not hand the device its old user back")
	}
	if resp.UserRole != "admin" || resp.UserDisplayName != "Grace again" || resp.UserOwner {
		t.Fatalf("role/name must come from the invite: %+v", resp)
	}

	after, _ := h.registry.FindByID(dev.DeviceID)
	if after.Status != pki.DeviceStatusActive || after.UserID != resp.UserID ||
		after.RevokedAt != "" || after.DeviceName != "phone" {
		t.Fatalf("device not re-activated under the new user: %+v", after)
	}
	if !h.registry.IsAllowedByPubKey(pubPEM) {
		t.Fatal("re-activated key must pass the registry gate")
	}
	consumed, _ := h.inviteStore.FindByCode(inv.Code)
	if consumed.ConsumedAt == "" || consumed.ConsumedByDeviceID != dev.DeviceID {
		t.Fatalf("the invite must be consumed by the rejoining device: %+v", consumed)
	}
	if u, _ := h.userRegistry.FindByID(dev.UserID); u == nil || u.Status != "active" {
		t.Fatalf("old user must stay a member: %+v", u)
	}
	out := audit.String()
	if !strings.Contains(out, "msg=device_reactivated") ||
		!strings.Contains(out, "previous_user_id="+dev.UserID) {
		t.Fatalf("expected a device_reactivated audit with the previous user, got:\n%s", out)
	}

	if w := invitePairWithKey(t, h, pubPEM, makeCSRForKey(t, priv), inv.Code, "Grace again"); w.Code != 200 {
		t.Fatalf("retry of own redemption: %d %s", w.Code, w.Body.String())
	}
}

func TestPair_Invite_LeftDeviceRejoinsOwnUser(t *testing.T) {
	h, _, _ := newLeaveTestHandler(t)
	_, _ = h.userRegistry.Create("Owner", "admin", "")
	pubPEM, priv, dev := pairedThenLeft(t, h, "Heidi")
	usersBefore, _ := h.userRegistry.List()

	inv, _ := h.inviteStore.Create(pki.CreateInviteParams{
		Role: "member", ExpiresIn: time.Hour, TargetUserID: dev.UserID})
	w := invitePairWithKey(t, h, pubPEM, makeCSRForKey(t, priv), inv.Code, "")
	if w.Code != 200 {
		t.Fatalf("rejoin own user: %d %s", w.Code, w.Body.String())
	}
	resp := decodePairResponse(t, w)
	if resp.UserID != dev.UserID || resp.DeviceID != dev.DeviceID {
		t.Fatalf("got %s/%s, want %s/%s", resp.UserID, resp.DeviceID, dev.UserID, dev.DeviceID)
	}
	usersAfter, _ := h.userRegistry.List()
	if len(usersAfter) != len(usersBefore) {
		t.Fatal("a second-device invite must not create a user")
	}
	if after, _ := h.registry.FindByID(dev.DeviceID); after.Status != pki.DeviceStatusActive {
		t.Fatalf("not re-activated: %+v", after)
	}
}

func TestPair_Invite_LeftDeviceKeyRecordsResetOnlyOnUserChange(t *testing.T) {
	seed := func(t *testing.T, db *sql.DB, deviceID string) {
		t.Helper()
		store := datasync.NewSyncStore(db, nil)
		now := time.Now().UnixMilli()
		wrapData, _ := json.Marshal(map[string]string{"recipient_device": deviceID})
		if _, err := store.PushRecords("", []datasync.SyncRecord{
			{ID: "team_1:" + deviceID, Type: "vault_wrap", UpdatedAt: now, VaultID: "team_1",
				Data: wrapData},
			{ID: deviceID, Type: "device_vault_key", UpdatedAt: now, Data: json.RawMessage(`{"dvk_pub":"P"}`)},
		}); err != nil {
			t.Fatal(err)
		}
	}
	count := func(t *testing.T, db *sql.DB, deviceID string) int {
		t.Helper()
		var n int
		if err := db.QueryRow(`SELECT COUNT(*) FROM sync_records WHERE id=? OR id=?`,
			"team_1:"+deviceID, deviceID).Scan(&n); err != nil {
			t.Fatal(err)
		}
		return n
	}

	t.Run("different user", func(t *testing.T) {
		h, db, audit := newLeaveTestHandler(t)
		_, _ = h.userRegistry.Create("Owner", "admin", "")
		pubPEM, priv, dev := pairedThenLeft(t, h, "Ivan")
		seed(t, db, dev.DeviceID)
		inv, _ := h.inviteStore.Create(pki.CreateInviteParams{Role: "member", ExpiresIn: time.Hour})
		if w := invitePairWithKey(t, h, pubPEM, makeCSRForKey(t, priv), inv.Code, "Someone"); w.Code != 200 {
			t.Fatalf("rejoin: %d %s", w.Code, w.Body.String())
		}
		if n := count(t, db, dev.DeviceID); n != 0 {
			t.Fatalf("%d key record(s) of the old binding survived a change of user", n)
		}
		if !strings.Contains(audit.String(), "msg=device_key_records_reset") {
			t.Fatalf("expected a device_key_records_reset audit, got:\n%s", audit.String())
		}
	})
	t.Run("same user", func(t *testing.T) {
		h, db, _ := newLeaveTestHandler(t)
		_, _ = h.userRegistry.Create("Owner", "admin", "")
		pubPEM, priv, dev := pairedThenLeft(t, h, "Judy")
		seed(t, db, dev.DeviceID)
		inv, _ := h.inviteStore.Create(pki.CreateInviteParams{
			Role: "member", ExpiresIn: time.Hour, TargetUserID: dev.UserID})
		if w := invitePairWithKey(t, h, pubPEM, makeCSRForKey(t, priv), inv.Code, ""); w.Code != 200 {
			t.Fatalf("rejoin: %d %s", w.Code, w.Body.String())
		}
		if n := count(t, db, dev.DeviceID); n != 2 {
			t.Fatalf("rejoining the same user must keep its key records, %d left", n)
		}
	})
}

func TestPair_Invite_LeftDeviceNeedsValidInvite(t *testing.T) {
	h, _, _ := newLeaveTestHandler(t)
	_, _ = h.userRegistry.Create("Owner", "admin", "")
	pubPEM, priv, dev := pairedThenLeft(t, h, "Ken")

	used, _ := h.inviteStore.Create(pki.CreateInviteParams{Role: "member", ExpiresIn: time.Hour})
	if err := h.inviteStore.MarkConsumed(used.Code, "someone-else"); err != nil {
		t.Fatal(err)
	}
	w := invitePairWithKey(t, h, pubPEM, makeCSRForKey(t, priv), used.Code, "Ken")
	if w.Code != 409 {
		t.Fatalf("consumed invite: expected 409, got %d: %s", w.Code, w.Body.String())
	}
	assertErrorCode(t, w.Body.Bytes(), "invite_consumed")
	if w := invitePairWithKey(t, h, pubPEM, makeCSRForKey(t, priv), "doesnotexist00000000", "Ken"); w.Code != 404 {
		t.Fatalf("unknown invite: expected 404, got %d", w.Code)
	}
	if after, _ := h.registry.FindByID(dev.DeviceID); after.Status != pki.DeviceStatusLeft {
		t.Fatalf("a refused redemption must not touch the device: %+v", after)
	}
}

func TestPair_Invite_RevokedAfterLeavingRefused(t *testing.T) {
	h, _, _ := newLeaveTestHandler(t)
	_, _ = h.userRegistry.Create("Owner", "admin", "")
	pubPEM, priv, dev := pairedThenLeft(t, h, "Liam")
	if err := h.registry.Revoke(dev.DeviceID); err != nil {
		t.Fatal(err)
	}
	inv, _ := h.inviteStore.Create(pki.CreateInviteParams{Role: "member", ExpiresIn: time.Hour})
	w := invitePairWithKey(t, h, pubPEM, makeCSRForKey(t, priv), inv.Code, "Liam")
	if w.Code != 403 {
		t.Fatalf("expected 403, got %d: %s", w.Code, w.Body.String())
	}
	assertErrorCode(t, w.Body.Bytes(), "device_revoked")
	if after, _ := h.inviteStore.FindByCode(inv.Code); after.ConsumedAt != "" {
		t.Fatal("the refused attempt burned the invite")
	}
}

func TestPair_Bootstrap_InactiveKeyRefused(t *testing.T) {
	for _, tc := range []struct {
		name   string
		mark   func(*pki.DeviceRegistry, string) error
		status string
		code   string
	}{
		{"left", (*pki.DeviceRegistry).Leave, pki.DeviceStatusLeft, "device_left"},
		{"revoked", (*pki.DeviceRegistry).Revoke, pki.DeviceStatusRevoked, "device_revoked"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			h, _, _ := newLeaveTestHandler(t)
			u, _ := h.userRegistry.Create("Gone", "admin", "")
			csrPEM, priv := makeCSR(t)
			pubPEM := makePubKeyPEM(t, priv)
			id, err := h.registry.RegisterDeviceForUser(pubPEM, "phone", u.UserID, "")
			if err != nil {
				t.Fatal(err)
			}
			if err := tc.mark(h.registry, id); err != nil {
				t.Fatal(err)
			}
			if err := h.userRegistry.Revoke(u.UserID); err != nil {
				t.Fatal(err)
			}

			token := h.GeneratePairingToken()
			body, _ := json.Marshal(PairRequest{
				DevicePublicKey: pubPEM, DeviceName: "phone", CSR: csrPEM,
				Credential:  PairCredential{Kind: "bootstrap", Token: token},
				DisplayName: "Me",
			})
			req := httptest.NewRequest("POST", "/api/pair", strings.NewReader(string(body)))
			w := httptest.NewRecorder()
			h.HandlePair(w, req)
			if w.Code != 403 {
				t.Fatalf("expected 403, got %d: %s", w.Code, w.Body.String())
			}
			assertErrorCode(t, w.Body.Bytes(), tc.code)

			users, _ := h.userRegistry.List()
			if len(users) != 1 {
				t.Fatalf("no owner may be minted for an inactive key, users=%d", len(users))
			}
			if dev, _ := h.registry.FindByID(id); dev.Status != tc.status {
				t.Fatalf("status changed to %q", dev.Status)
			}
			body2, _ := bootstrapRequest(t, token, "Fresh")
			req2 := httptest.NewRequest("POST", "/api/pair", strings.NewReader(string(body2)))
			w2 := httptest.NewRecorder()
			h.HandlePair(w2, req2)
			if w2.Code != 200 {
				t.Fatalf("the token must survive the refusal: %d %s", w2.Code, w2.Body.String())
			}
		})
	}
}
