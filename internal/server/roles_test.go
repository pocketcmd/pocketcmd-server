package server

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/pocketcmd/pocketcmd-server/internal/pki"
)

func testPubKey(t *testing.T) string {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("keygen: %v", err)
	}
	der, err := x509.MarshalPKIXPublicKey(&key.PublicKey)
	if err != nil {
		t.Fatalf("marshal pub: %v", err)
	}
	return string(pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: der}))
}

func TestRequireRole_AllowsMatching(t *testing.T) {
	h := RequireRole("admin", http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(200)
	}))
	req := apiRequest("GET", "/x", nil)
	req = req.WithContext(context.WithValue(req.Context(), contextKeyRole, "admin"))
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	if rec.Code != 200 {
		t.Fatalf("want 200, got %d", rec.Code)
	}
}

func TestRequireRole_RejectsMismatch(t *testing.T) {
	reached := false
	h := RequireRole("admin", http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		reached = true
	}))
	req := apiRequest("GET", "/x", nil)
	req = req.WithContext(context.WithValue(req.Context(), contextKeyRole, "member"))
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	if rec.Code != http.StatusForbidden {
		t.Fatalf("want 403, got %d", rec.Code)
	}
	if reached {
		t.Fatalf("handler should not have been reached")
	}
	var body map[string]string
	if err := json.NewDecoder(rec.Body).Decode(&body); err != nil {
		t.Fatalf("expected JSON body on 403, decode error: %v", err)
	}
	if body["error"] != "forbidden" {
		t.Errorf("expected error 'forbidden', got %q", body["error"])
	}
}

func TestRequireRole_RejectsMissingContextRole(t *testing.T) {
	h := RequireRole("admin", http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {}))
	req := apiRequest("GET", "/x", nil)
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	if rec.Code != http.StatusForbidden {
		t.Fatalf("want 403 when role absent, got %d", rec.Code)
	}
	var body map[string]string
	if err := json.NewDecoder(rec.Body).Decode(&body); err != nil {
		t.Fatalf("expected JSON body on 403, decode error: %v", err)
	}
	if body["error"] != "forbidden" {
		t.Errorf("expected error 'forbidden', got %q", body["error"])
	}
}

func TestResolveUser_Happy(t *testing.T) {
	devs := pki.NewDeviceRegistry(testStateDB(t))
	users := pki.NewUserRegistry(testStateDB(t))
	u, _ := users.Create("Bob", "member", "")
	id, _ := devs.RegisterDeviceForUser(testPubKey(t), "phone", u.UserID, "")
	got, err := ResolveUser(id, devs, users)
	if err != nil || got.UserID != u.UserID || got.Role != "member" {
		t.Fatalf("want %s/member, got %+v (err=%v)", u.UserID, got, err)
	}
}

func TestResolveUser_RevokedUser(t *testing.T) {
	devs := pki.NewDeviceRegistry(testStateDB(t))
	users := pki.NewUserRegistry(testStateDB(t))
	u, _ := users.Create("Alice", "admin", "")
	id, _ := devs.RegisterDeviceForUser(testPubKey(t), "iphone", u.UserID, "")
	_ = users.Revoke(u.UserID)
	_, err := ResolveUser(id, devs, users)
	if err == nil {
		t.Fatalf("want error for revoked user")
	}
}

func TestResolveUser_RevokedDevice(t *testing.T) {
	devs := pki.NewDeviceRegistry(testStateDB(t))
	users := pki.NewUserRegistry(testStateDB(t))
	u, _ := users.Create("Alice", "admin", "")
	id, _ := devs.RegisterDeviceForUser(testPubKey(t), "iphone", u.UserID, "")
	_ = devs.Revoke(id)
	_, err := ResolveUser(id, devs, users)
	if err == nil {
		t.Fatalf("want error for revoked device")
	}
}

func TestResolveUser_UnknownDevice(t *testing.T) {
	devs := pki.NewDeviceRegistry(testStateDB(t))
	users := pki.NewUserRegistry(testStateDB(t))
	_, err := ResolveUser("nonexistent-id", devs, users)
	if err == nil {
		t.Fatalf("want error for unknown device")
	}
}

func TestWithUserContext(t *testing.T) {
	u := &pki.UserRecord{UserID: "u1", Role: "admin", Status: "active"}
	ctx := withUserContext(context.Background(), u)
	if got, _ := ctx.Value(contextKeyUserID).(string); got != "u1" {
		t.Fatalf("userID: want u1, got %q", got)
	}
	if got, _ := ctx.Value(contextKeyRole).(string); got != "admin" {
		t.Fatalf("role: want admin, got %q", got)
	}
	if got, _ := ctx.Value(contextKeyUser).(*pki.UserRecord); got != u {
		t.Fatalf("user record not stashed in context")
	}
}
