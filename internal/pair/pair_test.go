package pair

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"encoding/pem"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/pocketcmd/pocketcmd-server/internal/pki"
	"github.com/pocketcmd/pocketcmd-server/internal/state"
)

func makeCSR(t *testing.T) (csrPEM string, privKey *ecdsa.PrivateKey) {
	t.Helper()
	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}
	csr, err := x509.CreateCertificateRequest(rand.Reader, &x509.CertificateRequest{
		Subject: pkix.Name{CommonName: "pocketcmd-device"},
	}, priv)
	if err != nil {
		t.Fatalf("create CSR: %v", err)
	}
	return string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE REQUEST", Bytes: csr})), priv
}

func makeCSRForKey(t *testing.T, priv *ecdsa.PrivateKey) string {
	t.Helper()
	csr, err := x509.CreateCertificateRequest(rand.Reader, &x509.CertificateRequest{
		Subject: pkix.Name{CommonName: "pocketcmd-device"},
	}, priv)
	if err != nil {
		t.Fatalf("create CSR: %v", err)
	}
	return string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE REQUEST", Bytes: csr}))
}

func makePubKeyPEM(t *testing.T, key *ecdsa.PrivateKey) string {
	t.Helper()
	der, err := x509.MarshalPKIXPublicKey(&key.PublicKey)
	if err != nil {
		t.Fatalf("marshal pubkey: %v", err)
	}
	return string(pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: der}))
}

func newTestHandler(t *testing.T) *PairingHandler {
	t.Helper()
	db, err := state.Open(t.TempDir())
	if err != nil {
		t.Fatalf("state.Open: %v", err)
	}
	t.Cleanup(func() { db.Close() })
	registry := pki.NewDeviceRegistry(db)
	users := pki.NewUserRegistry(db)
	invites := pki.NewInviteStore(db)
	serverKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generate server key: %v", err)
	}
	return NewPairingHandler(registry, users, invites, serverKey, "abcdef123456", "testhost", "https://192.168.1.10:8767")
}

func bootstrapRequest(t *testing.T, token, displayName string) ([]byte, string) {
	t.Helper()
	csrPEM, privKey := makeCSR(t)
	pubKeyPEM := makePubKeyPEM(t, privKey)
	body, _ := json.Marshal(PairRequest{
		DevicePublicKey: pubKeyPEM,
		DeviceName:      "test-device",
		CSR:             csrPEM,
		Credential:      PairCredential{Kind: "bootstrap", Token: token},
		DisplayName:     displayName,
	})
	return body, pubKeyPEM
}

func TestParseSSHConfig(t *testing.T) {
	raw := "Host myserver\n    HostName 192.168.1.100\n    User admin\n    Port 2222\n    IdentityFile ~/.ssh/id_ed25519\n\nHost dev\n    HostName dev.example.com\n    User deploy\n"

	hosts, _ := ParseSSHConfigString(raw)
	if len(hosts) != 2 {
		t.Fatalf("expected 2 hosts, got %d", len(hosts))
	}
	if hosts[0].Name != "myserver" {
		t.Fatalf("expected 'myserver', got '%s'", hosts[0].Name)
	}
	if hosts[0].Hostname != "192.168.1.100" {
		t.Fatalf("expected '192.168.1.100', got '%s'", hosts[0].Hostname)
	}
	if hosts[0].Username != "admin" {
		t.Fatalf("expected 'admin', got '%s'", hosts[0].Username)
	}
	if hosts[0].Port != 2222 {
		t.Fatalf("expected 2222, got %d", hosts[0].Port)
	}
	if hosts[1].Port != 22 {
		t.Fatalf("expected default port 22, got %d", hosts[1].Port)
	}
}

func TestParseSSHConfig_SkipsWildcards(t *testing.T) {
	raw := "Host *\n    ServerAliveInterval 60\n\nHost prod\n    HostName prod.example.com\n"
	hosts, _ := ParseSSHConfigString(raw)
	if len(hosts) != 1 {
		t.Fatalf("expected 1 host (wildcard skipped), got %d", len(hosts))
	}
	if hosts[0].Name != "prod" {
		t.Fatalf("expected 'prod', got '%s'", hosts[0].Name)
	}
}

func TestHandlePair_Success(t *testing.T) {
	h := newTestHandler(t)
	token := h.GeneratePairingToken()

	csrPEM, privKey := makeCSR(t)
	pubKeyPEM := makePubKeyPEM(t, privKey)

	body, _ := json.Marshal(PairRequest{
		DevicePublicKey: pubKeyPEM,
		DeviceName:      "iPhone 15",
		CSR:             csrPEM,
		Credential:      PairCredential{Kind: "bootstrap", Token: token},
		DisplayName:     "Alice",
	})

	req := httptest.NewRequest("POST", "/api/pair", strings.NewReader(string(body)))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()

	h.HandlePair(w, req)

	if w.Code != 200 {
		t.Fatalf("expected 200, got %d: %s", w.Code, w.Body.String())
	}

	var resp PairResponse
	if err := json.Unmarshal(w.Body.Bytes(), &resp); err != nil {
		t.Fatalf("unmarshal response: %v", err)
	}
	if resp.ClientCert == "" {
		t.Fatal("expected client cert in response")
	}
	if resp.ServerURL != "https://192.168.1.10:8767" {
		t.Fatalf("expected server URL, got %q", resp.ServerURL)
	}
	if resp.ServerFingerprint != "abcdef123456" {
		t.Fatalf("expected server fingerprint, got %q", resp.ServerFingerprint)
	}
	if resp.Hostname != "testhost" {
		t.Fatalf("expected hostname 'testhost', got %q", resp.Hostname)
	}
	if resp.DeviceID == "" {
		t.Fatal("expected device ID in response")
	}
	if resp.ExpiresAt == "" {
		t.Fatal("expected expires_at in response")
	}
	if resp.UserID == "" {
		t.Fatal("expected user_id in response")
	}
	if resp.UserDisplayName != "Alice" {
		t.Fatalf("expected user_display_name 'Alice', got %q", resp.UserDisplayName)
	}
}

func TestHandlePair_InvalidToken(t *testing.T) {
	h := newTestHandler(t)
	h.GeneratePairingToken()

	csrPEM, privKey := makeCSR(t)
	pubKeyPEM := makePubKeyPEM(t, privKey)

	body, _ := json.Marshal(PairRequest{
		DevicePublicKey: pubKeyPEM,
		DeviceName:      "test",
		CSR:             csrPEM,
		Credential:      PairCredential{Kind: "bootstrap", Token: "wrongtoken"},
		DisplayName:     "Alice",
	})
	req := httptest.NewRequest("POST", "/api/pair", strings.NewReader(string(body)))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()

	h.HandlePair(w, req)

	if w.Code != 401 {
		t.Fatalf("expected 401, got %d: %s", w.Code, w.Body.String())
	}
}

func TestHandlePair_ExpiredToken(t *testing.T) {
	h := newTestHandler(t)
	now := time.Now()
	h.now = func() time.Time { return now }
	token := h.GeneratePairingToken()
	now = now.Add(h.tokenTTL + time.Second)

	csrPEM, privKey := makeCSR(t)
	pubKeyPEM := makePubKeyPEM(t, privKey)

	body, _ := json.Marshal(PairRequest{
		DevicePublicKey: pubKeyPEM,
		DeviceName:      "test",
		CSR:             csrPEM,
		Credential:      PairCredential{Kind: "bootstrap", Token: token},
		DisplayName:     "Alice",
	})
	req := httptest.NewRequest("POST", "/api/pair", strings.NewReader(string(body)))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()

	h.HandlePair(w, req)

	if w.Code != 401 {
		t.Fatalf("expected 401, got %d: %s", w.Code, w.Body.String())
	}
}

func TestHandlePair_MissingFields(t *testing.T) {
	h := newTestHandler(t)
	token := h.GeneratePairingToken()

	body, _ := json.Marshal(PairRequest{
		DeviceName: "test",
		Credential: PairCredential{Kind: "bootstrap", Token: token},
	})
	req := httptest.NewRequest("POST", "/api/pair", strings.NewReader(string(body)))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()

	h.HandlePair(w, req)

	if w.Code != 400 {
		t.Fatalf("expected 400, got %d: %s", w.Code, w.Body.String())
	}
}

func TestHandlePair_Idempotent(t *testing.T) {
	h := newTestHandler(t)

	token := h.GeneratePairingToken()
	csrPEM, privKey := makeCSR(t)
	pubKeyPEM := makePubKeyPEM(t, privKey)

	body, _ := json.Marshal(PairRequest{
		DevicePublicKey: pubKeyPEM,
		DeviceName:      "iPhone 15",
		CSR:             csrPEM,
		Credential:      PairCredential{Kind: "bootstrap", Token: token},
		DisplayName:     "Alice",
	})
	req := httptest.NewRequest("POST", "/api/pair", strings.NewReader(string(body)))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	h.HandlePair(w, req)
	if w.Code != 200 {
		t.Fatalf("first pair: expected 200, got %d: %s", w.Code, w.Body.String())
	}

	body2, _ := json.Marshal(PairRequest{
		DevicePublicKey: pubKeyPEM,
		DeviceName:      "iPhone 15",
		CSR:             makeCSRForKey(t, privKey),
		Credential:      PairCredential{Kind: "bootstrap", Token: "any"},
		DisplayName:     "Alice",
	})
	req2 := httptest.NewRequest("POST", "/api/pair", strings.NewReader(string(body2)))
	req2.Header.Set("Content-Type", "application/json")
	w2 := httptest.NewRecorder()

	h.HandlePair(w2, req2)

	if w2.Code != 200 {
		t.Fatalf("expected 200 for idempotent re-pair, got %d: %s", w2.Code, w2.Body.String())
	}

	var resp PairResponse
	if err := json.Unmarshal(w2.Body.Bytes(), &resp); err != nil {
		t.Fatalf("unmarshal response: %v", err)
	}
	if resp.ClientCert == "" {
		t.Fatal("expected client cert in idempotent response")
	}
	if resp.UserID == "" {
		t.Fatal("expected user_id populated on idempotent re-pair")
	}
	if resp.UserDisplayName != "Alice" {
		t.Fatalf("expected user_display_name round-trip, got %q", resp.UserDisplayName)
	}
}

func TestHandlePair_CSRKeyMismatchRejected(t *testing.T) {
	h := newTestHandler(t)

	token := h.GeneratePairingToken()
	csrPEM, privKey := makeCSR(t)
	pubKeyPEM := makePubKeyPEM(t, privKey)
	body, _ := json.Marshal(PairRequest{
		DevicePublicKey: pubKeyPEM,
		DeviceName:      "iPhone 15",
		CSR:             csrPEM,
		Credential:      PairCredential{Kind: "bootstrap", Token: token},
		DisplayName:     "Alice",
	})
	req := httptest.NewRequest("POST", "/api/pair", strings.NewReader(string(body)))
	w := httptest.NewRecorder()
	h.HandlePair(w, req)
	if w.Code != 200 {
		t.Fatalf("bootstrap: expected 200, got %d: %s", w.Code, w.Body.String())
	}

	_, attackerKey := makeCSR(t)
	body2, _ := json.Marshal(PairRequest{
		DevicePublicKey: pubKeyPEM,
		DeviceName:      "iPhone 15",
		CSR:             makeCSRForKey(t, attackerKey),
		Credential:      PairCredential{Kind: "bootstrap", Token: "any"},
		DisplayName:     "Alice",
	})
	req2 := httptest.NewRequest("POST", "/api/pair", strings.NewReader(string(body2)))
	w2 := httptest.NewRecorder()
	h.HandlePair(w2, req2)
	if w2.Code != 400 || !strings.Contains(w2.Body.String(), "csr_key_mismatch") {
		t.Fatalf("expected 400 csr_key_mismatch, got %d: %s", w2.Code, w2.Body.String())
	}
}

func TestHandlePair_RateLimit(t *testing.T) {
	h := newTestHandler(t)
	h.GeneratePairingToken()

	csrPEM, privKey := makeCSR(t)
	pubKeyPEM := makePubKeyPEM(t, privKey)

	body, _ := json.Marshal(PairRequest{
		DevicePublicKey: pubKeyPEM,
		DeviceName:      "test",
		CSR:             csrPEM,
		Credential:      PairCredential{Kind: "bootstrap", Token: "wrongtoken"},
		DisplayName:     "Alice",
	})

	for i := 0; i < MaxPairAttempts; i++ {
		req := httptest.NewRequest("POST", "/api/pair", strings.NewReader(string(body)))
		req.Header.Set("Content-Type", "application/json")
		w := httptest.NewRecorder()
		h.HandlePair(w, req)
		if w.Code != 401 {
			t.Fatalf("attempt %d: expected 401, got %d", i+1, w.Code)
		}
	}

	req := httptest.NewRequest("POST", "/api/pair", strings.NewReader(string(body)))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	h.HandlePair(w, req)

	if w.Code != http.StatusTooManyRequests {
		t.Fatalf("expected 429, got %d: %s", w.Code, w.Body.String())
	}
}

func TestHandlePair_InvalidCSR(t *testing.T) {
	h := newTestHandler(t)
	token := h.GeneratePairingToken()

	_, privKey := makeCSR(t)
	pubKeyPEM := makePubKeyPEM(t, privKey)

	body, _ := json.Marshal(PairRequest{
		DevicePublicKey: pubKeyPEM,
		DeviceName:      "test",
		CSR:             "not a valid CSR PEM",
		Credential:      PairCredential{Kind: "bootstrap", Token: token},
		DisplayName:     "Alice",
	})
	req := httptest.NewRequest("POST", "/api/pair", strings.NewReader(string(body)))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()

	h.HandlePair(w, req)

	if w.Code != 400 {
		t.Fatalf("expected 400 for invalid CSR, got %d: %s", w.Code, w.Body.String())
	}
	if !strings.Contains(w.Body.String(), "invalid_csr") {
		t.Fatalf("expected 'invalid_csr' error code, got: %s", w.Body.String())
	}
}

func TestHandlePair_InvalidPublicKey(t *testing.T) {
	h := newTestHandler(t)
	token := h.GeneratePairingToken()

	csrPEM, _ := makeCSR(t)

	body, _ := json.Marshal(PairRequest{
		DevicePublicKey: "not a valid PEM public key",
		DeviceName:      "test",
		CSR:             csrPEM,
		Credential:      PairCredential{Kind: "bootstrap", Token: token},
		DisplayName:     "Alice",
	})
	req := httptest.NewRequest("POST", "/api/pair", strings.NewReader(string(body)))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()

	h.HandlePair(w, req)

	if w.Code != 400 {
		t.Fatalf("expected 400 for invalid public key, got %d: %s", w.Code, w.Body.String())
	}
	if !strings.Contains(w.Body.String(), "invalid_public_key") {
		t.Fatalf("expected 'invalid_public_key' error code, got: %s", w.Body.String())
	}
}

func TestHandlePair_MethodNotAllowed(t *testing.T) {
	h := newTestHandler(t)
	req := httptest.NewRequest("GET", "/api/pair", nil)
	w := httptest.NewRecorder()
	h.HandlePair(w, req)

	if w.Code != http.StatusMethodNotAllowed {
		t.Fatalf("expected 405 for GET, got %d", w.Code)
	}
}

func TestPairingToken_NotExpired(t *testing.T) {
	h := newTestHandler(t)
	h.tokenTTL = 5 * time.Second
	token := h.GeneratePairingToken()

	h.mu.Lock()
	valid := h.activeToken != nil &&
		h.activeToken.token == token &&
		!h.activeToken.used &&
		time.Now().Before(h.activeToken.expiresAt)
	h.mu.Unlock()
	if !valid {
		t.Fatal("token should be valid within its TTL")
	}

	csrPEM, privKey := makeCSR(t)
	pubKeyPEM := makePubKeyPEM(t, privKey)

	body, _ := json.Marshal(PairRequest{
		DevicePublicKey: pubKeyPEM,
		DeviceName:      "valid-token-test",
		CSR:             csrPEM,
		Credential:      PairCredential{Kind: "bootstrap", Token: token},
		DisplayName:     "Alice",
	})
	req := httptest.NewRequest("POST", "/api/pair", strings.NewReader(string(body)))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()

	h.HandlePair(w, req)
	if w.Code != 200 {
		t.Fatalf("expected 200 with non-expired token, got %d: %s", w.Code, w.Body.String())
	}
}

func TestParseSSHConfig_EmptyString(t *testing.T) {
	hosts, keys := ParseSSHConfigString("")
	if len(hosts) != 0 {
		t.Fatalf("expected 0 hosts from empty input, got %d", len(hosts))
	}
	if len(keys) != 0 {
		t.Fatalf("expected 0 keys from empty input, got %d", len(keys))
	}
}

func TestParseSSHConfig_CommentsOnly(t *testing.T) {
	raw := "# This is a comment\n# Another comment\n"
	hosts, keys := ParseSSHConfigString(raw)
	if len(hosts) != 0 {
		t.Fatalf("expected 0 hosts, got %d", len(hosts))
	}
	if len(keys) != 0 {
		t.Fatalf("expected 0 keys, got %d", len(keys))
	}
}

func TestParseSSHConfig_HostNoFields(t *testing.T) {
	raw := "Host lonely\n"
	hosts, _ := ParseSSHConfigString(raw)
	if len(hosts) != 1 {
		t.Fatalf("expected 1 host, got %d", len(hosts))
	}
	if hosts[0].Name != "lonely" {
		t.Fatalf("expected 'lonely', got '%s'", hosts[0].Name)
	}
	if hosts[0].Port != 22 {
		t.Fatalf("expected default port 22, got %d", hosts[0].Port)
	}
}

func TestOnPairSuccess_Callback(t *testing.T) {
	h := newTestHandler(t)
	token := h.GeneratePairingToken()

	var callbackDeviceID, callbackDeviceName string
	h.OnPairSuccess(func(deviceID, deviceName string) {
		callbackDeviceID = deviceID
		callbackDeviceName = deviceName
	})

	csrPEM, privKey := makeCSR(t)
	pubKeyPEM := makePubKeyPEM(t, privKey)

	body, _ := json.Marshal(PairRequest{
		DevicePublicKey: pubKeyPEM,
		DeviceName:      "callback-test",
		CSR:             csrPEM,
		Credential:      PairCredential{Kind: "bootstrap", Token: token},
		DisplayName:     "Alice",
	})
	req := httptest.NewRequest("POST", "/api/pair", strings.NewReader(string(body)))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()

	h.HandlePair(w, req)

	if w.Code != 200 {
		t.Fatalf("expected 200, got %d: %s", w.Code, w.Body.String())
	}
	if callbackDeviceID == "" {
		t.Fatal("expected callback to be invoked with device ID")
	}
	if callbackDeviceName != "callback-test" {
		t.Fatalf("expected callback device name 'callback-test', got %q", callbackDeviceName)
	}
}

func TestPairingToken_Expiry(t *testing.T) {
	h := newTestHandler(t)
	now := time.Now()
	h.now = func() time.Time { return now }
	token := h.GeneratePairingToken()

	now = now.Add(h.tokenTTL + time.Second)

	body, _ := bootstrapRequest(t, token, "Alice")
	req := httptest.NewRequest("POST", "/api/pair", strings.NewReader(string(body)))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	h.HandlePair(w, req)

	if w.Code != 401 {
		t.Fatalf("expected 401 for expired token, got %d: %s", w.Code, w.Body.String())
	}
	assertErrorCode(t, w.Body.Bytes(), "invalid_pairing_token")
}

func TestPair_Bootstrap_CreatesFirstUserAsAdmin(t *testing.T) {
	h := newTestHandler(t)
	token := h.GeneratePairingToken()
	body, _ := bootstrapRequest(t, token, "Alice")

	req := httptest.NewRequest("POST", "/api/pair", strings.NewReader(string(body)))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	h.HandlePair(w, req)

	if w.Code != 200 {
		t.Fatalf("expected 200, got %d: %s", w.Code, w.Body.String())
	}

	var resp PairResponse
	if err := json.Unmarshal(w.Body.Bytes(), &resp); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if resp.UserID == "" {
		t.Fatal("expected user_id in response")
	}
	if resp.UserDisplayName != "Alice" {
		t.Fatalf("expected user_display_name 'Alice', got %q", resp.UserDisplayName)
	}

	users, err := h.userRegistry.List()
	if err != nil {
		t.Fatalf("list users: %v", err)
	}
	if len(users) != 1 {
		t.Fatalf("expected 1 user, got %d", len(users))
	}
	if users[0].Role != "admin" {
		t.Fatalf("expected admin role, got %q", users[0].Role)
	}
	if users[0].DisplayName != "Alice" {
		t.Fatalf("expected display name 'Alice', got %q", users[0].DisplayName)
	}
}

func TestPair_Bootstrap_RejectedWhenUsersExist(t *testing.T) {
	h := newTestHandler(t)

	_, err := h.userRegistry.Create("Existing", "admin", "")
	if err != nil {
		t.Fatalf("pre-seed user: %v", err)
	}

	token := h.GeneratePairingToken()
	body, _ := bootstrapRequest(t, token, "NewUser")

	req := httptest.NewRequest("POST", "/api/pair", strings.NewReader(string(body)))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	h.HandlePair(w, req)

	if w.Code != 403 {
		t.Fatalf("expected 403, got %d: %s", w.Code, w.Body.String())
	}
	assertErrorCode(t, w.Body.Bytes(), "bootstrap_not_allowed")
}

func TestPair_Bootstrap_RequiresDisplayName(t *testing.T) {
	h := newTestHandler(t)
	token := h.GeneratePairingToken()

	csrPEM, privKey := makeCSR(t)
	pubKeyPEM := makePubKeyPEM(t, privKey)

	body, _ := json.Marshal(PairRequest{
		DevicePublicKey: pubKeyPEM,
		DeviceName:      "test-device",
		CSR:             csrPEM,
		Credential:      PairCredential{Kind: "bootstrap", Token: token},
		DisplayName:     "",
	})

	req := httptest.NewRequest("POST", "/api/pair", strings.NewReader(string(body)))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	h.HandlePair(w, req)

	if w.Code != 400 {
		t.Fatalf("expected 400, got %d: %s", w.Code, w.Body.String())
	}
	assertErrorCode(t, w.Body.Bytes(), "display_name_required")
}

func TestPair_Bootstrap_ConcurrentRequestsCreateOneUser(t *testing.T) {
	const N = 10
	h := newTestHandler(t)
	token := h.GeneratePairingToken()

	type result struct {
		status int
	}
	results := make([]result, N)
	var wg sync.WaitGroup
	wg.Add(N)

	for i := 0; i < N; i++ {
		i := i
		go func() {
			defer wg.Done()

			csrPEM, privKey := makeCSR(t)
			pubKeyPEM := makePubKeyPEM(t, privKey)
			body, _ := json.Marshal(PairRequest{
				DevicePublicKey: pubKeyPEM,
				DeviceName:      "concurrent-device",
				CSR:             csrPEM,
				Credential:      PairCredential{Kind: "bootstrap", Token: token},
				DisplayName:     "ConcurrentUser",
			})

			req := httptest.NewRequest("POST", "/api/pair", strings.NewReader(string(body)))
			req.Header.Set("Content-Type", "application/json")
			w := httptest.NewRecorder()
			h.HandlePair(w, req)
			results[i] = result{status: w.Code}
		}()
	}

	wg.Wait()

	successes := 0
	for _, r := range results {
		if r.status == 200 {
			successes++
		}
	}
	if successes != 1 {
		t.Fatalf("expected exactly 1 successful bootstrap, got %d (statuses: %v)", successes, results)
	}

	users, err := h.userRegistry.List()
	if err != nil {
		t.Fatalf("list users: %v", err)
	}
	if len(users) != 1 {
		t.Fatalf("expected exactly 1 user after concurrent bootstrap, got %d", len(users))
	}
}

func TestPair_Invite_NewUser(t *testing.T) {
	h := newTestHandler(t)

	_, err := h.userRegistry.Create("Admin", "admin", "")
	if err != nil {
		t.Fatalf("create admin: %v", err)
	}

	inv, err := h.inviteStore.Create(pki.CreateInviteParams{
		Role:      "member",
		ExpiresIn: time.Hour,
	})
	if err != nil {
		t.Fatalf("create invite: %v", err)
	}

	csrPEM, privKey := makeCSR(t)
	pubKeyPEM := makePubKeyPEM(t, privKey)

	body, _ := json.Marshal(PairRequest{
		DevicePublicKey: pubKeyPEM,
		DeviceName:      "Bob's Phone",
		CSR:             csrPEM,
		Credential:      PairCredential{Kind: "invite", Token: inv.Code},
		DisplayName:     "Bob",
	})

	req := httptest.NewRequest("POST", "/api/pair", strings.NewReader(string(body)))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	h.HandlePair(w, req)

	if w.Code != 200 {
		t.Fatalf("expected 200, got %d: %s", w.Code, w.Body.String())
	}

	var resp PairResponse
	if err := json.Unmarshal(w.Body.Bytes(), &resp); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if resp.UserID == "" {
		t.Fatal("expected user_id")
	}
	if resp.UserDisplayName != "Bob" {
		t.Fatalf("expected 'Bob', got %q", resp.UserDisplayName)
	}

	users, _ := h.userRegistry.List()
	var found bool
	for _, u := range users {
		if u.DisplayName == "Bob" && u.Role == "member" {
			found = true
		}
	}
	if !found {
		t.Fatal("expected new user 'Bob' as member in registry")
	}
}

func TestPair_Invite_AddDeviceToExistingUser(t *testing.T) {
	h := newTestHandler(t)

	bob, err := h.userRegistry.Create("Bob", "member", "")
	if err != nil {
		t.Fatalf("create bob: %v", err)
	}

	inv, err := h.inviteStore.Create(pki.CreateInviteParams{
		Role:         "member",
		ExpiresIn:    time.Hour,
		TargetUserID: bob.UserID,
	})
	if err != nil {
		t.Fatalf("create invite: %v", err)
	}

	csrPEM, privKey := makeCSR(t)
	pubKeyPEM := makePubKeyPEM(t, privKey)

	body, _ := json.Marshal(PairRequest{
		DevicePublicKey: pubKeyPEM,
		DeviceName:      "Bob's Tablet",
		CSR:             csrPEM,
		Credential:      PairCredential{Kind: "invite", Token: inv.Code},
		DisplayName:     "ShouldBeIgnored",
	})

	req := httptest.NewRequest("POST", "/api/pair", strings.NewReader(string(body)))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	h.HandlePair(w, req)

	if w.Code != 200 {
		t.Fatalf("expected 200, got %d: %s", w.Code, w.Body.String())
	}

	var resp PairResponse
	if err := json.Unmarshal(w.Body.Bytes(), &resp); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if resp.UserID != bob.UserID {
		t.Fatalf("expected user_id %q, got %q", bob.UserID, resp.UserID)
	}
	if resp.UserDisplayName != "Bob" {
		t.Fatalf("expected display name 'Bob', got %q", resp.UserDisplayName)
	}

	devices, _ := h.registry.DevicesByUserID(bob.UserID)
	if len(devices) != 1 {
		t.Fatalf("expected 1 device for bob, got %d", len(devices))
	}
}

func TestPair_Invite_PinnedFingerprintMatch(t *testing.T) {
	h := newTestHandler(t)

	_, _ = h.userRegistry.Create("Admin", "admin", "")

	csrPEM, privKey := makeCSR(t)
	pubKeyPEM := makePubKeyPEM(t, privKey)
	fp, err := pki.PubKeyFingerprint(pubKeyPEM)
	if err != nil {
		t.Fatalf("fingerprint: %v", err)
	}

	inv, err := h.inviteStore.Create(pki.CreateInviteParams{
		Role:              "member",
		ExpiresIn:         time.Hour,
		PinnedFingerprint: fp,
	})
	if err != nil {
		t.Fatalf("create invite: %v", err)
	}

	body, _ := json.Marshal(PairRequest{
		DevicePublicKey: pubKeyPEM,
		DeviceName:      "test",
		CSR:             csrPEM,
		Credential:      PairCredential{Kind: "invite", Token: inv.Code},
		DisplayName:     "Charlie",
	})

	req := httptest.NewRequest("POST", "/api/pair", strings.NewReader(string(body)))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	h.HandlePair(w, req)

	if w.Code != 200 {
		t.Fatalf("expected 200, got %d: %s", w.Code, w.Body.String())
	}
}

func TestPair_Invite_PinnedFingerprintMismatch(t *testing.T) {
	h := newTestHandler(t)

	_, _ = h.userRegistry.Create("Admin", "admin", "")

	inv, err := h.inviteStore.Create(pki.CreateInviteParams{
		Role:              "member",
		ExpiresIn:         time.Hour,
		PinnedFingerprint: "deadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeef",
	})
	if err != nil {
		t.Fatalf("create invite: %v", err)
	}

	csrPEM, privKey := makeCSR(t)
	pubKeyPEM := makePubKeyPEM(t, privKey)

	body, _ := json.Marshal(PairRequest{
		DevicePublicKey: pubKeyPEM,
		DeviceName:      "test",
		CSR:             csrPEM,
		Credential:      PairCredential{Kind: "invite", Token: inv.Code},
		DisplayName:     "Dave",
	})

	req := httptest.NewRequest("POST", "/api/pair", strings.NewReader(string(body)))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	h.HandlePair(w, req)

	if w.Code != 403 {
		t.Fatalf("expected 403, got %d: %s", w.Code, w.Body.String())
	}
	assertErrorCode(t, w.Body.Bytes(), "device_pin_mismatch")

	updated, _ := h.inviteStore.FindByCode(inv.Code)
	if updated == nil {
		t.Fatal("invite not found after mismatch")
	}
	if updated.ConsumedAt != "" {
		t.Fatal("invite must not be consumed on pin mismatch")
	}
}

func TestPair_Invite_ExpiredRejected(t *testing.T) {
	h := newTestHandler(t)

	inv, err := h.inviteStore.Create(pki.CreateInviteParams{
		Role:      "member",
		ExpiresIn: -1 * time.Second,
	})
	if err != nil {
		t.Fatalf("create invite: %v", err)
	}

	h.inviteStore.Sweep(time.Now())

	csrPEM, privKey := makeCSR(t)
	pubKeyPEM := makePubKeyPEM(t, privKey)

	body, _ := json.Marshal(PairRequest{
		DevicePublicKey: pubKeyPEM,
		DeviceName:      "test",
		CSR:             csrPEM,
		Credential:      PairCredential{Kind: "invite", Token: inv.Code},
		DisplayName:     "Eve",
	})

	req := httptest.NewRequest("POST", "/api/pair", strings.NewReader(string(body)))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	h.HandlePair(w, req)

	if w.Code != 410 {
		t.Fatalf("expected 410, got %d: %s", w.Code, w.Body.String())
	}
	assertErrorCode(t, w.Body.Bytes(), "invite_expired")
}

func TestPair_Invite_ConsumedRejected(t *testing.T) {
	h := newTestHandler(t)

	_, _ = h.userRegistry.Create("Admin", "admin", "")

	inv, err := h.inviteStore.Create(pki.CreateInviteParams{
		Role:      "member",
		ExpiresIn: time.Hour,
	})
	if err != nil {
		t.Fatalf("create invite: %v", err)
	}

	csrPEM, privKey := makeCSR(t)
	pubKeyPEM := makePubKeyPEM(t, privKey)
	body, _ := json.Marshal(PairRequest{
		DevicePublicKey: pubKeyPEM,
		DeviceName:      "first",
		CSR:             csrPEM,
		Credential:      PairCredential{Kind: "invite", Token: inv.Code},
		DisplayName:     "Frank",
	})
	req := httptest.NewRequest("POST", "/api/pair", strings.NewReader(string(body)))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	h.HandlePair(w, req)
	if w.Code != 200 {
		t.Fatalf("first redemption: expected 200, got %d", w.Code)
	}

	csrPEM2, privKey2 := makeCSR(t)
	pubKeyPEM2 := makePubKeyPEM(t, privKey2)
	body2, _ := json.Marshal(PairRequest{
		DevicePublicKey: pubKeyPEM2,
		DeviceName:      "second",
		CSR:             csrPEM2,
		Credential:      PairCredential{Kind: "invite", Token: inv.Code},
		DisplayName:     "Frank2",
	})
	req2 := httptest.NewRequest("POST", "/api/pair", strings.NewReader(string(body2)))
	req2.Header.Set("Content-Type", "application/json")
	w2 := httptest.NewRecorder()
	h.HandlePair(w2, req2)

	if w2.Code != 409 {
		t.Fatalf("expected 409, got %d: %s", w2.Code, w2.Body.String())
	}
	assertErrorCode(t, w2.Body.Bytes(), "invite_consumed")
}

func invitePairWithKey(t *testing.T, h *PairingHandler, pubKeyPEM, csrPEM, code, displayName string) *httptest.ResponseRecorder {
	t.Helper()
	body, _ := json.Marshal(PairRequest{
		DevicePublicKey: pubKeyPEM,
		DeviceName:      "phone",
		CSR:             csrPEM,
		Credential:      PairCredential{Kind: "invite", Token: code},
		DisplayName:     displayName,
	})
	req := httptest.NewRequest("POST", "/api/pair", strings.NewReader(string(body)))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	h.HandlePair(w, req)
	return w
}

func decodePairResponse(t *testing.T, w *httptest.ResponseRecorder) PairResponse {
	t.Helper()
	var resp PairResponse
	if err := json.Unmarshal(w.Body.Bytes(), &resp); err != nil {
		t.Fatalf("unmarshal pair response: %v (raw: %s)", err, w.Body.String())
	}
	if resp.ClientCert == "" {
		t.Fatal("pair response carries no client cert")
	}
	return resp
}

func TestPair_Invite_StillActiveDeviceRepairsKeepingNewMemberInvite(t *testing.T) {
	h := newTestHandler(t)
	_, _ = h.userRegistry.Create("Admin", "admin", "")

	inv1, err := h.inviteStore.Create(pki.CreateInviteParams{Role: "member", ExpiresIn: time.Hour})
	if err != nil {
		t.Fatalf("create invite 1: %v", err)
	}
	inv2, err := h.inviteStore.Create(pki.CreateInviteParams{Role: "admin", ExpiresIn: time.Hour})
	if err != nil {
		t.Fatalf("create invite 2: %v", err)
	}

	csrPEM, privKey := makeCSR(t)
	pubKeyPEM := makePubKeyPEM(t, privKey)

	w1 := invitePairWithKey(t, h, pubKeyPEM, csrPEM, inv1.Code, "Grace")
	if w1.Code != 200 {
		t.Fatalf("first pair: expected 200, got %d: %s", w1.Code, w1.Body.String())
	}
	first := decodePairResponse(t, w1)
	usersAfterFirst, _ := h.userRegistry.List()

	w2 := invitePairWithKey(t, h, pubKeyPEM, makeCSRForKey(t, privKey), inv2.Code, "Grace2")
	if w2.Code != 200 {
		t.Fatalf("re-pair: expected 200, got %d: %s", w2.Code, w2.Body.String())
	}
	second := decodePairResponse(t, w2)
	if second.UserID != first.UserID || second.DeviceID != first.DeviceID {
		t.Fatalf("re-pair switched identity: %s/%s -> %s/%s",
			first.UserID, first.DeviceID, second.UserID, second.DeviceID)
	}
	if second.UserRole != "member" || second.UserDisplayName != "Grace" {
		t.Fatalf("re-pair took role/name from the invite: role=%q name=%q",
			second.UserRole, second.UserDisplayName)
	}

	usersAfterSecond, _ := h.userRegistry.List()
	if len(usersAfterSecond) != len(usersAfterFirst) {
		t.Fatalf("re-pair created a user: %d -> %d", len(usersAfterFirst), len(usersAfterSecond))
	}
	inv2After, _ := h.inviteStore.FindByCode(inv2.Code)
	if inv2After.ConsumedAt != "" {
		t.Fatal("re-pair consumed a new-member invite meant for someone else")
	}
}

func TestPair_Invite_StillActiveDeviceRepairsWithOwnSecondDeviceInvite(t *testing.T) {
	h := newTestHandler(t)
	_, _ = h.userRegistry.Create("Admin", "admin", "")

	joinInv, err := h.inviteStore.Create(pki.CreateInviteParams{Role: "member", ExpiresIn: time.Hour})
	if err != nil {
		t.Fatalf("create join invite: %v", err)
	}
	csrPEM, privKey := makeCSR(t)
	pubKeyPEM := makePubKeyPEM(t, privKey)
	if w := invitePairWithKey(t, h, pubKeyPEM, csrPEM, joinInv.Code, "Heidi"); w.Code != 200 {
		t.Fatalf("first pair: expected 200, got %d: %s", w.Code, w.Body.String())
	}
	dev, ok := h.registry.LookupByPublicKeyPEM(pubKeyPEM)
	if !ok {
		t.Fatal("device not registered after pair")
	}

	ownInv, err := h.inviteStore.Create(pki.CreateInviteParams{
		Role:         "member",
		ExpiresIn:    time.Hour,
		TargetUserID: dev.UserID,
	})
	if err != nil {
		t.Fatalf("create own invite: %v", err)
	}
	usersBefore, _ := h.userRegistry.List()

	w := invitePairWithKey(t, h, pubKeyPEM, csrPEM, ownInv.Code, "")
	if w.Code != 200 {
		t.Fatalf("re-pair: expected 200, got %d: %s", w.Code, w.Body.String())
	}
	resp := decodePairResponse(t, w)
	if resp.UserID != dev.UserID || resp.DeviceID != dev.DeviceID {
		t.Fatalf("re-pair returned %s/%s, want %s/%s", resp.UserID, resp.DeviceID, dev.UserID, dev.DeviceID)
	}

	after, _ := h.inviteStore.FindByCode(ownInv.Code)
	if after.ConsumedAt == "" || after.ConsumedByDeviceID != dev.DeviceID {
		t.Fatalf("own invite not retired by the re-paired device: consumed_at=%q by=%q",
			after.ConsumedAt, after.ConsumedByDeviceID)
	}
	usersAfter, _ := h.userRegistry.List()
	if len(usersAfter) != len(usersBefore) {
		t.Fatalf("re-pair created a user: %d -> %d", len(usersBefore), len(usersAfter))
	}
	devices, _ := h.registry.DevicesByUserID(dev.UserID)
	if len(devices) != 1 || devices[0].Status != "active" {
		t.Fatalf("expected the one active device to stay, got %+v", devices)
	}

	if w := invitePairWithKey(t, h, pubKeyPEM, csrPEM, ownInv.Code, ""); w.Code != 200 {
		t.Fatalf("repeat of own redemption: expected 200, got %d: %s", w.Code, w.Body.String())
	}
}

func TestPair_Invite_StillActiveDeviceOtherUsersInviteRefusedUnconsumed(t *testing.T) {
	h := newTestHandler(t)
	_, _ = h.userRegistry.Create("Admin", "admin", "")
	bob, err := h.userRegistry.Create("Bob", "member", "")
	if err != nil {
		t.Fatalf("create bob: %v", err)
	}

	joinInv, _ := h.inviteStore.Create(pki.CreateInviteParams{Role: "member", ExpiresIn: time.Hour})
	csrPEM, privKey := makeCSR(t)
	pubKeyPEM := makePubKeyPEM(t, privKey)
	if w := invitePairWithKey(t, h, pubKeyPEM, csrPEM, joinInv.Code, "Heidi"); w.Code != 200 {
		t.Fatalf("first pair: expected 200, got %d: %s", w.Code, w.Body.String())
	}
	dev, _ := h.registry.LookupByPublicKeyPEM(pubKeyPEM)

	bobInv, err := h.inviteStore.Create(pki.CreateInviteParams{
		Role: "member", ExpiresIn: time.Hour, TargetUserID: bob.UserID,
	})
	if err != nil {
		t.Fatalf("create bob invite: %v", err)
	}
	w := invitePairWithKey(t, h, pubKeyPEM, csrPEM, bobInv.Code, "")
	if w.Code != 409 {
		t.Fatalf("expected 409, got %d: %s", w.Code, w.Body.String())
	}
	assertErrorCode(t, w.Body.Bytes(), "device_already_paired")

	after, _ := h.inviteStore.FindByCode(bobInv.Code)
	if after.ConsumedAt != "" {
		t.Fatal("the refused attempt burned another user's invite")
	}
	still, _ := h.registry.LookupByPublicKeyPEM(pubKeyPEM)
	if still.UserID != dev.UserID || still.Status != "active" {
		t.Fatalf("refused attempt changed the registration: %+v", still)
	}
}

func TestPair_Invite_LostResponseRetryRepairs(t *testing.T) {
	h := newTestHandler(t)
	_, _ = h.userRegistry.Create("Admin", "admin", "")
	inv, _ := h.inviteStore.Create(pki.CreateInviteParams{Role: "member", ExpiresIn: time.Hour})

	csrPEM, privKey := makeCSR(t)
	pubKeyPEM := makePubKeyPEM(t, privKey)
	w1 := invitePairWithKey(t, h, pubKeyPEM, csrPEM, inv.Code, "Ivan")
	if w1.Code != 200 {
		t.Fatalf("first pair: expected 200, got %d: %s", w1.Code, w1.Body.String())
	}
	first := decodePairResponse(t, w1)
	usersBefore, _ := h.userRegistry.List()

	w2 := invitePairWithKey(t, h, pubKeyPEM, csrPEM, inv.Code, "Ivan")
	if w2.Code != 200 {
		t.Fatalf("retry: expected 200, got %d: %s", w2.Code, w2.Body.String())
	}
	second := decodePairResponse(t, w2)
	if second.UserID != first.UserID || second.DeviceID != first.DeviceID {
		t.Fatalf("retry switched identity: %s/%s -> %s/%s",
			first.UserID, first.DeviceID, second.UserID, second.DeviceID)
	}
	usersAfter, _ := h.userRegistry.List()
	if len(usersAfter) != len(usersBefore) {
		t.Fatalf("retry created a user: %d -> %d", len(usersBefore), len(usersAfter))
	}

	csr2, priv2 := makeCSR(t)
	pub2 := makePubKeyPEM(t, priv2)
	other, _ := h.inviteStore.Create(pki.CreateInviteParams{Role: "member", ExpiresIn: time.Hour})
	if w := invitePairWithKey(t, h, pub2, csr2, other.Code, "Judy"); w.Code != 200 {
		t.Fatalf("second device pair: expected 200, got %d: %s", w.Code, w.Body.String())
	}
	w3 := invitePairWithKey(t, h, pub2, csr2, inv.Code, "Judy")
	if w3.Code != 409 {
		t.Fatalf("foreign consumed invite: expected 409, got %d: %s", w3.Code, w3.Body.String())
	}
	assertErrorCode(t, w3.Body.Bytes(), "invite_consumed")
}

func TestPair_Invite_RevokedDeviceKeyRefused(t *testing.T) {
	h := newTestHandler(t)
	_, _ = h.userRegistry.Create("Admin", "admin", "")

	inv1, err := h.inviteStore.Create(pki.CreateInviteParams{Role: "member", ExpiresIn: time.Hour})
	if err != nil {
		t.Fatalf("create invite 1: %v", err)
	}
	csrPEM, privKey := makeCSR(t)
	pubKeyPEM := makePubKeyPEM(t, privKey)
	pair := func(code, name string) *httptest.ResponseRecorder {
		body, _ := json.Marshal(PairRequest{
			DevicePublicKey: pubKeyPEM,
			DeviceName:      "phone",
			CSR:             csrPEM,
			Credential:      PairCredential{Kind: "invite", Token: code},
			DisplayName:     name,
		})
		req := httptest.NewRequest("POST", "/api/pair", strings.NewReader(string(body)))
		req.Header.Set("Content-Type", "application/json")
		w := httptest.NewRecorder()
		h.HandlePair(w, req)
		return w
	}
	if w := pair(inv1.Code, "Grace"); w.Code != 200 {
		t.Fatalf("first pair: expected 200, got %d: %s", w.Code, w.Body.String())
	}
	dev, found := h.registry.LookupByPublicKeyPEM(pubKeyPEM)
	if !found {
		t.Fatal("device not registered")
	}
	if err := h.registry.Revoke(dev.DeviceID); err != nil {
		t.Fatalf("revoke: %v", err)
	}

	inv2, err := h.inviteStore.Create(pki.CreateInviteParams{
		Role: "member", ExpiresIn: time.Hour, TargetUserID: dev.UserID,
	})
	if err != nil {
		t.Fatalf("create invite 2: %v", err)
	}
	w := pair(inv2.Code, "")
	if w.Code != 403 {
		t.Fatalf("expected 403 device_revoked, got %d: %s", w.Code, w.Body.String())
	}
	assertErrorCode(t, w.Body.Bytes(), "device_revoked")

	after, _ := h.inviteStore.FindByCode(inv2.Code)
	if after.ConsumedAt != "" {
		t.Fatal("the refused attempt burned the invite")
	}
	still, _ := h.registry.LookupByPublicKeyPEM(pubKeyPEM)
	if still.Status == "active" {
		t.Fatal("a revoked key was silently re-admitted")
	}
}

func TestPair_Invite_RevokedRejected(t *testing.T) {
	h := newTestHandler(t)

	inv, err := h.inviteStore.Create(pki.CreateInviteParams{
		Role:      "member",
		ExpiresIn: time.Hour,
	})
	if err != nil {
		t.Fatalf("create invite: %v", err)
	}

	if err := h.inviteStore.Revoke(inv.Code, "admin-uid"); err != nil {
		t.Fatalf("revoke: %v", err)
	}

	csrPEM, privKey := makeCSR(t)
	pubKeyPEM := makePubKeyPEM(t, privKey)
	body, _ := json.Marshal(PairRequest{
		DevicePublicKey: pubKeyPEM,
		DeviceName:      "test",
		CSR:             csrPEM,
		Credential:      PairCredential{Kind: "invite", Token: inv.Code},
		DisplayName:     "Grace",
	})

	req := httptest.NewRequest("POST", "/api/pair", strings.NewReader(string(body)))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	h.HandlePair(w, req)

	if w.Code != 410 {
		t.Fatalf("expected 410, got %d: %s", w.Code, w.Body.String())
	}
	assertErrorCode(t, w.Body.Bytes(), "invite_revoked")
}

func TestPair_Invite_UnknownCodeRejected(t *testing.T) {
	h := newTestHandler(t)

	csrPEM, privKey := makeCSR(t)
	pubKeyPEM := makePubKeyPEM(t, privKey)
	body, _ := json.Marshal(PairRequest{
		DevicePublicKey: pubKeyPEM,
		DeviceName:      "test",
		CSR:             csrPEM,
		Credential:      PairCredential{Kind: "invite", Token: "unknowncodexxxxxx"},
		DisplayName:     "Hank",
	})

	req := httptest.NewRequest("POST", "/api/pair", strings.NewReader(string(body)))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	h.HandlePair(w, req)

	if w.Code != 404 {
		t.Fatalf("expected 404, got %d: %s", w.Code, w.Body.String())
	}
	assertErrorCode(t, w.Body.Bytes(), "invite_not_found")
}

func TestPair_Invite_BadCSRDoesNotConsumeInvite(t *testing.T) {
	h := newTestHandler(t)

	_, _ = h.userRegistry.Create("Admin", "admin", "")

	inv, err := h.inviteStore.Create(pki.CreateInviteParams{
		Role:      "member",
		ExpiresIn: time.Hour,
	})
	if err != nil {
		t.Fatalf("create invite: %v", err)
	}

	csrPEM, privKey := makeCSR(t)
	pubKeyPEM := makePubKeyPEM(t, privKey)

	body, _ := json.Marshal(PairRequest{
		DevicePublicKey: pubKeyPEM,
		DeviceName:      "test-device",
		CSR:             "this is not a valid CSR",
		Credential:      PairCredential{Kind: "invite", Token: inv.Code},
		DisplayName:     "Ivy",
	})
	req := httptest.NewRequest("POST", "/api/pair", strings.NewReader(string(body)))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	h.HandlePair(w, req)

	if w.Code != 400 {
		t.Fatalf("expected 400 on bad CSR, got %d: %s", w.Code, w.Body.String())
	}

	updated, findErr := h.inviteStore.FindByCode(inv.Code)
	if findErr != nil {
		t.Fatalf("find invite: %v", findErr)
	}
	if updated == nil {
		t.Fatal("invite not found after failed redemption")
	}
	if updated.ConsumedAt != "" {
		t.Fatalf("invite must not be consumed after sign failure, but ConsumedAt=%q", updated.ConsumedAt)
	}

	body2, _ := json.Marshal(PairRequest{
		DevicePublicKey: pubKeyPEM,
		DeviceName:      "test-device",
		CSR:             csrPEM,
		Credential:      PairCredential{Kind: "invite", Token: inv.Code},
		DisplayName:     "Ivy",
	})
	req2 := httptest.NewRequest("POST", "/api/pair", strings.NewReader(string(body2)))
	req2.Header.Set("Content-Type", "application/json")
	w2 := httptest.NewRecorder()
	h.HandlePair(w2, req2)

	if w2.Code != 200 {
		t.Fatalf("retry with valid CSR: expected 200, got %d: %s", w2.Code, w2.Body.String())
	}
}

func TestPair_Invite_RequiresDisplayName(t *testing.T) {
	h := newTestHandler(t)

	_, err := h.userRegistry.Create("Admin", "admin", "")
	if err != nil {
		t.Fatalf("create admin: %v", err)
	}

	inv, err := h.inviteStore.Create(pki.CreateInviteParams{
		Role:      "member",
		ExpiresIn: time.Hour,
	})
	if err != nil {
		t.Fatalf("create invite: %v", err)
	}

	csrPEM, privKey := makeCSR(t)
	pubKeyPEM := makePubKeyPEM(t, privKey)

	body, _ := json.Marshal(PairRequest{
		DevicePublicKey: pubKeyPEM,
		DeviceName:      "test-device",
		CSR:             csrPEM,
		Credential:      PairCredential{Kind: "invite", Token: inv.Code},
		DisplayName:     "",
	})

	req := httptest.NewRequest("POST", "/api/pair", strings.NewReader(string(body)))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	h.HandlePair(w, req)

	if w.Code != 400 {
		t.Fatalf("expected 400, got %d: %s", w.Code, w.Body.String())
	}
	assertErrorCode(t, w.Body.Bytes(), "display_name_required")
}

func TestPair_Invite_RacedClaimHasNoSideEffects(t *testing.T) {
	h := newTestHandler(t)
	_, _ = h.userRegistry.Create("Admin", "admin", "")

	inv, err := h.inviteStore.Create(pki.CreateInviteParams{
		Role:      "member",
		ExpiresIn: time.Hour,
	})
	if err != nil {
		t.Fatalf("create invite: %v", err)
	}

	if err := h.inviteStore.MarkConsumed(inv.Code, "winner-device-01"); err != nil {
		t.Fatalf("winner consume: %v", err)
	}

	usersBefore, _ := h.userRegistry.List()
	devicesBefore, _ := h.registry.List()

	csrPEM, privKey := makeCSR(t)
	pubKeyPEM := makePubKeyPEM(t, privKey)
	body, _ := json.Marshal(PairRequest{
		DevicePublicKey: pubKeyPEM,
		DeviceName:      "loser",
		CSR:             csrPEM,
		Credential:      PairCredential{Kind: "invite", Token: inv.Code},
		DisplayName:     "Loser",
	})
	req := httptest.NewRequest("POST", "/api/pair", strings.NewReader(string(body)))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	h.HandlePair(w, req)

	if w.Code != 409 {
		t.Fatalf("expected 409, got %d: %s", w.Code, w.Body.String())
	}
	assertErrorCode(t, w.Body.Bytes(), "invite_consumed")

	usersAfter, _ := h.userRegistry.List()
	if len(usersAfter) != len(usersBefore) {
		t.Fatalf("losing racer created a user: %d -> %d", len(usersBefore), len(usersAfter))
	}
	devicesAfter, _ := h.registry.List()
	if len(devicesAfter) != len(devicesBefore) {
		t.Fatalf("losing racer registered a device: %d -> %d", len(devicesBefore), len(devicesAfter))
	}
	after, _ := h.inviteStore.FindByCode(inv.Code)
	if after.ConsumedByDeviceID != "winner-device-01" {
		t.Fatalf("claim attribution changed: %q", after.ConsumedByDeviceID)
	}
}

func assertErrorCode(t *testing.T, body []byte, expected string) {
	t.Helper()
	var errBody struct {
		Error string `json:"error"`
	}
	if err := json.Unmarshal(body, &errBody); err != nil {
		t.Fatalf("unmarshal error body: %v (raw: %s)", err, string(body))
	}
	if errBody.Error != expected {
		t.Fatalf("expected error code %q, got %q", expected, errBody.Error)
	}
}

func postPair(t *testing.T, h *PairingHandler, body []byte) int {
	t.Helper()
	req := httptest.NewRequest("POST", "/api/pair", strings.NewReader(string(body)))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	h.HandlePair(w, req)
	return w.Code
}

func TestGeneratePairingToken_RefreshReplacesExpiredToken(t *testing.T) {
	h := newTestHandler(t)
	if h.TokenTTL() != DefaultTokenTTL {
		t.Fatalf("TokenTTL() = %v, want %v", h.TokenTTL(), DefaultTokenTTL)
	}
	now := time.Now()
	h.now = func() time.Time { return now }
	expired := h.GeneratePairingToken()
	now = now.Add(h.TokenTTL())
	fresh := h.GeneratePairingToken()

	stale, _ := bootstrapRequest(t, expired, "Alice")
	if code := postPair(t, h, stale); code != 401 {
		t.Fatalf("expired token: expected 401, got %d", code)
	}
	body, _ := bootstrapRequest(t, fresh, "Alice")
	if code := postPair(t, h, body); code != 200 {
		t.Fatalf("refreshed token: expected 200, got %d", code)
	}
}

func TestHandlePair_RepairAfterRotationNeedsNoToken(t *testing.T) {
	db, err := state.Open(t.TempDir())
	if err != nil {
		t.Fatalf("state.Open: %v", err)
	}
	t.Cleanup(func() { db.Close() })
	registry := pki.NewDeviceRegistry(db)
	users := pki.NewUserRegistry(db)
	invites := pki.NewInviteStore(db)
	newHandler := func() *PairingHandler {
		key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		if err != nil {
			t.Fatalf("generate server key: %v", err)
		}
		return NewPairingHandler(registry, users, invites, key, "fp", "host", "https://host:8767")
	}

	before := newHandler()
	token := before.GeneratePairingToken()
	csrPEM, privKey := makeCSR(t)
	pubKeyPEM := makePubKeyPEM(t, privKey)
	first, _ := json.Marshal(PairRequest{
		DevicePublicKey: pubKeyPEM,
		DeviceName:      "Pixel",
		CSR:             csrPEM,
		Credential:      PairCredential{Kind: "bootstrap", Token: token},
		DisplayName:     "Alice",
	})
	if code := postPair(t, before, first); code != 200 {
		t.Fatalf("bootstrap: expected 200, got %d", code)
	}

	after := newHandler()
	repair, _ := json.Marshal(PairRequest{
		DevicePublicKey: pubKeyPEM,
		DeviceName:      "Pixel",
		CSR:             makeCSRForKey(t, privKey),
		Credential:      PairCredential{Kind: "bootstrap", Token: "0123456789abcdef0123456789abcdef"},
	})
	if code := postPair(t, after, repair); code != 200 {
		t.Fatalf("re-pair of a registered device: expected 200, got %d", code)
	}

	stranger, _ := bootstrapRequest(t, "0123456789abcdef0123456789abcdef", "Mallory")
	if code := postPair(t, after, stranger); code != 401 {
		t.Fatalf("unknown device with the re-pair code: expected 401, got %d", code)
	}
}

func TestPair_LengthCaps(t *testing.T) {
	h := newTestHandler(t)
	send := func(req PairRequest) (int, string) {
		body, _ := json.Marshal(req)
		w := httptest.NewRecorder()
		h.HandlePair(w, httptest.NewRequest("POST", "/api/pair", strings.NewReader(string(body))))
		var e struct {
			Error string `json:"error"`
		}
		_ = json.Unmarshal(w.Body.Bytes(), &e)
		return w.Code, e.Error
	}
	fresh := func(token, displayName, deviceName, label string) PairRequest {
		csrPEM, priv := makeCSR(t)
		return PairRequest{
			DevicePublicKey: makePubKeyPEM(t, priv),
			DeviceName:      deviceName,
			DeviceLabel:     label,
			CSR:             csrPEM,
			Credential:      PairCredential{Kind: "bootstrap", Token: token},
			DisplayName:     displayName,
		}
	}

	token := h.GeneratePairingToken()
	if code, e := send(fresh(token, strings.Repeat("ü", pki.MaxDisplayNameLen+1), "dev", "")); code != 400 || e != "display_name_too_long" {
		t.Fatalf("over-long display name: %d %s", code, e)
	}
	if code, e := send(fresh(token, "ok", strings.Repeat("ü", pki.MaxDeviceNameLen+1), "")); code != 400 || e != "name_too_long" {
		t.Fatalf("over-long device name: %d %s", code, e)
	}
	if code, e := send(fresh(token, "ok", "dev", strings.Repeat("ü", pki.MaxDeviceNameLen+1))); code != 400 || e != "name_too_long" {
		t.Fatalf("over-long device label: %d %s", code, e)
	}
	name := strings.Repeat("ü", pki.MaxDisplayNameLen)
	dev := strings.Repeat("ü", pki.MaxDeviceNameLen)
	if code, e := send(fresh(token, name, dev, dev)); code != 200 {
		t.Fatalf("at-cap values: %d %s", code, e)
	}
	users, _ := h.userRegistry.List()
	if len(users) != 1 || users[0].DisplayName != name {
		t.Fatalf("display name must be stored untruncated, got %+v", users)
	}
	devices, _ := h.registry.List()
	if len(devices) != 1 || devices[0].DeviceName != dev || devices[0].DeviceLabel != dev {
		t.Fatalf("device fields must be stored untruncated, got %+v", devices)
	}

	inv, err := h.inviteStore.Create(pki.CreateInviteParams{Role: "member", ExpiresIn: time.Hour})
	if err != nil {
		t.Fatal(err)
	}
	invReq := func(displayName, deviceName string) PairRequest {
		r := fresh("", displayName, deviceName, "")
		r.Credential = PairCredential{Kind: "invite", Token: inv.Code}
		return r
	}
	if code, e := send(invReq(strings.Repeat("x", pki.MaxDisplayNameLen+1), "dev")); code != 400 || e != "display_name_too_long" {
		t.Fatalf("invite over-long display name: %d %s", code, e)
	}
	if code, e := send(invReq("ok", strings.Repeat("x", pki.MaxDeviceNameLen+1))); code != 400 || e != "name_too_long" {
		t.Fatalf("invite over-long device name: %d %s", code, e)
	}
	if got, _ := h.inviteStore.FindByCode(inv.Code); got.ConsumedAt != "" {
		t.Fatal("refused redemptions must not consume the invite")
	}
	if code, e := send(invReq("ok", "dev")); code != 200 {
		t.Fatalf("valid invite redemption: %d %s", code, e)
	}
}

func TestPair_RejectsNonP256Key(t *testing.T) {
	h := newTestHandler(t)
	priv, err := ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	token := h.GeneratePairingToken()
	body, _ := json.Marshal(PairRequest{
		DevicePublicKey: makePubKeyPEM(t, priv),
		DeviceName:      "dev",
		CSR:             makeCSRForKey(t, priv),
		Credential:      PairCredential{Kind: "bootstrap", Token: token},
		DisplayName:     "ok",
	})
	w := httptest.NewRecorder()
	h.HandlePair(w, httptest.NewRequest("POST", "/api/pair", strings.NewReader(string(body))))
	if w.Code != http.StatusBadRequest || !strings.Contains(w.Body.String(), "invalid_public_key") {
		t.Fatalf("expected 400 invalid_public_key, got %d %s", w.Code, w.Body.String())
	}
	if devices, _ := h.registry.List(); len(devices) != 0 {
		t.Fatal("nothing may be registered")
	}
	if !h.activeToken.used {
		body, _ := bootstrapRequest(t, token, "ok")
		w := httptest.NewRecorder()
		h.HandlePair(w, httptest.NewRequest("POST", "/api/pair", strings.NewReader(string(body))))
		if w.Code != http.StatusOK {
			t.Fatalf("token must survive a refused request: %d %s", w.Code, w.Body.String())
		}
	}
}

func TestPair_Invite_ExpiryFollowsHandlerClock(t *testing.T) {
	h := newTestHandler(t)
	now := time.Now()
	h.now = func() time.Time { return now }

	inv, err := h.inviteStore.Create(pki.CreateInviteParams{
		Role:      pki.RoleMember,
		ExpiresIn: time.Hour,
	})
	if err != nil {
		t.Fatalf("create invite: %v", err)
	}

	now = now.Add(time.Hour + time.Second)

	csrPEM, privKey := makeCSR(t)
	body, _ := json.Marshal(PairRequest{
		DevicePublicKey: makePubKeyPEM(t, privKey),
		DeviceName:      "test",
		CSR:             csrPEM,
		Credential:      PairCredential{Kind: "invite", Token: inv.Code},
		DisplayName:     "Eve",
	})
	req := httptest.NewRequest("POST", "/api/pair", strings.NewReader(string(body)))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	h.HandlePair(w, req)

	if w.Code != http.StatusGone {
		t.Fatalf("expected 410 on the advanced clock, got %d: %s", w.Code, w.Body.String())
	}
	assertErrorCode(t, w.Body.Bytes(), "invite_expired")
}

func TestSweepRateLimits_DropsOnlyExpiredWindows(t *testing.T) {
	h := newTestHandler(t)
	now := time.Now()
	h.now = func() time.Time { return now }

	h.recordFailedAttempt("10.0.0.1")
	now = now.Add(RateLimitWindow / 2)
	h.recordFailedAttempt("10.0.0.2")

	h.SweepRateLimits(now.Add(RateLimitWindow/2 + time.Second))

	h.mu.Lock()
	_, first := h.rateLimits["10.0.0.1"]
	_, second := h.rateLimits["10.0.0.2"]
	h.mu.Unlock()
	if first {
		t.Fatal("expired window for 10.0.0.1 should have been swept")
	}
	if !second {
		t.Fatal("live window for 10.0.0.2 must survive the sweep")
	}
}
