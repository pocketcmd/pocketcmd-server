package server

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"database/sql"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"io"
	"math/big"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/pocketcmd/pocketcmd-server/internal/config"
	"github.com/pocketcmd/pocketcmd-server/internal/metrics"
	"github.com/pocketcmd/pocketcmd-server/internal/pair"
	"github.com/pocketcmd/pocketcmd-server/internal/pki"
	"github.com/pocketcmd/pocketcmd-server/internal/push"
	"github.com/pocketcmd/pocketcmd-server/internal/session"
)

func apiRequest(method, target string, body io.Reader) *http.Request {
	req := httptest.NewRequest(method, target, body)
	req.Header.Set(APIVersionHeader, APIVersion)
	return req
}

func issueTestClientCert(t *testing.T, serverKey *ecdsa.PrivateKey, pub any, ttl time.Duration) *x509.Certificate {
	t.Helper()
	der, err := pki.IssueClientCert(pkix.Name{CommonName: "pocketcmd-client"}, pub, serverKey, ttl)
	if err != nil {
		t.Fatal(err)
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatal(err)
	}
	return cert
}

func testVerifier(t *testing.T, serverKey *ecdsa.PrivateKey) *pki.ClientCertVerifier {
	t.Helper()
	v, err := pki.NewClientCertVerifier(serverKey)
	if err != nil {
		t.Fatal(err)
	}
	return v
}

func testRegistries(t *testing.T) (*pki.DeviceRegistry, *pki.UserRegistry) {
	t.Helper()
	db := testStateDB(t)
	seedTestUser(t, db)
	return testDeviceRegistryOn(db), pki.NewUserRegistry(db)
}

func seedTestUser(t *testing.T, db *sql.DB) {
	t.Helper()
	if _, err := db.Exec(`INSERT OR IGNORE INTO users (user_id, display_name, role, status, created_at)
		VALUES ('test-user', 'test user', 'admin', 'active', ?)`, time.Now().UTC().Format(time.RFC3339)); err != nil {
		t.Fatal(err)
	}
}

func registerTestDevice(t *testing.T, registry *pki.DeviceRegistry, serverKey *ecdsa.PrivateKey) (certPEM []byte, keyPEM []byte, deviceID string) {
	t.Helper()
	deviceKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}

	pubDER, err := x509.MarshalPKIXPublicKey(&deviceKey.PublicKey)
	if err != nil {
		t.Fatal(err)
	}
	pubPEM := string(pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: pubDER}))

	deviceID, err = registry.RegisterDeviceForUser(pubPEM, "test-device", "test-user", "")
	if err != nil {
		t.Fatal(err)
	}

	certDER := issueTestClientCert(t, serverKey, &deviceKey.PublicKey, 30*time.Minute).Raw
	certPEM = pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: certDER})

	privDER, err := x509.MarshalECPrivateKey(deviceKey)
	if err != nil {
		t.Fatal(err)
	}
	keyPEM = pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: privDER})
	return certPEM, keyPEM, deviceID
}

func bindDeviceToAdminUser(t *testing.T, registry *pki.DeviceRegistry, users *pki.UserRegistry, deviceID string) {
	t.Helper()
	u, err := users.Create("test-admin", "admin", "")
	if err != nil {
		t.Fatalf("create admin user: %v", err)
	}
	bindDeviceToUserID(t, registry, deviceID, u.UserID)
}

func bindDeviceToMemberUser(t *testing.T, registry *pki.DeviceRegistry, users *pki.UserRegistry, deviceID string) {
	t.Helper()
	u, err := users.Create("test-member", "member", "")
	if err != nil {
		t.Fatalf("create member user: %v", err)
	}
	bindDeviceToUserID(t, registry, deviceID, u.UserID)
}

func parseCertificate(t *testing.T, certPEM []byte) *x509.Certificate {
	t.Helper()
	block, _ := pem.Decode(certPEM)
	if block == nil {
		t.Fatal("failed to decode certificate PEM")
	}
	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		t.Fatal(err)
	}
	return cert
}

func requestWithTLS(method, url string, body []byte, cert *x509.Certificate) *http.Request {
	var req *http.Request
	if body != nil {
		req = apiRequest(method, url, bytes.NewReader(body))
	} else {
		req = apiRequest(method, url, nil)
	}
	req.TLS = &tls.ConnectionState{
		PeerCertificates: []*x509.Certificate{cert},
	}
	return req
}

func TestHealthEndpoint(t *testing.T) {
	cfg := &config.ServerConfig{Host: "127.0.0.1", Port: 8767}
	srv := NewServer(cfg)

	req := apiRequest("GET", "/api/health", nil)
	w := httptest.NewRecorder()
	srv.ServeHTTP(w, req)

	if w.Code != 200 {
		t.Fatalf("expected 200, got %d", w.Code)
	}

	var body map[string]interface{}
	json.Unmarshal(w.Body.Bytes(), &body)
	if body["status"] != "ok" {
		t.Fatalf("expected status ok, got %v", body["status"])
	}
}

func TestHealthEndpoint_DBUnavailable(t *testing.T) {
	srv := NewServer(&config.ServerConfig{Host: "127.0.0.1", Port: 8767})
	db := testStateDB(t)
	srv.SetStateDB(db)

	w := httptest.NewRecorder()
	srv.ServeHTTP(w, httptest.NewRequest("GET", "/api/health", nil))
	if w.Code != http.StatusOK {
		t.Fatalf("live db: expected 200, got %d: %s", w.Code, w.Body.String())
	}
	var body struct {
		Status string            `json:"status"`
		Checks map[string]string `json:"checks"`
	}
	_ = json.Unmarshal(w.Body.Bytes(), &body)
	if body.Status != "ok" || body.Checks["db"] != "ok" {
		t.Fatalf("live db: unexpected body %s", w.Body.String())
	}

	db.Close()
	w = httptest.NewRecorder()
	srv.ServeHTTP(w, httptest.NewRequest("GET", "/api/health", nil))
	if w.Code != http.StatusServiceUnavailable {
		t.Fatalf("closed db: expected 503, got %d: %s", w.Code, w.Body.String())
	}
	var degraded struct {
		Status string `json:"status"`
		Error  string `json:"error"`
	}
	_ = json.Unmarshal(w.Body.Bytes(), &degraded)
	if degraded.Status != "degraded" || degraded.Error != "db_unavailable" {
		t.Fatalf("closed db: unexpected body %s", w.Body.String())
	}
}

func TestAPIConfig(t *testing.T) {
	cfg := &config.ServerConfig{Host: "127.0.0.1", Port: 8767, PollIntervalMs: 2000}
	srv := NewServer(cfg)

	req := apiRequest("GET", "/api/config", nil)
	w := httptest.NewRecorder()
	srv.ServeHTTP(w, req)

	if w.Code != 200 {
		t.Fatalf("expected 200, got %d", w.Code)
	}

	var body map[string]interface{}
	json.Unmarshal(w.Body.Bytes(), &body)
	if body["pollIntervalMs"] != float64(2000) {
		t.Fatalf("expected pollIntervalMs 2000, got %v", body["pollIntervalMs"])
	}
}

func TestSessionEndpoint_RequiresCert(t *testing.T) {
	cfg := &config.ServerConfig{Host: "127.0.0.1", Port: 8767}
	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	registry, users := testRegistries(t)
	mgr := session.NewManager(key)

	srv := NewServer(cfg)
	srv.SetSecurityServices(mgr, registry, users, key)

	req := apiRequest("POST", "/api/session", nil)
	w := httptest.NewRecorder()
	srv.ServeHTTP(w, req)

	if w.Code != http.StatusForbidden {
		t.Fatalf("expected 403 without client cert, got %d", w.Code)
	}
}

func TestSessionEndpoint_WithValidCert(t *testing.T) {
	cfg := &config.ServerConfig{Host: "127.0.0.1", Port: 0}
	serverKey, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	registry, users := testRegistries(t)
	mgr := session.NewManager(serverKey)

	srv := NewServer(cfg)
	srv.SetSecurityServices(mgr, registry, users, serverKey)

	certPEM, _, _ := registerTestDevice(t, registry, serverKey)
	cert := parseCertificate(t, certPEM)

	req := requestWithTLS("POST", "/api/session", nil, cert)
	w := httptest.NewRecorder()
	srv.ServeHTTP(w, req)

	if w.Code != 200 {
		t.Fatalf("expected 200, got %d: %s", w.Code, w.Body.String())
	}

	var body map[string]interface{}
	json.Unmarshal(w.Body.Bytes(), &body)
	if body["token"] == nil || body["token"] == "" {
		t.Fatal("expected non-empty token in response")
	}
	if body["expires_in"] != float64(300) {
		t.Fatalf("expected expires_in 300, got %v", body["expires_in"])
	}
}

func TestSessionEndpoint_UnregisteredDevice(t *testing.T) {
	cfg := &config.ServerConfig{Host: "127.0.0.1", Port: 0}
	serverKey, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	registry, users := testRegistries(t)
	mgr := session.NewManager(serverKey)

	srv := NewServer(cfg)
	srv.SetSecurityServices(mgr, registry, users, serverKey)

	unregKey, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	serial, _ := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	template := x509.Certificate{
		SerialNumber: serial,
		Subject:      pkix.Name{CommonName: "unknown"},
		NotBefore:    time.Now().Add(-time.Minute),
		NotAfter:     time.Now().Add(time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature,
	}
	certDER, _ := x509.CreateCertificate(rand.Reader, &template, &template, &unregKey.PublicKey, unregKey)
	cert, _ := x509.ParseCertificate(certDER)

	req := requestWithTLS("POST", "/api/session", nil, cert)
	w := httptest.NewRecorder()
	srv.ServeHTTP(w, req)

	if w.Code != http.StatusForbidden {
		t.Fatalf("expected 403 for unregistered device, got %d", w.Code)
	}
}

func TestCertRenewEndpoint(t *testing.T) {
	cfg := &config.ServerConfig{Host: "127.0.0.1", Port: 0}
	serverKey, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	registry, users := testRegistries(t)
	mgr := session.NewManager(serverKey)

	srv := NewServer(cfg)
	srv.SetSecurityServices(mgr, registry, users, serverKey)

	certPEM, keyPEM, _ := registerTestDevice(t, registry, serverKey)
	cert := parseCertificate(t, certPEM)

	block, _ := pem.Decode(keyPEM)
	deviceKey, _ := x509.ParseECPrivateKey(block.Bytes)
	csrTemplate := x509.CertificateRequest{Subject: pkix.Name{CommonName: "pocketcmd-client"}}
	csrDER, err := x509.CreateCertificateRequest(rand.Reader, &csrTemplate, deviceKey)
	if err != nil {
		t.Fatal(err)
	}
	csrPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE REQUEST", Bytes: csrDER})

	body, _ := json.Marshal(map[string]string{"csr": string(csrPEM)})
	req := requestWithTLS("POST", "/api/cert/renew", body, cert)
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	srv.ServeHTTP(w, req)

	if w.Code != 200 {
		t.Fatalf("expected 200, got %d: %s", w.Code, w.Body.String())
	}

	var resp map[string]string
	json.Unmarshal(w.Body.Bytes(), &resp)
	if resp["cert"] == "" {
		t.Fatal("expected non-empty cert in response")
	}
	renewBlock, _ := pem.Decode([]byte(resp["cert"]))
	if renewBlock == nil || renewBlock.Type != "CERTIFICATE" {
		t.Fatal("expected valid certificate PEM")
	}
}

func TestCertRenewEndpoint_EmptyCSR(t *testing.T) {
	cfg := &config.ServerConfig{Host: "127.0.0.1", Port: 0}
	serverKey, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	registry, users := testRegistries(t)
	mgr := session.NewManager(serverKey)

	srv := NewServer(cfg)
	srv.SetSecurityServices(mgr, registry, users, serverKey)

	certPEM, _, _ := registerTestDevice(t, registry, serverKey)
	cert := parseCertificate(t, certPEM)

	body, _ := json.Marshal(map[string]string{"csr": ""})
	req := requestWithTLS("POST", "/api/cert/renew", body, cert)
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	srv.ServeHTTP(w, req)

	if w.Code != http.StatusBadRequest {
		t.Fatalf("expected 400 for empty CSR, got %d", w.Code)
	}
}

func TestCertRenewEndpoint_UnregisteredDevice(t *testing.T) {
	cfg := &config.ServerConfig{Host: "127.0.0.1", Port: 0}
	serverKey, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	registry, users := testRegistries(t)
	mgr := session.NewManager(serverKey)

	srv := NewServer(cfg)
	srv.SetSecurityServices(mgr, registry, users, serverKey)

	certPEM, _, _ := registerTestDevice(t, registry, serverKey)
	cert := parseCertificate(t, certPEM)

	otherKey, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	csrTemplate := x509.CertificateRequest{Subject: pkix.Name{CommonName: "other"}}
	csrDER, _ := x509.CreateCertificateRequest(rand.Reader, &csrTemplate, otherKey)
	csrPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE REQUEST", Bytes: csrDER})

	body, _ := json.Marshal(map[string]string{"csr": string(csrPEM)})
	req := requestWithTLS("POST", "/api/cert/renew", body, cert)
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	srv.ServeHTTP(w, req)

	if w.Code != http.StatusBadRequest {
		t.Fatalf("expected 400 for CSR/mTLS key mismatch, got %d: %s", w.Code, w.Body.String())
	}
}

func TestCertRenew_InvalidJSON(t *testing.T) {
	cfg := &config.ServerConfig{Host: "127.0.0.1", Port: 0}
	serverKey, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	registry, users := testRegistries(t)
	mgr := session.NewManager(serverKey)

	srv := NewServer(cfg)
	srv.SetSecurityServices(mgr, registry, users, serverKey)

	certPEM, _, _ := registerTestDevice(t, registry, serverKey)
	cert := parseCertificate(t, certPEM)

	req := requestWithTLS("POST", "/api/cert/renew", []byte("not-json"), cert)
	w := httptest.NewRecorder()
	srv.ServeHTTP(w, req)

	if w.Code != http.StatusBadRequest {
		t.Fatalf("expected 400 for invalid JSON, got %d", w.Code)
	}
}

func TestHandleSession_NilTLS(t *testing.T) {
	cfg := &config.ServerConfig{Host: "127.0.0.1", Port: 0}
	serverKey, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	mgr := session.NewManager(serverKey)

	srv := NewServer(cfg)
	srv.jwtManager = mgr

	req := apiRequest("POST", "/api/session", nil)
	w := httptest.NewRecorder()
	srv.handleSession(w, req)

	if w.Code != http.StatusForbidden {
		t.Fatalf("expected 403, got %d", w.Code)
	}
}

func TestHandleSession_EmptyPeerCerts(t *testing.T) {
	cfg := &config.ServerConfig{Host: "127.0.0.1", Port: 0}
	serverKey, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	mgr := session.NewManager(serverKey)

	srv := NewServer(cfg)
	srv.jwtManager = mgr

	req := apiRequest("POST", "/api/session", nil)
	req.TLS = &tls.ConnectionState{PeerCertificates: []*x509.Certificate{}}
	w := httptest.NewRecorder()
	srv.handleSession(w, req)

	if w.Code != http.StatusForbidden {
		t.Fatalf("expected 403 with empty peer certs, got %d", w.Code)
	}
}

func TestHandleCertRenew_InvalidCSR(t *testing.T) {
	cfg := &config.ServerConfig{Host: "127.0.0.1", Port: 0}
	serverKey, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	registry, users := testRegistries(t)
	mgr := session.NewManager(serverKey)

	srv := NewServer(cfg)
	srv.SetSecurityServices(mgr, registry, users, serverKey)

	certPEM, _, _ := registerTestDevice(t, registry, serverKey)
	cert := parseCertificate(t, certPEM)

	body, _ := json.Marshal(map[string]string{"csr": "not-a-valid-csr"})
	req := requestWithTLS("POST", "/api/cert/renew", body, cert)
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	srv.ServeHTTP(w, req)

	if w.Code != http.StatusBadRequest {
		t.Fatalf("expected 400 for invalid CSR, got %d", w.Code)
	}
}

func TestSSHConfigsEndpoint(t *testing.T) {
	cfg := &config.ServerConfig{Host: "127.0.0.1", Port: 8767}
	srv := NewServer(cfg)

	req := apiRequest("GET", "/api/ssh-configs", nil)
	w := httptest.NewRecorder()
	srv.handleSSHConfigs(w, req)

	if w.Code != 200 {
		t.Fatalf("expected 200, got %d", w.Code)
	}
	var body map[string]interface{}
	json.Unmarshal(w.Body.Bytes(), &body)
	if _, ok := body["hosts"]; !ok {
		t.Fatal("expected hosts field in response")
	}
}

func TestSSHConfigsEndpoint_RequiresJWT(t *testing.T) {
	cfg := &config.ServerConfig{Host: "127.0.0.1", Port: 0}
	serverKey, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	registry, users := testRegistries(t)
	mgr := session.NewManager(serverKey)

	srv := NewServer(cfg)
	srv.SetSecurityServices(mgr, registry, users, serverKey)
	srv.RegisterSSHRoutes()

	req := apiRequest("GET", "/api/ssh-configs", nil)
	w := httptest.NewRecorder()
	srv.ServeHTTP(w, req)
	if w.Code != 401 {
		t.Fatalf("expected 401 without cert, got %d", w.Code)
	}

	certPEM, _, _ := registerTestDevice(t, registry, serverKey)
	cert := parseCertificate(t, certPEM)
	req = requestWithTLS("GET", "/api/ssh-configs", nil, cert)
	w = httptest.NewRecorder()
	srv.ServeHTTP(w, req)
	if w.Code != 401 {
		t.Fatalf("expected 401 without JWT, got %d", w.Code)
	}
}

func TestSSHConfigsEndpoint_WithJWT(t *testing.T) {
	cfg := &config.ServerConfig{Host: "127.0.0.1", Port: 0}
	serverKey, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	registry := testDeviceRegistry(t)
	users := pki.NewUserRegistry(testStateDB(t))
	mgr := session.NewManager(serverKey)

	srv := NewServer(cfg)
	srv.SetSecurityServices(mgr, registry, users, serverKey)
	srv.RegisterSSHRoutes()

	certPEM, _, deviceID := registerTestDevice(t, registry, serverKey)
	bindDeviceToAdminUser(t, registry, users, deviceID)
	cert := parseCertificate(t, certPEM)
	certFP := pki.CertFingerprint(cert.Raw)
	token, err := mgr.Issue(deviceID, certFP)
	if err != nil {
		t.Fatal(err)
	}

	req := requestWithTLS("GET", "/api/ssh-configs", nil, cert)
	req.Header.Set("Authorization", "Bearer "+token)
	w := httptest.NewRecorder()
	srv.ServeHTTP(w, req)

	if w.Code != 200 {
		t.Fatalf("expected 200, got %d: %s", w.Code, w.Body.String())
	}
}

func TestSSHConfigsEndpoint_Rejects403ForMember(t *testing.T) {
	cfg := &config.ServerConfig{Host: "127.0.0.1", Port: 0}
	serverKey, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	registry := testDeviceRegistry(t)
	users := pki.NewUserRegistry(testStateDB(t))
	mgr := session.NewManager(serverKey)

	srv := NewServer(cfg)
	srv.SetSecurityServices(mgr, registry, users, serverKey)
	srv.RegisterSSHRoutes()

	certPEM, _, deviceID := registerTestDevice(t, registry, serverKey)
	bindDeviceToMemberUser(t, registry, users, deviceID)
	cert := parseCertificate(t, certPEM)
	certFP := pki.CertFingerprint(cert.Raw)
	token, err := mgr.Issue(deviceID, certFP)
	if err != nil {
		t.Fatal(err)
	}

	req := requestWithTLS("GET", "/api/ssh-configs", nil, cert)
	req.Header.Set("Authorization", "Bearer "+token)
	w := httptest.NewRecorder()
	srv.ServeHTTP(w, req)

	if w.Code != http.StatusForbidden {
		t.Fatalf("expected 403, got %d: %s", w.Code, w.Body.String())
	}
	var body map[string]string
	if err := json.NewDecoder(w.Body).Decode(&body); err != nil {
		t.Fatalf("expected JSON body on 403, decode error: %v", err)
	}
	if body["error"] != "forbidden" {
		t.Errorf("expected error 'forbidden', got %q", body["error"])
	}
}

func TestSSHConfigsEndpoint_OneShot(t *testing.T) {
	cfg := &config.ServerConfig{Host: "127.0.0.1", Port: 0}
	serverKey, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	registry := testDeviceRegistry(t)
	users := pki.NewUserRegistry(testStateDB(t))
	mgr := session.NewManager(serverKey)

	srv := NewServer(cfg)
	srv.SetSecurityServices(mgr, registry, users, serverKey)
	srv.RegisterSSHRoutes()
	srv.EnableSSHOneShot()

	certPEM, _, deviceID := registerTestDevice(t, registry, serverKey)
	bindDeviceToAdminUser(t, registry, users, deviceID)
	cert := parseCertificate(t, certPEM)
	certFP := pki.CertFingerprint(cert.Raw)
	token, err := mgr.Issue(deviceID, certFP)
	if err != nil {
		t.Fatal(err)
	}

	doFetch := func() int {
		req := requestWithTLS("GET", "/api/ssh-configs", nil, cert)
		req.Header.Set("Authorization", "Bearer "+token)
		w := httptest.NewRecorder()
		srv.ServeHTTP(w, req)
		return w.Code
	}

	if code := doFetch(); code != 200 {
		t.Fatalf("first fetch: expected 200, got %d", code)
	}
	if code := doFetch(); code != http.StatusConflict {
		t.Fatalf("second fetch: expected 409, got %d", code)
	}

	certPEM2, _, deviceID2 := registerTestDevice(t, registry, serverKey)
	bindDeviceToAdminUser(t, registry, users, deviceID2)
	cert2 := parseCertificate(t, certPEM2)
	certFP2 := pki.CertFingerprint(cert2.Raw)
	token2, err := mgr.Issue(deviceID2, certFP2)
	if err != nil {
		t.Fatal(err)
	}
	req := requestWithTLS("GET", "/api/ssh-configs", nil, cert2)
	req.Header.Set("Authorization", "Bearer "+token2)
	w := httptest.NewRecorder()
	srv.ServeHTTP(w, req)
	if w.Code != http.StatusConflict {
		t.Fatalf("second device fetch: expected 409, got %d", w.Code)
	}
}

func TestSSHConfigsEndpoint_FetchCallback(t *testing.T) {
	cfg := &config.ServerConfig{Host: "127.0.0.1", Port: 0}
	serverKey, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	registry := testDeviceRegistry(t)
	users := pki.NewUserRegistry(testStateDB(t))
	mgr := session.NewManager(serverKey)

	srv := NewServer(cfg)
	srv.SetSecurityServices(mgr, registry, users, serverKey)
	srv.RegisterSSHRoutes()

	got := make(chan string, 2)
	srv.OnSSHConfigsFetch(func(deviceID string) { got <- deviceID })

	req := apiRequest("GET", "/api/ssh-configs", nil)
	w := httptest.NewRecorder()
	srv.ServeHTTP(w, req)
	if w.Code != 401 {
		t.Fatalf("expected 401 for unauth, got %d", w.Code)
	}
	select {
	case id := <-got:
		t.Fatalf("callback fired on unauthenticated request: %q", id)
	default:
	}

	certPEM, _, deviceID := registerTestDevice(t, registry, serverKey)
	bindDeviceToAdminUser(t, registry, users, deviceID)
	cert := parseCertificate(t, certPEM)
	certFP := pki.CertFingerprint(cert.Raw)
	token, err := mgr.Issue(deviceID, certFP)
	if err != nil {
		t.Fatal(err)
	}
	req = requestWithTLS("GET", "/api/ssh-configs", nil, cert)
	req.Header.Set("Authorization", "Bearer "+token)
	w = httptest.NewRecorder()
	srv.ServeHTTP(w, req)
	if w.Code != 200 {
		t.Fatalf("expected 200, got %d: %s", w.Code, w.Body.String())
	}
	select {
	case id := <-got:
		if id != deviceID {
			t.Fatalf("callback deviceID = %q, want %q", id, deviceID)
		}
	case <-time.After(time.Second):
		t.Fatal("callback did not fire after successful fetch")
	}
}

func TestPushRegisterEndpoint(t *testing.T) {
	t.Setenv("HOME", t.TempDir())

	cfg := &config.ServerConfig{Host: "127.0.0.1", Port: 0}
	serverKey, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	db := testStateDB(t)
	registry := testDeviceRegistryOn(db)
	users := pki.NewUserRegistry(testStateDB(t))
	mgr := session.NewManager(serverKey)

	srv := NewServer(cfg)
	srv.SetSecurityServices(mgr, registry, users, serverKey)
	srv.SetPushStore(push.NewStore(db))

	certPEM, _, deviceID := registerTestDevice(t, registry, serverKey)
	bindDeviceToAdminUser(t, registry, users, deviceID)
	cert := parseCertificate(t, certPEM)
	certFP := pki.CertFingerprint(cert.Raw)
	token, _ := mgr.Issue(deviceID, certFP)

	body, _ := json.Marshal(map[string]interface{}{
		"device_id":    deviceID,
		"device_token": "tok-test",
		"platform":     "android",
		"signed_token": "sig-test",
		"expires_at":   time.Now().Add(time.Hour).UnixMilli(),
	})
	req := requestWithTLS("POST", "/api/push/register", body, cert)
	req.Header.Set("Authorization", "Bearer "+token)
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	srv.ServeHTTP(w, req)

	if w.Code != 200 {
		t.Fatalf("expected 200, got %d: %s", w.Code, w.Body.String())
	}
	var resp map[string]any
	json.Unmarshal(w.Body.Bytes(), &resp)
	if resp["status"] != "ok" {
		t.Fatalf("expected status ok, got %v", resp["status"])
	}
	if len(resp) != 1 {
		t.Fatalf("the answer is exactly {status: ok} with no push switch to report, got %v", resp)
	}
}

func TestPushRegisterEndpoint_StoresRegistration(t *testing.T) {
	t.Setenv("HOME", t.TempDir())

	cfg := &config.ServerConfig{Host: "127.0.0.1", Port: 0}
	serverKey, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	db := testStateDB(t)
	registry := testDeviceRegistryOn(db)
	users := pki.NewUserRegistry(testStateDB(t))
	mgr := session.NewManager(serverKey)

	srv := NewServer(cfg)
	srv.SetSecurityServices(mgr, registry, users, serverKey)
	pushStore := push.NewStore(db)
	srv.SetPushStore(pushStore)

	certPEM, _, deviceID := registerTestDevice(t, registry, serverKey)
	bindDeviceToAdminUser(t, registry, users, deviceID)
	cert := parseCertificate(t, certPEM)
	token, _ := mgr.Issue(deviceID, pki.CertFingerprint(cert.Raw))

	body, _ := json.Marshal(map[string]interface{}{
		"device_token": "tok-test",
		"platform":     "android",
		"signed_token": "sig-test",
		"expires_at":   time.Now().Add(time.Hour).UnixMilli(),
	})
	req := requestWithTLS("POST", "/api/push/register", body, cert)
	req.Header.Set("Authorization", "Bearer "+token)
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	srv.ServeHTTP(w, req)
	if w.Code != 200 {
		t.Fatalf("expected 200, got %d: %s", w.Code, w.Body.String())
	}
	var resp map[string]any
	if err := json.Unmarshal(w.Body.Bytes(), &resp); err != nil {
		t.Fatal(err)
	}
	if resp["status"] != "ok" || len(resp) != 1 {
		t.Fatalf("want exactly {status: ok}, got %v", resp)
	}
	if regs, err := pushStore.ReadAll(); err != nil || len(regs) != 1 || regs[0].DeviceID != deviceID {
		t.Fatalf("registration must be stored under the caller's device: regs=%v err=%v", regs, err)
	}
}

func TestPushRegisterEndpoint_InvalidBody(t *testing.T) {
	cfg := &config.ServerConfig{Host: "127.0.0.1", Port: 0}
	serverKey, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	registry := testDeviceRegistry(t)
	users := pki.NewUserRegistry(testStateDB(t))
	mgr := session.NewManager(serverKey)

	srv := NewServer(cfg)
	srv.SetSecurityServices(mgr, registry, users, serverKey)

	certPEM, _, deviceID := registerTestDevice(t, registry, serverKey)
	bindDeviceToAdminUser(t, registry, users, deviceID)
	cert := parseCertificate(t, certPEM)
	certFP := pki.CertFingerprint(cert.Raw)
	token, _ := mgr.Issue(deviceID, certFP)

	req := requestWithTLS("POST", "/api/push/register", []byte("not json"), cert)
	req.Header.Set("Authorization", "Bearer "+token)
	w := httptest.NewRecorder()
	srv.ServeHTTP(w, req)

	if w.Code != 400 {
		t.Fatalf("expected 400 for invalid body, got %d", w.Code)
	}
}

func newPushTestServer(t *testing.T) (*Server, *x509.Certificate, string, string, *push.Store) {
	t.Helper()
	cfg := &config.ServerConfig{Host: "127.0.0.1", Port: 0}
	serverKey, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	// Devices and push registrations must share one db because of the FK.
	db := testStateDB(t)
	registry := testDeviceRegistryOn(db)
	users := pki.NewUserRegistry(testStateDB(t))
	pushStore := push.NewStore(db)
	mgr := session.NewManager(serverKey)

	srv := NewServer(cfg)
	srv.SetSecurityServices(mgr, registry, users, serverKey)
	srv.SetPushStore(pushStore)

	certPEM, _, deviceID := registerTestDevice(t, registry, serverKey)
	bindDeviceToAdminUser(t, registry, users, deviceID)
	cert := parseCertificate(t, certPEM)
	certFP := pki.CertFingerprint(cert.Raw)
	token, _ := mgr.Issue(deviceID, certFP)
	return srv, cert, deviceID, token, pushStore
}

func TestHandlePushRegister_AllFieldsPersisted(t *testing.T) {
	tempHome := t.TempDir()
	t.Setenv("HOME", tempHome)

	srv, cert, deviceID, token, pushStore := newPushTestServer(t)

	expiresAt := time.Now().Add(time.Hour).UnixMilli()
	body, _ := json.Marshal(map[string]interface{}{
		"device_id":    deviceID,
		"device_token": "tok-abc123",
		"platform":     "ios",
		"signed_token": "sig-xyz789",
		"expires_at":   expiresAt,
	})
	req := requestWithTLS("POST", "/api/push/register", body, cert)
	req.Header.Set("Authorization", "Bearer "+token)
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	srv.ServeHTTP(w, req)

	if w.Code != 200 {
		t.Fatalf("expected 200, got %d: %s", w.Code, w.Body.String())
	}
	var resp map[string]string
	json.Unmarshal(w.Body.Bytes(), &resp)
	if resp["status"] != "ok" {
		t.Fatalf("expected status ok, got %v", resp)
	}

	regs, err := pushStore.ReadAll()
	if err != nil {
		t.Fatalf("read registrations: %v", err)
	}
	if len(regs) != 1 {
		t.Fatalf("expected 1 registration, got %d", len(regs))
	}
	reg := regs[0]
	if reg.DeviceID != deviceID {
		t.Errorf("device_id: got %q, want %q", reg.DeviceID, deviceID)
	}
	if reg.DeviceToken != "tok-abc123" {
		t.Errorf("device_token: got %q, want %q", reg.DeviceToken, "tok-abc123")
	}
	if reg.Platform != "ios" {
		t.Errorf("platform: got %q, want %q", reg.Platform, "ios")
	}
	if reg.SignedToken != "sig-xyz789" {
		t.Errorf("signed_token: got %q, want %q", reg.SignedToken, "sig-xyz789")
	}
	if reg.ExpiresAt != expiresAt {
		t.Errorf("expires_at: got %d, want %d", reg.ExpiresAt, expiresAt)
	}
}

func TestHandlePushRegister_MissingDeviceID_UsesCallerDevice(t *testing.T) {
	tempHome := t.TempDir()
	t.Setenv("HOME", tempHome)
	srv, cert, deviceID, token, pushStore := newPushTestServer(t)

	body, _ := json.Marshal(map[string]interface{}{
		"device_token": "tok-abc123",
		"platform":     "ios",
		"signed_token": "sig-xyz789",
		"expires_at":   time.Now().Add(time.Hour).UnixMilli(),
	})
	req := requestWithTLS("POST", "/api/push/register", body, cert)
	req.Header.Set("Authorization", "Bearer "+token)
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	srv.ServeHTTP(w, req)

	if w.Code != 200 {
		t.Fatalf("expected 200 for missing device_id, got %d: %s", w.Code, w.Body.String())
	}
	regs, err := pushStore.ReadAll()
	if err != nil || len(regs) != 1 || regs[0].DeviceID != deviceID {
		t.Fatalf("expected registration stored under caller device ID, got %+v (err=%v)", regs, err)
	}
}

func TestHandlePushRegister_ForeignDeviceID_Returns403(t *testing.T) {
	t.Setenv("HOME", t.TempDir())
	srv, cert, _, token, _ := newPushTestServer(t)

	body, _ := json.Marshal(map[string]interface{}{
		"device_id":    "some-other-device",
		"device_token": "tok-abc123",
		"platform":     "ios",
		"signed_token": "sig-xyz789",
		"expires_at":   time.Now().Add(time.Hour).UnixMilli(),
	})
	req := requestWithTLS("POST", "/api/push/register", body, cert)
	req.Header.Set("Authorization", "Bearer "+token)
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	srv.ServeHTTP(w, req)

	if w.Code != 403 {
		t.Fatalf("expected 403 for foreign device_id, got %d: %s", w.Code, w.Body.String())
	}
}

func TestHandlePushRegister_MissingDeviceToken_Returns400(t *testing.T) {
	t.Setenv("HOME", t.TempDir())
	srv, cert, deviceID, token, _ := newPushTestServer(t)

	body, _ := json.Marshal(map[string]interface{}{
		"device_id":    deviceID,
		"platform":     "ios",
		"signed_token": "sig-xyz789",
		"expires_at":   time.Now().Add(time.Hour).UnixMilli(),
	})
	req := requestWithTLS("POST", "/api/push/register", body, cert)
	req.Header.Set("Authorization", "Bearer "+token)
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	srv.ServeHTTP(w, req)

	if w.Code != 400 {
		t.Fatalf("expected 400 for missing device_token, got %d: %s", w.Code, w.Body.String())
	}
}

func TestHandlePushRegister_MissingPlatform_Returns400(t *testing.T) {
	t.Setenv("HOME", t.TempDir())
	srv, cert, deviceID, token, _ := newPushTestServer(t)

	body, _ := json.Marshal(map[string]interface{}{
		"device_id":    deviceID,
		"device_token": "tok-abc123",
		"signed_token": "sig-xyz789",
		"expires_at":   time.Now().Add(time.Hour).UnixMilli(),
	})
	req := requestWithTLS("POST", "/api/push/register", body, cert)
	req.Header.Set("Authorization", "Bearer "+token)
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	srv.ServeHTTP(w, req)

	if w.Code != 400 {
		t.Fatalf("expected 400 for missing platform, got %d: %s", w.Code, w.Body.String())
	}
}

func TestHandlePushRegister_MissingSignedToken_Returns400(t *testing.T) {
	t.Setenv("HOME", t.TempDir())
	srv, cert, deviceID, token, _ := newPushTestServer(t)

	body, _ := json.Marshal(map[string]interface{}{
		"device_id":    deviceID,
		"device_token": "tok-abc123",
		"platform":     "ios",
		"expires_at":   time.Now().Add(time.Hour).UnixMilli(),
	})
	req := requestWithTLS("POST", "/api/push/register", body, cert)
	req.Header.Set("Authorization", "Bearer "+token)
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	srv.ServeHTTP(w, req)

	if w.Code != 400 {
		t.Fatalf("expected 400 for missing signed_token, got %d: %s", w.Code, w.Body.String())
	}
}

func TestHandlePushRegister_MissingExpiresAt_Returns400(t *testing.T) {
	t.Setenv("HOME", t.TempDir())
	srv, cert, deviceID, token, _ := newPushTestServer(t)

	body, _ := json.Marshal(map[string]interface{}{
		"device_id":    deviceID,
		"device_token": "tok-abc123",
		"platform":     "ios",
		"signed_token": "sig-xyz789",
		"expires_at":   0,
	})
	req := requestWithTLS("POST", "/api/push/register", body, cert)
	req.Header.Set("Authorization", "Bearer "+token)
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	srv.ServeHTTP(w, req)

	if w.Code != 400 {
		t.Fatalf("expected 400 for zero expires_at, got %d: %s", w.Code, w.Body.String())
	}
}

func TestJWTMiddleware_RejectsNoAuth(t *testing.T) {
	serverKey, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	mgr := session.NewManager(serverKey)
	registry := testDeviceRegistry(t)

	handler := RequireJWT(mgr, registry, testVerifier(t, serverKey), http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(200)
	}))

	req := apiRequest("GET", "/api/test", nil)
	w := httptest.NewRecorder()
	handler.ServeHTTP(w, req)

	if w.Code != 401 {
		t.Fatalf("expected 401, got %d", w.Code)
	}
}

func TestRequireJWT_ValidToken(t *testing.T) {
	serverKey, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	registry := testDeviceRegistry(t)
	mgr := session.NewManager(serverKey)

	certPEM, _, deviceID := registerTestDevice(t, registry, serverKey)
	cert := parseCertificate(t, certPEM)
	certFP := pki.CertFingerprint(cert.Raw)
	token, _ := mgr.Issue(deviceID, certFP)

	var gotDeviceID string
	handler := RequireJWT(mgr, registry, testVerifier(t, serverKey), http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotDeviceID = r.Context().Value(contextKeyDeviceID).(string)
		w.WriteHeader(200)
	}))

	req := requestWithTLS("GET", "/api/test", nil, cert)
	req.Header.Set("Authorization", "Bearer "+token)
	w := httptest.NewRecorder()
	handler.ServeHTTP(w, req)

	if w.Code != 200 {
		t.Fatalf("expected 200, got %d: %s", w.Code, w.Body.String())
	}
	if gotDeviceID != deviceID {
		t.Fatalf("expected device ID %s, got %s", deviceID, gotDeviceID)
	}
}

func TestRequireJWT_ExpiredToken(t *testing.T) {
	serverKey, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	registry := testDeviceRegistry(t)
	mgr := session.NewManager(serverKey)

	certPEM, _, deviceID := registerTestDevice(t, registry, serverKey)
	cert := parseCertificate(t, certPEM)
	certFP := pki.CertFingerprint(cert.Raw)
	token, _ := mgr.Issue(deviceID, certFP)

	otherKey, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	otherMgr := session.NewManager(otherKey)

	handler := RequireJWT(otherMgr, registry, testVerifier(t, serverKey), http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(200)
	}))

	req := requestWithTLS("GET", "/api/test", nil, cert)
	req.Header.Set("Authorization", "Bearer "+token)
	w := httptest.NewRecorder()
	handler.ServeHTTP(w, req)

	if w.Code != 401 {
		t.Fatalf("expected 401 for invalid token, got %d", w.Code)
	}
}

func TestRequireJWT_WrongCertBinding(t *testing.T) {
	serverKey, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	registry := testDeviceRegistry(t)
	mgr := session.NewManager(serverKey)

	certPEM, _, deviceID := registerTestDevice(t, registry, serverKey)
	cert := parseCertificate(t, certPEM)

	token, _ := mgr.Issue(deviceID, "wrong-fingerprint-aabbccdd")

	handler := RequireJWT(mgr, registry, testVerifier(t, serverKey), http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(200)
	}))

	req := requestWithTLS("GET", "/api/test", nil, cert)
	req.Header.Set("Authorization", "Bearer "+token)
	w := httptest.NewRecorder()
	handler.ServeHTTP(w, req)

	if w.Code != 401 {
		t.Fatalf("expected 401 for wrong cert binding, got %d: %s", w.Code, w.Body.String())
	}
	if !strings.Contains(w.Body.String(), "invalid_token") {
		t.Fatalf("expected generic invalid_token error, got: %s", w.Body.String())
	}
}

func TestRequireJWT_UnregisteredCert(t *testing.T) {
	serverKey, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	registry := testDeviceRegistry(t)
	mgr := session.NewManager(serverKey)

	unregKey, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	serial, _ := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	template := x509.Certificate{
		SerialNumber: serial,
		Subject:      pkix.Name{CommonName: "unknown"},
		NotBefore:    time.Now().Add(-time.Minute),
		NotAfter:     time.Now().Add(time.Hour),
	}
	certDER, _ := x509.CreateCertificate(rand.Reader, &template, &template, &unregKey.PublicKey, unregKey)
	cert, _ := x509.ParseCertificate(certDER)

	handler := RequireJWT(mgr, registry, testVerifier(t, serverKey), http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(200)
	}))

	req := requestWithTLS("GET", "/api/test", nil, cert)
	req.Header.Set("Authorization", "Bearer some-token")
	w := httptest.NewRecorder()
	handler.ServeHTTP(w, req)

	if w.Code != http.StatusForbidden {
		t.Fatalf("expected 403 for unregistered cert, got %d", w.Code)
	}
}

func TestRequireMTLS_NoCert(t *testing.T) {
	cfg := &config.ServerConfig{Host: "127.0.0.1", Port: 0}
	serverKey, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	registry, users := testRegistries(t)
	mgr := session.NewManager(serverKey)

	srv := NewServer(cfg)
	srv.SetSecurityServices(mgr, registry, users, serverKey)

	req := apiRequest("POST", "/api/session", nil)
	w := httptest.NewRecorder()
	srv.ServeHTTP(w, req)

	if w.Code != http.StatusForbidden {
		t.Fatalf("expected 403 without mTLS, got %d", w.Code)
	}
}

func TestRequireMTLS_UnregisteredCert(t *testing.T) {
	cfg := &config.ServerConfig{Host: "127.0.0.1", Port: 0}
	serverKey, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	registry, users := testRegistries(t)
	mgr := session.NewManager(serverKey)

	srv := NewServer(cfg)
	srv.SetSecurityServices(mgr, registry, users, serverKey)

	unregKey, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	serial, _ := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	template := x509.Certificate{
		SerialNumber: serial,
		Subject:      pkix.Name{CommonName: "unknown"},
		NotBefore:    time.Now().Add(-time.Minute),
		NotAfter:     time.Now().Add(time.Hour),
	}
	certDER, _ := x509.CreateCertificate(rand.Reader, &template, &template, &unregKey.PublicKey, unregKey)
	cert, _ := x509.ParseCertificate(certDER)

	req := requestWithTLS("POST", "/api/session", nil, cert)
	w := httptest.NewRecorder()
	srv.ServeHTTP(w, req)

	if w.Code != http.StatusForbidden {
		t.Fatalf("expected 403 for unregistered cert, got %d", w.Code)
	}
}

func TestRegisterPairRoute(t *testing.T) {
	cfg := &config.ServerConfig{Host: "127.0.0.1", Port: 0}
	serverKey, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	registry := testDeviceRegistry(t)

	srv := NewServer(cfg)
	users := pki.NewUserRegistry(testStateDB(t))
	invites := pki.NewInviteStore(testStateDB(t))
	handler := pair.NewPairingHandler(registry, users, invites, serverKey, "fp", "localhost", "https://localhost:8443")
	srv.RegisterPairRoute(handler)

	req := apiRequest("POST", "/api/pair", strings.NewReader("{}"))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	srv.ServeHTTP(w, req)

	if w.Code == 404 {
		t.Fatal("expected /api/pair route to be registered, got 404")
	}
}

func TestSetSecurityServices(t *testing.T) {
	cfg := &config.ServerConfig{Host: "127.0.0.1", Port: 0}
	serverKey, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	registry := testDeviceRegistry(t)
	mgr := session.NewManager(serverKey)

	users := pki.NewUserRegistry(testStateDB(t))
	srv := NewServer(cfg)
	srv.SetSecurityServices(mgr, registry, users, serverKey)

	if srv.jwtManager != mgr {
		t.Fatal("jwtManager not set")
	}
	if srv.deviceRegistry != registry {
		t.Fatal("deviceRegistry not set")
	}
	if srv.userRegistry != users {
		t.Fatal("userRegistry not set")
	}
	if srv.serverKey != serverKey {
		t.Fatal("serverKey not set")
	}

	for _, p := range []struct{ method, path string }{
		{"POST", "/api/session"},
		{"POST", "/api/cert/renew"},
		{"POST", "/api/push/register"},
	} {
		req := apiRequest(p.method, p.path, nil)
		w := httptest.NewRecorder()
		srv.ServeHTTP(w, req)
		if w.Code == 404 {
			t.Fatalf("expected %s %s to be registered, got 404", p.method, p.path)
		}
	}

	req := apiRequest("GET", "/api/ssh-configs", nil)
	w := httptest.NewRecorder()
	srv.ServeHTTP(w, req)
	if w.Code != 404 {
		t.Fatalf("expected /api/ssh-configs to be 404 without RegisterSSHRoutes, got %d", w.Code)
	}
}

func TestRegisterSSHRoutes_RequiresSecurity(t *testing.T) {
	cfg := &config.ServerConfig{Host: "127.0.0.1", Port: 0}
	srv := NewServer(cfg)
	defer func() {
		if r := recover(); r == nil {
			t.Fatal("expected RegisterSSHRoutes to panic without security services")
		}
	}()
	srv.RegisterSSHRoutes()
}

func TestRegisterSSHRoutes_RegistersWhenEnabled(t *testing.T) {
	cfg := &config.ServerConfig{Host: "127.0.0.1", Port: 0}
	serverKey, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	registry, users := testRegistries(t)
	mgr := session.NewManager(serverKey)

	srv := NewServer(cfg)
	srv.SetSecurityServices(mgr, registry, users, serverKey)
	srv.RegisterSSHRoutes()

	req := apiRequest("GET", "/api/ssh-configs", nil)
	w := httptest.NewRecorder()
	srv.ServeHTTP(w, req)
	if w.Code == 404 {
		t.Fatal("expected /api/ssh-configs to be registered")
	}
	if w.Code != 401 {
		t.Fatalf("expected 401 without auth, got %d", w.Code)
	}
}

func TestRegisterMetricRoutes_PanicsWithoutSecurityServices(t *testing.T) {
	cfg := &config.ServerConfig{Host: "127.0.0.1", Port: 0}

	srv := NewServer(cfg)
	api := metrics.NewMetricAPI(nil, nil)
	defer func() {
		if recover() == nil {
			t.Fatal("expected panic when registering metric routes without security services")
		}
	}()
	srv.RegisterMetricRoutes(api)
}

func TestRegisterMetricRoutes_WithJWTManager(t *testing.T) {
	cfg := &config.ServerConfig{Host: "127.0.0.1", Port: 0}
	serverKey, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	registry, users := testRegistries(t)
	mgr := session.NewManager(serverKey)

	srv := NewServer(cfg)
	srv.SetSecurityServices(mgr, registry, users, serverKey)
	api := metrics.NewMetricAPI(nil, nil)
	srv.RegisterMetricRoutes(api)

	req := apiRequest("GET", "/api/metrics/available", nil)
	w := httptest.NewRecorder()
	srv.ServeHTTP(w, req)
	if w.Code != 401 {
		t.Fatalf("expected 401 without auth, got %d", w.Code)
	}
}

func TestRegisterSyncRoutes_WithJWTManager(t *testing.T) {
	cfg := &config.ServerConfig{Host: "127.0.0.1", Port: 0}
	serverKey, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	registry, users := testRegistries(t)
	mgr := session.NewManager(serverKey)

	srv := NewServer(cfg)
	srv.SetSecurityServices(mgr, registry, users, serverKey)
	store := newTestSyncStore(t)
	srv.RegisterSyncRoutes(store)

	req := apiRequest("GET", "/api/sync/manifest", nil)
	w := httptest.NewRecorder()
	srv.ServeHTTP(w, req)
	if w.Code != 401 {
		t.Fatalf("expected 401 without auth, got %d", w.Code)
	}
}

func TestRegisterSyncRoutes_PanicsWithoutSecurityServices(t *testing.T) {
	cfg := &config.ServerConfig{Port: 0, Host: "127.0.0.1"}
	store := newTestSyncStore(t)

	srv := NewServer(cfg)
	defer func() {
		if recover() == nil {
			t.Fatal("expected panic when registering sync routes without security services")
		}
	}()
	srv.RegisterSyncRoutes(store)
}

func TestSetTLSConfig(t *testing.T) {
	cfg := &config.ServerConfig{Host: "127.0.0.1", Port: 0}
	srv := NewServer(cfg)

	tlsCfg := &tls.Config{MinVersion: tls.VersionTLS13}
	srv.SetTLSConfig(tlsCfg)

	if srv.tlsConfig != tlsCfg {
		t.Fatal("expected TLS config to be set")
	}
}

func TestShutdown_NoServer(t *testing.T) {
	cfg := &config.ServerConfig{Host: "127.0.0.1", Port: 0}
	srv := NewServer(cfg)

	if err := srv.Shutdown(context.Background()); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestShutdown_WithShutdownFn(t *testing.T) {
	cfg := &config.ServerConfig{Host: "127.0.0.1", Port: 0}
	srv := NewServer(cfg)

	called := false
	srv.shutdownFn = func() { called = true }
	srv.Shutdown(context.Background())
	if !called {
		t.Fatal("expected shutdownFn to be called")
	}
}

func TestListenBindConflict(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	port := ln.Addr().(*net.TCPAddr).Port

	srv := NewServer(&config.ServerConfig{Host: "127.0.0.1", Port: port})
	if err := srv.Listen(); err == nil {
		t.Fatal("Listen on an occupied port: expected error, got nil")
	}

	if err := srv.Serve(context.Background()); err == nil {
		t.Fatal("Serve without successful Listen: expected error, got nil")
	}
}

func TestStartAndShutdown(t *testing.T) {
	cfg := &config.ServerConfig{Host: "127.0.0.1", Port: 0}

	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	port := ln.Addr().(*net.TCPAddr).Port
	ln.Close()
	cfg.Port = port

	srv := NewServer(cfg)

	ctx, cancel := context.WithCancel(context.Background())

	errCh := make(chan error, 1)
	go func() { errCh <- srv.Start(ctx) }()

	time.Sleep(200 * time.Millisecond)

	resp, err := http.Get(fmt.Sprintf("http://127.0.0.1:%d/api/health", port))
	if err != nil {
		t.Fatalf("GET /api/health: %v", err)
	}
	resp.Body.Close()
	if resp.StatusCode != 200 {
		t.Fatalf("expected 200, got %d", resp.StatusCode)
	}

	cancel()
	shutdownCtx, shutdownCancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer shutdownCancel()
	srv.Shutdown(shutdownCtx)

	select {
	case err := <-errCh:
		if err != nil && err != http.ErrServerClosed {
			t.Fatalf("unexpected error: %v", err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("server did not shut down")
	}
}

func TestStartWithTLS(t *testing.T) {
	cfg := &config.ServerConfig{Host: "127.0.0.1", Port: 0}

	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	port := ln.Addr().(*net.TCPAddr).Port
	ln.Close()
	cfg.Port = port

	srv := NewServer(cfg)

	serverKey, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	serial, _ := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	template := x509.Certificate{
		SerialNumber: serial,
		Subject:      pkix.Name{CommonName: "test"},
		NotBefore:    time.Now().Add(-time.Minute),
		NotAfter:     time.Now().Add(time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		IPAddresses:  []net.IP{net.ParseIP("127.0.0.1")},
	}
	certDER, _ := x509.CreateCertificate(rand.Reader, &template, &template, &serverKey.PublicKey, serverKey)
	certPEMBytes := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: certDER})
	keyDER, _ := x509.MarshalECPrivateKey(serverKey)
	keyPEMBytes := pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: keyDER})

	tlsCert, _ := tls.X509KeyPair(certPEMBytes, keyPEMBytes)
	srv.SetTLSConfig(&tls.Config{
		Certificates: []tls.Certificate{tlsCert},
		ClientAuth:   tls.NoClientCert,
	})

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	errCh := make(chan error, 1)
	go func() { errCh <- srv.Start(ctx) }()
	time.Sleep(200 * time.Millisecond)

	client := &http.Client{
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
		},
	}
	resp, err := client.Get(fmt.Sprintf("https://127.0.0.1:%d/api/health", port))
	if err != nil {
		t.Fatalf("GET /api/health over TLS: %v", err)
	}
	resp.Body.Close()
	if resp.StatusCode != 200 {
		t.Fatalf("expected 200, got %d", resp.StatusCode)
	}

	cancel()
	srv.Shutdown(context.Background())
}

type challengeTestEnv struct {
	srv      *Server
	registry *pki.DeviceRegistry
}

func newChallengeTestEnv(t *testing.T) *challengeTestEnv {
	t.Helper()
	cfg := &config.ServerConfig{Host: "127.0.0.1", Port: 0}
	serverKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	registry, users := testRegistries(t)
	mgr := session.NewManager(serverKey)

	srv := NewServer(cfg)
	srv.SetSecurityServices(mgr, registry, users, serverKey)
	srv.SetPairingFingerprint("aa:bb:cc:dd:ee:ff")

	return &challengeTestEnv{srv: srv, registry: registry}
}

func (e *challengeTestEnv) registerActiveDevice(t *testing.T) string {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	pubDER, err := x509.MarshalPKIXPublicKey(&key.PublicKey)
	if err != nil {
		t.Fatal(err)
	}
	pubPEM := string(pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: pubDER}))
	if _, err := e.registry.RegisterDeviceForUser(pubPEM, "test-device", "test-user", ""); err != nil {
		t.Fatal(err)
	}
	return pubPEM
}

func TestCertChallenge_RegisteredActive_Returns200(t *testing.T) {
	env := newChallengeTestEnv(t)
	pubPEM := env.registerActiveDevice(t)

	body, _ := json.Marshal(map[string]string{"public_key": pubPEM})
	req := apiRequest("POST", "/api/cert/challenge", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	env.srv.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", w.Code, w.Body.String())
	}
	var resp map[string]string
	if err := json.Unmarshal(w.Body.Bytes(), &resp); err != nil {
		t.Fatalf("invalid JSON response: %v", err)
	}
	if resp["nonce"] == "" {
		t.Fatal("expected non-empty nonce")
	}
	if len(resp["nonce"]) != 64 {
		t.Fatalf("expected 64-char hex nonce (32 bytes), got length %d", len(resp["nonce"]))
	}
	if resp["expires_at"] == "" {
		t.Fatal("expected non-empty expires_at")
	}
	exp, err := time.Parse(time.RFC3339Nano, resp["expires_at"])
	if err != nil {
		t.Fatalf("expires_at not RFC3339: %v", err)
	}
	if !exp.After(time.Now()) {
		t.Fatal("expected expires_at to be in the future")
	}
}

func assertDecoyChallenge(t *testing.T, srv *Server, w *httptest.ResponseRecorder) {
	t.Helper()
	if w.Code != http.StatusOK {
		t.Fatalf("expected 200 (no key-liveness oracle), got %d: %s", w.Code, w.Body.String())
	}
	var resp map[string]string
	if err := json.Unmarshal(w.Body.Bytes(), &resp); err != nil {
		t.Fatalf("invalid JSON: %v", err)
	}
	if len(resp["nonce"]) != 64 || resp["expires_at"] == "" {
		t.Fatalf("decoy must look exactly like a real challenge, got %v", resp)
	}
	if _, found := srv.nonces.Take(resp["nonce"]); found {
		t.Fatal("decoy nonce must not be stored")
	}
}

func TestCertChallenge_UnknownPublicKey_Decoy(t *testing.T) {
	env := newChallengeTestEnv(t)

	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	pubDER, _ := x509.MarshalPKIXPublicKey(&key.PublicKey)
	pubPEM := string(pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: pubDER}))

	body, _ := json.Marshal(map[string]string{"public_key": pubPEM})
	req := apiRequest("POST", "/api/cert/challenge", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	env.srv.ServeHTTP(w, req)
	assertDecoyChallenge(t, env.srv, w)
}

func TestCertChallenge_RevokedUser_Decoy(t *testing.T) {
	env := newChallengeTestEnv(t)
	pubPEM := env.registerActiveDevice(t)
	if err := env.srv.userRegistry.Revoke("test-user"); err != nil {
		t.Fatal(err)
	}
	body, _ := json.Marshal(map[string]string{"public_key": pubPEM})
	req := apiRequest("POST", "/api/cert/challenge", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	env.srv.ServeHTTP(w, req)
	assertDecoyChallenge(t, env.srv, w)
}

func TestCertChallenge_RevokedDevice_Decoy(t *testing.T) {
	cfg := &config.ServerConfig{Host: "127.0.0.1", Port: 0}
	serverKey, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	registry, users := testRegistries(t)
	mgr := session.NewManager(serverKey)

	srv := NewServer(cfg)
	srv.SetSecurityServices(mgr, registry, users, serverKey)
	srv.SetPairingFingerprint("aa:bb:cc:dd:ee:ff")

	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	pubDER, _ := x509.MarshalPKIXPublicKey(&key.PublicKey)
	pubPEM := string(pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: pubDER}))
	deviceID, err := registry.RegisterDeviceForUser(pubPEM, "test-device", "test-user", "")
	if err != nil {
		t.Fatal(err)
	}

	if err := registry.Revoke(deviceID); err != nil {
		t.Fatal(err)
	}

	body, _ := json.Marshal(map[string]string{"public_key": pubPEM})
	req := apiRequest("POST", "/api/cert/challenge", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	srv.ServeHTTP(w, req)
	assertDecoyChallenge(t, srv, w)
}

func TestCertChallenge_Unauthenticated_NoMTLSRequired(t *testing.T) {
	env := newChallengeTestEnv(t)
	pubPEM := env.registerActiveDevice(t)

	body, _ := json.Marshal(map[string]string{"public_key": pubPEM})
	req := apiRequest("POST", "/api/cert/challenge", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	env.srv.ServeHTTP(w, req)

	if strings.Contains(w.Body.String(), "client certificate required") {
		t.Fatalf("endpoint rejected request with mTLS error: %s", w.Body.String())
	}
	if w.Code != http.StatusOK && w.Code != http.StatusForbidden {
		t.Fatalf("expected 200 or 403, got %d: %s", w.Code, w.Body.String())
	}
}

func TestCertChallenge_MissingPublicKey_Returns400(t *testing.T) {
	env := newChallengeTestEnv(t)

	tests := []struct {
		name string
		body []byte
	}{
		{"empty body", []byte(`{}`)},
		{"empty public_key field", []byte(`{"public_key":""}`)},
		{"invalid JSON", []byte(`not-json`)},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			req := apiRequest("POST", "/api/cert/challenge", bytes.NewReader(tc.body))
			req.Header.Set("Content-Type", "application/json")
			w := httptest.NewRecorder()
			env.srv.ServeHTTP(w, req)

			if w.Code != http.StatusBadRequest {
				t.Fatalf("expected 400, got %d: %s", w.Code, w.Body.String())
			}
		})
	}
}

func TestCertChallenge_IPRateLimited(t *testing.T) {
	// The default limiter allows 60 req/min per IP.
	env := newChallengeTestEnv(t)
	pubPEM := env.registerActiveDevice(t)

	got429 := false
	for i := 0; i < 100; i++ {
		body, _ := json.Marshal(map[string]string{"public_key": pubPEM})
		req := apiRequest("POST", "/api/cert/challenge", bytes.NewReader(body))
		req.Header.Set("Content-Type", "application/json")
		w := httptest.NewRecorder()
		env.srv.ServeHTTP(w, req)
		if w.Code == http.StatusTooManyRequests {
			got429 = true
			break
		}
	}
	if !got429 {
		t.Fatal("expected at least one 429 after 100 rapid requests from the same IP")
	}
}

func TestCertChallenge_PublicKeyRateLimited(t *testing.T) {
	// The per-key limiter allows 10 req/min; distinct IPs keep the IP bucket out of the way.
	env := newChallengeTestEnv(t)
	pubPEM := env.registerActiveDevice(t)

	got429 := false
	for i := 0; i <= 10; i++ {
		body, _ := json.Marshal(map[string]string{"public_key": pubPEM})
		req := apiRequest("POST", "/api/cert/challenge", bytes.NewReader(body))
		req.Header.Set("Content-Type", "application/json")
		req.RemoteAddr = fmt.Sprintf("10.0.0.%d:1234", i+1)
		w := httptest.NewRecorder()
		env.srv.ServeHTTP(w, req)
		if w.Code == http.StatusTooManyRequests {
			got429 = true
			break
		}
	}
	if !got429 {
		t.Fatal("expected at least one 429 after 11 requests with the same public key from different IPs")
	}
}

func TestCertChallenge_NoPairingFingerprint_Returns500(t *testing.T) {
	cfg := &config.ServerConfig{Host: "127.0.0.1", Port: 0}
	serverKey, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	registry, users := testRegistries(t)
	mgr := session.NewManager(serverKey)

	srv := NewServer(cfg)
	srv.SetSecurityServices(mgr, registry, users, serverKey)

	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	pubDER, _ := x509.MarshalPKIXPublicKey(&key.PublicKey)
	pubPEM := string(pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: pubDER}))

	body, _ := json.Marshal(map[string]string{"public_key": pubPEM})
	req := apiRequest("POST", "/api/cert/challenge", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	srv.ServeHTTP(w, req)

	if w.Code != http.StatusInternalServerError {
		t.Fatalf("expected 500 when pairingFingerprint is empty, got %d: %s", w.Code, w.Body.String())
	}
}

type renewTestEnv struct {
	srv          *Server
	registry     *pki.DeviceRegistry
	serverKey    *ecdsa.PrivateKey
	pairingFP    string
	deviceKey    *ecdsa.PrivateKey
	devicePubPEM string
	deviceID     string
}

func newRenewTestEnv(t *testing.T) *renewTestEnv {
	t.Helper()
	cfg := &config.ServerConfig{Host: "127.0.0.1", Port: 0}
	serverKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	registry, users := testRegistries(t)
	mgr := session.NewManager(serverKey)
	const fp = "aa:bb:cc:dd:ee:ff"

	srv := NewServer(cfg)
	srv.SetSecurityServices(mgr, registry, users, serverKey)
	srv.SetPairingFingerprint(fp)

	devKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	pubDER, _ := x509.MarshalPKIXPublicKey(&devKey.PublicKey)
	pubPEM := string(pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: pubDER}))
	deviceID, err := registry.RegisterDeviceForUser(pubPEM, "test-device", "test-user", "")
	if err != nil {
		t.Fatal(err)
	}

	return &renewTestEnv{
		srv:          srv,
		registry:     registry,
		serverKey:    serverKey,
		pairingFP:    fp,
		deviceKey:    devKey,
		devicePubPEM: pubPEM,
		deviceID:     deviceID,
	}
}

func buildCSR(t *testing.T, privKey *ecdsa.PrivateKey) string {
	t.Helper()
	tmpl := x509.CertificateRequest{Subject: pkix.Name{CommonName: "pocketcmd-client"}}
	csrDER, err := x509.CreateCertificateRequest(rand.Reader, &tmpl, privKey)
	if err != nil {
		t.Fatal(err)
	}
	return string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE REQUEST", Bytes: csrDER}))
}

func buildMTLSCert(t *testing.T, serverKey, privKey *ecdsa.PrivateKey) *x509.Certificate {
	t.Helper()
	return issueTestClientCert(t, serverKey, &privKey.PublicKey, 30*time.Minute)
}

func signChallengeForRenew(t *testing.T, privKey *ecdsa.PrivateKey, nonce, fp string) string {
	t.Helper()
	msg := nonce + ":" + fp
	digest := sha256.Sum256([]byte(msg))
	sigBytes, err := ecdsa.SignASN1(rand.Reader, privKey, digest[:])
	if err != nil {
		t.Fatal(err)
	}
	return base64.StdEncoding.EncodeToString(sigBytes)
}

func revokeDevice(t *testing.T, registry *pki.DeviceRegistry, deviceID string) {
	t.Helper()
	if err := registry.Revoke(deviceID); err != nil {
		t.Fatal(err)
	}
}

func putNonce(t *testing.T, env *renewTestEnv, pubPEM string, ttl time.Duration) string {
	t.Helper()
	buf := make([]byte, 16)
	if _, err := rand.Read(buf); err != nil {
		t.Fatal(err)
	}
	nonce := fmt.Sprintf("%x", buf)
	env.srv.nonces.Put(nonce, pki.NonceEntry{
		PublicKeyPEM:      pubPEM,
		ServerFingerprint: env.pairingFP,
		ExpiresAt:         time.Now().Add(ttl),
	})
	return nonce
}

func TestCertRenewChallenge_ValidSignature_Returns200AndCert(t *testing.T) {
	env := newRenewTestEnv(t)
	nonce := putNonce(t, env, env.devicePubPEM, 30*time.Second)
	sig := signChallengeForRenew(t, env.deviceKey, nonce, env.pairingFP)
	csrPEM := buildCSR(t, env.deviceKey)

	body, _ := json.Marshal(map[string]string{
		"signed_challenge": sig,
		"public_key":       env.devicePubPEM,
		"csr":              csrPEM,
		"nonce":            nonce,
	})
	req := apiRequest("POST", "/api/cert/renew", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	env.srv.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", w.Code, w.Body.String())
	}
	var resp map[string]string
	json.Unmarshal(w.Body.Bytes(), &resp)
	if resp["cert"] == "" {
		t.Fatal("expected non-empty cert in response")
	}
	block, _ := pem.Decode([]byte(resp["cert"]))
	if block == nil || block.Type != "CERTIFICATE" {
		t.Fatal("expected valid CERTIFICATE PEM in response")
	}
}

func TestCertRenewChallenge_DartStylePEMWithoutTrailingNewline_Returns200(t *testing.T) {
	env := newRenewTestEnv(t)

	// Same key material as devicePubPEM, but PEM without the trailing newline as the app sends it.
	dartPubPEM := strings.TrimRight(env.devicePubPEM, "\n")
	if dartPubPEM == env.devicePubPEM {
		t.Fatal("test setup: expected Go PEM to end with a newline")
	}
	removeDevice(t, env.registry, env.deviceID)
	if _, err := env.registry.RegisterDeviceForUser(dartPubPEM, "dart-device", "test-user", ""); err != nil {
		t.Fatal(err)
	}

	nonce := putNonce(t, env, dartPubPEM, 30*time.Second)
	sig := signChallengeForRenew(t, env.deviceKey, nonce, env.pairingFP)
	csrPEM := buildCSR(t, env.deviceKey)

	body, _ := json.Marshal(map[string]string{
		"signed_challenge": sig,
		"public_key":       dartPubPEM,
		"csr":              csrPEM,
		"nonce":            nonce,
	})
	req := apiRequest("POST", "/api/cert/renew", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	env.srv.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("expected 200 for Dart-framed PEM, got %d: %s", w.Code, w.Body.String())
	}
}

func TestCertRenewChallenge_NonceNotFound_Returns401(t *testing.T) {
	env := newRenewTestEnv(t)
	sig := signChallengeForRenew(t, env.deviceKey, "no-such-nonce", env.pairingFP)
	csrPEM := buildCSR(t, env.deviceKey)

	body, _ := json.Marshal(map[string]string{
		"signed_challenge": sig,
		"public_key":       env.devicePubPEM,
		"csr":              csrPEM,
		"nonce":            "no-such-nonce",
	})
	req := apiRequest("POST", "/api/cert/renew", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	env.srv.ServeHTTP(w, req)

	if w.Code != http.StatusUnauthorized {
		t.Fatalf("expected 401, got %d: %s", w.Code, w.Body.String())
	}
}

func TestCertRenewChallenge_ExpiredNonce_Returns401(t *testing.T) {
	env := newRenewTestEnv(t)
	nonce := putNonce(t, env, env.devicePubPEM, -time.Second)
	sig := signChallengeForRenew(t, env.deviceKey, nonce, env.pairingFP)
	csrPEM := buildCSR(t, env.deviceKey)

	body, _ := json.Marshal(map[string]string{
		"signed_challenge": sig,
		"public_key":       env.devicePubPEM,
		"csr":              csrPEM,
		"nonce":            nonce,
	})
	req := apiRequest("POST", "/api/cert/renew", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	env.srv.ServeHTTP(w, req)

	if w.Code != http.StatusUnauthorized {
		t.Fatalf("expected 401 for expired nonce, got %d: %s", w.Code, w.Body.String())
	}
}

func TestCertRenewChallenge_BadSignature_Returns401(t *testing.T) {
	env := newRenewTestEnv(t)
	nonce := putNonce(t, env, env.devicePubPEM, 30*time.Second)
	csrPEM := buildCSR(t, env.deviceKey)

	body, _ := json.Marshal(map[string]string{
		"signed_challenge": base64.StdEncoding.EncodeToString([]byte("not-a-valid-sig")),
		"public_key":       env.devicePubPEM,
		"csr":              csrPEM,
		"nonce":            nonce,
	})
	req := apiRequest("POST", "/api/cert/renew", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	env.srv.ServeHTTP(w, req)

	if w.Code != http.StatusUnauthorized {
		t.Fatalf("expected 401 for bad signature, got %d: %s", w.Code, w.Body.String())
	}
}

func TestCertRenewChallenge_WrongFingerprintSigned_Returns401(t *testing.T) {
	env := newRenewTestEnv(t)
	nonce := putNonce(t, env, env.devicePubPEM, 30*time.Second)
	sig := signChallengeForRenew(t, env.deviceKey, nonce, "wrong:fingerprint")
	csrPEM := buildCSR(t, env.deviceKey)

	body, _ := json.Marshal(map[string]string{
		"signed_challenge": sig,
		"public_key":       env.devicePubPEM,
		"csr":              csrPEM,
		"nonce":            nonce,
	})
	req := apiRequest("POST", "/api/cert/renew", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	env.srv.ServeHTTP(w, req)

	if w.Code != http.StatusUnauthorized {
		t.Fatalf("expected 401 for wrong fingerprint in signed message, got %d: %s", w.Code, w.Body.String())
	}
}

func TestCertRenewChallenge_MissingCSR_Returns400(t *testing.T) {
	env := newRenewTestEnv(t)
	nonce := putNonce(t, env, env.devicePubPEM, 30*time.Second)
	sig := signChallengeForRenew(t, env.deviceKey, nonce, env.pairingFP)

	body, _ := json.Marshal(map[string]string{
		"signed_challenge": sig,
		"public_key":       env.devicePubPEM,
		"nonce":            nonce,
	})
	req := apiRequest("POST", "/api/cert/renew", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	env.srv.ServeHTTP(w, req)

	if w.Code != http.StatusBadRequest {
		t.Fatalf("expected 400 for missing csr, got %d: %s", w.Code, w.Body.String())
	}
}

func TestCertRenewChallenge_MissingPublicKey_Returns400(t *testing.T) {
	env := newRenewTestEnv(t)
	csrPEM := buildCSR(t, env.deviceKey)

	body, _ := json.Marshal(map[string]string{
		"signed_challenge": base64.StdEncoding.EncodeToString([]byte("sig")),
		"csr":              csrPEM,
	})
	req := apiRequest("POST", "/api/cert/renew", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	env.srv.ServeHTTP(w, req)

	if w.Code != http.StatusBadRequest {
		t.Fatalf("expected 400 for missing public_key, got %d: %s", w.Code, w.Body.String())
	}
}

func TestCertRenewChallenge_CSRPublicKeyMismatch_Returns400(t *testing.T) {
	env := newRenewTestEnv(t)
	nonce := putNonce(t, env, env.devicePubPEM, 30*time.Second)
	sig := signChallengeForRenew(t, env.deviceKey, nonce, env.pairingFP)

	otherKey, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	csrPEM := buildCSR(t, otherKey)

	body, _ := json.Marshal(map[string]string{
		"signed_challenge": sig,
		"public_key":       env.devicePubPEM,
		"csr":              csrPEM,
		"nonce":            nonce,
	})
	req := apiRequest("POST", "/api/cert/renew", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	env.srv.ServeHTTP(w, req)

	if w.Code != http.StatusBadRequest {
		t.Fatalf("expected 400 for CSR/public_key mismatch, got %d: %s", w.Code, w.Body.String())
	}
}

func TestCertRenewChallenge_RevokedDevice_Returns403(t *testing.T) {
	env := newRenewTestEnv(t)

	revokeDevice(t, env.registry, env.deviceID)

	nonce := putNonce(t, env, env.devicePubPEM, 30*time.Second)
	sig := signChallengeForRenew(t, env.deviceKey, nonce, env.pairingFP)
	csrPEM := buildCSR(t, env.deviceKey)

	body, _ := json.Marshal(map[string]string{
		"signed_challenge": sig,
		"public_key":       env.devicePubPEM,
		"csr":              csrPEM,
		"nonce":            nonce,
	})
	req := apiRequest("POST", "/api/cert/renew", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	env.srv.ServeHTTP(w, req)

	if w.Code != http.StatusForbidden {
		t.Fatalf("expected 403 for revoked device, got %d: %s", w.Code, w.Body.String())
	}
}

func TestCertRenewChallenge_AtomicNonce_SingleSuccess(t *testing.T) {
	env := newRenewTestEnv(t)
	nonce := putNonce(t, env, env.devicePubPEM, 30*time.Second)
	sig := signChallengeForRenew(t, env.deviceKey, nonce, env.pairingFP)
	csrPEM := buildCSR(t, env.deviceKey)

	body, _ := json.Marshal(map[string]string{
		"signed_challenge": sig,
		"public_key":       env.devicePubPEM,
		"csr":              csrPEM,
		"nonce":            nonce,
	})

	const workers = 20
	var successes int32
	var wg sync.WaitGroup
	wg.Add(workers)
	for i := 0; i < workers; i++ {
		go func() {
			defer wg.Done()
			req := apiRequest("POST", "/api/cert/renew", bytes.NewReader(body))
			req.Header.Set("Content-Type", "application/json")
			w := httptest.NewRecorder()
			env.srv.ServeHTTP(w, req)
			if w.Code == http.StatusOK {
				atomic.AddInt32(&successes, 1)
			}
		}()
	}
	wg.Wait()

	if successes != 1 {
		t.Fatalf("expected exactly one 200 from concurrent renewals, got %d", successes)
	}
}

func TestCertRenewChallenge_AllUnauthorizedReturnsSameBody(t *testing.T) {
	env := newRenewTestEnv(t)

	do401 := func(t *testing.T, label string, body []byte) string {
		t.Helper()
		req := apiRequest("POST", "/api/cert/renew", bytes.NewReader(body))
		req.Header.Set("Content-Type", "application/json")
		w := httptest.NewRecorder()
		env.srv.ServeHTTP(w, req)
		if w.Code != http.StatusUnauthorized {
			t.Fatalf("[%s] expected 401, got %d: %s", label, w.Code, w.Body.String())
		}
		return strings.TrimSpace(w.Body.String())
	}

	csrPEM := buildCSR(t, env.deviceKey)
	fakeSig := base64.StdEncoding.EncodeToString([]byte("garbage"))

	body1, _ := json.Marshal(map[string]string{
		"signed_challenge": fakeSig,
		"public_key":       env.devicePubPEM,
		"csr":              csrPEM,
		"nonce":            "absent-nonce",
	})
	msg1 := do401(t, "nonce-not-found", body1)

	expiredNonce := putNonce(t, env, env.devicePubPEM, -time.Second)
	sig2 := signChallengeForRenew(t, env.deviceKey, expiredNonce, env.pairingFP)
	body2, _ := json.Marshal(map[string]string{
		"signed_challenge": sig2,
		"public_key":       env.devicePubPEM,
		"csr":              csrPEM,
		"nonce":            expiredNonce,
	})
	msg2 := do401(t, "expired-nonce", body2)

	validNonce := putNonce(t, env, env.devicePubPEM, 30*time.Second)
	body3, _ := json.Marshal(map[string]string{
		"signed_challenge": fakeSig,
		"public_key":       env.devicePubPEM,
		"csr":              csrPEM,
		"nonce":            validNonce,
	})
	msg3 := do401(t, "bad-signature", body3)

	n4 := putNonce(t, env, env.devicePubPEM, 30*time.Second)
	sig4 := signChallengeForRenew(t, env.deviceKey, n4, "wrong:fp")
	body4, _ := json.Marshal(map[string]string{
		"signed_challenge": sig4,
		"public_key":       env.devicePubPEM,
		"csr":              csrPEM,
		"nonce":            n4,
	})
	msg4 := do401(t, "wrong-fp", body4)

	if msg1 != msg2 || msg2 != msg3 || msg3 != msg4 {
		t.Fatalf("401 bodies differ:\n  nonce-not-found: %q\n  expired-nonce:   %q\n  bad-signature:   %q\n  wrong-fp:        %q",
			msg1, msg2, msg3, msg4)
	}
}

func TestCertRenewStandard_MTLSValidCSR_Returns200(t *testing.T) {
	env := newRenewTestEnv(t)
	mtlsCert := buildMTLSCert(t, env.serverKey, env.deviceKey)
	csrPEM := buildCSR(t, env.deviceKey)

	body, _ := json.Marshal(map[string]string{"csr": csrPEM})
	req := requestWithTLS("POST", "/api/cert/renew", body, mtlsCert)
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	env.srv.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", w.Code, w.Body.String())
	}
	var resp map[string]string
	json.Unmarshal(w.Body.Bytes(), &resp)
	if resp["cert"] == "" {
		t.Fatal("expected cert in response")
	}
}

func TestCertRenewStandard_NoMTLS_Returns401(t *testing.T) {
	env := newRenewTestEnv(t)
	csrPEM := buildCSR(t, env.deviceKey)

	body, _ := json.Marshal(map[string]string{"csr": csrPEM})
	req := apiRequest("POST", "/api/cert/renew", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	env.srv.ServeHTTP(w, req)

	if w.Code != http.StatusUnauthorized {
		t.Fatalf("expected 401 with no mTLS cert, got %d: %s", w.Code, w.Body.String())
	}
}

func TestCertRenewStandard_RevokedDevice_Returns403(t *testing.T) {
	env := newRenewTestEnv(t)

	revokeDevice(t, env.registry, env.deviceID)

	mtlsCert := buildMTLSCert(t, env.serverKey, env.deviceKey)
	csrPEM := buildCSR(t, env.deviceKey)

	body, _ := json.Marshal(map[string]string{"csr": csrPEM})
	req := requestWithTLS("POST", "/api/cert/renew", body, mtlsCert)
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	env.srv.ServeHTTP(w, req)

	if w.Code != http.StatusForbidden {
		t.Fatalf("expected 403 for revoked device, got %d: %s", w.Code, w.Body.String())
	}
}

func TestCertRenewStandard_CSRPublicKeyMismatch_Returns400(t *testing.T) {
	env := newRenewTestEnv(t)
	mtlsCert := buildMTLSCert(t, env.serverKey, env.deviceKey)

	otherKey, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	csrPEM := buildCSR(t, otherKey)

	body, _ := json.Marshal(map[string]string{"csr": csrPEM})
	req := requestWithTLS("POST", "/api/cert/renew", body, mtlsCert)
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	env.srv.ServeHTTP(w, req)

	if w.Code != http.StatusBadRequest {
		t.Fatalf("expected 400 for CSR/mTLS key mismatch, got %d: %s", w.Code, w.Body.String())
	}
}

func TestRevokedUser_NoCredentials(t *testing.T) {
	env := newRenewTestEnv(t)
	cert := buildMTLSCert(t, env.serverKey, env.deviceKey)

	w := httptest.NewRecorder()
	env.srv.ServeHTTP(w, requestWithTLS("POST", "/api/session", nil, cert))
	if w.Code != http.StatusOK {
		t.Fatalf("session before revoke: %d %s", w.Code, w.Body.String())
	}

	if err := env.srv.userRegistry.Revoke("test-user"); err != nil {
		t.Fatal(err)
	}
	if dev, _ := env.registry.FindByID(env.deviceID); dev.Status != pki.DeviceStatusActive {
		t.Fatal("test setup: the device itself must stay active")
	}

	w = httptest.NewRecorder()
	env.srv.ServeHTTP(w, requestWithTLS("POST", "/api/session", nil, cert))
	if w.Code != http.StatusForbidden {
		t.Fatalf("session after user revoke: %d %s, want 403", w.Code, w.Body.String())
	}

	csr := buildCSR(t, env.deviceKey)
	body, _ := json.Marshal(map[string]string{"csr": csr})
	w = httptest.NewRecorder()
	env.srv.ServeHTTP(w, requestWithTLS("POST", "/api/cert/renew", body, cert))
	if w.Code != http.StatusForbidden {
		t.Fatalf("mTLS renew after user revoke: %d %s, want 403", w.Code, w.Body.String())
	}

	nonce := putNonce(t, env, env.devicePubPEM, 30*time.Second)
	body, _ = json.Marshal(map[string]string{
		"signed_challenge": signChallengeForRenew(t, env.deviceKey, nonce, env.pairingFP),
		"public_key":       env.devicePubPEM,
		"csr":              csr,
		"nonce":            nonce,
	})
	req := apiRequest("POST", "/api/cert/renew", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	w = httptest.NewRecorder()
	env.srv.ServeHTTP(w, req)
	if w.Code != http.StatusForbidden {
		t.Fatalf("challenge renew after user revoke: %d %s, want 403", w.Code, w.Body.String())
	}
}

func TestListen_IPv6Host(t *testing.T) {
	srv := NewServer(&config.ServerConfig{Host: "::1", Port: 0})
	if err := srv.Listen(); err != nil {
		t.Skipf("IPv6 loopback unavailable: %v", err)
	}
	defer srv.listener.Close()
	if host, _, err := net.SplitHostPort(srv.listener.Addr().String()); err != nil || host != "::1" {
		t.Fatalf("listener bound to %s, want [::1]:<port> (%v)", srv.listener.Addr(), err)
	}
}
