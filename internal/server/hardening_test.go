package server

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"encoding/pem"
	"errors"
	"io"
	"math/big"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/pocketcmd/pocketcmd-server/internal/authz"
	"github.com/pocketcmd/pocketcmd-server/internal/config"
	"github.com/pocketcmd/pocketcmd-server/internal/pki"
	"github.com/pocketcmd/pocketcmd-server/internal/session"
)

type certGateEnv struct {
	srv       *Server
	registry  *pki.DeviceRegistry
	mgr       *session.Manager
	serverKey *ecdsa.PrivateKey
	deviceKey *ecdsa.PrivateKey
	deviceID  string
}

func newCertGateEnv(t *testing.T) *certGateEnv {
	t.Helper()
	serverKey, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	db := testStateDB(t)
	registry := testDeviceRegistryOn(db)
	users := pki.NewUserRegistry(db)
	mgr := session.NewManager(serverKey)
	srv := NewServer(&config.ServerConfig{Host: "127.0.0.1", Port: 0})
	srv.SetSecurityServices(mgr, registry, users, serverKey)
	srv.SetPairingFingerprint("aa:bb")

	deviceKey, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	pubDER, _ := x509.MarshalPKIXPublicKey(&deviceKey.PublicKey)
	pubPEM := string(pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: pubDER}))
	deviceID, err := registry.RegisterDeviceForUser(pubPEM, "phone", "u1", "")
	if err != nil {
		t.Fatal(err)
	}
	bindDeviceToAdminUser(t, registry, users, deviceID)
	return &certGateEnv{srv: srv, registry: registry, mgr: mgr, serverKey: serverKey, deviceKey: deviceKey, deviceID: deviceID}
}

func (e *certGateEnv) session(t *testing.T, cert *x509.Certificate) *httptest.ResponseRecorder {
	t.Helper()
	w := httptest.NewRecorder()
	e.srv.ServeHTTP(w, requestWithTLS("POST", "/api/session", nil, cert))
	return w
}

func (e *certGateEnv) authed(t *testing.T, cert *x509.Certificate) *httptest.ResponseRecorder {
	t.Helper()
	token, err := e.mgr.Issue(e.deviceID, pki.CertFingerprint(cert.Raw))
	if err != nil {
		t.Fatal(err)
	}
	req := requestWithTLS("GET", "/api/host-keys", nil, cert)
	req.Header.Set("Authorization", "Bearer "+token)
	w := httptest.NewRecorder()
	e.srv.ServeHTTP(w, req)
	return w
}

func (e *certGateEnv) renew(t *testing.T, cert *x509.Certificate) *httptest.ResponseRecorder {
	t.Helper()
	body, _ := json.Marshal(map[string]string{"csr": buildCSR(t, e.deviceKey)})
	req := requestWithTLS("POST", "/api/cert/renew", body, cert)
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	e.srv.ServeHTTP(w, req)
	return w
}

func errorCode(t *testing.T, w *httptest.ResponseRecorder) string {
	t.Helper()
	var resp map[string]string
	_ = json.Unmarshal(w.Body.Bytes(), &resp)
	return resp["error"]
}

func TestCertGate_ExpiredBeyondGraceIsRejectedEverywhere(t *testing.T) {
	env := newCertGateEnv(t)
	expired := issueTestClientCert(t, env.serverKey, &env.deviceKey.PublicKey, -20*time.Minute)

	if w := env.session(t, expired); w.Code != http.StatusUnauthorized || errorCode(t, w) != "client_cert_expired" {
		t.Fatalf("/api/session: want 401 client_cert_expired, got %d %s", w.Code, w.Body.String())
	}
	if w := env.authed(t, expired); w.Code != http.StatusUnauthorized || errorCode(t, w) != "client_cert_expired" {
		t.Fatalf("JWT route: want 401 client_cert_expired, got %d %s", w.Code, w.Body.String())
	}
	if w := env.renew(t, expired); w.Code != http.StatusUnauthorized || errorCode(t, w) != "client_cert_expired" {
		t.Fatalf("mTLS renew: want 401 client_cert_expired, got %d %s", w.Code, w.Body.String())
	}
}

func TestCertGate_WithinGraceStillRenews(t *testing.T) {
	env := newCertGateEnv(t)
	inGrace := issueTestClientCert(t, env.serverKey, &env.deviceKey.PublicKey, -3*time.Minute)
	w := env.renew(t, inGrace)
	if w.Code != http.StatusOK {
		t.Fatalf("renewal inside grace must succeed, got %d %s", w.Code, w.Body.String())
	}
	var resp map[string]string
	if err := json.Unmarshal(w.Body.Bytes(), &resp); err != nil || resp["cert"] == "" {
		t.Fatalf("no cert in renewal response: %s", w.Body.String())
	}
	renewed := parseCertificate(t, []byte(resp["cert"]))
	if w := env.session(t, renewed); w.Code != http.StatusOK {
		t.Fatalf("renewed cert rejected: %d %s", w.Code, w.Body.String())
	}
}

func TestCertGate_SelfSignedForRegisteredKeyIsRejected(t *testing.T) {
	env := newCertGateEnv(t)
	serial, _ := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	tmpl := &x509.Certificate{
		SerialNumber: serial, Subject: pkix.Name{CommonName: "pocketcmd-client"},
		NotBefore: time.Now().Add(-time.Minute), NotAfter: time.Now().Add(24 * time.Hour),
	}
	der, _ := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &env.deviceKey.PublicKey, env.deviceKey)
	selfSigned, _ := x509.ParseCertificate(der)

	for name, w := range map[string]*httptest.ResponseRecorder{
		"session": env.session(t, selfSigned),
		"jwt":     env.authed(t, selfSigned),
		"renew":   env.renew(t, selfSigned),
	} {
		if w.Code != http.StatusUnauthorized || errorCode(t, w) != "client_cert_invalid" {
			t.Fatalf("%s: want 401 client_cert_invalid for a self-signed cert, got %d %s", name, w.Code, w.Body.String())
		}
	}
	other, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	stranger := issueTestClientCert(t, env.serverKey, &other.PublicKey, 30*time.Minute)
	if w := env.session(t, stranger); w.Code != http.StatusForbidden || errorCode(t, w) != "device_not_registered" {
		t.Fatalf("unregistered key: want 403 device_not_registered, got %d %s", w.Code, w.Body.String())
	}
}

func TestRateLimit_PreAuthRoutes(t *testing.T) {
	for _, route := range []struct{ method, path string }{
		{"GET", "/api/config"},
		{"GET", "/api/capabilities"},
		{"POST", "/api/cert/renew"},
	} {
		t.Run(route.path, func(t *testing.T) {
			env := newCertGateEnv(t)
			var last int
			for i := 0; i < 61; i++ {
				req := apiRequest(route.method, route.path, bytes.NewReader([]byte(`{}`)))
				w := httptest.NewRecorder()
				env.srv.ServeHTTP(w, req)
				last = w.Code
			}
			if last != http.StatusTooManyRequests {
				t.Fatalf("61st request must be 429, got %d", last)
			}
		})
	}
}

func TestRateLimit_SessionEndpoint(t *testing.T) {
	env := newCertGateEnv(t)
	cert := issueTestClientCert(t, env.serverKey, &env.deviceKey.PublicKey, 30*time.Minute)
	var last int
	for i := 0; i < 61; i++ {
		last = env.session(t, cert).Code
	}
	if last != http.StatusTooManyRequests {
		t.Fatalf("61st /api/session must be 429, got %d", last)
	}
}

func TestCertChallenge_PerKeyLimiterIgnoresPEMFraming(t *testing.T) {
	env := newChallengeTestEnv(t)
	pubPEM := env.registerActiveDevice(t)
	variants := []string{pubPEM, strings.TrimSuffix(pubPEM, "\n")}
	var last int
	for i := 0; i < 11; i++ {
		body, _ := json.Marshal(map[string]string{"public_key": variants[i%2]})
		req := apiRequest("POST", "/api/cert/challenge", bytes.NewReader(body))
		req.RemoteAddr = "203.0.113." + string(rune('1'+i)) + ":1000"
		req.Header.Set("Content-Type", "application/json")
		w := httptest.NewRecorder()
		env.srv.ServeHTTP(w, req)
		last = w.Code
	}
	if last != http.StatusTooManyRequests {
		t.Fatalf("11th challenge for the same key must be 429 regardless of PEM framing, got %d", last)
	}
	body, _ := json.Marshal(map[string]string{"public_key": "not a pem"})
	req := apiRequest("POST", "/api/cert/challenge", bytes.NewReader(body))
	w := httptest.NewRecorder()
	env.srv.ServeHTTP(w, req)
	if w.Code != http.StatusBadRequest {
		t.Fatalf("malformed key: want 400, got %d", w.Code)
	}
}

func TestLogPath_MasksInviteCodes(t *testing.T) {
	cases := map[string]string{
		"/api/invites":                             "/api/invites",
		"/api/invites/":                            "/api/invites/",
		"/api/invites/abcd1234":                    "/api/invites/abcd1234",
		"/api/invites/abcd1234efgh5678ijkl":        "/api/invites/abcd1234…",
		"/api/invites/abcd1234efgh5678ijkl/revoke": "/api/invites/abcd1234…/revoke",
		"/api/users/some-user-id":                  "/api/users/some-user-id",
	}
	for in, want := range cases {
		if got := logPath(in); got != want {
			t.Errorf("logPath(%q)=%q want %q", in, got, want)
		}
	}
}

func TestLoggingMiddleware_RequestLogMasksInviteCode(t *testing.T) {
	var buf bytes.Buffer
	logger := testAuditLogger(&buf)
	h := LoggingMiddleware(logger, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusForbidden)
	}))
	const code = "k7f3m9q2w8e1r5t6y0u4"
	h.ServeHTTP(httptest.NewRecorder(), apiRequest("DELETE", "/api/invites/"+code, nil))
	if strings.Contains(buf.String(), code) {
		t.Fatalf("full invite code leaked into the request log: %s", buf.String())
	}
	if !strings.Contains(buf.String(), "/api/invites/"+code[:8]) {
		t.Fatalf("masked prefix missing from log: %s", buf.String())
	}
}

func TestLineWindow_KeepsNewestN(t *testing.T) {
	w := newLineWindow(3)
	for _, l := range []string{"a", "b", "c", "d", "e"} {
		w.push([]byte(l))
	}
	got := w.lines()
	if len(got) != 3 || string(got[0]) != "c" || string(got[1]) != "d" || string(got[2]) != "e" {
		t.Fatalf("want [c d e], got %q", got)
	}
	w2 := newLineWindow(5)
	w2.push([]byte("only"))
	if got := w2.lines(); len(got) != 1 || string(got[0]) != "only" {
		t.Fatalf("partial window: %q", got)
	}
	if got := newLineWindow(0).lines(); len(got) != 0 {
		t.Fatalf("empty window must yield nothing: %q", got)
	}
}

func TestRouteBuilders_CapJSONBodies(t *testing.T) {
	f := newTeamTestFixture(t)
	var readErr error
	read := func(w http.ResponseWriter, r *http.Request) {
		_, readErr = io.ReadAll(r.Body)
		w.WriteHeader(http.StatusNoContent)
	}
	f.srv.handle("POST /api/test/member", f.srv.memberRoute(read))
	f.srv.handle("POST /api/test/admin", f.srv.adminRoute(read))
	f.srv.handle("POST /api/test/owner", f.srv.ownerRoute(read))
	f.srv.handle("POST /api/test/perm", f.srv.permRoute(authz.PermMetricsRead, read))

	big := strings.Repeat("x", maxJSONBody+1)
	for _, path := range []string{"/api/test/member", "/api/test/admin", "/api/test/owner", "/api/test/perm"} {
		readErr = nil
		f.do("POST", path, big, f.adminToken, f.adminCert)
		var tooBig *http.MaxBytesError
		if !errors.As(readErr, &tooBig) {
			t.Errorf("%s: body over maxJSONBody should fail to read, got %v", path, readErr)
		}
	}
}
