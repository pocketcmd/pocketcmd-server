package server

import (
	"bytes"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/pocketcmd/pocketcmd-server/internal/config"
)

func TestCapabilitiesEndpoint(t *testing.T) {
	cfg := &config.ServerConfig{Port: 0, Host: "127.0.0.1"}
	srv := NewServer(cfg)

	srv.SetCapabilities("0.1.0")

	req := apiRequest("GET", "/api/capabilities", nil)
	w := httptest.NewRecorder()
	srv.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d", w.Code)
	}

	var resp struct {
		Features   *json.RawMessage `json:"features"`
		Version    string           `json:"version"`
		APIVersion string           `json:"api_version"`
	}
	if err := json.NewDecoder(w.Body).Decode(&resp); err != nil {
		t.Fatalf("decode: %v", err)
	}

	if resp.Features != nil {
		t.Errorf("expected no features field, got %s", *resp.Features)
	}
	if resp.Version != "0.1.0" {
		t.Errorf("expected version 0.1.0, got %s", resp.Version)
	}
	if resp.APIVersion == "" {
		t.Error("expected api_version to be advertised")
	}
}

func TestRequireJWT_RevokedUserIsRejected(t *testing.T) {
	f := newTeamTestFixture(t)

	if err := f.users.Revoke(f.adminUser.UserID); err != nil {
		t.Fatalf("revoke user: %v", err)
	}

	body, _ := json.Marshal(map[string]interface{}{
		"device_id":    "test-device",
		"device_token": "tok",
		"platform":     "ios",
		"signed_token": "sig",
		"expires_at":   time.Now().Add(time.Hour).Unix(),
	})
	req := apiRequest("POST", "/api/push/register", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer "+f.adminToken)
	req.TLS = &tls.ConnectionState{
		PeerCertificates: []*x509.Certificate{f.adminCert},
	}
	w := httptest.NewRecorder()
	f.srv.ServeHTTP(w, req)

	if w.Code != http.StatusForbidden {
		t.Fatalf("expected 403 for revoked user, got %d: %s", w.Code, w.Body.String())
	}
	var resp map[string]string
	if err := json.NewDecoder(w.Body).Decode(&resp); err != nil {
		t.Fatalf("expected JSON body on 403, decode error: %v", err)
	}
	if resp["error"] != "forbidden" {
		t.Errorf("expected error 'forbidden', got %q", resp["error"])
	}
}

func TestDisabledFeaturesReturn404(t *testing.T) {
	cfg := &config.ServerConfig{Port: 0, Host: "127.0.0.1"}
	srv := NewServer(cfg)

	endpoints := []struct {
		method string
		path   string
	}{
		{"GET", "/api/sync/manifest"},
		{"POST", "/api/sync/pull"},
		{"POST", "/api/sync/push"},
		{"GET", "/api/metrics/available"},
		{"GET", "/api/metrics/latest"},
		{"GET", "/api/metrics/series"},
	}

	for _, ep := range endpoints {
		req := apiRequest(ep.method, ep.path, nil)
		w := httptest.NewRecorder()
		srv.ServeHTTP(w, req)
		if w.Code != http.StatusNotFound {
			t.Errorf("%s %s: expected 404, got %d", ep.method, ep.path, w.Code)
		}
	}
}
