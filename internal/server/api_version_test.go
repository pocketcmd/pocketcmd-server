package server

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestRequireAPIVersion(t *testing.T) {
	f := newMatrixFixture(t)

	send := func(method, path, header string) *httptest.ResponseRecorder {
		req := httptest.NewRequest(method, path, nil)
		if header != "" {
			req.Header.Set(APIVersionHeader, header)
		}
		w := httptest.NewRecorder()
		f.srv.ServeHTTP(w, req)
		return w
	}
	assertMismatch := func(t *testing.T, w *httptest.ResponseRecorder) {
		t.Helper()
		if w.Code != http.StatusBadRequest {
			t.Fatalf("expected 400, got %d: %s", w.Code, w.Body.String())
		}
		var body map[string]string
		if err := json.NewDecoder(w.Body).Decode(&body); err != nil {
			t.Fatal(err)
		}
		if body["error"] != "api_version_mismatch" || body["server_api_version"] != APIVersion {
			t.Fatalf("unexpected body %v", body)
		}
	}

	for _, path := range []string{"/api/health", "/api/capabilities"} {
		if w := send("GET", path, ""); w.Code != http.StatusOK {
			t.Errorf("GET %s without header: expected 200, got %d", path, w.Code)
		}
	}

	for _, rt := range authSweepRoutes {
		assertMismatch(t, send(rt.method, rt.url, ""))
		assertMismatch(t, send(rt.method, rt.url, "0.9"))
	}
	for _, c := range []struct{ method, path string }{
		{"GET", "/api/config"},
		{"POST", "/api/pair"},
		{"POST", "/api/session"},
		{"POST", "/api/cert/challenge"},
		{"POST", "/api/cert/renew"},
	} {
		assertMismatch(t, send(c.method, c.path, ""))
		assertMismatch(t, send(c.method, c.path, "2.0"))
		assertMismatch(t, send(c.method, c.path, "10.0"))
	}

	for _, header := range []string{APIVersion, "1", "1.7"} {
		if w := send("GET", "/api/users", header); w.Code != http.StatusUnauthorized {
			t.Fatalf("header %q: expected 401 past the version gate, got %d: %s", header, w.Code, w.Body.String())
		}
	}
}
