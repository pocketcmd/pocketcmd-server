package server

import (
	"encoding/json"
	"fmt"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"sync"
	"testing"
)

type memSink struct {
	mu      sync.Mutex
	entries []json.RawMessage
}

func (s *memSink) Append(entry json.RawMessage) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.entries = append(s.entries, entry)
}

func (s *memSink) last(t *testing.T) map[string]any {
	t.Helper()
	s.mu.Lock()
	defer s.mu.Unlock()
	if len(s.entries) == 0 {
		t.Fatal("no log entries captured")
	}
	var m map[string]any
	if err := json.Unmarshal(s.entries[len(s.entries)-1], &m); err != nil {
		t.Fatal(err)
	}
	return m
}

func TestBufferHandler_AttrsAndGroups(t *testing.T) {
	sink := &memSink{}
	logger := slog.New(NewBufferHandler(sink)).
		With("device_id", "dev1").
		WithGroup("req")
	logger.Warn("denied", "path", "/x", slog.Group("tls", "ver", "1.3"))

	m := sink.last(t)
	if m["level"] != "WARN" || m["msg"] != "denied" {
		t.Fatalf("record fields = %v", m)
	}
	if m["device_id"] != "dev1" {
		t.Fatalf("device_id = %v", m["device_id"])
	}
	if m["req.path"] != "/x" || m["req.tls.ver"] != "1.3" {
		t.Fatalf("grouped keys = %v", m)
	}
}

func TestTeeHandler_FansOut(t *testing.T) {
	a, b := &memSink{}, &memSink{}
	logger := slog.New(NewTeeHandler(NewBufferHandler(a), NewBufferHandler(b)))
	logger.Info("request", "path", "/tee")
	for _, sink := range []*memSink{a, b} {
		if m := sink.last(t); m["path"] != "/tee" {
			t.Fatalf("tee entry = %v", m)
		}
	}
}

func TestLoggingMiddleware_CallerAttribution(t *testing.T) {
	sink := &memSink{}
	logger := slog.New(NewBufferHandler(sink))
	// The handler fills the holder the logging middleware planted, as requireJWT would.
	h := LoggingMiddleware(logger, http.HandlerFunc(
		func(w http.ResponseWriter, r *http.Request) {
			if c := callerHolder(r.Context()); c != nil {
				c.deviceID = "dev-42"
				c.userID = "u-1"
				c.displayName = "alice"
			}
			w.WriteHeader(http.StatusTeapot)
		}))
	srv := httptest.NewServer(h)
	defer srv.Close()
	if _, err := http.Get(srv.URL + "/api/thing"); err != nil {
		t.Fatal(err)
	}

	m := sink.last(t)
	if m["device_id"] != "dev-42" || m["user_id"] != "u-1" || m["user"] != "alice" {
		t.Fatalf("caller attribution missing: %v", m)
	}
	if m["remote"] == "" || m["remote"] == nil {
		t.Fatalf("remote missing: %v", m)
	}
	if m["status"] != float64(http.StatusTeapot) {
		t.Fatalf("status = %v", m["status"])
	}
}

func TestLoggingMiddleware_AnonymousRequestOmitsCaller(t *testing.T) {
	sink := &memSink{}
	h := LoggingMiddleware(slog.New(NewBufferHandler(sink)),
		http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {}))
	srv := httptest.NewServer(h)
	defer srv.Close()
	if _, err := http.Get(srv.URL + "/api/config"); err != nil {
		t.Fatal(err)
	}
	m := sink.last(t)
	for _, key := range []string{"device_id", "user_id", "user"} {
		if _, ok := m[key]; ok {
			t.Fatalf("unauthenticated request must not carry %s: %v", key, m)
		}
	}
}

func TestLogStore_PersistPageAndPrune(t *testing.T) {
	db := testStateDB(t)
	store := NewLogStore(db, 4)
	store.pruneEvery = 1
	logger := slog.New(NewBufferHandler(store))

	for i := 1; i <= 6; i++ {
		logger.Info("request", "path", fmt.Sprintf("/p%d", i))
	}

	entries, total, _ := store.Query(LogQuery{Limit: 10})
	if total != 4 || len(entries) != 4 {
		t.Fatalf("total=%d len=%d", total, len(entries))
	}
	paths := make([]string, 0, len(entries))
	for _, e := range entries {
		var m map[string]any
		_ = json.Unmarshal(e.Entry, &m)
		paths = append(paths, fmt.Sprint(m["path"]))
	}
	if paths[0] != "/p6" || paths[3] != "/p3" {
		t.Fatalf("query = %v", paths)
	}

	entries, _, hasMore := store.Query(LogQuery{Limit: 2})
	if len(entries) != 2 || !hasMore {
		t.Fatalf("first page: len=%d hasMore=%v", len(entries), hasMore)
	}
	entries, _, _ = store.Query(LogQuery{Limit: 2, BeforeID: entries[1].ID})
	var m map[string]any
	_ = json.Unmarshal(entries[0].Entry, &m)
	if len(entries) != 2 || m["path"] != "/p4" {
		t.Fatalf("cursor page = %v", entries)
	}

	entries, total, _ = NewLogStore(db, 4).Query(LogQuery{Limit: 10})
	if total != 4 || len(entries) != 4 {
		t.Fatalf("reopened store: total=%d len=%d", total, len(entries))
	}
}
