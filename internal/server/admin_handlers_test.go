package server

import (
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/pocketcmd/pocketcmd-server/internal/config"
)

func adminFixture(t *testing.T) *teamTestFixture {
	t.Helper()
	dir := t.TempDir()
	config.SetPocketCmdDir(dir)
	t.Cleanup(func() { config.SetPocketCmdDir("") })
	f := newTeamTestFixture(t)
	f.srv.RegisterAdminRoutes("test-1.2.3")
	return f
}

func TestAdmin_Status(t *testing.T) {
	f := adminFixture(t)

	w := f.do("GET", "/api/server/status", "", f.adminToken, f.adminCert)
	if w.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", w.Code, w.Body.String())
	}
	var resp map[string]any
	if err := json.NewDecoder(w.Body).Decode(&resp); err != nil {
		t.Fatal(err)
	}
	if resp["version"] != "test-1.2.3" {
		t.Errorf("version = %v", resp["version"])
	}
	if resp["active_devices"].(float64) != 2 || resp["active_users"].(float64) != 2 {
		t.Errorf("counts = %v devices / %v users",
			resp["active_devices"], resp["active_users"])
	}

	w = f.do("GET", "/api/server/status", "", f.memberToken, f.memberCert)
	if w.Code != http.StatusForbidden {
		t.Fatalf("expected 403 for member, got %d", w.Code)
	}
}

func TestAdmin_ConfigReadAdminOnly(t *testing.T) {
	f := adminFixture(t)

	w := f.do("GET", "/api/server/config", "", f.adminToken, f.adminCert)
	if w.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", w.Code, w.Body.String())
	}
	var cfg map[string]any
	if err := json.NewDecoder(w.Body).Decode(&cfg); err != nil {
		t.Fatal(err)
	}
	if len(cfg) != 1 || cfg["service_mode"] != "background" {
		t.Fatalf("expected exactly {service_mode: background}, got %v", cfg)
	}

	for _, bad := range []string{`{"push_enabled":true}`, `{"push_enabled":false}`, `{}`} {
		w = f.do("PATCH", "/api/server/config", bad, f.adminToken, f.adminCert)
		if w.Code != http.StatusMethodNotAllowed {
			t.Fatalf("PATCH %s: expected 405, got %d: %s", bad, w.Code, w.Body.String())
		}
	}
	if _, err := os.Stat(config.ConfigFilePath()); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("config.json must not be written by a refused PATCH: %v", err)
	}
}

func TestAdmin_LogsTail(t *testing.T) {
	dir := t.TempDir()
	config.SetPocketCmdDir(dir)
	t.Cleanup(func() { config.SetPocketCmdDir("") })
	f := newTeamTestFixture(t)
	store := NewLogStore(testStateDB(t), 3)
	store.pruneEvery = 1
	logger := slog.New(NewBufferHandler(store))
	for i := 1; i <= 5; i++ {
		logger.Info("request", "path", fmt.Sprintf("/api/thing_%d", i))
	}
	f.srv.SetLogSource(store)
	f.srv.RegisterAdminRoutes("test-1.2.3")

	w := f.do("GET", "/api/logs?limit=2", "", f.adminToken, f.adminCert)
	if w.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", w.Code, w.Body.String())
	}
	var resp logsResp
	if err := json.NewDecoder(w.Body).Decode(&resp); err != nil {
		t.Fatal(err)
	}
	if resp.Total != 3 || len(resp.Entries) != 2 {
		t.Fatalf("total=%d entries=%d", resp.Total, len(resp.Entries))
	}
	if resp.Entries[0]["path"] != "/api/thing_5" ||
		resp.Entries[1]["path"] != "/api/thing_4" {
		t.Fatalf("expected newest first, got %+v", resp.Entries)
	}
	if resp.Entries[0]["msg"] != "request" || resp.Entries[0]["level"] != "INFO" {
		t.Fatalf("expected slog fields, got %+v", resp.Entries[0])
	}
	if resp.NextBeforeID == 0 {
		t.Fatal("expected a next page cursor")
	}

	w = f.do("GET", fmt.Sprintf("/api/logs?limit=2&offset=99&before_id=%d", resp.NextBeforeID),
		"", f.adminToken, f.adminCert)
	resp = logsResp{}
	_ = json.NewDecoder(w.Body).Decode(&resp)
	if len(resp.Entries) != 1 || resp.Entries[0]["path"] != "/api/thing_3" {
		t.Fatalf("expected thing_3 after the cursor, got %+v", resp.Entries)
	}
	if resp.NextBeforeID != 0 {
		t.Fatalf("exhausted cursor must omit next_before_id, got %d", resp.NextBeforeID)
	}

	w = f.do("GET", "/api/logs", "", f.memberToken, f.memberCert)
	if w.Code != http.StatusForbidden {
		t.Fatalf("expected 403 for member, got %d", w.Code)
	}

	admin2Cert, admin2Token, _ :=
		newTeamUserDevice(t, f.devices, f.users, f.mgr, f.serverKey, "erin", "admin")
	w = f.do("GET", "/api/logs", "", admin2Token, admin2Cert)
	if w.Code != http.StatusForbidden {
		t.Fatalf("expected 403 for non-owner admin, got %d", w.Code)
	}
}

type logsResp struct {
	Entries      []map[string]any `json:"entries"`
	Total        int              `json:"total"`
	NextBeforeID int64            `json:"next_before_id"`
}

func pathsOf(t *testing.T, entries []map[string]any) []string {
	t.Helper()
	out := make([]string, 0, len(entries))
	for _, e := range entries {
		if _, ok := e["id"].(float64); !ok {
			t.Fatalf("entry missing stable id: %+v", e)
		}
		out = append(out, e["path"].(string))
	}
	return out
}

func TestAdmin_LogsBeforeIDPagination(t *testing.T) {
	f := adminFixture(t)
	store := NewLogStore(testStateDB(t), 100)
	f.srv.SetLogSource(store)
	appendReq := func(path string) {
		store.Append(json.RawMessage(fmt.Sprintf(`{"msg":"request","path":%q}`, path)))
	}
	for i := 1; i <= 6; i++ {
		appendReq(fmt.Sprintf("/e%d", i))
	}

	getPage := func(query string) logsResp {
		t.Helper()
		w := f.do("GET", "/api/logs?"+query, "", f.adminToken, f.adminCert)
		if w.Code != http.StatusOK {
			t.Fatalf("GET %s: %d %s", query, w.Code, w.Body.String())
		}
		var resp logsResp
		if err := json.NewDecoder(w.Body).Decode(&resp); err != nil {
			t.Fatal(err)
		}
		return resp
	}

	page1 := getPage("limit=2")
	if got := pathsOf(t, page1.Entries); len(got) != 2 || got[0] != "/e6" || got[1] != "/e5" {
		t.Fatalf("page1 = %v", got)
	}
	if page1.Total != 6 || page1.NextBeforeID == 0 {
		t.Fatalf("page1 total=%d next=%d", page1.Total, page1.NextBeforeID)
	}

	appendReq("/e7")
	appendReq("/e8")

	page2 := getPage(fmt.Sprintf("limit=2&before_id=%d", page1.NextBeforeID))
	if got := pathsOf(t, page2.Entries); len(got) != 2 || got[0] != "/e4" || got[1] != "/e3" {
		t.Fatalf("page2 must continue at /e4 with no dup/skip, got %v", got)
	}
	page3 := getPage(fmt.Sprintf("limit=2&before_id=%d", page2.NextBeforeID))
	if got := pathsOf(t, page3.Entries); len(got) != 2 || got[0] != "/e2" || got[1] != "/e1" {
		t.Fatalf("page3 = %v", got)
	}
	if page3.NextBeforeID != 0 {
		t.Fatalf("exhausted cursor must omit next_before_id, got %d", page3.NextBeforeID)
	}
}

func TestAdmin_LogsUserFilter(t *testing.T) {
	f := adminFixture(t)
	store := NewLogStore(testStateDB(t), 100)
	f.srv.SetLogSource(store)
	appendFor := func(userID, path string) {
		store.Append(json.RawMessage(fmt.Sprintf(
			`{"msg":"request","user_id":%q,"path":%q}`, userID, path)))
	}
	appendFor("u1", "/a1")
	appendFor("u2", "/b1")
	appendFor("u1", "/a2")
	appendFor("u2", "/b2")
	appendFor("u1", "/a3")

	w := f.do("GET", "/api/logs?user_id=u1&limit=2", "", f.adminToken, f.adminCert)
	if w.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", w.Code, w.Body.String())
	}
	var resp logsResp
	if err := json.NewDecoder(w.Body).Decode(&resp); err != nil {
		t.Fatal(err)
	}
	if got := pathsOf(t, resp.Entries); len(got) != 2 || got[0] != "/a3" || got[1] != "/a2" {
		t.Fatalf("filtered page = %v", got)
	}
	if resp.Total != 3 {
		t.Fatalf("filtered total = %d, want 3", resp.Total)
	}
	if resp.NextBeforeID == 0 {
		t.Fatal("expected a next page for u1")
	}

	w = f.do("GET", fmt.Sprintf("/api/logs?user_id=u1&limit=2&before_id=%d", resp.NextBeforeID),
		"", f.adminToken, f.adminCert)
	var resp2 logsResp
	_ = json.NewDecoder(w.Body).Decode(&resp2)
	if got := pathsOf(t, resp2.Entries); len(got) != 1 || got[0] != "/a1" {
		t.Fatalf("filtered page2 = %v", got)
	}
	if resp2.NextBeforeID != 0 {
		t.Fatalf("exhausted filtered cursor must omit next_before_id, got %d", resp2.NextBeforeID)
	}
}

func TestAdmin_LogsWithoutBuffer(t *testing.T) {
	f := adminFixture(t)

	w := f.do("GET", "/api/logs", "", f.adminToken, f.adminCert)
	if w.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", w.Code, w.Body.String())
	}
	var resp struct {
		Entries []map[string]any `json:"entries"`
		Total   int              `json:"total"`
	}
	if err := json.NewDecoder(w.Body).Decode(&resp); err != nil {
		t.Fatal(err)
	}
	if resp.Total != 0 || len(resp.Entries) != 0 {
		t.Fatalf("expected empty log, got %+v", resp)
	}
}

func TestAdmin_AuditTail(t *testing.T) {
	f := adminFixture(t)

	var content string
	for i := 1; i <= 5; i++ {
		content += fmt.Sprintf(`{"msg":"event_%d"}`+"\n", i)
	}
	if err := os.WriteFile(
		filepath.Join(config.PocketCmdDir(), "audit.log"),
		[]byte(content), 0600); err != nil {
		t.Fatal(err)
	}

	w := f.do("GET", "/api/audit?limit=2", "", f.adminToken, f.adminCert)
	if w.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", w.Code, w.Body.String())
	}
	var resp struct {
		Entries []map[string]string `json:"entries"`
		Total   int                 `json:"total"`
	}
	if err := json.NewDecoder(w.Body).Decode(&resp); err != nil {
		t.Fatal(err)
	}
	if resp.Total != 5 || len(resp.Entries) != 2 {
		t.Fatalf("total=%d entries=%d", resp.Total, len(resp.Entries))
	}
	if resp.Entries[0]["msg"] != "event_5" || resp.Entries[1]["msg"] != "event_4" {
		t.Fatalf("expected newest first, got %+v", resp.Entries)
	}

	w = f.do("GET", "/api/audit?limit=2&offset=2", "", f.adminToken, f.adminCert)
	_ = json.NewDecoder(w.Body).Decode(&resp)
	if resp.Entries[0]["msg"] != "event_3" {
		t.Fatalf("expected event_3 at offset 2, got %+v", resp.Entries)
	}

	admin2Cert, admin2Token, _ :=
		newTeamUserDevice(t, f.devices, f.users, f.mgr, f.serverKey, "dave", "admin")
	w = f.do("GET", "/api/audit", "", admin2Token, admin2Cert)
	if w.Code != http.StatusForbidden {
		t.Fatalf("expected 403 for non-owner, got %d", w.Code)
	}
}

func atMin(m int) string { return fmt.Sprintf("2026-01-02T10:%02d:00Z", m) }

func logsTimeFixture(t *testing.T) (*teamTestFixture, *LogStore) {
	t.Helper()
	f := adminFixture(t)
	store := NewLogStore(testStateDB(t), 100)
	f.srv.SetLogSource(store)
	return f, store
}

func appendAt(store *LogStore, timeStr, userID, path string) {
	store.Append(json.RawMessage(fmt.Sprintf(
		`{"msg":"request","time":%q,"user_id":%q,"path":%q}`, timeStr, userID, path)))
}

func getLogs(t *testing.T, f *teamTestFixture, query string) logsResp {
	t.Helper()
	w := f.do("GET", "/api/logs?"+query, "", f.adminToken, f.adminCert)
	if w.Code != http.StatusOK {
		t.Fatalf("GET /api/logs?%s: %d %s", query, w.Code, w.Body.String())
	}
	var resp logsResp
	if err := json.NewDecoder(w.Body).Decode(&resp); err != nil {
		t.Fatal(err)
	}
	return resp
}

func TestAdmin_LogsTimeWindow(t *testing.T) {
	f, store := logsTimeFixture(t)
	for i := 1; i <= 6; i++ {
		appendAt(store, atMin(i-1), "u1", fmt.Sprintf("/e%d", i))
	}

	resp := getLogs(t, f, "from="+atMin(3))
	if got := pathsOf(t, resp.Entries); len(got) != 3 || got[0] != "/e6" || got[2] != "/e4" {
		t.Fatalf("from page = %v", got)
	}
	if resp.Total != 3 {
		t.Fatalf("from total = %d, want 3", resp.Total)
	}

	resp = getLogs(t, f, "to="+atMin(2))
	if got := pathsOf(t, resp.Entries); len(got) != 3 || got[0] != "/e3" || got[2] != "/e1" {
		t.Fatalf("to page = %v", got)
	}
	if resp.Total != 3 {
		t.Fatalf("to total = %d, want 3", resp.Total)
	}

	resp = getLogs(t, f, "limit=2&from="+atMin(1)+"&to="+atMin(4))
	if got := pathsOf(t, resp.Entries); len(got) != 2 || got[0] != "/e5" || got[1] != "/e4" {
		t.Fatalf("window page1 = %v", got)
	}
	if resp.Total != 4 || resp.NextBeforeID == 0 {
		t.Fatalf("window page1 total=%d next=%d", resp.Total, resp.NextBeforeID)
	}
	resp = getLogs(t, f, fmt.Sprintf("limit=2&from=%s&to=%s&before_id=%d",
		atMin(1), atMin(4), resp.NextBeforeID))
	if got := pathsOf(t, resp.Entries); len(got) != 2 || got[0] != "/e3" || got[1] != "/e2" {
		t.Fatalf("window page2 = %v", got)
	}
	if resp.NextBeforeID != 0 {
		t.Fatalf("exhausted filtered window must omit next_before_id, got %d", resp.NextBeforeID)
	}

	resp = getLogs(t, f, "from="+atMin(2)+"&to="+atMin(2))
	if got := pathsOf(t, resp.Entries); len(got) != 1 || got[0] != "/e3" || resp.Total != 1 {
		t.Fatalf("instant window = %v total=%d", got, resp.Total)
	}
}

func TestAdmin_LogsTimeWindowWithCursor(t *testing.T) {
	f, store := logsTimeFixture(t)
	appendAt(store, atMin(10), "u1", "/in1")
	appendAt(store, atMin(30), "u1", "/out-late")
	appendAt(store, atMin(11), "u1", "/in2")
	appendAt(store, atMin(1), "u1", "/out-early")
	appendAt(store, atMin(12), "u1", "/in3")
	appendAt(store, atMin(13), "u1", "/in4")
	appendAt(store, atMin(14), "u1", "/in5")
	window := "from=" + atMin(10) + "&to=" + atMin(19)

	page1 := getLogs(t, f, "limit=2&"+window)
	if got := pathsOf(t, page1.Entries); len(got) != 2 || got[0] != "/in5" || got[1] != "/in4" {
		t.Fatalf("page1 = %v", got)
	}
	if page1.Total != 5 || page1.NextBeforeID == 0 {
		t.Fatalf("page1 total=%d next=%d", page1.Total, page1.NextBeforeID)
	}

	appendAt(store, atMin(15), "u1", "/in6-new")
	appendAt(store, atMin(45), "u1", "/out-new")

	page2 := getLogs(t, f, fmt.Sprintf("limit=2&%s&before_id=%d", window, page1.NextBeforeID))
	if got := pathsOf(t, page2.Entries); len(got) != 2 || got[0] != "/in3" || got[1] != "/in2" {
		t.Fatalf("page2 must continue at /in3 with no dup/skip, got %v", got)
	}
	page3 := getLogs(t, f, fmt.Sprintf("limit=2&%s&before_id=%d", window, page2.NextBeforeID))
	if got := pathsOf(t, page3.Entries); len(got) != 1 || got[0] != "/in1" {
		t.Fatalf("page3 = %v", got)
	}
	if page3.NextBeforeID != 0 {
		t.Fatalf("exhausted filtered cursor must omit next_before_id, got %d", page3.NextBeforeID)
	}
}

func TestAdmin_LogsTimeWindowWithUserFilter(t *testing.T) {
	f, store := logsTimeFixture(t)
	appendAt(store, atMin(0), "u1", "/a-early")
	appendAt(store, atMin(10), "u1", "/a1")
	appendAt(store, atMin(11), "u2", "/b1")
	appendAt(store, atMin(12), "u1", "/a2")
	appendAt(store, atMin(13), "u1", "/a3")
	appendAt(store, atMin(40), "u1", "/a-late")
	query := "user_id=u1&from=" + atMin(10) + "&to=" + atMin(19)

	resp := getLogs(t, f, "limit=2&"+query)
	if got := pathsOf(t, resp.Entries); len(got) != 2 || got[0] != "/a3" || got[1] != "/a2" {
		t.Fatalf("composed page1 = %v", got)
	}
	if resp.Total != 3 || resp.NextBeforeID == 0 {
		t.Fatalf("composed total=%d next=%d", resp.Total, resp.NextBeforeID)
	}
	resp = getLogs(t, f, fmt.Sprintf("limit=2&%s&before_id=%d", query, resp.NextBeforeID))
	if got := pathsOf(t, resp.Entries); len(got) != 1 || got[0] != "/a1" {
		t.Fatalf("composed page2 = %v", got)
	}
	if resp.NextBeforeID != 0 {
		t.Fatalf("exhausted composed cursor must omit next_before_id, got %d", resp.NextBeforeID)
	}
}

type sentinelLogSource struct{ queried bool }

func (s *sentinelLogSource) Query(LogQuery) ([]LogEntry, int, bool) {
	s.queried = true
	return nil, 0, false
}

func expectTimeError(t *testing.T, w *httptest.ResponseRecorder, wantCode, query string) {
	t.Helper()
	if w.Code != http.StatusBadRequest {
		t.Fatalf("%s: expected 400, got %d: %s", query, w.Code, w.Body.String())
	}
	var body map[string]any
	if err := json.NewDecoder(w.Body).Decode(&body); err != nil {
		t.Fatalf("%s: non-JSON error body", query)
	}
	if len(body) != 1 || body["error"] != wantCode {
		t.Fatalf("%s: error body = %v, want {error:%s}", query, body, wantCode)
	}
}

var timeValidationCases = []struct {
	query    string
	wantCode string
}{
	{"from=not-a-time", "invalid_time"},
	{"to=not-a-time", "invalid_time"},
	{"from=1755550000", "invalid_time"},           // epoch seconds, not RFC3339
	{"from=2026-01-02", "invalid_time"},           // date only
	{"from=2026-01-02T10:00:00", "invalid_time"},  // missing zone
	{"from=1999-12-31T23:59:59Z", "invalid_time"}, // below year floor
	{"to=3001-01-01T00:00:00Z", "invalid_time"},   // above year ceiling
	{"from=0001-01-01T00:00:00Z", "invalid_time"}, // absurd past
	{"from=2026-01-02T10:05:00Z&to=2026-01-02T10:00:00Z", "invalid_time_range"},
}

func TestAdmin_LogsTimeValidation(t *testing.T) {
	f := adminFixture(t)
	sentinel := &sentinelLogSource{}
	f.srv.SetLogSource(sentinel)

	for _, tc := range timeValidationCases {
		w := f.do("GET", "/api/logs?"+tc.query, "", f.adminToken, f.adminCert)
		expectTimeError(t, w, tc.wantCode, tc.query)
	}
	if sentinel.queried {
		t.Fatal("store was queried despite invalid time params")
	}

	w := f.do("GET", "/api/logs?from="+atMin(0), "", f.adminToken, f.adminCert)
	if w.Code != http.StatusOK || !sentinel.queried {
		t.Fatalf("valid window: code=%d queried=%v", w.Code, sentinel.queried)
	}
}

func writeAuditLines(t *testing.T, lines []string) {
	t.Helper()
	content := ""
	for _, l := range lines {
		content += l + "\n"
	}
	if err := os.WriteFile(
		filepath.Join(config.PocketCmdDir(), "audit.log"),
		[]byte(content), 0600); err != nil {
		t.Fatal(err)
	}
}

type auditResp struct {
	Entries []map[string]any `json:"entries"`
	Total   int              `json:"total"`
}

func getAudit(t *testing.T, f *teamTestFixture, query string) auditResp {
	t.Helper()
	w := f.do("GET", "/api/audit?"+query, "", f.adminToken, f.adminCert)
	if w.Code != http.StatusOK {
		t.Fatalf("GET /api/audit?%s: %d %s", query, w.Code, w.Body.String())
	}
	var resp auditResp
	if err := json.NewDecoder(w.Body).Decode(&resp); err != nil {
		t.Fatal(err)
	}
	return resp
}

func auditMsgs(entries []map[string]any) []string {
	out := make([]string, 0, len(entries))
	for _, e := range entries {
		out = append(out, fmt.Sprint(e["msg"]))
	}
	return out
}

func TestAdmin_AuditTimeWindow(t *testing.T) {
	f := adminFixture(t)
	var lines []string
	for i := 1; i <= 6; i++ {
		lines = append(lines, fmt.Sprintf(
			`{"time":%q,"level":"INFO","msg":"event_%d"}`, atMin(i-1), i))
	}
	writeAuditLines(t, lines)
	window := "from=" + atMin(1) + "&to=" + atMin(4)

	resp := getAudit(t, f, "limit=2&"+window)
	if got := auditMsgs(resp.Entries); len(got) != 2 || got[0] != "event_5" || got[1] != "event_4" {
		t.Fatalf("window page1 = %v", got)
	}
	if resp.Total != 4 {
		t.Fatalf("filtered total = %d, want 4", resp.Total)
	}

	resp = getAudit(t, f, "limit=2&offset=2&"+window)
	if got := auditMsgs(resp.Entries); len(got) != 2 || got[0] != "event_3" || got[1] != "event_2" {
		t.Fatalf("window page2 = %v", got)
	}
	resp = getAudit(t, f, "limit=2&offset=4&"+window)
	if len(resp.Entries) != 0 || resp.Total != 4 {
		t.Fatalf("exhausted window page = %+v", resp)
	}

	resp = getAudit(t, f, "from="+atMin(4))
	if got := auditMsgs(resp.Entries); len(got) != 2 || got[0] != "event_6" || got[1] != "event_5" {
		t.Fatalf("from-only = %v", got)
	}
	resp = getAudit(t, f, "to="+atMin(1))
	if got := auditMsgs(resp.Entries); len(got) != 2 || got[0] != "event_2" || got[1] != "event_1" {
		t.Fatalf("to-only = %v", got)
	}
}

func TestAdmin_AuditUnparsableTimeLines(t *testing.T) {
	f := adminFixture(t)
	writeAuditLines(t, []string{
		fmt.Sprintf(`{"time":%q,"msg":"timed_in"}`, atMin(10)),
		`{"msg":"no_time"}`,
		`{"time":"garbage","msg":"bad_time"}`,
		fmt.Sprintf(`{"time":%q,"msg":"timed_out"}`, atMin(40)),
		`not json at all`,
	})

	resp := getAudit(t, f, "from="+atMin(0)+"&to="+atMin(19))
	if got := auditMsgs(resp.Entries); len(got) != 1 || got[0] != "timed_in" || resp.Total != 1 {
		t.Fatalf("filtered = %v total=%d", got, resp.Total)
	}

	resp = getAudit(t, f, "")
	if resp.Total != 4 || len(resp.Entries) != 4 {
		t.Fatalf("unfiltered total = %d entries=%d", resp.Total, len(resp.Entries))
	}
}

func TestAdmin_AuditTimeValidation(t *testing.T) {
	f := adminFixture(t)
	for _, tc := range timeValidationCases {
		w := f.do("GET", "/api/audit?"+tc.query, "", f.adminToken, f.adminCert)
		expectTimeError(t, w, tc.wantCode, tc.query)
	}
}

func TestAdmin_TimeParamHostility(t *testing.T) {
	f, store := logsTimeFixture(t)
	// Widen the per-device limiter in place so 429s do not mask handler results.
	f.srv.rateLimiter.limit = 1_000_000
	appendAt(store, atMin(0), "u1", "/seed")
	writeAuditLines(t, []string{fmt.Sprintf(`{"time":%q,"msg":"seed"}`, atMin(0))})

	hostile := []string{
		`'; DROP TABLE server_logs;--`,
		`" OR "1"="1`,
		`%' ESCAPE '\`,
		"\x00",
		"%00",
		"a\x00b",
		strings.Repeat("9", 10000),
		strings.Repeat("A", 65536),
		"-1",
		"-9223372036854775809", // int64 underflow
		"9223372036854775808",  // int64 overflow
		"1e309",
		"NaN",
		"2026-01-02T10:00:00Z' OR '1'='1",
		"2026-01-02T10:00:00Z\x00",
		"\u202e2026-01-02T10:00:00Z", // RTL override before the timestamp
	}
	params := []string{"from", "to", "limit", "before_id", "user_id", "offset"}
	for _, endpoint := range []string{"/api/logs", "/api/audit"} {
		for _, p := range params {
			for _, v := range hostile {
				q := url.Values{p: {v}}
				w := f.do("GET", endpoint+"?"+q.Encode(), "", f.adminToken, f.adminCert)
				if w.Code != http.StatusOK && w.Code != http.StatusBadRequest {
					t.Fatalf("%s %s=%q: got %d, want 200/400: %s",
						endpoint, p, v, w.Code, w.Body.String())
				}
			}
		}
	}

	if resp := getLogs(t, f, ""); resp.Total != 1 {
		t.Fatalf("server_logs damaged by hostile input: %+v", resp)
	}
	if resp := getAudit(t, f, ""); resp.Total != 1 {
		t.Fatalf("audit feed damaged by hostile input: %+v", resp)
	}
}

func TestAdmin_ConfigTooNew(t *testing.T) {
	dir := t.TempDir()
	config.SetPocketCmdDir(dir)
	t.Cleanup(func() { config.SetPocketCmdDir("") })
	f := newTeamTestFixture(t)
	f.srv.RegisterAdminRoutes("test")
	raw := []byte(`{"config_version": 99, "service_mode": "background"}`)
	if err := os.WriteFile(config.ConfigFilePath(), raw, 0600); err != nil {
		t.Fatal(err)
	}
	w := f.do("GET", "/api/server/config", "", f.adminToken, f.adminCert)
	if w.Code != http.StatusInternalServerError || !strings.Contains(w.Body.String(), "config_unreadable") {
		t.Fatalf("GET: %d %s", w.Code, w.Body.String())
	}
	if got, _ := os.ReadFile(config.ConfigFilePath()); string(got) != string(raw) {
		t.Fatalf("config.json was modified: %s", got)
	}
}
