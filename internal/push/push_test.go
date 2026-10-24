package push

import (
	"database/sql"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/pocketcmd/pocketcmd-server/internal/state"
)

func testStore(t *testing.T) (*Store, *sql.DB) {
	t.Helper()
	db, err := state.Open(t.TempDir())
	if err != nil {
		t.Fatalf("state.Open: %v", err)
	}
	t.Cleanup(func() { db.Close() })
	return NewStore(db), db
}

func seedDevice(t *testing.T, db *sql.DB, deviceID string) {
	t.Helper()
	if _, err := db.Exec(`INSERT INTO devices (device_id, public_key, user_id, paired_at)
		VALUES (?, 'pem', 'u1', '2026-01-01T00:00:00Z')`, deviceID); err != nil {
		t.Fatal(err)
	}
}

func TestPushStore_ReadAllSkipsExpired(t *testing.T) {
	store, db := testStore(t)
	seedDevice(t, db, "dev1")
	seedDevice(t, db, "dev2")

	if err := store.Upsert(PushRegistration{
		DeviceID: "dev1", DeviceToken: "t1", Platform: "android",
		SignedToken: "s1", ExpiresAt: time.Now().Add(time.Hour).UnixMilli(),
	}); err != nil {
		t.Fatal(err)
	}
	if err := store.Upsert(PushRegistration{
		DeviceID: "dev2", DeviceToken: "t2", Platform: "android",
		SignedToken: "s2", ExpiresAt: time.Now().Add(-time.Hour).UnixMilli(),
	}); err != nil {
		t.Fatal(err)
	}

	regs, err := store.ReadAll()
	if err != nil {
		t.Fatal(err)
	}
	if len(regs) != 1 || regs[0].DeviceID != "dev1" {
		t.Fatalf("expected only dev1, got %+v", regs)
	}
}

func TestPushStore_ReadAllEmpty(t *testing.T) {
	store, _ := testStore(t)
	regs, err := store.ReadAll()
	if err != nil {
		t.Fatal(err)
	}
	if len(regs) != 0 {
		t.Fatal("expected 0 registrations from empty store")
	}
}

func TestPushStore_UpsertOverwrites(t *testing.T) {
	store, db := testStore(t)
	seedDevice(t, db, "dev1")
	exp := time.Now().Add(time.Hour).UnixMilli()

	for _, tok := range []string{"old-token", "new-token"} {
		if err := store.Upsert(PushRegistration{
			DeviceID: "dev1", DeviceToken: tok, Platform: "android",
			SignedToken: "sig", ExpiresAt: exp,
		}); err != nil {
			t.Fatal(err)
		}
	}

	regs, _ := store.ReadAll()
	if len(regs) != 1 || regs[0].DeviceToken != "new-token" {
		t.Fatalf("expected single overwritten registration, got %+v", regs)
	}
}

func TestPushStore_Remove(t *testing.T) {
	store, db := testStore(t)
	seedDevice(t, db, "dev1")
	if err := store.Upsert(PushRegistration{
		DeviceID: "dev1", DeviceToken: "t", Platform: "android",
		SignedToken: "s", ExpiresAt: time.Now().Add(time.Hour).UnixMilli(),
	}); err != nil {
		t.Fatal(err)
	}
	if err := store.Remove("dev1"); err != nil {
		t.Fatal(err)
	}
	if err := store.Remove("dev1"); err != nil {
		t.Fatal("removing a missing registration must not error")
	}
	regs, _ := store.ReadAll()
	if len(regs) != 0 {
		t.Fatalf("expected empty store, got %+v", regs)
	}
}

func TestPushStore_DeviceDeleteCascades(t *testing.T) {
	store, db := testStore(t)
	seedDevice(t, db, "dev1")
	if err := store.Upsert(PushRegistration{
		DeviceID: "dev1", DeviceToken: "t", Platform: "android",
		SignedToken: "s", ExpiresAt: time.Now().Add(time.Hour).UnixMilli(),
	}); err != nil {
		t.Fatal(err)
	}
	if _, err := db.Exec("DELETE FROM devices WHERE device_id='dev1'"); err != nil {
		t.Fatal(err)
	}
	regs, _ := store.ReadAll()
	if len(regs) != 0 {
		t.Fatalf("expected FK cascade to remove registration, got %+v", regs)
	}
}

func testNotification() Notification {
	return Notification{
		SignalType: "metric_alert",
		Title:      "CPU Alert: host",
		Body:       "CPU at 97.2 (threshold: 90.0)",
		Sound:      "default",
		Data: map[string]string{
			"metric_id":   "custom:cpu",
			"server_name": "host",
			"value":       "97.21",
			"threshold":   "90.00",
		},
	}
}

func TestPushClient_NotifyNoRegistrations(t *testing.T) {
	client := NewPushClient("http://localhost:9999")
	gone, err := client.Notify(nil, testNotification())
	if err != nil {
		t.Fatal("should not error with no registrations")
	}
	if len(gone) != 0 {
		t.Fatal("no registrations should yield no gone devices")
	}
}

func TestPushClient_Notify_PostsV2Schema(t *testing.T) {
	var got map[string]interface{}
	var gotPath string
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotPath = r.URL.Path
		_ = json.NewDecoder(r.Body).Decode(&got)
		fmt.Fprint(w, `{"ok":true}`)
	}))
	defer ts.Close()

	client := NewPushClient(ts.URL)
	regs := []PushRegistration{{
		DeviceID:    "d1",
		DeviceToken: "tok-x",
		Platform:    "android",
		SignedToken: "sig-y",
		ExpiresAt:   time.Now().Add(time.Hour).UnixMilli(),
	}}
	gone, err := client.Notify(regs, testNotification())
	if err != nil {
		t.Fatal(err)
	}
	if len(gone) != 0 {
		t.Fatalf("unexpected gone devices: %v", gone)
	}

	if gotPath != "/notify" {
		t.Fatalf("wrong path: got %q want %q", gotPath, "/notify")
	}
	want := map[string]interface{}{
		"v":            float64(2),
		"device_token": "tok-x",
		"platform":     "android",
		"signed_token": "sig-y",
		"signal_type":  "metric_alert",
		"title":        "CPU Alert: host",
		"body":         "CPU at 97.2 (threshold: 90.0)",
		"sound":        "default",
	}
	for k, v := range want {
		if got[k] != v {
			t.Fatalf("key %q: want %v got %v", k, v, got[k])
		}
	}
	data, ok := got["data"].(map[string]interface{})
	if !ok {
		t.Fatalf("expected data object, got %T", got["data"])
	}
	if data["metric_id"] != "custom:cpu" || data["threshold"] != "90.00" {
		t.Fatalf("data payload not forwarded: %v", data)
	}
	if _, present := got["channel_id"]; present {
		t.Fatal("channel_id should be omitted when unset")
	}
}

func TestPushClient_Notify_OmitsEmptyOptionalFields(t *testing.T) {
	var got map[string]interface{}
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_ = json.NewDecoder(r.Body).Decode(&got)
		fmt.Fprint(w, `{"ok":true}`)
	}))
	defer ts.Close()

	client := NewPushClient(ts.URL)
	regs := []PushRegistration{{DeviceID: "d1", ExpiresAt: time.Now().Add(time.Hour).UnixMilli()}}
	_, err := client.Notify(regs, Notification{SignalType: "x", Title: "T", Body: "B"})
	if err != nil {
		t.Fatal(err)
	}
	for _, k := range []string{"channel_id", "sound", "data"} {
		if _, present := got[k]; present {
			t.Fatalf("%s should be omitted when unset", k)
		}
	}
}

func TestPushClient_Notify_ServerError(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(500)
		fmt.Fprint(w, `{"error":"internal"}`)
	}))
	defer ts.Close()

	client := NewPushClient(ts.URL)
	regs := []PushRegistration{{DeviceID: "d1", ExpiresAt: time.Now().Add(time.Hour).UnixMilli()}}
	_, err := client.Notify(regs, testNotification())
	if err == nil {
		t.Fatal("notify should return error on server 500")
	}
	if !strings.Contains(err.Error(), "500") {
		t.Fatalf("error %q should contain status 500", err.Error())
	}
}

func TestPushClient_Notify_StaleSignedToken(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusForbidden)
		fmt.Fprint(w, `{"error":"Invalid signed_token"}`)
	}))
	defer ts.Close()

	client := NewPushClient(ts.URL)
	regs := []PushRegistration{{DeviceID: "d1", ExpiresAt: time.Now().Add(time.Hour).UnixMilli()}}
	gone, err := client.Notify(regs, testNotification())
	if len(gone) != 0 {
		t.Fatal("403 must not mark the registration gone")
	}
	if err == nil || !strings.Contains(err.Error(), "stale signed_token") {
		t.Fatalf("403 error should mention stale signed_token, got %v", err)
	}
}

func TestPushClient_Notify_TokenGone(t *testing.T) {
	var calls int
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls++
		var body map[string]interface{}
		_ = json.NewDecoder(r.Body).Decode(&body)
		if body["device_token"] == "dead" {
			w.WriteHeader(http.StatusGone)
			fmt.Fprint(w, `{"error":"token_gone"}`)
			return
		}
		fmt.Fprint(w, `{"ok":true}`)
	}))
	defer ts.Close()

	client := NewPushClient(ts.URL)
	regs := []PushRegistration{
		{DeviceID: "d1", DeviceToken: "dead", ExpiresAt: time.Now().Add(time.Hour).UnixMilli()},
		{DeviceID: "d2", DeviceToken: "alive", ExpiresAt: time.Now().Add(time.Hour).UnixMilli()},
	}
	gone, err := client.Notify(regs, testNotification())
	if err != nil {
		t.Fatalf("410 is not an error: %v", err)
	}
	if len(gone) != 1 || gone[0] != "d1" {
		t.Fatalf("expected gone=[d1], got %v", gone)
	}
	if calls != 2 {
		t.Fatalf("a 410 must not stop delivery to other devices; got %d calls", calls)
	}
}

func TestPushClient_Notify_MultipleDevices(t *testing.T) {
	var count int
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		count++
		w.WriteHeader(200)
	}))
	defer ts.Close()

	client := NewPushClient(ts.URL)
	regs := []PushRegistration{
		{DeviceID: "d1", ExpiresAt: time.Now().Add(time.Hour).UnixMilli()},
		{DeviceID: "d2", ExpiresAt: time.Now().Add(time.Hour).UnixMilli()},
	}
	client.Notify(regs, testNotification())
	if count != 2 {
		t.Fatalf("expected 2 requests, got %d", count)
	}
}

func TestPushClient_Notify_ContinuesAfterFailure(t *testing.T) {
	var count int
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		count++
		if count == 1 {
			w.WriteHeader(500)
			return
		}
		fmt.Fprint(w, `{"ok":true}`)
	}))
	defer ts.Close()

	client := NewPushClient(ts.URL)
	regs := []PushRegistration{
		{DeviceID: "d1", ExpiresAt: time.Now().Add(time.Hour).UnixMilli()},
		{DeviceID: "d2", ExpiresAt: time.Now().Add(time.Hour).UnixMilli()},
	}
	_, err := client.Notify(regs, testNotification())
	if err == nil {
		t.Fatal("expected aggregated error from failed device")
	}
	if count != 2 {
		t.Fatalf("failure for one device must not skip the rest; got %d calls", count)
	}
}

func TestPushStore_RemoveRejectsEmptyID(t *testing.T) {
	store, _ := testStore(t)
	if err := store.Remove(""); err == nil {
		t.Fatal("empty device id should be rejected")
	}
}

func TestPushRegistration_JSONRoundTrip_AllFields(t *testing.T) {
	in := PushRegistration{
		DeviceID:    "d1",
		DeviceToken: "tok",
		Platform:    "android",
		SignedToken: "sig",
		ExpiresAt:   42,
	}
	b, err := json.Marshal(in)
	if err != nil {
		t.Fatal(err)
	}
	var out PushRegistration
	if err := json.Unmarshal(b, &out); err != nil {
		t.Fatal(err)
	}
	if out != in {
		t.Fatalf("round trip lost data: in=%+v out=%+v", in, out)
	}
}
