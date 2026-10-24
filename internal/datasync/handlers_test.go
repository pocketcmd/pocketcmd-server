package datasync

import (
	"bytes"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"
	"testing/iotest"
	"time"
)

func TestSyncManifestEndpoint(t *testing.T) {
	dir := t.TempDir()
	store := NewSyncStoreAt(dir)
	handler := NewSyncHandler(store)

	now := time.Now().UnixMilli()
	store.PushRecords("", []SyncRecord{
		{ID: "task-1", Type: "task", SchemaVersion: 1, UpdatedAt: now, DeviceID: "dev-a", Data: json.RawMessage(`{}`)},
	})

	req := httptest.NewRequest("GET", "/api/sync/manifest", nil)
	w := httptest.NewRecorder()
	handler.HandleManifest(w, req)

	if w.Code != 200 {
		t.Fatalf("expected 200, got %d", w.Code)
	}

	var manifest SyncManifest
	json.Unmarshal(w.Body.Bytes(), &manifest)
	if len(manifest.Records) != 1 {
		t.Fatalf("expected 1 record, got %d", len(manifest.Records))
	}
}

func TestSyncPullEndpoint(t *testing.T) {
	dir := t.TempDir()
	store := NewSyncStoreAt(dir)
	handler := NewSyncHandler(store)

	now := time.Now().UnixMilli()
	store.PushRecords("", []SyncRecord{
		{ID: "task-1", Type: "task", SchemaVersion: 1, UpdatedAt: now, DeviceID: "dev-a", Data: json.RawMessage(`{"name":"test"}`)},
	})

	body, _ := json.Marshal(map[string][]string{"ids": {"task-1"}})
	req := httptest.NewRequest("POST", "/api/sync/pull", bytes.NewReader(body))
	w := httptest.NewRecorder()
	handler.HandlePull(w, req)

	if w.Code != 200 {
		t.Fatalf("expected 200, got %d", w.Code)
	}

	var resp struct{ Records []SyncRecord }
	json.Unmarshal(w.Body.Bytes(), &resp)
	if len(resp.Records) != 1 || resp.Records[0].ID != "task-1" {
		t.Fatal("expected task-1 in pull response")
	}
}

func TestSyncPushEndpoint(t *testing.T) {
	dir := t.TempDir()
	store := NewSyncStoreAt(dir)
	handler := NewSyncHandler(store)

	record := SyncRecord{
		ID: "task-1", Type: "task", SchemaVersion: 1,
		UpdatedAt: time.Now().UnixMilli(), DeviceID: "dev-a",
		Data: json.RawMessage(`{"name":"pushed"}`),
	}
	body, _ := json.Marshal(map[string][]SyncRecord{"records": {record}})
	req := httptest.NewRequest("POST", "/api/sync/push", bytes.NewReader(body))
	w := httptest.NewRecorder()
	handler.HandlePush(w, req)

	if w.Code != 200 {
		t.Fatalf("expected 200, got %d", w.Code)
	}

	var result PushResult
	json.Unmarshal(w.Body.Bytes(), &result)
	if len(result.Accepted) != 1 {
		t.Fatal("expected 1 accepted")
	}
}

func TestSyncPushPayloadLimit(t *testing.T) {
	dir := t.TempDir()
	store := NewSyncStoreAt(dir)
	handler := NewSyncHandler(store)

	bigData := make([]byte, 11*1024*1024)
	req := httptest.NewRequest("POST", "/api/sync/push", bytes.NewReader(bigData))
	w := httptest.NewRecorder()
	handler.HandlePush(w, req)

	if w.Code != 413 {
		t.Fatalf("expected 413 for oversized payload, got %d", w.Code)
	}
}

func TestSyncPullEndpoint_Empty(t *testing.T) {
	dir := t.TempDir()
	store := NewSyncStoreAt(dir)
	handler := NewSyncHandler(store)

	body, _ := json.Marshal(map[string][]string{"ids": {"nonexistent"}})
	req := httptest.NewRequest("POST", "/api/sync/pull", bytes.NewReader(body))
	w := httptest.NewRecorder()
	handler.HandlePull(w, req)

	if w.Code != 200 {
		t.Fatalf("expected 200, got %d", w.Code)
	}

	var resp struct{ Records []SyncRecord }
	json.Unmarshal(w.Body.Bytes(), &resp)
	if len(resp.Records) != 0 {
		t.Fatal("expected empty records for nonexistent IDs")
	}
	if !bytes.Contains(w.Body.Bytes(), []byte(`"records":[]`)) {
		t.Fatalf("empty pull must answer an empty array, got %s", w.Body.String())
	}
}

func TestSyncManifestEndpoint_EmptyIsArray(t *testing.T) {
	handler := NewSyncHandler(NewSyncStoreAt(t.TempDir()))

	req := httptest.NewRequest("GET", "/api/sync/manifest", nil)
	w := httptest.NewRecorder()
	handler.HandleManifest(w, req)

	if w.Code != 200 {
		t.Fatalf("expected 200, got %d", w.Code)
	}
	if !bytes.Contains(w.Body.Bytes(), []byte(`"records":[]`)) {
		t.Fatalf("empty manifest must answer an empty array, got %s", w.Body.String())
	}
}

func TestSyncPushEndpoint_Rejection(t *testing.T) {
	dir := t.TempDir()
	store := NewSyncStoreAt(dir)
	handler := NewSyncHandler(store)

	now := time.Now().UnixMilli()
	record1 := SyncRecord{ID: "t1", Type: "task", SchemaVersion: 1, UpdatedAt: now, DeviceID: "dev", Data: json.RawMessage(`{}`)}
	body1, _ := json.Marshal(map[string][]SyncRecord{"records": {record1}})
	req1 := httptest.NewRequest("POST", "/api/sync/push", bytes.NewReader(body1))
	w1 := httptest.NewRecorder()
	handler.HandlePush(w1, req1)

	record2 := SyncRecord{ID: "t1", Type: "task", SchemaVersion: 1, UpdatedAt: now - 1000, DeviceID: "dev2", Data: json.RawMessage(`{}`)}
	body2, _ := json.Marshal(map[string][]SyncRecord{"records": {record2}})
	req2 := httptest.NewRequest("POST", "/api/sync/push", bytes.NewReader(body2))
	w2 := httptest.NewRecorder()
	handler.HandlePush(w2, req2)

	var result PushResult
	json.Unmarshal(w2.Body.Bytes(), &result)
	if len(result.Rejected) != 1 {
		t.Fatal("expected rejection of older record")
	}
}

func TestSyncHandler_PullBadJSON(t *testing.T) {
	dir := t.TempDir()
	store := NewSyncStoreAt(dir)
	handler := NewSyncHandler(store)

	req := httptest.NewRequest("POST", "/api/sync/pull", bytes.NewReader([]byte("bad json")))
	w := httptest.NewRecorder()
	handler.HandlePull(w, req)
	if w.Code != 400 {
		t.Fatalf("expected 400 for bad JSON, got %d", w.Code)
	}
}

func TestSyncHandler_PushBadJSON(t *testing.T) {
	dir := t.TempDir()
	store := NewSyncStoreAt(dir)
	handler := NewSyncHandler(store)

	req := httptest.NewRequest("POST", "/api/sync/push", bytes.NewReader([]byte("bad json")))
	w := httptest.NewRecorder()
	handler.HandlePush(w, req)
	if w.Code != 400 {
		t.Fatalf("expected 400 for bad JSON, got %d", w.Code)
	}
}

func TestHandlePush_StampsAuthenticatedDeviceID(t *testing.T) {
	store := newTestStore(t)
	handler := NewSyncHandler(store)

	body, _ := json.Marshal(map[string]any{"records": []map[string]any{{
		"id": "stamp-1", "type": "task", "updated_at": time.Now().UnixMilli(),
		"device_id": "spoofed", "data": map[string]any{"v": 1},
	}}})
	req := httptest.NewRequest("POST", "/api/sync/push", bytes.NewReader(body))
	req = req.WithContext(WithDeviceID(WithUserID(req.Context(), "u1"), "real-device"))
	w := httptest.NewRecorder()
	handler.HandlePush(w, req)
	if w.Code != http.StatusOK {
		t.Fatalf("push: %d %s", w.Code, w.Body.String())
	}
	var result PushResult
	if err := json.Unmarshal(w.Body.Bytes(), &result); err != nil {
		t.Fatal(err)
	}
	if len(result.Accepted) != 1 {
		t.Fatalf("expected acceptance, got %+v", result)
	}

	recs, err := store.PullRecords("u1", []string{"stamp-1"})
	if err != nil || len(recs) != 1 {
		t.Fatalf("pull: %v %+v", err, recs)
	}
	if recs[0].DeviceID != "real-device" {
		t.Fatalf("device_id = %q, want the authenticated device", recs[0].DeviceID)
	}
}

func TestSyncHandler_PushBodyReadError_Is400(t *testing.T) {
	store := NewSyncStoreAt(t.TempDir())
	handler := NewSyncHandler(store)

	req := httptest.NewRequest("POST", "/api/sync/push", iotest.ErrReader(errors.New("connection reset")))
	w := httptest.NewRecorder()
	handler.HandlePush(w, req)

	if w.Code != http.StatusBadRequest {
		t.Fatalf("expected 400 for a body read error, got %d: %s", w.Code, w.Body.String())
	}
}
