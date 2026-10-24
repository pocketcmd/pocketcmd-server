package metrics

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

func testSchedulerWithConfig(cfg *MonitoringConfig) *Scheduler {
	s := &Scheduler{}
	s.config = cfg
	return s
}

func TestAPILatest(t *testing.T) {
	dir := t.TempDir()
	store, _ := NewMetricStore(dir)
	defer store.Close()

	now := time.Now().UnixMilli()
	store.Write(MetricPoint{MetricID: "custom:cpu", Value: 42.5, Timestamp: now, Unit: "%"})
	store.Flush()

	handler := NewMetricAPI(store, nil)
	req := httptest.NewRequest("GET", "/api/metrics/latest", nil)
	w := httptest.NewRecorder()
	handler.HandleLatest(w, req)

	if w.Code != 200 {
		t.Fatalf("expected 200, got %d", w.Code)
	}

	var resp struct {
		Metrics map[string]MetricPoint `json:"metrics"`
	}
	json.Unmarshal(w.Body.Bytes(), &resp)
	if resp.Metrics["custom:cpu"].Value != 42.5 {
		t.Fatalf("expected 42.5, got %f", resp.Metrics["custom:cpu"].Value)
	}
}

func TestAPISeries(t *testing.T) {
	dir := t.TempDir()
	store, _ := NewMetricStore(dir)
	defer store.Close()

	base := time.Now().Add(-30 * time.Minute).UnixMilli()
	for i := 0; i < 5; i++ {
		store.Write(MetricPoint{MetricID: "custom:cpu", Value: float64(40 + i), Timestamp: base + int64(i*60000), Unit: "%"})
	}
	store.Flush()

	handler := NewMetricAPI(store, nil)
	req := httptest.NewRequest("GET", "/api/metrics/series?metric=custom:cpu&range=1h", nil)
	w := httptest.NewRecorder()
	handler.HandleSeries(w, req)

	if w.Code != 200 {
		t.Fatalf("expected 200, got %d", w.Code)
	}

	var resp struct {
		Points []MetricPoint `json:"points"`
	}
	json.Unmarshal(w.Body.Bytes(), &resp)
	if len(resp.Points) != 5 {
		t.Fatalf("expected 5 points, got %d", len(resp.Points))
	}
}

func TestAPISeries_EmptyIsArray(t *testing.T) {
	dir := t.TempDir()
	store, _ := NewMetricStore(dir)
	defer store.Close()

	handler := NewMetricAPI(store, nil)
	req := httptest.NewRequest("GET", "/api/metrics/series?metric=custom:cpu&range=1h", nil)
	w := httptest.NewRecorder()
	handler.HandleSeries(w, req)

	if w.Code != 200 {
		t.Fatalf("expected 200, got %d", w.Code)
	}
	if !strings.Contains(w.Body.String(), `"points":[]`) {
		t.Fatalf("a metric with no points must answer an empty array, got %s", w.Body.String())
	}
}

func TestAPIAvailable(t *testing.T) {
	dir := t.TempDir()
	store, _ := NewMetricStore(dir)
	defer store.Close()

	cfg := DefaultMonitoringConfig()
	cfg.Custom = []CustomMetricConfig{
		{ID: "req-1", Label: "Containers", Command: "docker ps -q | wc -l"},
		{ID: "req-2", Label: "Conns", Command: "ss -t | wc -l"},
	}
	store.Write(MetricPoint{MetricID: "custom:gone", Value: 1, Timestamp: time.Now().UnixMilli()})
	handler := NewMetricAPI(store, testSchedulerWithConfig(cfg))
	req := httptest.NewRequest("GET", "/api/metrics/available", nil)
	w := httptest.NewRecorder()
	handler.HandleAvailable(w, req)

	if w.Code != 200 {
		t.Fatalf("expected 200, got %d", w.Code)
	}

	var resp struct {
		Metrics []MetricInfo `json:"metrics"`
	}
	json.Unmarshal(w.Body.Bytes(), &resp)
	if len(resp.Metrics) != 2 {
		t.Fatalf("expected the 2 configured metrics, got %+v", resp.Metrics)
	}
	if resp.Metrics[0].ID != "custom:req-1" || resp.Metrics[0].Label != "Containers" ||
		resp.Metrics[1].ID != "custom:req-2" || resp.Metrics[1].Label != "Conns" {
		t.Fatalf("catalog mismatch: %+v", resp.Metrics)
	}
	if strings.Contains(w.Body.String(), `"builtin"`) {
		t.Fatalf("catalog entries must not carry a builtin flag: %s", w.Body.String())
	}
}

func TestAPIAvailable_NoDefaultCatalog(t *testing.T) {
	dir := t.TempDir()
	store, _ := NewMetricStore(dir)
	defer store.Close()

	for name, sched := range map[string]*Scheduler{
		"default config": testSchedulerWithConfig(DefaultMonitoringConfig()),
		"no config":      nil,
	} {
		handler := NewMetricAPI(store, sched)
		w := httptest.NewRecorder()
		handler.HandleAvailable(w, httptest.NewRequest("GET", "/api/metrics/available", nil))
		if w.Code != 200 {
			t.Fatalf("%s: expected 200, got %d", name, w.Code)
		}
		if strings.TrimSpace(w.Body.String()) != `{"metrics":[]}` {
			t.Fatalf("%s: expected an empty catalog, got %s", name, w.Body.String())
		}
	}
}

func TestAPIAvailable_WithCustomMetrics(t *testing.T) {
	dir := t.TempDir()
	store, _ := NewMetricStore(dir)
	defer store.Close()

	cfg := &MonitoringConfig{
		DefaultInterval: 30,
		RetentionDays:   7,
		Custom:          []CustomMetricConfig{{ID: "c1", Label: "My Metric"}},
	}

	handler := NewMetricAPI(store, testSchedulerWithConfig(cfg))
	req := httptest.NewRequest("GET", "/api/metrics/available", nil)
	w := httptest.NewRecorder()
	handler.HandleAvailable(w, req)

	var resp struct{ Metrics []MetricInfo }
	json.Unmarshal(w.Body.Bytes(), &resp)

	hasCustom := false
	for _, m := range resp.Metrics {
		if m.ID == "custom:c1" && m.Label == "My Metric" {
			hasCustom = true
		}
	}
	if !hasCustom {
		t.Fatal("expected custom:c1 in available list")
	}
}

func TestAPISeries_AllRanges(t *testing.T) {
	dir := t.TempDir()
	store, _ := NewMetricStore(dir)
	defer store.Close()

	base := time.Now().Add(-7 * 24 * time.Hour).UnixMilli()
	for i := 0; i < 100; i++ {
		store.Write(MetricPoint{MetricID: "custom:cpu", Value: float64(40 + i%20), Timestamp: base + int64(i*3600000), Unit: "%"})
	}
	store.Flush()

	handler := NewMetricAPI(store, nil)

	for _, r := range []string{"1m", "1h", "6h", "24h", "7d", "30d", "1y"} {
		req := httptest.NewRequest("GET", "/api/metrics/series?metric=custom:cpu&range="+r, nil)
		w := httptest.NewRecorder()
		handler.HandleSeries(w, req)
		if w.Code != 200 {
			t.Fatalf("range %s: expected 200, got %d", r, w.Code)
		}
	}

	req := httptest.NewRequest("GET", "/api/metrics/series?metric=custom:cpu&range=invalid", nil)
	w := httptest.NewRecorder()
	handler.HandleSeries(w, req)
	if w.Code != 400 {
		t.Fatalf("expected 400 for invalid range, got %d", w.Code)
	}
}

func TestMetricAPI_SchedulerConfig(t *testing.T) {
	dir := t.TempDir()
	store, _ := NewMetricStore(dir)
	defer store.Close()

	cfg := DefaultMonitoringConfig()
	api := NewMetricAPI(store, testSchedulerWithConfig(cfg))
	if api.getConfig() != cfg {
		t.Fatal("expected getConfig to return scheduler config")
	}

	api2 := NewMetricAPI(store, nil)
	if api2.getConfig() != nil {
		t.Fatal("expected nil config for nil scheduler")
	}
}

func TestAPISeries_MissingParams(t *testing.T) {
	dir := t.TempDir()
	store, _ := NewMetricStore(dir)
	defer store.Close()

	handler := NewMetricAPI(store, nil)
	req := httptest.NewRequest("GET", "/api/metrics/series", nil)
	w := httptest.NewRecorder()
	handler.HandleSeries(w, req)

	if w.Code != http.StatusBadRequest {
		t.Fatalf("expected 400, got %d", w.Code)
	}
}
