//go:build integration

package metrics

import (
	"context"
	"encoding/json"
	"io"
	"log/slog"
	"net/http/httptest"
	"sync"
	"testing"
	"time"
)

func waitFor(t *testing.T, timeout time.Duration, what string, cond func() bool) {
	t.Helper()
	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		if cond() {
			return
		}
		time.Sleep(50 * time.Millisecond)
	}
	t.Fatalf("timed out waiting for %s", what)
}

func TestIntegration_SchedulerRunsNothingByDefault(t *testing.T) {
	dir := t.TempDir()
	store, err := NewMetricStore(dir)
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()

	evaluator := NewEvaluator(func(signalType, title, body string, data map[string]string) {}, "test-host")
	logger := slog.New(slog.NewJSONHandler(io.Discard, nil))

	source := &fakeSource{cfg: &MonitoringConfig{DefaultInterval: 1, RetentionDays: 7}, updatedAt: time.Now().UnixMilli()}
	scheduler := NewScheduler(store, evaluator, source, logger)

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	scheduler.Start(ctx)
	defer scheduler.Stop()

	time.Sleep(2500 * time.Millisecond)
	latest, err := store.Latest()
	if err != nil {
		t.Fatal(err)
	}
	if len(latest) != 0 {
		t.Fatalf("a server with no configured metrics collected %v", latest)
	}
}

func TestIntegration_SchedulerCustomCommand(t *testing.T) {
	dir := t.TempDir()
	store, err := NewMetricStore(dir)
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()

	evaluator := NewEvaluator(func(signalType, title, body string, data map[string]string) {}, "test-host")
	logger := slog.New(slog.NewJSONHandler(io.Discard, nil))

	cfg := &MonitoringConfig{
		DefaultInterval: 1,
		RetentionDays:   7,
		Custom: []CustomMetricConfig{
			{ID: "test-cmd", Label: "Test", Command: "echo 42"},
		},
	}
	source := &fakeSource{cfg: cfg, updatedAt: time.Now().UnixMilli()}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	scheduler := NewScheduler(store, evaluator, source, logger)
	scheduler.Start(ctx)
	defer scheduler.Stop()

	waitFor(t, 10*time.Second, "custom command collection", func() bool {
		latest, _ := store.Latest()
		_, ok := latest["custom:test-cmd"]
		return ok
	})
	latest, _ := store.Latest()
	if val := latest["custom:test-cmd"]; val.Value != 42 {
		t.Fatalf("expected 42, got %f", val.Value)
	}
}

func TestIntegration_AlertFiringOnCollection(t *testing.T) {
	dir := t.TempDir()
	store, err := NewMetricStore(dir)
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()

	var mu sync.Mutex
	var alerts []map[string]string
	evaluator := NewEvaluator(func(signalType, title, body string, data map[string]string) {
		mu.Lock()
		alerts = append(alerts, data)
		mu.Unlock()
	}, "test-host")
	logger := slog.New(slog.NewJSONHandler(io.Discard, nil))

	cfg := &MonitoringConfig{
		DefaultInterval: 1,
		RetentionDays:   7,
		Custom: []CustomMetricConfig{
			{ID: "one", Label: "One", Command: "echo 1", Alerts: []AlertRule{
				{ID: "one-alert", Threshold: 0, Operator: "greater"},
			}},
		},
	}
	source := &fakeSource{cfg: cfg, updatedAt: time.Now().UnixMilli()}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	scheduler := NewScheduler(store, evaluator, source, logger)
	scheduler.Start(ctx)
	defer scheduler.Stop()

	waitFor(t, 10*time.Second, "alert to fire (one > 0)", func() bool {
		mu.Lock()
		defer mu.Unlock()
		return len(alerts) > 0
	})
	mu.Lock()
	defer mu.Unlock()
	if alerts[0]["server_name"] != "test-host" {
		t.Fatalf("expected server_name=test-host, got %s", alerts[0]["server_name"])
	}
	if alerts[0]["metric_label"] != "One" {
		t.Fatalf("expected the configured label in the push, got %q", alerts[0]["metric_label"])
	}
}

func TestIntegration_FullAPIRoundTrip(t *testing.T) {
	dir := t.TempDir()
	store, err := NewMetricStore(dir)
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()

	evaluator := NewEvaluator(func(signalType, title, body string, data map[string]string) {}, "test-host")
	logger := slog.New(slog.NewJSONHandler(io.Discard, nil))

	cfg := &MonitoringConfig{
		DefaultInterval: 1,
		RetentionDays:   7,
		Custom: []CustomMetricConfig{
			{ID: "answer", Label: "Answer", Command: "echo 42"},
		},
	}
	source := &fakeSource{cfg: cfg, updatedAt: time.Now().UnixMilli()}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	scheduler := NewScheduler(store, evaluator, source, logger)
	scheduler.Start(ctx)
	defer scheduler.Stop()

	waitFor(t, 10*time.Second, "custom command collection", func() bool {
		latest, _ := store.Latest()
		_, ok := latest["custom:answer"]
		return ok
	})

	api := NewMetricAPI(store, scheduler)

	req := httptest.NewRequest("GET", "/api/metrics/available", nil)
	w := httptest.NewRecorder()
	api.HandleAvailable(w, req)
	if w.Code != 200 {
		t.Fatalf("available: expected 200, got %d", w.Code)
	}
	var availResp struct{ Metrics []MetricInfo }
	json.Unmarshal(w.Body.Bytes(), &availResp)
	if len(availResp.Metrics) == 0 {
		t.Fatal("available: expected metrics listed")
	}

	req2 := httptest.NewRequest("GET", "/api/metrics/latest", nil)
	w2 := httptest.NewRecorder()
	api.HandleLatest(w2, req2)
	if w2.Code != 200 {
		t.Fatalf("latest: expected 200, got %d", w2.Code)
	}
	var latestResp struct{ Metrics map[string]MetricPoint }
	json.Unmarshal(w2.Body.Bytes(), &latestResp)
	if len(latestResp.Metrics) == 0 {
		t.Fatal("latest: expected collected metrics")
	}

	req3 := httptest.NewRequest("GET", "/api/metrics/series?metric=custom:answer&range=1h", nil)
	w3 := httptest.NewRecorder()
	api.HandleSeries(w3, req3)
	if w3.Code != 200 {
		t.Fatalf("series: expected 200, got %d", w3.Code)
	}
	var seriesResp struct {
		Metric string        `json:"metric"`
		Points []MetricPoint `json:"points"`
	}
	json.Unmarshal(w3.Body.Bytes(), &seriesResp)
	if len(seriesResp.Points) == 0 {
		t.Fatal("series: expected data points")
	}
}
