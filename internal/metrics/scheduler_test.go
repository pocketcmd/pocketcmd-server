package metrics

import (
	"sync"
	"testing"
)

type fakeSource struct {
	mu        sync.Mutex
	cfg       *MonitoringConfig
	updatedAt int64
}

func (f *fakeSource) Load() (*MonitoringConfig, int64, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.cfg, f.updatedAt, nil
}

func (f *fakeSource) set(cfg *MonitoringConfig, updatedAt int64) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.cfg = cfg
	f.updatedAt = updatedAt
}

func newTestScheduler(t *testing.T, source ConfigSource) *Scheduler {
	t.Helper()
	store, err := NewMetricStore(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { store.Close() })
	eval := NewEvaluator(func(signalType, title, body string, data map[string]string) {}, "testserver")
	return NewScheduler(store, eval, source, nil)
}

func TestScheduler_LoadConfig_Default(t *testing.T) {
	sched := newTestScheduler(t, &fakeSource{})

	sched.loadConfig()

	cfg := sched.GetConfig()
	if cfg == nil {
		t.Fatal("expected default config")
	}
	if cfg.DefaultInterval != 30 {
		t.Fatalf("expected default interval 30, got %d", cfg.DefaultInterval)
	}
	if len(cfg.Custom) != 0 {
		t.Fatal("default config must not run any metrics: the server has none of its own")
	}
}

func TestScheduler_LoadConfig_FromSource(t *testing.T) {
	source := &fakeSource{
		cfg: &MonitoringConfig{
			DefaultInterval: 60,
			RetentionDays:   14,
			Custom: []CustomMetricConfig{
				{ID: "c1", Label: "Conns", Command: "true"},
			},
		},
		updatedAt: 1000,
	}
	sched := newTestScheduler(t, source)

	sched.loadConfig()

	got := sched.GetConfig()
	if got.DefaultInterval != 60 {
		t.Fatalf("expected interval 60, got %d", got.DefaultInterval)
	}
	if got.RetentionDays != 14 {
		t.Fatalf("expected retention 14, got %d", got.RetentionDays)
	}
}

func TestScheduler_ConfigChanged(t *testing.T) {
	source := &fakeSource{
		cfg:       &MonitoringConfig{DefaultInterval: 30, RetentionDays: 7},
		updatedAt: 1000,
	}
	sched := newTestScheduler(t, source)
	sched.loadConfig()

	if _, _, changed := sched.loadIfChanged(); changed {
		t.Fatal("config should not have changed")
	}

	source.set(&MonitoringConfig{DefaultInterval: 30, RetentionDays: 7}, 2000)

	cfg, updatedAt, changed := sched.loadIfChanged()
	if !changed {
		t.Fatal("config should have changed after updating updated_at")
	}
	if cfg == nil || updatedAt != 2000 {
		t.Fatalf("expected the loaded config back, got cfg=%v updatedAt=%d", cfg, updatedAt)
	}
}
