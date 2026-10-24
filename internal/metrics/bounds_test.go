package metrics

import (
	"context"
	"testing"
	"time"
)

func TestEffectiveInterval_ClampsEverything(t *testing.T) {
	def := 45 * time.Second
	huge := 10_000_000_000
	tiny := 1
	ok := 60
	cases := []struct {
		name     string
		override *int
		def      time.Duration
		want     time.Duration
	}{
		{"override in range", &ok, def, 60 * time.Second},
		{"override overflow → default", &huge, def, def},
		{"override too small → default", &tiny, def, def},
		{"nil override → default", nil, def, def},
		{"default too small → 30s", nil, time.Second, 30 * time.Second},
		{"default overflow → 30s", nil, time.Duration(huge) * time.Second, 30 * time.Second},
		{"default zero → 30s", nil, 0, 30 * time.Second},
	}
	for _, c := range cases {
		if got := EffectiveInterval(c.override, c.def); got != c.want {
			t.Errorf("%s: got %v want %v", c.name, got, c.want)
		}
		if got := EffectiveInterval(c.override, c.def); got <= 0 {
			t.Errorf("%s: non-positive interval %v", c.name, got)
		}
	}
}

func TestClampRetention(t *testing.T) {
	for in, want := range map[int]int{0: 1, -5: 1, 7: 7, 30: 30, 31: 30, 200000: 30} {
		if got := ClampRetention(in); got != want {
			t.Errorf("ClampRetention(%d)=%d want %d", in, got, want)
		}
	}
	if d := time.Duration(ClampRetention(200000)) * 24 * time.Hour; d <= 0 {
		t.Fatalf("overflowed: %v", d)
	}
}

func TestScheduler_CreateTimers_SurvivesOverflowingOverride(t *testing.T) {
	huge := 10_000_000_000
	source := &fakeSource{
		cfg: &MonitoringConfig{
			DefaultInterval: huge, RetentionDays: 7,
			Custom: []CustomMetricConfig{{ID: "c1", Label: "one", Command: "echo 1", IntervalOverride: &huge}},
		},
		updatedAt: 1,
	}
	sched := newTestScheduler(t, source)
	sched.loadConfig()

	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() {
		defer close(done)
		sched.createTimers(ctx)
	}()
	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("createTimers did not return")
	}
	cancel()
	sched.wg.Wait()
}

func TestMonitoringConfig_Validate(t *testing.T) {
	five := 5
	if err := (&MonitoringConfig{}).Validate(); err != nil {
		t.Fatalf("empty config (unset scalars) must validate: %v", err)
	}
	if err := (&MonitoringConfig{DefaultInterval: 30, RetentionDays: 30,
		Custom: []CustomMetricConfig{{ID: "c", Label: "l", Command: "true", IntervalOverride: &five,
			Alerts: []AlertRule{{ID: "a", Operator: "less"}}}}}).Validate(); err != nil {
		t.Fatalf("valid config rejected: %v", err)
	}
	if err := (&MonitoringConfig{RetentionDays: 31}).Validate(); err == nil {
		t.Fatal("retention 31 must be rejected")
	}
	if err := (&MonitoringConfig{DefaultInterval: 4}).Validate(); err == nil {
		t.Fatal("default interval 4 must be rejected")
	}
	if err := (&MonitoringConfig{Custom: []CustomMetricConfig{{ID: "c", Label: "a", Command: "true"}, {ID: "c", Label: "b", Command: "true"}}}).Validate(); err == nil {
		t.Fatal("duplicate custom metric must be rejected")
	}
	if err := (&MonitoringConfig{Custom: []CustomMetricConfig{{ID: "c", Label: "a", Command: "true",
		Alerts: []AlertRule{{ID: "r", Operator: "gte"}}}}}).Validate(); err == nil {
		t.Fatal("unknown operator must be rejected")
	}
}
