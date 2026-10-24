package metrics

import (
	"testing"
	"time"

	"github.com/pocketcmd/pocketcmd-server/internal/state"
)

func TestEvaluator_Fires(t *testing.T) {
	var pushed []string
	eval := NewEvaluator(func(signalType, title, body string, data map[string]string) {
		pushed = append(pushed, data["metric_id"])
	}, "testserver")

	rules := []AlertRule{{ID: "r1", Threshold: 90, Operator: "greater"}}
	eval.Evaluate("custom:cpu", "", "", 95, rules)

	if len(pushed) != 1 || pushed[0] != "custom:cpu" {
		t.Fatalf("expected 1 push for custom:cpu, got %v", pushed)
	}
}

func TestEvaluator_BelowThreshold(t *testing.T) {
	var pushed []string
	eval := NewEvaluator(func(signalType, title, body string, data map[string]string) {
		pushed = append(pushed, data["metric_id"])
	}, "testserver")

	rules := []AlertRule{{ID: "r1", Threshold: 90, Operator: "greater"}}
	eval.Evaluate("custom:cpu", "", "", 85, rules)

	if len(pushed) != 0 {
		t.Fatal("should not fire when below threshold")
	}
}

func TestEvaluator_LessOperator(t *testing.T) {
	var pushed []string
	eval := NewEvaluator(func(signalType, title, body string, data map[string]string) {
		pushed = append(pushed, data["metric_id"])
	}, "testserver")

	rules := []AlertRule{{ID: "r1", Threshold: 10, Operator: "less"}}
	eval.Evaluate("custom:disk", "", "", 5, rules)

	if len(pushed) != 1 {
		t.Fatal("should fire when value is less than threshold")
	}
}

func TestEvaluator_Cooldown(t *testing.T) {
	var pushCount int
	eval := NewEvaluator(func(signalType, title, body string, data map[string]string) {
		pushCount++
	}, "testserver")

	rules := []AlertRule{{ID: "r1", Threshold: 90, Operator: "greater"}}

	eval.Evaluate("custom:cpu", "", "", 95, rules)
	eval.Evaluate("custom:cpu", "", "", 95, rules)
	eval.Evaluate("custom:cpu", "", "", 95, rules)

	if pushCount != 1 {
		t.Fatalf("expected 1 push (cooldown), got %d", pushCount)
	}
}

func TestEvaluator_FlappingSuppressedByFloor(t *testing.T) {
	var pushCount int
	eval := NewEvaluator(func(signalType, title, body string, data map[string]string) {
		pushCount++
	}, "testserver")

	rules := []AlertRule{{ID: "r1", Threshold: 90, Operator: "greater"}}

	eval.Evaluate("custom:cpu", "", "", 95, rules)
	for i := 0; i < 5; i++ {
		eval.Evaluate("custom:cpu", "", "", 80, rules)
		eval.Evaluate("custom:cpu", "", "", 95, rules)
	}

	if pushCount != 1 {
		t.Fatalf("expected 1 push (flapping within floor), got %d", pushCount)
	}
}

func TestEvaluator_ResolveReFiresAfterFloor(t *testing.T) {
	var pushCount int
	eval := NewEvaluator(func(signalType, title, body string, data map[string]string) {
		pushCount++
	}, "testserver")
	clock := time.Now()
	eval.now = func() time.Time { return clock }

	rules := []AlertRule{{ID: "r1", Threshold: 90, Operator: "greater"}}

	eval.Evaluate("custom:cpu", "", "", 95, rules)
	eval.Evaluate("custom:cpu", "", "", 80, rules)

	clock = clock.Add(reFireFloor + time.Minute)
	eval.Evaluate("custom:cpu", "", "", 95, rules)

	if pushCount != 2 {
		t.Fatalf("expected 2 pushes (new episode after floor), got %d", pushCount)
	}
}

func TestEvaluator_FloorSuppressedEpisodeRetriesAtFloor(t *testing.T) {
	var pushCount int
	eval := NewEvaluator(func(signalType, title, body string, data map[string]string) {
		pushCount++
	}, "testserver")
	clock := time.Now()
	eval.now = func() time.Time { return clock }

	rules := []AlertRule{{ID: "r1", Threshold: 90, Operator: "greater"}}

	eval.Evaluate("custom:cpu", "", "", 95, rules)
	eval.Evaluate("custom:cpu", "", "", 80, rules)
	eval.Evaluate("custom:cpu", "", "", 95, rules)

	clock = clock.Add(reFireFloor + time.Minute)
	eval.Evaluate("custom:cpu", "", "", 95, rules)

	if pushCount != 2 {
		t.Fatalf("expected 2 pushes (suppressed episode retries at floor), got %d", pushCount)
	}
}

func TestEvaluator_ContinuousBreachWaitsFullCooldown(t *testing.T) {
	var pushCount int
	eval := NewEvaluator(func(signalType, title, body string, data map[string]string) {
		pushCount++
	}, "testserver")
	clock := time.Now()
	eval.now = func() time.Time { return clock }

	rules := []AlertRule{{ID: "r1", Threshold: 90, Operator: "greater"}}

	eval.Evaluate("custom:cpu", "", "", 95, rules)

	clock = clock.Add(reFireFloor + time.Minute)
	eval.Evaluate("custom:cpu", "", "", 95, rules)

	if pushCount != 1 {
		t.Fatalf("expected 1 push (continuous breach inside cooldown), got %d", pushCount)
	}
}

func TestEvaluator_MetricIDPinsRule(t *testing.T) {
	var pushed []string
	eval := NewEvaluator(func(signalType, title, body string, data map[string]string) {
		pushed = append(pushed, data["metric_id"])
	}, "testserver")

	rules := []AlertRule{{
		ID: "r1", Threshold: 90, Operator: "greater",
		MetricID: "builtin:disk:aG9tZQ",
	}}

	eval.Evaluate("builtin:disk:cm9vdA", "", "", 95, rules)
	if len(pushed) != 0 {
		t.Fatalf("pinned rule fired for wrong metric: %v", pushed)
	}

	eval.Evaluate("builtin:disk:aG9tZQ", "", "", 95, rules)
	if len(pushed) != 1 || pushed[0] != "builtin:disk:aG9tZQ" {
		t.Fatalf("expected 1 push for pinned partition, got %v", pushed)
	}
}

func TestEvaluator_EmptyMetricIDAppliesToAll(t *testing.T) {
	var pushed []string
	eval := NewEvaluator(func(signalType, title, body string, data map[string]string) {
		pushed = append(pushed, data["metric_id"])
	}, "testserver")

	rules := []AlertRule{{ID: "r1", Threshold: 90, Operator: "greater"}}

	eval.Evaluate("builtin:disk:cm9vdA", "", "", 95, rules)
	if len(pushed) != 1 {
		t.Fatalf("unpinned rule should fire for any metric of its block, got %v", pushed)
	}
}

func TestEvaluator_LabelInNotification(t *testing.T) {
	var titles, bodies []string
	var labels []string
	eval := NewEvaluator(func(signalType, title, body string, data map[string]string) {
		titles = append(titles, title)
		bodies = append(bodies, body)
		labels = append(labels, data["metric_label"])
	}, "testserver")

	rules := []AlertRule{{ID: "r1", Threshold: 90, Operator: "greater"}}

	eval.Evaluate("custom:req-1dc0251cbc6ae8bf", "Docker Containers", "", 95, rules)
	if len(titles) != 1 || titles[0] != "Docker Containers Alert on testserver" {
		t.Fatalf("custom label missing from title: %v", titles)
	}
	if bodies[0] != "Docker Containers at 95.0 (threshold: 90.0)" {
		t.Fatalf("custom label missing from body: %v", bodies)
	}
	if labels[0] != "Docker Containers" {
		t.Fatalf("metric_label missing from data: %v", labels)
	}

	rules2 := []AlertRule{{ID: "r2", Threshold: 90, Operator: "greater"}}
	eval.Evaluate("custom:req-unlabelled", "", "", 95, rules2)
	if len(titles) != 2 || titles[1] != "custom:req-unlabelled Alert on testserver" {
		t.Fatalf("id fallback missing: %v", titles)
	}
	if labels[1] != "custom:req-unlabelled" {
		t.Fatalf("metric_label fallback missing from data: %v", labels)
	}
}

func TestEvaluator_UnitInPushData(t *testing.T) {
	var bodies, units []string
	eval := NewEvaluator(func(signalType, title, body string, data map[string]string) {
		bodies = append(bodies, body)
		units = append(units, data["unit"])
	}, "testserver")

	eval.Evaluate("custom:cpu", "CPU", "%", 95, []AlertRule{{ID: "r1", Threshold: 90, Operator: "greater"}})
	eval.Evaluate("custom:mem", "Memory", "GB", 12.4, []AlertRule{{ID: "r2", Threshold: 12, Operator: "greater"}})
	eval.Evaluate("custom:load", "Load 1m", "", 4.5, []AlertRule{{ID: "r3", Threshold: 4, Operator: "greater"}})

	want := []string{
		"CPU at 95.0% (threshold: 90.0%)",
		"Memory at 12.4 GB (threshold: 12.0 GB)",
		"Load 1m at 4.5 (threshold: 4.0)",
	}
	if len(bodies) != len(want) {
		t.Fatalf("expected %d pushes, got %d: %v", len(want), len(bodies), bodies)
	}
	for i := range want {
		if bodies[i] != want[i] {
			t.Errorf("body[%d] = %q, want %q", i, bodies[i], want[i])
		}
	}
	if units[0] != "%" || units[1] != "GB" || units[2] != "" {
		t.Fatalf("unit missing from push data: %v", units)
	}
}

func TestEvaluator_CooldownExpiry(t *testing.T) {
	var pushCount int
	eval := NewEvaluator(func(signalType, title, body string, data map[string]string) {
		pushCount++
	}, "testserver")
	clock := time.Now()
	eval.now = func() time.Time { return clock }

	rules := []AlertRule{{ID: "r1", Threshold: 90, Operator: "greater"}}

	eval.Evaluate("custom:cpu", "", "", 95, rules)

	clock = clock.Add(alertCooldown + time.Hour)
	eval.Evaluate("custom:cpu", "", "", 95, rules)

	if pushCount != 2 {
		t.Fatalf("expected 2 pushes after cooldown expiry, got %d", pushCount)
	}
}

func TestEvaluator_StatePersistsAcrossRestart(t *testing.T) {
	db, err := state.Open(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	store := NewAlertStateStore(db)
	rules := []AlertRule{{ID: "r1", Threshold: 90, Operator: "greater"}}
	clock := time.Now()

	pushes := 0
	eval := NewEvaluator(func(string, string, string, map[string]string) { pushes++ }, "srv")
	eval.now = func() time.Time { return clock }
	eval.SetStateStore(store)
	eval.Evaluate("custom:cpu", "", "", 95, rules)
	if pushes != 1 {
		t.Fatalf("first breach: %d pushes", pushes)
	}

	clock = clock.Add(30 * time.Second)
	eval2 := NewEvaluator(func(string, string, string, map[string]string) { pushes++ }, "srv")
	eval2.now = func() time.Time { return clock }
	eval2.SetStateStore(store)
	eval2.Evaluate("custom:cpu", "", "", 95, rules)
	if pushes != 1 {
		t.Fatalf("ongoing breach after restart must not re-push, got %d", pushes)
	}

	eval2.Evaluate("custom:cpu", "", "", 50, rules)
	clock = clock.Add(reFireFloor + time.Second)
	eval3 := NewEvaluator(func(string, string, string, map[string]string) { pushes++ }, "srv")
	eval3.now = func() time.Time { return clock }
	eval3.SetStateStore(store)
	eval3.Evaluate("custom:cpu", "", "", 95, rules)
	if pushes != 2 {
		t.Fatalf("new episode after restart must push, got %d", pushes)
	}

	saved, err := store.Load()
	if err != nil {
		t.Fatal(err)
	}
	if st := saved["r1"]; !st.Breached || !st.EpisodeFired || !st.LastFired.Equal(clock.Truncate(time.Millisecond)) {
		t.Fatalf("persisted state %+v, want breached+episode at %v", st, clock)
	}
}
