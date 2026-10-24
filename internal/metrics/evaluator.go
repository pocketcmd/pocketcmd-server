package metrics

import (
	"fmt"
	"log/slog"
	"sync"
	"time"
)

const (
	// alertCooldown spaces repeat pushes within one continuous breach.
	alertCooldown = time.Hour

	// reFireFloor is the minimum spacing between pushes of the same rule across episodes.
	reFireFloor = 10 * time.Minute
)

type PushFunc func(signalType, title, body string, data map[string]string)

type Evaluator struct {
	pushFn       PushFunc
	serverName   string
	now          func() time.Time
	mu           sync.Mutex
	lastFired    map[string]time.Time // survives resolves so reFireFloor can space out flapping
	wasAbove     map[string]bool
	episodeFired map[string]bool
	store        *AlertStateStore // nil = in-memory only
}

func (e *Evaluator) SetStateStore(store *AlertStateStore) {
	e.mu.Lock()
	defer e.mu.Unlock()
	e.store = store
	if store == nil {
		return
	}
	saved, err := store.Load()
	if err != nil {
		slog.Warn("alert state load failed; starting from a blank state", "error", err)
		return
	}
	for id, st := range saved {
		if !st.LastFired.IsZero() {
			e.lastFired[id] = st.LastFired
		}
		e.wasAbove[id] = st.Breached
		if st.EpisodeFired {
			e.episodeFired[id] = true
		}
	}
}

// e.mu must be held.
func (e *Evaluator) persist(ruleID string) {
	if e.store == nil {
		return
	}
	st := AlertRuleState{
		LastFired:    e.lastFired[ruleID],
		EpisodeFired: e.episodeFired[ruleID],
		Breached:     e.wasAbove[ruleID],
	}
	if err := e.store.Save(ruleID, st); err != nil {
		slog.Warn("alert state save failed", "rule_id", ruleID, "error", err)
	}
}

func NewEvaluator(pushFn PushFunc, serverName string) *Evaluator {
	return &Evaluator{
		pushFn:       pushFn,
		serverName:   serverName,
		now:          time.Now,
		lastFired:    make(map[string]time.Time),
		wasAbove:     make(map[string]bool),
		episodeFired: make(map[string]bool),
	}
}

func (e *Evaluator) Evaluate(metricID, label, unit string, value float64, rules []AlertRule) {
	type firedAlert struct {
		title, body string
		data        map[string]string
	}
	var fired []firedAlert

	// Pushes do network I/O, so dispatch after the lock is released.
	e.mu.Lock()
	for _, rule := range rules {
		if rule.MetricID != "" && rule.MetricID != metricID {
			continue
		}
		breached := e.isBreached(value, rule)

		if !breached {
			if e.wasAbove[rule.ID] || e.episodeFired[rule.ID] {
				e.wasAbove[rule.ID] = false
				delete(e.episodeFired, rule.ID)
				e.persist(rule.ID)
			}
			continue
		}

		if !e.wasAbove[rule.ID] {
			e.wasAbove[rule.ID] = true
			e.persist(rule.ID)
		}

		// A fresh episode only has to clear the floor; repeats wait out the full cooldown.
		required := alertCooldown
		if !e.episodeFired[rule.ID] {
			required = reFireFloor
		}
		if last, ok := e.lastFired[rule.ID]; ok && e.now().Sub(last) < required {
			continue
		}

		e.lastFired[rule.ID] = e.now()
		e.episodeFired[rule.ID] = true
		e.persist(rule.ID)
		display := label
		if display == "" {
			display = metricID
		}
		fired = append(fired, firedAlert{
			title: fmt.Sprintf("%s Alert on %s", display, e.serverName),
			body: fmt.Sprintf("%s at %s (threshold: %s)", display,
				formatWithUnit(value, unit), formatWithUnit(rule.Threshold, unit)),
			data: map[string]string{
				"metric_id":    metricID,
				"metric_label": display,
				"server_name":  e.serverName,
				"value":        fmt.Sprintf("%.2f", value),
				"threshold":    fmt.Sprintf("%.2f", rule.Threshold),
				"unit":         unit,
			},
		})
	}
	e.mu.Unlock()

	for _, a := range fired {
		e.pushFn("metric_alert", a.title, a.body, a.data)
	}
}

func formatWithUnit(v float64, unit string) string {
	switch unit {
	case "":
		return fmt.Sprintf("%.1f", v)
	case "%":
		return fmt.Sprintf("%.1f%%", v)
	default:
		return fmt.Sprintf("%.1f %s", v, unit)
	}
}

func (e *Evaluator) isBreached(value float64, rule AlertRule) bool {
	switch rule.Operator {
	case "greater":
		return value > rule.Threshold
	case "less":
		return value < rule.Threshold
	default:
		return false
	}
}
