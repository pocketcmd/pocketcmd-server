// Package metrics collects, stores and evaluates server metrics.
package metrics

import (
	"fmt"
	"time"
)

// An unbounded seconds value would overflow time.Duration.
const (
	MinIntervalSeconds = 5
	MaxIntervalSeconds = 21600
	MinRetentionDays   = 1
	MaxRetentionDays   = 30
)

func ValidIntervalSeconds(v int) bool {
	return v >= MinIntervalSeconds && v <= MaxIntervalSeconds
}

func ClampRetention(days int) int {
	if days < MinRetentionDays {
		return MinRetentionDays
	}
	if days > MaxRetentionDays {
		return MaxRetentionDays
	}
	return days
}

func EffectiveInterval(override *int, def time.Duration) time.Duration {
	if override != nil && ValidIntervalSeconds(*override) {
		return time.Duration(*override) * time.Second
	}
	if def < MinIntervalSeconds*time.Second || def > MaxIntervalSeconds*time.Second {
		return 30 * time.Second
	}
	return def
}

func (c *MonitoringConfig) Validate() error {
	if c.DefaultInterval != 0 && !ValidIntervalSeconds(c.DefaultInterval) {
		return fmt.Errorf("default_interval_seconds must be %d–%d", MinIntervalSeconds, MaxIntervalSeconds)
	}
	if c.RetentionDays != 0 && (c.RetentionDays < MinRetentionDays || c.RetentionDays > MaxRetentionDays) {
		return fmt.Errorf("retention_days must be %d–%d", MinRetentionDays, MaxRetentionDays)
	}
	ruleIDs := map[string]bool{}
	checkRules := func(rules []AlertRule) error {
		for _, r := range rules {
			if r.ID == "" {
				return fmt.Errorf("alert rule id is empty")
			}
			if ruleIDs[r.ID] {
				return fmt.Errorf("duplicate alert rule id %q", r.ID)
			}
			ruleIDs[r.ID] = true
			if r.Operator != "greater" && r.Operator != "less" {
				return fmt.Errorf("alert rule %q: unknown operator %q", r.ID, r.Operator)
			}
		}
		return nil
	}
	customIDs := map[string]bool{}
	for _, m := range c.Custom {
		if m.ID == "" {
			return fmt.Errorf("custom metric id is empty")
		}
		if customIDs[m.ID] {
			return fmt.Errorf("duplicate custom metric id %q", m.ID)
		}
		customIDs[m.ID] = true
		if m.IntervalOverride != nil && !ValidIntervalSeconds(*m.IntervalOverride) {
			return fmt.Errorf("custom %q: interval_override must be %d–%d", m.ID, MinIntervalSeconds, MaxIntervalSeconds)
		}
		if err := checkRules(m.Alerts); err != nil {
			return err
		}
	}
	return nil
}

// MonitoringConfig is synced from the mobile app as the "monitoring_config" record.
type MonitoringConfig struct {
	ServerID        string               `json:"server_id"`
	DefaultInterval int                  `json:"default_interval_seconds"`
	RetentionDays   int                  `json:"retention_days"`
	Custom          []CustomMetricConfig `json:"custom_metrics"`
}

type CustomMetricConfig struct {
	ID               string      `json:"id"`
	Label            string      `json:"label"`
	Command          string      `json:"command"`
	IntervalOverride *int        `json:"interval_override"`
	Alerts           []AlertRule `json:"alerts"`
}

type AlertRule struct {
	ID        string  `json:"id"`
	Threshold float64 `json:"threshold"`
	Operator  string  `json:"operator"` // "greater" or "less"
	// MetricID pins the rule to one metric ID; empty applies to every point of the parent metric.
	MetricID string `json:"metric_id,omitempty"`
}

type MetricPoint struct {
	MetricID  string  `json:"metric_id"`
	Value     float64 `json:"value"`
	Timestamp int64   `json:"timestamp"` // unix ms
	Unit      string  `json:"unit"`
}

type MetricInfo struct {
	ID    string `json:"id"`
	Label string `json:"label"`
	Unit  string `json:"unit"`
}

func DefaultMonitoringConfig() *MonitoringConfig {
	return &MonitoringConfig{
		DefaultInterval: 30,
		RetentionDays:   7,
	}
}
