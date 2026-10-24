package datasync

import (
	"encoding/json"
	"strings"
	"testing"
	"time"

	"github.com/pocketcmd/pocketcmd-server/internal/metrics"
)

func monitoringPayload(t *testing.T, cfg metrics.MonitoringConfig) json.RawMessage {
	t.Helper()
	data, err := json.Marshal(cfg)
	if err != nil {
		t.Fatal(err)
	}
	return data
}

func monitoringRec(data json.RawMessage, updatedAt int64) SyncRecord {
	return SyncRecord{
		ID: "monitoring_config", Type: "monitoring_config", SchemaVersion: 1,
		UpdatedAt: updatedAt, DeviceID: "dev-a", Data: data,
	}
}

func TestMonitoringPush_RejectedRecordLeavesPreviousConfigIntact(t *testing.T) {
	store := newTestStore(t)
	t1 := time.Now().UnixMilli()

	valid := metrics.MonitoringConfig{
		DefaultInterval: 30, RetentionDays: 7,
		Custom: []metrics.CustomMetricConfig{
			{ID: "c0", Label: "Load", Command: "cut -d' ' -f1 /proc/loadavg",
				Alerts: []metrics.AlertRule{{ID: "r1", Threshold: 90, Operator: "greater"}}},
			{ID: "c1", Label: "Conns", Command: "ss -t | wc -l"},
		},
	}
	res, err := store.PushRecords("", []SyncRecord{monitoringRec(monitoringPayload(t, valid), t1)})
	if err != nil || len(res.Accepted) != 1 {
		t.Fatalf("valid push: %v %+v", err, res)
	}

	bad := valid
	bad.Custom = []metrics.CustomMetricConfig{{
		ID: "c0", Label: "Load", Command: "cut -d' ' -f1 /proc/loadavg",
		Alerts: []metrics.AlertRule{
			{ID: "dup", Threshold: 90, Operator: "greater"},
			{ID: "dup", Threshold: 95, Operator: "greater"},
		},
	}, valid.Custom[1]}
	res, err = store.PushRecords("", []SyncRecord{
		{ID: "t-1", Type: "task", SchemaVersion: 1, UpdatedAt: t1, DeviceID: "dev-a", Data: json.RawMessage(`{}`)},
		monitoringRec(monitoringPayload(t, bad), t1+1),
	})
	if err != nil {
		t.Fatal(err)
	}
	if len(res.Rejected) != 1 || res.Rejected[0].ID != "monitoring_config" || res.Rejected[0].Reason != RejectMonitoringApplyFailed || len(res.Accepted) != 1 {
		t.Fatalf("bad config must be rejected and the rest of the batch kept: %+v", res)
	}

	got := store.monitoringRecord()
	if got == nil {
		t.Fatal("previous monitoring config vanished")
	}
	if got.UpdatedAt != t1 {
		t.Fatalf("updated_at moved to %d (want %d) on a rejected push", got.UpdatedAt, t1)
	}
	var cfg metrics.MonitoringConfig
	if err := json.Unmarshal(got.Data, &cfg); err != nil {
		t.Fatal(err)
	}
	if len(cfg.Custom) != 2 || cfg.Custom[0].ID != "c0" || len(cfg.Custom[0].Alerts) != 1 ||
		cfg.Custom[0].Alerts[0].ID != "r1" || cfg.Custom[1].ID != "c1" {
		t.Fatalf("previous config was partially wiped: %s", got.Data)
	}

	res, err = store.PushRecords("", []SyncRecord{monitoringRec(monitoringPayload(t, valid), t1+1)})
	if err != nil || len(res.Accepted) != 1 {
		t.Fatalf("corrected push must be accepted, got %v %+v", err, res)
	}
	if got := store.monitoringRecord(); got == nil || got.UpdatedAt != t1+1 {
		t.Fatalf("corrected config not applied: %+v", got)
	}
}

func TestMonitoringPush_RejectsOutOfRangeValues(t *testing.T) {
	store := newTestStore(t)
	now := time.Now().UnixMilli()
	huge := 10_000_000_000

	cases := map[string]metrics.MonitoringConfig{
		"custom interval_override overflow": {Custom: []metrics.CustomMetricConfig{
			{ID: "c", Label: "l", Command: "true", IntervalOverride: &huge}}},
		"custom interval_override too small": {Custom: []metrics.CustomMetricConfig{
			{ID: "c", Label: "l", Command: "true", IntervalOverride: intPtr(1)}}},
		"retention_days overflow":     {RetentionDays: 200000},
		"default_interval too large":  {DefaultInterval: metrics.MaxIntervalSeconds + 1},
		"unknown operator":            {Custom: []metrics.CustomMetricConfig{{ID: "c", Label: "l", Command: "true", Alerts: []metrics.AlertRule{{ID: "r", Operator: "gte"}}}}},
		"duplicate custom metric ids": {Custom: []metrics.CustomMetricConfig{{ID: "c", Label: "a", Command: "true"}, {ID: "c", Label: "b", Command: "true"}}},
	}
	i := int64(0)
	for name, cfg := range cases {
		i++
		res, err := store.PushRecords("", []SyncRecord{monitoringRec(monitoringPayload(t, cfg), now+i)})
		if err != nil {
			t.Fatalf("%s: %v", name, err)
		}
		if len(res.Rejected) != 1 {
			t.Fatalf("%s: expected rejection, got %+v", name, res)
		}
	}
	if store.monitoringRecord() != nil {
		t.Fatal("no config should have been stored")
	}

	ok := metrics.MonitoringConfig{Custom: []metrics.CustomMetricConfig{
		{ID: "c", Label: "l", Command: "true", IntervalOverride: intPtr(metrics.MaxIntervalSeconds)}}}
	res, _ := store.PushRecords("", []SyncRecord{monitoringRec(monitoringPayload(t, ok), now+100)})
	if len(res.Accepted) != 1 {
		t.Fatalf("boundary config must be accepted: %+v", res)
	}
	var stored metrics.MonitoringConfig
	if err := json.Unmarshal(store.monitoringRecord().Data, &stored); err != nil {
		t.Fatal(err)
	}
	if stored.DefaultInterval != 30 || stored.RetentionDays != 7 {
		t.Fatalf("unset scalars must be stored as defaults, got %+v", stored)
	}
	if !strings.Contains(string(store.monitoringRecord().Data), `"interval_override":21600`) {
		t.Fatalf("override not round-tripped: %s", store.monitoringRecord().Data)
	}
}

func intPtr(v int) *int { return &v }
