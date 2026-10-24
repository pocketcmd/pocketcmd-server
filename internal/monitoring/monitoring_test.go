package monitoring

import (
	"database/sql"
	"encoding/json"
	"reflect"
	"testing"

	"github.com/pocketcmd/pocketcmd-server/internal/metrics"
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

func applyConfig(t *testing.T, s *Store, db *sql.DB, cfg *metrics.MonitoringConfig, meta Meta) {
	t.Helper()
	data, err := json.Marshal(cfg)
	if err != nil {
		t.Fatal(err)
	}
	tx, err := db.Begin()
	if err != nil {
		t.Fatal(err)
	}
	if err := s.Apply(tx, data, meta, false); err != nil {
		tx.Rollback()
		t.Fatalf("apply: %v", err)
	}
	if err := tx.Commit(); err != nil {
		t.Fatal(err)
	}
}

func intp(v int) *int { return &v }

func fullConfig() *metrics.MonitoringConfig {
	return &metrics.MonitoringConfig{
		ServerID:        "srv-1",
		DefaultInterval: 30,
		RetentionDays:   7,
		Custom: []metrics.CustomMetricConfig{
			{ID: "req-abc", Label: "Dps", Command: "docker ps | wc -l", IntervalOverride: intp(15),
				Alerts: []metrics.AlertRule{
					{ID: "r4@custom:req-abc", Threshold: 100, Operator: "less", MetricID: "custom:req-abc"},
					{ID: "r5", Threshold: 0, Operator: "less"},
				}},
			{ID: "owner-cmd", Label: "Conns", Command: "ss -t | wc -l"},
		},
	}
}

func TestRoundTrip_DecomposeCompose(t *testing.T) {
	s, db := testStore(t)
	in := fullConfig()
	meta := Meta{UpdatedAt: 4242, DeviceID: "dev-1", SchemaVersion: 1}
	applyConfig(t, s, db, in, meta)

	data, gotMeta, ok, err := s.Snapshot()
	if err != nil || !ok {
		t.Fatalf("snapshot: ok=%v err=%v", ok, err)
	}
	if gotMeta != meta {
		t.Fatalf("meta mangled: in=%+v out=%+v", meta, gotMeta)
	}
	var out metrics.MonitoringConfig
	if err := json.Unmarshal(data, &out); err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(*in, out) {
		t.Fatalf("round trip lost data:\n in=%+v\nout=%+v", *in, out)
	}
}

func TestRoundTrip_EmptyListsStayLists(t *testing.T) {
	s, db := testStore(t)
	applyConfig(t, s, db, &metrics.MonitoringConfig{DefaultInterval: 30, RetentionDays: 7},
		Meta{UpdatedAt: 1, SchemaVersion: 1})

	data, _, ok, err := s.Snapshot()
	if err != nil || !ok {
		t.Fatal(err)
	}
	var raw map[string]json.RawMessage
	_ = json.Unmarshal(data, &raw)
	if string(raw["custom_metrics"]) != "[]" {
		t.Fatalf("expected an empty array, got custom=%s", raw["custom_metrics"])
	}
	if _, present := raw["builtin_metrics"]; present {
		t.Fatalf("builtin_metrics must not be emitted any more: %s", data)
	}
}

func TestApply_ReplacesPreviousConfig(t *testing.T) {
	s, db := testStore(t)
	applyConfig(t, s, db, fullConfig(), Meta{UpdatedAt: 1, SchemaVersion: 1})

	slim := &metrics.MonitoringConfig{
		DefaultInterval: 60, RetentionDays: 14,
		Custom: []metrics.CustomMetricConfig{{ID: "owner-cmd", Label: "Conns", Command: "ss -t | wc -l"}},
	}
	applyConfig(t, s, db, slim, Meta{UpdatedAt: 2, SchemaVersion: 1})

	cfg, updatedAt, err := s.Load()
	if err != nil {
		t.Fatal(err)
	}
	if updatedAt != 2 {
		t.Fatalf("updated_at: got %d", updatedAt)
	}
	if len(cfg.Custom) != 1 || cfg.Custom[0].ID != "owner-cmd" || len(cfg.Custom[0].Alerts) != 0 {
		t.Fatalf("stale rows survived: %+v", cfg)
	}
}

func TestApply_TombstoneWipes(t *testing.T) {
	s, db := testStore(t)
	applyConfig(t, s, db, fullConfig(), Meta{UpdatedAt: 1, SchemaVersion: 1})

	tx, _ := db.Begin()
	if err := s.Apply(tx, nil, Meta{UpdatedAt: 2}, true); err != nil {
		t.Fatal(err)
	}
	tx.Commit()

	_, _, ok, err := s.Snapshot()
	if err != nil {
		t.Fatal(err)
	}
	if ok {
		t.Fatal("expected no config after tombstone")
	}
}

func TestApproveCommand_AndRequestDeleteCascade(t *testing.T) {
	s, db := testStore(t)
	requests := metrics.NewRequestStore(db)

	req, err := requests.Create("Dps", "docker ps | wc -l", intp(15), "user-1")
	if err != nil {
		t.Fatal(err)
	}
	if err := s.ApproveCommand(*req); err != nil {
		t.Fatal(err)
	}

	cfg, updatedAt, err := s.Load()
	if err != nil || cfg == nil {
		t.Fatalf("load after approve: cfg=%v err=%v", cfg, err)
	}
	if len(cfg.Custom) != 1 || cfg.Custom[0].ID != req.ID || cfg.Custom[0].Label != "Dps" {
		t.Fatalf("approved command missing: %+v", cfg.Custom)
	}
	if updatedAt == 0 {
		t.Fatal("approve must stamp updated_at")
	}

	if _, err := db.Exec(`INSERT INTO alert_rules (id, custom_id, threshold, operator)
		VALUES ('rule-1', ?, 100, 'less')`, req.ID); err != nil {
		t.Fatal(err)
	}

	if _, err := requests.Delete(req.ID); err != nil {
		t.Fatal(err)
	}
	cfg, _, err = s.Load()
	if err != nil {
		t.Fatal(err)
	}
	if len(cfg.Custom) != 0 {
		t.Fatalf("cascade failed, command survived: %+v", cfg.Custom)
	}
	var n int
	if err := db.QueryRow("SELECT count(*) FROM alert_rules").Scan(&n); err != nil {
		t.Fatal(err)
	}
	if n != 0 {
		t.Fatalf("cascade failed, %d alert rules survived", n)
	}
}

func TestTouch_MonotonicAndNotifies(t *testing.T) {
	s, db := testStore(t)
	applyConfig(t, s, db, fullConfig(), Meta{UpdatedAt: 10, SchemaVersion: 1})

	notified := 0
	s.SetOnChange(func() { notified++ })

	if err := s.Touch(); err != nil {
		t.Fatal(err)
	}
	_, after, _ := s.Load()
	if after <= 10 {
		t.Fatalf("touch must move updated_at forward, got %d", after)
	}
	if notified != 1 {
		t.Fatalf("expected 1 change notification, got %d", notified)
	}

	s2, _ := testStore(t)
	if err := s2.Touch(); err != nil {
		t.Fatal(err)
	}
	cfg, updatedAt, err := s2.Load()
	if err != nil || cfg == nil || updatedAt == 0 {
		t.Fatalf("touch on empty store must seed settings: cfg=%v ts=%d err=%v", cfg, updatedAt, err)
	}
}
