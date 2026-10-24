// Package monitoring owns the normalized representation of the team's monitoring configuration in state.db.
package monitoring

import (
	"database/sql"
	"encoding/json"
	"fmt"
	"time"

	"github.com/pocketcmd/pocketcmd-server/internal/metrics"
)

type Meta struct {
	UpdatedAt     int64
	DeviceID      string
	SchemaVersion int
}

type Store struct {
	db       *sql.DB
	onChange func()
}

func NewStore(db *sql.DB) *Store {
	return &Store{db: db}
}

func (s *Store) SetOnChange(fn func()) { s.onChange = fn }

func (s *Store) notify() {
	if s.onChange != nil {
		s.onChange()
	}
}

func (s *Store) Apply(tx *sql.Tx, data json.RawMessage, meta Meta, deleted bool) error {
	var cfg metrics.MonitoringConfig
	if !deleted {
		if err := json.Unmarshal(data, &cfg); err != nil {
			return fmt.Errorf("monitoring config decode: %w", err)
		}
		if err := cfg.Validate(); err != nil {
			return fmt.Errorf("monitoring config invalid: %w", err)
		}
		def := metrics.DefaultMonitoringConfig()
		if cfg.DefaultInterval == 0 {
			cfg.DefaultInterval = def.DefaultInterval
		}
		if cfg.RetentionDays == 0 {
			cfg.RetentionDays = def.RetentionDays
		}
	}

	for _, stmt := range []string{
		"DELETE FROM alert_rules",
		"DELETE FROM custom_metrics",
	} {
		if _, err := tx.Exec(stmt); err != nil {
			return err
		}
	}
	if deleted {
		_, err := tx.Exec("DELETE FROM monitoring_settings")
		return err
	}

	if _, err := tx.Exec(`INSERT INTO monitoring_settings
		(id, default_interval_seconds, retention_days, server_id, schema_version, device_id, updated_at)
		VALUES (1, ?, ?, ?, ?, ?, ?)
		ON CONFLICT(id) DO UPDATE SET
			default_interval_seconds=excluded.default_interval_seconds,
			retention_days=excluded.retention_days,
			server_id=excluded.server_id,
			schema_version=excluded.schema_version,
			device_id=excluded.device_id,
			updated_at=excluded.updated_at`,
		cfg.DefaultInterval, cfg.RetentionDays, cfg.ServerID,
		meta.SchemaVersion, meta.DeviceID, meta.UpdatedAt); err != nil {
		return err
	}

	insertRule := func(rule metrics.AlertRule, customID string, pos int) error {
		_, err := tx.Exec(`INSERT INTO alert_rules
			(id, custom_id, metric_id_pin, threshold, operator, position)
			VALUES (?, ?, ?, ?, ?, ?)`,
			rule.ID, customID, rule.MetricID, rule.Threshold, rule.Operator, pos)
		return err
	}

	for i, c := range cfg.Custom {
		var interval any
		if c.IntervalOverride != nil {
			interval = *c.IntervalOverride
		}
		var requestID any
		var one int
		if err := tx.QueryRow("SELECT 1 FROM metric_requests WHERE id=?", c.ID).Scan(&one); err == nil {
			requestID = c.ID
		}
		if _, err := tx.Exec(`INSERT INTO custom_metrics (id, label, command, interval_override, position, request_id)
			VALUES (?, ?, ?, ?, ?, ?)`,
			c.ID, c.Label, c.Command, interval, i, requestID); err != nil {
			return err
		}
		for j, rule := range c.Alerts {
			if err := insertRule(rule, c.ID, j); err != nil {
				return err
			}
		}
	}
	return nil
}

// Separate from Apply because its transaction may still roll back.
func (s *Store) NotifyApplied() { s.notify() }

func (s *Store) Load() (*metrics.MonitoringConfig, int64, error) {
	cfg, meta, ok, err := s.load()
	if err != nil || !ok {
		return nil, 0, err
	}
	return cfg, meta.UpdatedAt, nil
}

func (s *Store) Snapshot() (data json.RawMessage, meta Meta, ok bool, err error) {
	cfg, meta, ok, err := s.load()
	if err != nil || !ok {
		return nil, meta, ok, err
	}
	data, err = json.Marshal(cfg)
	return data, meta, true, err
}

func (s *Store) load() (*metrics.MonitoringConfig, Meta, bool, error) {
	var meta Meta
	cfg := &metrics.MonitoringConfig{
		Custom: []metrics.CustomMetricConfig{},
	}
	err := s.db.QueryRow(`SELECT default_interval_seconds, retention_days, server_id,
		schema_version, device_id, updated_at FROM monitoring_settings WHERE id=1`).
		Scan(&cfg.DefaultInterval, &cfg.RetentionDays, &cfg.ServerID,
			&meta.SchemaVersion, &meta.DeviceID, &meta.UpdatedAt)
	if err == sql.ErrNoRows {
		return nil, meta, false, nil
	}
	if err != nil {
		return nil, meta, false, err
	}

	rulesByCustom, err := s.loadRules()
	if err != nil {
		return nil, meta, false, err
	}

	rows, err := s.db.Query(`SELECT id, label, command, interval_override
		FROM custom_metrics ORDER BY position`)
	if err != nil {
		return nil, meta, false, err
	}
	defer rows.Close()
	for rows.Next() {
		var c metrics.CustomMetricConfig
		var interval sql.NullInt64
		if err := rows.Scan(&c.ID, &c.Label, &c.Command, &interval); err != nil {
			return nil, meta, false, err
		}
		if interval.Valid {
			v := int(interval.Int64)
			c.IntervalOverride = &v
		}
		c.Alerts = rulesByCustom[c.ID]
		cfg.Custom = append(cfg.Custom, c)
	}
	return cfg, meta, true, rows.Err()
}

func (s *Store) loadRules() (map[string][]metrics.AlertRule, error) {
	rows, err := s.db.Query(`SELECT id, custom_id, metric_id_pin, threshold, operator
		FROM alert_rules ORDER BY position`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := make(map[string][]metrics.AlertRule)
	for rows.Next() {
		var rule metrics.AlertRule
		var customID string
		if err := rows.Scan(&rule.ID, &customID,
			&rule.MetricID, &rule.Threshold, &rule.Operator); err != nil {
			return nil, err
		}
		out[customID] = append(out[customID], rule)
	}
	return out, rows.Err()
}

func (s *Store) ApproveCommand(req metrics.MetricRequest) error {
	tx, err := s.db.Begin()
	if err != nil {
		return err
	}
	defer tx.Rollback()
	var interval any
	if req.IntervalOverride != nil {
		interval = *req.IntervalOverride
	}
	var pos int
	_ = tx.QueryRow("SELECT COALESCE(MAX(position)+1, 0) FROM custom_metrics").Scan(&pos)
	if _, err := tx.Exec(`INSERT INTO custom_metrics (id, label, command, interval_override, position, request_id)
		VALUES (?, ?, ?, ?, ?, ?)
		ON CONFLICT(id) DO UPDATE SET
			label=excluded.label,
			command=excluded.command,
			interval_override=excluded.interval_override,
			request_id=excluded.request_id`,
		req.ID, req.Label, req.Command, interval, pos, req.ID); err != nil {
		return err
	}
	if err := touch(tx); err != nil {
		return err
	}
	if err := tx.Commit(); err != nil {
		return err
	}
	s.notify()
	return nil
}

func (s *Store) Touch() error {
	tx, err := s.db.Begin()
	if err != nil {
		return err
	}
	defer tx.Rollback()
	if err := touch(tx); err != nil {
		return err
	}
	if err := tx.Commit(); err != nil {
		return err
	}
	s.notify()
	return nil
}

func touch(tx *sql.Tx) error {
	now := time.Now().UnixMilli()
	def := metrics.DefaultMonitoringConfig()
	_, err := tx.Exec(`INSERT INTO monitoring_settings
		(id, default_interval_seconds, retention_days, server_id, schema_version, device_id, updated_at)
		VALUES (1, ?, ?, '', 1, '', ?)
		ON CONFLICT(id) DO UPDATE SET updated_at=MAX(excluded.updated_at, monitoring_settings.updated_at+1)`,
		def.DefaultInterval, def.RetentionDays, now)
	return err
}
