package metrics

import (
	"crypto/rand"
	"database/sql"
	"encoding/hex"
	"fmt"
	"os"
	"strings"
	"time"
)

type MetricRequest struct {
	ID               string `json:"id"`
	Label            string `json:"label"`
	Command          string `json:"command"`
	IntervalOverride *int   `json:"interval_override,omitempty"` // seconds
	RequestedBy      string `json:"requested_by"`                // user_id
	CreatedAt        string `json:"created_at"`
	Status           string `json:"status"` // pending | approved | declined
	DecidedBy        string `json:"decided_by,omitempty"`
	DecidedAt        string `json:"decided_at,omitempty"`
}

type RequestStore struct {
	db *sql.DB
}

func NewRequestStore(db *sql.DB) *RequestStore {
	return &RequestStore{db: db}
}

const requestCols = `id, label, command, interval_override, requested_by,
	created_at, status, decided_by, decided_at`

func scanRequest(row interface{ Scan(...any) error }) (*MetricRequest, error) {
	var req MetricRequest
	var interval sql.NullInt64
	if err := row.Scan(&req.ID, &req.Label, &req.Command, &interval,
		&req.RequestedBy, &req.CreatedAt, &req.Status, &req.DecidedBy, &req.DecidedAt); err != nil {
		return nil, err
	}
	if interval.Valid {
		v := int(interval.Int64)
		req.IntervalOverride = &v
	}
	return &req, nil
}

func (s *RequestStore) Create(label, command string, intervalSeconds *int, requestedBy string) (*MetricRequest, error) {
	label = strings.TrimSpace(label)
	command = strings.TrimSpace(command)
	if label == "" || command == "" {
		return nil, fmt.Errorf("label and command are required")
	}
	if len(label) > 120 || len(command) > 4096 {
		return nil, fmt.Errorf("label or command too long")
	}
	if err := ValidateCommand(command); err != nil {
		return nil, err
	}
	if intervalSeconds != nil && !ValidIntervalSeconds(*intervalSeconds) {
		return nil, fmt.Errorf("interval_override must be %d–%d seconds", MinIntervalSeconds, MaxIntervalSeconds)
	}
	buf := make([]byte, 8)
	if _, err := rand.Read(buf); err != nil {
		return nil, err
	}
	req := &MetricRequest{
		ID:               "req-" + hex.EncodeToString(buf),
		Label:            label,
		Command:          command,
		IntervalOverride: intervalSeconds,
		RequestedBy:      requestedBy,
		CreatedAt:        time.Now().UTC().Format(time.RFC3339),
		Status:           "pending",
	}
	var interval any
	if req.IntervalOverride != nil {
		interval = *req.IntervalOverride
	}
	_, err := s.db.Exec(`INSERT INTO metric_requests
		(id, label, command, interval_override, requested_by, created_at, status)
		VALUES (?, ?, ?, ?, ?, ?, 'pending')`,
		req.ID, req.Label, req.Command, interval, req.RequestedBy, req.CreatedAt)
	if err != nil {
		return nil, err
	}
	return req, nil
}

func (s *RequestStore) FindByID(id string) (*MetricRequest, error) {
	req, err := scanRequest(s.db.QueryRow(
		"SELECT "+requestCols+" FROM metric_requests WHERE id=?", id))
	if err == sql.ErrNoRows {
		return nil, nil
	}
	return req, err
}

func (s *RequestStore) List() ([]MetricRequest, error) {
	rows, err := s.db.Query("SELECT " + requestCols + " FROM metric_requests ORDER BY created_at DESC")
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []MetricRequest
	for rows.Next() {
		req, err := scanRequest(rows)
		if err != nil {
			continue
		}
		out = append(out, *req)
	}
	return out, rows.Err()
}

// Deleting also revokes an approved command through the custom_metrics FK cascade.
func (s *RequestStore) Delete(id string) (*MetricRequest, error) {
	req, err := s.FindByID(id)
	if err != nil {
		return nil, err
	}
	if req == nil {
		return nil, os.ErrNotExist
	}
	_, err = s.db.Exec("DELETE FROM metric_requests WHERE id=?", id)
	return req, err
}

func (s *RequestStore) Decide(id, status, decidedBy string) (*MetricRequest, error) {
	if status != "approved" && status != "declined" {
		return nil, fmt.Errorf("invalid status %q", status)
	}
	res, err := s.db.Exec(`UPDATE metric_requests SET status=?, decided_by=?, decided_at=?
		WHERE id=? AND status='pending'`,
		status, decidedBy, time.Now().UTC().Format(time.RFC3339), id)
	if err != nil {
		return nil, err
	}
	if n, _ := res.RowsAffected(); n == 0 {
		req, err := s.FindByID(id)
		if err != nil {
			return nil, err
		}
		if req == nil {
			return nil, os.ErrNotExist
		}
		return nil, fmt.Errorf("request already %s", req.Status)
	}
	return s.FindByID(id)
}

// An approved request still referenced by a custom metric is kept; deleting it would revoke the command.
func (s *RequestStore) PruneDecided(before time.Time) (int64, error) {
	cutoff := before.UTC().Format(time.RFC3339)
	res, err := s.db.Exec(`DELETE FROM metric_requests WHERE decided_at <> '' AND decided_at < ? AND (
		status = 'declined' OR
		(status = 'approved' AND NOT EXISTS (
			SELECT 1 FROM custom_metrics WHERE custom_metrics.request_id = metric_requests.id)))`,
		cutoff)
	if err != nil {
		return 0, err
	}
	return res.RowsAffected()
}
