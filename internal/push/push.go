// Package push sends notifications through the relay and stores device registrations.
package push

import (
	"bytes"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"time"
)

const notifyVersion = 2

type PushRegistration struct {
	DeviceID    string `json:"device_id"`
	DeviceToken string `json:"device_token"`
	Platform    string `json:"platform"`
	SignedToken string `json:"signed_token"`
	ExpiresAt   int64  `json:"expires_at"`
}

// Notification is sent to the relay, which requires Title and Body to be set.
type Notification struct {
	SignalType string
	Title      string
	Body       string
	ChannelID  string // relay defaults to channel_messages
	Sound      string
	Data       map[string]string // relay caps at 20 keys / 1 KB
}

type PushClient struct {
	relayURL   string
	httpClient *http.Client
}

func NewPushClient(relayURL string) *PushClient {
	return &PushClient{relayURL: relayURL, httpClient: &http.Client{Timeout: 10 * time.Second}}
}

func (c *PushClient) Notify(regs []PushRegistration, n Notification) (gone []string, err error) {
	var errs []error
	for _, reg := range regs {
		body := map[string]interface{}{
			"v":            notifyVersion,
			"device_token": reg.DeviceToken,
			"platform":     reg.Platform,
			"signed_token": reg.SignedToken,
			"signal_type":  n.SignalType,
			"title":        n.Title,
			"body":         n.Body,
		}
		if n.ChannelID != "" {
			body["channel_id"] = n.ChannelID
		}
		if n.Sound != "" {
			body["sound"] = n.Sound
		}
		if len(n.Data) > 0 {
			body["data"] = n.Data
		}
		data, err := json.Marshal(body)
		if err != nil {
			errs = append(errs, fmt.Errorf("relay notify %s: marshal: %w", reg.DeviceID, err))
			continue
		}
		req, err := http.NewRequest("POST", c.relayURL+"/notify", bytes.NewReader(data))
		if err != nil {
			errs = append(errs, fmt.Errorf("relay notify %s: %w", reg.DeviceID, err))
			continue
		}
		req.Header.Set("Content-Type", "application/json")
		resp, err := c.httpClient.Do(req)
		if err != nil {
			errs = append(errs, fmt.Errorf("relay notify %s: %w", reg.DeviceID, err))
			continue
		}
		switch {
		case resp.StatusCode == http.StatusGone:
			gone = append(gone, reg.DeviceID)
		case resp.StatusCode == http.StatusForbidden:
			respBody, _ := io.ReadAll(resp.Body)
			errs = append(errs, fmt.Errorf(
				"relay notify %s: status 403 (stale signed_token; app must re-register push) body %s",
				reg.DeviceID, string(respBody)))
		case resp.StatusCode >= 300:
			respBody, _ := io.ReadAll(resp.Body)
			errs = append(errs, fmt.Errorf("relay notify %s: status %d body %s",
				reg.DeviceID, resp.StatusCode, string(respBody)))
		}
		resp.Body.Close()
	}
	return gone, errors.Join(errs...)
}

type Store struct {
	db *sql.DB
}

func NewStore(db *sql.DB) *Store {
	return &Store{db: db}
}

func (s *Store) Upsert(reg PushRegistration) error {
	if reg.DeviceID == "" {
		return fmt.Errorf("device id required")
	}
	_, err := s.db.Exec(`INSERT INTO push_registrations
		(device_id, device_token, platform, signed_token, expires_at, updated_at)
		VALUES (?, ?, ?, ?, ?, ?)
		ON CONFLICT(device_id) DO UPDATE SET
			device_token=excluded.device_token,
			platform=excluded.platform,
			signed_token=excluded.signed_token,
			expires_at=excluded.expires_at,
			updated_at=excluded.updated_at`,
		reg.DeviceID, reg.DeviceToken, reg.Platform, reg.SignedToken,
		reg.ExpiresAt, time.Now().UnixMilli())
	return err
}

func (s *Store) ReadAll() ([]PushRegistration, error) {
	rows, err := s.db.Query(`SELECT device_id, device_token, platform, signed_token, expires_at
		FROM push_registrations WHERE expires_at > ?`, time.Now().UnixMilli())
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var regs []PushRegistration
	for rows.Next() {
		var reg PushRegistration
		if err := rows.Scan(&reg.DeviceID, &reg.DeviceToken, &reg.Platform,
			&reg.SignedToken, &reg.ExpiresAt); err != nil {
			continue
		}
		regs = append(regs, reg)
	}
	return regs, rows.Err()
}

func (s *Store) Remove(deviceID string) error {
	if deviceID == "" {
		return fmt.Errorf("invalid device id %q", deviceID)
	}
	_, err := s.db.Exec("DELETE FROM push_registrations WHERE device_id=?", deviceID)
	return err
}
