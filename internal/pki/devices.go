package pki

import (
	"crypto/sha256"
	"crypto/x509"
	"database/sql"
	"encoding/hex"
	"encoding/pem"
	"errors"
	"fmt"
	"io/fs"
	"strings"
	"sync"
	"time"
	"unicode/utf8"
)

// Only an active device authenticates; a revoked key never pairs again, a left key may via an invite.
const (
	DeviceStatusActive  = "active"
	DeviceStatusRevoked = "revoked"
	DeviceStatusLeft    = "left"
)

var ErrDeviceNotLeft = errors.New("device is not in the left state")

type DeviceRecord struct {
	DeviceID    string `json:"device_id"`
	PublicKey   string `json:"public_key"` // PEM-encoded ECDSA public key
	DeviceName  string `json:"device_name"`
	Status      string `json:"status"`
	PairedAt    string `json:"paired_at"`
	UserID      string `json:"user_id,omitempty"`
	DeviceLabel string `json:"device_label,omitempty"`
	RevokedAt   string `json:"revoked_at,omitempty"` // set on revoke and on leave
	LastSeenAt  string `json:"last_seen_at,omitempty"`
}

func PubKeyFingerprint(pubKeyPEM string) (string, error) {
	block, _ := pem.Decode([]byte(pubKeyPEM))
	if block == nil {
		return "", fmt.Errorf("invalid PEM")
	}
	hash := sha256.Sum256(block.Bytes)
	return hex.EncodeToString(hash[:]), nil
}

func PublicKeysEqual(aPEM, bPEM string) bool {
	fpA, errA := PubKeyFingerprint(aPEM)
	fpB, errB := PubKeyFingerprint(bPEM)
	return errA == nil && errB == nil && fpA == fpB
}

type DeviceRegistry struct {
	db *sql.DB

	// touched memoizes the last TouchLastSeen write per device; a zero-row UPDATE
	// still takes SQLite's writer lock.
	touchMu sync.Mutex
	touched map[string]time.Time
}

func NewDeviceRegistry(db *sql.DB) *DeviceRegistry {
	return &DeviceRegistry{db: db, touched: make(map[string]time.Time)}
}

const deviceCols = "device_id, public_key, device_name, device_label, status, user_id, paired_at, revoked_at, last_seen_at"

func scanDevice(row interface{ Scan(...any) error }) (*DeviceRecord, error) {
	var d DeviceRecord
	if err := row.Scan(&d.DeviceID, &d.PublicKey, &d.DeviceName, &d.DeviceLabel,
		&d.Status, &d.UserID, &d.PairedAt, &d.RevokedAt, &d.LastSeenAt); err != nil {
		return nil, err
	}
	return &d, nil
}

func (r *DeviceRegistry) IsAllowedByPubKey(pubKeyPEM string) bool {
	dev, ok := r.LookupByPublicKeyPEM(pubKeyPEM)
	if !ok {
		return false
	}
	return dev.Status == DeviceStatusActive
}

func (r *DeviceRegistry) IsAllowedByCert(certDER []byte) bool {
	cert, err := x509.ParseCertificate(certDER)
	if err != nil {
		return false
	}
	pubPEM, err := PublicKeyPEM(cert.PublicKey)
	if err != nil {
		return false
	}
	return r.IsAllowedByPubKey(pubPEM)
}

func (r *DeviceRegistry) FindByID(deviceID string) (*DeviceRecord, error) {
	d, err := scanDevice(r.db.QueryRow(
		"SELECT "+deviceCols+" FROM devices WHERE device_id=?", deviceID))
	if err == sql.ErrNoRows {
		return nil, fs.ErrNotExist
	}
	return d, err
}

func (r *DeviceRegistry) LookupByPublicKeyPEM(pubKeyPEM string) (*DeviceRecord, bool) {
	deviceID, err := DeviceIDFromPublicKey(pubKeyPEM)
	if err != nil {
		return nil, false
	}
	dev, err := r.FindByID(deviceID)
	if err != nil {
		return nil, false
	}
	// Guard against device-id prefix collisions with a full-fingerprint compare.
	if !PublicKeysEqual(dev.PublicKey, pubKeyPEM) {
		return nil, false
	}
	return dev, true
}

const MinPrefixLen = 8

func (r *DeviceRegistry) FindByPubKeyPrefix(prefix string) (*DeviceRecord, error) {
	if len(prefix) < MinPrefixLen {
		return nil, fmt.Errorf("device prefix must be at least %d characters (got %q)", MinPrefixLen, prefix)
	}
	devices, err := r.List()
	if err != nil {
		return nil, err
	}
	for _, d := range devices {
		fp, _ := PubKeyFingerprint(d.PublicKey)
		if strings.HasPrefix(fp, prefix) || strings.HasPrefix(d.DeviceID, prefix) {
			return &d, nil
		}
	}
	return nil, fmt.Errorf("no device found matching prefix %s", prefix)
}

func (r *DeviceRegistry) List() ([]DeviceRecord, error) {
	rows, err := r.db.Query("SELECT " + deviceCols + " FROM devices ORDER BY paired_at")
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var devices []DeviceRecord
	for rows.Next() {
		d, err := scanDevice(rows)
		if err != nil {
			continue
		}
		devices = append(devices, *d)
	}
	return devices, rows.Err()
}

func (r *DeviceRegistry) RegisterDeviceForUser(pubKeyPEM, deviceName, userID, deviceLabel string) (string, error) {
	if userID == "" {
		return "", fmt.Errorf("user_id required")
	}
	if err := ValidateDevicePublicKey(pubKeyPEM); err != nil {
		return "", err
	}
	if !ValidDeviceName(deviceName) || !ValidDeviceName(deviceLabel) {
		return "", ErrNameTooLong
	}
	deviceID, err := DeviceIDFromPublicKey(pubKeyPEM)
	if err != nil {
		return "", err
	}

	_, err = r.db.Exec(`INSERT OR IGNORE INTO devices
		(device_id, public_key, device_name, device_label, status, user_id, paired_at)
		VALUES (?, ?, ?, ?, 'active', ?, ?)`,
		deviceID, pubKeyPEM, deviceName, deviceLabel, userID,
		time.Now().UTC().Format(time.RFC3339))
	if err != nil {
		return "", err
	}
	return deviceID, nil
}

func (r *DeviceRegistry) DevicesByUserID(userID string) ([]DeviceRecord, error) {
	rows, err := r.db.Query("SELECT "+deviceCols+" FROM devices WHERE user_id=? ORDER BY paired_at", userID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []DeviceRecord
	for rows.Next() {
		d, err := scanDevice(rows)
		if err != nil {
			continue
		}
		out = append(out, *d)
	}
	return out, rows.Err()
}

func (r *DeviceRegistry) TouchLastSeen(deviceID string, throttle time.Duration) error {
	now := time.Now().UTC()
	r.touchMu.Lock()
	if last, ok := r.touched[deviceID]; ok && now.Sub(last) < throttle {
		r.touchMu.Unlock()
		return nil
	}
	r.touchMu.Unlock()

	cutoff := now.Add(-throttle).Format(time.RFC3339)
	res, err := r.db.Exec(`UPDATE devices SET last_seen_at=?
		WHERE device_id=? AND status='active' AND (last_seen_at='' OR last_seen_at < ?)`,
		now.Format(time.RFC3339), deviceID, cutoff)
	if err != nil {
		return err
	}
	if n, _ := res.RowsAffected(); n == 0 {
		var one int
		if err := r.db.QueryRow("SELECT 1 FROM devices WHERE device_id=?", deviceID).Scan(&one); err == sql.ErrNoRows {
			return fs.ErrNotExist
		}
	}
	r.touchMu.Lock()
	r.touched[deviceID] = now
	r.touchMu.Unlock()
	return nil
}

func (r *DeviceRegistry) Revoke(deviceID string) error {
	_, err := r.db.Exec(`UPDATE devices SET status='revoked', revoked_at=?
		WHERE device_id=? AND status IN ('active','left')`,
		time.Now().UTC().Format(time.RFC3339), deviceID)
	if err != nil {
		return err
	}
	_, err = r.db.Exec("DELETE FROM push_registrations WHERE device_id=?", deviceID)
	return err
}

func (r *DeviceRegistry) Leave(deviceID string) error {
	_, err := r.db.Exec(`UPDATE devices SET status='left', revoked_at=?
		WHERE device_id=? AND status='active'`,
		time.Now().UTC().Format(time.RFC3339), deviceID)
	if err != nil {
		return err
	}
	_, err = r.db.Exec("DELETE FROM push_registrations WHERE device_id=?", deviceID)
	return err
}

func (r *DeviceRegistry) Reactivate(deviceID, userID, deviceName, deviceLabel string,
	prepare func(tx *sql.Tx, previousUserID string) error) error {
	if userID == "" {
		return fmt.Errorf("user_id required")
	}
	if !ValidDeviceName(deviceName) || !ValidDeviceName(deviceLabel) {
		return ErrNameTooLong
	}
	tx, err := r.db.Begin()
	if err != nil {
		return err
	}
	defer tx.Rollback()

	var status, previousUserID string
	err = tx.QueryRow("SELECT status, user_id FROM devices WHERE device_id=?", deviceID).
		Scan(&status, &previousUserID)
	if err == sql.ErrNoRows {
		return fs.ErrNotExist
	}
	if err != nil {
		return err
	}
	if status != DeviceStatusLeft {
		return ErrDeviceNotLeft
	}
	if prepare != nil {
		if err := prepare(tx, previousUserID); err != nil {
			return err
		}
	}
	res, err := tx.Exec(`UPDATE devices SET status='active', user_id=?, device_name=?,
		device_label=?, paired_at=?, revoked_at='', last_seen_at=''
		WHERE device_id=? AND status='left'`,
		userID, deviceName, deviceLabel, time.Now().UTC().Format(time.RFC3339), deviceID)
	if err != nil {
		return err
	}
	if n, _ := res.RowsAffected(); n != 1 {
		return ErrDeviceNotLeft
	}
	if err := tx.Commit(); err != nil {
		return err
	}
	r.touchMu.Lock()
	delete(r.touched, deviceID)
	r.touchMu.Unlock()
	return nil
}

const MaxDeviceNameLen = 128

var ErrNameTooLong = errors.New("device name too long")

func ValidDeviceName(name string) bool {
	return utf8.RuneCountInString(name) <= MaxDeviceNameLen
}

func (r *DeviceRegistry) Rename(deviceID string, name, label *string) error {
	if name == nil && label == nil {
		return nil
	}
	if (name != nil && !ValidDeviceName(*name)) || (label != nil && !ValidDeviceName(*label)) {
		return ErrNameTooLong
	}
	set, args := "", []any{}
	if name != nil {
		set += "device_name=?"
		args = append(args, *name)
	}
	if label != nil {
		if set != "" {
			set += ", "
		}
		set += "device_label=?"
		args = append(args, *label)
	}
	args = append(args, deviceID)
	res, err := r.db.Exec("UPDATE devices SET "+set+" WHERE device_id=?", args...)
	if err != nil {
		return err
	}
	if n, _ := res.RowsAffected(); n == 0 {
		return fs.ErrNotExist
	}
	return nil
}

// The public key stays so a scrubbed device still presents as revoked, not unknown.
func (r *DeviceRegistry) ScrubUserDevices(userID string) error {
	_, err := r.db.Exec(`UPDATE devices SET device_name='', device_label='',
		last_seen_at='' WHERE user_id=? AND status IN ('revoked','left')`, userID)
	return err
}
