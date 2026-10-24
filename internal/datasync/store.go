// Package datasync is the sync-record store and its HTTP handlers.
package datasync

import (
	"database/sql"
	"encoding/json"
	"fmt"
	"log/slog"
	"regexp"
	"strings"
	"sync"
	"time"

	"github.com/pocketcmd/pocketcmd-server/internal/monitoring"
	"github.com/pocketcmd/pocketcmd-server/internal/state"
)

var validRecordID = regexp.MustCompile(`^[a-zA-Z0-9:_-]+$`)

var supportedTypes = map[string]bool{
	"task":              true,
	"ssh_key":           true,
	"task_group":        true,
	"task_tag":          true,
	"sftp_bookmark":     true,
	"workspace":         true,
	"snippet":           true,
	"snippet_folder":    true,
	"command_template":  true,
	"layout_config":     true,
	"port_forward_rule": true,
	"alert_config":      true,
	"settings":          true,
	"monitoring_config": true,
	"dashboard":         true,
	"secret_item":       true,
	"vault_wrap":        true,
	"vault_meta":        true,
	"device_vault_key":  true,
	"enroll_request":    true,
	"device_revocation": true,
	"files_enrollment":  true,
}

// deviceScopedWriteTypes are the record types whose record id is a device id.
var deviceScopedWriteTypes = map[string]bool{
	"device_vault_key":  true,
	"enroll_request":    true,
	"device_revocation": true,
}

// teamScopedTypes are visible to and writable by every active member.
var teamScopedTypes = map[string]bool{
	"monitoring_config": true,
}

// teamVisibleTypes are readable by every member but stay owner-scoped for writes.
var teamVisibleTypes = map[string]bool{
	"device_vault_key":  true,
	"device_revocation": true,
}

type visibility struct {
	s      *SyncStore
	userID string
	levels map[string]int
}

// Must be called with s.mu held.
func (s *SyncStore) visibilityFor(userID string) *visibility {
	return &visibility{s: s, userID: userID, levels: map[string]int{}}
}

func (v *visibility) level(vaultID string) int {
	if l, ok := v.levels[vaultID]; ok {
		return l
	}
	l := v.s.levelFor(v.userID, vaultID)
	v.levels[vaultID] = l
	return l
}

func (v *visibility) visible(recType, recID, recUserID, recVaultID string, deleted bool, data json.RawMessage) bool {
	s, userID := v.s, v.userID
	if userID == "" {
		return true
	}
	if s.AuthorizeRead != nil && !s.AuthorizeRead(userID, recType) {
		return false
	}
	if vid, ok := recordVaultID(recType, recID); ok && isTeamVault(vid) {
		recVaultID = vid
	}
	if recType == "vault_wrap" {
		if recUserID == userID {
			return true
		}
		// Fails closed: an unresolvable recipient falls through to the manager check.
		if devID := wrapRecipientDevice(data); devID != "" && s.ResolveDeviceUser != nil {
			if owner, ok := s.ResolveDeviceUser(devID); ok && owner != "" && owner == userID &&
				v.recipientEntitled(recUserID, recVaultID, deleted) {
				return true
			}
		}
		return v.level(recVaultID) >= LevelManage
	}
	if isTeamVault(recVaultID) {
		return v.level(recVaultID) >= LevelView
	}
	if teamVisibleTypes[recType] {
		return true
	}
	return teamScopedTypes[recType] || recUserID == userID
}

func (v *visibility) recipientEntitled(recUserID, recVaultID string, deleted bool) bool {
	if deleted {
		return true
	}
	if isTeamVault(recVaultID) {
		return v.level(recVaultID) >= LevelView
	}
	return recUserID == "" || recUserID == v.userID
}

func wrapRecipientDevice(data json.RawMessage) string {
	var d struct {
		RecipientDevice string `json:"recipient_device"`
	}
	if err := json.Unmarshal(data, &d); err != nil {
		return ""
	}
	return d.RecipientDevice
}

type SyncRecord struct {
	ID            string          `json:"id"`
	Type          string          `json:"type"`
	SchemaVersion int             `json:"schema_version"`
	UpdatedAt     int64           `json:"updated_at"`
	DeviceID      string          `json:"device_id"`
	Deleted       bool            `json:"deleted"`
	Data          json.RawMessage `json:"data"`
	// Credentials is client-side ciphertext; never log or parse it.
	Credentials string `json:"credentials,omitempty"`
	UserID      string `json:"user_id,omitempty"`
	VaultID     string `json:"vault_id,omitempty"`
}

const PersonalVaultID = "personal"

func recordVaultID(recType, id string) (vaultID string, ok bool) {
	switch recType {
	case "vault_wrap":
		i := strings.IndexByte(id, ':')
		if i <= 0 || i == len(id)-1 {
			return "", false
		}
		return id[:i], true
	case "vault_meta":
		return id, id != ""
	}
	return "", false
}

func isTeamVault(vaultID string) bool {
	return vaultID != "" && vaultID != PersonalVaultID
}

type ManifestEntry struct {
	ID        string `json:"id"`
	Type      string `json:"type"`
	UpdatedAt int64  `json:"updated_at"`
	Deleted   bool   `json:"deleted"`
}

type SyncManifest struct {
	Version     int             `json:"version"`
	LastUpdated int64           `json:"last_updated"`
	Records     []ManifestEntry `json:"records"`
}

// Push rejection reasons are part of the wire contract; never rename one.
const (
	RejectSuperseded                = "superseded"
	RejectInvalidIDOrType           = "invalid_id_or_type"
	RejectInvalidVaultRecordID      = "invalid_vault_record_id"
	RejectVaultIDMismatch           = "vault_id_mismatch"
	RejectVaultACLDenied            = "vault_acl_denied"
	RejectVaultMovedOnLiveRecord    = "vault_moved_on_live_record"
	RejectDeviceScopeDenied         = "device_scope_denied"
	RejectCrossUserOwner            = "cross_user_owner"
	RejectPolicyDenied              = "policy_denied"
	RejectMonitoringUnsupported     = "monitoring_unsupported"
	RejectMonitoringApplyFailed     = "monitoring_apply_failed"
	RejectRevocationDeleteForbidden = "revocation_delete_forbidden"
	RejectWriteFailed               = "write_failed"
	RejectFutureTimestamp           = "future_timestamp"
)

var TransientRejectReasons = map[string]bool{
	RejectSuperseded:            true,
	RejectMonitoringApplyFailed: true,
	RejectWriteFailed:           true,
}

const MaxClockSkew = 5 * time.Minute

type RejectedRecord struct {
	ID     string `json:"id"`
	Reason string `json:"reason"`
}

type PushResult struct {
	Accepted      []string         `json:"accepted"`
	Rejected      []RejectedRecord `json:"rejected"`
	ServerUpdated int64            `json:"server_updated"`
}

type SyncStore struct {
	db *sql.DB
	mu sync.RWMutex

	// monitoring is the canonical store for monitoring_config, which has no sync_records row.
	monitoring *monitoring.Store

	AuthorizeWrite     func(userID string, old *SyncRecord, rec SyncRecord) bool
	AuthorizeRead      func(userID string, recType string) bool
	OnWriteDenied      func(userID string, rec SyncRecord)
	VaultAdminOverride func(userID string) bool
	// ResolveDeviceUser maps a deviceId to its owning user regardless of device status; callers treat ok=false as deny.
	ResolveDeviceUser func(deviceID string) (userID string, ok bool)
	IsTeamAdmin       func(userID string) bool
}

func NewSyncStore(db *sql.DB, mon *monitoring.Store) *SyncStore {
	return &SyncStore{db: db, monitoring: mon}
}

func (s *SyncStore) monitoringRecord() *SyncRecord {
	if s.monitoring == nil {
		return nil
	}
	data, meta, ok, err := s.monitoring.Snapshot()
	if err != nil {
		slog.Warn("monitoring config compose failed", "error", err)
		return nil
	}
	if !ok {
		return nil
	}
	return &SyncRecord{
		ID:            "monitoring_config",
		Type:          "monitoring_config",
		SchemaVersion: meta.SchemaVersion,
		UpdatedAt:     meta.UpdatedAt,
		DeviceID:      meta.DeviceID,
		Data:          data,
	}
}

func (s *SyncStore) PushRecords(userID string, records []SyncRecord) (*PushResult, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	now := time.Now()
	tx, err := s.db.Begin()
	if err != nil {
		return nil, err
	}
	defer tx.Rollback()

	p := &pushBatch{
		s:            s,
		tx:           tx,
		userID:       userID,
		now:          now.UnixMilli(),
		maxUpdatedAt: now.Add(MaxClockSkew).UnixMilli(),
		result: &PushResult{
			Accepted:      []string{},
			Rejected:      []RejectedRecord{},
			ServerUpdated: now.UnixMilli(),
		},
	}
	for _, rec := range records {
		rec, ok := p.validateIncoming(rec)
		if !ok {
			continue
		}
		if rec.Type == "monitoring_config" {
			if err := p.applyMonitoring(rec); err != nil {
				return nil, err
			}
			continue
		}
		p.writeRecord(rec)
	}

	if err := tx.Commit(); err != nil {
		return nil, err
	}

	if p.monitoringApplied {
		s.monitoring.NotifyApplied()
	}

	return p.result, nil
}

type pushBatch struct {
	s                 *SyncStore
	tx                *sql.Tx
	userID            string
	now, maxUpdatedAt int64
	result            *PushResult
	monitoringApplied bool
}

func (p *pushBatch) reject(rec SyncRecord, reason string) {
	p.result.Rejected = append(p.result.Rejected, RejectedRecord{ID: rec.ID, Reason: reason})
	slog.Info("sync push rejected", "type", rec.Type, "id", rec.ID, "reason", reason)
}

func (p *pushBatch) deny(rec SyncRecord, reason string) {
	p.reject(rec, reason)
	if p.s.OnWriteDenied != nil {
		p.s.OnWriteDenied(p.userID, rec)
	}
}

func (p *pushBatch) validateIncoming(rec SyncRecord) (SyncRecord, bool) {
	if !validRecordID.MatchString(rec.ID) || !supportedTypes[rec.Type] {
		p.reject(rec, RejectInvalidIDOrType)
		return rec, false
	}
	if rec.UpdatedAt == 0 {
		rec.UpdatedAt = p.now
	}
	if rec.UpdatedAt > p.maxUpdatedAt {
		p.reject(rec, RejectFutureTimestamp)
		return rec, false
	}

	if rec.Type == "vault_wrap" || rec.Type == "vault_meta" {
		vid, ok := recordVaultID(rec.Type, rec.ID)
		if !ok {
			p.reject(rec, RejectInvalidVaultRecordID)
			return rec, false
		}
		switch {
		case vid == PersonalVaultID:
			if rec.VaultID != "" && rec.VaultID != PersonalVaultID {
				p.reject(rec, RejectVaultIDMismatch)
				return rec, false
			}
		case rec.VaultID == "":
			rec.VaultID = vid
		case rec.VaultID != vid:
			p.reject(rec, RejectVaultIDMismatch)
			return rec, false
		}
	}

	// device_revocation is never tombstoned, on any path; CleanupTombstones relies on this.
	if rec.Type == "device_revocation" && rec.Deleted {
		p.reject(rec, RejectRevocationDeleteForbidden)
		return rec, false
	}
	if p.userID != "" && deviceScopedWriteTypes[rec.Type] &&
		!p.s.mayWriteDeviceRecord(p.userID, rec.ID) {
		p.deny(rec, RejectDeviceScopeDenied)
		return rec, false
	}
	return rec, true
}

func (p *pushBatch) applyMonitoring(rec SyncRecord) error {
	s, tx := p.s, p.tx
	if s.monitoring == nil || rec.ID != "monitoring_config" {
		p.reject(rec, RejectMonitoringUnsupported)
		return nil
	}
	existing := s.monitoringRecord()
	if existing != nil && existing.UpdatedAt >= rec.UpdatedAt {
		p.reject(rec, RejectSuperseded)
		return nil
	}
	if p.userID != "" && s.AuthorizeWrite != nil && !s.AuthorizeWrite(p.userID, existing, rec) {
		p.deny(rec, RejectPolicyDenied)
		return nil
	}
	meta := monitoring.Meta{
		UpdatedAt:     rec.UpdatedAt,
		DeviceID:      rec.DeviceID,
		SchemaVersion: rec.SchemaVersion,
	}
	// SQLite aborts only the failing statement, so the wipe-and-rebuild needs a savepoint.
	if _, err := tx.Exec("SAVEPOINT monitoring_apply"); err != nil {
		p.reject(rec, RejectMonitoringApplyFailed)
		return nil
	}
	if err := s.monitoring.Apply(tx, rec.Data, meta, rec.Deleted); err != nil {
		slog.Warn("monitoring config apply failed", "error", err)
		if _, rbErr := tx.Exec("ROLLBACK TO monitoring_apply"); rbErr != nil {
			return fmt.Errorf("monitoring apply rollback: %w", rbErr)
		}
		_, _ = tx.Exec("RELEASE monitoring_apply")
		p.reject(rec, RejectMonitoringApplyFailed)
		return nil
	}
	if _, err := tx.Exec("RELEASE monitoring_apply"); err != nil {
		return fmt.Errorf("monitoring apply release: %w", err)
	}
	p.monitoringApplied = true
	p.result.Accepted = append(p.result.Accepted, rec.ID)
	return nil
}

func (p *pushBatch) writeRecord(rec SyncRecord) {
	s, tx, userID := p.s, p.tx, p.userID
	row := tx.QueryRow("SELECT "+syncCols+" FROM sync_records WHERE type=? AND id=?",
		rec.Type, rec.ID)
	var existing *SyncRecord
	if prev, scanErr := scanRecord(row); scanErr == nil {
		existing = &prev
		if existing.UpdatedAt >= rec.UpdatedAt {
			p.reject(rec, RejectSuperseded)
			return
		}
		if existing.VaultID != rec.VaultID && !existing.Deleted {
			p.reject(rec, RejectVaultMovedOnLiveRecord)
			return
		}
		if userID != "" && existing.UserID != "" && existing.UserID != userID &&
			!teamScopedTypes[rec.Type] && !isTeamVault(rec.VaultID) {
			p.reject(rec, RejectCrossUserOwner)
			return
		}
	}

	if userID != "" && isTeamVault(rec.VaultID) {
		required := LevelEdit
		if rec.Type == "vault_wrap" || rec.Type == "vault_meta" {
			required = LevelManage
		}
		if s.levelForQ(tx, userID, rec.VaultID) < required {
			p.deny(rec, RejectVaultACLDenied)
			return
		}
	}

	if userID != "" && s.AuthorizeWrite != nil && !s.AuthorizeWrite(userID, existing, rec) {
		p.deny(rec, RejectPolicyDenied)
		return
	}

	owner := userID
	if owner == "" && existing != nil {
		owner = existing.UserID
	}

	data := rec.Data
	if data == nil {
		data = json.RawMessage("null")
	}
	_, err := tx.Exec(`INSERT OR REPLACE INTO sync_records (id, type, schema_version, updated_at, device_id, deleted, data, credentials, user_id, vault_id)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
		rec.ID, rec.Type, rec.SchemaVersion, rec.UpdatedAt, rec.DeviceID,
		state.BoolInt(rec.Deleted), string(data), rec.Credentials, owner, rec.VaultID)
	if err != nil {
		slog.Warn("sync push write failed", "id", rec.ID, "error", err)
		p.reject(rec, RejectWriteFailed)
		return
	}
	p.result.Accepted = append(p.result.Accepted, rec.ID)
}

// Fails closed: without a resolver or for an unknown device only an admin may write.
func (s *SyncStore) mayWriteDeviceRecord(userID, deviceID string) bool {
	if s.IsTeamAdmin != nil && s.IsTeamAdmin(userID) {
		return true
	}
	if s.ResolveDeviceUser == nil {
		return false
	}
	owner, ok := s.ResolveDeviceUser(deviceID)
	return ok && owner != "" && owner == userID
}

func (s *SyncStore) PullRecords(userID string, ids []string) ([]SyncRecord, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	vis := s.visibilityFor(userID)
	var records []SyncRecord
	for _, id := range ids {
		if id == "monitoring_config" {
			if rec := s.monitoringRecord(); rec != nil &&
				vis.visible(rec.Type, rec.ID, "", "", false, rec.Data) {
				records = append(records, *rec)
			}
			continue
		}
		// Drain the cursor before visibility filtering: the ACL check queries the same handle.
		rows, err := s.db.Query("SELECT "+syncCols+" FROM sync_records WHERE id=?", id)
		if err != nil {
			continue
		}
		var matches []SyncRecord
		for rows.Next() {
			if rec, scanErr := scanRecord(rows); scanErr == nil {
				matches = append(matches, rec)
			}
		}
		rows.Close()
		for _, rec := range matches {
			if vis.visible(rec.Type, rec.ID, rec.UserID, rec.VaultID, rec.Deleted, rec.Data) {
				records = append(records, rec)
			}
		}
	}
	return records, nil
}

func (s *SyncStore) RecordsByType(recType string) ([]SyncRecord, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	rows, err := s.db.Query("SELECT "+syncCols+" FROM sync_records WHERE type=?", recType)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var records []SyncRecord
	for rows.Next() {
		rec, err := scanRecord(rows)
		if err != nil {
			continue
		}
		records = append(records, rec)
	}
	return records, rows.Err()
}

func (s *SyncStore) GetManifest(userID string) (*SyncManifest, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	rows, err := s.db.Query(`SELECT id, type, updated_at, deleted, user_id, vault_id,
		CASE WHEN type='vault_wrap' THEN data ELSE '' END FROM sync_records`)
	if err != nil {
		return nil, err
	}

	// Drain the cursor before visibility filtering: the ACL check queries the same handle.
	type scanned struct {
		entry   ManifestEntry
		deleted int
		owner   string
		vaultID string
		data    string
	}
	var all []scanned
	for rows.Next() {
		var sc scanned
		if err := rows.Scan(&sc.entry.ID, &sc.entry.Type, &sc.entry.UpdatedAt, &sc.deleted, &sc.owner, &sc.vaultID, &sc.data); err != nil {
			continue
		}
		all = append(all, sc)
	}
	rows.Close()

	vis := s.visibilityFor(userID)
	manifest := &SyncManifest{Version: 1}
	for _, sc := range all {
		if !vis.visible(sc.entry.Type, sc.entry.ID, sc.owner, sc.vaultID, sc.deleted != 0, json.RawMessage(sc.data)) {
			continue
		}
		entry := sc.entry
		entry.Deleted = sc.deleted != 0
		if entry.UpdatedAt > manifest.LastUpdated {
			manifest.LastUpdated = entry.UpdatedAt
		}
		manifest.Records = append(manifest.Records, entry)
	}

	if rec := s.monitoringRecord(); rec != nil &&
		vis.visible(rec.Type, rec.ID, "", "", false, rec.Data) {
		manifest.Records = append(manifest.Records, ManifestEntry{
			ID:        rec.ID,
			Type:      rec.Type,
			UpdatedAt: rec.UpdatedAt,
		})
		if rec.UpdatedAt > manifest.LastUpdated {
			manifest.LastUpdated = rec.UpdatedAt
		}
	}
	return manifest, nil
}

func (s *SyncStore) PurgeUserData(userID string, deviceIDs []string) (int64, error) {
	if userID == "" && len(deviceIDs) == 0 {
		return 0, nil
	}
	s.mu.Lock()
	defer s.mu.Unlock()

	match := ""
	var args []interface{}
	args = append(args, time.Now().UnixMilli())
	if userID != "" {
		match = "user_id = ?"
		args = append(args, userID)
	}
	if len(deviceIDs) > 0 {
		placeholders := ""
		for i, id := range deviceIDs {
			if i > 0 {
				placeholders += ","
			}
			placeholders += "?"
			args = append(args, id)
		}
		if match != "" {
			match += " OR "
		}
		// The device branch only matches ownerless rows; a device key may be re-paired under another user.
		match += "(user_id = '' AND device_id IN (" + placeholders + "))"
	}
	args = append(args, PersonalVaultID)
	exempt := ""
	for i, t := range purgeExemptTypes {
		if i > 0 {
			exempt += ","
		}
		exempt += "?"
		args = append(args, t)
	}
	res, err := s.db.Exec(`UPDATE sync_records SET deleted=1, data='{}', credentials='', updated_at=?
		WHERE (`+match+`) AND (vault_id = '' OR vault_id = ?)
		AND type NOT IN (`+exempt+`)
		AND NOT (deleted=1 AND data='{}' AND credentials='')`, args...)
	if err != nil {
		return 0, err
	}
	n, _ := res.RowsAffected()
	return n, nil
}

var purgeExemptTypes = []string{"device_revocation", "device_vault_key"}

func (s *SyncStore) CleanupTombstones(maxAge time.Duration) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	cutoff := time.Now().Add(-maxAge).UnixMilli()
	_, err := s.db.Exec("DELETE FROM sync_records WHERE deleted=1 AND updated_at < ?", cutoff)
	return err
}

const syncCols = "id, type, schema_version, updated_at, device_id, deleted, data, credentials, user_id, vault_id"

func scanRecord(row interface{ Scan(...any) error }) (SyncRecord, error) {
	var rec SyncRecord
	var deleted int
	var dataStr string
	err := row.Scan(&rec.ID, &rec.Type, &rec.SchemaVersion, &rec.UpdatedAt, &rec.DeviceID, &deleted, &dataStr, &rec.Credentials, &rec.UserID, &rec.VaultID)
	if err != nil {
		return rec, err
	}
	rec.Deleted = deleted != 0
	rec.Data = json.RawMessage(dataStr)
	return rec, nil
}
