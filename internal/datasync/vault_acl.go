package datasync

import (
	"database/sql"
	"encoding/json"
	"errors"
	"strings"
	"time"
)

var ErrLastManager = errors.New("vault would be left without a manager")

// Higher levels include lower ones.
const (
	LevelNone   = 0
	LevelView   = 1
	LevelEdit   = 2
	LevelManage = 3
)

func LevelFromString(s string) int {
	switch s {
	case "view":
		return LevelView
	case "edit":
		return LevelEdit
	case "manage":
		return LevelManage
	}
	return LevelNone
}

func LevelString(level int) string {
	switch level {
	case LevelView:
		return "view"
	case LevelEdit:
		return "edit"
	case LevelManage:
		return "manage"
	}
	return "none"
}

type VaultMember struct {
	UserID string `json:"user_id"`
	Level  string `json:"level"`
}

// PushRecords reads s.db while its tx is open, so the pool must be larger than one.
type rowQuerier interface {
	QueryRow(query string, args ...any) *sql.Row
}

// Must be called with s.mu held.
func (s *SyncStore) levelFor(userID, vaultID string) int {
	return s.levelForQ(s.db, userID, vaultID)
}

func (s *SyncStore) levelForQ(q rowQuerier, userID, vaultID string) int {
	if s.VaultAdminOverride != nil && s.VaultAdminOverride(userID) {
		return LevelManage
	}
	row := q.QueryRow(
		"SELECT level FROM vault_acl WHERE vault_id=? AND user_id=?", vaultID, userID)
	var level int
	if err := row.Scan(&level); err != nil {
		return LevelNone
	}
	return level
}

func (s *SyncStore) VaultLevel(userID, vaultID string) int {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.levelFor(userID, vaultID)
}

func (s *SyncStore) GrantVault(vaultID, userID string, level int) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	_, err := s.db.Exec(`INSERT OR REPLACE INTO vault_acl (vault_id, user_id, level, updated_at)
		VALUES (?, ?, ?, ?)`, vaultID, userID, level, time.Now().UnixMilli())
	return err
}

func (s *SyncStore) CreateVault(vaultID, userID string) (created bool, err error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	res, err := s.db.Exec(`INSERT INTO vault_acl (vault_id, user_id, level, updated_at)
		SELECT ?, ?, ?, ? WHERE NOT EXISTS (SELECT 1 FROM vault_acl WHERE vault_id=?)`,
		vaultID, userID, LevelManage, time.Now().UnixMilli(), vaultID)
	if err != nil {
		return false, err
	}
	n, err := res.RowsAffected()
	return n == 1, err
}

func (s *SyncStore) soleManager(vaultID, userID string) (bool, error) {
	var level, managers int
	err := s.db.QueryRow(`SELECT
		COALESCE((SELECT level FROM vault_acl WHERE vault_id=? AND user_id=?), 0),
		(SELECT count(*) FROM vault_acl WHERE vault_id=? AND level=?)`,
		vaultID, userID, vaultID, LevelManage).Scan(&level, &managers)
	if err != nil {
		return false, err
	}
	return level == LevelManage && managers <= 1, nil
}

func (s *SyncStore) GrantVaultGuarded(vaultID, userID string, level int) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if level < LevelManage {
		sole, err := s.soleManager(vaultID, userID)
		if err != nil {
			return err
		}
		if sole {
			return ErrLastManager
		}
	}
	_, err := s.db.Exec(`INSERT OR REPLACE INTO vault_acl (vault_id, user_id, level, updated_at)
		VALUES (?, ?, ?, ?)`, vaultID, userID, level, time.Now().UnixMilli())
	return err
}

func (s *SyncStore) RevokeVault(vaultID, userID string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.revokeVaultLocked(vaultID, userID)
}

func (s *SyncStore) RevokeVaultGuarded(vaultID, userID string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	sole, err := s.soleManager(vaultID, userID)
	if err != nil {
		return err
	}
	if sole {
		return ErrLastManager
	}
	return s.revokeVaultLocked(vaultID, userID)
}

func (s *SyncStore) revokeVaultLocked(vaultID, userID string) error {
	if _, err := s.db.Exec(
		"DELETE FROM vault_acl WHERE vault_id=? AND user_id=?", vaultID, userID); err != nil {
		return err
	}
	return s.tombstoneWrapsFor(vaultID, userID)
}

// Must be called with s.mu held.
func (s *SyncStore) tombstoneWrapsFor(vaultID, userID string) error {
	prefix := vaultID + ":"

	// Scan then filter: vault ids may contain '_', a LIKE wildcard.
	rows, err := s.db.Query("SELECT id, data FROM sync_records WHERE type='vault_wrap'")
	if err != nil {
		return err
	}
	type wrapRow struct{ id, data string }
	var all []wrapRow
	for rows.Next() {
		var w wrapRow
		if err := rows.Scan(&w.id, &w.data); err != nil {
			continue
		}
		all = append(all, w)
	}
	rows.Close()

	targets := map[string]string{}
	for _, w := range all {
		if !strings.HasPrefix(w.id, prefix) {
			continue
		}
		suffix := w.id[len(prefix):]
		devID := wrapRecipientDevice(json.RawMessage(w.data))
		if devID == "" {
			devID = suffix
		}
		// An unresolvable device is not this user's and is left alone.
		if s.ResolveDeviceUser == nil {
			continue
		}
		if owner, ok := s.ResolveDeviceUser(devID); ok && owner != "" && owner == userID {
			targets[w.id] = devID
		}
	}

	now := time.Now().UnixMilli()
	for id, devID := range targets {
		// recipient_device must survive in the tombstone so the removal stays visible to that device.
		recipientData, _ := json.Marshal(
			map[string]string{"recipient_device": devID})
		if _, err := s.db.Exec(`UPDATE sync_records SET deleted=1, data=?, credentials='', updated_at=?
			WHERE type='vault_wrap' AND id=?`, string(recipientData), now, id); err != nil {
			return err
		}
	}
	return nil
}

func (s *SyncStore) VaultsForUser(userID string) ([]string, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	rows, err := s.db.Query(
		"SELECT vault_id FROM vault_acl WHERE user_id=? ORDER BY vault_id", userID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []string
	for rows.Next() {
		var v string
		if err := rows.Scan(&v); err != nil {
			continue
		}
		out = append(out, v)
	}
	return out, rows.Err()
}

func (s *SyncStore) VaultMembers(vaultID string) ([]VaultMember, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	rows, err := s.db.Query(
		"SELECT user_id, level FROM vault_acl WHERE vault_id=? ORDER BY user_id", vaultID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var members []VaultMember
	for rows.Next() {
		var m VaultMember
		var level int
		if err := rows.Scan(&m.UserID, &level); err != nil {
			continue
		}
		m.Level = LevelString(level)
		members = append(members, m)
	}
	return members, rows.Err()
}

func (s *SyncStore) VaultExists(vaultID string) bool {
	s.mu.RLock()
	defer s.mu.RUnlock()
	row := s.db.QueryRow("SELECT 1 FROM vault_acl WHERE vault_id=? LIMIT 1", vaultID)
	var one int
	return row.Scan(&one) == nil
}
