package pki

import (
	"crypto/rand"
	"database/sql"
	"encoding/base32"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"time"
	"unicode/utf8"
)

var (
	ErrNotOwner           = errors.New("user is not the owner")
	ErrUserNotFound       = errors.New("user not found")
	ErrUserNotActive      = errors.New("user is not active")
	ErrSelfTransfer       = errors.New("cannot transfer ownership to self")
	ErrDisplayNameTooLong = errors.New("display name too long")
	ErrOwnerImmutable     = errors.New("the owner cannot be demoted or revoked")
)

const (
	RoleAdmin  = "admin"
	RoleMember = "member"
)

// Only an active user authenticates.
const (
	UserStatusActive  = "active"
	UserStatusRevoked = "revoked"
)

const MaxDisplayNameLen = 64

func ValidDisplayName(name string) bool {
	return name != "" && utf8.RuneCountInString(name) <= MaxDisplayNameLen
}

type UserRecord struct {
	UserID          string `json:"user_id"`
	DisplayName     string `json:"display_name"`
	Role            string `json:"role"`
	Status          string `json:"status"`
	CreatedAt       string `json:"created_at"`
	CreatedByUserID string `json:"created_by_user_id"`
	RevokedAt       string `json:"revoked_at,omitempty"`
	// the single owner is always an admin
	Owner       bool          `json:"owner,omitempty"`
	Permissions PermissionSet `json:"permissions,omitempty"`
	// permissions column as scanned; SetPermissionsGuarded compares against it
	permissionsRaw string
}

// An empty Metrics list means all metrics.
type Grant struct {
	Granted bool     `json:"granted"`
	Metrics []string `json:"metrics,omitempty"`
}

type PermissionSet map[string]Grant

type UserRegistry struct {
	db *sql.DB
}

func NewUserRegistry(db *sql.DB) *UserRegistry {
	return &UserRegistry{db: db}
}

func newUserID() (string, error) {
	buf := make([]byte, 10)
	if _, err := rand.Read(buf); err != nil {
		return "", err
	}
	s := strings.ToLower(base32.StdEncoding.WithPadding(base32.NoPadding).EncodeToString(buf))
	return s[:12], nil
}

const userCols = "user_id, display_name, role, status, owner, permissions, created_at, created_by, revoked_at"

func scanUser(row interface{ Scan(...any) error }) (*UserRecord, error) {
	var rec UserRecord
	var owner int
	var perms string
	if err := row.Scan(&rec.UserID, &rec.DisplayName, &rec.Role, &rec.Status,
		&owner, &perms, &rec.CreatedAt, &rec.CreatedByUserID, &rec.RevokedAt); err != nil {
		return nil, err
	}
	rec.Owner = owner != 0
	rec.permissionsRaw = perms
	if perms != "" && perms != "{}" {
		if err := json.Unmarshal([]byte(perms), &rec.Permissions); err != nil {
			return nil, fmt.Errorf("user %s permissions: %w", rec.UserID, err)
		}
	}
	return &rec, nil
}

func (r *UserRegistry) Create(displayName, role, createdByUserID string) (*UserRecord, error) {
	if role != RoleAdmin && role != RoleMember {
		return nil, fmt.Errorf("invalid role: %q", role)
	}
	if displayName == "" {
		return nil, fmt.Errorf("display_name required")
	}
	if !ValidDisplayName(displayName) {
		return nil, ErrDisplayNameTooLong
	}
	id, err := newUserID()
	if err != nil {
		return nil, err
	}
	rec := &UserRecord{
		UserID:          id,
		DisplayName:     displayName,
		Role:            role,
		Status:          UserStatusActive,
		CreatedAt:       time.Now().UTC().Format(time.RFC3339),
		CreatedByUserID: createdByUserID,
	}
	_, err = r.db.Exec(`INSERT INTO users (user_id, display_name, role, status, created_at, created_by)
		VALUES (?, ?, ?, 'active', ?, ?)`,
		rec.UserID, rec.DisplayName, rec.Role, rec.CreatedAt, rec.CreatedByUserID)
	if err != nil {
		return nil, err
	}
	return rec, nil
}

func (r *UserRegistry) FindByID(userID string) (*UserRecord, error) {
	rec, err := scanUser(r.db.QueryRow("SELECT "+userCols+" FROM users WHERE user_id=?", userID))
	if err == sql.ErrNoRows {
		return nil, nil
	}
	return rec, err
}

func (r *UserRegistry) FindByDisplayName(name string) (*UserRecord, error) {
	rows, err := r.db.Query("SELECT "+userCols+" FROM users WHERE lower(display_name)=lower(?) AND status='active'", name)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var matches []*UserRecord
	for rows.Next() {
		rec, err := scanUser(rows)
		if err != nil {
			return nil, err
		}
		matches = append(matches, rec)
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}
	if len(matches) == 0 {
		return nil, nil
	}
	if len(matches) > 1 {
		return nil, fmt.Errorf("ambiguous display name %q matches %d users", name, len(matches))
	}
	return matches[0], nil
}

func (r *UserRegistry) List() ([]UserRecord, error) {
	rows, err := r.db.Query("SELECT " + userCols + " FROM users ORDER BY created_at")
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []UserRecord
	for rows.Next() {
		rec, err := scanUser(rows)
		if err != nil {
			continue
		}
		out = append(out, *rec)
	}
	return out, rows.Err()
}

func (r *UserRegistry) updateOne(userID, query string, args ...any) error {
	res, err := r.db.Exec(query, args...)
	if err != nil {
		return err
	}
	if n, _ := res.RowsAffected(); n == 0 {
		return fmt.Errorf("user %q not found", userID)
	}
	return nil
}

func (r *UserRegistry) SetRole(userID, role string) error {
	if role != RoleAdmin && role != RoleMember {
		return fmt.Errorf("invalid role: %q", role)
	}
	return r.updateOne(userID, "UPDATE users SET role=? WHERE user_id=?", role, userID)
}

const activeAdminCount = "(SELECT count(*) FROM users WHERE status='active' AND role='admin')"

func (r *UserRegistry) SetRoleGuarded(userID, role string) (applied bool, err error) {
	if role != RoleAdmin && role != RoleMember {
		return false, fmt.Errorf("invalid role: %q", role)
	}
	if role == RoleAdmin {
		return true, r.SetRole(userID, role)
	}
	res, err := r.db.Exec(`UPDATE users SET role=? WHERE user_id=? AND owner=0 AND (
		role<>'admin' OR status<>'active' OR `+activeAdminCount+` > 1)`,
		role, userID)
	if err != nil {
		return false, err
	}
	if n, _ := res.RowsAffected(); n > 0 {
		return true, nil
	}
	u, err := r.FindByID(userID)
	if err != nil {
		return false, err
	}
	if u == nil {
		return false, fmt.Errorf("user %q not found", userID)
	}
	if u.Owner {
		return false, ErrOwnerImmutable
	}
	return false, nil
}

func (r *UserRegistry) SetDisplayName(userID, name string) error {
	if name == "" {
		return fmt.Errorf("display_name required")
	}
	if !ValidDisplayName(name) {
		return ErrDisplayNameTooLong
	}
	return r.updateOne(userID, "UPDATE users SET display_name=? WHERE user_id=?", name, userID)
}

func (r *UserRegistry) Revoke(userID string) error {
	var status string
	err := r.db.QueryRow("SELECT status FROM users WHERE user_id=?", userID).Scan(&status)
	if err == sql.ErrNoRows {
		return fmt.Errorf("user %q not found", userID)
	}
	if err != nil {
		return err
	}
	if status == UserStatusRevoked {
		return nil
	}
	return r.updateOne(userID, "UPDATE users SET status='revoked', revoked_at=? WHERE user_id=?",
		time.Now().UTC().Format(time.RFC3339), userID)
}

func (r *UserRegistry) RevokeGuarded(userID string) (applied bool, err error) {
	res, err := r.db.Exec(`UPDATE users SET status='revoked', revoked_at=?
		WHERE user_id=? AND status='active' AND owner=0 AND (
		role<>'admin' OR `+activeAdminCount+` > 1)`,
		time.Now().UTC().Format(time.RFC3339), userID)
	if err != nil {
		return false, err
	}
	if n, _ := res.RowsAffected(); n > 0 {
		return true, nil
	}
	u, err := r.FindByID(userID)
	if err != nil {
		return false, err
	}
	if u == nil {
		return false, fmt.Errorf("user %q not found", userID)
	}
	if u.Status == UserStatusRevoked {
		return true, nil
	}
	if u.Owner {
		return false, ErrOwnerImmutable
	}
	return false, nil
}

// The row stays so the id is never reused.
func (r *UserRegistry) ScrubPersonalData(userID string) error {
	_, err := r.db.Exec(
		"UPDATE users SET display_name='' WHERE user_id=? AND status='revoked'",
		userID)
	return err
}

func (r *UserRegistry) SetOwner(userID string, owner bool) error {
	v := 0
	if owner {
		v = 1
	}
	return r.updateOne(userID, "UPDATE users SET owner=? WHERE user_id=?", v, userID)
}

func (r *UserRegistry) TransferOwnership(fromID, toID string) error {
	if fromID == toID {
		return ErrSelfTransfer
	}
	tx, err := r.db.Begin()
	if err != nil {
		return err
	}
	defer tx.Rollback()

	var fromOwner int
	var fromStatus string
	switch err := tx.QueryRow("SELECT owner, status FROM users WHERE user_id=?", fromID).
		Scan(&fromOwner, &fromStatus); {
	case err == sql.ErrNoRows:
		return ErrUserNotFound
	case err != nil:
		return err
	}
	if fromOwner == 0 || fromStatus != UserStatusActive {
		return ErrNotOwner
	}
	var toStatus string
	switch err := tx.QueryRow("SELECT status FROM users WHERE user_id=?", toID).Scan(&toStatus); {
	case err == sql.ErrNoRows:
		return ErrUserNotFound
	case err != nil:
		return err
	}
	if toStatus != UserStatusActive {
		return ErrUserNotActive
	}
	if _, err := tx.Exec("UPDATE users SET owner=0 WHERE user_id=?", fromID); err != nil {
		return err
	}
	if _, err := tx.Exec("UPDATE users SET owner=1, role='admin' WHERE user_id=?", toID); err != nil {
		return err
	}
	var owners int
	if err := tx.QueryRow("SELECT count(*) FROM users WHERE owner=1").Scan(&owners); err != nil {
		return err
	}
	if owners != 1 {
		return fmt.Errorf("ownership transfer would leave %d owners", owners)
	}
	return tx.Commit()
}

func (r *UserRegistry) SetPermissions(userID string, perms PermissionSet) error {
	data, err := marshalPermissions(perms)
	if err != nil {
		return err
	}
	return r.updateOne(userID, "UPDATE users SET permissions=? WHERE user_id=?", data, userID)
}

func (r *UserRegistry) SetPermissionsGuarded(target *UserRecord, perms PermissionSet) (applied bool, err error) {
	data, err := marshalPermissions(perms)
	if err != nil {
		return false, err
	}
	expected := target.permissionsRaw
	if expected == "" {
		if expected, err = marshalPermissions(target.Permissions); err != nil {
			return false, err
		}
	}
	res, err := r.db.Exec("UPDATE users SET permissions=? WHERE user_id=? AND permissions=?",
		data, target.UserID, expected)
	if err != nil {
		return false, err
	}
	if n, _ := res.RowsAffected(); n > 0 {
		return true, nil
	}
	u, err := r.FindByID(target.UserID)
	if err != nil {
		return false, err
	}
	if u == nil {
		return false, fmt.Errorf("user %q not found", target.UserID)
	}
	return false, nil
}

func marshalPermissions(perms PermissionSet) (string, error) {
	if len(perms) == 0 {
		return "{}", nil
	}
	data, err := json.Marshal(perms)
	if err != nil {
		return "", err
	}
	return string(data), nil
}

func (r *UserRegistry) CountActiveAdmins() (int, error) {
	var n int
	err := r.db.QueryRow("SELECT " + activeAdminCount).Scan(&n)
	return n, err
}
