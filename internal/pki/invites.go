package pki

import (
	"crypto/rand"
	"database/sql"
	"encoding/base32"
	"errors"
	"fmt"
	"regexp"
	"strings"
	"time"
	"unicode/utf8"
)

var (
	ErrInviteNotFound        = errors.New("invite not found")
	ErrInviteNotRedeemable   = errors.New("invite not redeemable")
	ErrAmbiguousInvitePrefix = errors.New("ambiguous invite prefix")
	ErrLabelTooLong          = errors.New("invite label too long")
)

const MaxInviteLabelLen = 128

func ValidInviteLabel(label string) bool {
	return utf8.RuneCountInString(label) <= MaxInviteLabelLen
}

type InviteRecord struct {
	Code               string `json:"code"`
	Role               string `json:"role"`
	TargetUserID       string `json:"target_user_id,omitempty"`
	PinnedFingerprint  string `json:"pinned_fingerprint,omitempty"`
	CreatedByUserID    string `json:"created_by_user_id,omitempty"`
	CreatedAt          string `json:"created_at"`
	ExpiresAt          string `json:"expires_at"`
	Label              string `json:"label,omitempty"`
	ConsumedAt         string `json:"consumed_at,omitempty"`
	ConsumedByDeviceID string `json:"consumed_by_device_id,omitempty"`
	ExpiredAt          string `json:"expired_at,omitempty"`
	RevokedAt          string `json:"revoked_at,omitempty"`
	RevokedByUserID    string `json:"revoked_by_user_id,omitempty"`
}

func (i *InviteRecord) IsActive(now time.Time) bool {
	if i.ConsumedAt != "" || i.RevokedAt != "" || i.ExpiredAt != "" {
		return false
	}
	t, err := time.Parse(time.RFC3339, i.ExpiresAt)
	if err != nil || !t.After(now) {
		return false
	}
	return true
}

type CreateInviteParams struct {
	Role              string
	ExpiresIn         time.Duration
	TargetUserID      string
	PinnedFingerprint string
	Label             string
	CreatedByUID      string
}

type InviteStore struct {
	db *sql.DB
}

func NewInviteStore(db *sql.DB) *InviteStore {
	return &InviteStore{db: db}
}

func newInviteCode() (string, error) {
	buf := make([]byte, 10)
	if _, err := rand.Read(buf); err != nil {
		return "", err
	}
	code := strings.ToLower(base32.StdEncoding.WithPadding(base32.NoPadding).EncodeToString(buf))
	return code[:16], nil
}

const inviteCols = `code, role, label, target_user_id, pinned_fingerprint,
	created_by, created_at, expires_at, consumed_at, consumed_by_device_id,
	expired_at, revoked_at, revoked_by`

func scanInvite(row interface{ Scan(...any) error }) (*InviteRecord, error) {
	var rec InviteRecord
	if err := row.Scan(&rec.Code, &rec.Role, &rec.Label, &rec.TargetUserID,
		&rec.PinnedFingerprint, &rec.CreatedByUserID, &rec.CreatedAt, &rec.ExpiresAt,
		&rec.ConsumedAt, &rec.ConsumedByDeviceID, &rec.ExpiredAt,
		&rec.RevokedAt, &rec.RevokedByUserID); err != nil {
		return nil, err
	}
	return &rec, nil
}

func (s *InviteStore) Create(p CreateInviteParams) (*InviteRecord, error) {
	if p.Role != RoleAdmin && p.Role != RoleMember {
		return nil, fmt.Errorf("invalid role: %q", p.Role)
	}
	if !ValidInviteLabel(p.Label) {
		return nil, ErrLabelTooLong
	}
	code, err := newInviteCode()
	if err != nil {
		return nil, err
	}
	now := time.Now().UTC()
	rec := &InviteRecord{
		Code:              code,
		Role:              p.Role,
		TargetUserID:      p.TargetUserID,
		PinnedFingerprint: strings.ToLower(p.PinnedFingerprint),
		CreatedByUserID:   p.CreatedByUID,
		CreatedAt:         now.Format(time.RFC3339),
		ExpiresAt:         now.Add(p.ExpiresIn).Format(time.RFC3339),
		Label:             p.Label,
	}
	_, err = s.db.Exec(`INSERT INTO invites
		(code, role, label, target_user_id, pinned_fingerprint, created_by, created_at, expires_at)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?)`,
		rec.Code, rec.Role, rec.Label, rec.TargetUserID, rec.PinnedFingerprint,
		rec.CreatedByUserID, rec.CreatedAt, rec.ExpiresAt)
	if err != nil {
		return nil, err
	}
	return rec, nil
}

func (s *InviteStore) FindByCode(code string) (*InviteRecord, error) {
	rec, err := scanInvite(s.db.QueryRow(
		"SELECT "+inviteCols+" FROM invites WHERE code=?", strings.ToLower(code)))
	if err == sql.ErrNoRows {
		return nil, nil
	}
	return rec, err
}

// A prefix is checked against the code alphabet before any LIKE query runs.
var (
	storePrefix        = regexp.MustCompile(`^[a-z2-7]{1,16}$`)
	validInvitePrefix  = regexp.MustCompile(`^[a-z2-7]{8,16}$`)
	likeWildcardEscape = strings.NewReplacer(`\`, `\\`, `%`, `\%`, `_`, `\_`)
)

const InviteCodePrefixLen = 8

func InviteCodePrefix(code string) string {
	if len(code) >= InviteCodePrefixLen {
		return code[:InviteCodePrefixLen]
	}
	return code
}

var ErrInvalidInvitePrefix = errors.New("invalid invite code prefix")

func ValidInvitePrefix(prefix string) bool {
	return validInvitePrefix.MatchString(strings.ToLower(prefix))
}

func (s *InviteStore) FindByPrefix(prefix string) (*InviteRecord, error) {
	prefix = strings.ToLower(prefix)
	if !storePrefix.MatchString(prefix) {
		return nil, ErrInvalidInvitePrefix
	}
	rows, err := s.db.Query("SELECT "+inviteCols+` FROM invites WHERE code LIKE ? || '%' ESCAPE '\'`,
		likeWildcardEscape.Replace(prefix))
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var matches []*InviteRecord
	for rows.Next() {
		rec, err := scanInvite(rows)
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
		return nil, fmt.Errorf("%w: %q matches %d invites", ErrAmbiguousInvitePrefix, prefix, len(matches))
	}
	return matches[0], nil
}

func (s *InviteStore) listAll() ([]InviteRecord, error) {
	rows, err := s.db.Query("SELECT " + inviteCols + " FROM invites ORDER BY created_at")
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []InviteRecord
	for rows.Next() {
		rec, err := scanInvite(rows)
		if err != nil {
			continue
		}
		out = append(out, *rec)
	}
	return out, rows.Err()
}

func (s *InviteStore) ListActive() ([]InviteRecord, error) {
	all, err := s.listAll()
	if err != nil {
		return nil, err
	}
	now := time.Now().UTC()
	var out []InviteRecord
	for _, i := range all {
		if i.IsActive(now) {
			out = append(out, i)
		}
	}
	return out, nil
}

func (s *InviteStore) MarkConsumed(code, deviceID string) error {
	now := time.Now().UTC().Format(time.RFC3339)
	res, err := s.db.Exec(`UPDATE invites SET consumed_at=?, consumed_by_device_id=?
		WHERE code=? AND consumed_at='' AND revoked_at='' AND expired_at='' AND expires_at > ?`,
		now, deviceID, strings.ToLower(code), now)
	if err != nil {
		return err
	}
	if n, _ := res.RowsAffected(); n == 0 {
		rec, err := s.FindByCode(code)
		if err != nil {
			return err
		}
		if rec == nil {
			return ErrInviteNotFound
		}
		return ErrInviteNotRedeemable
	}
	return nil
}

func (s *InviteStore) UnmarkConsumed(code, deviceID string) error {
	_, err := s.db.Exec(`UPDATE invites SET consumed_at='', consumed_by_device_id=''
		WHERE code=? AND consumed_at<>'' AND consumed_by_device_id=?`,
		strings.ToLower(code), deviceID)
	return err
}

func (s *InviteStore) Revoke(code, byUserID string) error {
	rec, err := s.FindByCode(code)
	if err != nil {
		return err
	}
	if rec == nil {
		return fmt.Errorf("invite not found")
	}
	if rec.ConsumedAt != "" {
		return fmt.Errorf("cannot revoke consumed invite")
	}
	if rec.ExpiredAt != "" {
		return fmt.Errorf("cannot revoke expired invite")
	}
	if rec.RevokedAt != "" {
		return nil
	}
	_, err = s.db.Exec(`UPDATE invites SET revoked_at=?, revoked_by=?
		WHERE code=? AND revoked_at=''`,
		time.Now().UTC().Format(time.RFC3339), byUserID, rec.Code)
	return err
}

func (s *InviteStore) Sweep(now time.Time) {
	_, _ = s.db.Exec(`UPDATE invites SET expired_at=?
		WHERE expired_at='' AND consumed_at='' AND revoked_at='' AND expires_at <= ?`,
		now.UTC().Format(time.RFC3339), now.UTC().Format(time.RFC3339))
}

func (s *InviteStore) Prune(now time.Time, age time.Duration) (int64, error) {
	cutoff := now.Add(-age).UTC().Format(time.RFC3339)
	res, err := s.db.Exec(`DELETE FROM invites WHERE
		(consumed_at <> '' AND consumed_at < ?) OR
		(expired_at  <> '' AND expired_at  < ?) OR
		(revoked_at  <> '' AND revoked_at  < ?)`, cutoff, cutoff, cutoff)
	if err != nil {
		return 0, err
	}
	return res.RowsAffected()
}
