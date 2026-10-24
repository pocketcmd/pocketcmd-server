package server

import (
	"bytes"
	"encoding/json"
	"errors"
	"net/http"
	"regexp"
	"sort"

	"github.com/pocketcmd/pocketcmd-server/internal/authz"
	"github.com/pocketcmd/pocketcmd-server/internal/datasync"
	"github.com/pocketcmd/pocketcmd-server/internal/httperr"
	"github.com/pocketcmd/pocketcmd-server/internal/pki"
)

var validVaultID = regexp.MustCompile(`^[a-zA-Z0-9_-]{1,64}$`)

func (s *Server) RegisterVaultRoutes(store *datasync.SyncStore) {
	s.requireSecurityServices("RegisterVaultRoutes")
	store.VaultAdminOverride = func(userID string) bool {
		u, err := s.userRegistry.FindByID(userID)
		if err != nil || u == nil {
			return false
		}
		return authz.IsOwner(u)
	}
	s.installDeviceHooks(store)
	s.vaultRevoker = store
	s.handle("GET /api/vault/pubkeys", s.memberRoute(s.handleVaultPubkeys(store)))
	s.handle("GET /api/vault/members", s.memberRoute(s.handleVaultMembers(store)))
	s.handle("POST /api/vault/create", s.memberRoute(s.handleVaultCreate(store)))
	s.handle("POST /api/vault/grant", s.memberRoute(s.handleVaultGrant(store)))
	s.handle("POST /api/vault/revoke", s.memberRoute(s.handleVaultRevoke(store)))
}

func (s *Server) auditVault(event, callerID, vaultID, targetUser, level string) {
	s.auditLogger.Info(event,
		"user_id", callerID, "vault_id", vaultID,
		"target_user", targetUser, "level", level)
}

type deviceEntry struct {
	DeviceID    string          `json:"device_id"`
	UserID      string          `json:"user_id"`
	DisplayName string          `json:"display_name"`
	Label       string          `json:"label,omitempty"`
	DvkPub      string          `json:"dvk_pub"`
	Kind        string          `json:"kind,omitempty"` // "p256" or "x25519"
	MTLSSPKI    string          `json:"mtls_spki,omitempty"`
	Sig         string          `json:"sig,omitempty"` // mTLS signature over deviceId, SPKI, DVK, kind
	Backing     string          `json:"backing,omitempty"`
	Attestation json.RawMessage `json:"attestation,omitempty"`
	CreatedAt   int64           `json:"created_at,omitempty"`
	UpdatedAt   int64           `json:"updated_at"`
}

func (s *Server) handleVaultPubkeys(store *datasync.SyncStore) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		users, err := s.userRegistry.List()
		if err != nil {
			httperr.JSON(w, http.StatusInternalServerError, "store_error")
			return
		}
		active := map[string]string{}
		for _, u := range users {
			if u.Status == pki.UserStatusActive {
				active[u.UserID] = u.DisplayName
			}
		}
		httperr.WriteJSON(w, http.StatusOK, map[string]any{
			"devices": s.deviceDirectory(store, active),
		})
	}
}

func (s *Server) deviceDirectory(store *datasync.SyncStore, active map[string]string) []deviceEntry {
	recs, err := store.RecordsByType("device_vault_key")
	if err != nil || s.deviceRegistry == nil {
		return []deviceEntry{}
	}
	out := make([]deviceEntry, 0, len(recs))
	for _, rec := range recs {
		if rec.Deleted {
			continue
		}
		dev, err := s.deviceRegistry.FindByID(rec.ID)
		if err != nil || dev == nil || dev.Status != pki.DeviceStatusActive {
			continue
		}
		if rec.UserID != "" && rec.UserID != dev.UserID {
			continue
		}
		name, ok := active[dev.UserID]
		if !ok {
			continue
		}
		var d struct {
			DvkPub      string          `json:"dvk_pub"`
			Kind        string          `json:"kind"`
			MTLSSPKI    string          `json:"mtls_spki"`
			Sig         string          `json:"sig"`
			Backing     string          `json:"backing"`
			Attestation json.RawMessage `json:"attestation"`
			Label       string          `json:"label"`
			CreatedAt   int64           `json:"created_at"`
		}
		if json.Unmarshal(rec.Data, &d) != nil || d.DvkPub == "" {
			continue
		}
		label := dev.DeviceLabel
		if label == "" {
			label = dev.DeviceName
		}
		if label == "" {
			label = d.Label
		}
		out = append(out, deviceEntry{
			DeviceID:    rec.ID,
			UserID:      dev.UserID,
			DisplayName: name,
			Label:       label,
			DvkPub:      d.DvkPub,
			Kind:        d.Kind,
			MTLSSPKI:    d.MTLSSPKI,
			Sig:         d.Sig,
			Backing:     d.Backing,
			Attestation: attestationObject(d.Attestation),
			CreatedAt:   d.CreatedAt,
			UpdatedAt:   rec.UpdatedAt,
		})
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].UserID != out[j].UserID {
			return out[i].UserID < out[j].UserID
		}
		return out[i].DeviceID < out[j].DeviceID
	})
	return out
}

func attestationObject(raw json.RawMessage) json.RawMessage {
	trimmed := bytes.TrimSpace(raw)
	if len(trimmed) == 0 || trimmed[0] != '{' {
		return nil
	}
	return json.RawMessage(trimmed)
}

func (s *Server) handleVaultCreate(store *datasync.SyncStore) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		caller := callerFrom(r)
		if !authz.IsOwner(caller) && caller.Role != pki.RoleAdmin {
			httperr.JSON(w, http.StatusForbidden, "owner_or_admin_required")
			return
		}
		var req struct {
			VaultID string `json:"vault_id"`
		}
		if json.NewDecoder(r.Body).Decode(&req) != nil ||
			!validVaultID.MatchString(req.VaultID) ||
			req.VaultID == datasync.PersonalVaultID {
			httperr.JSON(w, http.StatusBadRequest, "invalid_vault_id")
			return
		}
		created, err := store.CreateVault(req.VaultID, caller.UserID)
		if err != nil {
			httperr.JSON(w, http.StatusInternalServerError, "store_error")
			return
		}
		if !created {
			httperr.JSON(w, http.StatusConflict, "vault_exists")
			return
		}
		s.auditVault("vault_created", caller.UserID, req.VaultID, caller.UserID, "manage")
		httperr.WriteJSON(w, http.StatusOK, map[string]string{"vault_id": req.VaultID})
	}
}

func (s *Server) handleVaultGrant(store *datasync.SyncStore) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		caller := callerFrom(r)
		var req struct {
			VaultID string `json:"vault_id"`
			UserID  string `json:"user_id"`
			Level   string `json:"level"`
		}
		level := 0
		if json.NewDecoder(r.Body).Decode(&req) == nil {
			level = datasync.LevelFromString(req.Level)
		}
		if !validVaultID.MatchString(req.VaultID) || req.UserID == "" ||
			level == datasync.LevelNone || req.VaultID == datasync.PersonalVaultID {
			httperr.JSON(w, http.StatusBadRequest, "invalid_request")
			return
		}
		if store.VaultLevel(caller.UserID, req.VaultID) < datasync.LevelManage {
			httperr.JSON(w, http.StatusForbidden, "manage_required")
			return
		}
		target, err := s.userRegistry.FindByID(req.UserID)
		if err != nil || target == nil || target.Status != pki.UserStatusActive {
			httperr.JSON(w, http.StatusNotFound, "user_not_found")
			return
		}
		switch err := store.GrantVaultGuarded(req.VaultID, req.UserID, level); {
		case err == nil:
		case errors.Is(err, datasync.ErrLastManager):
			httperr.JSON(w, http.StatusConflict, "last_manager")
			return
		default:
			httperr.JSON(w, http.StatusInternalServerError, "store_error")
			return
		}
		s.auditVault("vault_granted", caller.UserID, req.VaultID, req.UserID, req.Level)
		w.WriteHeader(http.StatusNoContent)
	}
}

func (s *Server) handleVaultRevoke(store *datasync.SyncStore) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		caller := callerFrom(r)
		var req struct {
			VaultID string `json:"vault_id"`
			UserID  string `json:"user_id"`
		}
		if json.NewDecoder(r.Body).Decode(&req) != nil ||
			!validVaultID.MatchString(req.VaultID) || req.UserID == "" {
			httperr.JSON(w, http.StatusBadRequest, "invalid_request")
			return
		}
		if store.VaultLevel(caller.UserID, req.VaultID) < datasync.LevelManage {
			httperr.JSON(w, http.StatusForbidden, "manage_required")
			return
		}
		// Owner access is a role, not a grant; an ACL revoke could not cut it.
		if target, err := s.userRegistry.FindByID(req.UserID); err == nil && authz.IsOwner(target) {
			httperr.JSON(w, http.StatusConflict, "cannot_revoke_owner")
			return
		}
		switch err := store.RevokeVaultGuarded(req.VaultID, req.UserID); {
		case err == nil:
		case errors.Is(err, datasync.ErrLastManager):
			httperr.JSON(w, http.StatusConflict, "last_manager")
			return
		default:
			httperr.JSON(w, http.StatusInternalServerError, "store_error")
			return
		}
		s.auditVault("vault_revoked", caller.UserID, req.VaultID, req.UserID, "")
		w.WriteHeader(http.StatusNoContent)
	}
}

func (s *Server) handleVaultMembers(store *datasync.SyncStore) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		caller := callerFrom(r)
		vaultID := r.URL.Query().Get("vault_id")
		if !validVaultID.MatchString(vaultID) {
			httperr.JSON(w, http.StatusBadRequest, "invalid_vault_id")
			return
		}
		if store.VaultLevel(caller.UserID, vaultID) < datasync.LevelView {
			httperr.JSON(w, http.StatusForbidden, "forbidden")
			return
		}
		members, err := store.VaultMembers(vaultID)
		if err != nil {
			httperr.JSON(w, http.StatusInternalServerError, "store_error")
			return
		}
		if members == nil {
			members = []datasync.VaultMember{}
		}
		httperr.WriteJSON(w, http.StatusOK, map[string]any{"members": members})
	}
}
