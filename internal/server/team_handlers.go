package server

import (
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"time"

	"github.com/pocketcmd/pocketcmd-server/internal/authz"
	"github.com/pocketcmd/pocketcmd-server/internal/httperr"
	"github.com/pocketcmd/pocketcmd-server/internal/pki"
)

type teamHandlers struct {
	srv     *Server
	users   *pki.UserRegistry
	devices *pki.DeviceRegistry
	invites *pki.InviteStore
}

func (t *teamHandlers) audit() *slog.Logger { return t.srv.auditLogger }

func (t *teamHandlers) scrubLogs(userID string) {
	if lp, ok := t.srv.logSource.(interface{ PurgeUser(string) }); ok {
		lp.PurgeUser(userID)
	}
}

// Pre-check only; the race-proof guard is SetRoleGuarded.
func wouldRemoveLastAdmin(users *pki.UserRegistry, targetID, newRole string) (bool, error) {
	n, err := users.CountActiveAdmins()
	if err != nil {
		return false, err
	}
	target, err := users.FindByID(targetID)
	if err != nil {
		return false, err
	}
	if target == nil || target.Status != pki.UserStatusActive {
		return false, nil
	}
	if target.Role != pki.RoleAdmin {
		return false, nil
	}
	if newRole == pki.RoleAdmin {
		return false, nil
	}
	return n <= 1, nil
}

const maxInviteLifetimeSeconds = 30 * 24 * 3600

func (t *teamHandlers) handleCreateInvite(w http.ResponseWriter, r *http.Request) {
	var body struct {
		Role             string `json:"role"`
		ExpiresInSeconds int    `json:"expires_in_seconds"`
		TargetUserID     string `json:"target_user_id,omitempty"`
		PinnedFP         string `json:"pinned_fingerprint,omitempty"`
		Label            string `json:"label,omitempty"`
	}
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		httperr.JSON(w, http.StatusBadRequest, "invalid_body")
		return
	}
	if body.ExpiresInSeconds <= 0 {
		body.ExpiresInSeconds = 86400
	}
	if body.ExpiresInSeconds > maxInviteLifetimeSeconds {
		body.ExpiresInSeconds = maxInviteLifetimeSeconds
	}
	if !pki.ValidInviteLabel(body.Label) {
		httperr.JSON(w, http.StatusBadRequest, "label_too_long")
		return
	}
	caller := callerFrom(r)
	callerID := callerIDFrom(r)
	if body.TargetUserID != "" {
		// Authorize before the existence check so the 404 cannot probe user ids.
		if body.TargetUserID == callerID {
			if !authz.Allowed(caller, authz.PermInvitesDevice) {
				httperr.JSON(w, http.StatusForbidden, "forbidden")
				return
			}
		} else if !authz.IsOwner(caller) {
			httperr.JSON(w, http.StatusForbidden, "owner_required")
			return
		}
		target, err := t.users.FindByID(body.TargetUserID)
		if err != nil {
			httperr.JSON(w, http.StatusInternalServerError, "store_error")
			return
		}
		if target == nil || target.Status != pki.UserStatusActive {
			httperr.JSON(w, http.StatusNotFound, "target_user_not_found")
			return
		}
		body.Role = target.Role
	} else {
		if !authz.Allowed(caller, authz.PermInvitesManage) {
			httperr.JSON(w, http.StatusForbidden, "forbidden")
			return
		}
		if body.Role == pki.RoleAdmin && !authz.IsOwner(caller) {
			httperr.JSON(w, http.StatusForbidden, "owner_required")
			return
		}
	}
	creator := callerID
	inv, err := t.invites.Create(pki.CreateInviteParams{
		Role:              body.Role,
		ExpiresIn:         time.Duration(body.ExpiresInSeconds) * time.Second,
		TargetUserID:      body.TargetUserID,
		PinnedFingerprint: body.PinnedFP,
		Label:             body.Label,
		CreatedByUID:      creator,
	})
	if err != nil {
		httperr.JSON(w, http.StatusBadRequest, "invalid_invite_params")
		return
	}
	t.audit().Info("invite_created",
		"invite_id", pki.InviteCodePrefix(inv.Code),
		"role", inv.Role,
		"expires_at", inv.ExpiresAt,
		"created_by", creator,
		"target_user_id", inv.TargetUserID,
		"has_pin", inv.PinnedFingerprint != "",
	)
	host := t.srv.advertisedHost
	if host == "" {
		host = t.srv.cfg.Host
	}
	qr := fmt.Sprintf(
		"pocketcmd://invite?host=%s&port=%d&code=%s#%s",
		host, t.srv.cfg.Port, inv.Code, t.srv.pairingFingerprint,
	)
	httperr.WriteJSON(w, http.StatusOK, map[string]string{
		"code":       inv.Code,
		"expires_at": inv.ExpiresAt,
		"qr_url":     qr,
	})
}

func (t *teamHandlers) handleListInvites(w http.ResponseWriter, r *http.Request) {
	callerID := callerIDFrom(r)
	active, err := t.invites.ListActive()
	if err != nil {
		httperr.JSON(w, http.StatusInternalServerError, "store_error")
		return
	}
	if !authz.Allowed(callerFrom(r), authz.PermInvitesManage) {
		own := active[:0]
		for _, inv := range active {
			if inv.CreatedByUserID == callerID {
				own = append(own, inv)
			}
		}
		active = own
	}
	names := map[string]string{}
	if users, err := t.users.List(); err == nil {
		for _, u := range users {
			names[u.UserID] = u.DisplayName
		}
	}
	type inviteSummary struct {
		Code          string `json:"code,omitempty"`
		CodePrefix    string `json:"code_prefix"`
		Role          string `json:"role"`
		ExpiresAt     string `json:"expires_at"`
		TargetUserID  string `json:"target_user_id,omitempty"`
		Label         string `json:"label,omitempty"`
		HasPin        bool   `json:"has_pin"`
		CreatedBy     string `json:"created_by,omitempty"`
		CreatedByName string `json:"created_by_name,omitempty"`
	}
	out := make([]inviteSummary, 0, len(active))
	for _, inv := range active {
		entry := inviteSummary{
			CodePrefix:    pki.InviteCodePrefix(inv.Code),
			Role:          inv.Role,
			ExpiresAt:     inv.ExpiresAt,
			TargetUserID:  inv.TargetUserID,
			Label:         inv.Label,
			HasPin:        inv.PinnedFingerprint != "",
			CreatedBy:     inv.CreatedByUserID,
			CreatedByName: names[inv.CreatedByUserID],
		}
		// The code is a bearer credential; only its creator sees it in full.
		if inv.CreatedByUserID == callerID {
			entry.Code = inv.Code
		}
		out = append(out, entry)
	}
	httperr.WriteJSON(w, http.StatusOK, out)
}

func (t *teamHandlers) handleRevokeInvite(w http.ResponseWriter, r *http.Request) {
	code := r.PathValue("code")
	caller := callerIDFrom(r)

	if !pki.ValidInvitePrefix(code) {
		httperr.JSON(w, http.StatusBadRequest, "invalid_code")
		return
	}
	inv, err := t.invites.FindByCode(code)
	if err != nil {
		httperr.JSON(w, http.StatusInternalServerError, "store_error")
		return
	}
	if inv == nil {
		inv, err = t.invites.FindByPrefix(code)
		if errors.Is(err, pki.ErrAmbiguousInvitePrefix) {
			httperr.JSON(w, http.StatusConflict, "ambiguous_prefix")
			return
		}
		if err != nil {
			httperr.JSON(w, http.StatusInternalServerError, "store_error")
			return
		}
	}
	if inv == nil {
		httperr.JSON(w, http.StatusNotFound, "invite_not_found")
		return
	}
	if !authz.Allowed(callerFrom(r), authz.PermInvitesManage) && inv.CreatedByUserID != caller {
		httperr.JSON(w, http.StatusForbidden, "forbidden")
		return
	}
	if inv.ConsumedAt != "" {
		httperr.JSON(w, http.StatusConflict, "invite_already_consumed")
		return
	}
	if err := t.invites.Revoke(inv.Code, caller); err != nil {
		httperr.JSON(w, http.StatusInternalServerError, "store_error")
		return
	}
	t.audit().Info("invite_revoked",
		"invite_id", pki.InviteCodePrefix(inv.Code),
		"revoked_by", caller,
	)
	httperr.WriteJSON(w, http.StatusOK, map[string]string{"status": "ok"})
}

func (t *teamHandlers) handleListUsers(w http.ResponseWriter, r *http.Request) {
	all, err := t.users.List()
	if err != nil {
		httperr.JSON(w, http.StatusInternalServerError, "store_error")
		return
	}
	type userSummary struct {
		UserID      string            `json:"user_id"`
		DisplayName string            `json:"display_name"`
		Role        string            `json:"role"`
		Owner       bool              `json:"owner,omitempty"`
		DeviceCount int               `json:"device_count"`
		Permissions pki.PermissionSet `json:"permissions,omitempty"`
	}
	caller := callerFrom(r)
	callerID := callerIDFrom(r)
	activeDevices := map[string]int{}
	if devices, err := t.devices.List(); err == nil {
		for _, d := range devices {
			if d.Status == pki.DeviceStatusActive {
				activeDevices[d.UserID]++
			}
		}
	}
	out := make([]userSummary, 0)
	for _, u := range all {
		if u.Status != pki.UserStatusActive {
			continue
		}
		active := activeDevices[u.UserID]
		entry := userSummary{
			UserID:      u.UserID,
			DisplayName: u.DisplayName,
			Role:        u.Role,
			Owner:       u.Owner,
			DeviceCount: active,
		}
		if caller.Role == pki.RoleAdmin || callerID == u.UserID {
			entry.Permissions = u.Permissions
		}
		out = append(out, entry)
	}
	httperr.WriteJSON(w, http.StatusOK, out)
}

type apiError struct {
	status int
	code   string
}

func fail(status int, code string) *apiError { return &apiError{status: status, code: code} }

func (e *apiError) write(w http.ResponseWriter) { httperr.JSON(w, e.status, e.code) }

type userPatch struct {
	Role        *string            `json:"role"`
	DisplayName *string            `json:"display_name"`
	Permissions *pki.PermissionSet `json:"permissions"`
}

func (t *teamHandlers) handlePatchUser(w http.ResponseWriter, r *http.Request) {
	targetID := r.PathValue("id")
	callerID := callerIDFrom(r)
	caller := callerFrom(r)

	var body userPatch
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		httperr.JSON(w, http.StatusBadRequest, "invalid_body")
		return
	}
	if body.Role == nil && body.DisplayName == nil && body.Permissions == nil {
		httperr.JSON(w, http.StatusBadRequest, "no_fields")
		return
	}

	target, err := t.users.FindByID(targetID)
	if err != nil {
		httperr.JSON(w, http.StatusInternalServerError, "store_error")
		return
	}
	if target == nil {
		httperr.JSON(w, http.StatusNotFound, "user_not_found")
		return
	}

	if e := t.validateUserPatch(caller, callerID, target, &body); e != nil {
		e.write(w)
		return
	}
	if e := t.applyUserPatch(target, body, callerID); e != nil {
		e.write(w)
		return
	}
	httperr.WriteJSON(w, http.StatusOK, map[string]string{"status": "ok"})
}

func (t *teamHandlers) validateUserPatch(caller *pki.UserRecord, callerID string, target *pki.UserRecord, body *userPatch) *apiError {
	if body.DisplayName != nil {
		allowed := callerID == target.UserID
		if !allowed && target.Role == pki.RoleAdmin {
			allowed = authz.IsOwner(caller)
		} else if !allowed {
			allowed = authz.Allowed(caller, authz.PermUsersManage)
		}
		if !allowed {
			return fail(http.StatusForbidden, "forbidden")
		}
		if *body.DisplayName == "" {
			return fail(http.StatusBadRequest, "display_name_required")
		}
		if !pki.ValidDisplayName(*body.DisplayName) {
			return fail(http.StatusBadRequest, "display_name_too_long")
		}
	}

	if body.Role != nil {
		if !authz.IsOwner(caller) {
			return fail(http.StatusForbidden, "owner_required")
		}
		if target.Owner {
			return fail(http.StatusConflict, "owner_immutable")
		}
		if *body.Role != pki.RoleAdmin && *body.Role != pki.RoleMember {
			return fail(http.StatusBadRequest, "invalid_role")
		}
		isLast, err := wouldRemoveLastAdmin(t.users, target.UserID, *body.Role)
		if err != nil {
			return fail(http.StatusInternalServerError, "store_error")
		}
		if isLast {
			return fail(http.StatusConflict, "last_admin")
		}
	}

	if body.Permissions != nil {
		effectiveRole := target.Role
		if body.Role != nil {
			effectiveRole = *body.Role
		}
		perms, e := resolvePermissionPatch(caller, target, effectiveRole, *body.Permissions)
		if e != nil {
			return e
		}
		body.Permissions = &perms
	}
	return nil
}

// Owner-granted keys are written only by the owner; for other callers an
// omitted or resent owner-granted key keeps its stored value.
func resolvePermissionPatch(caller, target *pki.UserRecord, effectiveRole string, req pki.PermissionSet) (pki.PermissionSet, *apiError) {
	if caller.Role != pki.RoleAdmin {
		return nil, fail(http.StatusForbidden, "forbidden")
	}
	if err := authz.ValidatePermissionSet(req); err != nil {
		return nil, fail(http.StatusBadRequest, "invalid_permissions")
	}
	if target.Owner {
		return nil, fail(http.StatusConflict, "owner_immutable")
	}
	owner := authz.IsOwner(caller)
	for k, g := range req {
		if authz.OwnerGrantedPermissions[k] && g.Granted != target.Permissions[k].Granted && !owner {
			return nil, fail(http.StatusForbidden, "owner_required")
		}
	}

	var out pki.PermissionSet
	if effectiveRole == pki.RoleMember {
		out = make(pki.PermissionSet, len(req)+len(authz.OwnerGrantedPermissions))
	} else {
		if !owner {
			return nil, fail(http.StatusForbidden, "owner_required")
		}
		for k := range req {
			if !authz.OwnerGrantedPermissions[k] {
				return nil, fail(http.StatusBadRequest, "target_not_member")
			}
		}
		out = make(pki.PermissionSet, len(target.Permissions)+len(req))
		for k, g := range target.Permissions {
			out[k] = g
		}
	}
	for k, g := range req {
		if authz.OwnerGrantedPermissions[k] && !owner {
			if stored, ok := target.Permissions[k]; ok {
				out[k] = stored
			} else {
				delete(out, k)
			}
			continue
		}
		out[k] = g
	}
	for k := range authz.OwnerGrantedPermissions {
		if _, sent := req[k]; sent {
			continue
		}
		if owner {
			delete(out, k)
			continue
		}
		if g, ok := target.Permissions[k]; ok {
			out[k] = g
		}
	}
	return out, nil
}

func (t *teamHandlers) applyUserPatch(target *pki.UserRecord, body userPatch, callerID string) *apiError {
	targetID := target.UserID
	if body.DisplayName != nil {
		if err := t.users.SetDisplayName(targetID, *body.DisplayName); err != nil {
			return fail(http.StatusInternalServerError, "store_error")
		}
		t.audit().Info("user_renamed",
			"user_id", targetID,
			"old_name", target.DisplayName,
			"new_name", *body.DisplayName,
			"changed_by", callerID,
		)
	}

	if body.Role != nil {
		applied, err := t.users.SetRoleGuarded(targetID, *body.Role)
		if errors.Is(err, pki.ErrOwnerImmutable) {
			return fail(http.StatusConflict, "owner_immutable")
		}
		if err != nil {
			return fail(http.StatusInternalServerError, "store_error")
		}
		if !applied {
			return fail(http.StatusConflict, "last_admin")
		}
		t.audit().Info("role_changed",
			"user_id", targetID,
			"from", target.Role,
			"to", *body.Role,
			"changed_by", callerID,
		)
	}

	if body.Permissions != nil {
		applied, err := t.users.SetPermissionsGuarded(target, *body.Permissions)
		if err != nil {
			return fail(http.StatusInternalServerError, "store_error")
		}
		if !applied {
			return fail(http.StatusConflict, "permissions_changed")
		}
		granted := make([]string, 0, len(*body.Permissions))
		for k, g := range *body.Permissions {
			if g.Granted {
				granted = append(granted, k)
			}
		}
		t.audit().Info("permission_changed",
			"user_id", targetID,
			"granted", granted,
			"changed_by", callerID,
		)
	}
	return nil
}

func (t *teamHandlers) handleTransferOwnership(w http.ResponseWriter, r *http.Request) {
	targetID := r.PathValue("id")
	callerID := callerIDFrom(r)
	if targetID == callerID {
		httperr.JSON(w, http.StatusBadRequest, "self_transfer")
		return
	}
	switch err := t.users.TransferOwnership(callerID, targetID); {
	case err == nil:
	case errors.Is(err, pki.ErrUserNotFound):
		httperr.JSON(w, http.StatusNotFound, "user_not_found")
		return
	case errors.Is(err, pki.ErrUserNotActive):
		httperr.JSON(w, http.StatusConflict, "target_not_active")
		return
	case errors.Is(err, pki.ErrNotOwner):
		// A concurrent transfer won between the route gate and the transaction.
		httperr.JSON(w, http.StatusForbidden, "owner_required")
		return
	default:
		httperr.JSON(w, http.StatusInternalServerError, "store_error")
		return
	}
	t.audit().Info("owner_transferred",
		"previous_owner", callerID,
		"new_owner", targetID,
	)
	httperr.WriteJSON(w, http.StatusOK, map[string]string{
		"status":         "ok",
		"new_owner":      targetID,
		"previous_owner": callerID,
	})
}

func (t *teamHandlers) handleDeleteUser(w http.ResponseWriter, r *http.Request) {
	targetID := r.PathValue("id")
	callerID := callerIDFrom(r)
	caller := callerFrom(r)
	purgeData := r.URL.Query().Get("purge_data") == "true"

	target, err := t.users.FindByID(targetID)
	if err != nil {
		httperr.JSON(w, http.StatusInternalServerError, "store_error")
		return
	}
	if target == nil {
		httperr.JSON(w, http.StatusNotFound, "user_not_found")
		return
	}
	if e := authorizeUserDelete(caller, callerID, target); e != nil {
		e.write(w)
		return
	}

	applied, err := t.users.RevokeGuarded(targetID)
	if errors.Is(err, pki.ErrOwnerImmutable) {
		httperr.JSON(w, http.StatusConflict, "owner_immutable")
		return
	}
	if err != nil {
		httperr.JSON(w, http.StatusInternalServerError, "store_error")
		return
	}
	if !applied {
		httperr.JSON(w, http.StatusConflict, "last_admin")
		return
	}

	devicesForUser, deviceFailures := t.revokeUserDevices(targetID, callerID, deviceIDFrom(r))
	t.revokeUserVaults(targetID, callerID)
	t.revokeUserInvites(targetID, callerID)

	var purgedRecords int64
	if purgeData {
		n, e := t.purgeUserData(targetID, callerID, devicesForUser)
		if e != nil {
			e.write(w)
			return
		}
		purgedRecords = n
	}

	if deviceFailures > 0 {
		t.audit().Info("user_revoke_incomplete",
			"user_id", targetID,
			"revoked_by", callerID,
			"device_failures", deviceFailures,
		)
		httperr.JSON(w, http.StatusInternalServerError, "revoke_incomplete")
		return
	}

	t.audit().Info("user_revoked",
		"user_id", targetID,
		"revoked_by", callerID,
		"purge_data", purgeData,
	)

	if purgeData {
		httperr.WriteJSON(w, http.StatusOK, map[string]interface{}{"status": "ok", "purged_records": purgedRecords})
	} else {
		httperr.WriteJSON(w, http.StatusOK, map[string]string{"status": "ok"})
	}
}

func authorizeUserDelete(caller *pki.UserRecord, callerID string, target *pki.UserRecord) *apiError {
	if target.Owner {
		return fail(http.StatusConflict, "owner_immutable")
	}
	if callerID == target.UserID {
		return nil
	}
	if target.Role == pki.RoleAdmin {
		if !authz.IsOwner(caller) {
			return fail(http.StatusForbidden, "owner_required")
		}
		return nil
	}
	if !authz.Allowed(caller, authz.PermUsersManage) {
		return fail(http.StatusForbidden, "forbidden")
	}
	return nil
}

func (t *teamHandlers) revokeUserDevices(targetID, callerID, callerDeviceID string) (devices []pki.DeviceRecord, failures int) {
	devices, err := t.devices.DevicesByUserID(targetID)
	if err != nil {
		t.srv.logger.Error("user revoke: listing devices failed", "user_id", targetID, "err", err)
		failures++
	}
	for _, d := range devices {
		if d.Status != pki.DeviceStatusActive {
			continue
		}
		if callerID == targetID && d.DeviceID == callerDeviceID {
			if err := t.devices.Leave(d.DeviceID); err != nil {
				t.srv.logger.Error("user revoke: device leave failed", "device_id", d.DeviceID, "err", err)
				failures++
				continue
			}
			t.audit().Info("device_left",
				"device_id", d.DeviceID,
				"user_id", targetID,
				"via", "leave_team",
			)
			continue
		}
		if err := t.devices.Revoke(d.DeviceID); err != nil {
			t.srv.logger.Error("user revoke: device revoke failed", "device_id", d.DeviceID, "err", err)
			failures++
			continue
		}
		t.audit().Info("device_revoked",
			"device_id", d.DeviceID,
			"user_id", targetID,
			"revoked_by", callerID,
		)
	}
	return devices, failures
}

func (t *teamHandlers) revokeUserVaults(targetID, callerID string) {
	vr := t.srv.vaultRevoker
	if vr == nil {
		return
	}
	vaults, err := vr.VaultsForUser(targetID)
	if err != nil {
		t.srv.logger.Error("user revoke: listing vaults failed", "user_id", targetID, "err", err)
	}
	for _, vaultID := range vaults {
		if err := vr.RevokeVault(vaultID, targetID); err != nil {
			t.srv.logger.Error("user revoke: vault revoke failed", "vault_id", vaultID, "user_id", targetID, "err", err)
			continue
		}
		t.srv.auditVault("vault_revoked", callerID, vaultID, targetID, "")
	}
}

func (t *teamHandlers) revokeUserInvites(targetID, callerID string) {
	activeInvites, err := t.invites.ListActive()
	if err != nil {
		t.srv.logger.Error("user revoke: listing invites failed", "user_id", targetID, "err", err)
	}
	for _, inv := range activeInvites {
		if inv.TargetUserID != targetID && inv.CreatedByUserID != targetID {
			continue
		}
		if err := t.invites.Revoke(inv.Code, callerID); err != nil {
			t.srv.logger.Error("user revoke: invite revoke failed", "invite_id", pki.InviteCodePrefix(inv.Code), "err", err)
			continue
		}
		t.audit().Info("invite_revoked",
			"invite_id", pki.InviteCodePrefix(inv.Code),
			"revoked_by", callerID,
		)
	}
}

func (t *teamHandlers) purgeUserData(targetID, callerID string, devices []pki.DeviceRecord) (int64, *apiError) {
	t.audit().Info("user_data_purge_requested",
		"user_id", targetID,
		"requested_by", callerID,
	)
	var purgedRecords int64
	if purger := t.srv.dataPurger; purger != nil {
		deviceIDs := make([]string, 0, len(devices))
		for _, d := range devices {
			deviceIDs = append(deviceIDs, d.DeviceID)
		}
		n, err := purger.PurgeUserData(targetID, deviceIDs)
		if err != nil {
			return 0, fail(http.StatusInternalServerError, "purge_failed")
		}
		purgedRecords = n
	}
	scrubbed := true
	if err := t.users.ScrubPersonalData(targetID); err != nil {
		t.srv.logger.Error("user purge: scrubbing user failed", "user_id", targetID, "err", err)
		scrubbed = false
	}
	if err := t.devices.ScrubUserDevices(targetID); err != nil {
		t.srv.logger.Error("user purge: scrubbing devices failed", "user_id", targetID, "err", err)
		scrubbed = false
	}
	t.scrubLogs(targetID)
	if scrubbed {
		t.audit().Info("user_data_purged",
			"user_id", targetID,
			"requested_by", callerID,
			"purged_records", purgedRecords,
		)
	}
	return purgedRecords, nil
}
