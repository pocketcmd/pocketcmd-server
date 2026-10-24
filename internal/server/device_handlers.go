package server

import (
	"encoding/json"
	"net/http"
	"sort"

	"github.com/pocketcmd/pocketcmd-server/internal/authz"
	"github.com/pocketcmd/pocketcmd-server/internal/httperr"
	"github.com/pocketcmd/pocketcmd-server/internal/pki"
)

type deviceSummary struct {
	DeviceID    string  `json:"device_id"`
	DeviceName  string  `json:"device_name"`
	DeviceLabel string  `json:"device_label,omitempty"`
	UserID      string  `json:"user_id"`
	DisplayName string  `json:"display_name,omitempty"`
	Status      string  `json:"status"`
	PairedAt    string  `json:"paired_at"`
	RemovedAt   *string `json:"removed_at"`
	LastSeenAt  string  `json:"last_seen_at,omitempty"`
	Self        bool    `json:"self,omitempty"`
}

func summarizeDevice(d pki.DeviceRecord, displayName, callerDeviceID string) deviceSummary {
	var removed *string
	if d.RevokedAt != "" {
		at := d.RevokedAt
		removed = &at
	}
	return deviceSummary{
		DeviceID:    d.DeviceID,
		DeviceName:  d.DeviceName,
		DeviceLabel: d.DeviceLabel,
		UserID:      d.UserID,
		DisplayName: displayName,
		Status:      d.Status,
		PairedAt:    d.PairedAt,
		RemovedAt:   removed,
		LastSeenAt:  d.LastSeenAt,
		Self:        d.DeviceID == callerDeviceID,
	}
}

func (t *teamHandlers) userDisplayNames() map[string]string {
	names := map[string]string{}
	if users, err := t.users.List(); err == nil {
		for _, u := range users {
			names[u.UserID] = u.DisplayName
		}
	}
	return names
}

func (t *teamHandlers) handleListDevices(w http.ResponseWriter, r *http.Request) {
	caller := callerFrom(r)
	callerID := callerIDFrom(r)
	callerDeviceID := deviceIDFrom(r)
	includeAll := r.URL.Query().Get("include") == "all"

	all, err := t.devices.List()
	if err != nil {
		httperr.JSON(w, http.StatusInternalServerError, "store_error")
		return
	}
	names := t.userDisplayNames()

	out := make([]deviceSummary, 0)
	for _, d := range all {
		if d.Status != pki.DeviceStatusActive && !includeAll {
			continue
		}
		if caller.Role != pki.RoleAdmin && d.UserID != callerID {
			continue
		}
		out = append(out, summarizeDevice(d, names[d.UserID], callerDeviceID))
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].Self != out[j].Self {
			return out[i].Self
		}
		if out[i].LastSeenAt != out[j].LastSeenAt {
			return out[i].LastSeenAt > out[j].LastSeenAt
		}
		return out[i].DeviceID < out[j].DeviceID
	})

	httperr.WriteJSON(w, http.StatusOK, out)
}

func (t *teamHandlers) handlePatchDevice(w http.ResponseWriter, r *http.Request) {
	targetID := r.PathValue("id")
	caller := callerFrom(r)
	callerID := callerIDFrom(r)
	callerDeviceID := deviceIDFrom(r)
	if targetID == "self" {
		targetID = callerDeviceID
	}

	var body struct {
		DeviceName  *string `json:"device_name"`
		DeviceLabel *string `json:"device_label"`
	}
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		httperr.JSON(w, http.StatusBadRequest, "invalid_body")
		return
	}
	if body.DeviceName == nil && body.DeviceLabel == nil {
		httperr.JSON(w, http.StatusBadRequest, "no_fields")
		return
	}

	target, err := t.devices.FindByID(targetID)
	if err != nil {
		httperr.JSON(w, http.StatusNotFound, "device_not_found")
		return
	}
	if target.DeviceID != callerDeviceID && !authz.Allowed(caller, authz.PermUsersManage) {
		httperr.JSON(w, http.StatusForbidden, "forbidden")
		return
	}
	if (body.DeviceName != nil && !pki.ValidDeviceName(*body.DeviceName)) ||
		(body.DeviceLabel != nil && !pki.ValidDeviceName(*body.DeviceLabel)) {
		httperr.JSON(w, http.StatusBadRequest, "name_too_long")
		return
	}

	if err := t.devices.Rename(targetID, body.DeviceName, body.DeviceLabel); err != nil {
		httperr.JSON(w, http.StatusInternalServerError, "store_error")
		return
	}
	updated, err := t.devices.FindByID(targetID)
	if err != nil {
		httperr.JSON(w, http.StatusInternalServerError, "store_error")
		return
	}
	t.audit().Info("device_renamed",
		"device_id", targetID,
		"user_id", target.UserID,
		"old_name", target.DeviceName,
		"new_name", updated.DeviceName,
		"old_label", target.DeviceLabel,
		"new_label", updated.DeviceLabel,
		"changed_by", callerID,
	)
	httperr.WriteJSON(w, http.StatusOK, summarizeDevice(*updated, t.userDisplayNames()[updated.UserID], callerDeviceID))
}

func (t *teamHandlers) handleDeleteDevice(w http.ResponseWriter, r *http.Request) {
	targetID := r.PathValue("id")
	caller := callerFrom(r)
	callerID := callerIDFrom(r)
	callerDeviceID := deviceIDFrom(r)

	if targetID == "self" {
		targetID = callerDeviceID
	}

	target, err := t.devices.FindByID(targetID)
	if err != nil {
		httperr.JSON(w, http.StatusNotFound, "device_not_found")
		return
	}

	if target.UserID == callerID && authz.IsOwner(caller) && target.Status == pki.DeviceStatusActive {
		// The owner is immutable, so their last device must not be unpaired.
		all, err := t.devices.List()
		if err != nil {
			httperr.JSON(w, http.StatusInternalServerError, "store_error")
			return
		}
		others := 0
		for _, d := range all {
			if d.Status == pki.DeviceStatusActive && d.UserID == callerID && d.DeviceID != target.DeviceID {
				others++
			}
		}
		if others == 0 {
			httperr.JSON(w, http.StatusConflict, "last_device")
			return
		}
	}

	if target.UserID != callerID {
		owner, err := t.users.FindByID(target.UserID)
		if err != nil {
			httperr.JSON(w, http.StatusInternalServerError, "store_error")
			return
		}
		if owner != nil && owner.Role == pki.RoleAdmin {
			if !authz.IsOwner(caller) {
				httperr.JSON(w, http.StatusForbidden, "owner_required")
				return
			}
		} else if !authz.Allowed(caller, authz.PermUsersManage) {
			httperr.JSON(w, http.StatusForbidden, "forbidden")
			return
		}
	}

	if target.DeviceID == callerDeviceID {
		if err := t.devices.Leave(targetID); err != nil {
			httperr.JSON(w, http.StatusInternalServerError, "store_error")
			return
		}
		t.audit().Info("device_left",
			"device_id", targetID,
			"user_id", target.UserID,
			"self_unpair", true,
		)
	} else {
		if err := t.devices.Revoke(targetID); err != nil {
			httperr.JSON(w, http.StatusInternalServerError, "store_error")
			return
		}
		t.audit().Info("device_revoked",
			"device_id", targetID,
			"user_id", target.UserID,
			"revoked_by", callerID,
			"previous_status", target.Status,
			"self_unpair", false,
		)
	}

	httperr.WriteJSON(w, http.StatusOK, map[string]string{"status": "ok"})
}
