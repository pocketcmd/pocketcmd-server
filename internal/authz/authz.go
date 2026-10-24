// Package authz resolves permission checks for team users.
package authz

import "github.com/pocketcmd/pocketcmd-server/internal/pki"

const (
	PermMetricsCommandsCreate = "metrics.commands.create"
	PermMetricsCommandsUpdate = "metrics.commands.update"
	PermMetricsCommandsDelete = "metrics.commands.delete"
	PermMetricsCommandsRead   = "metrics.commands.read"
	PermMetricsRead           = "metrics.read"
	PermAlertsCreate          = "alerts.create"
	PermAlertsUpdate          = "alerts.update"
	PermAlertsDelete          = "alerts.delete"
	PermAlertsRead            = "alerts.read"
	PermSSHKeysSync           = "sshkeys.sync"
	PermUsersManage           = "users.manage"
	PermInvitesManage         = "invites.manage"
	// PermInvitesDevice gates creating a second-device invite for the caller's own user.
	PermInvitesDevice = "invites.device"
)

// Not held by admins by role; only the owner may grant them.
var OwnerGrantedPermissions = map[string]bool{
	PermMetricsCommandsCreate: true,
}

var KnownPermissions = map[string]bool{
	PermMetricsCommandsCreate: true,
	PermMetricsCommandsUpdate: true,
	PermMetricsCommandsDelete: true,
	PermMetricsCommandsRead:   true,
	PermMetricsRead:           true,
	PermAlertsCreate:          true,
	PermAlertsUpdate:          true,
	PermAlertsDelete:          true,
	PermAlertsRead:            true,
	PermSSHKeysSync:           true,
	PermUsersManage:           true,
	PermInvitesManage:         true,
	PermInvitesDevice:         true,
}

func DefaultMemberPermissions() pki.PermissionSet {
	return pki.PermissionSet{
		PermMetricsCommandsRead: {Granted: true},
		PermMetricsRead:         {Granted: true},
		PermAlertsRead:          {Granted: true},
		PermSSHKeysSync:         {Granted: true},
		PermInvitesDevice:       {Granted: true},
	}
}

func IsOwner(u *pki.UserRecord) bool {
	return u != nil && u.Status == pki.UserStatusActive && u.Owner
}

func Allowed(u *pki.UserRecord, perm string) bool {
	if u == nil || u.Status != pki.UserStatusActive {
		return false
	}
	return holdsImplicitly(u, perm) || u.Permissions[perm].Granted
}

func holdsImplicitly(u *pki.UserRecord, perm string) bool {
	return u.Owner || (u.Role == pki.RoleAdmin && !OwnerGrantedPermissions[perm])
}

func AlertMetricAllowed(u *pki.UserRecord, metricID string) bool {
	if !Allowed(u, PermAlertsRead) {
		return false
	}
	if holdsImplicitly(u, PermAlertsRead) {
		return true
	}
	g := u.Permissions[PermAlertsRead]
	if !g.Granted {
		return false
	}
	if len(g.Metrics) == 0 {
		return true
	}
	for _, id := range g.Metrics {
		if id == metricID {
			return true
		}
	}
	return false
}

func ValidatePermissionSet(p pki.PermissionSet) error {
	for k := range p {
		if !KnownPermissions[k] {
			return &UnknownPermissionError{Key: k}
		}
	}
	return nil
}

type UnknownPermissionError struct{ Key string }

func (e *UnknownPermissionError) Error() string { return "unknown permission: " + e.Key }
