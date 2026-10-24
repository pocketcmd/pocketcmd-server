package authz

import (
	"encoding/json"
	"testing"

	"github.com/pocketcmd/pocketcmd-server/internal/pki"
)

func activeMember(perms pki.PermissionSet) *pki.UserRecord {
	return &pki.UserRecord{UserID: "m1", Role: "member", Status: "active", Permissions: perms}
}

func TestAllowed_AdminImplicitlyHoldsAllButOwnerGranted(t *testing.T) {
	admin := &pki.UserRecord{UserID: "a1", Role: "admin", Status: "active"}
	for perm := range KnownPermissions {
		if got, want := Allowed(admin, perm), !OwnerGrantedPermissions[perm]; got != want {
			t.Errorf("admin %s: got %v, want %v", perm, got, want)
		}
	}
}

func TestAllowed_OwnerHoldsEverything(t *testing.T) {
	owner := &pki.UserRecord{UserID: "o1", Role: "admin", Status: "active", Owner: true}
	for perm := range KnownPermissions {
		if !Allowed(owner, perm) {
			t.Errorf("owner should hold %s", perm)
		}
	}
}

func TestAllowed_OwnerGrantedNeedsGrant(t *testing.T) {
	grant := pki.PermissionSet{PermMetricsCommandsCreate: {Granted: true}}
	for _, u := range []*pki.UserRecord{
		{UserID: "a1", Role: "admin", Status: "active", Permissions: grant},
		{UserID: "m1", Role: "member", Status: "active", Permissions: grant},
	} {
		if !Allowed(u, PermMetricsCommandsCreate) {
			t.Errorf("%s with the grant should hold %s", u.Role, PermMetricsCommandsCreate)
		}
	}
	revoked := &pki.UserRecord{UserID: "a2", Role: "admin", Status: "revoked", Permissions: grant}
	if Allowed(revoked, PermMetricsCommandsCreate) {
		t.Error("a revoked admin keeps no grant")
	}
}

func TestAllowed_MemberHoldsOnlyGrants(t *testing.T) {
	m := activeMember(pki.PermissionSet{PermMetricsRead: {Granted: true}})
	if !Allowed(m, PermMetricsRead) {
		t.Error("granted permission should pass")
	}
	if Allowed(m, PermMetricsCommandsCreate) {
		t.Error("ungranted permission should fail")
	}
}

func TestAllowed_RevokedAndNilUsersDenied(t *testing.T) {
	revoked := &pki.UserRecord{UserID: "r1", Role: "admin", Status: "revoked"}
	if Allowed(revoked, PermMetricsRead) {
		t.Error("revoked admin should be denied")
	}
	if Allowed(nil, PermMetricsRead) {
		t.Error("nil user should be denied")
	}
}

func TestAlertMetricAllowed_ScopeSemantics(t *testing.T) {
	all := activeMember(pki.PermissionSet{PermAlertsRead: {Granted: true}})
	if !AlertMetricAllowed(all, "custom:cpu") {
		t.Error("empty scope should mean all metrics")
	}
	scoped := activeMember(pki.PermissionSet{
		PermAlertsRead: {Granted: true, Metrics: []string{"custom:cpu"}},
	})
	if !AlertMetricAllowed(scoped, "custom:cpu") {
		t.Error("in-scope metric should pass")
	}
	if AlertMetricAllowed(scoped, "custom:foo") {
		t.Error("out-of-scope metric should fail")
	}
	none := activeMember(pki.PermissionSet{})
	if AlertMetricAllowed(none, "custom:cpu") {
		t.Error("no grant should fail")
	}
	admin := &pki.UserRecord{UserID: "a1", Role: "admin", Status: "active", Permissions: pki.PermissionSet{
		PermAlertsRead: {Granted: true, Metrics: []string{"custom:cpu"}},
	}}
	if !AlertMetricAllowed(admin, "custom:foo") {
		t.Error("admin should receive every metric's alerts regardless of a stored scope")
	}
	admin.Status = "revoked"
	if AlertMetricAllowed(admin, "custom:cpu") {
		t.Error("revoked admin should receive nothing")
	}
}

func TestValidatePermissionSet(t *testing.T) {
	if err := ValidatePermissionSet(DefaultMemberPermissions()); err != nil {
		t.Errorf("defaults should validate: %v", err)
	}
	if err := ValidatePermissionSet(pki.PermissionSet{"bogus.key": {Granted: true}}); err == nil {
		t.Error("unknown key should be rejected")
	}
}

func mustJSON(t *testing.T, v interface{}) json.RawMessage {
	t.Helper()
	b, err := json.Marshal(v)
	if err != nil {
		t.Fatal(err)
	}
	return b
}

func cfgJSON(t *testing.T, custom []map[string]interface{}) json.RawMessage {
	t.Helper()
	return mustJSON(t, map[string]interface{}{
		"default_interval_seconds": 30,
		"retention_days":           7,
		"custom_metrics":           custom,
	})
}

func TestMonitoringDiff_FirstWriteIsCreate(t *testing.T) {
	newCfg := cfgJSON(t, []map[string]interface{}{
		{"id": "x", "label": "X", "command": "echo 1"},
	})
	req := MonitoringWritePermissions(nil, newCfg, false)
	if !req[PermMetricsCommandsCreate] {
		t.Error("first write should require create")
	}
	if req[PermAlertsCreate] {
		t.Error("no alerts defined, alerts.create should not be required")
	}
}

func TestMonitoringDiff_FirstWriteWithoutCommandsIsUpdate(t *testing.T) {
	newCfg := cfgJSON(t, []map[string]interface{}{})
	req := MonitoringWritePermissions(nil, newCfg, false)
	if !req[PermMetricsCommandsUpdate] || req[PermMetricsCommandsCreate] || len(req) != 1 {
		t.Errorf("command-free first write should require only update, got %v", req)
	}
}

func TestMonitoringDiff_CommandBodyChangeIsCreate(t *testing.T) {
	oldCfg := cfgJSON(t, []map[string]interface{}{
		{"id": "a", "label": "A", "command": "echo a"},
	})
	body := cfgJSON(t, []map[string]interface{}{
		{"id": "a", "label": "A", "command": "echo CHANGED"},
	})
	req := MonitoringWritePermissions(oldCfg, body, false)
	if !req[PermMetricsCommandsCreate] || !req[PermMetricsCommandsUpdate] {
		t.Errorf("command body change should require create and update, got %v", req)
	}
	label := cfgJSON(t, []map[string]interface{}{
		{"id": "a", "label": "Renamed", "command": "echo a", "interval_override": 60},
	})
	req = MonitoringWritePermissions(oldCfg, label, false)
	if req[PermMetricsCommandsCreate] || !req[PermMetricsCommandsUpdate] {
		t.Errorf("label/interval change should require update only, got %v", req)
	}
}

func TestMonitoringDiff_CommandAddChangeRemove(t *testing.T) {
	oldCfg := cfgJSON(t, []map[string]interface{}{
		{"id": "a", "label": "A", "command": "echo a"},
		{"id": "b", "label": "B", "command": "echo b"},
	})

	newCfg := cfgJSON(t, []map[string]interface{}{
		{"id": "a", "label": "A", "command": "echo CHANGED"},
		{"id": "c", "label": "C", "command": "echo c"},
	})
	req := MonitoringWritePermissions(oldCfg, newCfg, false)
	for _, want := range []string{PermMetricsCommandsCreate, PermMetricsCommandsUpdate, PermMetricsCommandsDelete} {
		if !req[want] {
			t.Errorf("expected %s to be required, got %v", want, req)
		}
	}
}

func TestMonitoringDiff_IdenticalWriteRequiresNothing(t *testing.T) {
	cfg := cfgJSON(t, []map[string]interface{}{
		{"id": "a", "label": "A", "command": "echo a"},
	})
	req := MonitoringWritePermissions(cfg, cfg, false)
	if len(req) != 0 {
		t.Errorf("no-op write should require no permissions, got %v", req)
	}
}

func TestMonitoringDiff_AlertChanges(t *testing.T) {
	oldCfg := cfgJSON(t, []map[string]interface{}{
		{"id": "a", "label": "A", "command": "echo a",
			"alerts": []map[string]interface{}{{"id": "al1", "threshold": 90.0, "operator": "greater"}}},
	})
	newCfg := cfgJSON(t, []map[string]interface{}{
		{"id": "a", "label": "A", "command": "echo a",
			"alerts": []map[string]interface{}{
				{"id": "al1", "threshold": 50.0, "operator": "greater"},
				{"id": "al2", "threshold": 10.0, "operator": "less"},
			}},
	})
	req := MonitoringWritePermissions(oldCfg, newCfg, false)
	if !req[PermAlertsUpdate] || !req[PermAlertsCreate] {
		t.Errorf("expected alerts.update + alerts.create, got %v", req)
	}
	if req[PermMetricsCommandsUpdate] {
		t.Errorf("command body unchanged, commands.update should not be required, got %v", req)
	}

	req = MonitoringWritePermissions(newCfg, oldCfg, false)
	if !req[PermAlertsDelete] {
		t.Errorf("expected alerts.delete, got %v", req)
	}
}

func TestMonitoringDiff_IntervalChangeIsUpdate(t *testing.T) {
	oldCfg := cfgJSON(t, nil)
	newCfg := mustJSON(t, map[string]interface{}{
		"default_interval_seconds": 60,
		"retention_days":           7,
		"custom_metrics":           nil,
	})
	req := MonitoringWritePermissions(oldCfg, newCfg, false)
	if !req[PermMetricsCommandsUpdate] {
		t.Errorf("interval change should require commands.update, got %v", req)
	}
	if len(req) != 1 {
		t.Errorf("interval change needs nothing else, got %v", req)
	}
}

func TestMonitoringDiff_TombstoneIsDelete(t *testing.T) {
	oldCfg := cfgJSON(t, []map[string]interface{}{
		{"id": "a", "label": "A", "command": "echo a",
			"alerts": []map[string]interface{}{{"id": "al1", "threshold": 1.0, "operator": "greater"}}},
	})
	req := MonitoringWritePermissions(oldCfg, nil, true)
	if !req[PermMetricsCommandsDelete] || !req[PermAlertsDelete] {
		t.Errorf("tombstone should require deletes, got %v", req)
	}
}

func TestMonitoringDiff_MalformedRequiresEverything(t *testing.T) {
	req := MonitoringWritePermissions(nil, json.RawMessage(`{not json`), false)
	for _, want := range []string{
		PermMetricsCommandsCreate, PermMetricsCommandsUpdate, PermMetricsCommandsDelete,
		PermAlertsCreate, PermAlertsUpdate, PermAlertsDelete,
	} {
		if !req[want] {
			t.Errorf("malformed config should require %s", want)
		}
	}
}
