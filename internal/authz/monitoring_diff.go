package authz

import (
	"encoding/json"
	"reflect"

	"github.com/pocketcmd/pocketcmd-server/internal/metrics"
)

func MonitoringWritePermissions(oldData, newData json.RawMessage, deleted bool) map[string]bool {
	all := map[string]bool{
		PermMetricsCommandsCreate: true,
		PermMetricsCommandsUpdate: true,
		PermMetricsCommandsDelete: true,
		PermAlertsCreate:          true,
		PermAlertsUpdate:          true,
		PermAlertsDelete:          true,
	}

	oldCfg, oldOK := parseConfig(oldData)
	if deleted {
		if !oldOK || oldCfg == nil {
			return all
		}
		req := map[string]bool{PermMetricsCommandsDelete: true}
		if configHasAlerts(oldCfg) {
			req[PermAlertsDelete] = true
		}
		return req
	}
	newCfg, newOK := parseConfig(newData)
	if !newOK || newCfg == nil {
		return all
	}
	if !oldOK {
		return all
	}
	if oldCfg == nil {
		if len(newCfg.Custom) == 0 {
			return map[string]bool{PermMetricsCommandsUpdate: true}
		}
		req := map[string]bool{PermMetricsCommandsCreate: true}
		if configHasAlerts(newCfg) {
			req[PermAlertsCreate] = true
		}
		return req
	}

	req := map[string]bool{}

	oldCustom := map[string]metrics.CustomMetricConfig{}
	for _, c := range oldCfg.Custom {
		oldCustom[c.ID] = c
	}
	newCustom := map[string]metrics.CustomMetricConfig{}
	for _, c := range newCfg.Custom {
		newCustom[c.ID] = c
	}
	for id, nc := range newCustom {
		oc, existed := oldCustom[id]
		if !existed {
			req[PermMetricsCommandsCreate] = true
			if len(nc.Alerts) > 0 {
				req[PermAlertsCreate] = true
			}
			continue
		}
		diffAlerts(req, oc.Alerts, nc.Alerts)
		if commandBodyChanged(oc, nc) {
			req[PermMetricsCommandsUpdate] = true
		}
		// A changed command body is new code on the host, so it also needs create.
		if oc.Command != nc.Command {
			req[PermMetricsCommandsCreate] = true
		}
	}
	for id, oc := range oldCustom {
		if _, kept := newCustom[id]; !kept {
			req[PermMetricsCommandsDelete] = true
			if len(oc.Alerts) > 0 {
				req[PermAlertsDelete] = true
			}
		}
	}

	if oldCfg.DefaultInterval != newCfg.DefaultInterval ||
		oldCfg.RetentionDays != newCfg.RetentionDays ||
		oldCfg.ServerID != newCfg.ServerID {
		req[PermMetricsCommandsUpdate] = true
	}

	return req
}

func parseConfig(data json.RawMessage) (*metrics.MonitoringConfig, bool) {
	if len(data) == 0 || string(data) == "null" {
		return nil, true
	}
	var cfg metrics.MonitoringConfig
	if err := json.Unmarshal(data, &cfg); err != nil {
		return nil, false
	}
	return &cfg, true
}

func configHasAlerts(cfg *metrics.MonitoringConfig) bool {
	for _, c := range cfg.Custom {
		if len(c.Alerts) > 0 {
			return true
		}
	}
	return false
}

func commandBodyChanged(a, b metrics.CustomMetricConfig) bool {
	return a.Label != b.Label || a.Command != b.Command ||
		!intPtrEq(a.IntervalOverride, b.IntervalOverride)
}

func diffAlerts(req map[string]bool, old, new_ []metrics.AlertRule) {
	oldByID := map[string]metrics.AlertRule{}
	for _, a := range old {
		oldByID[a.ID] = a
	}
	newByID := map[string]metrics.AlertRule{}
	for _, a := range new_ {
		newByID[a.ID] = a
	}
	for id, na := range newByID {
		oa, existed := oldByID[id]
		if !existed {
			req[PermAlertsCreate] = true
		} else if !reflect.DeepEqual(oa, na) {
			req[PermAlertsUpdate] = true
		}
	}
	for id := range oldByID {
		if _, kept := newByID[id]; !kept {
			req[PermAlertsDelete] = true
		}
	}
}

func intPtrEq(a, b *int) bool {
	if a == nil || b == nil {
		return a == b
	}
	return *a == *b
}
