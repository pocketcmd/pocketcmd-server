package server

import (
	"encoding/json"
	"errors"
	"net/http"
	"os"

	"github.com/pocketcmd/pocketcmd-server/internal/authz"
	"github.com/pocketcmd/pocketcmd-server/internal/httperr"
	"github.com/pocketcmd/pocketcmd-server/internal/metrics"
	"github.com/pocketcmd/pocketcmd-server/internal/monitoring"
)

type metricRequestHandlers struct {
	requests   *metrics.RequestStore
	monitoring *monitoring.Store
	srv        *Server
}

func (s *Server) RegisterMetricRequestRoutes(requests *metrics.RequestStore, mon *monitoring.Store) {
	s.requireSecurityServices("RegisterMetricRequestRoutes")
	s.metricRequests = requests
	h := &metricRequestHandlers{requests: requests, monitoring: mon, srv: s}
	s.handle("POST /api/metrics/requests", s.memberRoute(h.handleCreate))
	s.handle("GET /api/metrics/requests", s.memberRoute(h.handleList))
	s.handle("POST /api/metrics/requests/{id}/approve", s.permRoute(authz.PermMetricsCommandsCreate, h.handleApprove))
	s.handle("POST /api/metrics/requests/{id}/decline", s.permRoute(authz.PermMetricsCommandsCreate, h.handleDecline))
	s.handle("DELETE /api/metrics/requests/{id}", s.memberRoute(h.handleDelete))
}

func (h *metricRequestHandlers) handleCreate(w http.ResponseWriter, r *http.Request) {
	callerID := callerIDFrom(r)
	var body struct {
		Label            string `json:"label"`
		Command          string `json:"command"`
		IntervalOverride *int   `json:"interval_override"`
	}
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		httperr.JSON(w, http.StatusBadRequest, "invalid_body")
		return
	}
	req, err := h.requests.Create(body.Label, body.Command, body.IntervalOverride, callerID)
	if err != nil {
		httperr.JSON(w, http.StatusBadRequest, "invalid_request")
		return
	}
	h.srv.auditLogger.Info("metric_request_created",
		"request_id", req.ID, "label", req.Label, "requested_by", callerID)
	httperr.WriteJSON(w, http.StatusOK, req)
}

func (h *metricRequestHandlers) handleList(w http.ResponseWriter, r *http.Request) {
	callerID := callerIDFrom(r)
	caller := callerFrom(r)
	all, err := h.requests.List()
	if err != nil {
		httperr.JSON(w, http.StatusInternalServerError, "store_error")
		return
	}
	if !authz.Allowed(caller, authz.PermMetricsCommandsCreate) && !authz.Allowed(caller, authz.PermMetricsCommandsDelete) {
		own := all[:0]
		for _, req := range all {
			if req.RequestedBy == callerID {
				own = append(own, req)
			}
		}
		all = own
	}
	if all == nil {
		all = []metrics.MetricRequest{}
	}
	httperr.WriteJSON(w, http.StatusOK, all)
}

func (h *metricRequestHandlers) handleApprove(w http.ResponseWriter, r *http.Request) {
	h.decide(w, r, "approved")
}

func (h *metricRequestHandlers) handleDecline(w http.ResponseWriter, r *http.Request) {
	h.decide(w, r, "declined")
}

func (h *metricRequestHandlers) decide(w http.ResponseWriter, r *http.Request, status string) {
	callerID := callerIDFrom(r)
	id := r.PathValue("id")

	// Update the monitoring config first so a failure leaves the request pending.
	if status == "approved" {
		req, err := h.requests.FindByID(id)
		if err != nil {
			httperr.JSON(w, http.StatusInternalServerError, "store_error")
			return
		}
		if req == nil {
			httperr.JSON(w, http.StatusNotFound, "request_not_found")
			return
		}
		if req.Status != "pending" {
			httperr.JSON(w, http.StatusConflict, "already_decided")
			return
		}
		if err := h.monitoring.ApproveCommand(*req); err != nil {
			httperr.JSON(w, http.StatusInternalServerError, "config_update_failed")
			return
		}
	}

	req, err := h.requests.Decide(id, status, callerID)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			httperr.JSON(w, http.StatusNotFound, "request_not_found")
			return
		}
		httperr.JSON(w, http.StatusConflict, "already_decided")
		return
	}
	h.srv.auditLogger.Info("metric_request_"+status,
		"request_id", req.ID, "label", req.Label,
		"requested_by", req.RequestedBy, "decided_by", callerID)
	httperr.WriteJSON(w, http.StatusOK, req)
}

func (h *metricRequestHandlers) handleDelete(w http.ResponseWriter, r *http.Request) {
	callerID := callerIDFrom(r)
	hasGrant := authz.Allowed(callerFrom(r), authz.PermMetricsCommandsDelete)
	id := r.PathValue("id")
	req, err := h.requests.FindByID(id)
	if err != nil {
		httperr.JSON(w, http.StatusInternalServerError, "store_error")
		return
	}
	if req == nil {
		// Non-holders get the same 403 as for a foreign request, so ids stay unprobeable.
		if hasGrant {
			httperr.JSON(w, http.StatusNotFound, "request_not_found")
		} else {
			httperr.JSON(w, http.StatusForbidden, "permission_required")
		}
		return
	}
	withdrawOwn := req.RequestedBy == callerID && req.Status == "pending"
	if !hasGrant && !withdrawOwn {
		httperr.JSON(w, http.StatusForbidden, "permission_required")
		return
	}
	// The custom_metrics FK cascades, removing the command in the same statement.
	if _, err := h.requests.Delete(id); err != nil {
		if errors.Is(err, os.ErrNotExist) {
			httperr.JSON(w, http.StatusNotFound, "request_not_found")
			return
		}
		httperr.JSON(w, http.StatusInternalServerError, "store_error")
		return
	}
	if req.Status == "approved" {
		if err := h.monitoring.Touch(); err != nil {
			httperr.JSON(w, http.StatusInternalServerError, "config_update_failed")
			return
		}
	}
	h.srv.auditLogger.Info("metric_request_deleted",
		"request_id", req.ID, "label", req.Label,
		"status_was", req.Status, "deleted_by", callerID)
	httperr.WriteJSON(w, http.StatusOK, map[string]string{"status": "ok"})
}
