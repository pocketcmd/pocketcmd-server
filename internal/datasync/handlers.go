package datasync

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"log/slog"
	"net/http"

	"github.com/pocketcmd/pocketcmd-server/internal/httperr"
)

const (
	maxPushPayload = 10 * 1024 * 1024
	maxRecordSize  = 1 * 1024 * 1024
	maxPullPayload = 1 * 1024 * 1024
	maxPullIDs     = 10000
	maxPushRecords = 10000
)

type ctxKey string

const (
	ctxKeyUserID   ctxKey = "sync_user_id"
	ctxKeyDeviceID ctxKey = "sync_device_id"
)

func WithUserID(ctx context.Context, userID string) context.Context {
	return context.WithValue(ctx, ctxKeyUserID, userID)
}

func userIDFrom(ctx context.Context) string {
	uid, _ := ctx.Value(ctxKeyUserID).(string)
	return uid
}

func WithDeviceID(ctx context.Context, deviceID string) context.Context {
	return context.WithValue(ctx, ctxKeyDeviceID, deviceID)
}

func deviceIDFrom(ctx context.Context) string {
	id, _ := ctx.Value(ctxKeyDeviceID).(string)
	return id
}

type SyncHandler struct {
	store *SyncStore
}

func NewSyncHandler(store *SyncStore) *SyncHandler {
	return &SyncHandler{store: store}
}

func (h *SyncHandler) HandleManifest(w http.ResponseWriter, r *http.Request) {
	manifest, err := h.store.GetManifest(userIDFrom(r.Context()))
	if err != nil {
		slog.Error("sync manifest failed", "err", err)
		httperr.JSON(w, http.StatusInternalServerError, "store_error")
		return
	}
	if manifest.Records == nil {
		manifest.Records = []ManifestEntry{}
	}
	httperr.WriteJSON(w, http.StatusOK, manifest)
}

func (h *SyncHandler) HandlePull(w http.ResponseWriter, r *http.Request) {
	r.Body = http.MaxBytesReader(w, r.Body, maxPullPayload)
	var req struct {
		IDs []string `json:"ids"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		httperr.JSON(w, http.StatusBadRequest, "invalid_body")
		return
	}
	if len(req.IDs) > maxPullIDs {
		httperr.JSON(w, http.StatusRequestEntityTooLarge, "too_many_ids")
		return
	}

	records, err := h.store.PullRecords(userIDFrom(r.Context()), req.IDs)
	if err != nil {
		slog.Error("sync pull failed", "err", err)
		httperr.JSON(w, http.StatusInternalServerError, "store_error")
		return
	}

	if records == nil {
		records = []SyncRecord{}
	}
	httperr.WriteJSON(w, http.StatusOK, map[string][]SyncRecord{"records": records})
}

func (h *SyncHandler) HandlePush(w http.ResponseWriter, r *http.Request) {
	r.Body = http.MaxBytesReader(w, r.Body, maxPushPayload)
	body, err := io.ReadAll(r.Body)
	if err != nil {
		var tooLarge *http.MaxBytesError
		if errors.As(err, &tooLarge) {
			httperr.JSON(w, http.StatusRequestEntityTooLarge, "payload_too_large")
			return
		}
		httperr.JSON(w, http.StatusBadRequest, "invalid_body")
		return
	}

	var req struct {
		Records []SyncRecord `json:"records"`
	}
	if err := json.Unmarshal(body, &req); err != nil {
		httperr.JSON(w, http.StatusBadRequest, "invalid_body")
		return
	}

	if len(req.Records) > maxPushRecords {
		httperr.JSON(w, http.StatusRequestEntityTooLarge, "too_many_records")
		return
	}

	for _, rec := range req.Records {
		if len(rec.Data) > maxRecordSize || len(rec.Credentials) > maxRecordSize {
			httperr.JSON(w, http.StatusRequestEntityTooLarge, "record_too_large")
			return
		}
	}

	if devID := deviceIDFrom(r.Context()); devID != "" {
		for i := range req.Records {
			req.Records[i].DeviceID = devID
		}
	}

	result, err := h.store.PushRecords(userIDFrom(r.Context()), req.Records)
	if err != nil {
		slog.Error("sync push failed", "err", err)
		httperr.JSON(w, http.StatusInternalServerError, "store_error")
		return
	}

	httperr.WriteJSON(w, http.StatusOK, result)
}
