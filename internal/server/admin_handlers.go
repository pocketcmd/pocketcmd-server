package server

import (
	"bufio"
	"encoding/json"
	"errors"
	"net/http"
	"os"
	"path/filepath"
	"strconv"
	"time"

	"github.com/pocketcmd/pocketcmd-server/internal/config"
	"github.com/pocketcmd/pocketcmd-server/internal/httperr"
	"github.com/pocketcmd/pocketcmd-server/internal/pki"
)

type adminHandlers struct {
	srv       *Server
	version   string
	startedAt time.Time
}

func (s *Server) RegisterAdminRoutes(version string) {
	s.requireSecurityServices("RegisterAdminRoutes")
	a := &adminHandlers{
		srv:       s,
		version:   version,
		startedAt: time.Now(),
	}
	s.handle("GET /api/server/status", s.adminRoute(a.handleStatus))
	s.handle("GET /api/server/config", s.adminRoute(a.handleGetConfig))
	s.handle("GET /api/audit", s.ownerRoute(a.handleAudit))
	s.handle("GET /api/logs", s.ownerRoute(a.handleLogs))
}

func (a *adminHandlers) handleStatus(w http.ResponseWriter, r *http.Request) {
	activeDevices, totalDevices := 0, 0
	if devices, err := a.srv.deviceRegistry.List(); err == nil {
		totalDevices = len(devices)
		for _, d := range devices {
			if d.Status == pki.DeviceStatusActive {
				activeDevices++
			}
		}
	}
	activeUsers := 0
	if users, err := a.srv.userRegistry.List(); err == nil {
		for _, u := range users {
			if u.Status == pki.UserStatusActive {
				activeUsers++
			}
		}
	}

	var stateBytes int64
	_ = filepath.Walk(config.PocketCmdDir(), func(_ string, info os.FileInfo, err error) error {
		if err == nil && info != nil && !info.IsDir() {
			stateBytes += info.Size()
		}
		return nil
	})

	httperr.WriteJSON(w, http.StatusOK, map[string]any{
		"version":         a.version,
		"started_at":      a.startedAt.UTC().Format(time.RFC3339),
		"uptime_seconds":  int64(time.Since(a.startedAt).Seconds()),
		"state_dir_bytes": stateBytes,
		"active_devices":  activeDevices,
		"total_devices":   totalDevices,
		"active_users":    activeUsers,
	})
}

func (a *adminHandlers) handleGetConfig(w http.ResponseWriter, r *http.Request) {
	cfg, ok := a.loadConfig(w)
	if !ok {
		return
	}
	httperr.WriteJSON(w, http.StatusOK, map[string]any{
		"service_mode": cfg.ServiceMode,
	})
}

func (a *adminHandlers) loadConfig(w http.ResponseWriter) (config.FeatureConfig, bool) {
	cfg, err := config.LoadFeatureConfig(config.ConfigFilePath())
	switch {
	case err == nil:
		return cfg, true
	case errors.Is(err, os.ErrNotExist):
		return config.DefaultFeatureConfig(), true
	default:
		a.srv.logger.Error("server config unreadable", "err", err)
		httperr.JSON(w, http.StatusInternalServerError, "config_unreadable")
		return config.FeatureConfig{}, false
	}
}

func parseTimeRange(w http.ResponseWriter, r *http.Request) (fromMs, toMs int64, ok bool) {
	parseBound := func(name string) (int64, bool) {
		v := r.URL.Query().Get(name)
		if v == "" {
			return 0, true
		}
		t, err := time.Parse(time.RFC3339, v)
		if err != nil || t.Year() < 2000 || t.Year() > 3000 {
			httperr.JSON(w, http.StatusBadRequest, "invalid_time")
			return 0, false
		}
		return t.UnixMilli(), true
	}
	if fromMs, ok = parseBound("from"); !ok {
		return 0, 0, false
	}
	if toMs, ok = parseBound("to"); !ok {
		return 0, 0, false
	}
	if fromMs > 0 && toMs > 0 && fromMs > toMs {
		httperr.JSON(w, http.StatusBadRequest, "invalid_time_range")
		return 0, 0, false
	}
	return fromMs, toMs, true
}

func (a *adminHandlers) handleLogs(w http.ResponseWriter, r *http.Request) {
	fromMs, toMs, ok := parseTimeRange(w, r)
	if !ok {
		return
	}
	limit := 50
	if v, err := strconv.Atoi(r.URL.Query().Get("limit")); err == nil && v > 0 && v <= 200 {
		limit = v
	}
	var beforeID int64
	if v, err := strconv.ParseInt(r.URL.Query().Get("before_id"), 10, 64); err == nil && v > 0 {
		beforeID = v
	}
	userID := r.URL.Query().Get("user_id")

	entries := []map[string]any{}
	total := 0
	hasMore := false
	var nextBeforeID int64
	if logs := a.srv.logSource; logs != nil {
		rows, n, more := logs.Query(LogQuery{
			Limit: limit, BeforeID: beforeID, UserID: userID,
			FromMs: fromMs, ToMs: toMs,
		})
		total, hasMore = n, more
		for _, row := range rows {
			m := map[string]any{}
			if err := json.Unmarshal(row.Entry, &m); err != nil {
				continue
			}
			m["id"] = row.ID
			entries = append(entries, m)
			nextBeforeID = row.ID
		}
	}
	resp := map[string]any{
		"entries": entries,
		"total":   total,
	}
	if hasMore && nextBeforeID > 0 {
		resp["next_before_id"] = nextBeforeID
	}
	httperr.WriteJSON(w, http.StatusOK, resp)
}

type lineWindow struct {
	slots [][]byte
	next  int
	count int
}

func newLineWindow(n int) *lineWindow {
	if n < 1 {
		n = 1
	}
	return &lineWindow{slots: make([][]byte, n)}
}

func (w *lineWindow) push(line []byte) {
	w.slots[w.next] = append(w.slots[w.next][:0], line...)
	w.next = (w.next + 1) % len(w.slots)
	if w.count < len(w.slots) {
		w.count++
	}
}

func (w *lineWindow) lines() [][]byte {
	out := make([][]byte, 0, w.count)
	start := (w.next - w.count + len(w.slots)) % len(w.slots)
	for i := 0; i < w.count; i++ {
		out = append(out, w.slots[(start+i)%len(w.slots)])
	}
	return out
}

func (a *adminHandlers) handleAudit(w http.ResponseWriter, r *http.Request) {
	fromMs, toMs, ok := parseTimeRange(w, r)
	if !ok {
		return
	}
	limit := 50
	if v, err := strconv.Atoi(r.URL.Query().Get("limit")); err == nil && v > 0 && v <= 200 {
		limit = v
	}
	offset := 0
	if v, err := strconv.Atoi(r.URL.Query().Get("offset")); err == nil && v > 0 {
		offset = v
	}

	timeFiltered := fromMs > 0 || toMs > 0
	inWindow := func(line []byte) bool {
		var meta struct {
			Time string `json:"time"`
		}
		if json.Unmarshal(line, &meta) != nil || meta.Time == "" {
			return false
		}
		t, err := time.Parse(time.RFC3339Nano, meta.Time)
		if err != nil {
			return false
		}
		ms := t.UnixMilli()
		return (fromMs == 0 || ms >= fromMs) && (toMs == 0 || ms <= toMs)
	}

	window := newLineWindow(offset + limit)
	total := 0
	path := filepath.Join(config.PocketCmdDir(), "audit.log")
	if f, err := os.Open(path); err == nil {
		defer f.Close()
		scanner := bufio.NewScanner(f)
		scanner.Buffer(make([]byte, 0, 64*1024), 1024*1024)
		for scanner.Scan() {
			line := scanner.Bytes()
			if !json.Valid(line) {
				continue
			}
			if timeFiltered && !inWindow(line) {
				continue
			}
			total++
			window.push(line)
		}
	}

	kept := window.lines()
	end := len(kept) - offset
	if end < 0 {
		end = 0
	}
	start := end - limit
	if start < 0 {
		start = 0
	}
	entries := make([]json.RawMessage, 0, end-start)
	for i := end - 1; i >= start; i-- {
		entries = append(entries, json.RawMessage(kept[i]))
	}

	httperr.WriteJSON(w, http.StatusOK, map[string]any{
		"entries": entries,
		"total":   total,
	})
}
