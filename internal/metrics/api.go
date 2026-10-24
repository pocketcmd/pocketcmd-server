package metrics

import (
	"log/slog"
	"net/http"
	"time"

	"github.com/pocketcmd/pocketcmd-server/internal/httperr"
)

type MetricAPI struct {
	store     *MetricStore
	scheduler *Scheduler
}

func NewMetricAPI(store *MetricStore, scheduler *Scheduler) *MetricAPI {
	return &MetricAPI{store: store, scheduler: scheduler}
}

func (a *MetricAPI) getConfig() *MonitoringConfig {
	if a.scheduler != nil {
		return a.scheduler.GetConfig()
	}
	return nil
}

func (a *MetricAPI) HandleAvailable(w http.ResponseWriter, r *http.Request) {
	infos := []MetricInfo{}
	if config := a.getConfig(); config != nil {
		for _, m := range config.Custom {
			infos = append(infos, MetricInfo{
				ID:    "custom:" + m.ID,
				Label: m.Label,
				Unit:  "",
			})
		}
	}
	httperr.WriteJSON(w, http.StatusOK, map[string][]MetricInfo{"metrics": infos})
}

func (a *MetricAPI) HandleLatest(w http.ResponseWriter, r *http.Request) {
	latest, err := a.store.Latest()
	if err != nil {
		slog.Error("metrics latest query failed", "err", err)
		httperr.JSON(w, http.StatusInternalServerError, "store_error")
		return
	}
	httperr.WriteJSON(w, http.StatusOK, map[string]map[string]MetricPoint{"metrics": latest})
}

func (a *MetricAPI) HandleSeries(w http.ResponseWriter, r *http.Request) {
	metricID := r.URL.Query().Get("metric")
	rangeStr := r.URL.Query().Get("range")

	if metricID == "" || rangeStr == "" {
		httperr.JSON(w, http.StatusBadRequest, "missing_params")
		return
	}

	duration, bucketSeconds := parseRange(rangeStr)
	if duration == 0 {
		httperr.JSON(w, http.StatusBadRequest, "invalid_range")
		return
	}

	var points []MetricPoint
	var err error

	if bucketSeconds == 0 {
		points, err = a.store.Series(metricID, duration)
	} else {
		points, err = a.store.SeriesDownsampled(metricID, duration, bucketSeconds)
	}

	if err != nil {
		slog.Error("metrics series query failed", "err", err, "metric", metricID)
		httperr.JSON(w, http.StatusInternalServerError, "store_error")
		return
	}

	unit := ""
	if len(points) > 0 {
		unit = points[len(points)-1].Unit
	}
	if points == nil {
		points = []MetricPoint{}
	}

	httperr.WriteJSON(w, http.StatusOK, map[string]interface{}{
		"metric": metricID,
		"unit":   unit,
		"points": points,
	})
}

func parseRange(s string) (duration time.Duration, bucketSeconds int64) {
	switch s {
	case "1m":
		return time.Minute, 0
	case "1h":
		return time.Hour, 0
	case "6h":
		return 6 * time.Hour, 60
	case "24h":
		return 24 * time.Hour, 300
	case "7d":
		return 7 * 24 * time.Hour, 3600
	case "30d":
		return 30 * 24 * time.Hour, 21600
	case "1y":
		return 365 * 24 * time.Hour, 86400
	default:
		return 0, 0
	}
}
