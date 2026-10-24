package metrics

import (
	"context"
	"log/slog"
	"sync"
	"time"
)

type ConfigSource interface {
	// Load returns the current config and its updated_at stamp, or (nil, 0, nil) when none has been synced yet.
	Load() (*MonitoringConfig, int64, error)
}

type Scheduler struct {
	store           *MetricStore
	evaluator       *Evaluator
	source          ConfigSource
	logger          *slog.Logger
	config          *MonitoringConfig
	configMu        sync.RWMutex
	configUpdatedAt int64
	reload          chan struct{}
	// timerCancel is owned by the goroutine driving reloads; Stop cancels the parent context instead.
	timerCancel context.CancelFunc
	cancel      context.CancelFunc
	wg          sync.WaitGroup
}

func NewScheduler(store *MetricStore, evaluator *Evaluator, source ConfigSource, logger *slog.Logger) *Scheduler {
	return &Scheduler{
		store:     store,
		evaluator: evaluator,
		source:    source,
		logger:    logger,
		reload:    make(chan struct{}, 1),
	}
}

func (s *Scheduler) Reload() {
	select {
	case s.reload <- struct{}{}:
	default:
	}
}

func (s *Scheduler) Start(ctx context.Context) {
	ctx, s.cancel = context.WithCancel(ctx)

	s.loadConfig()
	s.createTimers(ctx)

	s.wg.Add(1)
	go func() {
		defer s.wg.Done()
		for {
			select {
			case <-ctx.Done():
				return
			case <-s.reload:
				cfg, updatedAt, changed := s.loadIfChanged()
				if !changed {
					continue
				}
				if s.logger != nil {
					s.logger.Info("monitoring config changed, reloading")
				}
				s.stopTimers()
				s.setConfig(cfg, updatedAt)
				s.createTimers(ctx)
			}
		}
	}()
}

func (s *Scheduler) Stop() {
	if s.cancel != nil {
		s.cancel()
	}
	s.wg.Wait()
}

func (s *Scheduler) loadConfig() {
	cfg, updatedAt, err := s.source.Load()
	if err != nil {
		if s.logger != nil {
			s.logger.Warn("monitoring config load failed; keeping previous", "error", err)
		}
		s.configMu.Lock()
		if s.config == nil {
			s.config = DefaultMonitoringConfig()
		}
		s.configMu.Unlock()
		return
	}
	s.setConfig(cfg, updatedAt)
}

func (s *Scheduler) setConfig(cfg *MonitoringConfig, updatedAt int64) {
	s.configMu.Lock()
	defer s.configMu.Unlock()
	if cfg == nil {
		s.config = DefaultMonitoringConfig()
		s.configUpdatedAt = 0
		return
	}
	s.config = cfg
	s.configUpdatedAt = updatedAt
}

// A load error counts as unchanged so the previous config keeps running.
func (s *Scheduler) loadIfChanged() (*MonitoringConfig, int64, bool) {
	cfg, updatedAt, err := s.source.Load()
	if err != nil {
		return nil, 0, false
	}
	s.configMu.RLock()
	defer s.configMu.RUnlock()
	return cfg, updatedAt, updatedAt != s.configUpdatedAt
}

func (s *Scheduler) createTimers(ctx context.Context) {
	genCtx, cancel := context.WithCancel(ctx)
	s.timerCancel = cancel

	cfg := s.config
	if cfg == nil {
		return
	}

	// EffectiveInterval clamps out-of-range values; time.NewTicker panics on a non-positive interval.
	defaultInterval := EffectiveInterval(nil, time.Duration(cfg.DefaultInterval)*time.Second)

	for _, m := range cfg.Custom {
		interval := EffectiveInterval(m.IntervalOverride, defaultInterval)
		cmd := m
		s.startTimer(genCtx, interval, func() {
			s.collectCustom(cmd)
		})
	}
}

func (s *Scheduler) startTimer(ctx context.Context, interval time.Duration, fn func()) {
	s.wg.Add(1)
	go func() {
		defer s.wg.Done()
		if interval <= 0 {
			interval = 30 * time.Second
		}
		ticker := time.NewTicker(interval)
		defer ticker.Stop()
		fn()
		for {
			select {
			case <-ctx.Done():
				return
			case <-ticker.C:
				fn()
			}
		}
	}()
}

// stopTimers must only be called from the reload goroutine.
func (s *Scheduler) stopTimers() {
	if s.timerCancel != nil {
		s.timerCancel()
		s.timerCancel = nil
	}
}

func (s *Scheduler) collectCustom(cmd CustomMetricConfig) {
	if err := ValidateCommand(cmd.Command); err != nil {
		return
	}
	val, err := RunCommand(cmd.Command)
	if err != nil {
		if s.logger != nil {
			s.logger.Debug("custom command failed", "id", cmd.ID, "label", cmd.Label, "error", err)
		}
		return
	}

	p := MetricPoint{
		MetricID:  "custom:" + cmd.ID,
		Value:     val,
		Timestamp: time.Now().UnixMilli(),
	}
	s.store.Write(p)

	if len(cmd.Alerts) > 0 {
		// Custom metric IDs are opaque handles; notifications carry the label instead.
		s.evaluator.Evaluate(p.MetricID, cmd.Label, p.Unit, p.Value, cmd.Alerts)
	}
}

func (s *Scheduler) GetConfig() *MonitoringConfig {
	s.configMu.RLock()
	defer s.configMu.RUnlock()
	return s.config
}
