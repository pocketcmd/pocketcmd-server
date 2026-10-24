package server

import (
	"context"
	"crypto/tls"
	"fmt"
	"net"
	"net/http"
	"strconv"
	"time"
)

func (s *Server) Start(ctx context.Context) error {
	if err := s.Listen(); err != nil {
		return err
	}
	return s.Serve(ctx)
}

func (s *Server) Listen() error {
	addr := net.JoinHostPort(s.cfg.Host, strconv.Itoa(s.cfg.Port))
	ln, err := net.Listen("tcp", addr)
	if err != nil {
		return err
	}

	if s.tlsConfig != nil {
		ln = tls.NewListener(ln, s.tlsConfig)
	}
	s.listener = ln
	return nil
}

func (s *Server) Serve(ctx context.Context) error {
	if s.listener == nil {
		return fmt.Errorf("server: Serve called before Listen")
	}
	ln := s.listener

	ctx, cancel := context.WithCancel(ctx)

	httpServer := &http.Server{
		Handler:           LoggingMiddleware(s.logger, s),
		ReadHeaderTimeout: 10 * time.Second,
		ReadTimeout:       30 * time.Second,
		WriteTimeout:      60 * time.Second,
		IdleTimeout:       120 * time.Second,
		MaxHeaderBytes:    16 << 10,
	}
	s.shutdownMu.Lock()
	s.shutdownFn = cancel
	s.httpServer = httpServer
	s.shutdownMu.Unlock()

	go func() {
		ticker := time.NewTicker(5 * time.Minute)
		defer ticker.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case now := <-ticker.C:
				s.rateLimiter.Cleanup()
				s.challengePubKeyLimiter.Cleanup()
				if s.pairing != nil {
					s.pairing.SweepRateLimits(now)
				}
			}
		}
	}()

	go func() {
		ticker := time.NewTicker(30 * time.Second)
		defer ticker.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case now := <-ticker.C:
				s.nonces.Sweep(now)
			}
		}
	}()

	go func() {
		ticker := time.NewTicker(60 * time.Second)
		defer ticker.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case now := <-ticker.C:
				if s.inviteStore != nil {
					s.inviteStore.Sweep(now)
				}
			}
		}
	}()

	go func() {
		s.pruneStores(time.Now())
		ticker := time.NewTicker(time.Hour)
		defer ticker.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case now := <-ticker.C:
				s.pruneStores(now)
			}
		}
	}()

	return s.httpServer.Serve(ln)
}

const (
	InvitePruneAge        = 7 * 24 * time.Hour
	MetricRequestPruneAge = 30 * 24 * time.Hour
)

func (s *Server) pruneStores(now time.Time) {
	if s.inviteStore != nil {
		if n, err := s.inviteStore.Prune(now, InvitePruneAge); err != nil {
			s.logger.Warn("invite prune failed", "err", err)
		} else if n > 0 {
			s.logger.Info("pruned terminal invites", "count", n)
		}
	}
	if s.metricRequests != nil {
		if n, err := s.metricRequests.PruneDecided(now.Add(-MetricRequestPruneAge)); err != nil {
			s.logger.Warn("metric request prune failed", "err", err)
		} else if n > 0 {
			s.logger.Info("pruned decided metric requests", "count", n)
		}
	}
}

func (s *Server) Shutdown(ctx context.Context) error {
	s.shutdownMu.Lock()
	fn := s.shutdownFn
	srv := s.httpServer
	s.shutdownMu.Unlock()

	var drainErr error
	if srv != nil {
		// Drain before cancelling: in-flight requests may still touch the sweepers.
		drainCtx, drainCancel := context.WithTimeout(context.Background(), 30*time.Second)
		defer drainCancel()
		drainErr = srv.Shutdown(drainCtx)
	}
	if fn != nil {
		fn()
	}
	return drainErr
}
