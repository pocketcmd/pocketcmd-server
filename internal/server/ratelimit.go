package server

import (
	"net"
	"net/http"
	"sync"
	"time"

	"github.com/pocketcmd/pocketcmd-server/internal/httperr"
)

type DeviceRateLimiter struct {
	mu     sync.Mutex
	counts map[string]*rateBucket
	limit  int
	window time.Duration
}

type rateBucket struct {
	count       int
	windowStart time.Time
}

func NewDeviceRateLimiter(limit int, window time.Duration) *DeviceRateLimiter {
	return &DeviceRateLimiter{
		counts: make(map[string]*rateBucket),
		limit:  limit,
		window: window,
	}
}

func (rl *DeviceRateLimiter) Allow(deviceID string) bool {
	rl.mu.Lock()
	defer rl.mu.Unlock()

	now := time.Now()
	bucket, exists := rl.counts[deviceID]
	if !exists || now.Sub(bucket.windowStart) > rl.window {
		rl.counts[deviceID] = &rateBucket{count: 1, windowStart: now}
		return true
	}

	bucket.count++
	return bucket.count <= rl.limit
}

func (rl *DeviceRateLimiter) Cleanup() {
	rl.mu.Lock()
	defer rl.mu.Unlock()
	now := time.Now()
	for id, bucket := range rl.counts {
		if now.Sub(bucket.windowStart) > rl.window {
			delete(rl.counts, id)
		}
	}
}

// On authenticated routes this must sit inside the JWT middleware so it keys on the device id.
func RateLimitMiddleware(rl *DeviceRateLimiter, next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		deviceID := deviceIDFrom(r)
		if deviceID == "" {
			host, _, err := net.SplitHostPort(r.RemoteAddr)
			if err != nil {
				host = r.RemoteAddr
			}
			deviceID = host
		}

		if !rl.Allow(deviceID) {
			httperr.JSON(w, http.StatusTooManyRequests, "rate_limited")
			return
		}

		next.ServeHTTP(w, r)
	})
}
