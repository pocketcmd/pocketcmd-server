package server

import (
	"context"
	"crypto/x509"
	"errors"
	"log/slog"
	"net/http"
	"strings"
	"time"

	"github.com/pocketcmd/pocketcmd-server/internal/httperr"
	"github.com/pocketcmd/pocketcmd-server/internal/pki"
	"github.com/pocketcmd/pocketcmd-server/internal/session"
)

const maxJSONBody = 64 * 1024

func BodyLimitMiddleware(limit int64, next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		r.Body = http.MaxBytesReader(w, r.Body, limit)
		next.ServeHTTP(w, r)
	})
}

const APIVersionHeader = "X-PocketCmd-Api-Version"

var apiVersionExempt = map[string]bool{
	"GET /api/health":       true,
	"GET /api/capabilities": true,
}

// RequireAPIVersion compares majors only: minors within a major are additive.
func RequireAPIVersion(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if apiMajor(r.Header.Get(APIVersionHeader)) != apiMajor(APIVersion) {
			httperr.WriteJSON(w, http.StatusBadRequest, map[string]string{
				"error":              "api_version_mismatch",
				"server_api_version": APIVersion,
			})
			return
		}
		next.ServeHTTP(w, r)
	})
}

func apiMajor(v string) string {
	major, _, _ := strings.Cut(v, ".")
	return major
}

func (s *Server) authed(h http.Handler) http.Handler {
	return s.requireJWT(RateLimitMiddleware(s.rateLimiter, h))
}

func (s *Server) memberRoute(h http.HandlerFunc) http.Handler {
	return s.authed(BodyLimitMiddleware(maxJSONBody, http.HandlerFunc(h)))
}

func (s *Server) adminRoute(h http.HandlerFunc) http.Handler {
	return s.authed(RequireRole(pki.RoleAdmin, BodyLimitMiddleware(maxJSONBody, http.HandlerFunc(h))))
}

func (s *Server) ownerRoute(h http.HandlerFunc) http.Handler {
	return s.authed(RequireOwner(BodyLimitMiddleware(maxJSONBody, http.HandlerFunc(h))))
}

func (s *Server) permRoute(perm string, h http.HandlerFunc) http.Handler {
	return s.authed(RequirePermission(perm, BodyLimitMiddleware(maxJSONBody, http.HandlerFunc(h))))
}

type statusWriter struct {
	http.ResponseWriter
	status int
}

func (w *statusWriter) WriteHeader(code int) {
	w.status = code
	w.ResponseWriter.WriteHeader(code)
}

// Planted by LoggingMiddleware so the inner auth middlewares can report the caller back out.
type requestCaller struct {
	deviceID    string
	userID      string
	displayName string
}

const contextKeyRequestCaller = contextKey("request_caller")

func callerHolder(ctx context.Context) *requestCaller {
	h, _ := ctx.Value(contextKeyRequestCaller).(*requestCaller)
	return h
}

func LoggingMiddleware(logger *slog.Logger, next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/api/health" {
			next.ServeHTTP(w, r)
			return
		}

		caller := &requestCaller{}
		r = r.WithContext(
			context.WithValue(r.Context(), contextKeyRequestCaller, caller))

		start := time.Now()
		sw := &statusWriter{ResponseWriter: w, status: http.StatusOK}
		next.ServeHTTP(sw, r)
		latency := time.Since(start)

		attrs := []any{
			"method", r.Method,
			"path", logPath(r.URL.Path),
			"status", sw.status,
			"latency_ms", latency.Milliseconds(),
			"remote", r.RemoteAddr,
		}
		if caller.deviceID != "" {
			attrs = append(attrs, "device_id", caller.deviceID)
		}
		if caller.userID != "" {
			attrs = append(attrs, "user_id", caller.userID)
		}
		if caller.displayName != "" {
			attrs = append(attrs, "user", caller.displayName)
		}

		if sw.status >= 500 {
			logger.Error("request", attrs...)
		} else if sw.status >= 400 {
			logger.Warn("request", attrs...)
		} else {
			logger.Info("request", attrs...)
		}
	})
}

// Invite codes are bearer credentials, so logged paths carry only the prefix.
func logPath(p string) string {
	const invites = "/api/invites/"
	if !strings.HasPrefix(p, invites) {
		return p
	}
	rest := p[len(invites):]
	code, tail, _ := strings.Cut(rest, "/")
	if len(code) <= pki.InviteCodePrefixLen {
		return p
	}
	masked := invites + pki.InviteCodePrefix(code) + "…"
	if tail != "" {
		masked += "/" + tail
	}
	return masked
}

func (s *Server) requireJWT(next http.Handler) http.Handler {
	return RequireJWT(s.jwtManager, s.deviceRegistry, s.certVerifier, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		deviceID := deviceIDFrom(r)
		u, err := ResolveUser(deviceID, s.deviceRegistry, s.userRegistry)
		if err != nil {
			s.auditLogger.Info("user_resolve_denied",
				"device_id", deviceID,
				"reason", err.Error(),
				"remote_addr", r.RemoteAddr,
			)
			httperr.JSON(w, http.StatusForbidden, "forbidden")
			return
		}
		_ = s.deviceRegistry.TouchLastSeen(deviceID, time.Hour)
		if h := callerHolder(r.Context()); h != nil {
			h.userID = u.UserID
			h.displayName = u.DisplayName
		}
		r = r.WithContext(withUserContext(r.Context(), u))
		next.ServeHTTP(w, r)
	}))
}

func peerCertificate(r *http.Request) *x509.Certificate {
	if r.TLS == nil || len(r.TLS.PeerCertificates) == 0 {
		return nil
	}
	return r.TLS.PeerCertificates[0]
}

func (s *Server) requireMTLS(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		cert := peerCertificate(r)
		if cert == nil {
			httperr.JSON(w, http.StatusForbidden, "client_cert_required")
			return
		}

		if s.deviceRegistry != nil && !s.deviceRegistry.IsAllowedByCert(cert.Raw) {
			httperr.JSON(w, http.StatusForbidden, "device_not_registered")
			return
		}
		if !peerCertValid(w, s.certVerifier, cert) {
			return
		}

		next.ServeHTTP(w, r)
	})
}

func peerCertValid(w http.ResponseWriter, verifier *pki.ClientCertVerifier, cert *x509.Certificate) bool {
	if verifier == nil {
		httperr.JSON(w, http.StatusUnauthorized, "client_cert_invalid")
		return false
	}
	switch err := verifier.Verify(cert, time.Now()); {
	case err == nil:
		return true
	case errors.Is(err, pki.ErrClientCertExpired):
		httperr.JSON(w, http.StatusUnauthorized, "client_cert_expired")
	default:
		httperr.JSON(w, http.StatusUnauthorized, "client_cert_invalid")
	}
	return false
}

func RequireJWT(mgr *session.Manager, registry *pki.DeviceRegistry, verifier *pki.ClientCertVerifier, next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		cert := peerCertificate(r)
		if cert == nil {
			httperr.JSON(w, http.StatusUnauthorized, "client_cert_required")
			return
		}

		if registry != nil && !registry.IsAllowedByCert(cert.Raw) {
			httperr.JSON(w, http.StatusForbidden, "device_not_registered")
			return
		}
		if !peerCertValid(w, verifier, cert) {
			return
		}

		authHeader := r.Header.Get("Authorization")
		if !strings.HasPrefix(authHeader, "Bearer ") {
			httperr.JSON(w, http.StatusUnauthorized, "authorization_required")
			return
		}
		tokenStr := strings.TrimPrefix(authHeader, "Bearer ")

		certFP := pki.CertFingerprint(cert.Raw)
		claims, err := mgr.Validate(tokenStr, certFP)
		if err != nil {
			httperr.JSON(w, http.StatusUnauthorized, "invalid_token")
			return
		}

		if h := callerHolder(r.Context()); h != nil {
			h.deviceID = claims.DeviceID
		}
		ctx := context.WithValue(r.Context(), contextKeyDeviceID, claims.DeviceID)
		next.ServeHTTP(w, r.WithContext(ctx))
	})
}
