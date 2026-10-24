// Package server implements the PocketCmd HTTP API.
package server

import (
	"context"
	"crypto/ecdsa"
	"crypto/tls"
	"database/sql"
	"encoding/json"
	"log/slog"
	"net"
	"net/http"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/pocketcmd/pocketcmd-server/internal/authz"
	"github.com/pocketcmd/pocketcmd-server/internal/config"
	"github.com/pocketcmd/pocketcmd-server/internal/datasync"
	"github.com/pocketcmd/pocketcmd-server/internal/httperr"
	"github.com/pocketcmd/pocketcmd-server/internal/metrics"
	"github.com/pocketcmd/pocketcmd-server/internal/pair"
	"github.com/pocketcmd/pocketcmd-server/internal/pki"
	"github.com/pocketcmd/pocketcmd-server/internal/push"
	"github.com/pocketcmd/pocketcmd-server/internal/session"
)

type contextKey string

const contextKeyDeviceID = contextKey("device_id")

type Server struct {
	cfg         *config.ServerConfig
	mux         *http.ServeMux
	tlsConfig   *tls.Config
	listener    net.Listener
	httpServer  *http.Server
	shutdownMu  sync.Mutex
	logger      *slog.Logger
	auditLogger *slog.Logger // never nil: discards until SetAuditLogger
	logSource   LogSource
	shutdownFn  context.CancelFunc

	jwtManager     *session.Manager
	deviceRegistry *pki.DeviceRegistry
	userRegistry   *pki.UserRegistry
	serverKey      *ecdsa.PrivateKey
	certVerifier   *pki.ClientCertVerifier

	nonces             *pki.NonceStore
	pairingFingerprint string

	pairing *pair.PairingHandler

	inviteStore    *pki.InviteStore
	metricRequests *metrics.RequestStore

	stateDB *sql.DB

	pushStore *push.Store

	dataPurger DataPurger

	vaultRevoker VaultRevoker

	advertisedHost string

	rateLimiter            *DeviceRateLimiter
	challengePubKeyLimiter *DeviceRateLimiter

	capabilitiesVer string

	sshFetchCallback func(deviceID string)

	routePatterns []string

	sshOneShot atomic.Bool
	sshClaimed atomic.Bool
}

func NewServer(cfg *config.ServerConfig) *Server {
	s := &Server{
		cfg:                    cfg,
		mux:                    http.NewServeMux(),
		logger:                 slog.Default(),
		auditLogger:            slog.New(slog.DiscardHandler),
		rateLimiter:            NewDeviceRateLimiter(60, time.Minute),
		challengePubKeyLimiter: NewDeviceRateLimiter(10, time.Minute),
		nonces:                 pki.NewNonceStore(),
	}

	s.handle("GET /api/health",
		RateLimitMiddleware(s.rateLimiter, http.HandlerFunc(s.handleHealth)))
	s.handle("GET /api/config",
		RateLimitMiddleware(s.rateLimiter, http.HandlerFunc(s.handleAPIConfig)))
	s.handle("GET /api/capabilities",
		RateLimitMiddleware(s.rateLimiter, http.HandlerFunc(s.handleCapabilities)))
	s.handle("POST /api/cert/challenge",
		RateLimitMiddleware(s.rateLimiter, http.HandlerFunc(s.handleCertChallenge)))

	return s
}

func (s *Server) SetSecurityServices(jwt *session.Manager, registry *pki.DeviceRegistry, users *pki.UserRegistry, serverKey *ecdsa.PrivateKey) {
	s.jwtManager = jwt
	s.deviceRegistry = registry
	s.userRegistry = users
	s.serverKey = serverKey
	verifier, err := pki.NewClientCertVerifier(serverKey)
	if err != nil {
		panic("SetSecurityServices: client cert verifier: " + err.Error())
	}
	s.certVerifier = verifier

	mtls := func(h http.HandlerFunc) http.Handler {
		return s.requireMTLS(RateLimitMiddleware(s.rateLimiter, http.HandlerFunc(h)))
	}
	s.handle("POST /api/session", mtls(s.handleSession))
	// /api/cert/renew authenticates internally (mTLS or signed challenge).
	s.handle("POST /api/cert/renew",
		RateLimitMiddleware(s.rateLimiter, http.HandlerFunc(s.handleCertRenew)))

	s.handle("GET /api/host-keys", s.authed(http.HandlerFunc(s.handleHostKeys)))
	s.handle("POST /api/push/register", s.authed(http.HandlerFunc(s.handlePushRegister)))
}

func (s *Server) requireSecurityServices(caller string) {
	if s.jwtManager == nil {
		panic(caller + ": SetSecurityServices must be called first")
	}
}

func (s *Server) RegisterSSHRoutes() {
	s.requireSecurityServices("RegisterSSHRoutes")
	s.handle("GET /api/ssh-configs",
		s.authed(RequireRole(pki.RoleAdmin, http.HandlerFunc(s.handleSSHConfigs))))
}

func (s *Server) RegisterPairRoute(handler *pair.PairingHandler) {
	s.pairing = handler
	s.handle("POST /api/pair",
		RateLimitMiddleware(s.rateLimiter, http.HandlerFunc(handler.HandlePair)))
}

func (s *Server) RegisterTeamRoutes(users *pki.UserRegistry, devices *pki.DeviceRegistry, invites *pki.InviteStore) {
	s.requireSecurityServices("RegisterTeamRoutes")
	s.inviteStore = invites
	t := &teamHandlers{
		srv:     s,
		users:   users,
		devices: devices,
		invites: invites,
	}
	s.handle("POST /api/invites", s.memberRoute(t.handleCreateInvite))
	s.handle("GET /api/invites", s.memberRoute(t.handleListInvites))
	s.handle("DELETE /api/invites/{code}", s.memberRoute(t.handleRevokeInvite))
	s.handle("GET /api/users", s.memberRoute(t.handleListUsers))
	s.handle("PATCH /api/users/{id}", s.memberRoute(t.handlePatchUser))
	s.handle("DELETE /api/users/{id}", s.memberRoute(t.handleDeleteUser))
	s.handle("POST /api/users/{id}/transfer-ownership", s.ownerRoute(t.handleTransferOwnership))
	s.handle("GET /api/devices", s.memberRoute(t.handleListDevices))
	s.handle("PATCH /api/devices/{id}", s.memberRoute(t.handlePatchDevice))
	s.handle("DELETE /api/devices/{id}", s.memberRoute(t.handleDeleteDevice))
}

func (s *Server) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	s.mux.ServeHTTP(w, r)
}

func (s *Server) handle(pattern string, h http.Handler) {
	s.routePatterns = append(s.routePatterns, pattern)
	if !apiVersionExempt[pattern] {
		h = RequireAPIVersion(h)
	}
	s.mux.Handle(pattern, h)
}

type DataPurger interface {
	PurgeUserData(userID string, deviceIDs []string) (int64, error)
}

type VaultRevoker interface {
	VaultsForUser(userID string) ([]string, error)
	RevokeVault(vaultID, userID string) error
}

func (s *Server) installDeviceHooks(store *datasync.SyncStore) {
	if s.deviceRegistry != nil {
		registry := s.deviceRegistry
		store.ResolveDeviceUser = func(deviceID string) (string, bool) {
			if deviceID == "" {
				return "", false
			}
			dev, err := registry.FindByID(deviceID)
			if err != nil || dev == nil || dev.UserID == "" {
				return "", false
			}
			// Revoked devices must still resolve so their wraps can be tombstoned.
			return dev.UserID, true
		}
	}
	if s.userRegistry == nil {
		return
	}
	store.IsTeamAdmin = func(userID string) bool {
		u, err := s.userRegistry.FindByID(userID)
		if err != nil || u == nil || u.Status != pki.UserStatusActive {
			return false
		}
		return authz.IsOwner(u) || u.Role == pki.RoleAdmin
	}
}

func (s *Server) installSyncPolicy(store *datasync.SyncStore) {
	s.installDeviceHooks(store)
	if s.userRegistry == nil {
		return
	}
	lookup := func(userID string) *pki.UserRecord {
		u, err := s.userRegistry.FindByID(userID)
		if err != nil || u == nil {
			return nil
		}
		return u
	}
	store.AuthorizeWrite = func(userID string, old *datasync.SyncRecord, rec datasync.SyncRecord) bool {
		u := lookup(userID)
		switch rec.Type {
		case "ssh_key":
			return authz.Allowed(u, authz.PermSSHKeysSync)
		case "monitoring_config":
			var oldData json.RawMessage
			if old != nil {
				oldData = old.Data
			}
			for perm := range authz.MonitoringWritePermissions(oldData, rec.Data, rec.Deleted) {
				if !authz.Allowed(u, perm) {
					return false
				}
			}
			return true
		default:
			return true
		}
	}
	store.AuthorizeRead = func(userID string, recType string) bool {
		if recType != "monitoring_config" {
			return true
		}
		return authz.Allowed(lookup(userID), authz.PermMetricsCommandsRead)
	}
	store.OnWriteDenied = func(userID string, rec datasync.SyncRecord) {
		s.auditLogger.Info("sync_write_denied",
			"user_id", userID,
			"record_type", rec.Type,
			"record_id", rec.ID,
		)
	}
}

func (s *Server) RegisterSyncRoutes(store *datasync.SyncStore) {
	s.requireSecurityServices("RegisterSyncRoutes")
	s.dataPurger = store
	s.vaultRevoker = store
	s.installSyncPolicy(store)
	handler := datasync.NewSyncHandler(store)
	scoped := func(h http.HandlerFunc) http.HandlerFunc {
		return func(w http.ResponseWriter, r *http.Request) {
			ctx := r.Context()
			if uid := callerIDFrom(r); uid != "" {
				ctx = datasync.WithUserID(ctx, uid)
			}
			if did := deviceIDFrom(r); did != "" {
				ctx = datasync.WithDeviceID(ctx, did)
			}
			h(w, r.WithContext(ctx))
		}
	}
	s.handle("GET /api/sync/manifest", s.authed(scoped(handler.HandleManifest)))
	s.handle("POST /api/sync/pull", s.authed(scoped(handler.HandlePull)))
	s.handle("POST /api/sync/push", s.authed(scoped(handler.HandlePush)))
}

func (s *Server) RegisterMetricRoutes(api *metrics.MetricAPI) {
	s.requireSecurityServices("RegisterMetricRoutes")
	s.handle("GET /api/metrics/available", s.permRoute(authz.PermMetricsRead, api.HandleAvailable))
	s.handle("GET /api/metrics/latest", s.permRoute(authz.PermMetricsRead, api.HandleLatest))
	s.handle("GET /api/metrics/series", s.permRoute(authz.PermMetricsRead, api.HandleSeries))
}

func (s *Server) SetTLSConfig(cfg *tls.Config) {
	s.tlsConfig = cfg
}

func (s *Server) SetAuditLogger(logger *slog.Logger) {
	if logger == nil {
		logger = slog.New(slog.DiscardHandler)
	}
	s.auditLogger = logger
}

func (s *Server) SetLogSource(src LogSource) {
	s.logSource = src
}

func (s *Server) OnSSHConfigsFetch(fn func(deviceID string)) {
	s.sshFetchCallback = fn
}

func (s *Server) EnableSSHOneShot() {
	s.sshOneShot.Store(true)
}

func (s *Server) SetPairingFingerprint(fp string) {
	s.pairingFingerprint = fp
}

func (s *Server) SetAdvertisedHost(h string) { s.advertisedHost = h }

func (s *Server) SetStateDB(db *sql.DB) { s.stateDB = db }

func (s *Server) handleHealth(w http.ResponseWriter, r *http.Request) {
	status := "ok"
	checks := map[string]string{}

	if s.deviceRegistry != nil {
		checks["devices"] = "ok"
	}

	if s.tlsConfig != nil {
		checks["tls"] = "ok"
	} else {
		checks["tls"] = "not configured"
	}

	if s.stateDB != nil {
		ctx, cancel := context.WithTimeout(r.Context(), 2*time.Second)
		defer cancel()
		var one int
		if err := s.stateDB.QueryRowContext(ctx, "SELECT 1").Scan(&one); err != nil || one != 1 {
			s.logger.Error("health: state.db ping failed", "err", err)
			checks["db"] = "unavailable"
			httperr.WriteJSON(w, http.StatusServiceUnavailable, map[string]interface{}{
				"status": "degraded",
				"error":  "db_unavailable",
				"checks": checks,
			})
			return
		}
		checks["db"] = "ok"
	}

	httperr.WriteJSON(w, http.StatusOK, map[string]interface{}{
		"status": status,
		"checks": checks,
	})
}

func (s *Server) handleAPIConfig(w http.ResponseWriter, r *http.Request) {
	httperr.WriteJSON(w, http.StatusOK, map[string]interface{}{
		"pollIntervalMs": s.cfg.PollIntervalMs,
	})
}

func (s *Server) SetCapabilities(version string) {
	s.capabilitiesVer = version
}

// APIVersion is the wire-protocol version, always "<release major>.0"; bump
// the major on incompatible changes.
const APIVersion = "1.0"

func (s *Server) handleCapabilities(w http.ResponseWriter, r *http.Request) {
	httperr.WriteJSON(w, http.StatusOK, map[string]interface{}{
		"version":     s.capabilitiesVer,
		"api_version": APIVersion,
	})
}

func (s *Server) handleSession(w http.ResponseWriter, r *http.Request) {
	cert := peerCertificate(r)
	if cert == nil {
		httperr.JSON(w, http.StatusForbidden, "client_cert_required")
		return
	}
	certFP := pki.CertFingerprint(cert.Raw)

	pubPEM, err := pki.PublicKeyPEM(cert.PublicKey)
	if err != nil {
		httperr.JSON(w, http.StatusInternalServerError, "invalid_certificate")
		return
	}
	deviceID, err := pki.DeviceIDFromPublicKey(pubPEM)
	if err != nil {
		httperr.JSON(w, http.StatusInternalServerError, "invalid_certificate")
		return
	}
	if h := callerHolder(r.Context()); h != nil {
		h.deviceID = deviceID
	}

	dev, err := s.deviceRegistry.FindByID(deviceID)
	if err != nil || dev == nil || dev.Status != pki.DeviceStatusActive || !s.deviceUserActive(dev) {
		s.auditLogger.Info("session_denied",
			"device_id", deviceID,
			"reason", "device_or_user_inactive",
			"remote_addr", r.RemoteAddr,
		)
		httperr.JSON(w, http.StatusForbidden, "forbidden")
		return
	}

	token, err := s.jwtManager.Issue(deviceID, certFP)
	if err != nil {
		httperr.JSON(w, http.StatusInternalServerError, "internal_error")
		return
	}

	httperr.WriteJSON(w, http.StatusOK, map[string]interface{}{
		"token":      token,
		"expires_in": int(s.jwtManager.TTL().Seconds()),
	})
}

func (s *Server) handleSSHConfigs(w http.ResponseWriter, r *http.Request) {
	if s.sshOneShot.Load() {
		if !s.sshClaimed.CompareAndSwap(false, true) {
			httperr.JSON(w, http.StatusConflict, "already_fetched")
			return
		}
	}

	hosts, keys := pair.ParseSSHConfig()

	deviceID := deviceIDFrom(r)
	exportUserID := callerIDFrom(r)
	keyPaths := make([]string, 0, len(keys))
	for _, k := range keys {
		keyPaths = append(keyPaths, k.Path)
	}
	s.auditLogger.Info("ssh_configs_export",
		"device_id", deviceID,
		"user_id", exportUserID,
		"remote_addr", r.RemoteAddr,
		"host_count", len(hosts),
		"key_count", len(keys),
		"key_paths", keyPaths,
	)

	type apiHost struct {
		Name     string `json:"name"`
		Hostname string `json:"hostname"`
		Username string `json:"username,omitempty"`
		Port     int    `json:"port"`
		KeyRef   string `json:"key_ref,omitempty"`
	}
	type apiKey struct {
		Path      string `json:"path"`
		Content   string `json:"content"`
		Encrypted bool   `json:"encrypted"`
	}

	apiHosts := []apiHost{}
	for _, h := range hosts {
		apiHosts = append(apiHosts, apiHost{
			Name:     h.Name,
			Hostname: h.Hostname,
			Username: h.Username,
			Port:     h.Port,
			KeyRef:   h.KeyRef,
		})
	}

	apiKeys := []apiKey{}
	for _, k := range keys {
		encrypted := strings.Contains(k.Content, "ENCRYPTED")
		apiKeys = append(apiKeys, apiKey{
			Path:      k.Path,
			Content:   k.Content,
			Encrypted: encrypted,
		})
	}

	if err := httperr.WriteJSON(w, http.StatusOK, map[string]interface{}{
		"hosts": apiHosts,
		"keys":  apiKeys,
	}); err != nil {
		return
	}

	if s.sshFetchCallback != nil {
		s.sshFetchCallback(deviceID)
	}
}

func (s *Server) handlePushRegister(w http.ResponseWriter, r *http.Request) {
	var req struct {
		DeviceID    string `json:"device_id"`
		DeviceToken string `json:"device_token"`
		Platform    string `json:"platform"`
		SignedToken string `json:"signed_token"`
		ExpiresAt   int64  `json:"expires_at"`
	}
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, maxJSONBody)).Decode(&req); err != nil {
		httperr.JSON(w, http.StatusBadRequest, "invalid_body")
		return
	}
	if req.DeviceToken == "" || req.Platform == "" ||
		req.SignedToken == "" || req.ExpiresAt == 0 {
		httperr.JSON(w, http.StatusBadRequest, "missing_fields")
		return
	}
	// Always store under the authenticated device's id, never the client-sent one.
	callerDeviceID := deviceIDFrom(r)
	if callerDeviceID == "" {
		httperr.JSON(w, http.StatusForbidden, "forbidden")
		return
	}
	if req.DeviceID != "" && req.DeviceID != callerDeviceID {
		httperr.JSON(w, http.StatusForbidden, "device_id_mismatch")
		return
	}
	if s.pushStore == nil {
		httperr.JSON(w, http.StatusServiceUnavailable, "push_unavailable")
		return
	}
	err := s.pushStore.Upsert(push.PushRegistration{
		DeviceID:    callerDeviceID,
		DeviceToken: req.DeviceToken,
		Platform:    req.Platform,
		SignedToken: req.SignedToken,
		ExpiresAt:   req.ExpiresAt,
	})
	if err != nil {
		s.logger.Error("push register: write failed", "err", err)
		httperr.JSON(w, http.StatusInternalServerError, "store_error")
		return
	}
	httperr.WriteJSON(w, http.StatusOK, map[string]any{"status": "ok"})
}

func (s *Server) SetPushStore(store *push.Store) { s.pushStore = store }
