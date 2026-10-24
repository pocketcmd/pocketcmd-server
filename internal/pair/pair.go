// Package pair implements the /api/pair device pairing endpoint.
package pair

import (
	"crypto/ecdsa"
	"crypto/rand"
	"crypto/subtle"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/pocketcmd/pocketcmd-server/internal/authz"
	"github.com/pocketcmd/pocketcmd-server/internal/datasync"
	"github.com/pocketcmd/pocketcmd-server/internal/httperr"
	"github.com/pocketcmd/pocketcmd-server/internal/pki"
)

const (
	DefaultTokenTTL = 60 * time.Second
	DefaultCertTTL  = pki.ClientCertTTL
	MaxPairAttempts = 3
	RateLimitWindow = 60 * time.Second
	maxPairBody     = 64 << 10
)

type PairCredential struct {
	Kind  string `json:"kind"`  // "bootstrap" | "invite"
	Token string `json:"token"` // bootstrap pairing_token OR invite code
}

type PairRequest struct {
	DevicePublicKey string         `json:"device_public_key"`
	DeviceName      string         `json:"device_name"`
	DeviceLabel     string         `json:"device_label,omitempty"`
	CSR             string         `json:"csr"`
	Credential      PairCredential `json:"credential"`
	DisplayName     string         `json:"display_name,omitempty"`
}

type PairResponse struct {
	DeviceID          string `json:"device_id"`
	ClientCert        string `json:"client_cert"`
	ExpiresAt         string `json:"expires_at"`
	ServerURL         string `json:"server_url"`
	ServerFingerprint string `json:"server_fingerprint"`
	Hostname          string `json:"hostname"`
	UserID            string `json:"user_id"`
	UserDisplayName   string `json:"user_display_name"`
	UserRole          string `json:"user_role"` // admin|member
	UserOwner         bool   `json:"user_owner"`
	// SSHHostKeys carries the machine's SSH host-key SHA-256 fingerprints.
	SSHHostKeys []string `json:"ssh_host_keys,omitempty"`
}

type pairingToken struct {
	token     string
	expiresAt time.Time
	used      bool
}

type rateLimitEntry struct {
	attempts  int
	windowEnd time.Time
}

type PairingHandler struct {
	registry          *pki.DeviceRegistry
	userRegistry      *pki.UserRegistry
	inviteStore       *pki.InviteStore
	serverKey         *ecdsa.PrivateKey
	serverFingerprint string
	hostname          string
	serverURL         string
	tokenTTL          time.Duration
	auditLogger       *slog.Logger

	now func() time.Time

	mu            sync.Mutex
	activeToken   *pairingToken
	rateLimits    map[string]*rateLimitEntry
	onPairSuccess func(deviceID, deviceName string)
}

func NewPairingHandler(
	registry *pki.DeviceRegistry,
	users *pki.UserRegistry,
	invites *pki.InviteStore,
	serverKey *ecdsa.PrivateKey,
	serverFingerprint, hostname, serverURL string,
) *PairingHandler {
	if registry == nil || users == nil || invites == nil {
		panic("NewPairingHandler: registry, users, and invites are required")
	}
	return &PairingHandler{
		registry:          registry,
		userRegistry:      users,
		inviteStore:       invites,
		serverKey:         serverKey,
		serverFingerprint: serverFingerprint,
		hostname:          hostname,
		serverURL:         serverURL,
		tokenTTL:          DefaultTokenTTL,
		auditLogger:       slog.New(slog.DiscardHandler),
		now:               time.Now,
		rateLimits:        make(map[string]*rateLimitEntry),
	}
}

func (h *PairingHandler) SetAuditLogger(l *slog.Logger) {
	if l == nil {
		l = slog.New(slog.DiscardHandler)
	}
	h.auditLogger = l
}

func (h *PairingHandler) OnPairSuccess(fn func(deviceID, deviceName string)) {
	h.mu.Lock()
	defer h.mu.Unlock()
	h.onPairSuccess = fn
}

func (h *PairingHandler) GeneratePairingToken() string {
	h.mu.Lock()
	defer h.mu.Unlock()
	token := randomHex(16)
	h.activeToken = &pairingToken{
		token:     token,
		expiresAt: h.now().Add(h.tokenTTL),
	}
	return token
}

func (h *PairingHandler) TokenTTL() time.Duration {
	return h.tokenTTL
}

func (h *PairingHandler) HandlePair(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		httperr.JSON(w, http.StatusMethodNotAllowed, "method_not_allowed")
		return
	}

	var req PairRequest
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, maxPairBody)).Decode(&req); err != nil {
		httperr.JSON(w, http.StatusBadRequest, "invalid_body")
		return
	}

	switch req.Credential.Kind {
	case "bootstrap":
		h.handleBootstrapPair(w, r, &req)
	case "invite":
		h.handleInvitePair(w, r, &req)
	default:
		httperr.JSON(w, http.StatusBadRequest, "credential_kind_required")
	}
}

func (h *PairingHandler) csrBoundToDevice(w http.ResponseWriter, req *PairRequest) bool {
	if err := pki.ValidateDevicePublicKey(req.DevicePublicKey); err != nil {
		httperr.JSON(w, http.StatusBadRequest, "invalid_public_key")
		return false
	}
	csrPub, err := pki.ParsePublicKeyFromCSR([]byte(req.CSR))
	if err != nil {
		httperr.JSON(w, http.StatusBadRequest, "invalid_csr")
		return false
	}
	if !pki.PublicKeysEqual(csrPub, req.DevicePublicKey) {
		httperr.JSON(w, http.StatusBadRequest, "csr_key_mismatch")
		return false
	}
	return true
}

func validDeviceFields(w http.ResponseWriter, req *PairRequest) bool {
	if !pki.ValidDeviceName(req.DeviceName) || !pki.ValidDeviceName(req.DeviceLabel) {
		httperr.JSON(w, http.StatusBadRequest, "name_too_long")
		return false
	}
	return true
}

type pairError struct {
	status int
	code   string
}

func refuse(status int, code string) *pairError {
	return &pairError{status: status, code: code}
}

func (e *pairError) write(w http.ResponseWriter) { httperr.JSON(w, e.status, e.code) }

func (h *PairingHandler) validatePairRequest(w http.ResponseWriter, req *PairRequest) bool {
	if req.DevicePublicKey == "" || req.DeviceName == "" || req.CSR == "" {
		httperr.JSON(w, http.StatusBadRequest, "invalid_body")
		return false
	}
	if !h.csrBoundToDevice(w, req) {
		return false
	}
	return validDeviceFields(w, req)
}

func validateDisplayName(name string) *pairError {
	if name == "" {
		return refuse(http.StatusBadRequest, "display_name_required")
	}
	if !pki.ValidDisplayName(name) {
		return refuse(http.StatusBadRequest, "display_name_too_long")
	}
	return nil
}

func (h *PairingHandler) notifyPaired(deviceID, deviceName string) {
	h.mu.Lock()
	cb := h.onPairSuccess
	h.mu.Unlock()
	if cb != nil {
		cb(deviceID, deviceName)
	}
}

func (h *PairingHandler) handleBootstrapPair(w http.ResponseWriter, r *http.Request, req *PairRequest) {
	clientIP := extractIP(r)

	if !h.validatePairRequest(w, req) {
		return
	}

	if h.registry.IsAllowedByPubKey(req.DevicePublicKey) {
		h.issueAndRespondWithUser(w, req)
		return
	}

	if h.isRateLimited(clientIP) {
		slog.Warn("pair rate limited", "remote", r.RemoteAddr)
		httperr.JSON(w, http.StatusTooManyRequests, "rate_limited")
		return
	}
	if pe := h.refuseInactiveBootstrapKey(req, clientIP); pe != nil {
		pe.write(w)
		return
	}
	if pe := validateDisplayName(req.DisplayName); pe != nil {
		pe.write(w)
		return
	}

	userRec, deviceID, pe := h.bootstrapTeam(req, clientIP, r.RemoteAddr)
	if pe != nil {
		pe.write(w)
		return
	}

	certPEM, expiresAt, signErr := h.signCSR(req.CSR)
	if signErr != nil {
		slog.Error("bootstrap pair: cert signing failed", "err", signErr)
		httperr.JSON(w, http.StatusInternalServerError, "cert_signing_failed")
		return
	}

	h.writeFullResponse(w, deviceID, certPEM, expiresAt, userRec)

	slog.Info("device paired", "device_id", deviceID, "device_name", req.DeviceName, "remote", r.RemoteAddr, "via", "bootstrap")
	h.emitBootstrapAudit(userRec, deviceID)
	h.notifyPaired(deviceID, req.DeviceName)
}

func (h *PairingHandler) refuseInactiveBootstrapKey(req *PairRequest, clientIP string) *pairError {
	dev, found := h.registry.LookupByPublicKeyPEM(req.DevicePublicKey)
	if !found || dev.Status == pki.DeviceStatusActive {
		return nil
	}
	h.recordFailedAttempt(clientIP)
	code := "device_revoked"
	if dev.Status == pki.DeviceStatusLeft {
		code = "device_left"
	}
	h.auditLogger.Info("bootstrap_pair_blocked_inactive_device",
		"device_id", dev.DeviceID,
		"user_id", dev.UserID,
		"status", dev.Status,
	)
	return refuse(http.StatusForbidden, code)
}

func (h *PairingHandler) bootstrapTeam(req *PairRequest, clientIP, remoteAddr string) (*pki.UserRecord, string, *pairError) {
	h.mu.Lock()
	defer h.mu.Unlock()

	tokenValid := h.activeToken != nil &&
		subtle.ConstantTimeCompare([]byte(h.activeToken.token), []byte(req.Credential.Token)) == 1 &&
		!h.activeToken.used &&
		h.now().Before(h.activeToken.expiresAt)
	if !tokenValid {
		h.recordFailedAttemptLocked(clientIP)
		slog.Warn("pair auth failed", "remote", remoteAddr)
		return nil, "", refuse(http.StatusUnauthorized, "invalid_pairing_token")
	}

	if users, err := h.userRegistry.List(); err == nil {
		for _, u := range users {
			if u.Status == pki.UserStatusActive {
				return nil, "", refuse(http.StatusForbidden, "bootstrap_not_allowed")
			}
		}
	}

	userRec, err := h.userRegistry.Create(req.DisplayName, pki.RoleAdmin, "")
	if err != nil {
		slog.Error("bootstrap pair: user creation failed", "err", err)
		return nil, "", refuse(http.StatusInternalServerError, "store_error")
	}
	if err := h.userRegistry.SetOwner(userRec.UserID, true); err != nil {
		slog.Error("bootstrap pair: set owner failed", "err", err)
		return nil, "", refuse(http.StatusInternalServerError, "store_error")
	}
	userRec.Owner = true

	deviceID, err := h.registry.RegisterDeviceForUser(req.DevicePublicKey, req.DeviceName, userRec.UserID, req.DeviceLabel)
	if err != nil {
		slog.Error("bootstrap pair: device registration failed", "err", err)
		return nil, "", refuse(http.StatusInternalServerError, "registration_failed")
	}

	// Consume the token before unlocking.
	h.activeToken.used = true
	delete(h.rateLimits, clientIP)
	return userRec, deviceID, nil
}

func (h *PairingHandler) emitBootstrapAudit(userRec *pki.UserRecord, deviceID string) {
	h.auditLogger.Info("user_created",
		"user_id", userRec.UserID,
		"role", userRec.Role,
		"display_name", userRec.DisplayName,
		"created_by", "",
		"via", "bootstrap",
	)
	h.auditLogger.Info("device_registered",
		"device_id", deviceID,
		"user_id", userRec.UserID,
		"via", "bootstrap",
	)
}

func (h *PairingHandler) handleInvitePair(w http.ResponseWriter, r *http.Request, req *PairRequest) {
	clientIP := extractIP(r)

	if !h.validatePairRequest(w, req) {
		return
	}
	if h.isRateLimited(clientIP) {
		slog.Warn("invite pair rate limited", "remote", r.RemoteAddr)
		httperr.JSON(w, http.StatusTooManyRequests, "rate_limited")
		return
	}

	inv, activeDev, ownRedemption, pe := h.resolveInvite(req, clientIP)
	if pe != nil {
		pe.write(w)
		return
	}

	if activeDev != nil {
		h.repairActiveDevice(w, r, req, inv, activeDev, ownRedemption)
		return
	}

	leftDev, pe := h.leftDeviceFor(req, inv, clientIP)
	if pe != nil {
		pe.write(w)
		return
	}
	targetUser, pe := h.resolveInviteUser(inv, req)
	if pe != nil {
		pe.write(w)
		return
	}

	certPEM, expiresAt, signErr := h.signCSR(req.CSR)
	if signErr != nil {
		slog.Error("invite pair: cert signing failed", "err", signErr)
		httperr.JSON(w, http.StatusInternalServerError, "cert_signing_failed")
		return
	}

	deviceID, pe := h.claimInvite(inv, req, clientIP)
	if pe != nil {
		pe.write(w)
		return
	}
	userRec, previousUserID, pe := h.redeemInvite(inv, req, targetUser, leftDev, deviceID)
	if pe != nil {
		pe.write(w)
		return
	}

	h.writeFullResponse(w, deviceID, certPEM, expiresAt, userRec)

	slog.Info("device paired", "device_id", deviceID, "device_name", req.DeviceName, "remote", r.RemoteAddr, "via", "invite",
		"rejoined", leftDev != nil)
	h.emitInviteAudit(inv, userRec, deviceID, targetUser == nil, leftDev != nil, previousUserID)
	h.notifyPaired(deviceID, req.DeviceName)
}

func (h *PairingHandler) resolveInvite(req *PairRequest, clientIP string) (inv *pki.InviteRecord, activeDev *pki.DeviceRecord, ownRedemption bool, pe *pairError) {
	inv, err := h.inviteStore.FindByCode(req.Credential.Token)
	if err != nil {
		slog.Error("invite lookup failed", "err", err)
		return nil, nil, false, refuse(http.StatusInternalServerError, "store_error")
	}
	if inv == nil {
		h.recordFailedAttempt(clientIP)
		return nil, nil, false, refuse(http.StatusNotFound, "invite_not_found")
	}

	if dev, found := h.registry.LookupByPublicKeyPEM(req.DevicePublicKey); found && dev.Status == pki.DeviceStatusActive {
		activeDev = dev
		ownRedemption = inv.ConsumedAt != "" && inv.RevokedAt == "" &&
			inv.ConsumedByDeviceID == dev.DeviceID
	}

	if inv.ConsumedAt != "" && !ownRedemption {
		h.recordFailedAttempt(clientIP)
		return nil, nil, false, refuse(http.StatusConflict, "invite_consumed")
	}
	if inv.RevokedAt != "" {
		h.recordFailedAttempt(clientIP)
		return nil, nil, false, refuse(http.StatusGone, "invite_revoked")
	}
	if !ownRedemption && !inv.IsActive(h.now()) {
		h.recordFailedAttempt(clientIP)
		return nil, nil, false, refuse(http.StatusGone, "invite_expired")
	}

	if inv.PinnedFingerprint != "" {
		got, fpErr := pki.PubKeyFingerprint(req.DevicePublicKey)
		if fpErr != nil {
			return nil, nil, false, refuse(http.StatusBadRequest, "invalid_public_key")
		}
		if !strings.EqualFold(got, inv.PinnedFingerprint) {
			h.recordFailedAttempt(clientIP)
			return nil, nil, false, refuse(http.StatusForbidden, "device_pin_mismatch")
		}
	}
	return inv, activeDev, ownRedemption, nil
}

// A left key may pair again through an invite; a revoked key never does.
func (h *PairingHandler) leftDeviceFor(req *PairRequest, inv *pki.InviteRecord, clientIP string) (*pki.DeviceRecord, *pairError) {
	existingDev, found := h.registry.LookupByPublicKeyPEM(req.DevicePublicKey)
	if !found {
		return nil, nil
	}
	switch existingDev.Status {
	case pki.DeviceStatusLeft:
		return existingDev, nil
	case pki.DeviceStatusActive:
		return nil, nil
	default:
		h.recordFailedAttempt(clientIP)
		h.auditLogger.Info("invite_pair_blocked_revoked_device",
			"device_id", existingDev.DeviceID,
			"user_id", existingDev.UserID,
			"status", existingDev.Status,
			"invite_id", pki.InviteCodePrefix(inv.Code),
		)
		return nil, refuse(http.StatusForbidden, "device_revoked")
	}
}

func (h *PairingHandler) resolveInviteUser(inv *pki.InviteRecord, req *PairRequest) (*pki.UserRecord, *pairError) {
	if inv.TargetUserID == "" {
		return nil, validateDisplayName(req.DisplayName)
	}
	userRec, err := h.userRegistry.FindByID(inv.TargetUserID)
	if err != nil {
		slog.Error("invite pair: user lookup failed", "err", err)
		return nil, refuse(http.StatusInternalServerError, "store_error")
	}
	if userRec == nil || userRec.Status != pki.UserStatusActive {
		return nil, refuse(http.StatusForbidden, "target_user_not_found")
	}
	return userRec, nil
}

// MarkConsumed is the only redemption gate that cannot race, so it runs before any user or device is created.
func (h *PairingHandler) claimInvite(inv *pki.InviteRecord, req *PairRequest, clientIP string) (string, *pairError) {
	deviceID, fpErr := pki.DeviceIDFromPublicKey(req.DevicePublicKey)
	if fpErr != nil {
		return "", refuse(http.StatusBadRequest, "invalid_public_key")
	}
	switch consumeErr := h.inviteStore.MarkConsumed(inv.Code, deviceID); {
	case consumeErr == nil:
		return deviceID, nil
	case errors.Is(consumeErr, pki.ErrInviteNotRedeemable):
		h.recordFailedAttempt(clientIP)
		return "", refuse(http.StatusConflict, "invite_consumed")
	case errors.Is(consumeErr, pki.ErrInviteNotFound):
		return "", refuse(http.StatusNotFound, "invite_not_found")
	default:
		slog.Error("invite pair: consume failed", "err", consumeErr)
		return "", refuse(http.StatusInternalServerError, "store_error")
	}
}

func (h *PairingHandler) unclaimInvite(inv *pki.InviteRecord, deviceID string) {
	if err := h.inviteStore.UnmarkConsumed(inv.Code, deviceID); err != nil {
		slog.Error("failed to un-consume invite after pair failure",
			"code_prefix", pki.InviteCodePrefix(inv.Code), "err", err)
	}
}

func (h *PairingHandler) redeemInvite(inv *pki.InviteRecord, req *PairRequest, targetUser *pki.UserRecord, leftDev *pki.DeviceRecord, deviceID string) (userRec *pki.UserRecord, previousUserID string, pe *pairError) {
	userRec = targetUser
	newUserCreated := targetUser == nil
	if newUserCreated {
		var err error
		userRec, err = h.userRegistry.Create(req.DisplayName, inv.Role, inv.CreatedByUserID)
		if err != nil {
			slog.Error("invite pair: user creation failed", "err", err)
			h.unclaimInvite(inv, deviceID)
			return nil, "", refuse(http.StatusInternalServerError, "store_error")
		}
		if userRec.Role == pki.RoleMember {
			defaults := authz.DefaultMemberPermissions()
			if err := h.userRegistry.SetPermissions(userRec.UserID, defaults); err != nil {
				slog.Error("invite pair: default permissions failed", "err", err)
				h.unclaimInvite(inv, deviceID)
				return nil, "", refuse(http.StatusInternalServerError, "store_error")
			}
			userRec.Permissions = defaults
		}
	}

	if leftDev != nil {
		prev, status, code := h.reactivateLeftDevice(leftDev, userRec, req)
		if code != "" {
			h.unclaimInvite(inv, deviceID)
			if newUserCreated {
				if err := h.userRegistry.Revoke(userRec.UserID); err != nil {
					slog.Error("invite pair: abandoning the new user failed",
						"user_id", userRec.UserID, "err", err)
				}
			}
			return nil, "", refuse(status, code)
		}
		return userRec, prev, nil
	}
	if _, err := h.registry.RegisterDeviceForUser(req.DevicePublicKey, req.DeviceName, userRec.UserID, req.DeviceLabel); err != nil {
		slog.Error("invite pair: device registration failed", "err", err)
		h.unclaimInvite(inv, deviceID)
		return nil, "", refuse(http.StatusInternalServerError, "registration_failed")
	}
	return userRec, "", nil
}

func (h *PairingHandler) emitInviteAudit(inv *pki.InviteRecord, userRec *pki.UserRecord, deviceID string, newUserCreated, rejoined bool, previousUserID string) {
	if newUserCreated {
		h.auditLogger.Info("user_created",
			"user_id", userRec.UserID,
			"role", userRec.Role,
			"display_name", userRec.DisplayName,
			"created_by", inv.CreatedByUserID,
			"via", "invite_redemption",
		)
	}
	if rejoined {
		h.auditLogger.Info("device_reactivated",
			"device_id", deviceID,
			"user_id", userRec.UserID,
			"previous_user_id", previousUserID,
			"previous_status", pki.DeviceStatusLeft,
			"via", "invite",
		)
	} else {
		h.auditLogger.Info("device_registered",
			"device_id", deviceID,
			"user_id", userRec.UserID,
			"via", "invite",
		)
	}
	h.auditLogger.Info("invite_consumed",
		"invite_id", pki.InviteCodePrefix(inv.Code),
		"device_id", deviceID,
		"user_id", userRec.UserID,
		"pin_matched", inv.PinnedFingerprint != "",
	)
}

func (h *PairingHandler) reactivateLeftDevice(dev *pki.DeviceRecord, userRec *pki.UserRecord, req *PairRequest) (previousUserID string, status int, code string) {
	var cleared int64
	err := h.registry.Reactivate(dev.DeviceID, userRec.UserID, req.DeviceName, req.DeviceLabel,
		func(tx *sql.Tx, prev string) error {
			previousUserID = prev
			if prev == userRec.UserID {
				return nil
			}
			n, err := datasync.ResetDeviceKeyRecords(tx, dev.DeviceID)
			cleared = n
			return err
		})
	switch {
	case err == nil:
		if previousUserID != userRec.UserID {
			h.auditLogger.Info("device_key_records_reset",
				"device_id", dev.DeviceID,
				"previous_user_id", previousUserID,
				"user_id", userRec.UserID,
				"records_removed", cleared,
			)
		}
		return previousUserID, 0, ""
	case errors.Is(err, pki.ErrDeviceNotLeft):
		if cur, findErr := h.registry.FindByID(dev.DeviceID); findErr == nil &&
			cur.Status == pki.DeviceStatusRevoked {
			return "", http.StatusForbidden, "device_revoked"
		}
		return "", http.StatusConflict, "device_already_paired"
	default:
		slog.Error("invite pair: re-activating a left device failed",
			"device_id", dev.DeviceID, "err", err)
		return "", http.StatusInternalServerError, "registration_failed"
	}
}

func (h *PairingHandler) repairActiveDevice(w http.ResponseWriter, r *http.Request, req *PairRequest, inv *pki.InviteRecord, dev *pki.DeviceRecord, ownRedemption bool) {
	refuse := func(reason string) {
		h.auditLogger.Info("invite_pair_blocked_already_paired",
			"device_id", dev.DeviceID,
			"user_id", dev.UserID,
			"invite_id", pki.InviteCodePrefix(inv.Code),
			"reason", reason,
		)
		httperr.JSON(w, http.StatusConflict, "device_already_paired")
	}

	if inv.TargetUserID != "" && inv.TargetUserID != dev.UserID {
		refuse("invite_targets_other_user")
		return
	}
	userRec, err := h.userRegistry.FindByID(dev.UserID)
	if err != nil {
		slog.Error("invite re-pair: user lookup failed", "err", err)
		httperr.JSON(w, http.StatusInternalServerError, "store_error")
		return
	}
	if userRec == nil || userRec.Status != pki.UserStatusActive {
		refuse("device_user_inactive")
		return
	}

	certPEM, expiresAt, signErr := h.signCSR(req.CSR)
	if signErr != nil {
		slog.Error("invite re-pair: cert signing failed", "err", signErr)
		httperr.JSON(w, http.StatusInternalServerError, "cert_signing_failed")
		return
	}

	consumed := false
	if !ownRedemption && inv.TargetUserID == dev.UserID {
		switch consumeErr := h.inviteStore.MarkConsumed(inv.Code, dev.DeviceID); {
		case consumeErr == nil:
			consumed = true
		case errors.Is(consumeErr, pki.ErrInviteNotRedeemable):
			// The re-pair never depended on the invite, so it stands.
		default:
			slog.Error("invite re-pair: retiring the invite failed",
				"code_prefix", pki.InviteCodePrefix(inv.Code), "err", consumeErr)
		}
	}

	h.writeFullResponse(w, dev.DeviceID, certPEM, expiresAt, userRec)

	slog.Info("device re-paired", "device_id", dev.DeviceID, "device_name", req.DeviceName, "remote", r.RemoteAddr, "via", "invite")
	h.auditLogger.Info("invite_pair_reused_registration",
		"device_id", dev.DeviceID,
		"user_id", dev.UserID,
		"invite_id", pki.InviteCodePrefix(inv.Code),
		"invite_consumed", consumed,
		"own_redemption_retry", ownRedemption,
	)

	h.notifyPaired(dev.DeviceID, req.DeviceName)
}

func (h *PairingHandler) signCSR(csrPEM string) (certPEM string, expiresAt string, err error) {
	raw, signErr := pki.SignCSR([]byte(csrPEM), h.serverKey, DefaultCertTTL)
	if signErr != nil {
		return "", "", signErr
	}
	return string(raw), h.now().Add(DefaultCertTTL).UTC().Format(time.RFC3339), nil
}

func (h *PairingHandler) writeFullResponse(w http.ResponseWriter, deviceID, certPEM, expiresAt string, userRec *pki.UserRecord) {
	resp := PairResponse{
		DeviceID:          deviceID,
		ClientCert:        certPEM,
		ExpiresAt:         expiresAt,
		ServerURL:         h.serverURL,
		ServerFingerprint: h.serverFingerprint,
		Hostname:          h.hostname,
	}
	resp.SSHHostKeys = pki.MachineSSHHostKeyFingerprints()
	if userRec != nil {
		resp.UserID = userRec.UserID
		resp.UserDisplayName = userRec.DisplayName
		resp.UserRole = userRec.Role
		resp.UserOwner = userRec.Owner
	}
	httperr.WriteJSON(w, http.StatusOK, resp)
}

func (h *PairingHandler) issueAndRespondWithUser(w http.ResponseWriter, req *PairRequest) {
	var userRec *pki.UserRecord
	deviceID, err := pki.DeviceIDFromPublicKey(req.DevicePublicKey)
	if err == nil {
		if dev, devErr := h.registry.FindByID(deviceID); devErr == nil && dev != nil && dev.UserID != "" {
			userRec, _ = h.userRegistry.FindByID(dev.UserID)
		}
	}

	certPEM, expiresAt, signErr := h.signCSR(req.CSR)
	if signErr != nil {
		slog.Error("re-pair: cert signing failed", "err", signErr)
		httperr.JSON(w, http.StatusInternalServerError, "cert_signing_failed")
		return
	}
	h.writeFullResponse(w, deviceID, certPEM, expiresAt, userRec)

	h.notifyPaired(deviceID, req.DeviceName)
}

func (h *PairingHandler) isRateLimited(ip string) bool {
	h.mu.Lock()
	defer h.mu.Unlock()
	entry, ok := h.rateLimits[ip]
	if !ok {
		return false
	}
	if h.now().After(entry.windowEnd) {
		delete(h.rateLimits, ip)
		return false
	}
	return entry.attempts >= MaxPairAttempts
}

func (h *PairingHandler) recordFailedAttempt(ip string) {
	h.mu.Lock()
	defer h.mu.Unlock()
	h.recordFailedAttemptLocked(ip)
}

func (h *PairingHandler) recordFailedAttemptLocked(ip string) {
	now := h.now()
	entry, ok := h.rateLimits[ip]
	if !ok || now.After(entry.windowEnd) {
		h.rateLimits[ip] = &rateLimitEntry{
			attempts:  1,
			windowEnd: now.Add(RateLimitWindow),
		}
		return
	}
	entry.attempts++
}

func (h *PairingHandler) SweepRateLimits(now time.Time) {
	h.mu.Lock()
	defer h.mu.Unlock()
	for ip, rl := range h.rateLimits {
		if now.After(rl.windowEnd) {
			delete(h.rateLimits, ip)
		}
	}
}

func extractIP(r *http.Request) string {
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		return r.RemoteAddr
	}
	return host
}

func randomHex(nBytes int) string {
	b := make([]byte, nBytes)
	if _, err := rand.Read(b); err != nil {
		panic(fmt.Sprintf("crypto/rand failed: %v", err))
	}
	return fmt.Sprintf("%x", b)
}
