package server

import (
	"crypto/ecdsa"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"errors"
	"io"
	"net/http"
	"time"

	"github.com/pocketcmd/pocketcmd-server/internal/httperr"
	"github.com/pocketcmd/pocketcmd-server/internal/pki"
)

const maxChallengeBody = 16 << 10

func (s *Server) handleCertChallenge(w http.ResponseWriter, r *http.Request) {
	var req struct {
		PublicKey string `json:"public_key"`
	}
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, maxChallengeBody)).Decode(&req); err != nil || req.PublicKey == "" {
		s.auditCertEvent("cert_challenge", "bad_request", "", "", req.PublicKey, r)
		httperr.JSON(w, http.StatusBadRequest, "public_key_required")
		return
	}
	if s.pairingFingerprint == "" {
		httperr.JSON(w, http.StatusInternalServerError, "server_not_configured")
		return
	}
	// Keyed on the fingerprint, not the PEM text, so framing variants share a bucket.
	pubFP, err := pki.PubKeyFingerprint(req.PublicKey)
	if err != nil {
		s.auditCertEvent("cert_challenge", "bad_request", "", "", "", r)
		httperr.JSON(w, http.StatusBadRequest, "invalid_public_key")
		return
	}
	if !s.challengePubKeyLimiter.Allow(pubFP) {
		s.auditCertEvent("cert_challenge", "rate_limited", "", "", req.PublicKey, r)
		httperr.JSON(w, http.StatusTooManyRequests, "rate_limited")
		return
	}
	if s.deviceRegistry == nil {
		httperr.JSON(w, http.StatusInternalServerError, "server_not_configured")
		return
	}
	buf := make([]byte, 32)
	if _, err := rand.Read(buf); err != nil {
		httperr.JSON(w, http.StatusInternalServerError, "internal_error")
		return
	}
	nonce := hex.EncodeToString(buf)
	exp := time.Now().Add(30 * time.Second)

	// Unknown or inactive keys get the same 200 and an unstored nonce, so the
	// response is not a liveness oracle.
	dev, ok := s.deviceRegistry.LookupByPublicKeyPEM(req.PublicKey)
	switch {
	case !ok:
		s.auditCertEvent("cert_challenge", "unknown_device", "", "", req.PublicKey, r)
	case dev.Status != pki.DeviceStatusActive:
		s.auditCertEvent("cert_challenge", inactiveOutcome(dev.Status), dev.DeviceID, dev.UserID, req.PublicKey, r)
	case !s.deviceUserActive(dev):
		s.auditCertEvent("cert_challenge", "user_inactive", dev.DeviceID, dev.UserID, req.PublicKey, r)
	default:
		s.nonces.Put(nonce, pki.NonceEntry{
			PublicKeyPEM:      req.PublicKey,
			ServerFingerprint: s.pairingFingerprint,
			ExpiresAt:         exp,
		})
		s.auditCertEvent("cert_challenge", "issued", dev.DeviceID, dev.UserID, req.PublicKey, r)
	}
	httperr.WriteJSON(w, http.StatusOK, map[string]string{
		"nonce":      nonce,
		"expires_at": exp.UTC().Format(time.RFC3339Nano),
	})
}

func (s *Server) auditCertEvent(event, outcome, deviceID, userID, pubKeyPEM string, r *http.Request) {
	pubHint := ""
	if pubKeyPEM != "" {
		if id, err := pki.DeviceIDFromPublicKey(pubKeyPEM); err == nil {
			pubHint = id
		}
	}
	s.auditLogger.Info(event,
		"outcome", outcome,
		"device_id", deviceID,
		"user_id", userID,
		"pub_key_fp", pubHint,
		"remote_addr", r.RemoteAddr,
	)
}

func (s *Server) handleCertRenew(w http.ResponseWriter, r *http.Request) {
	body, err := io.ReadAll(http.MaxBytesReader(w, r.Body, maxJSONBody))
	if err != nil {
		httperr.JSON(w, http.StatusBadRequest, "invalid_body")
		return
	}

	var req struct {
		CSR             string `json:"csr"`
		SignedChallenge string `json:"signed_challenge"`
		PublicKey       string `json:"public_key"`
		Nonce           string `json:"nonce"`
	}
	if err := json.Unmarshal(body, &req); err != nil {
		httperr.JSON(w, http.StatusBadRequest, "invalid_body")
		return
	}

	if req.SignedChallenge != "" {
		s.renewViaChallenge(w, r, req.SignedChallenge, req.PublicKey, req.CSR, req.Nonce)
		return
	}
	s.renewViaMTLS(w, r, req.CSR)
}

// Every check runs unconditionally so response latency does not reveal which failed.
func (s *Server) renewViaChallenge(w http.ResponseWriter, r *http.Request, sig, pubPEM, csrPEM, nonce string) {
	if pubPEM == "" || csrPEM == "" || nonce == "" {
		s.auditCertEvent("cert_renew", "bad_request", "", "", pubPEM, r)
		httperr.JSON(w, http.StatusBadRequest, "missing_fields")
		return
	}

	entry, nonceFound := s.nonces.Take(nonce)
	nonceOK := nonceFound && entry.PublicKeyPEM == pubPEM

	dev, devFound := s.deviceRegistry.LookupByPublicKeyPEM(pubPEM)
	devActive := devFound && dev.Status == pki.DeviceStatusActive && s.deviceUserActive(dev)

	sigBytes, sigDecodeErr := base64.StdEncoding.DecodeString(sig)

	pubBlock, _ := pem.Decode([]byte(pubPEM))
	var ecPubKey *ecdsa.PublicKey
	if pubBlock != nil {
		if k, err := x509.ParsePKIXPublicKey(pubBlock.Bytes); err == nil {
			if ec, ok := k.(*ecdsa.PublicKey); ok {
				ecPubKey = ec
			}
		}
	}

	sigValid := false
	var verifyDigest [32]byte
	if nonceOK {
		msg := nonce + ":" + entry.ServerFingerprint
		verifyDigest = sha256.Sum256([]byte(msg))
	} else {
		verifyDigest = sha256.Sum256([]byte(pubPEM))
	}
	if ecPubKey != nil && sigDecodeErr == nil {
		sigValid = ecdsa.VerifyASN1(ecPubKey, verifyDigest[:], sigBytes)
	}
	sigValid = sigValid && nonceOK

	csrPubPEM, csrErr := pki.ParsePublicKeyFromCSR([]byte(csrPEM))
	csrMalformed := csrErr != nil
	csrBound := !csrMalformed && pki.PublicKeysEqual(csrPubPEM, pubPEM)

	deviceID := ""
	if devFound {
		deviceID = dev.DeviceID
	}

	userID := ""
	if devFound {
		userID = dev.UserID
	}

	if nonceOK && devActive && sigValid && csrBound {
		s.auditCertEvent("cert_renew", "issued_challenge", deviceID, userID, pubPEM, r)
		s.issueCertResponse(w, csrPEM)
		return
	}

	switch {
	case csrMalformed:
		s.auditCertEvent("cert_renew", "bad_csr", deviceID, userID, pubPEM, r)
		s.logger.Debug("cert renew: malformed CSR", "err", csrErr)
		httperr.JSON(w, http.StatusBadRequest, "invalid_csr")
	case !csrBound:
		s.auditCertEvent("cert_renew", "csr_pubkey_mismatch", deviceID, userID, pubPEM, r)
		httperr.JSON(w, http.StatusBadRequest, "csr_key_mismatch")
	case devFound && !devActive:
		s.auditCertEvent("cert_renew", inactiveDeviceOutcome(dev), deviceID, userID, pubPEM, r)
		httperr.JSON(w, http.StatusForbidden, "forbidden")
	case !devFound:
		s.auditCertEvent("cert_renew", "unknown_device", "", "", pubPEM, r)
		httperr.JSON(w, http.StatusForbidden, "forbidden")
	case !nonceOK:
		s.auditCertEvent("cert_renew", "nonce_missing_or_expired", deviceID, userID, pubPEM, r)
		httperr.JSON(w, http.StatusUnauthorized, "unauthorized")
	default:
		s.auditCertEvent("cert_renew", "bad_signature", deviceID, userID, pubPEM, r)
		httperr.JSON(w, http.StatusUnauthorized, "unauthorized")
	}
}

func (s *Server) renewViaMTLS(w http.ResponseWriter, r *http.Request, csrPEM string) {
	if csrPEM == "" {
		s.auditCertEvent("cert_renew", "bad_request", "", "", "", r)
		httperr.JSON(w, http.StatusBadRequest, "csr_required")
		return
	}

	peerCert := peerCertificate(r)
	if peerCert == nil {
		s.auditCertEvent("cert_renew", "no_mtls", "", "", "", r)
		httperr.JSON(w, http.StatusUnauthorized, "unauthorized")
		return
	}

	peerPubPEM, err := pki.PublicKeyPEM(peerCert.PublicKey)
	if err != nil {
		httperr.JSON(w, http.StatusInternalServerError, "invalid_certificate")
		return
	}

	csrPubPEM, err := pki.ParsePublicKeyFromCSR([]byte(csrPEM))
	if err != nil {
		s.auditCertEvent("cert_renew", "bad_csr", "", "", peerPubPEM, r)
		s.logger.Debug("cert renew: malformed CSR", "err", err)
		httperr.JSON(w, http.StatusBadRequest, "invalid_csr")
		return
	}
	if !pki.PublicKeysEqual(csrPubPEM, peerPubPEM) {
		s.auditCertEvent("cert_renew", "csr_pubkey_mismatch", "", "", peerPubPEM, r)
		httperr.JSON(w, http.StatusBadRequest, "csr_key_mismatch")
		return
	}

	dev, ok := s.deviceRegistry.LookupByPublicKeyPEM(peerPubPEM)
	if !ok || dev.Status != pki.DeviceStatusActive || !s.deviceUserActive(dev) {
		deviceID := ""
		mtlsUserID := ""
		if ok {
			deviceID = dev.DeviceID
			mtlsUserID = dev.UserID
		}
		outcome := "unknown_device"
		if ok {
			outcome = inactiveDeviceOutcome(dev)
		}
		s.auditCertEvent("cert_renew", outcome, deviceID, mtlsUserID, peerPubPEM, r)
		httperr.JSON(w, http.StatusForbidden, "forbidden")
		return
	}

	if s.certVerifier == nil {
		httperr.JSON(w, http.StatusUnauthorized, "client_cert_invalid")
		return
	}
	switch err := s.certVerifier.Verify(peerCert, time.Now()); {
	case err == nil:
	case errors.Is(err, pki.ErrClientCertExpired):
		s.auditCertEvent("cert_renew", "cert_expired", dev.DeviceID, dev.UserID, peerPubPEM, r)
		httperr.JSON(w, http.StatusUnauthorized, "client_cert_expired")
		return
	default:
		s.auditCertEvent("cert_renew", "cert_untrusted", dev.DeviceID, dev.UserID, peerPubPEM, r)
		httperr.JSON(w, http.StatusUnauthorized, "client_cert_invalid")
		return
	}

	s.auditCertEvent("cert_renew", "issued_mtls", dev.DeviceID, dev.UserID, peerPubPEM, r)
	s.issueCertResponse(w, csrPEM)
}

func inactiveOutcome(status string) string {
	if status == pki.DeviceStatusLeft {
		return "left"
	}
	return "revoked"
}

func inactiveDeviceOutcome(dev *pki.DeviceRecord) string {
	if dev.Status == pki.DeviceStatusActive {
		return "user_inactive"
	}
	return inactiveOutcome(dev.Status)
}

func (s *Server) deviceUserActive(dev *pki.DeviceRecord) bool {
	if s.userRegistry == nil || dev == nil || dev.UserID == "" {
		return false
	}
	u, err := s.userRegistry.FindByID(dev.UserID)
	return err == nil && u != nil && u.Status == pki.UserStatusActive
}

func (s *Server) issueCertResponse(w http.ResponseWriter, csrPEM string) {
	certPEM, err := pki.SignCSR([]byte(csrPEM), s.serverKey, pki.ClientCertTTL)
	if err != nil {
		s.logger.Error("cert signing failed", "err", err)
		httperr.JSON(w, http.StatusInternalServerError, "cert_signing_failed")
		return
	}

	expiresAt := time.Now().Add(pki.ClientCertTTL).UTC().Format(time.RFC3339)
	httperr.WriteJSON(w, http.StatusOK, map[string]string{
		"cert":       string(certPEM),
		"expires_at": expiresAt,
	})
}
