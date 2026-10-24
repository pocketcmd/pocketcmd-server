// Package pki manages the server key, client certificates, devices, users and invites.
package pki

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/hkdf"
	"crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/hex"
	"encoding/pem"
	"errors"
	"fmt"
	"math/big"
	"net"
	"os"
	"path/filepath"
	"time"
)

const jwtKeyDerivationInfo = "pocketcmd/jwt-signing/v1"

func DeriveJWTSigningKey(serverKey *ecdsa.PrivateKey) (*ecdsa.PrivateKey, error) {
	if serverKey == nil {
		return nil, fmt.Errorf("nil server key")
	}
	// HKDF input is the scalar's minimal big-endian encoding, so existing servers keep their key.
	raw, err := serverKey.Bytes()
	if err != nil {
		return nil, fmt.Errorf("derive jwt key: %w", err)
	}
	okm, err := hkdf.Key(sha256.New, bytes.TrimLeft(raw, "\x00"), nil, jwtKeyDerivationInfo, 48)
	if err != nil {
		return nil, fmt.Errorf("derive jwt key: %w", err)
	}
	curve := elliptic.P256()
	n := curve.Params().N
	d := new(big.Int).SetBytes(okm)
	d.Mod(d, new(big.Int).Sub(n, big.NewInt(1)))
	d.Add(d, big.NewInt(1))

	scalar := make([]byte, (n.BitLen()+7)/8)
	d.FillBytes(scalar)
	priv, err := ecdsa.ParseRawPrivateKey(curve, scalar)
	if err != nil {
		return nil, fmt.Errorf("derive jwt key: %w", err)
	}
	return priv, nil
}

func ServerCertExists(dir string) bool {
	_, err := os.Stat(filepath.Join(dir, "server.crt"))
	return err == nil
}

func LoadOrGenerateServerCert(dir string) (tls.Certificate, string, error) {
	certPath := filepath.Join(dir, "server.crt")
	keyPath := filepath.Join(dir, "server.key")

	if _, err := os.Stat(certPath); err == nil {
		cert, err := tls.LoadX509KeyPair(certPath, keyPath)
		if err == nil {
			fp := sha256.Sum256(cert.Certificate[0])
			return cert, hex.EncodeToString(fp[:]), nil
		}
	}

	if err := os.MkdirAll(dir, 0700); err != nil {
		return tls.Certificate{}, "", err
	}

	certPEM, keyPEM, fingerprint, err := generateCert("pocketcmd-server", 100*365*24*time.Hour)
	if err != nil {
		return tls.Certificate{}, "", err
	}

	if err := os.WriteFile(certPath, certPEM, 0600); err != nil {
		return tls.Certificate{}, "", err
	}
	if err := os.WriteFile(keyPath, keyPEM, 0600); err != nil {
		return tls.Certificate{}, "", err
	}

	cert, err := tls.X509KeyPair(certPEM, keyPEM)
	if err != nil {
		return tls.Certificate{}, "", err
	}
	return cert, fingerprint, nil
}

func generateCert(cn string, validity time.Duration) (certPEM, keyPEM []byte, fingerprint string, err error) {
	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, nil, "", err
	}

	serial, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	if err != nil {
		return nil, nil, "", err
	}

	template := x509.Certificate{
		SerialNumber: serial,
		Subject:      pkix.Name{CommonName: cn},
		NotBefore:    time.Now().Add(-time.Minute),
		NotAfter:     time.Now().Add(validity),
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth, x509.ExtKeyUsageClientAuth},
		IPAddresses: []net.IP{
			net.ParseIP("0.0.0.0"),
			net.ParseIP("127.0.0.1"),
		},
	}

	certDER, err := x509.CreateCertificate(rand.Reader, &template, &template, &priv.PublicKey, priv)
	if err != nil {
		return nil, nil, "", err
	}

	certPEM = pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: certDER})
	keyDER, err := x509.MarshalECPrivateKey(priv)
	if err != nil {
		return nil, nil, "", err
	}
	keyPEM = pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: keyDER})

	hash := sha256.Sum256(certDER)
	fingerprint = hex.EncodeToString(hash[:])
	return certPEM, keyPEM, fingerprint, nil
}

func LoadServerKey(tlsDir string) (*ecdsa.PrivateKey, error) {
	keyPEM, err := os.ReadFile(filepath.Join(tlsDir, "server.key"))
	if err != nil {
		return nil, err
	}
	block, _ := pem.Decode(keyPEM)
	if block == nil {
		return nil, fmt.Errorf("invalid key PEM")
	}
	return x509.ParseECPrivateKey(block.Bytes)
}

var ErrUnsupportedPublicKey = errors.New("device public key must be ECDSA P-256")

func ValidateDevicePublicKey(pubKeyPEM string) error {
	block, _ := pem.Decode([]byte(pubKeyPEM))
	if block == nil {
		return fmt.Errorf("invalid public key PEM")
	}
	pub, err := x509.ParsePKIXPublicKey(block.Bytes)
	if err != nil {
		return fmt.Errorf("invalid public key: %w", err)
	}
	return validateDevicePublicKey(pub)
}

func validateDevicePublicKey(pub any) error {
	ec, ok := pub.(*ecdsa.PublicKey)
	if !ok || ec.Curve != elliptic.P256() {
		return ErrUnsupportedPublicKey
	}
	return nil
}

const ClientCertTTL = 30 * time.Minute

const DeviceIDLen = 16

func DeviceIDFromFingerprint(fp string) string {
	return fp[:DeviceIDLen]
}

func DeviceIDFromPublicKey(pubKeyPEM string) (string, error) {
	fp, err := PubKeyFingerprint(pubKeyPEM)
	if err != nil {
		return "", err
	}
	if len(fp) < DeviceIDLen {
		return "", fmt.Errorf("fingerprint too short")
	}
	return DeviceIDFromFingerprint(fp), nil
}

// The CSR's subject is ignored; the certificate's CN is always the device id.
func SignCSR(csrPEM []byte, serverKey *ecdsa.PrivateKey, ttl time.Duration) (certPEM []byte, err error) {
	block, _ := pem.Decode(csrPEM)
	if block == nil || block.Type != "CERTIFICATE REQUEST" {
		return nil, fmt.Errorf("invalid CSR PEM")
	}
	csr, err := x509.ParseCertificateRequest(block.Bytes)
	if err != nil {
		return nil, fmt.Errorf("parse CSR: %w", err)
	}
	if err := csr.CheckSignature(); err != nil {
		return nil, fmt.Errorf("CSR signature invalid: %w", err)
	}
	if err := validateDevicePublicKey(csr.PublicKey); err != nil {
		return nil, err
	}
	pubDER, err := x509.MarshalPKIXPublicKey(csr.PublicKey)
	if err != nil {
		return nil, fmt.Errorf("marshal public key: %w", err)
	}
	fp := sha256.Sum256(pubDER)
	deviceID := DeviceIDFromFingerprint(hex.EncodeToString(fp[:]))
	certDER, err := IssueClientCert(pkix.Name{CommonName: deviceID}, csr.PublicKey, serverKey, ttl)
	if err != nil {
		return nil, err
	}
	return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: certDER}), nil
}

func clientIssuerTemplate(now time.Time) *x509.Certificate {
	return &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "pocketcmd-server"},
		NotBefore:             now.Add(-time.Minute),
		NotAfter:              now.Add(100 * 365 * 24 * time.Hour),
		IsCA:                  true,
		BasicConstraintsValid: true,
		KeyUsage:              x509.KeyUsageCertSign,
	}
}

func IssueClientCert(subject pkix.Name, pub any, serverKey *ecdsa.PrivateKey, ttl time.Duration) ([]byte, error) {
	serial, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	if err != nil {
		return nil, err
	}
	now := time.Now()
	template := x509.Certificate{
		SerialNumber: serial,
		Subject:      subject,
		NotBefore:    now.Add(-time.Minute),
		NotAfter:     now.Add(ttl),
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
	}
	certDER, err := x509.CreateCertificate(rand.Reader, &template, clientIssuerTemplate(now), pub, serverKey)
	if err != nil {
		return nil, fmt.Errorf("sign cert: %w", err)
	}
	return certDER, nil
}

const ClientCertGrace = 10 * time.Minute

var (
	ErrClientCertUntrusted   = errors.New("client certificate not issued by this server")
	ErrClientCertExpired     = errors.New("client certificate expired")
	ErrClientCertNotYetValid = errors.New("client certificate not yet valid")
)

type ClientCertVerifier struct {
	issuer *x509.Certificate
	grace  time.Duration
}

func NewClientCertVerifier(serverKey *ecdsa.PrivateKey) (*ClientCertVerifier, error) {
	if serverKey == nil {
		return nil, fmt.Errorf("nil server key")
	}
	tmpl := clientIssuerTemplate(time.Now())
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &serverKey.PublicKey, serverKey)
	if err != nil {
		return nil, fmt.Errorf("issuer cert: %w", err)
	}
	issuer, err := x509.ParseCertificate(der)
	if err != nil {
		return nil, fmt.Errorf("issuer cert: %w", err)
	}
	return &ClientCertVerifier{issuer: issuer, grace: ClientCertGrace}, nil
}

func (v *ClientCertVerifier) Verify(cert *x509.Certificate, now time.Time) error {
	if cert == nil {
		return ErrClientCertUntrusted
	}
	if err := cert.CheckSignatureFrom(v.issuer); err != nil {
		return ErrClientCertUntrusted
	}
	if now.Before(cert.NotBefore) {
		return ErrClientCertNotYetValid
	}
	if now.After(cert.NotAfter.Add(v.grace)) {
		return ErrClientCertExpired
	}
	return nil
}

func CertFingerprint(certDER []byte) string {
	fp := sha256.Sum256(certDER)
	return hex.EncodeToString(fp[:])
}

func PublicKeyPEM(pub any) (string, error) {
	der, err := x509.MarshalPKIXPublicKey(pub)
	if err != nil {
		return "", err
	}
	return string(pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: der})), nil
}

func ParsePublicKeyFromCSR(csrPEM []byte) (string, error) {
	block, _ := pem.Decode(csrPEM)
	if block == nil || block.Type != "CERTIFICATE REQUEST" {
		return "", fmt.Errorf("invalid CSR PEM")
	}
	csr, err := x509.ParseCertificateRequest(block.Bytes)
	if err != nil {
		return "", fmt.Errorf("parse CSR: %w", err)
	}
	pubPEM, err := PublicKeyPEM(csr.PublicKey)
	if err != nil {
		return "", fmt.Errorf("marshal public key: %w", err)
	}
	return pubPEM, nil
}

// Client certs are requested, not verified by TLS; authorization happens per request against the registry.
func BuildMTLSConfig(serverCert tls.Certificate) (*tls.Config, error) {
	return &tls.Config{
		Certificates: []tls.Certificate{serverCert},
		ClientAuth:   tls.RequestClientCert,
		MinVersion:   tls.VersionTLS13,
	}, nil
}
