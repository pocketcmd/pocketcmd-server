package pki

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"errors"
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestLoadOrGenerateServerCert_GeneratesNew(t *testing.T) {
	dir := t.TempDir()
	cert, fingerprint, err := LoadOrGenerateServerCert(dir)
	if err != nil {
		t.Fatal(err)
	}
	if len(fingerprint) != 64 {
		t.Fatalf("expected 64-char fingerprint, got %d", len(fingerprint))
	}
	if len(cert.Certificate) == 0 {
		t.Fatal("expected non-empty certificate")
	}
	if _, err := os.Stat(filepath.Join(dir, "server.crt")); err != nil {
		t.Fatal("server.crt should exist")
	}
	if _, err := os.Stat(filepath.Join(dir, "server.key")); err != nil {
		t.Fatal("server.key should exist")
	}
}

func TestLoadOrGenerateServerCert_LoadsExisting(t *testing.T) {
	dir := t.TempDir()
	_, fp1, err := LoadOrGenerateServerCert(dir)
	if err != nil {
		t.Fatal(err)
	}
	_, fp2, err := LoadOrGenerateServerCert(dir)
	if err != nil {
		t.Fatal(err)
	}
	if fp1 != fp2 {
		t.Fatal("fingerprints should match on reload")
	}
}

func TestLoadOrGenerateServerCert_CorruptFile(t *testing.T) {
	dir := t.TempDir()
	os.WriteFile(filepath.Join(dir, "server.crt"), []byte("not a cert"), 0600)
	os.WriteFile(filepath.Join(dir, "server.key"), []byte("not a key"), 0600)

	cert, fp, err := LoadOrGenerateServerCert(dir)
	if err != nil {
		t.Fatal(err)
	}
	if len(fp) != 64 {
		t.Fatal("expected valid fingerprint after regeneration")
	}
	if len(cert.Certificate) == 0 {
		t.Fatal("expected valid cert after regeneration")
	}
}

func TestLoadOrGenerateServerCert_CreatesDirIfNeeded(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "nested", "dir")
	cert, fp, err := LoadOrGenerateServerCert(dir)
	if err != nil {
		t.Fatal(err)
	}
	if len(cert.Certificate) == 0 || len(fp) != 64 {
		t.Fatal("expected valid cert")
	}
}

func TestBuildMTLSConfig(t *testing.T) {
	tlsDir := t.TempDir()
	cert, _, err := LoadOrGenerateServerCert(tlsDir)
	if err != nil {
		t.Fatal(err)
	}
	cfg, err := BuildMTLSConfig(cert)
	if err != nil {
		t.Fatal(err)
	}
	if cfg.ClientAuth != tls.RequestClientCert {
		t.Fatal("expected RequestClientCert")
	}
	if len(cfg.Certificates) == 0 {
		t.Fatal("expected server certificate")
	}
}

func generateCSR(t *testing.T) (csrPEM []byte, clientKey *ecdsa.PrivateKey) {
	t.Helper()
	clientKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	csrTemplate := &x509.CertificateRequest{
		Subject: pkix.Name{CommonName: "pocketcmd-device"},
	}
	csrDER, err := x509.CreateCertificateRequest(rand.Reader, csrTemplate, clientKey)
	if err != nil {
		t.Fatal(err)
	}
	csrPEM = pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE REQUEST", Bytes: csrDER})
	return csrPEM, clientKey
}

func TestSignCSR(t *testing.T) {
	dir := t.TempDir()
	_, _, err := LoadOrGenerateServerCert(dir)
	if err != nil {
		t.Fatal(err)
	}
	serverKey, err := LoadServerKey(dir)
	if err != nil {
		t.Fatal(err)
	}

	csrPEM, _ := generateCSR(t)

	certPEM, err := SignCSR(csrPEM, serverKey, 30*time.Minute)
	if err != nil {
		t.Fatal(err)
	}

	block, _ := pem.Decode(certPEM)
	if block == nil {
		t.Fatal("invalid cert PEM")
	}
	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		t.Fatal(err)
	}

	if cert.Subject.CommonName == "pocketcmd-device" || len(cert.Subject.CommonName) != 16 {
		t.Fatalf("expected CN=<deviceID>, got %q", cert.Subject.CommonName)
	}

	found := false
	for _, eku := range cert.ExtKeyUsage {
		if eku == x509.ExtKeyUsageClientAuth {
			found = true
			break
		}
	}
	if !found {
		t.Fatal("expected ClientAuth extended key usage")
	}
}

func TestSignCSR_ShortTTL(t *testing.T) {
	dir := t.TempDir()
	_, _, err := LoadOrGenerateServerCert(dir)
	if err != nil {
		t.Fatal(err)
	}
	serverKey, err := LoadServerKey(dir)
	if err != nil {
		t.Fatal(err)
	}

	csrPEM, _ := generateCSR(t)
	certPEM, err := SignCSR(csrPEM, serverKey, 30*time.Minute)
	if err != nil {
		t.Fatal(err)
	}

	block, _ := pem.Decode(certPEM)
	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		t.Fatal(err)
	}

	ttl := cert.NotAfter.Sub(cert.NotBefore)
	if ttl < 30*time.Minute || ttl > 32*time.Minute {
		t.Fatalf("unexpected TTL: %v", ttl)
	}
}

func TestLoadServerKey(t *testing.T) {
	dir := t.TempDir()
	_, _, err := LoadOrGenerateServerCert(dir)
	if err != nil {
		t.Fatal(err)
	}

	key, err := LoadServerKey(dir)
	if err != nil {
		t.Fatal(err)
	}
	if key == nil {
		t.Fatal("expected non-nil key")
	}
	if key.Curve != elliptic.P256() {
		t.Fatal("expected P-256 curve")
	}
}

func TestCertFingerprint(t *testing.T) {
	dir := t.TempDir()
	_, _, err := LoadOrGenerateServerCert(dir)
	if err != nil {
		t.Fatal(err)
	}

	certPEM, err := os.ReadFile(filepath.Join(dir, "server.crt"))
	if err != nil {
		t.Fatal(err)
	}
	block, _ := pem.Decode(certPEM)
	if block == nil {
		t.Fatal("invalid cert PEM")
	}

	fp := CertFingerprint(block.Bytes)
	if len(fp) != 64 {
		t.Fatalf("expected 64 hex chars, got %d: %s", len(fp), fp)
	}

	for _, c := range fp {
		if !((c >= '0' && c <= '9') || (c >= 'a' && c <= 'f')) {
			t.Fatalf("unexpected char in fingerprint: %c", c)
		}
	}
}

func TestSignCSR_InvalidCSR(t *testing.T) {
	dir := t.TempDir()
	_, _, err := LoadOrGenerateServerCert(dir)
	if err != nil {
		t.Fatal(err)
	}
	serverKey, err := LoadServerKey(dir)
	if err != nil {
		t.Fatal(err)
	}

	_, err = SignCSR([]byte("not a pem"), serverKey, 30*time.Minute)
	if err == nil {
		t.Fatal("expected error for invalid CSR PEM")
	}

	badBlock := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: []byte("garbage")})
	_, err = SignCSR(badBlock, serverKey, 30*time.Minute)
	if err == nil {
		t.Fatal("expected error for wrong PEM block type")
	}

	corruptCSR := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE REQUEST", Bytes: []byte("not a real csr")})
	_, err = SignCSR(corruptCSR, serverKey, 30*time.Minute)
	if err == nil {
		t.Fatal("expected error for corrupt CSR DER")
	}
}

func TestSignCSR_BadSignature(t *testing.T) {
	dir := t.TempDir()
	_, _, err := LoadOrGenerateServerCert(dir)
	if err != nil {
		t.Fatal(err)
	}
	serverKey, err := LoadServerKey(dir)
	if err != nil {
		t.Fatal(err)
	}

	csrPEM, _ := generateCSR(t)
	block, _ := pem.Decode(csrPEM)
	raw := make([]byte, len(block.Bytes))
	copy(raw, block.Bytes)
	if len(raw) > 10 {
		raw[len(raw)-1] ^= 0xFF
		raw[len(raw)-2] ^= 0xFF
		raw[len(raw)-5] ^= 0xFF
	}
	tamperedCSR := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE REQUEST", Bytes: raw})

	_, err = SignCSR(tamperedCSR, serverKey, 30*time.Minute)
	if err == nil {
		t.Fatal("expected error for CSR with tampered signature")
	}
}

func TestLoadServerKey_MissingFile(t *testing.T) {
	dir := t.TempDir()
	_, err := LoadServerKey(dir)
	if err == nil {
		t.Fatal("expected error for missing server key file")
	}
}

func TestLoadServerKey_CorruptFile(t *testing.T) {
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "server.key"), []byte("not a valid PEM"), 0600); err != nil {
		t.Fatal(err)
	}
	_, err := LoadServerKey(dir)
	if err == nil {
		t.Fatal("expected error for corrupt key file")
	}

	badPEM := pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: []byte("not a real key")})
	if err := os.WriteFile(filepath.Join(dir, "server.key"), badPEM, 0600); err != nil {
		t.Fatal(err)
	}
	_, err = LoadServerKey(dir)
	if err == nil {
		t.Fatal("expected error for invalid key DER inside valid PEM")
	}
}

func TestParsePublicKeyFromCSR_InvalidPEM(t *testing.T) {
	_, err := ParsePublicKeyFromCSR([]byte("not a pem"))
	if err == nil {
		t.Fatal("expected error for invalid PEM")
	}

	badBlock := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: []byte("garbage")})
	_, err = ParsePublicKeyFromCSR(badBlock)
	if err == nil {
		t.Fatal("expected error for wrong PEM block type")
	}

	corruptCSR := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE REQUEST", Bytes: []byte("not a real csr")})
	_, err = ParsePublicKeyFromCSR(corruptCSR)
	if err == nil {
		t.Fatal("expected error for corrupt CSR content")
	}
}

func TestParsePublicKeyFromCSR(t *testing.T) {
	csrPEM, clientKey := generateCSR(t)

	pubKeyPEM, err := ParsePublicKeyFromCSR(csrPEM)
	if err != nil {
		t.Fatal(err)
	}

	block, _ := pem.Decode([]byte(pubKeyPEM))
	if block == nil || block.Type != "PUBLIC KEY" {
		t.Fatal("expected PUBLIC KEY PEM block")
	}

	parsedPub, err := x509.ParsePKIXPublicKey(block.Bytes)
	if err != nil {
		t.Fatal(err)
	}

	ecPub, ok := parsedPub.(*ecdsa.PublicKey)
	if !ok {
		t.Fatal("expected *ecdsa.PublicKey")
	}

	if !ecPub.Equal(&clientKey.PublicKey) {
		t.Fatal("parsed public key does not match original client key")
	}
}

func TestSignCSR_SubjectIsDeviceID(t *testing.T) {
	serverKey, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	deviceKey, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	csrDER, err := x509.CreateCertificateRequest(rand.Reader, &x509.CertificateRequest{
		Subject: pkix.Name{CommonName: "pocketcmd-server", Organization: []string{"evil"}},
	}, deviceKey)
	if err != nil {
		t.Fatal(err)
	}
	csrPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE REQUEST", Bytes: csrDER})
	certPEM, err := SignCSR(csrPEM, serverKey, time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	block, _ := pem.Decode(certPEM)
	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		t.Fatal(err)
	}
	pubDER, _ := x509.MarshalPKIXPublicKey(&deviceKey.PublicKey)
	wantID, _ := DeviceIDFromPublicKey(string(pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: pubDER})))
	if cert.Subject.CommonName != wantID || len(cert.Subject.Organization) != 0 {
		t.Fatalf("subject = %v, want CN=%s only", cert.Subject, wantID)
	}

	p384, _ := ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
	csrDER, _ = x509.CreateCertificateRequest(rand.Reader, &x509.CertificateRequest{}, p384)
	if _, err := SignCSR(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE REQUEST", Bytes: csrDER}), serverKey, time.Minute); !errors.Is(err, ErrUnsupportedPublicKey) {
		t.Fatalf("P-384 CSR: want ErrUnsupportedPublicKey, got %v", err)
	}
	p384DER, _ := x509.MarshalPKIXPublicKey(&p384.PublicKey)
	if err := ValidateDevicePublicKey(string(pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: p384DER}))); !errors.Is(err, ErrUnsupportedPublicKey) {
		t.Fatalf("P-384 public key: want ErrUnsupportedPublicKey, got %v", err)
	}
}
