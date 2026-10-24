package pki

import (
	"crypto/ecdh"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"errors"
	"math/big"
	"testing"
	"time"
)

func TestClientCertVerifier_LifetimeAndIssuer(t *testing.T) {
	serverKey, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	otherKey, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	devKey, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	v, err := NewClientCertVerifier(serverKey)
	if err != nil {
		t.Fatal(err)
	}
	issue := func(key *ecdsa.PrivateKey, ttl time.Duration) *x509.Certificate {
		der, err := IssueClientCert(pkix.Name{CommonName: "c"}, &devKey.PublicKey, key, ttl)
		if err != nil {
			t.Fatal(err)
		}
		c, err := x509.ParseCertificate(der)
		if err != nil {
			t.Fatal(err)
		}
		return c
	}
	now := time.Now()

	fresh := issue(serverKey, 30*time.Minute)
	if err := v.Verify(fresh, now); err != nil {
		t.Fatalf("fresh cert rejected: %v", err)
	}
	if err := v.Verify(fresh, fresh.NotAfter.Add(ClientCertGrace-time.Second)); err != nil {
		t.Fatalf("cert inside grace rejected: %v", err)
	}
	if err := v.Verify(fresh, fresh.NotAfter.Add(ClientCertGrace+time.Second)); !errors.Is(err, ErrClientCertExpired) {
		t.Fatalf("expected ErrClientCertExpired, got %v", err)
	}
	old := issue(serverKey, 30*time.Minute)
	if err := v.Verify(old, now.Add(365*24*time.Hour)); !errors.Is(err, ErrClientCertExpired) {
		t.Fatalf("year-old cert must be expired, got %v", err)
	}
	foreign := issue(otherKey, 30*time.Minute)
	if err := v.Verify(foreign, now); !errors.Is(err, ErrClientCertUntrusted) {
		t.Fatalf("expected ErrClientCertUntrusted, got %v", err)
	}
	serial, _ := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	tmpl := &x509.Certificate{SerialNumber: serial, Subject: pkix.Name{CommonName: "c"},
		NotBefore: now.Add(-time.Minute), NotAfter: now.Add(time.Hour)}
	der, _ := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &devKey.PublicKey, devKey)
	self, _ := x509.ParseCertificate(der)
	if err := v.Verify(self, now); !errors.Is(err, ErrClientCertUntrusted) {
		t.Fatalf("self-signed cert must be untrusted, got %v", err)
	}
	if err := v.Verify(fresh, fresh.NotBefore.Add(-time.Second)); !errors.Is(err, ErrClientCertNotYetValid) {
		t.Fatalf("expected ErrClientCertNotYetValid, got %v", err)
	}
	if err := v.Verify(nil, now); err == nil {
		t.Fatal("nil cert must fail")
	}
}

func TestSignCSR_VerifiesAgainstClientCertVerifier(t *testing.T) {
	serverKey, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	devKey, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	csrDER, err := x509.CreateCertificateRequest(rand.Reader, &x509.CertificateRequest{Subject: pkix.Name{CommonName: "dev"}}, devKey)
	if err != nil {
		t.Fatal(err)
	}
	certPEM, err := SignCSR(pemEncode("CERTIFICATE REQUEST", csrDER), serverKey, 30*time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	cert := parsePEMCert(t, certPEM)
	v, _ := NewClientCertVerifier(serverKey)
	if err := v.Verify(cert, time.Now()); err != nil {
		t.Fatalf("SignCSR cert rejected by verifier: %v", err)
	}
}

func TestDeriveJWTSigningKey_DeterministicAndCorrectPoint(t *testing.T) {
	serverKey, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	k1, err := DeriveJWTSigningKey(serverKey)
	if err != nil {
		t.Fatal(err)
	}
	k2, _ := DeriveJWTSigningKey(serverKey)
	if !k1.Equal(k2) {
		t.Fatal("derivation is not deterministic")
	}
	if k1.Equal(serverKey) {
		t.Fatal("jwt key must differ from the server key")
	}
	scalar, err := k1.Bytes()
	if err != nil {
		t.Fatal(err)
	}
	ref, err := ecdh.P256().NewPrivateKey(scalar)
	if err != nil {
		t.Fatal(err)
	}
	got, err := k1.PublicKey.Bytes()
	if err != nil {
		t.Fatal(err)
	}
	if want := ref.PublicKey().Bytes(); string(got) != string(want) {
		t.Fatal("public point does not match the scalar")
	}
	digest := sha256.Sum256([]byte("x"))
	sig, err := ecdsa.SignASN1(rand.Reader, k1, digest[:])
	if err != nil || !ecdsa.VerifyASN1(&k1.PublicKey, digest[:], sig) {
		t.Fatalf("derived key cannot sign/verify: %v", err)
	}
}

func pemEncode(typ string, der []byte) []byte {
	return pem.EncodeToMemory(&pem.Block{Type: typ, Bytes: der})
}

func parsePEMCert(t *testing.T, certPEM []byte) *x509.Certificate {
	t.Helper()
	block, _ := pem.Decode(certPEM)
	if block == nil {
		t.Fatal("bad cert PEM")
	}
	c, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		t.Fatal(err)
	}
	return c
}
