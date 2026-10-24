package session

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/hex"
	"math/big"
	"strings"
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v5"
)

func generateSelfSignedCert(t *testing.T) (*x509.Certificate, *ecdsa.PrivateKey, string) {
	t.Helper()

	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}

	template := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: "test"},
		NotBefore:    time.Now().Add(-1 * time.Hour),
		NotAfter:     time.Now().Add(1 * time.Hour),
	}

	certDER, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}

	cert, err := x509.ParseCertificate(certDER)
	if err != nil {
		t.Fatal(err)
	}

	h := sha256.Sum256(certDER)
	fp := hex.EncodeToString(h[:])

	return cert, key, fp
}

func TestJWTService_IssueAndValidate(t *testing.T) {
	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	mgr := NewManager(key)

	_, _, certFP := generateSelfSignedCert(t)

	token, err := mgr.Issue("device123", certFP)
	if err != nil {
		t.Fatal(err)
	}

	claims, err := mgr.Validate(token, certFP)
	if err != nil {
		t.Fatal(err)
	}
	if claims.DeviceID != "device123" {
		t.Fatalf("expected device123, got %s", claims.DeviceID)
	}
	if claims.Cnf.X5tS256 != certFP {
		t.Fatalf("expected cert fingerprint %s, got %s", certFP, claims.Cnf.X5tS256)
	}
	if claims.Issuer != "pocketcmd" {
		t.Fatalf("expected issuer pocketcmd, got %s", claims.Issuer)
	}
}

func TestJWTService_ExpiredToken(t *testing.T) {
	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	mgr := &Manager{key: key, ttl: -1 * time.Second}

	_, _, certFP := generateSelfSignedCert(t)

	token, err := mgr.Issue("device123", certFP)
	if err != nil {
		t.Fatal(err)
	}

	_, err = mgr.Validate(token, certFP)
	if err == nil {
		t.Fatal("expected expiry error")
	}
}

func TestJWTService_WrongCertFingerprint(t *testing.T) {
	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	mgr := NewManager(key)

	_, _, certFP := generateSelfSignedCert(t)

	token, err := mgr.Issue("device123", certFP)
	if err != nil {
		t.Fatal(err)
	}

	_, err = mgr.Validate(token, "wrongfingerprint")
	if err == nil {
		t.Fatal("expected channel binding error")
	}
	if !strings.Contains(err.Error(), "channel binding mismatch") {
		t.Fatalf("expected channel binding mismatch error, got: %v", err)
	}
}

func TestJWTService_InvalidSignature(t *testing.T) {
	key1, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	key2, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)

	mgr1 := NewManager(key1)
	mgr2 := NewManager(key2)

	_, _, certFP := generateSelfSignedCert(t)

	token, err := mgr1.Issue("device123", certFP)
	if err != nil {
		t.Fatal(err)
	}

	_, err = mgr2.Validate(token, certFP)
	if err == nil {
		t.Fatal("expected signature verification error")
	}
}

func TestJWTService_RequiresExp(t *testing.T) {
	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	mgr := NewManager(key)
	_, _, certFP := generateSelfSignedCert(t)

	claims := Claims{
		RegisteredClaims: jwt.RegisteredClaims{
			Subject:  "device123",
			Issuer:   tokenIssuer,
			IssuedAt: jwt.NewNumericDate(time.Now()),
		},
		Cnf: CnfClaim{X5tS256: certFP},
	}
	token, err := jwt.NewWithClaims(jwt.SigningMethodES256, claims).SignedString(key)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := mgr.Validate(token, certFP); err == nil {
		t.Fatal("token without exp must be rejected")
	}
}

func TestJWTService_RejectsOtherAlgorithms(t *testing.T) {
	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	mgr := NewManager(key)
	_, _, certFP := generateSelfSignedCert(t)
	claims := func() Claims {
		return Claims{
			RegisteredClaims: jwt.RegisteredClaims{
				Subject:   "device123",
				Issuer:    tokenIssuer,
				IssuedAt:  jwt.NewNumericDate(time.Now()),
				ExpiresAt: jwt.NewNumericDate(time.Now().Add(time.Minute)),
			},
			Cnf: CnfClaim{X5tS256: certFP},
		}
	}

	pubDER, _ := x509.MarshalPKIXPublicKey(&key.PublicKey)
	hs, err := jwt.NewWithClaims(jwt.SigningMethodHS256, claims()).SignedString(pubDER)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := mgr.Validate(hs, certFP); err == nil {
		t.Fatal("HS256 token must be rejected")
	}

	none, err := jwt.NewWithClaims(jwt.SigningMethodNone, claims()).SignedString(jwt.UnsafeAllowNoneSignatureType)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := mgr.Validate(none, certFP); err == nil {
		t.Fatal("alg=none token must be rejected")
	}

	p384, _ := ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
	es384, err := jwt.NewWithClaims(jwt.SigningMethodES384, claims()).SignedString(p384)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := mgr.Validate(es384, certFP); err == nil {
		t.Fatal("ES384 token must be rejected")
	}
}
