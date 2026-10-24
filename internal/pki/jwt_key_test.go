package pki

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/hkdf"
	"crypto/rand"
	"crypto/sha256"
	"math/big"
	"testing"
)

func TestDeriveJWTSigningKey(t *testing.T) {
	sk, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}

	k1, err := DeriveJWTSigningKey(sk)
	if err != nil {
		t.Fatal(err)
	}
	k2, err := DeriveJWTSigningKey(sk)
	if err != nil {
		t.Fatal(err)
	}
	if !k1.Equal(k2) {
		t.Error("derivation is not deterministic, tokens would break on restart")
	}
	if k1.Equal(sk) {
		t.Error("JWT key equals the server key, so the CA and signing roles are not separated")
	}

	sk2, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	k3, err := DeriveJWTSigningKey(sk2)
	if err != nil {
		t.Fatal(err)
	}
	if k1.Equal(k3) {
		t.Error("distinct server keys derived the same JWT key")
	}

	if _, err := DeriveJWTSigningKey(nil); err == nil {
		t.Error("expected error on nil server key")
	}

	digest := sha256.Sum256([]byte("session token payload"))
	r, s, err := ecdsa.Sign(rand.Reader, k1, digest[:])
	if err != nil {
		t.Fatalf("sign with derived key: %v", err)
	}
	if !ecdsa.Verify(&k1.PublicKey, digest[:], r, s) {
		t.Fatal("derived key public/private mismatch: signature did not verify")
	}
}

func TestDeriveJWTSigningKey_LeadingZeroScalarUnchanged(t *testing.T) {
	scalar := bytes.Repeat([]byte{0xa5}, 32)
	scalar[0] = 0
	sk, err := ecdsa.ParseRawPrivateKey(elliptic.P256(), scalar)
	if err != nil {
		t.Fatal(err)
	}
	got, err := DeriveJWTSigningKey(sk)
	if err != nil {
		t.Fatal(err)
	}

	okm, err := hkdf.Key(sha256.New, scalar[1:], nil, jwtKeyDerivationInfo, 48)
	if err != nil {
		t.Fatal(err)
	}
	n := elliptic.P256().Params().N
	d := new(big.Int).SetBytes(okm)
	d.Mod(d, new(big.Int).Sub(n, big.NewInt(1)))
	d.Add(d, big.NewInt(1))
	want := make([]byte, 32)
	d.FillBytes(want)

	gotScalar, err := got.Bytes()
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(gotScalar, want) {
		t.Fatal("JWT key derivation changed for a scalar with a leading zero byte")
	}
}
