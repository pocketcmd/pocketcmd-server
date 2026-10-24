package pki

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/hex"
	"encoding/pem"
	"errors"
	"io/fs"
	"math/big"
	"strings"
	"testing"
	"time"

	"github.com/pocketcmd/pocketcmd-server/internal/state"
	"github.com/pocketcmd/pocketcmd-server/internal/testutil"
)

func generateTestKeyPair(t *testing.T) (pubKeyPEM string, privKey *ecdsa.PrivateKey) {
	t.Helper()
	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	pubDER, err := x509.MarshalPKIXPublicKey(&priv.PublicKey)
	if err != nil {
		t.Fatal(err)
	}
	pubPEM := pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: pubDER})
	return string(pubPEM), priv
}

func TestDeviceRegistry_AddAndLookup(t *testing.T) {
	reg := NewDeviceRegistry(testStateDB(t))
	pubKey, _ := generateTestKeyPair(t)

	id, err := reg.RegisterDeviceForUser(pubKey, "iPhone 15", "test-user", "")
	if err != nil {
		t.Fatal(err)
	}
	if id == "" {
		t.Fatal("expected non-empty device ID")
	}

	if !reg.IsAllowedByPubKey(pubKey) {
		t.Fatal("expected device to be allowed")
	}
}

func TestDeviceRegistry_Remove(t *testing.T) {
	reg := NewDeviceRegistry(testStateDB(t))
	pubKey, _ := generateTestKeyPair(t)

	id, _ := reg.RegisterDeviceForUser(pubKey, "iPhone 15", "test-user", "")
	if err := reg.Remove(id); err != nil {
		t.Fatal(err)
	}
	if reg.IsAllowedByPubKey(pubKey) {
		t.Fatal("expected device to be disallowed after removal")
	}
}

func TestDeviceRegistry_List(t *testing.T) {
	reg := NewDeviceRegistry(testStateDB(t))
	pub1, _ := generateTestKeyPair(t)
	pub2, _ := generateTestKeyPair(t)

	reg.RegisterDeviceForUser(pub1, "iPhone", "user1", "")
	reg.RegisterDeviceForUser(pub2, "Android", "user2", "")

	devices, err := reg.List()
	if err != nil {
		t.Fatal(err)
	}
	if len(devices) != 2 {
		t.Fatalf("expected 2 devices, got %d", len(devices))
	}
}

func TestDeviceRegistry_IdempotentRegister(t *testing.T) {
	reg := NewDeviceRegistry(testStateDB(t))
	pubKey, _ := generateTestKeyPair(t)

	id1, _ := reg.RegisterDeviceForUser(pubKey, "iPhone", "test-user", "")
	id2, _ := reg.RegisterDeviceForUser(pubKey, "iPhone", "test-user", "")
	if id1 != id2 {
		t.Fatalf("expected same device ID for same public key, got %s and %s", id1, id2)
	}

	devices, _ := reg.List()
	if len(devices) != 1 {
		t.Fatalf("expected 1 device after duplicate registration, got %d", len(devices))
	}
}

func TestDeviceRegistry_FindByID(t *testing.T) {
	reg := NewDeviceRegistry(testStateDB(t))
	pubKey, _ := generateTestKeyPair(t)

	id, _ := reg.RegisterDeviceForUser(pubKey, "iPhone", "test-user", "")

	dev, err := reg.FindByID(id)
	if err != nil {
		t.Fatal(err)
	}
	if dev.DeviceName != "iPhone" {
		t.Fatalf("expected iPhone, got %s", dev.DeviceName)
	}
}

func TestDeviceRegistry_IsAllowedByCert(t *testing.T) {
	reg := NewDeviceRegistry(testStateDB(t))
	pubKeyPEM, privKey := generateTestKeyPair(t)

	reg.RegisterDeviceForUser(pubKeyPEM, "test-device", "test-user", "")

	serial, _ := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	template := x509.Certificate{
		SerialNumber: serial,
		Subject:      pkix.Name{CommonName: "test"},
		NotBefore:    time.Now().Add(-time.Minute),
		NotAfter:     time.Now().Add(time.Hour),
	}
	certDER, err := x509.CreateCertificate(rand.Reader, &template, &template, &privKey.PublicKey, privKey)
	if err != nil {
		t.Fatal(err)
	}

	if !reg.IsAllowedByCert(certDER) {
		t.Fatal("expected cert to be allowed")
	}

	_, unregPriv := generateTestKeyPair(t)
	unregCertDER, _ := x509.CreateCertificate(rand.Reader, &template, &template, &unregPriv.PublicKey, unregPriv)
	if reg.IsAllowedByCert(unregCertDER) {
		t.Fatal("expected unregistered cert to be disallowed")
	}
}

func TestDeviceRegistry_Persistence(t *testing.T) {
	dir := t.TempDir()
	db1, err := state.Open(dir)
	if err != nil {
		t.Fatal(err)
	}
	defer db1.Close()
	reg1 := NewDeviceRegistry(db1)
	pubKey, _ := generateTestKeyPair(t)

	reg1.RegisterDeviceForUser(pubKey, "iPhone", "test-user", "")

	db2, err := state.Open(dir)
	if err != nil {
		t.Fatal(err)
	}
	defer db2.Close()
	reg2 := NewDeviceRegistry(db2)
	if !reg2.IsAllowedByPubKey(pubKey) {
		t.Fatal("should persist across instances")
	}
}

func TestDeviceRegistry_ListEmpty(t *testing.T) {
	reg := NewDeviceRegistry(testStateDB(t))
	devices, err := reg.List()
	if err != nil {
		t.Fatal(err)
	}
	if len(devices) != 0 {
		t.Fatalf("expected 0, got %d", len(devices))
	}
}

func TestDeviceRegistry_RemoveNonexistent(t *testing.T) {
	reg := NewDeviceRegistry(testStateDB(t))
	err := reg.Remove("nonexistent")
	if err == nil {
		t.Fatal("expected error removing nonexistent")
	}
}

func TestDeviceRegistry_InvalidPEM(t *testing.T) {
	reg := NewDeviceRegistry(testStateDB(t))
	_, err := reg.RegisterDeviceForUser("not a PEM", "bad", "test-user", "")
	if err == nil {
		t.Fatal("expected error for invalid PEM")
	}
}

func TestDeviceRegistry_DeviceIDIsSHA256Prefix(t *testing.T) {
	reg := NewDeviceRegistry(testStateDB(t))
	pubKey, _ := generateTestKeyPair(t)

	id, _ := reg.RegisterDeviceForUser(pubKey, "iPhone", "test-user", "")

	block, _ := pem.Decode([]byte(pubKey))
	hash := sha256.Sum256(block.Bytes)
	expected := hex.EncodeToString(hash[:])[:16]

	if id != expected {
		t.Fatalf("expected device ID %s, got %s", expected, id)
	}
}

func TestDeviceRegistry_FindByPubKeyPrefix(t *testing.T) {
	reg := NewDeviceRegistry(testStateDB(t))
	pubKey, _ := generateTestKeyPair(t)

	id, _ := reg.RegisterDeviceForUser(pubKey, "iPhone", "test-user", "")

	dev, err := reg.FindByPubKeyPrefix(id[:8])
	if err != nil {
		t.Fatal(err)
	}
	if dev.DeviceName != "iPhone" {
		t.Fatalf("expected iPhone, got %s", dev.DeviceName)
	}
}

func TestPubKeyFingerprint(t *testing.T) {
	pubKey, _ := generateTestKeyPair(t)
	fp, err := PubKeyFingerprint(pubKey)
	if err != nil {
		t.Fatal(err)
	}
	if len(fp) != 64 {
		t.Fatalf("expected 64-char hex fingerprint, got %d chars", len(fp))
	}
}

func TestPubKeyFingerprint_InvalidPEM(t *testing.T) {
	_, err := PubKeyFingerprint("not pem")
	if err == nil {
		t.Fatal("expected error for invalid PEM")
	}
}

func TestDeviceRegistry_IsAllowedByCert_UnregisteredCert(t *testing.T) {
	reg := NewDeviceRegistry(testStateDB(t))

	_, privKey := generateTestKeyPair(t)
	serial, _ := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	template := x509.Certificate{
		SerialNumber: serial,
		Subject:      pkix.Name{CommonName: "unregistered"},
		NotBefore:    time.Now().Add(-time.Minute),
		NotAfter:     time.Now().Add(time.Hour),
	}
	certDER, err := x509.CreateCertificate(rand.Reader, &template, &template, &privKey.PublicKey, privKey)
	if err != nil {
		t.Fatal(err)
	}

	if reg.IsAllowedByCert(certDER) {
		t.Fatal("expected unregistered cert to be disallowed")
	}

	if reg.IsAllowedByCert([]byte("not a cert")) {
		t.Fatal("expected invalid DER to be disallowed")
	}
}

func TestDeviceRegistry_StatusRevoked(t *testing.T) {
	reg := NewDeviceRegistry(testStateDB(t))
	pubKey, _ := generateTestKeyPair(t)

	id, err := reg.RegisterDeviceForUser(pubKey, "iPhone", "test-user", "")
	if err != nil {
		t.Fatal(err)
	}

	if !reg.IsAllowedByPubKey(pubKey) {
		t.Fatal("expected device to be allowed initially")
	}

	if err := reg.Revoke(id); err != nil {
		t.Fatal(err)
	}

	if reg.IsAllowedByPubKey(pubKey) {
		t.Fatal("expected revoked device to be disallowed")
	}
}

func TestDeviceRegistry_LookupByPublicKeyPEM(t *testing.T) {
	reg := NewDeviceRegistry(testStateDB(t))
	pubKey, _ := generateTestKeyPair(t)

	_, err := reg.RegisterDeviceForUser(pubKey, "iPhone", "test-user", "")
	if err != nil {
		t.Fatal(err)
	}

	dev, ok := reg.LookupByPublicKeyPEM(pubKey)
	if !ok {
		t.Fatal("expected to find device by PEM")
	}
	if dev.DeviceName != "iPhone" {
		t.Fatalf("expected DeviceName iPhone, got %s", dev.DeviceName)
	}
	if dev.Status != "active" {
		t.Fatalf("expected status active, got %s", dev.Status)
	}

	otherPEM, _ := generateTestKeyPair(t)
	_, ok = reg.LookupByPublicKeyPEM(otherPEM)
	if ok {
		t.Fatal("expected miss for unregistered public key")
	}

	_, ok = reg.LookupByPublicKeyPEM("not a pem")
	if ok {
		t.Fatal("expected miss for invalid PEM")
	}
}

func TestDeviceRegistry_RegisterDeviceForUser(t *testing.T) {
	reg := NewDeviceRegistry(testStateDB(t))
	pubPEM := testutil.ECDSAPubKeyPEM(t)
	id, err := reg.RegisterDeviceForUser(pubPEM, "iPhone 15", "user-abc", "iPhone 15 label")
	if err != nil {
		t.Fatalf("register: %v", err)
	}
	rec, _ := reg.FindByID(id)
	if rec.UserID != "user-abc" {
		t.Fatalf("UserID missing: %+v", rec)
	}
	if rec.DeviceLabel != "iPhone 15 label" {
		t.Fatalf("DeviceLabel missing: %+v", rec)
	}
}

func TestDeviceRegistry_DevicesByUserID(t *testing.T) {
	reg := NewDeviceRegistry(testStateDB(t))
	pk1, pk2, pk3 := testutil.ECDSAPubKeyPEM(t), testutil.ECDSAPubKeyPEM(t), testutil.ECDSAPubKeyPEM(t)
	_, _ = reg.RegisterDeviceForUser(pk1, "d1", "alice", "")
	_, _ = reg.RegisterDeviceForUser(pk2, "d2", "alice", "")
	_, _ = reg.RegisterDeviceForUser(pk3, "d3", "bob", "")
	devs, err := reg.DevicesByUserID("alice")
	if err != nil || len(devs) != 2 {
		t.Fatalf("want 2 alice devices, got %d (err=%v)", len(devs), err)
	}
}

func TestDeviceRegistry_Revoke(t *testing.T) {
	reg := NewDeviceRegistry(testStateDB(t))
	id, _ := reg.RegisterDeviceForUser(testutil.ECDSAPubKeyPEM(t), "d", "u1", "")
	if err := reg.Revoke(id); err != nil {
		t.Fatalf("revoke: %v", err)
	}
	rec, _ := reg.FindByID(id)
	if rec.Status != "revoked" || rec.RevokedAt == "" {
		t.Fatalf("revoke didn't stick: %+v", rec)
	}
	if err := reg.Revoke(id); err != nil {
		t.Fatalf("idempotent revoke must succeed: %v", err)
	}
}

func TestDeviceRegistry_TouchLastSeen(t *testing.T) {
	db := testStateDB(t)
	reg := NewDeviceRegistry(db)
	id, err := reg.RegisterDeviceForUser(testutil.ECDSAPubKeyPEM(t), "phone", "user-abc", "")
	if err != nil {
		t.Fatal(err)
	}

	if err := reg.TouchLastSeen(id, time.Hour); err != nil {
		t.Fatal(err)
	}
	rec, _ := reg.FindByID(id)
	if rec.LastSeenAt == "" {
		t.Fatal("expected last_seen_at to be set")
	}
	first := rec.LastSeenAt

	if err := reg.TouchLastSeen(id, time.Hour); err != nil {
		t.Fatal(err)
	}
	rec, _ = reg.FindByID(id)
	if rec.LastSeenAt != first {
		t.Fatalf("throttled touch rewrote stamp: %s -> %s", first, rec.LastSeenAt)
	}

	stale := time.Now().UTC().Add(-2 * time.Hour).Format(time.RFC3339)
	if _, err := db.Exec("UPDATE devices SET last_seen_at=? WHERE device_id=?", stale, id); err != nil {
		t.Fatal(err)
	}
	if err := reg.TouchLastSeen(id, time.Hour); err != nil {
		t.Fatal(err)
	}
	rec, _ = reg.FindByID(id)
	if rec.LastSeenAt != stale {
		t.Fatalf("memoized throttle still wrote: %s", rec.LastSeenAt)
	}

	reg = NewDeviceRegistry(db)
	if err := reg.TouchLastSeen(id, time.Hour); err != nil {
		t.Fatal(err)
	}
	rec, _ = reg.FindByID(id)
	if rec.LastSeenAt == "" || rec.LastSeenAt <= time.Now().UTC().Add(-time.Hour).Format(time.RFC3339) {
		t.Fatalf("expected refreshed stamp, got %s", rec.LastSeenAt)
	}

	if err := reg.Revoke(id); err != nil {
		t.Fatal(err)
	}
	if _, err := db.Exec("UPDATE devices SET last_seen_at='' WHERE device_id=?", id); err != nil {
		t.Fatal(err)
	}
	if err := reg.TouchLastSeen(id, 0); err != nil {
		t.Fatal(err)
	}
	rec, _ = reg.FindByID(id)
	if rec.LastSeenAt != "" {
		t.Fatal("revoked device must not receive a last_seen stamp")
	}
}

func TestDeviceRegistry_Rename(t *testing.T) {
	r := NewDeviceRegistry(testStateDB(t))
	pub, _ := generateTestKeyPair(t)
	id, err := r.RegisterDeviceForUser(pub, "orig", "u1", "lbl")
	if err != nil {
		t.Fatal(err)
	}
	name := "new name"
	if err := r.Rename(id, &name, nil); err != nil {
		t.Fatal(err)
	}
	d, _ := r.FindByID(id)
	if d.DeviceName != "new name" || d.DeviceLabel != "lbl" {
		t.Fatalf("partial rename: %+v", d)
	}
	label := "new label"
	if err := r.Rename(id, nil, &label); err != nil {
		t.Fatal(err)
	}
	d, _ = r.FindByID(id)
	if d.DeviceName != "new name" || d.DeviceLabel != "new label" {
		t.Fatalf("label rename: %+v", d)
	}
	long := strings.Repeat("x", MaxDeviceNameLen+1)
	if err := r.Rename(id, &long, nil); !errors.Is(err, ErrNameTooLong) {
		t.Fatalf("over-long name: got %v", err)
	}
	if err := r.Rename("nope", &name, nil); !errors.Is(err, fs.ErrNotExist) {
		t.Fatalf("unknown device: got %v", err)
	}
	if _, err := r.RegisterDeviceForUser(func() string { p, _ := generateTestKeyPair(t); return p }(), long, "u1", ""); !errors.Is(err, ErrNameTooLong) {
		t.Fatalf("register with over-long name: got %v", err)
	}
}
