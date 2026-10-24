package pki

import (
	"strings"
	"testing"
)

func TestDeviceRegistry_FindByPubKeyPrefix_RejectsEmptyAndShort(t *testing.T) {
	reg := NewDeviceRegistry(testStateDB(t))
	pubKey, _ := generateTestKeyPair(t)
	id, err := reg.RegisterDeviceForUser(pubKey, "iPhone", "test-user", "")
	if err != nil {
		t.Fatal(err)
	}
	for _, prefix := range []string{"", id[:1], id[:MinPrefixLen-1]} {
		dev, err := reg.FindByPubKeyPrefix(prefix)
		if err == nil || dev != nil {
			t.Fatalf("prefix %q must be refused, got dev=%v err=%v", prefix, dev, err)
		}
		if !strings.Contains(err.Error(), "at least") {
			t.Fatalf("prefix %q: unexpected error %v", prefix, err)
		}
	}
	if _, err := reg.FindByPubKeyPrefix(id[:MinPrefixLen]); err != nil {
		t.Fatalf("minimum-length prefix must work: %v", err)
	}
}
