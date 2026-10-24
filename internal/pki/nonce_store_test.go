package pki

import (
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

func TestNonceStore_PutTake_Success(t *testing.T) {
	s := NewNonceStore()
	s.Put("n1", NonceEntry{PublicKeyPEM: "pk1", ServerFingerprint: "fp", ExpiresAt: time.Now().Add(time.Second)})
	got, ok := s.Take("n1")
	if !ok {
		t.Fatalf("expected Take to succeed")
	}
	if got.PublicKeyPEM != "pk1" {
		t.Fatalf("wrong pubkey: %q", got.PublicKeyPEM)
	}
	if _, ok := s.Take("n1"); ok {
		t.Fatalf("second Take must fail (single-use)")
	}
}

func TestNonceStore_TakeExpired_NotFound(t *testing.T) {
	s := NewNonceStore()
	s.Put("n1", NonceEntry{PublicKeyPEM: "pk1", ExpiresAt: time.Now().Add(-time.Second)})
	if _, ok := s.Take("n1"); ok {
		t.Fatal("expired nonce must not be returned")
	}
}

func TestNonceStore_TakeMissing_NotFound(t *testing.T) {
	s := NewNonceStore()
	if _, ok := s.Take("absent"); ok {
		t.Fatal("missing nonce must not be returned")
	}
}

func TestNonceStore_TakeAtomic_ConcurrentSingleWinner(t *testing.T) {
	s := NewNonceStore()
	s.Put("n", NonceEntry{PublicKeyPEM: "pk", ExpiresAt: time.Now().Add(time.Second)})

	const workers = 100
	var wins int32
	var wg sync.WaitGroup
	wg.Add(workers)
	for i := 0; i < workers; i++ {
		go func() {
			defer wg.Done()
			if _, ok := s.Take("n"); ok {
				atomic.AddInt32(&wins, 1)
			}
		}()
	}
	wg.Wait()
	if wins != 1 {
		t.Fatalf("expected exactly one winner, got %d", wins)
	}
}

func TestNonceStore_Sweep_RemovesExpired(t *testing.T) {
	s := NewNonceStore()
	now := time.Now()
	s.Put("old", NonceEntry{PublicKeyPEM: "a", ExpiresAt: now.Add(-time.Second)})
	s.Put("new", NonceEntry{PublicKeyPEM: "b", ExpiresAt: now.Add(time.Minute)})
	s.Sweep(now)
	if _, ok := s.Take("old"); ok {
		t.Fatal("old should have been swept")
	}
	if _, ok := s.Take("new"); !ok {
		t.Fatal("new should survive")
	}
}
