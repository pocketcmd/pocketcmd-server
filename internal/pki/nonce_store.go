package pki

import (
	"sync"
	"time"
)

type NonceEntry struct {
	PublicKeyPEM      string
	ServerFingerprint string
	ExpiresAt         time.Time
}

type NonceStore struct {
	mu      sync.Mutex
	entries map[string]NonceEntry
}

func NewNonceStore() *NonceStore {
	return &NonceStore{entries: make(map[string]NonceEntry)}
}

func (s *NonceStore) Put(nonce string, e NonceEntry) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.entries[nonce] = e
}

func (s *NonceStore) Take(nonce string) (NonceEntry, bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	e, ok := s.entries[nonce]
	if !ok {
		return NonceEntry{}, false
	}
	delete(s.entries, nonce)
	if time.Now().After(e.ExpiresAt) {
		return NonceEntry{}, false
	}
	return e, true
}

func (s *NonceStore) Sweep(now time.Time) {
	s.mu.Lock()
	defer s.mu.Unlock()
	for k, v := range s.entries {
		if now.After(v.ExpiresAt) {
			delete(s.entries, k)
		}
	}
}
