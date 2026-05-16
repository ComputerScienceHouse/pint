package scep

import (
	"crypto/rand"
	"encoding/hex"
	"sync"
	"time"
)

const challengeTTL = 15 * time.Minute

type challengeEntry struct {
	username   string
	deviceName string
	expiresAt  time.Time
}

// ChallengeStore issues and validates one-time SCEP enrollment challenges.
type ChallengeStore struct {
	mu      sync.Mutex
	entries map[string]challengeEntry
}

func NewChallengeStore() *ChallengeStore {
	s := &ChallengeStore{entries: make(map[string]challengeEntry)}
	go s.reap()
	return s
}

// Issue generates a new challenge token associated with username and an optional device name.
func (s *ChallengeStore) Issue(username, deviceName string) (string, error) {
	b := make([]byte, 16)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	token := hex.EncodeToString(b)
	s.mu.Lock()
	s.entries[token] = challengeEntry{username: username, deviceName: deviceName, expiresAt: time.Now().Add(challengeTTL)}
	s.mu.Unlock()
	return token, nil
}

// Validate checks the challenge and returns the username and device name if valid, consuming the entry.
func (s *ChallengeStore) Validate(challenge string) (username, deviceName string, ok bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	e, exists := s.entries[challenge]
	if !exists || time.Now().After(e.expiresAt) {
		delete(s.entries, challenge)
		return "", "", false
	}
	delete(s.entries, challenge)
	return e.username, e.deviceName, true
}

func (s *ChallengeStore) reap() {
	ticker := time.NewTicker(challengeTTL)
	defer ticker.Stop()
	for range ticker.C {
		now := time.Now()
		s.mu.Lock()
		for k, e := range s.entries {
			if now.After(e.expiresAt) {
				delete(s.entries, k)
			}
		}
		s.mu.Unlock()
	}
}
