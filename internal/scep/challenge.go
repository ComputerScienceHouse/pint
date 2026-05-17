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
	platform   string
	expiresAt  time.Time
}

// ChallengeStore issues and validates one-time SCEP enrollment challenges.
type ChallengeStore struct {
	mu      sync.Mutex
	entries map[string]challengeEntry
	stop    chan struct{}
}

func NewChallengeStore() *ChallengeStore {
	s := &ChallengeStore{
		entries: make(map[string]challengeEntry),
		stop:    make(chan struct{}),
	}
	go s.reap()
	return s
}

// Stop terminates the background reaper goroutine. Call during shutdown or in tests.
func (s *ChallengeStore) Stop() {
	close(s.stop)
}

// Issue generates a new challenge token associated with username, an optional
// device name, and an optional platform string.
func (s *ChallengeStore) Issue(username, deviceName, platform string) (string, error) {
	b := make([]byte, 16)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	token := hex.EncodeToString(b)
	s.mu.Lock()
	s.entries[token] = challengeEntry{
		username:   username,
		deviceName: deviceName,
		platform:   platform,
		expiresAt:  time.Now().Add(challengeTTL),
	}
	s.mu.Unlock()
	return token, nil
}

// Validate checks the challenge and returns the username, device name, and
// platform if valid, consuming the entry.
func (s *ChallengeStore) Validate(challenge string) (username, deviceName, platform string, ok bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	e, exists := s.entries[challenge]
	if !exists || time.Now().After(e.expiresAt) {
		delete(s.entries, challenge)
		return "", "", "", false
	}
	delete(s.entries, challenge)
	return e.username, e.deviceName, e.platform, true
}

func (s *ChallengeStore) reap() {
	// Tick at TTL/4 so entries are cleaned up promptly; ticking at TTL lets entries
	// live up to ~2×TTL before being evicted.
	ticker := time.NewTicker(challengeTTL / 4)
	defer ticker.Stop()
	for {
		select {
		case <-s.stop:
			return
		case t := <-ticker.C:
			s.mu.Lock()
			for k, e := range s.entries {
				if t.After(e.expiresAt) {
					delete(s.entries, k)
				}
			}
			s.mu.Unlock()
		}
	}
}
