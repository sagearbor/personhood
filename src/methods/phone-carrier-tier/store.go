package phonecarriertier

import (
	"context"
	"crypto/subtle"
	"sync"
	"time"
)

// MaxAttempts is the number of incorrect Verify calls tolerated before an OTP
// is invalidated.
const MaxAttempts = 3

// OTPStore persists outstanding one-time passwords between BeginCeremony and
// CompleteCeremony. Keys are opaque strings chosen by the caller. The store
// MUST evict entries past expiresAt and track per-key attempt counts.
// Implementations MUST be safe for concurrent use.
type OTPStore interface {
	// Put stores otp under key with the given expiry, overwriting any previous
	// entry and resetting the attempt counter.
	Put(ctx context.Context, key, otp string, expiresAt time.Time) error

	// Verify compares attempt against the stored OTP in constant time. A missing
	// or expired entry is reported as valid=false, attemptsRemaining=0, nil err.
	Verify(ctx context.Context, key, attempt string) (valid bool, attemptsRemaining int, err error)

	// Invalidate removes any entry for key. Idempotent.
	Invalidate(ctx context.Context, key string) error
}

// InMemoryStore is a mutex-protected map-backed OTPStore for dev, tests, and
// single-process deployments. Production should swap in Redis so the attempt
// counter is shared across replicas.
type InMemoryStore struct {
	mu      sync.Mutex
	entries map[string]*otpEntry
}

type otpEntry struct {
	otp       string
	expiresAt time.Time
	attempts  int
	invalid   bool
}

// NewInMemoryStore constructs an empty InMemoryStore.
func NewInMemoryStore() *InMemoryStore {
	return &InMemoryStore{entries: make(map[string]*otpEntry)}
}

// Put implements OTPStore.
func (s *InMemoryStore) Put(_ context.Context, key, otp string, expiresAt time.Time) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.entries[key] = &otpEntry{otp: otp, expiresAt: expiresAt}
	return nil
}

// Verify implements OTPStore using a constant-time compare to remove a timing
// oracle.
func (s *InMemoryStore) Verify(_ context.Context, key, attempt string) (bool, int, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	entry, ok := s.entries[key]
	if !ok || entry.invalid {
		return false, 0, nil
	}
	if time.Now().After(entry.expiresAt) {
		delete(s.entries, key)
		return false, 0, nil
	}

	match := subtle.ConstantTimeCompare([]byte(entry.otp), []byte(attempt)) == 1
	if match {
		entry.invalid = true
		return true, 0, nil
	}

	entry.attempts++
	remaining := MaxAttempts - entry.attempts
	if remaining <= 0 {
		entry.invalid = true
		return false, 0, nil
	}
	return false, remaining, nil
}

// Invalidate implements OTPStore.
func (s *InMemoryStore) Invalidate(_ context.Context, key string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	delete(s.entries, key)
	return nil
}
