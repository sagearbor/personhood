package sms

import (
	"context"
	"crypto/subtle"
	"errors"
	"sync"
	"time"
)

// ErrOTPNotFound is returned by OTPStore.Verify when no entry exists for the
// provided key (either it was never Put, or it has expired / been
// invalidated).
var ErrOTPNotFound = errors.New("sms: otp not found or expired")

// MaxAttempts is the number of incorrect Verify calls tolerated before an
// OTP is invalidated. The 4th wrong call (or any call after invalidation)
// reports valid=false and attemptsRemaining=0.
const MaxAttempts = 3

// OTPStore is the abstraction the SMS method uses to persist outstanding
// one-time passwords between BeginCeremony and CompleteCeremony.
//
// Keys are opaque strings chosen by the caller (the SMS method composes
// "<sessionID>:<phoneNumber>"). The store MUST evict entries past expiresAt
// and MUST track per-key attempt counts.
//
// Implementations MUST be safe for concurrent use.
type OTPStore interface {
	// Put stores otp under key with the given expiry. It overwrites any
	// previous entry and resets the attempt counter to zero.
	Put(ctx context.Context, key, otp string, expiresAt time.Time) error

	// Verify compares attempt against the stored OTP, in constant time,
	// returning:
	//   - valid: true iff the attempt matches a non-expired entry that has
	//     not yet exceeded MaxAttempts.
	//   - attemptsRemaining: how many additional Verify calls the caller may
	//     make for this key before lockout. After a successful Verify the
	//     entry is invalidated, so attemptsRemaining is 0.
	//   - err: non-nil only for internal store failures; a missing or
	//     expired entry is reported as valid=false, attemptsRemaining=0, nil
	//     error.
	Verify(ctx context.Context, key, attempt string) (valid bool, attemptsRemaining int, err error)

	// Invalidate removes any entry for key. Idempotent.
	Invalidate(ctx context.Context, key string) error
}

// InMemoryStore is a mutex-protected map-backed OTPStore suitable for dev,
// tests, and single-process deployments.
//
// Production should swap in a Redis-backed implementation so that the
// attempt counter is shared across all issuer processes (otherwise an
// attacker can simply round-robin requests across replicas to defeat the
// lockout).
type InMemoryStore struct {
	mu      sync.Mutex
	entries map[string]*otpEntry
}

type otpEntry struct {
	otp       string
	expiresAt time.Time
	attempts  int
	invalid   bool // set after success or lockout
}

// NewInMemoryStore constructs an empty InMemoryStore.
func NewInMemoryStore() *InMemoryStore {
	return &InMemoryStore{entries: make(map[string]*otpEntry)}
}

// Put implements OTPStore.
func (s *InMemoryStore) Put(_ context.Context, key, otp string, expiresAt time.Time) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.entries[key] = &otpEntry{
		otp:       otp,
		expiresAt: expiresAt,
	}
	return nil
}

// Verify implements OTPStore. The comparison uses crypto/subtle.ConstantTimeCompare
// to remove a code-vs-attempt timing oracle.
func (s *InMemoryStore) Verify(_ context.Context, key, attempt string) (bool, int, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	entry, ok := s.entries[key]
	if !ok {
		return false, 0, nil
	}
	if entry.invalid {
		return false, 0, nil
	}
	if time.Now().After(entry.expiresAt) {
		delete(s.entries, key)
		return false, 0, nil
	}

	// Always perform the constant-time compare even if attempts are about to
	// be exceeded, so that the timing of a 3rd-wrong-attempt failure matches
	// a 1st-wrong-attempt failure (the latter still does the compare).
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
