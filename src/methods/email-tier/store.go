package emailtier

import (
	"context"
	"sync"
	"time"
)

// TokenStore persists outstanding magic-link tokens between BeginCeremony and
// CompleteCeremony. Implementations MUST be safe for concurrent use;
// production should back this with Redis so ceremonies survive process
// boundaries.
type TokenStore interface {
	// Put stores token for sessionID together with the bound email address and
	// the enrichment Signal captured at Begin time. The entry MUST be treated
	// as missing once expiresAt has passed.
	Put(ctx context.Context, sessionID, token, email string, signal Signal, expiresAt time.Time) error

	// Lookup returns the email and Signal bound to (sessionID, token) at Put
	// time, reporting whether a non-expired entry was found. A normal miss /
	// expiry MUST be reported as found=false with a nil error.
	Lookup(ctx context.Context, sessionID, token string) (email string, signal Signal, found bool, err error)

	// Delete removes any entry for sessionID. Idempotent.
	Delete(ctx context.Context, sessionID string) error
}

// InMemoryStore is a sync.Map-backed TokenStore for dev, tests, and
// single-process deployments. Only one outstanding token per session is
// supported (Put overwrites any previous entry).
type InMemoryStore struct {
	entries sync.Map // sessionID -> inMemoryEntry
}

type inMemoryEntry struct {
	token     string
	email     string
	signal    Signal
	expiresAt time.Time
}

// NewInMemoryStore constructs an empty InMemoryStore.
func NewInMemoryStore() *InMemoryStore { return &InMemoryStore{} }

// Put implements TokenStore.
func (s *InMemoryStore) Put(_ context.Context, sessionID, token, email string, signal Signal, expiresAt time.Time) error {
	s.entries.Store(sessionID, inMemoryEntry{
		token:     token,
		email:     email,
		signal:    signal,
		expiresAt: expiresAt,
	})
	return nil
}

// Lookup implements TokenStore.
func (s *InMemoryStore) Lookup(_ context.Context, sessionID, token string) (string, Signal, bool, error) {
	v, ok := s.entries.Load(sessionID)
	if !ok {
		return "", Signal{}, false, nil
	}
	entry := v.(inMemoryEntry)
	if time.Now().After(entry.expiresAt) {
		s.entries.Delete(sessionID)
		return "", Signal{}, false, nil
	}
	if entry.token != token {
		return "", Signal{}, false, nil
	}
	return entry.email, entry.signal, true, nil
}

// Delete implements TokenStore.
func (s *InMemoryStore) Delete(_ context.Context, sessionID string) error {
	s.entries.Delete(sessionID)
	return nil
}
