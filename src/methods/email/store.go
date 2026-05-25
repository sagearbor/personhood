package email

import (
	"context"
	"errors"
	"sync"
	"time"
)

// ErrTokenNotFound is returned by TokenStore.Lookup when no entry exists for
// the (sessionID, token) pair, or the entry has expired and been evicted.
var ErrTokenNotFound = errors.New("email: magic-link token not found or expired")

// TokenStore is the abstraction the Email method uses to persist outstanding
// magic-link tokens between BeginCeremony and CompleteCeremony.
//
// Implementations MUST be safe for concurrent use. Production deployments are
// expected to back this with Redis (or similar) so that ceremonies can be
// completed across issuer process boundaries.
type TokenStore interface {
	// Put stores token for sessionID together with the email address the link
	// was sent to. The entry MUST be evicted (or treated as missing) once
	// expiresAt has passed.
	Put(ctx context.Context, sessionID, token, email string, expiresAt time.Time) error

	// Lookup returns the email that was bound to (sessionID, token) at Put
	// time, and reports whether a non-expired entry was found.
	//
	// A non-nil error indicates an internal store failure; a normal cache miss
	// or expiry MUST be reported as found=false with a nil error.
	Lookup(ctx context.Context, sessionID, token string) (email string, found bool, err error)

	// Delete removes any entry associated with sessionID. It is idempotent:
	// deleting a non-existent entry returns nil.
	Delete(ctx context.Context, sessionID string) error
}

// InMemoryStore is a sync.Map-backed TokenStore suitable for dev, tests, and
// single-process deployments. Entries are keyed by sessionID; only one
// outstanding token per session is supported (Put overwrites any previous
// entry).
//
// Production should swap in a Redis-backed implementation so that horizontally
// scaled issuers and post-restart sessions both work.
type InMemoryStore struct {
	entries sync.Map // map[string]inMemoryEntry, keyed by sessionID
}

type inMemoryEntry struct {
	token     string
	email     string
	expiresAt time.Time
}

// NewInMemoryStore constructs an empty InMemoryStore.
func NewInMemoryStore() *InMemoryStore {
	return &InMemoryStore{}
}

// Put implements TokenStore.
func (s *InMemoryStore) Put(_ context.Context, sessionID, token, email string, expiresAt time.Time) error {
	s.entries.Store(sessionID, inMemoryEntry{
		token:     token,
		email:     email,
		expiresAt: expiresAt,
	})
	return nil
}

// Lookup implements TokenStore.
func (s *InMemoryStore) Lookup(_ context.Context, sessionID, token string) (string, bool, error) {
	v, ok := s.entries.Load(sessionID)
	if !ok {
		return "", false, nil
	}
	entry := v.(inMemoryEntry)
	if time.Now().After(entry.expiresAt) {
		s.entries.Delete(sessionID)
		return "", false, nil
	}
	if entry.token != token {
		return "", false, nil
	}
	return entry.email, true, nil
}

// Delete implements TokenStore.
func (s *InMemoryStore) Delete(_ context.Context, sessionID string) error {
	s.entries.Delete(sessionID)
	return nil
}
