package appattestdevice

import (
	"context"
	"errors"
	"sync"
)

// ErrNoChallenge is returned by ChallengeStore.GetChallenge when no challenge
// nonce has been issued (or it has already been consumed) for the session.
var ErrNoChallenge = errors.New("app-attest-device: no challenge issued for session")

// ChallengeStore persists the server-issued challenge nonce between
// BeginCeremony and CompleteCeremony. The device must sign exactly this nonce
// in its attestation, which is what binds the attestation to this ceremony and
// defeats replay.
//
// Keys are the issuer SessionID. Implementations MUST be safe for concurrent
// use.
type ChallengeStore interface {
	// PutChallenge stores nonce against sessionID, overwriting any previous
	// entry.
	PutChallenge(ctx context.Context, sessionID, nonce string) error

	// GetChallenge returns the nonce stored for sessionID, or ErrNoChallenge if
	// none exists.
	GetChallenge(ctx context.Context, sessionID string) (string, error)
}

// InMemoryStore is a sync.Map-backed ChallengeStore suitable for dev, tests,
// and single-process deployments. Production should swap in a shared backend
// (Redis/Postgres) so the challenge is visible to every issuer replica.
type InMemoryStore struct {
	bySession sync.Map // sessionID -> nonce (string)
}

// NewInMemoryStore returns an empty InMemoryStore.
func NewInMemoryStore() *InMemoryStore { return &InMemoryStore{} }

// PutChallenge implements ChallengeStore.
func (s *InMemoryStore) PutChallenge(_ context.Context, sessionID, nonce string) error {
	if sessionID == "" || nonce == "" {
		return errors.New("app-attest-device: PutChallenge requires non-empty sessionID and nonce")
	}
	s.bySession.Store(sessionID, nonce)
	return nil
}

// GetChallenge implements ChallengeStore.
func (s *InMemoryStore) GetChallenge(_ context.Context, sessionID string) (string, error) {
	v, ok := s.bySession.Load(sessionID)
	if !ok {
		return "", ErrNoChallenge
	}
	return v.(string), nil
}
