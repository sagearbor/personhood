package server

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"errors"
	"fmt"
	"os"
	"sync"
	"time"

	"github.com/sagearbor/personhood/pkg/redisclient"
	"github.com/sagearbor/personhood/pkg/types"
)

// ErrSessionNotFound is returned by SessionStore.Get when the requested
// session does not exist or has expired.
var ErrSessionNotFound = errors.New("server: session not found or expired")

// ErrSessionAlreadyIssued is returned when an issue-credential call is made
// on a session that already produced a credential. Sessions are single-use
// from the credential issuance side; clients must start a new session to
// reissue.
var ErrSessionAlreadyIssued = errors.New("server: session already issued a credential")

// SessionStore is the interface the server uses to persist per-enrollment
// state between /enrollment/start and /credentials/issue.
//
// InMemorySessionStore (this file) is the default, single-process backend.
// RedisSessionStore (session_redis.go) is selected instead when REDIS_URL is
// set (see NewSessionStoreFromEnv), so sessions survive process restarts and
// are shared across horizontally scaled issuer replicas.
//
// Every method returns SessionView, a plain, JSON-friendly value — never a
// mutable pointer — so both backends can share one call-site contract in
// handlers.go regardless of whether "the session" lives in a process-local
// map or a remote store.
//
// Implementations MUST be safe for concurrent use.
type SessionStore interface {
	// Create makes a fresh session bound to holderPublicKey (nil if the
	// client supplied none) and returns its view. now is the creation
	// timestamp; the returned ExpiresAt is now plus the store's configured
	// TTL.
	Create(holderPublicKey ed25519.PublicKey, now time.Time) (SessionView, error)

	// Get returns the current view of the session with the given ID, or
	// ErrSessionNotFound if it does not exist or has expired.
	Get(id string) (SessionView, error)

	// RecordMethodResult appends a successful MethodResult to the session as
	// a frozen VerifiedMethod entry. metadata supplies the strength +
	// freshness fields the credential needs.
	//
	// If metadata.Type is MethodTypeAnchor, the session's AnchorMethodID is
	// set (or replaced) so the next issuance call can record it on the
	// credential. Returns an error if result.Success is false, or
	// ErrSessionAlreadyIssued if the session already issued a credential.
	RecordMethodResult(sessionID string, result types.MethodResult, metadata types.MethodMetadata) error

	// MarkIssued stamps the session with the credential ID it produced,
	// blocking future RecordMethodResult / issue calls. Returns
	// ErrSessionAlreadyIssued if already marked.
	MarkIssued(sessionID, credentialID string) error
}

// SessionView is the lockless, JSON-friendly snapshot every SessionStore
// method returns. Mutating its fields has no effect on the underlying store.
type SessionView struct {
	ID        string    `json:"id"`
	HolderDID types.DID `json:"holder_did"`
	// HolderPublicKey is the client-supplied Ed25519 public key backing
	// HolderDID (nil when the client did not supply one). Marshals as
	// standard base64 under holder_public_key_b64; omitted entirely when nil.
	HolderPublicKey    ed25519.PublicKey      `json:"holder_public_key_b64,omitempty"`
	CreatedAt          time.Time              `json:"created_at"`
	ExpiresAt          time.Time              `json:"expires_at"`
	VerifiedMethods    []types.VerifiedMethod `json:"verified_methods"`
	AnchorMethodID     *string                `json:"anchor_method_id,omitempty"`
	IssuedCredentialID string                 `json:"issued_credential_id,omitempty"`
}

// NewSessionStoreFromEnv returns a RedisSessionStore when REDIS_URL is set,
// or an InMemorySessionStore (the default) otherwise. This mirrors the
// env-aware factory pattern already used for delivery (email.NewSenderFromEnv,
// sms.NewSenderFromEnv): the in-memory backend needs no configuration and
// stays the default so existing single-process deployments (including
// round-1) are unaffected; setting REDIS_URL is opt-in.
func NewSessionStoreFromEnv(ttl time.Duration) (SessionStore, error) {
	redisURL := os.Getenv("REDIS_URL")
	if redisURL == "" {
		return NewInMemorySessionStore(ttl), nil
	}
	client, err := redisclient.ParseURL(redisURL)
	if err != nil {
		return nil, fmt.Errorf("server: REDIS_URL: %w", err)
	}
	return NewRedisSessionStore(client, ttl), nil
}

// ----------------------------------------------------------------------------
// InMemorySessionStore
// ----------------------------------------------------------------------------

// session is the per-enrollment state InMemorySessionStore tracks in process
// memory. All mutations MUST go through InMemorySessionStore's methods,
// which take the per-session lock.
type session struct {
	id                 string
	holderDID          types.DID
	holderPublicKey    ed25519.PublicKey
	createdAt          time.Time
	expiresAt          time.Time
	verifiedMethods    []types.VerifiedMethod
	anchorMethodID     *string
	issuedCredentialID string

	mu sync.Mutex
}

func (sess *session) view() SessionView {
	sess.mu.Lock()
	defer sess.mu.Unlock()

	methodsCopy := make([]types.VerifiedMethod, len(sess.verifiedMethods))
	copy(methodsCopy, sess.verifiedMethods)

	var anchor *string
	if sess.anchorMethodID != nil {
		v := *sess.anchorMethodID
		anchor = &v
	}

	var holderPub ed25519.PublicKey
	if len(sess.holderPublicKey) == ed25519.PublicKeySize {
		holderPub = append(ed25519.PublicKey(nil), sess.holderPublicKey...)
	}

	return SessionView{
		ID:                 sess.id,
		HolderDID:          sess.holderDID,
		HolderPublicKey:    holderPub,
		CreatedAt:          sess.createdAt,
		ExpiresAt:          sess.expiresAt,
		VerifiedMethods:    methodsCopy,
		AnchorMethodID:     anchor,
		IssuedCredentialID: sess.issuedCredentialID,
	}
}

// InMemorySessionStore is the in-process catalogue of active enrollment
// sessions. Safe for concurrent use. Expired entries are evicted lazily on
// Get. Scoped to one process — see NewSessionStoreFromEnv for the
// Redis-backed alternative used when horizontally scaling.
type InMemorySessionStore struct {
	ttl time.Duration

	mu       sync.RWMutex
	sessions map[string]*session
}

// NewInMemorySessionStore constructs an InMemorySessionStore with the given
// session TTL.
func NewInMemorySessionStore(ttl time.Duration) *InMemorySessionStore {
	if ttl <= 0 {
		ttl = time.Hour
	}
	return &InMemorySessionStore{
		ttl:      ttl,
		sessions: make(map[string]*session),
	}
}

// Create implements SessionStore.
func (s *InMemorySessionStore) Create(holderPublicKey ed25519.PublicKey, now time.Time) (SessionView, error) {
	id, err := randomSessionID()
	if err != nil {
		return SessionView{}, err
	}
	holderDID := HolderDIDForSession(id, holderPublicKey)
	var pubCopy ed25519.PublicKey
	if len(holderPublicKey) == ed25519.PublicKeySize {
		pubCopy = append(ed25519.PublicKey(nil), holderPublicKey...)
	}
	sess := &session{
		id:              id,
		holderDID:       holderDID,
		holderPublicKey: pubCopy,
		createdAt:       now,
		expiresAt:       now.Add(s.ttl),
	}
	s.mu.Lock()
	s.sessions[id] = sess
	s.mu.Unlock()
	return sess.view(), nil
}

// get returns the live *session for id, or ErrSessionNotFound.
func (s *InMemorySessionStore) get(id string) (*session, error) {
	s.mu.RLock()
	sess, ok := s.sessions[id]
	s.mu.RUnlock()
	if !ok {
		return nil, ErrSessionNotFound
	}
	if time.Now().After(sess.expiresAt) {
		s.mu.Lock()
		delete(s.sessions, id)
		s.mu.Unlock()
		return nil, ErrSessionNotFound
	}
	return sess, nil
}

// Get implements SessionStore.
func (s *InMemorySessionStore) Get(id string) (SessionView, error) {
	sess, err := s.get(id)
	if err != nil {
		return SessionView{}, err
	}
	return sess.view(), nil
}

// RecordMethodResult implements SessionStore.
func (s *InMemorySessionStore) RecordMethodResult(sessionID string, result types.MethodResult, metadata types.MethodMetadata) error {
	if !result.Success {
		return errors.New("server: cannot record a failed MethodResult")
	}
	sess, err := s.get(sessionID)
	if err != nil {
		return err
	}
	sess.mu.Lock()
	defer sess.mu.Unlock()

	if sess.issuedCredentialID != "" {
		return ErrSessionAlreadyIssued
	}

	// Replace any previous entry for the same method ID rather than appending
	// duplicates; a user who re-runs a ceremony should overwrite, not stack.
	replaced := false
	for i, vm := range sess.verifiedMethods {
		if vm.MethodID == result.MethodID {
			sess.verifiedMethods[i] = types.VerifiedMethod{
				MethodID:          result.MethodID,
				Strength:          metadata.Strength,
				VerifiedAt:        result.VerifiedAt,
				FreshnessLifetime: metadata.FreshnessLifetime,
				AttestationDigest: result.AttestationDigest,
			}
			replaced = true
			break
		}
	}
	if !replaced {
		sess.verifiedMethods = append(sess.verifiedMethods, types.VerifiedMethod{
			MethodID:          result.MethodID,
			Strength:          metadata.Strength,
			VerifiedAt:        result.VerifiedAt,
			FreshnessLifetime: metadata.FreshnessLifetime,
			AttestationDigest: result.AttestationDigest,
		})
	}

	if metadata.Type == types.MethodTypeAnchor {
		id := result.MethodID
		sess.anchorMethodID = &id
	}
	return nil
}

// MarkIssued implements SessionStore.
func (s *InMemorySessionStore) MarkIssued(sessionID, credentialID string) error {
	sess, err := s.get(sessionID)
	if err != nil {
		return err
	}
	sess.mu.Lock()
	defer sess.mu.Unlock()
	if sess.issuedCredentialID != "" {
		return ErrSessionAlreadyIssued
	}
	sess.issuedCredentialID = credentialID
	return nil
}

// randomSessionID returns a 32-byte base64url (no padding) random string.
func randomSessionID() (string, error) {
	buf := make([]byte, 32)
	if _, err := rand.Read(buf); err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(buf), nil
}
