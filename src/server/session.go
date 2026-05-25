package server

import (
	"crypto/rand"
	"encoding/base64"
	"errors"
	"sync"
	"time"

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

// Session is the per-enrollment state the server tracks between
// /enrollment/start and /credentials/issue.
//
// All mutations MUST go through SessionStore's helper methods, which take
// per-session locks; the fields are exported only so handlers can read them.
type Session struct {
	// ID is the opaque session identifier returned to the client. v0.1
	// generates 32 bytes of randomness, base64url-encoded.
	ID string

	// HolderDID is the DID the credential will be bound to. v0.1 generates
	// it server-side from the SessionID (see did.go); future clients can
	// provide their own public key in /enrollment/start.
	HolderDID types.DID

	// CreatedAt and ExpiresAt define the session's lifetime.
	CreatedAt time.Time
	ExpiresAt time.Time

	// VerifiedMethods accumulates one entry per successful method ceremony
	// during this session. Order is insertion order.
	VerifiedMethods []types.VerifiedMethod

	// AnchorMethodID names the anchor method, if any, whose completion has
	// been recorded. Set by RecordMethodResult when the completed method's
	// metadata classifies it as MethodTypeAnchor.
	AnchorMethodID *string

	// IssuedCredentialID is non-empty once /credentials/issue has produced a
	// credential for this session. Used to prevent double-issuance.
	IssuedCredentialID string

	mu sync.Mutex
}

// SessionStore is the in-process catalogue of active enrollment sessions.
//
// Safe for concurrent use. Expired entries are evicted lazily on Get.
type SessionStore struct {
	ttl time.Duration

	mu       sync.RWMutex
	sessions map[string]*Session
}

// NewSessionStore constructs a SessionStore with the given session TTL.
func NewSessionStore(ttl time.Duration) *SessionStore {
	if ttl <= 0 {
		ttl = time.Hour
	}
	return &SessionStore{
		ttl:      ttl,
		sessions: make(map[string]*Session),
	}
}

// Create generates a fresh Session keyed by a 32-byte random ID. holderDID
// is bound onto the session and propagated into every subsequent ceremony.
func (s *SessionStore) Create(holderDID types.DID, now time.Time) (*Session, error) {
	id, err := randomSessionID()
	if err != nil {
		return nil, err
	}
	sess := &Session{
		ID:        id,
		HolderDID: holderDID,
		CreatedAt: now,
		ExpiresAt: now.Add(s.ttl),
	}
	s.mu.Lock()
	s.sessions[id] = sess
	s.mu.Unlock()
	return sess, nil
}

// Get returns the session with the given ID, or ErrSessionNotFound. Expired
// sessions are deleted on read so the caller never observes them.
func (s *SessionStore) Get(id string) (*Session, error) {
	s.mu.RLock()
	sess, ok := s.sessions[id]
	s.mu.RUnlock()
	if !ok {
		return nil, ErrSessionNotFound
	}
	if time.Now().After(sess.ExpiresAt) {
		s.mu.Lock()
		delete(s.sessions, id)
		s.mu.Unlock()
		return nil, ErrSessionNotFound
	}
	return sess, nil
}

// RecordMethodResult appends a successful MethodResult to the session as a
// frozen VerifiedMethod entry. metadata supplies the strength + freshness
// fields the credential needs.
//
// If metadata.Type is MethodTypeAnchor, the session's AnchorMethodID is set
// (or replaced) so the next issuance call can record it on the credential.
// Returns an error if result.Success is false.
func (s *SessionStore) RecordMethodResult(sessionID string, result types.MethodResult, metadata types.MethodMetadata) error {
	if !result.Success {
		return errors.New("server: cannot record a failed MethodResult")
	}
	sess, err := s.Get(sessionID)
	if err != nil {
		return err
	}
	sess.mu.Lock()
	defer sess.mu.Unlock()

	if sess.IssuedCredentialID != "" {
		return ErrSessionAlreadyIssued
	}

	// Replace any previous entry for the same method ID rather than appending
	// duplicates; a user who re-runs a ceremony should overwrite, not stack.
	replaced := false
	for i, vm := range sess.VerifiedMethods {
		if vm.MethodID == result.MethodID {
			sess.VerifiedMethods[i] = types.VerifiedMethod{
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
		sess.VerifiedMethods = append(sess.VerifiedMethods, types.VerifiedMethod{
			MethodID:          result.MethodID,
			Strength:          metadata.Strength,
			VerifiedAt:        result.VerifiedAt,
			FreshnessLifetime: metadata.FreshnessLifetime,
			AttestationDigest: result.AttestationDigest,
		})
	}

	if metadata.Type == types.MethodTypeAnchor {
		id := result.MethodID
		sess.AnchorMethodID = &id
	}
	return nil
}

// MarkIssued stamps the session with the credential ID it produced, blocking
// future RecordMethodResult / issue calls.
func (s *SessionStore) MarkIssued(sessionID, credentialID string) error {
	sess, err := s.Get(sessionID)
	if err != nil {
		return err
	}
	sess.mu.Lock()
	defer sess.mu.Unlock()
	if sess.IssuedCredentialID != "" {
		return ErrSessionAlreadyIssued
	}
	sess.IssuedCredentialID = credentialID
	return nil
}

// Snapshot returns a deep-copy view of the session safe to share with HTTP
// handlers without leaking the internal lock.
func (s *SessionStore) Snapshot(sessionID string) (SessionView, error) {
	sess, err := s.Get(sessionID)
	if err != nil {
		return SessionView{}, err
	}
	sess.mu.Lock()
	defer sess.mu.Unlock()

	methodsCopy := make([]types.VerifiedMethod, len(sess.VerifiedMethods))
	copy(methodsCopy, sess.VerifiedMethods)

	var anchor *string
	if sess.AnchorMethodID != nil {
		v := *sess.AnchorMethodID
		anchor = &v
	}

	return SessionView{
		ID:                 sess.ID,
		HolderDID:          sess.HolderDID,
		CreatedAt:          sess.CreatedAt,
		ExpiresAt:          sess.ExpiresAt,
		VerifiedMethods:    methodsCopy,
		AnchorMethodID:     anchor,
		IssuedCredentialID: sess.IssuedCredentialID,
	}, nil
}

// SessionView is the lockless, JSON-friendly snapshot returned by Snapshot.
// Mutating its fields has no effect on the underlying Session.
type SessionView struct {
	ID                 string                 `json:"id"`
	HolderDID          types.DID              `json:"holder_did"`
	CreatedAt          time.Time              `json:"created_at"`
	ExpiresAt          time.Time              `json:"expires_at"`
	VerifiedMethods    []types.VerifiedMethod `json:"verified_methods"`
	AnchorMethodID     *string                `json:"anchor_method_id,omitempty"`
	IssuedCredentialID string                 `json:"issued_credential_id,omitempty"`
}

// randomSessionID returns a 32-byte base64url (no padding) random string.
func randomSessionID() (string, error) {
	buf := make([]byte, 32)
	if _, err := rand.Read(buf); err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(buf), nil
}
