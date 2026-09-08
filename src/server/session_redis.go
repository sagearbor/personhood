package server

import (
	"context"
	"crypto/ed25519"
	"encoding/json"
	"errors"
	"fmt"
	"time"

	"github.com/sagearbor/personhood/pkg/redisclient"
	"github.com/sagearbor/personhood/pkg/types"
)

// redisSessionKeyPrefix namespaces session keys on a (possibly shared)
// Redis instance.
const redisSessionKeyPrefix = "personhood:session:"

// sessionRecord is the JSON-serializable form of a session's state — the
// same fields as the in-memory session type, minus its mutex (a mutex has no
// meaning once the state lives in Redis; RedisSessionStore serializes
// mutations with a read-modify-write over Get/Set instead — see the
// concurrency note on RedisSessionStore).
type sessionRecord struct {
	ID                 string                 `json:"id"`
	HolderDID          types.DID              `json:"holder_did"`
	HolderPublicKey    ed25519.PublicKey      `json:"holder_public_key,omitempty"`
	CreatedAt          time.Time              `json:"created_at"`
	ExpiresAt          time.Time              `json:"expires_at"`
	VerifiedMethods    []types.VerifiedMethod `json:"verified_methods"`
	AnchorMethodID     *string                `json:"anchor_method_id,omitempty"`
	IssuedCredentialID string                 `json:"issued_credential_id,omitempty"`
}

func (r sessionRecord) view() SessionView {
	methodsCopy := make([]types.VerifiedMethod, len(r.VerifiedMethods))
	copy(methodsCopy, r.VerifiedMethods)

	var anchor *string
	if r.AnchorMethodID != nil {
		v := *r.AnchorMethodID
		anchor = &v
	}

	var holderPub ed25519.PublicKey
	if len(r.HolderPublicKey) == ed25519.PublicKeySize {
		holderPub = append(ed25519.PublicKey(nil), r.HolderPublicKey...)
	}

	return SessionView{
		ID:                 r.ID,
		HolderDID:          r.HolderDID,
		HolderPublicKey:    holderPub,
		CreatedAt:          r.CreatedAt,
		ExpiresAt:          r.ExpiresAt,
		VerifiedMethods:    methodsCopy,
		AnchorMethodID:     anchor,
		IssuedCredentialID: r.IssuedCredentialID,
	}
}

// RedisSessionStore is a Redis-backed SessionStore, selected via REDIS_URL
// (see NewSessionStoreFromEnv) so enrollment sessions survive process
// restarts and are shared across horizontally scaled issuer replicas —
// unlike InMemorySessionStore, which is scoped to one process.
//
// Concurrency note: RecordMethodResult and MarkIssued are read-modify-write
// (GET, mutate, SET) rather than atomic Redis transactions (no WATCH/MULTI
// or Lua scripting is implemented — see the package doc on
// pkg/redisclient's minimal command surface). Two calls racing on the exact
// same session ID at the exact same instant can lose one update, same as
// InMemorySessionStore's per-session mutex only protects one process, not
// concurrent replicas hitting Redis independently before this change. In
// practice one holder drives one session serially through its ceremonies,
// so this is an acceptable v1 tradeoff, not a security hole — the worst
// case is a dropped verified-method record that the client can simply
// retry, not incorrect issuance.
type RedisSessionStore struct {
	client *redisclient.Client
	ttl    time.Duration
}

// NewRedisSessionStore constructs a RedisSessionStore. ttl is the session
// lifetime applied at Create time (mirrors InMemorySessionStore's ttl
// parameter); Redis's own key TTL is kept in sync with each record's
// ExpiresAt so stale sessions are reclaimed automatically.
func NewRedisSessionStore(client *redisclient.Client, ttl time.Duration) *RedisSessionStore {
	if ttl <= 0 {
		ttl = time.Hour
	}
	return &RedisSessionStore{client: client, ttl: ttl}
}

func sessionRedisKey(id string) string { return redisSessionKeyPrefix + id }

func (s *RedisSessionStore) write(ctx context.Context, rec sessionRecord) error {
	b, err := json.Marshal(rec)
	if err != nil {
		return fmt.Errorf("server: marshal session: %w", err)
	}
	// If ExpiresAt has already passed (shouldn't normally happen — we only
	// ever write records we just read-and-validated, or just created), fall
	// back to no TTL; read() below still enforces expiry explicitly so a
	// stale record is never served even if Redis has not yet evicted it.
	ttl := time.Until(rec.ExpiresAt)
	if err := s.client.Set(ctx, sessionRedisKey(rec.ID), b, ttl); err != nil {
		return fmt.Errorf("server: redis session write: %w", err)
	}
	return nil
}

func (s *RedisSessionStore) read(ctx context.Context, id string) (sessionRecord, error) {
	raw, found, err := s.client.Get(ctx, sessionRedisKey(id))
	if err != nil {
		return sessionRecord{}, fmt.Errorf("server: redis session read: %w", err)
	}
	if !found {
		return sessionRecord{}, ErrSessionNotFound
	}
	var rec sessionRecord
	if err := json.Unmarshal(raw, &rec); err != nil {
		return sessionRecord{}, fmt.Errorf("server: unmarshal session: %w", err)
	}
	if time.Now().After(rec.ExpiresAt) {
		_ = s.client.Del(ctx, sessionRedisKey(id))
		return sessionRecord{}, ErrSessionNotFound
	}
	return rec, nil
}

// Create implements SessionStore.
func (s *RedisSessionStore) Create(holderPublicKey ed25519.PublicKey, now time.Time) (SessionView, error) {
	id, err := randomSessionID()
	if err != nil {
		return SessionView{}, err
	}
	holderDID := HolderDIDForSession(id, holderPublicKey)
	var pubCopy ed25519.PublicKey
	if len(holderPublicKey) == ed25519.PublicKeySize {
		pubCopy = append(ed25519.PublicKey(nil), holderPublicKey...)
	}
	rec := sessionRecord{
		ID:              id,
		HolderDID:       holderDID,
		HolderPublicKey: pubCopy,
		CreatedAt:       now,
		ExpiresAt:       now.Add(s.ttl),
	}
	if err := s.write(context.Background(), rec); err != nil {
		return SessionView{}, err
	}
	return rec.view(), nil
}

// Get implements SessionStore.
func (s *RedisSessionStore) Get(id string) (SessionView, error) {
	rec, err := s.read(context.Background(), id)
	if err != nil {
		return SessionView{}, err
	}
	return rec.view(), nil
}

// RecordMethodResult implements SessionStore.
func (s *RedisSessionStore) RecordMethodResult(sessionID string, result types.MethodResult, metadata types.MethodMetadata) error {
	if !result.Success {
		return errors.New("server: cannot record a failed MethodResult")
	}
	ctx := context.Background()
	rec, err := s.read(ctx, sessionID)
	if err != nil {
		return err
	}
	if rec.IssuedCredentialID != "" {
		return ErrSessionAlreadyIssued
	}

	replaced := false
	for i, vm := range rec.VerifiedMethods {
		if vm.MethodID == result.MethodID {
			rec.VerifiedMethods[i] = types.VerifiedMethod{
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
		rec.VerifiedMethods = append(rec.VerifiedMethods, types.VerifiedMethod{
			MethodID:          result.MethodID,
			Strength:          metadata.Strength,
			VerifiedAt:        result.VerifiedAt,
			FreshnessLifetime: metadata.FreshnessLifetime,
			AttestationDigest: result.AttestationDigest,
		})
	}

	if metadata.Type == types.MethodTypeAnchor {
		id := result.MethodID
		rec.AnchorMethodID = &id
	}
	return s.write(ctx, rec)
}

// MarkIssued implements SessionStore.
func (s *RedisSessionStore) MarkIssued(sessionID, credentialID string) error {
	ctx := context.Background()
	rec, err := s.read(ctx, sessionID)
	if err != nil {
		return err
	}
	if rec.IssuedCredentialID != "" {
		return ErrSessionAlreadyIssued
	}
	rec.IssuedCredentialID = credentialID
	return s.write(ctx, rec)
}
