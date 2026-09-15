package server

import (
	"context"
	"crypto/ed25519"
	"encoding/json"
	"errors"
	"fmt"
	"time"

	"github.com/sagearbor/personhood/pkg/firestoreclient"
	"github.com/sagearbor/personhood/pkg/types"
)

// firestoreSessionCollection is the Firestore collection sessions are
// stored under.
const firestoreSessionCollection = "personhood-sessions"

// FirestoreSessionStore is a Firestore-backed SessionStore, selected via
// FIRESTORE_PROJECT_ID (see NewSessionStoreFromEnv) so enrollment sessions
// survive process restarts and are shared across horizontally scaled issuer
// replicas — same motivation as RedisSessionStore (session_redis.go), for a
// deployment that would rather lean on a managed, serverless datastore
// already available in the same GCP project than run Redis.
//
// Storage shape and concurrency tradeoffs mirror RedisSessionStore exactly:
// each session is one JSON blob (sessionRecord, shared with the Redis
// backend) under one document, and mutations are read-modify-write rather
// than an atomic transaction — see RedisSessionStore's doc comment for the
// full reasoning, which applies unchanged here.
type FirestoreSessionStore struct {
	client *firestoreclient.Client
	ttl    time.Duration
}

// NewFirestoreSessionStore constructs a FirestoreSessionStore. ttl mirrors
// NewRedisSessionStore's ttl parameter.
func NewFirestoreSessionStore(client *firestoreclient.Client, ttl time.Duration) *FirestoreSessionStore {
	if ttl <= 0 {
		ttl = time.Hour
	}
	return &FirestoreSessionStore{client: client, ttl: ttl}
}

func (s *FirestoreSessionStore) write(ctx context.Context, rec sessionRecord) error {
	b, err := json.Marshal(rec)
	if err != nil {
		return fmt.Errorf("server: marshal session: %w", err)
	}
	ttl := time.Until(rec.ExpiresAt)
	if err := s.client.Set(ctx, firestoreSessionCollection, rec.ID, b, ttl); err != nil {
		return fmt.Errorf("server: firestore session write: %w", err)
	}
	return nil
}

func (s *FirestoreSessionStore) read(ctx context.Context, id string) (sessionRecord, error) {
	raw, found, err := s.client.Get(ctx, firestoreSessionCollection, id)
	if err != nil {
		return sessionRecord{}, fmt.Errorf("server: firestore session read: %w", err)
	}
	if !found {
		return sessionRecord{}, ErrSessionNotFound
	}
	var rec sessionRecord
	if err := json.Unmarshal(raw, &rec); err != nil {
		return sessionRecord{}, fmt.Errorf("server: unmarshal session: %w", err)
	}
	if time.Now().After(rec.ExpiresAt) {
		_ = s.client.Del(ctx, firestoreSessionCollection, id)
		return sessionRecord{}, ErrSessionNotFound
	}
	return rec, nil
}

// Create implements SessionStore.
func (s *FirestoreSessionStore) Create(holderPublicKey ed25519.PublicKey, now time.Time) (SessionView, error) {
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
func (s *FirestoreSessionStore) Get(id string) (SessionView, error) {
	rec, err := s.read(context.Background(), id)
	if err != nil {
		return SessionView{}, err
	}
	return rec.view(), nil
}

// RecordMethodResult implements SessionStore.
func (s *FirestoreSessionStore) RecordMethodResult(sessionID string, result types.MethodResult, metadata types.MethodMetadata) error {
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
func (s *FirestoreSessionStore) MarkIssued(sessionID, credentialID string) error {
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
