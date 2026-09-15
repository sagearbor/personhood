package governmentidliveness

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"

	"github.com/sagearbor/personhood/pkg/firestoreclient"
)

// Firestore collections namespacing the two independent lookups ResultStore
// exposes (by session, and by Persona inquiry id) — mirrors
// RedisResultStore's two key prefixes (store_redis.go).
const (
	firestoreBySessionCollection = "personhood-govid-by-session"
	firestoreByInquiryCollection = "personhood-govid-by-inquiry"
)

// FirestoreResultStore is a Firestore-backed ResultStore, selected via
// FIRESTORE_PROJECT_ID (see NewResultStoreFromEnv). Same shape as
// RedisResultStore: neither collection uses a TTL, mirroring InMemoryStore
// and RedisResultStore, which both keep results for the life of the
// enrollment flow rather than tying them to the session's own expiry.
type FirestoreResultStore struct {
	client *firestoreclient.Client
}

// NewFirestoreResultStore constructs a FirestoreResultStore.
func NewFirestoreResultStore(client *firestoreclient.Client) *FirestoreResultStore {
	return &FirestoreResultStore{client: client}
}

// PutInquiry implements ResultStore.
func (s *FirestoreResultStore) PutInquiry(ctx context.Context, sessionID, inquiryID string) error {
	if sessionID == "" || inquiryID == "" {
		return errors.New("government-id-liveness: PutInquiry requires non-empty sessionID and inquiryID")
	}
	if err := s.client.Set(ctx, firestoreByInquiryCollection, inquiryID, []byte(sessionID), 0); err != nil {
		return fmt.Errorf("government-id-liveness: firestore PutInquiry: %w", err)
	}
	return nil
}

// LookupSessionByInquiry implements ResultStore.
func (s *FirestoreResultStore) LookupSessionByInquiry(ctx context.Context, inquiryID string) (string, error) {
	raw, found, err := s.client.Get(ctx, firestoreByInquiryCollection, inquiryID)
	if err != nil {
		return "", fmt.Errorf("government-id-liveness: firestore LookupSessionByInquiry: %w", err)
	}
	if !found {
		return "", nil
	}
	return string(raw), nil
}

// PutResult implements ResultStore.
func (s *FirestoreResultStore) PutResult(ctx context.Context, sessionID string, result Result) error {
	if sessionID == "" {
		return errors.New("government-id-liveness: PutResult requires non-empty sessionID")
	}
	b, err := json.Marshal(result)
	if err != nil {
		return fmt.Errorf("government-id-liveness: marshal result: %w", err)
	}
	if err := s.client.Set(ctx, firestoreBySessionCollection, sessionID, b, 0); err != nil {
		return fmt.Errorf("government-id-liveness: firestore PutResult: %w", err)
	}
	return nil
}

// GetResult implements ResultStore.
func (s *FirestoreResultStore) GetResult(ctx context.Context, sessionID string) (Result, error) {
	raw, found, err := s.client.Get(ctx, firestoreBySessionCollection, sessionID)
	if err != nil {
		return Result{}, fmt.Errorf("government-id-liveness: firestore GetResult: %w", err)
	}
	if !found {
		return Result{}, ErrNoResultYet
	}
	var r Result
	if err := json.Unmarshal(raw, &r); err != nil {
		return Result{}, fmt.Errorf("government-id-liveness: unmarshal result: %w", err)
	}
	return r, nil
}
