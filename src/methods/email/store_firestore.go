package email

import (
	"context"
	"encoding/json"
	"fmt"
	"time"

	"github.com/sagearbor/personhood/pkg/firestoreclient"
)

// firestoreTokenCollection is the Firestore collection magic-link tokens
// are stored under.
const firestoreTokenCollection = "personhood-email-tokens"

// FirestoreTokenStore is a Firestore-backed TokenStore, selected via
// FIRESTORE_PROJECT_ID (see NewTokenStoreFromEnv). Same shape as
// RedisTokenStore (store_redis.go): one document per session ID holding the
// same JSON-serializable entry.
type FirestoreTokenStore struct {
	client *firestoreclient.Client
}

// NewFirestoreTokenStore constructs a FirestoreTokenStore.
func NewFirestoreTokenStore(client *firestoreclient.Client) *FirestoreTokenStore {
	return &FirestoreTokenStore{client: client}
}

// Put implements TokenStore.
func (s *FirestoreTokenStore) Put(ctx context.Context, sessionID, token, email string, expiresAt time.Time) error {
	b, err := json.Marshal(redisTokenEntry{Token: token, Email: email, ExpiresAt: expiresAt})
	if err != nil {
		return fmt.Errorf("email: marshal token entry: %w", err)
	}
	if err := s.client.Set(ctx, firestoreTokenCollection, sessionID, b, time.Until(expiresAt)); err != nil {
		return fmt.Errorf("email: firestore token write: %w", err)
	}
	return nil
}

// Lookup implements TokenStore.
func (s *FirestoreTokenStore) Lookup(ctx context.Context, sessionID, token string) (string, bool, error) {
	raw, found, err := s.client.Get(ctx, firestoreTokenCollection, sessionID)
	if err != nil {
		return "", false, fmt.Errorf("email: firestore token read: %w", err)
	}
	if !found {
		return "", false, nil
	}
	var e redisTokenEntry
	if err := json.Unmarshal(raw, &e); err != nil {
		return "", false, fmt.Errorf("email: unmarshal token entry: %w", err)
	}
	if time.Now().After(e.ExpiresAt) {
		_ = s.client.Del(ctx, firestoreTokenCollection, sessionID)
		return "", false, nil
	}
	if e.Token != token {
		return "", false, nil
	}
	return e.Email, true, nil
}

// Delete implements TokenStore.
func (s *FirestoreTokenStore) Delete(ctx context.Context, sessionID string) error {
	if err := s.client.Del(ctx, firestoreTokenCollection, sessionID); err != nil {
		return fmt.Errorf("email: firestore token delete: %w", err)
	}
	return nil
}
