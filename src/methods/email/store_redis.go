package email

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"time"

	"github.com/sagearbor/personhood/pkg/redisclient"
)

// redisTokenKeyPrefix namespaces magic-link token keys on a (possibly
// shared) Redis instance.
const redisTokenKeyPrefix = "personhood:email-token:"

// redisTokenEntry is the JSON-serializable form of one outstanding
// magic-link token.
type redisTokenEntry struct {
	Token     string    `json:"token"`
	Email     string    `json:"email"`
	ExpiresAt time.Time `json:"expires_at"`
}

// RedisTokenStore is a Redis-backed TokenStore, selected via REDIS_URL (see
// NewTokenStoreFromEnv) so magic-link ceremonies can be completed across
// issuer process boundaries — unlike InMemoryStore, which is scoped to one
// process.
type RedisTokenStore struct {
	client *redisclient.Client
}

// NewRedisTokenStore constructs a RedisTokenStore.
func NewRedisTokenStore(client *redisclient.Client) *RedisTokenStore {
	return &RedisTokenStore{client: client}
}

// NewTokenStoreFromEnv returns a RedisTokenStore when REDIS_URL is set, or
// an InMemoryStore (the default) otherwise — mirrors NewSenderFromEnv's
// env-aware selection pattern.
func NewTokenStoreFromEnv() (TokenStore, error) {
	redisURL := os.Getenv("REDIS_URL")
	if redisURL == "" {
		return NewInMemoryStore(), nil
	}
	client, err := redisclient.ParseURL(redisURL)
	if err != nil {
		return nil, fmt.Errorf("email: REDIS_URL: %w", err)
	}
	return NewRedisTokenStore(client), nil
}

func redisTokenKey(sessionID string) string { return redisTokenKeyPrefix + sessionID }

// Put implements TokenStore.
func (s *RedisTokenStore) Put(ctx context.Context, sessionID, token, email string, expiresAt time.Time) error {
	b, err := json.Marshal(redisTokenEntry{Token: token, Email: email, ExpiresAt: expiresAt})
	if err != nil {
		return fmt.Errorf("email: marshal token entry: %w", err)
	}
	if err := s.client.Set(ctx, redisTokenKey(sessionID), b, time.Until(expiresAt)); err != nil {
		return fmt.Errorf("email: redis token write: %w", err)
	}
	return nil
}

// Lookup implements TokenStore.
func (s *RedisTokenStore) Lookup(ctx context.Context, sessionID, token string) (string, bool, error) {
	raw, found, err := s.client.Get(ctx, redisTokenKey(sessionID))
	if err != nil {
		return "", false, fmt.Errorf("email: redis token read: %w", err)
	}
	if !found {
		return "", false, nil
	}
	var e redisTokenEntry
	if err := json.Unmarshal(raw, &e); err != nil {
		return "", false, fmt.Errorf("email: unmarshal token entry: %w", err)
	}
	if time.Now().After(e.ExpiresAt) {
		_ = s.client.Del(ctx, redisTokenKey(sessionID))
		return "", false, nil
	}
	if e.Token != token {
		return "", false, nil
	}
	return e.Email, true, nil
}

// Delete implements TokenStore.
func (s *RedisTokenStore) Delete(ctx context.Context, sessionID string) error {
	if err := s.client.Del(ctx, redisTokenKey(sessionID)); err != nil {
		return fmt.Errorf("email: redis token delete: %w", err)
	}
	return nil
}
