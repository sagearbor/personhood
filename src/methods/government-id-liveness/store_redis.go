package governmentidliveness

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"

	"github.com/sagearbor/personhood/pkg/redisclient"
)

// Redis key prefixes namespacing the two independent lookups ResultStore
// exposes (by session, and by Persona inquiry id).
const (
	redisBySessionKeyPrefix = "personhood:govid:by-session:"
	redisByInquiryKeyPrefix = "personhood:govid:by-inquiry:"
)

// RedisResultStore is a Redis-backed ResultStore, selected via REDIS_URL
// (see NewResultStoreFromEnv) so the webhook handler and the API handler
// can be scaled horizontally — unlike InMemoryStore, which is scoped to one
// process (a webhook landing on a different replica than the one polling
// CompleteCeremony would otherwise never see the result).
//
// Neither key carries a Redis TTL: results and inquiry bindings are kept
// for the life of the enrollment flow (mirroring InMemoryStore, which never
// evicts either), not tied to the session's own expiry.
type RedisResultStore struct {
	client *redisclient.Client
}

// NewRedisResultStore constructs a RedisResultStore.
func NewRedisResultStore(client *redisclient.Client) *RedisResultStore {
	return &RedisResultStore{client: client}
}

// NewResultStoreFromEnv returns a RedisResultStore when REDIS_URL is set, or
// an InMemoryStore (the default) otherwise.
func NewResultStoreFromEnv() (ResultStore, error) {
	redisURL := os.Getenv("REDIS_URL")
	if redisURL == "" {
		return NewInMemoryStore(), nil
	}
	client, err := redisclient.ParseURL(redisURL)
	if err != nil {
		return nil, fmt.Errorf("government-id-liveness: REDIS_URL: %w", err)
	}
	return NewRedisResultStore(client), nil
}

// PutInquiry implements ResultStore.
func (s *RedisResultStore) PutInquiry(ctx context.Context, sessionID, inquiryID string) error {
	if sessionID == "" || inquiryID == "" {
		return errors.New("government-id-liveness: PutInquiry requires non-empty sessionID and inquiryID")
	}
	if err := s.client.Set(ctx, redisByInquiryKeyPrefix+inquiryID, []byte(sessionID), 0); err != nil {
		return fmt.Errorf("government-id-liveness: redis PutInquiry: %w", err)
	}
	return nil
}

// LookupSessionByInquiry implements ResultStore.
func (s *RedisResultStore) LookupSessionByInquiry(ctx context.Context, inquiryID string) (string, error) {
	raw, found, err := s.client.Get(ctx, redisByInquiryKeyPrefix+inquiryID)
	if err != nil {
		return "", fmt.Errorf("government-id-liveness: redis LookupSessionByInquiry: %w", err)
	}
	if !found {
		return "", nil
	}
	return string(raw), nil
}

// PutResult implements ResultStore.
func (s *RedisResultStore) PutResult(ctx context.Context, sessionID string, result Result) error {
	if sessionID == "" {
		return errors.New("government-id-liveness: PutResult requires non-empty sessionID")
	}
	b, err := json.Marshal(result)
	if err != nil {
		return fmt.Errorf("government-id-liveness: marshal result: %w", err)
	}
	if err := s.client.Set(ctx, redisBySessionKeyPrefix+sessionID, b, 0); err != nil {
		return fmt.Errorf("government-id-liveness: redis PutResult: %w", err)
	}
	return nil
}

// GetResult implements ResultStore.
func (s *RedisResultStore) GetResult(ctx context.Context, sessionID string) (Result, error) {
	raw, found, err := s.client.Get(ctx, redisBySessionKeyPrefix+sessionID)
	if err != nil {
		return Result{}, fmt.Errorf("government-id-liveness: redis GetResult: %w", err)
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
