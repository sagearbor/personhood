package server

import (
	"context"
	"encoding/json"
	"fmt"

	"github.com/sagearbor/personhood/pkg/redisclient"
)

// redisIdentifierSeedPrefix + keyed hash -> {"seed": "<hex>"}. Never expires.
const redisIdentifierSeedPrefix = "personhood:identifier-seed:"

// RedisIdentifierStore is the IdentifierStore for issuers outside Google
// Cloud (scripts/issuer-kit). Seeds are claimed with SET NX, so two
// enrollments racing on one inbox get the same seed. Like
// RedisRevocationStore it is only as durable as the Redis server: losing
// these keys lets every inbox enroll once more as a new person.
type RedisIdentifierStore struct {
	client *redisclient.Client
}

func NewRedisIdentifierStore(client *redisclient.Client) *RedisIdentifierStore {
	return &RedisIdentifierStore{client: client}
}

func (s *RedisIdentifierStore) Lookup(ctx context.Context, key string) (string, bool, error) {
	if !validIdentifierKey(key) {
		return "", false, fmt.Errorf("server: malformed identifier key")
	}
	raw, found, err := s.client.Get(ctx, redisIdentifierSeedPrefix+key)
	if err != nil || !found {
		return "", false, err
	}
	var doc identifierSeedDoc
	if err := json.Unmarshal(raw, &doc); err != nil || doc.Seed == "" {
		return "", false, fmt.Errorf("server: corrupt identifier seed record")
	}
	return doc.Seed, true, nil
}

func (s *RedisIdentifierStore) GetOrCreate(ctx context.Context, key, seed string) (string, error) {
	if !validIdentifierKey(key) {
		return "", fmt.Errorf("server: malformed identifier key")
	}
	b, err := json.Marshal(identifierSeedDoc{Seed: seed})
	if err != nil {
		return "", err
	}
	created, err := redisSetNX(ctx, s.client, redisIdentifierSeedPrefix+key, b)
	if err != nil {
		return "", err
	}
	if created {
		return seed, nil
	}
	existing, found, err := s.Lookup(ctx, key)
	if err != nil {
		return "", err
	}
	if !found {
		return "", fmt.Errorf("server: identifier seed vanished after create conflict")
	}
	return existing, nil
}
