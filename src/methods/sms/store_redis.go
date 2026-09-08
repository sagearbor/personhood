package sms

import (
	"context"
	"crypto/subtle"
	"encoding/json"
	"fmt"
	"os"
	"time"

	"github.com/sagearbor/personhood/pkg/redisclient"
)

// redisOTPKeyPrefix namespaces OTP keys on a (possibly shared) Redis
// instance.
const redisOTPKeyPrefix = "personhood:sms-otp:"

// redisOTPEntry is the JSON-serializable form of one outstanding OTP,
// mirroring InMemoryStore's otpEntry.
type redisOTPEntry struct {
	OTP       string    `json:"otp"`
	ExpiresAt time.Time `json:"expires_at"`
	Attempts  int       `json:"attempts"`
	Invalid   bool      `json:"invalid"`
}

// RedisOTPStore is a Redis-backed OTPStore, selected via REDIS_URL (see
// NewOTPStoreFromEnv) so the attempt counter is shared across all issuer
// process replicas — unlike InMemoryStore, an attacker cannot defeat the
// lockout by round-robining requests across horizontally scaled processes.
//
// Concurrency note: Verify is read-modify-write (GET, mutate, SET), not an
// atomic Redis transaction — see pkg/redisclient's package doc on why this
// client implements only a minimal RESP2 command set (no WATCH/MULTI or Lua
// scripting). Two Verify calls racing on the exact same key at the exact
// same instant could each read the same pre-increment attempt count and
// both proceed, under-counting by one attempt in the rare worst case. This
// is a v1 tradeoff: it weakens (does not eliminate) the lockout under a
// literal simultaneous-request race, while still delivering the primary
// goal versus InMemoryStore — the counter is shared across replicas at all,
// closing the far easier "just round-robin across servers" bypass the
// in-memory store's doc comment warns about.
type RedisOTPStore struct {
	client *redisclient.Client
}

// NewRedisOTPStore constructs a RedisOTPStore.
func NewRedisOTPStore(client *redisclient.Client) *RedisOTPStore {
	return &RedisOTPStore{client: client}
}

// NewOTPStoreFromEnv returns a RedisOTPStore when REDIS_URL is set, or an
// InMemoryStore (the default) otherwise — mirrors NewSenderFromEnv's
// env-aware selection pattern.
func NewOTPStoreFromEnv() (OTPStore, error) {
	redisURL := os.Getenv("REDIS_URL")
	if redisURL == "" {
		return NewInMemoryStore(), nil
	}
	client, err := redisclient.ParseURL(redisURL)
	if err != nil {
		return nil, fmt.Errorf("sms: REDIS_URL: %w", err)
	}
	return NewRedisOTPStore(client), nil
}

func redisOTPKey(key string) string { return redisOTPKeyPrefix + key }

func (s *RedisOTPStore) write(ctx context.Context, key string, e redisOTPEntry) error {
	b, err := json.Marshal(e)
	if err != nil {
		return fmt.Errorf("sms: marshal otp entry: %w", err)
	}
	if err := s.client.Set(ctx, redisOTPKey(key), b, time.Until(e.ExpiresAt)); err != nil {
		return fmt.Errorf("sms: redis otp write: %w", err)
	}
	return nil
}

// Put implements OTPStore.
func (s *RedisOTPStore) Put(ctx context.Context, key, otp string, expiresAt time.Time) error {
	return s.write(ctx, key, redisOTPEntry{OTP: otp, ExpiresAt: expiresAt})
}

// Verify implements OTPStore. See the RedisOTPStore doc comment for the
// read-modify-write concurrency tradeoff versus InMemoryStore's mutex.
func (s *RedisOTPStore) Verify(ctx context.Context, key, attempt string) (bool, int, error) {
	raw, found, err := s.client.Get(ctx, redisOTPKey(key))
	if err != nil {
		return false, 0, fmt.Errorf("sms: redis otp read: %w", err)
	}
	if !found {
		return false, 0, nil
	}
	var e redisOTPEntry
	if err := json.Unmarshal(raw, &e); err != nil {
		return false, 0, fmt.Errorf("sms: unmarshal otp entry: %w", err)
	}
	if e.Invalid {
		return false, 0, nil
	}
	if time.Now().After(e.ExpiresAt) {
		_ = s.client.Del(ctx, redisOTPKey(key))
		return false, 0, nil
	}

	// Always perform the constant-time compare even if attempts are about to
	// be exceeded, matching InMemoryStore's timing-oracle mitigation.
	match := subtle.ConstantTimeCompare([]byte(e.OTP), []byte(attempt)) == 1

	if match {
		e.Invalid = true
		if err := s.write(ctx, key, e); err != nil {
			return false, 0, err
		}
		return true, 0, nil
	}

	e.Attempts++
	remaining := MaxAttempts - e.Attempts
	if remaining <= 0 {
		e.Invalid = true
		if err := s.write(ctx, key, e); err != nil {
			return false, 0, err
		}
		return false, 0, nil
	}
	if err := s.write(ctx, key, e); err != nil {
		return false, 0, err
	}
	return false, remaining, nil
}

// Invalidate implements OTPStore.
func (s *RedisOTPStore) Invalidate(ctx context.Context, key string) error {
	if err := s.client.Del(ctx, redisOTPKey(key)); err != nil {
		return fmt.Errorf("sms: redis otp delete: %w", err)
	}
	return nil
}
