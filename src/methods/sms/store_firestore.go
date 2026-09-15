package sms

import (
	"context"
	"crypto/subtle"
	"encoding/json"
	"fmt"
	"time"

	"github.com/sagearbor/personhood/pkg/firestoreclient"
)

// firestoreOTPCollection is the Firestore collection OTP entries are stored
// under.
const firestoreOTPCollection = "personhood-sms-otps"

// FirestoreOTPStore is a Firestore-backed OTPStore, selected via
// FIRESTORE_PROJECT_ID (see NewOTPStoreFromEnv). Same shape and
// read-modify-write concurrency tradeoff as RedisOTPStore (store_redis.go)
// — see that type's doc comment for the full reasoning, which applies
// unchanged here: Firestore's REST API used by pkg/firestoreclient has no
// compare-and-swap primitive either, so Verify is GET-mutate-PATCH just
// like the Redis backend.
type FirestoreOTPStore struct {
	client *firestoreclient.Client
}

// NewFirestoreOTPStore constructs a FirestoreOTPStore.
func NewFirestoreOTPStore(client *firestoreclient.Client) *FirestoreOTPStore {
	return &FirestoreOTPStore{client: client}
}

func (s *FirestoreOTPStore) write(ctx context.Context, key string, e redisOTPEntry) error {
	b, err := json.Marshal(e)
	if err != nil {
		return fmt.Errorf("sms: marshal otp entry: %w", err)
	}
	if err := s.client.Set(ctx, firestoreOTPCollection, key, b, time.Until(e.ExpiresAt)); err != nil {
		return fmt.Errorf("sms: firestore otp write: %w", err)
	}
	return nil
}

// Put implements OTPStore.
func (s *FirestoreOTPStore) Put(ctx context.Context, key, otp string, expiresAt time.Time) error {
	return s.write(ctx, key, redisOTPEntry{OTP: otp, ExpiresAt: expiresAt})
}

// Verify implements OTPStore. See the FirestoreOTPStore doc comment for the
// read-modify-write concurrency tradeoff.
func (s *FirestoreOTPStore) Verify(ctx context.Context, key, attempt string) (bool, int, error) {
	raw, found, err := s.client.Get(ctx, firestoreOTPCollection, key)
	if err != nil {
		return false, 0, fmt.Errorf("sms: firestore otp read: %w", err)
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
		_ = s.client.Del(ctx, firestoreOTPCollection, key)
		return false, 0, nil
	}

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
func (s *FirestoreOTPStore) Invalidate(ctx context.Context, key string) error {
	if err := s.client.Del(ctx, firestoreOTPCollection, key); err != nil {
		return fmt.Errorf("sms: firestore otp delete: %w", err)
	}
	return nil
}
