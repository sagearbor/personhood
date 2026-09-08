package sms

import (
	"context"
	"os"
	"testing"
	"time"

	"github.com/sagearbor/personhood/pkg/redisclient"
)

// redisTestClient returns a Client pointed at a real local Redis for tests
// in this file, or skips if none is configured. Run locally with:
//
//	redis-server --port 6399 --daemonize no &
//	REDIS_TEST_ADDR=127.0.0.1:6399 go test -race ./...
func redisTestClient(t *testing.T) *redisclient.Client {
	t.Helper()
	addr := os.Getenv("REDIS_TEST_ADDR")
	if addr == "" {
		addr = os.Getenv("REDIS_URL")
	}
	if addr == "" {
		t.Skip("REDIS_TEST_ADDR (or REDIS_URL) not set; skipping real-Redis integration test")
	}
	c, err := redisclient.ParseURL(addr)
	if err != nil {
		c = redisclient.New(addr)
	}
	return c
}

func TestIntegration_RedisOTPStore_PutVerifySuccess(t *testing.T) {
	client := redisTestClient(t)
	store := NewRedisOTPStore(client)
	ctx := context.Background()

	key := "sess-redis:+15551234567"
	t.Cleanup(func() { _ = store.Invalidate(ctx, key) })

	if err := store.Put(ctx, key, "123456", time.Now().Add(time.Hour)); err != nil {
		t.Fatalf("Put: %v", err)
	}

	valid, remaining, err := store.Verify(ctx, key, "123456")
	if err != nil {
		t.Fatalf("Verify: %v", err)
	}
	if !valid || remaining != 0 {
		t.Fatalf("Verify correct OTP: valid=%v remaining=%d", valid, remaining)
	}

	// The entry is single-use: a second Verify (even with the right code)
	// must fail once invalidated by success.
	valid, remaining, err = store.Verify(ctx, key, "123456")
	if err != nil {
		t.Fatalf("Verify after success: %v", err)
	}
	if valid {
		t.Error("Verify after a successful match should not succeed again")
	}
	if remaining != 0 {
		t.Errorf("remaining after invalidation = %d, want 0", remaining)
	}
}

func TestIntegration_RedisOTPStore_LockoutAfterMaxAttempts(t *testing.T) {
	client := redisTestClient(t)
	store := NewRedisOTPStore(client)
	ctx := context.Background()

	key := "sess-redis:+15559999999"
	t.Cleanup(func() { _ = store.Invalidate(ctx, key) })

	if err := store.Put(ctx, key, "654321", time.Now().Add(time.Hour)); err != nil {
		t.Fatalf("Put: %v", err)
	}

	// MaxAttempts (3) wrong guesses lock the entry out.
	for i := 1; i <= MaxAttempts; i++ {
		valid, remaining, err := store.Verify(ctx, key, "000000")
		if err != nil {
			t.Fatalf("Verify wrong attempt %d: %v", i, err)
		}
		if valid {
			t.Fatalf("Verify wrong attempt %d unexpectedly succeeded", i)
		}
		wantRemaining := MaxAttempts - i
		if remaining != wantRemaining {
			t.Errorf("attempt %d: remaining = %d, want %d", i, remaining, wantRemaining)
		}
	}

	// Even the correct code is now rejected — locked out.
	valid, remaining, err := store.Verify(ctx, key, "654321")
	if err != nil {
		t.Fatalf("Verify correct code after lockout: %v", err)
	}
	if valid {
		t.Error("expected lockout to reject even the correct code")
	}
	if remaining != 0 {
		t.Errorf("remaining after lockout = %d, want 0", remaining)
	}
}

func TestIntegration_RedisOTPStore_Expiry(t *testing.T) {
	client := redisTestClient(t)
	store := NewRedisOTPStore(client)
	ctx := context.Background()

	key := "sess-redis:+15550000000"
	t.Cleanup(func() { _ = store.Invalidate(ctx, key) })

	if err := store.Put(ctx, key, "111111", time.Now().Add(150*time.Millisecond)); err != nil {
		t.Fatalf("Put: %v", err)
	}

	time.Sleep(400 * time.Millisecond) // safely past the 150ms TTL

	// Verifying with the CORRECT code after expiry must still fail — if it
	// were still present, the correct code would succeed, so this
	// distinguishes "expired" from an ordinary wrong-code rejection.
	valid, remaining, err := store.Verify(ctx, key, "111111")
	if err != nil {
		t.Fatalf("Verify after expiry: %v", err)
	}
	if valid {
		t.Error("expected the OTP to have expired")
	}
	if remaining != 0 {
		t.Errorf("remaining after expiry = %d, want 0", remaining)
	}
}

func TestIntegration_RedisOTPStore_InvalidateRemovesEntry(t *testing.T) {
	client := redisTestClient(t)
	store := NewRedisOTPStore(client)
	ctx := context.Background()

	key := "sess-redis:+15558675309"
	if err := store.Put(ctx, key, "222222", time.Now().Add(time.Hour)); err != nil {
		t.Fatalf("Put: %v", err)
	}
	if err := store.Invalidate(ctx, key); err != nil {
		t.Fatalf("Invalidate: %v", err)
	}
	valid, remaining, err := store.Verify(ctx, key, "222222")
	if err != nil {
		t.Fatalf("Verify after Invalidate: %v", err)
	}
	if valid || remaining != 0 {
		t.Fatalf("Verify after Invalidate: valid=%v remaining=%d, want false/0", valid, remaining)
	}
}

func TestNewOTPStoreFromEnv(t *testing.T) {
	t.Run("defaults to in-memory when REDIS_URL is unset", func(t *testing.T) {
		t.Setenv("REDIS_URL", "")
		store, err := NewOTPStoreFromEnv()
		if err != nil {
			t.Fatalf("NewOTPStoreFromEnv: %v", err)
		}
		if _, ok := store.(*InMemoryStore); !ok {
			t.Errorf("expected *InMemoryStore, got %T", store)
		}
	})

	t.Run("selects Redis when REDIS_URL is set", func(t *testing.T) {
		redisTestClient(t) // skips this subtest if no test Redis is configured
		redisURL := os.Getenv("REDIS_TEST_ADDR")
		if redisURL == "" {
			redisURL = os.Getenv("REDIS_URL")
		}
		t.Setenv("REDIS_URL", redisURL)
		store, err := NewOTPStoreFromEnv()
		if err != nil {
			t.Fatalf("NewOTPStoreFromEnv: %v", err)
		}
		if _, ok := store.(*RedisOTPStore); !ok {
			t.Errorf("expected *RedisOTPStore, got %T", store)
		}
	})

	t.Run("rejects a malformed REDIS_URL", func(t *testing.T) {
		t.Setenv("REDIS_URL", "redis://")
		if _, err := NewOTPStoreFromEnv(); err == nil {
			t.Error("expected an error for a malformed REDIS_URL")
		}
	})
}
