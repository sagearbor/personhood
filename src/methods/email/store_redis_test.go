package email

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

func TestIntegration_RedisTokenStore_PutLookupDelete(t *testing.T) {
	client := redisTestClient(t)
	store := NewRedisTokenStore(client)
	ctx := context.Background()

	sessionID := "sess-redis-test-1"
	t.Cleanup(func() { _ = store.Delete(ctx, sessionID) })

	if _, found, err := store.Lookup(ctx, sessionID, "whatever"); err != nil {
		t.Fatalf("Lookup before Put: %v", err)
	} else if found {
		t.Fatal("Lookup before Put: unexpectedly found")
	}

	expiresAt := time.Now().Add(time.Hour)
	if err := store.Put(ctx, sessionID, "the-real-token", "friend@example.com", expiresAt); err != nil {
		t.Fatalf("Put: %v", err)
	}

	if _, found, err := store.Lookup(ctx, sessionID, "wrong-token"); err != nil {
		t.Fatalf("Lookup wrong token: %v", err)
	} else if found {
		t.Fatal("Lookup with the wrong token should not match")
	}

	email, found, err := store.Lookup(ctx, sessionID, "the-real-token")
	if err != nil {
		t.Fatalf("Lookup correct token: %v", err)
	}
	if !found || email != "friend@example.com" {
		t.Fatalf("Lookup correct token: found=%v email=%q", found, email)
	}

	if err := store.Delete(ctx, sessionID); err != nil {
		t.Fatalf("Delete: %v", err)
	}
	if _, found, err := store.Lookup(ctx, sessionID, "the-real-token"); err != nil {
		t.Fatalf("Lookup after Delete: %v", err)
	} else if found {
		t.Fatal("Lookup after Delete: unexpectedly still found")
	}

	// Delete on an already-missing entry is idempotent.
	if err := store.Delete(ctx, sessionID); err != nil {
		t.Errorf("Delete on a missing entry should be a no-op, got: %v", err)
	}
}

func TestIntegration_RedisTokenStore_Expiry(t *testing.T) {
	client := redisTestClient(t)
	store := NewRedisTokenStore(client)
	ctx := context.Background()

	sessionID := "sess-redis-test-expiry"
	t.Cleanup(func() { _ = store.Delete(ctx, sessionID) })

	if err := store.Put(ctx, sessionID, "tok", "friend@example.com", time.Now().Add(150*time.Millisecond)); err != nil {
		t.Fatalf("Put: %v", err)
	}
	if _, found, err := store.Lookup(ctx, sessionID, "tok"); err != nil || !found {
		t.Fatalf("Lookup immediately after Put: found=%v err=%v", found, err)
	}

	deadline := time.Now().Add(3 * time.Second)
	for time.Now().Before(deadline) {
		_, found, err := store.Lookup(ctx, sessionID, "tok")
		if err != nil {
			t.Fatalf("Lookup while polling for expiry: %v", err)
		}
		if !found {
			return
		}
		time.Sleep(50 * time.Millisecond)
	}
	t.Fatal("token did not expire within 3s of a 150ms TTL")
}

func TestNewTokenStoreFromEnv(t *testing.T) {
	t.Run("defaults to in-memory when REDIS_URL is unset", func(t *testing.T) {
		t.Setenv("REDIS_URL", "")
		store, err := NewTokenStoreFromEnv()
		if err != nil {
			t.Fatalf("NewTokenStoreFromEnv: %v", err)
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
		store, err := NewTokenStoreFromEnv()
		if err != nil {
			t.Fatalf("NewTokenStoreFromEnv: %v", err)
		}
		if _, ok := store.(*RedisTokenStore); !ok {
			t.Errorf("expected *RedisTokenStore, got %T", store)
		}
	})

	t.Run("rejects a malformed REDIS_URL", func(t *testing.T) {
		t.Setenv("REDIS_URL", "redis://")
		if _, err := NewTokenStoreFromEnv(); err == nil {
			t.Error("expected an error for a malformed REDIS_URL")
		}
	})
}
