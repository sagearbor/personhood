package governmentidliveness

import (
	"context"
	"errors"
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

func TestIntegration_RedisResultStore_InquiryBindingAndResult(t *testing.T) {
	client := redisTestClient(t)
	store := NewRedisResultStore(client)
	ctx := context.Background()

	sessionID := "sess-redis-govid-1"
	inquiryID := "inq-redis-govid-1"

	if got, err := store.LookupSessionByInquiry(ctx, inquiryID); err != nil {
		t.Fatalf("LookupSessionByInquiry before PutInquiry: %v", err)
	} else if got != "" {
		t.Fatalf("LookupSessionByInquiry before PutInquiry: got %q, want empty", got)
	}

	if err := store.PutInquiry(ctx, sessionID, inquiryID); err != nil {
		t.Fatalf("PutInquiry: %v", err)
	}
	got, err := store.LookupSessionByInquiry(ctx, inquiryID)
	if err != nil {
		t.Fatalf("LookupSessionByInquiry: %v", err)
	}
	if got != sessionID {
		t.Errorf("LookupSessionByInquiry = %q, want %q", got, sessionID)
	}

	if _, err := store.GetResult(ctx, sessionID); !errors.Is(err, ErrNoResultYet) {
		t.Fatalf("GetResult before PutResult: got %v, want ErrNoResultYet", err)
	}

	completedAt := time.Now().UTC().Truncate(time.Millisecond)
	result := Result{
		InquiryID:   inquiryID,
		Status:      StatusApproved,
		RawStatus:   "completed",
		CompletedAt: completedAt,
		EventName:   "inquiry.completed",
	}
	if err := store.PutResult(ctx, sessionID, result); err != nil {
		t.Fatalf("PutResult: %v", err)
	}

	gotResult, err := store.GetResult(ctx, sessionID)
	if err != nil {
		t.Fatalf("GetResult: %v", err)
	}
	if gotResult.InquiryID != result.InquiryID ||
		gotResult.Status != result.Status ||
		gotResult.RawStatus != result.RawStatus ||
		gotResult.EventName != result.EventName ||
		!gotResult.CompletedAt.Equal(result.CompletedAt) {
		t.Errorf("GetResult = %+v, want %+v", gotResult, result)
	}
}

func TestIntegration_RedisResultStore_RejectsEmptyIDs(t *testing.T) {
	client := redisTestClient(t)
	store := NewRedisResultStore(client)
	ctx := context.Background()

	if err := store.PutInquiry(ctx, "", "inq"); err == nil {
		t.Error("PutInquiry with an empty sessionID should fail")
	}
	if err := store.PutInquiry(ctx, "sess", ""); err == nil {
		t.Error("PutInquiry with an empty inquiryID should fail")
	}
	if err := store.PutResult(ctx, "", Result{}); err == nil {
		t.Error("PutResult with an empty sessionID should fail")
	}
}

func TestNewResultStoreFromEnv(t *testing.T) {
	t.Run("defaults to in-memory when REDIS_URL is unset", func(t *testing.T) {
		t.Setenv("REDIS_URL", "")
		store, err := NewResultStoreFromEnv()
		if err != nil {
			t.Fatalf("NewResultStoreFromEnv: %v", err)
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
		store, err := NewResultStoreFromEnv()
		if err != nil {
			t.Fatalf("NewResultStoreFromEnv: %v", err)
		}
		if _, ok := store.(*RedisResultStore); !ok {
			t.Errorf("expected *RedisResultStore, got %T", store)
		}
	})

	t.Run("rejects a malformed REDIS_URL", func(t *testing.T) {
		t.Setenv("REDIS_URL", "redis://")
		if _, err := NewResultStoreFromEnv(); err == nil {
			t.Error("expected an error for a malformed REDIS_URL")
		}
	})
}
