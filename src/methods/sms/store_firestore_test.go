package sms

import (
	"context"
	"os"
	"testing"
	"time"

	"github.com/sagearbor/personhood/pkg/firestoreclient"
)

// firestoreTestClient returns a Client pointed at a real local Firestore
// emulator for tests in this file, or skips if none is configured. Run
// locally (from the repo root) with:
//
//	firebase emulators:exec --only firestore 'cd src/methods/sms && go test -race ./...'
func firestoreTestClient(t *testing.T) *firestoreclient.Client {
	t.Helper()
	if os.Getenv("FIRESTORE_EMULATOR_HOST") == "" {
		t.Skip("FIRESTORE_EMULATOR_HOST not set; skipping real-Firestore integration test (run under `firebase emulators:exec --only firestore`)")
	}
	c, err := firestoreclient.New("personhood-test")
	if err != nil {
		t.Fatalf("firestoreclient.New: %v", err)
	}
	return c
}

func TestIntegration_FirestoreOTPStore_PutVerifyLockout(t *testing.T) {
	client := firestoreTestClient(t)
	store := NewFirestoreOTPStore(client)
	ctx := context.Background()

	key := "+15551234567-firestore-test"
	t.Cleanup(func() { _ = store.Invalidate(ctx, key) })

	if err := store.Put(ctx, key, "123456", time.Now().Add(time.Hour)); err != nil {
		t.Fatalf("Put: %v", err)
	}

	ok, remaining, err := store.Verify(ctx, key, "000000")
	if err != nil {
		t.Fatalf("Verify wrong attempt: %v", err)
	}
	if ok {
		t.Fatal("Verify wrong attempt: unexpectedly ok")
	}
	if remaining != MaxAttempts-1 {
		t.Fatalf("Verify wrong attempt: remaining = %d, want %d", remaining, MaxAttempts-1)
	}

	ok, _, err = store.Verify(ctx, key, "123456")
	if err != nil {
		t.Fatalf("Verify correct attempt: %v", err)
	}
	if !ok {
		t.Fatal("Verify correct attempt: expected ok=true")
	}

	// Once verified, the OTP is invalidated — a replay must not succeed.
	ok, _, err = store.Verify(ctx, key, "123456")
	if err != nil {
		t.Fatalf("Verify replay: %v", err)
	}
	if ok {
		t.Fatal("Verify replay after success: expected ok=false")
	}
}

func TestIntegration_FirestoreOTPStore_AttemptLockout(t *testing.T) {
	client := firestoreTestClient(t)
	store := NewFirestoreOTPStore(client)
	ctx := context.Background()

	key := "+15559876543-firestore-lockout"
	t.Cleanup(func() { _ = store.Invalidate(ctx, key) })

	if err := store.Put(ctx, key, "999999", time.Now().Add(time.Hour)); err != nil {
		t.Fatalf("Put: %v", err)
	}

	for i := 0; i < MaxAttempts; i++ {
		ok, _, err := store.Verify(ctx, key, "wrong")
		if err != nil {
			t.Fatalf("Verify attempt %d: %v", i, err)
		}
		if ok {
			t.Fatalf("Verify attempt %d: unexpectedly matched", i)
		}
	}

	// Even the correct OTP must now be rejected — the entry is locked out.
	ok, _, err := store.Verify(ctx, key, "999999")
	if err != nil {
		t.Fatalf("Verify after lockout: %v", err)
	}
	if ok {
		t.Fatal("Verify after lockout: expected ok=false even for the correct OTP")
	}
}

func TestNewOTPStoreFromEnv_Firestore(t *testing.T) {
	t.Run("selects Firestore when FIRESTORE_PROJECT_ID is set", func(t *testing.T) {
		t.Setenv("FIRESTORE_PROJECT_ID", "personhood-test")
		t.Setenv("REDIS_URL", "")
		store, err := NewOTPStoreFromEnv()
		if err != nil {
			t.Fatalf("NewOTPStoreFromEnv: %v", err)
		}
		if _, ok := store.(*FirestoreOTPStore); !ok {
			t.Errorf("expected *FirestoreOTPStore, got %T", store)
		}
	})

	t.Run("prioritizes Firestore over Redis when both are set", func(t *testing.T) {
		t.Setenv("FIRESTORE_PROJECT_ID", "personhood-test")
		t.Setenv("REDIS_URL", "redis://127.0.0.1:6399")
		store, err := NewOTPStoreFromEnv()
		if err != nil {
			t.Fatalf("NewOTPStoreFromEnv: %v", err)
		}
		if _, ok := store.(*FirestoreOTPStore); !ok {
			t.Errorf("expected *FirestoreOTPStore (Firestore should win), got %T", store)
		}
	})
}
