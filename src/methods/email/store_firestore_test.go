package email

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
//	firebase emulators:exec --only firestore 'cd src/methods/email && go test -race ./...'
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

func TestIntegration_FirestoreTokenStore_PutLookupDelete(t *testing.T) {
	client := firestoreTestClient(t)
	store := NewFirestoreTokenStore(client)
	ctx := context.Background()

	sessionID := "sess-firestore-test-1"
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

func TestIntegration_FirestoreTokenStore_Expiry(t *testing.T) {
	client := firestoreTestClient(t)
	store := NewFirestoreTokenStore(client)
	ctx := context.Background()

	sessionID := "sess-firestore-test-expiry"
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

func TestNewTokenStoreFromEnv_Firestore(t *testing.T) {
	t.Run("selects Firestore when FIRESTORE_PROJECT_ID is set", func(t *testing.T) {
		t.Setenv("FIRESTORE_PROJECT_ID", "personhood-test")
		t.Setenv("REDIS_URL", "")
		store, err := NewTokenStoreFromEnv()
		if err != nil {
			t.Fatalf("NewTokenStoreFromEnv: %v", err)
		}
		if _, ok := store.(*FirestoreTokenStore); !ok {
			t.Errorf("expected *FirestoreTokenStore, got %T", store)
		}
	})

	t.Run("prioritizes Firestore over Redis when both are set", func(t *testing.T) {
		t.Setenv("FIRESTORE_PROJECT_ID", "personhood-test")
		t.Setenv("REDIS_URL", "redis://127.0.0.1:6399")
		store, err := NewTokenStoreFromEnv()
		if err != nil {
			t.Fatalf("NewTokenStoreFromEnv: %v", err)
		}
		if _, ok := store.(*FirestoreTokenStore); !ok {
			t.Errorf("expected *FirestoreTokenStore (Firestore should win), got %T", store)
		}
	})
}
