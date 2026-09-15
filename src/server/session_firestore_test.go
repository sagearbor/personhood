package server

import (
	"crypto/ed25519"
	"crypto/rand"
	"os"
	"testing"
	"time"

	"github.com/sagearbor/personhood/pkg/firestoreclient"
	"github.com/sagearbor/personhood/pkg/types"
)

// firestoreTestClient returns a Client pointed at a real local Firestore
// emulator for tests in this file, or skips if none is configured. Run
// locally (from the repo root) with:
//
//	firebase emulators:exec --only firestore 'cd src/server && go test -race ./...'
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

func TestIntegration_FirestoreSessionStore_CreateGetRecordIssue(t *testing.T) {
	client := firestoreTestClient(t)
	store := NewFirestoreSessionStore(client, time.Hour)

	pub, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now()

	view, err := store.Create(pub, now)
	if err != nil {
		t.Fatalf("Create: %v", err)
	}
	if view.ID == "" {
		t.Fatal("Create: empty session ID")
	}
	if len(view.HolderPublicKey) != ed25519.PublicKeySize {
		t.Fatalf("Create: holder public key not persisted, got %v", view.HolderPublicKey)
	}
	wantDID := HolderDIDForSession(view.ID, pub)
	if view.HolderDID != wantDID {
		t.Errorf("Create: holder DID = %q, want %q", view.HolderDID, wantDID)
	}

	got, err := store.Get(view.ID)
	if err != nil {
		t.Fatalf("Get: %v", err)
	}
	if got.ID != view.ID || got.HolderDID != view.HolderDID {
		t.Errorf("Get returned a different session: %+v vs %+v", got, view)
	}
	if len(got.VerifiedMethods) != 0 {
		t.Fatalf("expected no verified methods yet, got %+v", got.VerifiedMethods)
	}

	result := types.MethodResult{
		Success:    true,
		MethodID:   "email",
		VerifiedAt: now,
	}
	metadata := types.MethodMetadata{ID: "email", Type: types.MethodTypeSupplementary, Strength: 8, FreshnessLifetime: time.Hour}
	if err := store.RecordMethodResult(view.ID, result, metadata); err != nil {
		t.Fatalf("RecordMethodResult: %v", err)
	}

	after, err := store.Get(view.ID)
	if err != nil {
		t.Fatalf("Get after record: %v", err)
	}
	if len(after.VerifiedMethods) != 1 || after.VerifiedMethods[0].MethodID != "email" {
		t.Fatalf("expected one verified email method, got %+v", after.VerifiedMethods)
	}

	if err := store.MarkIssued(view.ID, "urn:test:cred:1"); err != nil {
		t.Fatalf("MarkIssued: %v", err)
	}
	issued, err := store.Get(view.ID)
	if err != nil {
		t.Fatalf("Get after MarkIssued: %v", err)
	}
	if issued.IssuedCredentialID != "urn:test:cred:1" {
		t.Errorf("IssuedCredentialID = %q, want %q", issued.IssuedCredentialID, "urn:test:cred:1")
	}

	// A second MarkIssued and a post-issuance RecordMethodResult are both
	// rejected, matching InMemorySessionStore and RedisSessionStore.
	if err := store.MarkIssued(view.ID, "urn:test:cred:2"); err != ErrSessionAlreadyIssued {
		t.Errorf("second MarkIssued: got %v, want ErrSessionAlreadyIssued", err)
	}
	if err := store.RecordMethodResult(view.ID, result, metadata); err != ErrSessionAlreadyIssued {
		t.Errorf("RecordMethodResult after issue: got %v, want ErrSessionAlreadyIssued", err)
	}
}

func TestIntegration_FirestoreSessionStore_GetMissingOrExpired(t *testing.T) {
	client := firestoreTestClient(t)
	store := NewFirestoreSessionStore(client, time.Hour)

	if _, err := store.Get("does-not-exist"); err != ErrSessionNotFound {
		t.Errorf("Get on missing session: got %v, want ErrSessionNotFound", err)
	}

	// A store with a near-zero TTL should expire its own sessions.
	shortStore := NewFirestoreSessionStore(client, 100*time.Millisecond)
	view, err := shortStore.Create(nil, time.Now())
	if err != nil {
		t.Fatalf("Create: %v", err)
	}
	if len(view.HolderPublicKey) != 0 {
		t.Errorf("expected no holder public key for a nil-key Create, got %v", view.HolderPublicKey)
	}

	deadline := time.Now().Add(3 * time.Second)
	for time.Now().Before(deadline) {
		if _, err := shortStore.Get(view.ID); err == ErrSessionNotFound {
			return
		}
		time.Sleep(50 * time.Millisecond)
	}
	t.Fatal("session did not expire within 3s of a 100ms TTL")
}

func TestIntegration_FirestoreSessionStore_SharedAcrossInstances(t *testing.T) {
	client := firestoreTestClient(t)
	// Two independent store instances pointed at the same Firestore project
	// stand in for two horizontally scaled issuer replicas, or one replica
	// restarted between two requests — the entire point of this backend
	// versus InMemorySessionStore.
	writer := NewFirestoreSessionStore(client, time.Hour)
	reader := NewFirestoreSessionStore(client, time.Hour)

	view, err := writer.Create(nil, time.Now())
	if err != nil {
		t.Fatalf("Create on writer: %v", err)
	}
	got, err := reader.Get(view.ID)
	if err != nil {
		t.Fatalf("Get on a different store instance: %v", err)
	}
	if got.ID != view.ID {
		t.Errorf("cross-instance session mismatch: %+v vs %+v", got, view)
	}
}

func TestNewSessionStoreFromEnv_Firestore(t *testing.T) {
	t.Run("selects Firestore when FIRESTORE_PROJECT_ID is set", func(t *testing.T) {
		t.Setenv("FIRESTORE_PROJECT_ID", "personhood-test")
		t.Setenv("REDIS_URL", "")
		store, err := NewSessionStoreFromEnv(time.Minute)
		if err != nil {
			t.Fatalf("NewSessionStoreFromEnv: %v", err)
		}
		if _, ok := store.(*FirestoreSessionStore); !ok {
			t.Errorf("expected *FirestoreSessionStore, got %T", store)
		}
	})

	t.Run("prioritizes Firestore over Redis when both are set", func(t *testing.T) {
		t.Setenv("FIRESTORE_PROJECT_ID", "personhood-test")
		t.Setenv("REDIS_URL", "redis://127.0.0.1:6399")
		store, err := NewSessionStoreFromEnv(time.Minute)
		if err != nil {
			t.Fatalf("NewSessionStoreFromEnv: %v", err)
		}
		if _, ok := store.(*FirestoreSessionStore); !ok {
			t.Errorf("expected *FirestoreSessionStore (Firestore should win), got %T", store)
		}
	})
}
