package governmentidliveness

import (
	"context"
	"errors"
	"os"
	"testing"
	"time"

	"github.com/sagearbor/personhood/pkg/firestoreclient"
)

// firestoreTestClient returns a Client pointed at a real local Firestore
// emulator for tests in this file, or skips if none is configured. Run
// locally (from the repo root) with:
//
//	firebase emulators:exec --only firestore 'cd src/methods/government-id-liveness && go test -race ./...'
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

func TestIntegration_FirestoreResultStore_InquiryBindingAndResult(t *testing.T) {
	client := firestoreTestClient(t)
	store := NewFirestoreResultStore(client)
	ctx := context.Background()

	sessionID := "sess-firestore-govid-1"
	inquiryID := "inq-firestore-govid-1"

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

func TestIntegration_FirestoreResultStore_RejectsEmptyIDs(t *testing.T) {
	client := firestoreTestClient(t)
	store := NewFirestoreResultStore(client)
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

func TestNewResultStoreFromEnv_Firestore(t *testing.T) {
	t.Run("selects Firestore when FIRESTORE_PROJECT_ID is set", func(t *testing.T) {
		t.Setenv("FIRESTORE_PROJECT_ID", "personhood-test")
		t.Setenv("REDIS_URL", "")
		store, err := NewResultStoreFromEnv()
		if err != nil {
			t.Fatalf("NewResultStoreFromEnv: %v", err)
		}
		if _, ok := store.(*FirestoreResultStore); !ok {
			t.Errorf("expected *FirestoreResultStore, got %T", store)
		}
	})

	t.Run("prioritizes Firestore over Redis when both are set", func(t *testing.T) {
		t.Setenv("FIRESTORE_PROJECT_ID", "personhood-test")
		t.Setenv("REDIS_URL", "redis://127.0.0.1:6399")
		store, err := NewResultStoreFromEnv()
		if err != nil {
			t.Fatalf("NewResultStoreFromEnv: %v", err)
		}
		if _, ok := store.(*FirestoreResultStore); !ok {
			t.Errorf("expected *FirestoreResultStore (Firestore should win), got %T", store)
		}
	})
}
