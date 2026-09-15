package firestoreclient

import (
	"context"
	"os"
	"testing"
	"time"
)

// testClient returns a Client pointed at a real local Firestore emulator, or
// skips if FIRESTORE_EMULATOR_HOST is not set. Run locally with:
//
//	firebase emulators:exec --only firestore 'go test -race ./...'
//
// (from the repo root; firebase.json's "emulators.firestore" block picks the
// port). FIRESTORE_EMULATOR_HOST is set by emulators:exec automatically.
func testClient(t *testing.T) *Client {
	t.Helper()
	if os.Getenv("FIRESTORE_EMULATOR_HOST") == "" {
		t.Skip("FIRESTORE_EMULATOR_HOST not set; skipping real-Firestore integration test (run under `firebase emulators:exec --only firestore`)")
	}
	c, err := New("personhood-test")
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	return c
}

func uniqueID(t *testing.T) string {
	t.Helper()
	return t.Name() + "-" + time.Now().UTC().Format("150405.000000000")
}

func TestNew_RequiresProjectID(t *testing.T) {
	if _, err := New(""); err == nil {
		t.Fatal("New(\"\"): want error, got nil")
	}
}

func TestIntegration_SetGetDel(t *testing.T) {
	c := testClient(t)
	ctx := context.Background()
	id := uniqueID(t)

	if _, found, err := c.Get(ctx, "test-coll", id); err != nil || found {
		t.Fatalf("Get before Set: found=%v err=%v, want found=false", found, err)
	}

	want := []byte(`{"hello":"world","n":42}`)
	if err := c.Set(ctx, "test-coll", id, want, 0); err != nil {
		t.Fatalf("Set: %v", err)
	}

	got, found, err := c.Get(ctx, "test-coll", id)
	if err != nil || !found {
		t.Fatalf("Get after Set: found=%v err=%v, want found=true", found, err)
	}
	if string(got) != string(want) {
		t.Fatalf("Get after Set: got %q, want %q", got, want)
	}

	// Overwrite — Set is an upsert, not create-only.
	want2 := []byte(`{"hello":"again"}`)
	if err := c.Set(ctx, "test-coll", id, want2, 0); err != nil {
		t.Fatalf("Set (overwrite): %v", err)
	}
	got2, found2, err := c.Get(ctx, "test-coll", id)
	if err != nil || !found2 || string(got2) != string(want2) {
		t.Fatalf("Get after overwrite: got=%q found=%v err=%v, want %q/true", got2, found2, err, want2)
	}

	if err := c.Del(ctx, "test-coll", id); err != nil {
		t.Fatalf("Del: %v", err)
	}
	if _, found, err := c.Get(ctx, "test-coll", id); err != nil || found {
		t.Fatalf("Get after Del: found=%v err=%v, want found=false", found, err)
	}

	// Del on a document that was never created is not an error.
	if err := c.Del(ctx, "test-coll", uniqueID(t)); err != nil {
		t.Fatalf("Del on missing document: %v", err)
	}
}

func TestIntegration_TTLExpiry(t *testing.T) {
	c := testClient(t)
	ctx := context.Background()
	id := uniqueID(t)

	// A short TTL that has passed by the time we call Get: Get must treat
	// the document as expired and delete it on read, mirroring
	// pkg/redisclient's explicit application-level expiry check (both
	// stores rely on this, not just the backend's own TTL mechanism, since
	// neither client sets a TTL at all for ttl<=0 — see Set's doc comment).
	if err := c.Set(ctx, "test-coll-ttl", id, []byte("stale"), 20*time.Millisecond); err != nil {
		t.Fatalf("Set with short ttl: %v", err)
	}
	time.Sleep(100 * time.Millisecond)
	if _, found, err := c.Get(ctx, "test-coll-ttl", id); err != nil || found {
		t.Fatalf("Get on expired document: found=%v err=%v, want found=false", found, err)
	}

	// A generous TTL: still present immediately after.
	id2 := uniqueID(t)
	if err := c.Set(ctx, "test-coll-ttl", id2, []byte("fresh"), time.Hour); err != nil {
		t.Fatalf("Set with future ttl: %v", err)
	}
	if _, found, err := c.Get(ctx, "test-coll-ttl", id2); err != nil || !found {
		t.Fatalf("Get on unexpired document: found=%v err=%v, want found=true", found, err)
	}
}

func TestIntegration_MultipleCollectionsIsolated(t *testing.T) {
	c := testClient(t)
	ctx := context.Background()
	id := uniqueID(t)

	if err := c.Set(ctx, "coll-a", id, []byte("a"), 0); err != nil {
		t.Fatalf("Set coll-a: %v", err)
	}
	if _, found, err := c.Get(ctx, "coll-b", id); err != nil || found {
		t.Fatalf("Get coll-b with same id as coll-a: found=%v err=%v, want false (collections must not leak into each other)", found, err)
	}
	got, found, err := c.Get(ctx, "coll-a", id)
	if err != nil || !found || string(got) != "a" {
		t.Fatalf("Get coll-a: got=%q found=%v err=%v", got, found, err)
	}
}
