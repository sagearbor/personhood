package socialvouching

import (
	"context"
	"testing"
	"time"
)

func TestInMemoryGraphStore_SeedsAreKnown(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	g := NewInMemoryGraphStore(map[string]float64{"seed-1": 1.0})

	trust, known, err := g.TrustOf(ctx, "seed-1")
	if err != nil {
		t.Fatalf("TrustOf: %v", err)
	}
	if !known || trust != 1.0 {
		t.Fatalf("TrustOf(seed-1) = (%v, %v), want (1.0, true)", trust, known)
	}

	_, known, err = g.TrustOf(ctx, "nobody")
	if err != nil {
		t.Fatalf("TrustOf: %v", err)
	}
	if known {
		t.Fatal("TrustOf(nobody) reported known = true")
	}
}

func TestInMemoryGraphStore_RecordVouchDedupesByVoucher(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	g := NewInMemoryGraphStore(nil)

	if err := g.RecordVouch(ctx, "candidate-1", Vouch{VoucherID: "v1", Weight: 0.5, At: time.Now()}); err != nil {
		t.Fatalf("RecordVouch 1: %v", err)
	}
	// Same voucher vouching again overwrites, not duplicates.
	if err := g.RecordVouch(ctx, "candidate-1", Vouch{VoucherID: "v1", Weight: 0.9, At: time.Now()}); err != nil {
		t.Fatalf("RecordVouch 2: %v", err)
	}
	if err := g.RecordVouch(ctx, "candidate-1", Vouch{VoucherID: "v2", Weight: 1.0, At: time.Now()}); err != nil {
		t.Fatalf("RecordVouch 3: %v", err)
	}

	vouches, err := g.VouchesFor(ctx, "candidate-1")
	if err != nil {
		t.Fatalf("VouchesFor: %v", err)
	}
	if len(vouches) != 2 {
		t.Fatalf("VouchesFor returned %d vouches, want 2 (deduped by voucher)", len(vouches))
	}
	var v1Weight float64
	for _, v := range vouches {
		if v.VoucherID == "v1" {
			v1Weight = v.Weight
		}
	}
	if v1Weight != 0.9 {
		t.Fatalf("v1's weight = %v, want 0.9 (the latest vouch should win)", v1Weight)
	}
}

func TestInMemoryGraphStore_EnrollThenVouch(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	g := NewInMemoryGraphStore(nil)

	if err := g.Enroll(ctx, "graduate-1", 0.6); err != nil {
		t.Fatalf("Enroll: %v", err)
	}
	trust, known, err := g.TrustOf(ctx, "graduate-1")
	if err != nil {
		t.Fatalf("TrustOf: %v", err)
	}
	if !known || trust != 0.6 {
		t.Fatalf("TrustOf(graduate-1) = (%v, %v), want (0.6, true)", trust, known)
	}
}
