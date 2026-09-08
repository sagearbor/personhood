package fuzzyextractorselfie

import (
	"context"
	"testing"
)

func TestInMemoryAccumulator_NewPersonNoDuplicate(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	acc := NewInMemoryAccumulator()

	template := RandomTemplateForTesting()
	_, found, err := acc.FindDuplicate(ctx, template)
	if err != nil {
		t.Fatalf("FindDuplicate: %v", err)
	}
	if found {
		t.Fatal("FindDuplicate on empty accumulator reported a duplicate")
	}
}

func TestInMemoryAccumulator_ExactReenrollmentIsDuplicate(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	acc := NewInMemoryAccumulator()

	template := RandomTemplateForTesting()
	helper, commitment, err := Gen(template)
	if err != nil {
		t.Fatalf("Gen: %v", err)
	}
	if err := acc.Add(ctx, EnrollmentRecord{Helper: helper, Commitment: commitment}); err != nil {
		t.Fatalf("Add: %v", err)
	}

	rec, found, err := acc.FindDuplicate(ctx, template)
	if err != nil {
		t.Fatalf("FindDuplicate: %v", err)
	}
	if !found {
		t.Fatal("FindDuplicate: expected the same template to be flagged as a duplicate")
	}
	if rec.Commitment != commitment {
		t.Fatalf("FindDuplicate returned commitment %x, want %x", rec.Commitment, commitment)
	}
}

func TestInMemoryAccumulator_NoisyReenrollmentIsDuplicate(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	acc := NewInMemoryAccumulator()

	template := RandomTemplateForTesting()
	helper, commitment, err := Gen(template)
	if err != nil {
		t.Fatalf("Gen: %v", err)
	}
	if err := acc.Add(ctx, EnrollmentRecord{Helper: helper, Commitment: commitment}); err != nil {
		t.Fatalf("Add: %v", err)
	}

	noisy := NoisyTemplateForTesting(template, 5)
	_, found, err := acc.FindDuplicate(ctx, noisy)
	if err != nil {
		t.Fatalf("FindDuplicate: %v", err)
	}
	if !found {
		t.Fatal("FindDuplicate: expected a lightly-noised re-reading of the same person to be flagged as a duplicate")
	}
}

func TestInMemoryAccumulator_DistinctPeopleBothEnroll(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	acc := NewInMemoryAccumulator()

	templateA := RandomTemplateForTesting()
	helperA, commitmentA, err := Gen(templateA)
	if err != nil {
		t.Fatalf("Gen A: %v", err)
	}
	if err := acc.Add(ctx, EnrollmentRecord{Helper: helperA, Commitment: commitmentA}); err != nil {
		t.Fatalf("Add A: %v", err)
	}

	templateB := RandomTemplateForTesting()
	_, found, err := acc.FindDuplicate(ctx, templateB)
	if err != nil {
		t.Fatalf("FindDuplicate B: %v", err)
	}
	if found {
		t.Fatal("FindDuplicate: an unrelated second person was incorrectly flagged as a duplicate")
	}

	helperB, commitmentB, err := Gen(templateB)
	if err != nil {
		t.Fatalf("Gen B: %v", err)
	}
	if err := acc.Add(ctx, EnrollmentRecord{Helper: helperB, Commitment: commitmentB}); err != nil {
		t.Fatalf("Add B: %v", err)
	}

	count, err := acc.Count(ctx)
	if err != nil {
		t.Fatalf("Count: %v", err)
	}
	if count != 2 {
		t.Fatalf("Count = %d, want 2", count)
	}
}
