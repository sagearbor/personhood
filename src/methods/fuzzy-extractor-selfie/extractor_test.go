package fuzzyextractorselfie

import (
	"bytes"
	"testing"
)

func TestGenRep_ExactMatch(t *testing.T) {
	t.Parallel()
	template := RandomTemplateForTesting()

	helper, commitment, err := Gen(template)
	if err != nil {
		t.Fatalf("Gen: %v", err)
	}

	gotCommitment, ok, err := Rep(template, helper)
	if err != nil {
		t.Fatalf("Rep: %v", err)
	}
	if !ok {
		t.Fatal("Rep: expected match on exact same template, got no match")
	}
	if gotCommitment != commitment {
		t.Fatalf("Rep commitment = %x, want %x", gotCommitment, commitment)
	}
}

func TestGenRep_NoisyGenuineMatch(t *testing.T) {
	t.Parallel()
	template := RandomTemplateForTesting()
	helper, commitment, err := Gen(template)
	if err != nil {
		t.Fatalf("Gen: %v", err)
	}

	// Flip one bit in a handful of blocks — well within each block's 7-bit
	// correction capacity — simulating sensor noise on a second genuine
	// reading of the same person.
	noisy := NoisyTemplateForTesting(template, 5)

	gotCommitment, ok, err := Rep(noisy, helper)
	if err != nil {
		t.Fatalf("Rep: %v", err)
	}
	if !ok {
		t.Fatal("Rep: expected match on lightly-noised template, got no match")
	}
	if gotCommitment != commitment {
		t.Fatalf("Rep commitment = %x, want %x (noise should have been corrected)", gotCommitment, commitment)
	}
}

func TestGenRep_UnrelatedPersonNoMatch(t *testing.T) {
	t.Parallel()
	templateA := RandomTemplateForTesting()
	helperA, commitmentA, err := Gen(templateA)
	if err != nil {
		t.Fatalf("Gen: %v", err)
	}

	templateB := RandomTemplateForTesting()
	gotCommitment, ok, err := Rep(templateB, helperA)
	if err != nil {
		t.Fatalf("Rep: %v", err)
	}
	if ok && gotCommitment == commitmentA {
		t.Fatal("Rep: unrelated random template incorrectly matched")
	}
}

func TestGen_DistinctPeopleDistinctCommitments(t *testing.T) {
	t.Parallel()
	_, commitmentA, err := Gen(RandomTemplateForTesting())
	if err != nil {
		t.Fatalf("Gen A: %v", err)
	}
	_, commitmentB, err := Gen(RandomTemplateForTesting())
	if err != nil {
		t.Fatalf("Gen B: %v", err)
	}
	if commitmentA == commitmentB {
		t.Fatal("two independent Gen calls produced the same commitment")
	}
}

func TestGen_SameTemplateTwiceDifferentHelperAndCommitment(t *testing.T) {
	t.Parallel()
	template := RandomTemplateForTesting()
	helper1, commitment1, err := Gen(template)
	if err != nil {
		t.Fatalf("Gen 1: %v", err)
	}
	helper2, commitment2, err := Gen(template)
	if err != nil {
		t.Fatalf("Gen 2: %v", err)
	}
	// Gen is randomized per call (see package doc): two Gen calls on the
	// identical template must NOT produce the same helper/commitment pair.
	// Recognizing "same person" requires Rep against previously stored
	// helper data, which is exactly what the Accumulator does.
	if bytes.Equal(helper1, helper2) {
		t.Fatal("two Gen calls on the same template produced identical helper data")
	}
	if commitment1 == commitment2 {
		t.Fatal("two Gen calls on the same template produced identical commitments")
	}
}

func TestGen_BadTemplateLength(t *testing.T) {
	t.Parallel()
	if _, _, err := Gen(make([]byte, TemplateBytes-1)); err != ErrBadTemplateLength {
		t.Fatalf("Gen with short template: err = %v, want ErrBadTemplateLength", err)
	}
	if _, _, err := Gen(make([]byte, TemplateBytes+1)); err != ErrBadTemplateLength {
		t.Fatalf("Gen with long template: err = %v, want ErrBadTemplateLength", err)
	}
}

func TestRep_BadTemplateLength(t *testing.T) {
	t.Parallel()
	template := RandomTemplateForTesting()
	helper, _, err := Gen(template)
	if err != nil {
		t.Fatalf("Gen: %v", err)
	}
	if _, _, err := Rep(make([]byte, TemplateBytes-1), helper); err != ErrBadTemplateLength {
		t.Fatalf("Rep with short template: err = %v, want ErrBadTemplateLength", err)
	}
}

func TestCommitment_Hex(t *testing.T) {
	t.Parallel()
	_, commitment, err := Gen(RandomTemplateForTesting())
	if err != nil {
		t.Fatalf("Gen: %v", err)
	}
	hexStr := commitment.Hex()
	if len(hexStr) != 64 { // 32 bytes hex-encoded
		t.Fatalf("Hex() length = %d, want 64", len(hexStr))
	}
}
