package credential

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/sagearbor/personhood/pkg/types"
)

func newRoundtripFixture(t *testing.T) (types.PersonhoodCredential, *Verifier) {
	t.Helper()
	pub, priv := deterministicKey(t, 0x99)
	issuer := NewIssuer("did:web:issuer.example", "key-1", priv, "")
	issuedAt := time.Date(2026, 5, 24, 12, 0, 0, 0, time.UTC)
	anchor := "phone-liveness"
	cred, err := issuer.Issue(
		"did:key:z6Mkholder",
		sampleMethods(t, issuedAt),
		&anchor,
		nil,
		issuedAt,
		issuedAt.Add(365*24*time.Hour),
		nil,
	)
	if err != nil {
		t.Fatalf("Issue: %v", err)
	}
	verifier := NewVerifier(MapResolver{
		"did:web:issuer.example": pub,
	})
	return cred, verifier
}

func TestVerifier_Verify_HappyPath(t *testing.T) {
	t.Parallel()
	cred, v := newRoundtripFixture(t)
	if err := v.Verify(context.Background(), cred); err != nil {
		t.Fatalf("Verify: %v", err)
	}
}

func TestVerifier_Verify_TamperedSubjectField(t *testing.T) {
	t.Parallel()
	cred, v := newRoundtripFixture(t)
	cred.CredentialSubject.ID = "did:key:z6MkATTACKER"
	err := v.Verify(context.Background(), cred)
	if err == nil {
		t.Fatal("expected error from tampered credential subject")
	}
	if !errors.Is(err, ErrSignatureInvalid) {
		t.Errorf("expected ErrSignatureInvalid, got %v", err)
	}
}

func TestVerifier_Verify_TamperedMethodStrength(t *testing.T) {
	t.Parallel()
	cred, v := newRoundtripFixture(t)
	cred.CredentialSubject.VerifiedMethods[0].Strength = 100
	if err := v.Verify(context.Background(), cred); !errors.Is(err, ErrSignatureInvalid) {
		t.Errorf("expected ErrSignatureInvalid, got %v", err)
	}
}

func TestVerifier_Verify_TamperedProofValue(t *testing.T) {
	t.Parallel()
	cred, v := newRoundtripFixture(t)
	// Flip the last character of the proof value. base64url alphabet means
	// any other valid character is a safe swap that still decodes.
	orig := cred.Proof.ProofValue
	last := orig[len(orig)-1]
	swap := byte('A')
	if last == 'A' {
		swap = 'B'
	}
	cred.Proof.ProofValue = orig[:len(orig)-1] + string(swap)
	if err := v.Verify(context.Background(), cred); !errors.Is(err, ErrSignatureInvalid) {
		// A flip could also corrupt the base64 such that decoding fails.
		if !errors.Is(err, ErrProofMalformed) {
			t.Errorf("expected ErrSignatureInvalid or ErrProofMalformed, got %v", err)
		}
	}
}

func TestVerifier_Verify_UnknownIssuer(t *testing.T) {
	t.Parallel()
	cred, _ := newRoundtripFixture(t)
	v := NewVerifier(MapResolver{}) // empty map -> issuer unknown
	err := v.Verify(context.Background(), cred)
	if !errors.Is(err, ErrIssuerUnknown) {
		t.Errorf("expected ErrIssuerUnknown, got %v", err)
	}
}

func TestVerifier_Verify_StructuralValidationFails(t *testing.T) {
	t.Parallel()
	cred, v := newRoundtripFixture(t)
	cred.Context = []string{"https://example.com/wrong"} // breaks Validate
	err := v.Verify(context.Background(), cred)
	if !errors.Is(err, ErrStructuralInvalid) {
		t.Errorf("expected ErrStructuralInvalid, got %v", err)
	}
}

func TestVerifier_Verify_ProofMissing(t *testing.T) {
	t.Parallel()
	cred, v := newRoundtripFixture(t)
	cred.Proof = nil
	err := v.Verify(context.Background(), cred)
	if !errors.Is(err, ErrProofMissing) {
		t.Errorf("expected ErrProofMissing, got %v", err)
	}
}

func TestVerifier_Verify_ProofUnsupportedType(t *testing.T) {
	t.Parallel()
	cred, v := newRoundtripFixture(t)
	cred.Proof.Type = "JsonWebSignature2020"
	err := v.Verify(context.Background(), cred)
	if !errors.Is(err, ErrProofUnsupported) {
		t.Errorf("expected ErrProofUnsupported, got %v", err)
	}
}

func TestVerifier_Verify_ProofUnsupportedPurpose(t *testing.T) {
	t.Parallel()
	cred, v := newRoundtripFixture(t)
	cred.Proof.ProofPurpose = "authentication"
	err := v.Verify(context.Background(), cred)
	if !errors.Is(err, ErrProofUnsupported) {
		t.Errorf("expected ErrProofUnsupported, got %v", err)
	}
}

func TestVerifier_Verify_ProofMalformed(t *testing.T) {
	t.Parallel()
	cred, v := newRoundtripFixture(t)
	cred.Proof.ProofValue = "!!!not_base64!!!"
	err := v.Verify(context.Background(), cred)
	if !errors.Is(err, ErrProofMalformed) {
		t.Errorf("expected ErrProofMalformed, got %v", err)
	}
}

func TestVerifier_Verify_MultibaseRejectedV01(t *testing.T) {
	// v0.1 explicitly does not accept multibase-base58-btc proof values.
	t.Parallel()
	cred, v := newRoundtripFixture(t)
	cred.Proof.ProofValue = "z" + cred.Proof.ProofValue
	err := v.Verify(context.Background(), cred)
	if !errors.Is(err, ErrProofMalformed) {
		t.Errorf("expected ErrProofMalformed for multibase, got %v", err)
	}
	if err != nil && !strings.Contains(err.Error(), "multibase") {
		t.Errorf("expected error to mention multibase, got %v", err)
	}
}

func TestMapResolver(t *testing.T) {
	t.Parallel()
	pub, _ := deterministicKey(t, 0x22)
	m := MapResolver{"did:web:foo": pub}
	got, err := m.Resolve(context.Background(), "did:web:foo")
	if err != nil {
		t.Fatalf("Resolve hit: %v", err)
	}
	if string(got) != string(pub) {
		t.Error("Resolve returned wrong key")
	}
	if _, err := m.Resolve(context.Background(), "did:web:missing"); err == nil {
		t.Error("expected error for missing DID")
	}
	var nilMap MapResolver
	if _, err := nilMap.Resolve(context.Background(), "did:web:x"); err == nil {
		t.Error("expected error from nil MapResolver")
	}
}

func TestVerifier_NilResolver(t *testing.T) {
	t.Parallel()
	var v *Verifier
	if err := v.Verify(context.Background(), types.PersonhoodCredential{}); err == nil {
		t.Error("expected error from nil verifier")
	}
	v = &Verifier{}
	if err := v.Verify(context.Background(), types.PersonhoodCredential{}); err == nil {
		t.Error("expected error from verifier with nil resolver")
	}
}

func TestWebResolver_RejectsNonDIDWeb(t *testing.T) {
	t.Parallel()
	w := &WebResolver{}
	if _, err := w.Resolve(context.Background(), "did:key:zXYZ"); err == nil {
		t.Error("expected error for non-did:web DID")
	}
}

func TestWebResolver_RejectsPathForm(t *testing.T) {
	t.Parallel()
	w := &WebResolver{}
	_, err := w.Resolve(context.Background(), "did:web:example.com:user:alice")
	if err == nil {
		t.Error("expected error for path-form did:web in v0.1")
	}
}
