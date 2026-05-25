package credential

import (
	"crypto/ed25519"
	"strings"
	"testing"
	"time"

	"github.com/sagearbor/personhood/pkg/types"
)

// deterministicKey returns an Ed25519 keypair derived from a fixed seed so
// tests are bit-reproducible.
func deterministicKey(tb testing.TB, seed byte) (ed25519.PublicKey, ed25519.PrivateKey) {
	tb.Helper()
	seedBytes := make([]byte, ed25519.SeedSize)
	for i := range seedBytes {
		seedBytes[i] = seed
	}
	priv := ed25519.NewKeyFromSeed(seedBytes)
	return priv.Public().(ed25519.PublicKey), priv
}

// sampleMethods returns a small set of VerifiedMethods covering one anchor and
// one supplementary verification.
func sampleMethods(t testing.TB, verifiedAt time.Time) []types.VerifiedMethod {
	t.Helper()
	return []types.VerifiedMethod{
		{
			MethodID:          "phone-liveness",
			Strength:          80,
			VerifiedAt:        verifiedAt,
			FreshnessLifetime: 90 * 24 * time.Hour,
			AttestationDigest: "abc123def456",
		},
		{
			MethodID:          "email",
			Strength:          20,
			VerifiedAt:        verifiedAt,
			FreshnessLifetime: 30 * 24 * time.Hour,
			AttestationDigest: "feedface00",
		},
	}
}

func TestIssuer_Issue_HappyPath(t *testing.T) {
	t.Parallel()
	_, priv := deterministicKey(t, 0x42)
	issuer := NewIssuer("did:web:issuer.example", "key-1", priv, "")

	issuedAt := time.Date(2026, 5, 24, 12, 0, 0, 0, time.UTC)
	expiresAt := issuedAt.Add(365 * 24 * time.Hour)
	anchor := "phone-liveness"

	cred, err := issuer.Issue(
		"did:key:z6Mkholder",
		sampleMethods(t, issuedAt),
		&anchor,
		nil,
		issuedAt,
		expiresAt,
		nil,
	)
	if err != nil {
		t.Fatalf("Issue: %v", err)
	}
	if cred.Proof == nil {
		t.Fatal("expected Proof to be set after issuance")
	}
	if cred.Proof.Type != ProofTypeEd25519Signature2020 {
		t.Errorf("Proof.Type = %q, want %q", cred.Proof.Type, ProofTypeEd25519Signature2020)
	}
	if cred.Proof.ProofPurpose != ProofPurposeAssertionMethod {
		t.Errorf("Proof.ProofPurpose = %q, want %q", cred.Proof.ProofPurpose, ProofPurposeAssertionMethod)
	}
	if cred.Proof.VerificationMethod != "did:web:issuer.example#key-1" {
		t.Errorf("Proof.VerificationMethod = %q", cred.Proof.VerificationMethod)
	}
	if cred.Proof.ProofValue == "" {
		t.Error("Proof.ProofValue empty")
	}
	if cred.Issuer != "did:web:issuer.example" {
		t.Errorf("Issuer = %q", cred.Issuer)
	}
	if len(cred.Context) != 2 || cred.Context[0] != types.W3CVCContext || cred.Context[1] != types.PersonhoodVCContext {
		t.Errorf("Context = %v", cred.Context)
	}
	if cred.CredentialStatus != nil {
		t.Errorf("CredentialStatus should be nil when no statusListIndex passed, got %+v", cred.CredentialStatus)
	}
	if err := cred.Validate(); err != nil {
		t.Fatalf("issued credential failed Validate: %v", err)
	}
}

func TestIssuer_Issue_WithNullifierBinding(t *testing.T) {
	t.Parallel()
	_, priv := deterministicKey(t, 0x11)
	issuer := NewIssuer("did:web:issuer.example", "key-1", priv, "")

	issuedAt := time.Date(2026, 5, 24, 0, 0, 0, 0, time.UTC)
	anchor := "phone-liveness"
	binding := &types.NullifierBinding{
		Commitment: "0xabcdef",
		Curve:      "bn254",
		Scheme:     "pedersen-v1",
	}
	cred, err := issuer.Issue(
		"did:key:z6Mkholder",
		sampleMethods(t, issuedAt),
		&anchor,
		binding,
		issuedAt,
		issuedAt.Add(24*time.Hour),
		nil,
	)
	if err != nil {
		t.Fatalf("Issue: %v", err)
	}
	if cred.CredentialSubject.NullifierBinding == nil {
		t.Fatal("expected NullifierBinding to be present")
	}
	if cred.CredentialSubject.NullifierBinding.Commitment != "0xabcdef" {
		t.Errorf("NullifierBinding.Commitment = %q", cred.CredentialSubject.NullifierBinding.Commitment)
	}
}

func TestIssuer_Issue_WithStatusList(t *testing.T) {
	t.Parallel()
	_, priv := deterministicKey(t, 0x77)
	issuer := NewIssuer("did:web:issuer.example", "key-1", priv, "https://issuer.example/status/1")

	issuedAt := time.Date(2026, 5, 24, 0, 0, 0, 0, time.UTC)
	anchor := "phone-liveness"
	idx := 42
	cred, err := issuer.Issue(
		"did:key:z6Mkholder",
		sampleMethods(t, issuedAt),
		&anchor,
		nil,
		issuedAt,
		issuedAt.Add(24*time.Hour),
		&idx,
	)
	if err != nil {
		t.Fatalf("Issue: %v", err)
	}
	if cred.CredentialStatus == nil {
		t.Fatal("expected CredentialStatus to be set")
	}
	if cred.CredentialStatus.StatusListIndex != 42 {
		t.Errorf("StatusListIndex = %d", cred.CredentialStatus.StatusListIndex)
	}
	if cred.CredentialStatus.Type != StatusList2021EntryType {
		t.Errorf("Type = %q", cred.CredentialStatus.Type)
	}
	if cred.CredentialStatus.StatusListCredential != "https://issuer.example/status/1" {
		t.Errorf("StatusListCredential = %q", cred.CredentialStatus.StatusListCredential)
	}
	if !strings.HasSuffix(cred.CredentialStatus.ID, "#42") {
		t.Errorf("CredentialStatus.ID should embed index, got %q", cred.CredentialStatus.ID)
	}
}

func TestIssuer_Issue_RejectsBadInputs(t *testing.T) {
	t.Parallel()
	_, priv := deterministicKey(t, 0x33)
	issuer := NewIssuer("did:web:issuer.example", "key-1", priv, "")
	now := time.Now().UTC()
	anchor := "phone-liveness"

	cases := []struct {
		name string
		fn   func() (types.PersonhoodCredential, error)
	}{
		{"empty holder", func() (types.PersonhoodCredential, error) {
			return issuer.Issue("", sampleMethods(t, now), &anchor, nil, now, now.Add(time.Hour), nil)
		}},
		{"no methods", func() (types.PersonhoodCredential, error) {
			return issuer.Issue("did:key:zHolder", nil, nil, nil, now, now.Add(time.Hour), nil)
		}},
		{"expiration not after issuance", func() (types.PersonhoodCredential, error) {
			return issuer.Issue("did:key:zHolder", sampleMethods(t, now), &anchor, nil, now, now, nil)
		}},
		{"anchor not in methods", func() (types.PersonhoodCredential, error) {
			bogus := "not-a-real-method"
			return issuer.Issue("did:key:zHolder", sampleMethods(t, now), &bogus, nil, now, now.Add(time.Hour), nil)
		}},
	}
	for _, tc := range cases {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			if _, err := tc.fn(); err == nil {
				t.Fatal("expected error, got nil")
			}
		})
	}
}

func TestIssuer_Issue_RejectsBadKey(t *testing.T) {
	t.Parallel()
	issuer := &Issuer{
		IssuerDID:          "did:web:bad",
		VerificationMethod: "did:web:bad#k",
		PrivateKey:         ed25519.PrivateKey([]byte{0x00, 0x01}),
	}
	now := time.Now().UTC()
	anchor := "phone-liveness"
	_, err := issuer.Issue("did:key:zHolder", sampleMethods(t, now), &anchor, nil, now, now.Add(time.Hour), nil)
	if err == nil {
		t.Fatal("expected error for malformed private key")
	}
}

func TestIssuer_Issue_DeterministicSignatureForFixedSeed(t *testing.T) {
	// Ed25519 is deterministic. Two issuances with identical inputs (including
	// timestamps and the same private key) MUST produce byte-identical proofs;
	// this anchors that property as a regression guard against accidentally
	// introducing randomness into canonicalization.
	t.Parallel()
	_, priv := deterministicKey(t, 0x55)
	issuer := NewIssuer("did:web:issuer.example", "key-1", priv, "")
	issuedAt := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	anchor := "phone-liveness"

	c1, err := issuer.Issue("did:key:zHolder", sampleMethods(t, issuedAt), &anchor, nil, issuedAt, issuedAt.Add(time.Hour), nil)
	if err != nil {
		t.Fatalf("Issue #1: %v", err)
	}
	c2, err := issuer.Issue("did:key:zHolder", sampleMethods(t, issuedAt), &anchor, nil, issuedAt, issuedAt.Add(time.Hour), nil)
	if err != nil {
		t.Fatalf("Issue #2: %v", err)
	}
	if c1.Proof.ProofValue != c2.Proof.ProofValue {
		t.Errorf("non-deterministic signatures:\n c1 = %s\n c2 = %s", c1.Proof.ProofValue, c2.Proof.ProofValue)
	}
}
