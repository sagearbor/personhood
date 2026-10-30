package pq

import (
	"context"
	"encoding/json"
	"errors"
	"testing"
	"time"

	"crypto/ed25519"

	"github.com/cloudflare/circl/sign/mldsa/mldsa65"
	"github.com/sagearbor/personhood/pkg/types"
	"github.com/sagearbor/personhood/src/credential"
)

// deterministicKey returns an Ed25519 key pair from a fixed seed byte.
func deterministicKey(tb testing.TB, seed byte) (ed25519.PublicKey, ed25519.PrivateKey) {
	tb.Helper()
	s := make([]byte, ed25519.SeedSize)
	for i := range s {
		s[i] = seed
	}
	priv := ed25519.NewKeyFromSeed(s)
	return priv.Public().(ed25519.PublicKey), priv
}

func sampleMethods(tb testing.TB, at time.Time) []types.VerifiedMethod {
	tb.Helper()
	return []types.VerifiedMethod{{
		MethodID:          "email",
		Strength:          20,
		VerifiedAt:        at,
		FreshnessLifetime: 30 * 24 * time.Hour,
		AttestationDigest: "feedface00",
	}}
}

func newIssuer(tb testing.TB, withPQ bool) *credential.Issuer {
	tb.Helper()
	_, priv := deterministicKey(tb, 0x42)
	iss := credential.NewIssuer(pqTestDID, "key-1", priv, "")
	if withPQ {
		_, pqPriv, err := KeyFromSeed(testSeed())
		if err != nil {
			tb.Fatal(err)
		}
		iss.PQ = Signer{Key: pqPriv, VerificationMethod: string(pqTestDID) + "#key-pq-1"}
	}
	return iss
}

func testSeed() []byte {
	seed := make([]byte, mldsa65.SeedSize)
	for i := range seed {
		seed[i] = 0x24
	}
	return seed
}

const pqTestDID = types.DID("did:web:issuer.example")

// newPQFixture issues a credential signed with both Ed25519 and ML-DSA-65
// and returns it with the public keys.
func newPQFixture(t testing.TB) (types.PersonhoodCredential, credential.MapResolver, MapResolver) {
	t.Helper()
	pub, _ := deterministicKey(t, 0x42)
	pqPub, _, err := KeyFromSeed(testSeed())
	if err != nil {
		t.Fatal(err)
	}
	issuedAt := time.Date(2026, 10, 29, 12, 0, 0, 0, time.UTC)
	cred, err := newIssuer(t, true).Issue("did:key:z6Mkholder", sampleMethods(t, issuedAt), nil, nil,
		issuedAt, issuedAt.Add(365*24*time.Hour), nil)
	if err != nil {
		t.Fatal(err)
	}
	return cred, credential.MapResolver{pqTestDID: pub}, MapResolver{pqTestDID: pqPub}
}

// hybridVerifier verifies Ed25519 and, when present, ML-DSA.
func hybridVerifier(ed credential.MapResolver, pq MapResolver, require bool) *credential.Verifier {
	v := credential.NewVerifier(ed)
	v.PQ, v.RequirePQ = Verifier{Resolver: pq}, require
	return v
}

func TestPQ_IssueAddsProofAndBothVerify(t *testing.T) {
	cred, ed, pq := newPQFixture(t)
	p := cred.Proof.PQProof
	if p == nil || p.Type != ProofType || p.Cryptosuite != Cryptosuite || p.VerificationMethod != string(pqTestDID)+"#key-pq-1" {
		t.Fatalf("PQProof = %+v", p)
	}
	if err := hybridVerifier(ed, pq, true).Verify(context.Background(), cred); err != nil {
		t.Fatalf("Verify with RequirePQ: %v", err)
	}
}

func TestPQ_TamperedFailsBothSignatures(t *testing.T) {
	cred, ed, pq := newPQFixture(t)
	cred.CredentialSubject.VerifiedMethods[0].Strength = 100

	v := hybridVerifier(ed, pq, false)
	if err := v.Verify(context.Background(), cred); !errors.Is(err, credential.ErrSignatureInvalid) {
		t.Errorf("Ed25519 on tampered credential: err = %v, want ErrSignatureInvalid", err)
	}
	// The ML-DSA signature must fail on its own too, not just because the
	// Ed25519 check runs first.
	input, err := credential.SigningInput(cred)
	if err != nil {
		t.Fatal(err)
	}
	if err := (Verifier{Resolver: pq}).VerifyPQ(context.Background(), cred.Issuer, cred.Proof.PQProof, input); !errors.Is(err, credential.ErrPQSignatureInvalid) {
		t.Errorf("ML-DSA on tampered credential: err = %v, want ErrPQSignatureInvalid", err)
	}
}

func TestPQ_TamperedPQProofValueFails(t *testing.T) {
	cred, ed, pq := newPQFixture(t)
	b := []byte(cred.Proof.PQProof.ProofValue)
	if b[10] == 'A' {
		b[10] = 'B'
	} else {
		b[10] = 'A'
	}
	cred.Proof.PQProof.ProofValue = string(b)
	if err := hybridVerifier(ed, pq, false).Verify(context.Background(), cred); !errors.Is(err, credential.ErrPQSignatureInvalid) {
		t.Errorf("err = %v, want ErrPQSignatureInvalid", err)
	}
}

// A verifier that knows nothing about PQ (today's OpenLine build, or any
// verifier that unmarshals into a type without PQProof) still verifies the
// Ed25519 proof of a hybrid credential.
func TestPQ_OldVerifierStillVerifiesEd25519(t *testing.T) {
	cred, ed, _ := newPQFixture(t)
	if err := credential.NewVerifier(ed).Verify(context.Background(), cred); err != nil {
		t.Fatalf("Verify without PQResolver: %v", err)
	}
	// Simulate a verifier whose Proof type predates pqProof: drop it on the
	// wire and verify what is left.
	raw, err := json.Marshal(cred)
	if err != nil {
		t.Fatal(err)
	}
	var m map[string]any
	if err := json.Unmarshal(raw, &m); err != nil {
		t.Fatal(err)
	}
	delete(m["proof"].(map[string]any), "pqProof")
	stripped, _ := json.Marshal(m)
	var old types.PersonhoodCredential
	if err := json.Unmarshal(stripped, &old); err != nil {
		t.Fatal(err)
	}
	if err := credential.NewVerifier(ed).Verify(context.Background(), old); err != nil {
		t.Fatalf("Verify with pqProof dropped: %v", err)
	}
}

func TestPQ_RequirePQRejectsEd25519Only(t *testing.T) {
	now := time.Now()
	cred, err := newIssuer(t, false).Issue("did:key:z6Mkholder", sampleMethods(t, now), nil, nil, now, now.Add(time.Hour), nil)
	if err != nil {
		t.Fatal(err)
	}
	if cred.Proof.PQProof != nil {
		t.Fatal("issuer without a PQ signer added a PQProof")
	}
	_, ed, pq := newPQFixture(t)
	if err := hybridVerifier(ed, pq, true).Verify(context.Background(), cred); !errors.Is(err, credential.ErrPQProofMissing) {
		t.Errorf("err = %v, want ErrPQProofMissing", err)
	}
	// Without RequirePQ the same credential is fine (migration period).
	if err := hybridVerifier(ed, pq, false).Verify(context.Background(), cred); err != nil {
		t.Errorf("without RequirePQ: %v", err)
	}
	v := credential.NewVerifier(ed)
	v.RequirePQ = true
	if err := v.Verify(context.Background(), cred); err == nil {
		t.Error("RequirePQ without a PQ verifier accepted the credential")
	}
}

func TestPQ_UnknownCryptosuiteRejected(t *testing.T) {
	cred, ed, pq := newPQFixture(t)
	cred.Proof.PQProof.Cryptosuite = "mldsa44-jcs-personhood-v1"
	if err := hybridVerifier(ed, pq, false).Verify(context.Background(), cred); !errors.Is(err, credential.ErrProofUnsupported) {
		t.Errorf("err = %v, want ErrProofUnsupported", err)
	}
}

func TestPQKeyFromSeed_RejectsWrongSize(t *testing.T) {
	if _, _, err := KeyFromSeed(make([]byte, 31)); err == nil {
		t.Error("31-byte seed accepted")
	}
}

// Sizes, for docs/POST_QUANTUM.md: go test -run TestPQ_Sizes -v
func TestPQ_Sizes(t *testing.T) {
	cred, _, _ := newPQFixture(t)
	hybrid, _ := json.Marshal(cred)
	cred.Proof.PQProof = nil
	edOnly, _ := json.Marshal(cred)
	t.Logf("ML-DSA-65: public key %d B, signature %d B; credential JSON %d B Ed25519-only, %d B hybrid",
		mldsa65.PublicKeySize, mldsa65.SignatureSize, len(edOnly), len(hybrid))
}

func benchIssue(b *testing.B, withPQ bool) {
	issuer := newIssuer(b, withPQ)
	now := time.Now()
	methods := sampleMethods(b, now)
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		if _, err := issuer.Issue("did:key:z6Mkholder", methods, nil, nil, now, now.Add(time.Hour), nil); err != nil {
			b.Fatal(err)
		}
	}
}

func BenchmarkIssue_Ed25519Only(b *testing.B) { benchIssue(b, false) }
func BenchmarkIssue_Hybrid(b *testing.B)      { benchIssue(b, true) }

func benchVerify(b *testing.B, withPQ bool) {
	cred, ed, pq := newPQFixture(b)
	v := credential.NewVerifier(ed)
	if withPQ {
		v = hybridVerifier(ed, pq, true)
	}
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		if err := v.Verify(context.Background(), cred); err != nil {
			b.Fatal(err)
		}
	}
}

func BenchmarkVerify_Ed25519Only(b *testing.B) { benchVerify(b, false) }
func BenchmarkVerify_Hybrid(b *testing.B)      { benchVerify(b, true) }

// Raw primitive cost, without JSON canonicalization.
func BenchmarkMLDSA65_Sign(b *testing.B) {
	_, priv, _ := KeyFromSeed(testSeed())
	msg := make([]byte, 1000)
	sig := make([]byte, mldsa65.SignatureSize)
	for i := 0; i < b.N; i++ {
		_ = mldsa65.SignTo(priv, msg, signingContext, true, sig)
	}
}

func BenchmarkMLDSA65_Verify(b *testing.B) {
	pub, priv, _ := KeyFromSeed(testSeed())
	msg := make([]byte, 1000)
	sig := make([]byte, mldsa65.SignatureSize)
	_ = mldsa65.SignTo(priv, msg, signingContext, true, sig)
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		mldsa65.Verify(pub, msg, signingContext, sig)
	}
}

func BenchmarkEd25519_Sign(b *testing.B) {
	_, priv := deterministicKey(b, 0x42)
	msg := make([]byte, 1000)
	for i := 0; i < b.N; i++ {
		ed25519.Sign(priv, msg)
	}
}

func BenchmarkEd25519_Verify(b *testing.B) {
	pub, priv := deterministicKey(b, 0x42)
	msg := make([]byte, 1000)
	sig := ed25519.Sign(priv, msg)
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		ed25519.Verify(pub, msg, sig)
	}
}
