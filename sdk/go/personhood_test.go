package personhood

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/sagearbor/personhood/pkg/types"
	"github.com/sagearbor/personhood/src/credential"
)

const (
	testIssuerDID = types.DID("did:web:issuer.example")
	testHolderDID = types.DID("did:web:holder.example")
	anchorID      = "government-id-liveness"
	suppID        = "email"
)

// fixedNow is the verification clock used across tests for determinism.
var fixedNow = time.Date(2026, 6, 15, 12, 0, 0, 0, time.UTC)

// mintCredential issues a signed credential and returns it alongside the
// issuer public key and (optionally) a configured issuer for status-list use.
func mintCredential(t *testing.T, statusListURL string, statusIdx *int, withNullifier bool) (types.PersonhoodCredential, ed25519.PublicKey) {
	t.Helper()
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}
	iss := credential.NewIssuer(testIssuerDID, "key-1", priv, statusListURL)

	methods := []types.VerifiedMethod{
		{
			MethodID:          anchorID,
			Strength:          90,
			VerifiedAt:        fixedNow.Add(-1 * time.Hour),
			FreshnessLifetime: 90 * 24 * time.Hour,
			AttestationDigest: "deadbeef",
		},
		{
			MethodID:          suppID,
			Strength:          12,
			VerifiedAt:        fixedNow.Add(-2 * time.Hour),
			FreshnessLifetime: 30 * 24 * time.Hour,
			AttestationDigest: "cafebabe",
		},
	}
	anchor := anchorID

	var binding *types.NullifierBinding
	if withNullifier {
		binding = &types.NullifierBinding{
			Commitment: "0a1b2c3d4e5f",
			Curve:      "bn254",
			Scheme:     "pedersen-v1",
		}
	}

	cred, err := iss.Issue(
		testHolderDID, methods, &anchor, binding,
		fixedNow.Add(-1*time.Hour), fixedNow.Add(24*time.Hour), statusIdx,
	)
	if err != nil {
		t.Fatalf("issue credential: %v", err)
	}
	return cred, pub
}

func votePolicy(t *testing.T) types.Policy {
	t.Helper()
	return types.Policy{
		Version:             "1.0",
		PolicyID:            "openline/suffrage/vote/v1",
		Action:              "vote.cast",
		AnchorRequired:      true,
		NullifierRequired:   true,
		NullifierContextTag: "openline/suffrage/vote/election-1",
	}
}

func TestVerify_OK_WithNullifier(t *testing.T) {
	cred, pub := mintCredential(t, "", nil, true)
	v := NewVerifier(
		TrustedIssuers(map[types.DID]ed25519.PublicKey{testIssuerDID: pub}),
		WithClock(func() time.Time { return fixedNow }),
	)
	res, err := v.Verify(context.Background(), cred, votePolicy(t))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !res.OK || res.Code != types.EvalOK {
		t.Fatalf("want OK, got OK=%v code=%s human=%q", res.OK, res.Code, res.Human)
	}
	if res.Nullifier == "" {
		t.Fatal("expected a derived nullifier when policy.NullifierRequired is true")
	}
}

func TestVerify_UnknownIssuer(t *testing.T) {
	cred, _ := mintCredential(t, "", nil, true)
	// Empty trusted-issuer set: the issuer DID resolves to no key.
	v := NewVerifier(
		TrustedIssuers(map[types.DID]ed25519.PublicKey{}),
		WithClock(func() time.Time { return fixedNow }),
	)
	res, err := v.Verify(context.Background(), cred, votePolicy(t))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if res.OK || res.Code != types.EvalUnknownIssuer {
		t.Fatalf("want EvalUnknownIssuer, got OK=%v code=%s", res.OK, res.Code)
	}
}

func TestVerify_TamperedSignature(t *testing.T) {
	cred, pub := mintCredential(t, "", nil, true)
	// Tamper with the subject after signing: signature must no longer verify.
	cred.CredentialSubject.ID = types.DID("did:web:attacker.example")
	v := NewVerifier(
		TrustedIssuers(map[types.DID]ed25519.PublicKey{testIssuerDID: pub}),
		WithClock(func() time.Time { return fixedNow }),
	)
	res, err := v.Verify(context.Background(), cred, votePolicy(t))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if res.OK || res.Code != types.EvalSignatureInvalid {
		t.Fatalf("want EvalSignatureInvalid, got OK=%v code=%s", res.OK, res.Code)
	}
}

func TestVerify_AnchorMissing(t *testing.T) {
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}
	iss := credential.NewIssuer(testIssuerDID, "key-1", priv, "")
	// Supplementary-only credential: no anchor.
	cred, err := iss.Issue(
		testHolderDID,
		[]types.VerifiedMethod{{
			MethodID:          suppID,
			Strength:          12,
			VerifiedAt:        fixedNow.Add(-2 * time.Hour),
			FreshnessLifetime: 30 * 24 * time.Hour,
			AttestationDigest: "cafebabe",
		}},
		nil, nil,
		fixedNow.Add(-1*time.Hour), fixedNow.Add(24*time.Hour), nil,
	)
	if err != nil {
		t.Fatalf("issue: %v", err)
	}
	v := NewVerifier(
		TrustedIssuers(map[types.DID]ed25519.PublicKey{testIssuerDID: pub}),
		WithClock(func() time.Time { return fixedNow }),
	)
	res, err := v.Verify(context.Background(), cred, votePolicy(t))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if res.OK || res.Code != types.EvalAnchorMissing {
		t.Fatalf("want EvalAnchorMissing, got OK=%v code=%s", res.OK, res.Code)
	}
}

func TestVerify_Revoked(t *testing.T) {
	// Stand up a Status List 2021 endpoint with bit 7 set (revoked).
	const idx = 7
	bs := credential.NewBitString(1024)
	if err := bs.Set(idx); err != nil {
		t.Fatalf("set bit: %v", err)
	}
	encoded, err := bs.Encode()
	if err != nil {
		t.Fatalf("encode: %v", err)
	}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_ = json.NewEncoder(w).Encode(map[string]any{
			"credentialSubject": map[string]any{
				"type":          "StatusList2021",
				"statusPurpose": "revocation",
				"encodedList":   encoded,
			},
		})
	}))
	defer srv.Close()

	statusIdx := idx
	cred, pub := mintCredential(t, srv.URL, &statusIdx, true)

	v := NewVerifier(
		TrustedIssuers(map[types.DID]ed25519.PublicKey{testIssuerDID: pub}),
		WithClock(func() time.Time { return fixedNow }),
		WithHTTPClient(srv.Client()),
	)
	res, err := v.Verify(context.Background(), cred, votePolicy(t))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if res.OK || res.Code != types.EvalRevoked {
		t.Fatalf("want EvalRevoked, got OK=%v code=%s", res.OK, res.Code)
	}
}

func TestVerify_NotRevoked_WhenBitClear(t *testing.T) {
	const idx = 7
	bs := credential.NewBitString(1024) // bit clear → not revoked
	encoded, err := bs.Encode()
	if err != nil {
		t.Fatalf("encode: %v", err)
	}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_ = json.NewEncoder(w).Encode(map[string]any{
			"credentialSubject": map[string]any{"encodedList": encoded},
		})
	}))
	defer srv.Close()

	statusIdx := idx
	cred, pub := mintCredential(t, srv.URL, &statusIdx, true)
	v := NewVerifier(
		TrustedIssuers(map[types.DID]ed25519.PublicKey{testIssuerDID: pub}),
		WithClock(func() time.Time { return fixedNow }),
		WithHTTPClient(srv.Client()),
	)
	res, err := v.Verify(context.Background(), cred, votePolicy(t))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !res.OK {
		t.Fatalf("want OK (bit clear), got code=%s human=%q", res.Code, res.Human)
	}
}

func TestVerify_ResolverRequired(t *testing.T) {
	v := NewVerifier(nil)
	if _, err := v.Verify(context.Background(), types.PersonhoodCredential{}, types.Policy{}); err != ErrResolverRequired {
		t.Fatalf("want ErrResolverRequired, got %v", err)
	}
}

func TestParseHelpers(t *testing.T) {
	yaml := []byte("version: \"1.0\"\npolicy_id: p\naction: a\nanchor_required: true\n")
	if _, err := ParsePolicyYAML(yaml); err != nil {
		t.Fatalf("ParsePolicyYAML: %v", err)
	}
	jsonPol := []byte(`{"version":"1.0","policy_id":"p","action":"a","anchor_required":true}`)
	if _, err := ParsePolicyJSON(jsonPol); err != nil {
		t.Fatalf("ParsePolicyJSON: %v", err)
	}
	cred, _ := mintCredential(t, "", nil, true)
	raw, err := json.Marshal(cred)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	if _, err := ParseCredential(raw); err != nil {
		t.Fatalf("ParseCredential: %v", err)
	}
}
