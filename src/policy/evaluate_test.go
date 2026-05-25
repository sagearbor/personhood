package policy

import (
	"testing"
	"time"

	"github.com/sagearbor/personhood/pkg/types"
)

// fixedNow is a stable wall-clock time used across all evaluator tests so the
// behavior is purely deterministic.
var fixedNow = time.Date(2026, 5, 24, 12, 0, 0, 0, time.UTC)

// ptr is a tiny helper to take the address of a literal — Go's lack of
// addressable literals makes this ergonomic in test fixtures.
func ptr[T any](v T) *T { return &v }

// fakeDigest returns a deterministic 64-char hex placeholder for attestation
// digests in test fixtures. The evaluator doesn't inspect digest contents.
func fakeDigest(seed string) string {
	out := ""
	for len(out) < 64 {
		out += seed
	}
	return out[:64]
}

// baseCredential returns a structurally-valid credential with one anchor
// (phone-liveness, strength 75, verified 1h ago) and one supplementary method
// (email, strength 20, verified 1h ago). Tests mutate this fixture to
// construct specific scenarios.
func baseCredential() types.PersonhoodCredential {
	return types.PersonhoodCredential{
		Context: []string{
			types.W3CVCContext,
			types.PersonhoodVCContext,
		},
		ID:             "urn:uuid:cred-1",
		Type:           []string{"VerifiableCredential", "PersonhoodCredential"},
		Issuer:         "did:web:issuer.example",
		IssuanceDate:   fixedNow.Add(-30 * 24 * time.Hour),
		ExpirationDate: fixedNow.Add(335 * 24 * time.Hour),
		CredentialSubject: types.CredentialSubject{
			ID: "did:key:holder1",
			VerifiedMethods: []types.VerifiedMethod{
				{
					MethodID:          "phone-liveness",
					Strength:          75,
					VerifiedAt:        fixedNow.Add(-1 * time.Hour),
					FreshnessLifetime: 7 * 24 * time.Hour,
					AttestationDigest: fakeDigest("ab"),
				},
				{
					MethodID:          "email",
					Strength:          20,
					VerifiedAt:        fixedNow.Add(-1 * time.Hour),
					FreshnessLifetime: 30 * 24 * time.Hour,
					AttestationDigest: fakeDigest("cd"),
				},
			},
			AnchorMethodID: ptr("phone-liveness"),
			NullifierBinding: &types.NullifierBinding{
				Commitment: "deadbeef",
				Curve:      "bn254",
				Scheme:     "pedersen-v1",
			},
		},
	}
}

func basePolicy() types.Policy {
	return types.Policy{
		Version:        types.PolicyDSLVersion,
		PolicyID:       "test/eval/v1",
		Action:         "test.action",
		AnchorRequired: true,
	}
}

func TestEvaluate_OK(t *testing.T) {
	cred := baseCredential()
	pol := basePolicy()
	res := Evaluate(cred, pol, fixedNow)
	if !res.OK || res.Code != types.EvalOK {
		t.Fatalf("want OK, got code=%s human=%q details=%v", res.Code, res.Human, res.Details)
	}
	if res.DerivedNullifier != nil {
		t.Fatalf("nullifier should be nil when policy does not require it")
	}
}

func TestEvaluate_OKWithNullifier(t *testing.T) {
	cred := baseCredential()
	pol := basePolicy()
	pol.NullifierRequired = true
	pol.NullifierContextTag = "ubi_2026_q2"
	res := Evaluate(cred, pol, fixedNow)
	if !res.OK || res.Code != types.EvalOK {
		t.Fatalf("want OK, got code=%s human=%q", res.Code, res.Human)
	}
	if res.DerivedNullifier == nil || *res.DerivedNullifier == "" {
		t.Fatal("DerivedNullifier missing")
	}
	if len(*res.DerivedNullifier) != 64 {
		t.Fatalf("DerivedNullifier should be 64-char hex, got %q", *res.DerivedNullifier)
	}
}

func TestEvaluate_FreshAnchorSignal(t *testing.T) {
	cred := baseCredential()
	pol := basePolicy()
	pol.RequireFreshAnchorProof = true
	res := Evaluate(cred, pol, fixedNow)
	if !res.OK {
		t.Fatalf("expected OK with fresh-anchor signal, got %s: %s", res.Code, res.Human)
	}
	if got, _ := res.Details["fresh_anchor_required"].(bool); !got {
		t.Fatalf("fresh_anchor_required flag missing from details: %v", res.Details)
	}
}

func TestEvaluate_SignatureInvalid(t *testing.T) {
	cred := baseCredential()
	cred.Context = nil // structural failure
	pol := basePolicy()
	res := Evaluate(cred, pol, fixedNow)
	if res.OK || res.Code != types.EvalSignatureInvalid {
		t.Fatalf("want EvalSignatureInvalid, got code=%s ok=%v", res.Code, res.OK)
	}
}

func TestEvaluate_VCExpiredByExpiration(t *testing.T) {
	cred := baseCredential()
	cred.ExpirationDate = fixedNow.Add(-1 * time.Hour)
	cred.IssuanceDate = fixedNow.Add(-365 * 24 * time.Hour)
	pol := basePolicy()
	res := Evaluate(cred, pol, fixedNow)
	if res.OK || res.Code != types.EvalVCExpired {
		t.Fatalf("want EvalVCExpired, got code=%s", res.Code)
	}
}

func TestEvaluate_VCExpiredByMaxAge(t *testing.T) {
	cred := baseCredential()
	cred.IssuanceDate = fixedNow.Add(-365 * 24 * time.Hour)
	pol := basePolicy()
	pol.MaxCredentialAgeSeconds = 30 * 24 * 60 * 60 // 30 days
	res := Evaluate(cred, pol, fixedNow)
	if res.OK || res.Code != types.EvalVCExpired {
		t.Fatalf("want EvalVCExpired, got code=%s", res.Code)
	}
}

func TestEvaluate_AnchorMissing(t *testing.T) {
	cred := baseCredential()
	cred.CredentialSubject.AnchorMethodID = nil
	// drop the anchor method so the credential remains structurally valid.
	cred.CredentialSubject.VerifiedMethods = []types.VerifiedMethod{
		{
			MethodID:          "email",
			Strength:          20,
			VerifiedAt:        fixedNow.Add(-1 * time.Hour),
			FreshnessLifetime: 30 * 24 * time.Hour,
			AttestationDigest: fakeDigest("cd"),
		},
	}
	pol := basePolicy()
	res := Evaluate(cred, pol, fixedNow)
	if res.OK || res.Code != types.EvalAnchorMissing {
		t.Fatalf("want EvalAnchorMissing, got code=%s", res.Code)
	}
}

// TestEvaluate_StackingWithoutAnchor verifies the key anti-pattern: piling on
// weak supplementary methods cannot satisfy anchor_required.
func TestEvaluate_StackingWithoutAnchor(t *testing.T) {
	cred := baseCredential()
	cred.CredentialSubject.AnchorMethodID = nil
	cred.CredentialSubject.VerifiedMethods = []types.VerifiedMethod{
		{MethodID: "email", Strength: 20, VerifiedAt: fixedNow.Add(-1 * time.Hour), FreshnessLifetime: 30 * 24 * time.Hour, AttestationDigest: fakeDigest("aa")},
		{MethodID: "sms", Strength: 20, VerifiedAt: fixedNow.Add(-1 * time.Hour), FreshnessLifetime: 30 * 24 * time.Hour, AttestationDigest: fakeDigest("bb")},
		{MethodID: "social-a", Strength: 20, VerifiedAt: fixedNow.Add(-1 * time.Hour), FreshnessLifetime: 30 * 24 * time.Hour, AttestationDigest: fakeDigest("cc")},
		{MethodID: "social-b", Strength: 20, VerifiedAt: fixedNow.Add(-1 * time.Hour), FreshnessLifetime: 30 * 24 * time.Hour, AttestationDigest: fakeDigest("dd")},
		{MethodID: "social-c", Strength: 20, VerifiedAt: fixedNow.Add(-1 * time.Hour), FreshnessLifetime: 30 * 24 * time.Hour, AttestationDigest: fakeDigest("ee")},
	}
	pol := basePolicy() // anchor_required: true
	pol.MinSupplementaryPoints = 50
	res := Evaluate(cred, pol, fixedNow)
	if res.OK {
		t.Fatalf("stacking weak methods should NOT satisfy anchor-required policy")
	}
	if res.Code != types.EvalAnchorMissing {
		t.Fatalf("want EvalAnchorMissing for the anti-pattern, got %s", res.Code)
	}
}

func TestEvaluate_AnchorMethodExpiredByPolicy(t *testing.T) {
	cred := baseCredential()
	// anchor verified 2 days ago
	cred.CredentialSubject.VerifiedMethods[0].VerifiedAt = fixedNow.Add(-48 * time.Hour)
	pol := basePolicy()
	pol.MaxAnchorMethodAgeSeconds = 24 * 60 * 60 // 24h
	res := Evaluate(cred, pol, fixedNow)
	if res.OK || res.Code != types.EvalAnchorMethodExpired {
		t.Fatalf("want EvalAnchorMethodExpired, got code=%s", res.Code)
	}
}

func TestEvaluate_AnchorMethodExpiredByMethodLifetime(t *testing.T) {
	cred := baseCredential()
	// FreshnessLifetime = 1h, verified 2h ago
	cred.CredentialSubject.VerifiedMethods[0].FreshnessLifetime = 1 * time.Hour
	cred.CredentialSubject.VerifiedMethods[0].VerifiedAt = fixedNow.Add(-2 * time.Hour)
	pol := basePolicy() // no MaxAnchorMethodAgeSeconds override
	res := Evaluate(cred, pol, fixedNow)
	if res.OK || res.Code != types.EvalAnchorMethodExpired {
		t.Fatalf("want EvalAnchorMethodExpired, got code=%s", res.Code)
	}
}

func TestEvaluate_MethodBlocked(t *testing.T) {
	cred := baseCredential()
	pol := basePolicy()
	pol.BlockedMethods = []string{"email"}
	res := Evaluate(cred, pol, fixedNow)
	if res.OK || res.Code != types.EvalMethodBlocked {
		t.Fatalf("want EvalMethodBlocked, got code=%s", res.Code)
	}
}

func TestEvaluate_MethodNotAllowed(t *testing.T) {
	cred := baseCredential()
	pol := basePolicy()
	pol.AllowedMethods = []string{"phone-liveness"} // omits "email"
	res := Evaluate(cred, pol, fixedNow)
	if res.OK || res.Code != types.EvalMethodNotAllowed {
		t.Fatalf("want EvalMethodNotAllowed, got code=%s", res.Code)
	}
}

// TestEvaluate_BlockedOverridesAllowed checks that if a method appears in both
// allowed_methods AND blocked_methods, the block wins.
func TestEvaluate_BlockedOverridesAllowed(t *testing.T) {
	cred := baseCredential()
	pol := basePolicy()
	pol.AllowedMethods = []string{"phone-liveness", "email"}
	pol.BlockedMethods = []string{"email"}
	res := Evaluate(cred, pol, fixedNow)
	if res.OK || res.Code != types.EvalMethodBlocked {
		t.Fatalf("blocked should win over allowed; got code=%s", res.Code)
	}
}

func TestEvaluate_MethodStrengthInsufficient(t *testing.T) {
	cred := baseCredential()
	pol := basePolicy()
	pol.MinStrengthPerMethod = map[string]int{"email": 30}
	res := Evaluate(cred, pol, fixedNow)
	if res.OK || res.Code != types.EvalMethodStrengthInsufficient {
		t.Fatalf("want EvalMethodStrengthInsufficient, got code=%s", res.Code)
	}
}

func TestEvaluate_InsufficientSupplementary(t *testing.T) {
	cred := baseCredential() // email strength 20
	pol := basePolicy()
	pol.MinSupplementaryPoints = 50
	res := Evaluate(cred, pol, fixedNow)
	if res.OK || res.Code != types.EvalInsufficientSupplementary {
		t.Fatalf("want EvalInsufficientSupplementary, got code=%s", res.Code)
	}
	have, _ := res.Details["have_points"].(int)
	need, _ := res.Details["need_points"].(int)
	if have != 20 || need != 50 {
		t.Fatalf("details mismatch: have=%d need=%d", have, need)
	}
}

// TestEvaluate_ExpiredSupplementaryDropped checks that a supplementary method
// past its FreshnessLifetime is not counted toward the supplementary total.
func TestEvaluate_ExpiredSupplementaryDropped(t *testing.T) {
	cred := baseCredential()
	cred.CredentialSubject.VerifiedMethods[1].VerifiedAt = fixedNow.Add(-365 * 24 * time.Hour) // way past lifetime
	pol := basePolicy()
	pol.MinSupplementaryPoints = 1 // even 1 point fails because email is expired
	res := Evaluate(cred, pol, fixedNow)
	if res.OK || res.Code != types.EvalInsufficientSupplementary {
		t.Fatalf("want EvalInsufficientSupplementary (expired supp ignored), got %s", res.Code)
	}
}

func TestEvaluate_NullifierMissing(t *testing.T) {
	cred := baseCredential()
	cred.CredentialSubject.NullifierBinding = nil
	pol := basePolicy()
	pol.NullifierRequired = true
	pol.NullifierContextTag = "ubi_2026_q2"
	res := Evaluate(cred, pol, fixedNow)
	if res.OK || res.Code != types.EvalNullifierMissing {
		t.Fatalf("want EvalNullifierMissing, got code=%s", res.Code)
	}
}

// TestEvaluate_NullifierBindingMalformed checks that an unpopulated binding
// surfaces as EvalNullifierMissing rather than crashing.
func TestEvaluate_NullifierBindingMalformed(t *testing.T) {
	cred := baseCredential()
	cred.CredentialSubject.NullifierBinding = &types.NullifierBinding{
		Commitment: "", Curve: "bn254", Scheme: "pedersen-v1",
	}
	pol := basePolicy()
	pol.NullifierRequired = true
	pol.NullifierContextTag = "ubi_2026_q2"
	res := Evaluate(cred, pol, fixedNow)
	if res.OK || res.Code != types.EvalNullifierMissing {
		t.Fatalf("want EvalNullifierMissing for malformed binding, got %s", res.Code)
	}
}
