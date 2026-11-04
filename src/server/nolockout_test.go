package server

import (
	"context"
	"net/http"
	"testing"
	"time"

	"github.com/sagearbor/personhood/pkg/types"
	fuzzyextractorselfie "github.com/sagearbor/personhood/src/methods/fuzzy-extractor-selfie"
)

func TestConfig_NoFalseLockoutNeedsHolderRevocation(t *testing.T) {
	_, priv := newHolderKey(t)
	cfg := Config{Addr: ":0", PublicURL: "http://localhost:1", IssuerPrivateKey: priv, SessionTTL: time.Minute, NoFalseLockout: true}
	if err := cfg.Validate(); err == nil {
		t.Fatal("NoFalseLockout without HolderRevocation: want error")
	}
	cfg.HolderRevocation = true
	if err := cfg.Validate(); err != nil {
		t.Fatal(err)
	}
}

func TestLockoutConfigFromEnv(t *testing.T) {
	t.Setenv("RECOVERY_DELAY", "2m")
	t.Setenv("RECOVERY_VOUCHES", "3")
	t.Setenv("RECOVERY_DOCUMENT_METHODS", "document-chip, other")
	c, err := lockoutConfigFromEnv()
	if err != nil {
		t.Fatal(err)
	}
	c = c.withDefaults()
	if c.RecoveryDelay != 2*time.Minute || c.RecoveryVouches != 3 || len(c.RecoveryDocumentMethods) != 2 ||
		c.RecoveryCooldown != 30*24*time.Hour || c.FaceMatchExtraVouches != 2 || c.FaceMatchMaxOthers != 2 {
		t.Fatalf("config = %+v", c)
	}
	t.Setenv("RECOVERY_DELAY", "5s")
	if _, err := lockoutConfigFromEnv(); err == nil {
		t.Fatal("RECOVERY_DELAY under a minute: want error")
	}
}

func TestBuildDependencies_SelfieRelay(t *testing.T) {
	t.Setenv("SELFIE_ANCHOR", "1")
	t.Setenv("FIRESTORE_PROJECT_ID", "")
	t.Setenv("REDIS_URL", "")
	deps, err := BuildDependencies("http://example.invalid/v1/methods/email/verify", "")
	if err != nil {
		t.Fatal(err)
	}
	if deps.SelfieMatches == nil {
		t.Fatal("selfie registered without a match relay")
	}
	// Unwired, the relay is a no-op.
	if err := deps.SelfieMatches.OnMatch(context.Background(), "s", fuzzyextractorselfie.Commitment{}); err != nil {
		t.Fatal(err)
	}
}

func TestHolderLedger_UnbanAndBanInfo(t *testing.T) {
	for name, l := range map[string]HolderLedger{"memory": NewInMemoryHolderLedger(), "kv": newKVHolderLedger(newMemKV())} {
		t.Run(name, func(t *testing.T) {
			ctx := context.Background()
			if _, err := l.Ban(ctx, BanKindHolder, "did:key:z1", BanRecord{Reason: "r", EvidenceDigest: "d"}); err != nil {
				t.Fatal(err)
			}
			rec, found, err := l.BanInfo(ctx, BanKindHolder, "did:key:z1")
			if err != nil || !found || rec.EvidenceDigest != "d" {
				t.Fatalf("BanInfo = %+v %v %v", rec, found, err)
			}
			if err := l.Unban(ctx, BanKindHolder, "did:key:z1"); err != nil {
				t.Fatal(err)
			}
			if banned, _ := l.Banned(ctx, BanKindHolder, "did:key:z1"); banned {
				t.Fatal("still banned after Unban")
			}
			if err := l.Unban(ctx, BanKindHolder, "did:key:z1"); err != nil {
				t.Fatalf("Unban of nothing: %v", err)
			}
			if already, _ := l.Ban(ctx, BanKindHolder, "did:key:z1", BanRecord{Reason: "again"}); already {
				t.Fatal("re-ban after Unban reported already banned")
			}
		})
	}
}

func TestNoFalseLockout_Config(t *testing.T) {
	env := newLockoutEnv(t, nil)
	st, out := do(t, http.MethodGet, env.base+"/v1/config", nil, nil)
	if st != 200 || out["no_false_lockout"] != true || out["manual_review"] != true || out["recovery_delay_seconds"].(float64) != 72*3600 {
		t.Fatalf("config: %d %v", st, out)
	}
}

func TestNoFalseLockout_AdminRoutesNeedToken(t *testing.T) {
	env := newLockoutEnv(t, nil)
	for _, p := range []struct{ method, path string }{
		{http.MethodGet, "/v1/admin/reviews"},
		{http.MethodPost, "/v1/admin/reviews/x/decide"},
		{http.MethodPost, "/v1/admin/reinstate"},
	} {
		if st, _ := do(t, p.method, env.base+p.path, map[string]any{}, nil); st != 401 {
			t.Fatalf("%s %s without token: %d", p.method, p.path, st)
		}
	}
	if st, o := env.admin(t, http.MethodPost, "/v1/admin/reinstate", map[string]any{"holder_did": "did:key:zX"}); st != 400 {
		t.Fatalf("reinstate without reason: %d %v", st, o)
	}
}

func TestNoFalseLockout_ReviewsNeedAdminToken(t *testing.T) {
	env := newLockoutEnv(t, func(c *Config) { c.AdminToken = "" })
	if st, _ := do(t, http.MethodPost, env.base+"/v1/reviews", map[string]any{}, nil); st != 404 && st != 405 {
		t.Fatalf("reviews mounted without an operator: %d", st)
	}
	face := fuzzyextractorselfie.RandomTemplateForTesting()
	env.enrolled(t, "", face)
	e := env.person(t)
	if acts := faceMatchActions(env.selfie(t, e, face)); len(acts) != 2 {
		t.Fatalf("options without an operator = %v, want recover + other_anchor", acts)
	}
	if _, ok := env.srv.Registry().Get(OperatorReviewMethodID); ok {
		t.Fatal("operator-review registered without an admin token")
	}
}

func TestNoFalseLockout_DecideNeedsNoteAndOpenReview(t *testing.T) {
	env := newLockoutEnv(t, nil)
	p := env.person(t)
	_, out := do(t, http.MethodPost, env.base+"/v1/reviews", map[string]any{"session_id": p.session.SessionID, "kind": ReviewOther, "message": "x"}, nil)
	id := out["review_id"].(string)
	if st, _ := env.admin(t, http.MethodPost, "/v1/admin/reviews/"+id+"/decide", map[string]any{"approve": true}); st != 400 {
		t.Fatalf("decide without note: %d", st)
	}
	if st, _ := env.admin(t, http.MethodPost, "/v1/admin/reviews/"+id+"/decide", map[string]any{"approve": false, "note": "no evidence"}); st != 200 {
		t.Fatalf("deny: %d", st)
	}
	if st, o := env.admin(t, http.MethodPost, "/v1/admin/reviews/"+id+"/decide", map[string]any{"approve": true, "note": "changed mind"}); st != 409 {
		t.Fatalf("decide twice: %d %v", st, o)
	}
	if r := env.again(t, p).complete(t, env.base, OperatorReviewMethodID, nil); r.Result.Success {
		t.Fatal("denied review granted the anchor")
	}
	// A face_match review needs a session that matched.
	if st, o := do(t, http.MethodPost, env.base+"/v1/reviews", map[string]any{"session_id": p.session.SessionID, "kind": ReviewFaceMatch}, nil); st != 409 || apiErrCode(o) != "no_face_match" {
		t.Fatalf("face_match review without a match: %d %v", st, o)
	}
}

// An approved recovery review opens a recovery with the operator as the
// second factor; the cancel window still applies.
func TestNoFalseLockout_RecoveryReview(t *testing.T) {
	env := newLockoutEnv(t, nil)
	face := fuzzyextractorselfie.RandomTemplateForTesting()
	ann, aCred := env.enrolled(t, "", face)
	ann2 := env.person(t)
	env.selfie(t, ann2, fuzzyextractorselfie.NoisyTemplateForTesting(face, 10))
	_, out := do(t, http.MethodPost, env.base+"/v1/reviews", map[string]any{"session_id": ann2.session.SessionID, "kind": ReviewRecovery, "message": "lost my phone, no email"}, nil)
	st, dec := env.admin(t, http.MethodPost, "/v1/admin/reviews/"+out["review_id"].(string)+"/decide", map[string]any{"approve": true, "note": "video call with two neighbours"})
	if st != 200 {
		t.Fatalf("decide: %d %v", st, dec)
	}
	rec := dec["recovery"].(map[string]any)
	if rec["factors"].([]any)[0] != FactorOperatorReview || rec["status"] != RecoveryPending {
		t.Fatalf("recovery = %v", rec)
	}
	if _, p := do(t, http.MethodGet, env.base+"/v1/recovery/pending?holder_did="+string(ann.session.HolderDID), nil, nil); len(p["pending"].([]any)) != 1 {
		t.Fatalf("old key does not see the operator-opened recovery: %v", p)
	}
	env.clock.advance(73 * time.Hour)
	s := env.again(t, ann2)
	if st, o := do(t, http.MethodPost, env.base+"/v1/recovery/"+rec["recovery_id"].(string)+"/complete", map[string]any{"session_id": s.session.SessionID}, nil); st != 200 {
		t.Fatalf("complete: %d %v", st, o)
	}
	if c := env.mustIssue(t, s); nullifierOf(c) != nullifierOf(aCred) {
		t.Fatal("recovered identity has a different nullifier")
	}
	// A key retired by a recovery cannot be "reinstated" back into the
	// identity.
	if st, o := env.admin(t, http.MethodPost, "/v1/admin/reinstate", map[string]any{"holder_did": ann.session.HolderDID, "reason": "oops"}); st != 409 || apiErrCode(o) != "retired_by_recovery" {
		t.Fatalf("reinstate retired key: %d %v", st, o)
	}
}

// docTestMethod stands in for a document-chip anchor: a stable digest per
// document.
type docTestMethod struct{ digest string }

func (m docTestMethod) Metadata() types.MethodMetadata {
	return types.MethodMetadata{ID: "doc-test", Type: types.MethodTypeAnchor, Strength: 60, UXFriction: types.FrictionMed, FreshnessLifetime: time.Hour * 24, Version: "0"}
}
func (m docTestMethod) IsAvailableForUser(types.UserContext) (bool, string) { return true, "" }
func (m docTestMethod) HealthCheck(context.Context) error                   { return nil }
func (m docTestMethod) BeginCeremony(context.Context, types.CeremonyContext) (types.ChallengeData, error) {
	return types.ChallengeData{}, nil
}
func (m docTestMethod) CompleteCeremony(context.Context, types.CeremonyContext, types.ResponseData) (types.MethodResult, error) {
	return types.MethodResult{Success: true, MethodID: "doc-test", VerifiedAt: time.Now(), AttestationDigest: m.digest}, nil
}

func TestNoFalseLockout_DocumentFactor(t *testing.T) {
	env := newLockoutEnv(t, func(c *Config) { c.Lockout.RecoveryDocumentMethods = []string{"doc-test"} })
	if err := env.srv.Registry().Register(docTestMethod{digest: "passport-123"}); err != nil {
		t.Fatal(err)
	}
	face := fuzzyextractorselfie.RandomTemplateForTesting()
	ann := env.person(t)
	ann.complete(t, env.base, "doc-test", nil)
	env.selfie(t, ann, face)
	env.mustIssue(t, ann)

	ann2 := env.person(t)
	env.selfie(t, ann2, face)
	if st, o := env.startRecovery(t, ann2); st != 403 || !hasNextAction(o, "document") {
		t.Fatalf("without the document: %d %v", st, o)
	}
	ann2.complete(t, env.base, "doc-test", nil)
	if st, o := env.startRecovery(t, ann2); st != 200 || o["factors"].([]any)[0] != FactorDocument {
		t.Fatalf("with the document: %d %v", st, o)
	}
}
