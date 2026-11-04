package server

// The owner's edge-case list (docs/EDGE_CASES.md), as a table. Each row is
// one person in one situation, and asserts the outcome the owner asked for:
// an honest person always ends with a credential or a named next step, and
// a look-alike never ends with someone else's identity.
//
// Run just this table with: go test -run TestEdgeCases -v ./src/server

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/base64"
	"net/http"
	"sync"
	"testing"
	"time"

	"github.com/sagearbor/personhood/pkg/types"
	"github.com/sagearbor/personhood/src/credential"
	fuzzyextractorselfie "github.com/sagearbor/personhood/src/methods/fuzzy-extractor-selfie"
	socialvouching "github.com/sagearbor/personhood/src/methods/social-vouching"
)

type edgeCase struct {
	id     string // stable id, referenced from docs/EDGE_CASES.md
	row    string // the owner's row
	expect string // the outcome asserted
	run    func(t *testing.T)
}

func TestEdgeCases(t *testing.T) {
	cases := []edgeCase{
		{"identical_twin", "Identical twins", "second twin is routed (not refused), declines the match, gets their own credential via in-person vouching with K+2 vouchers; the first twin is untouched and the second cannot recover the first's identity", edgeIdenticalTwin},
		{"twin_cap", "Identical twins (abuse bound)", "only FaceMatchMaxOthers holders per face get through a declined match; the next is pointed at manual review", edgeTwinCap},
		{"lookalike_cannot_take_over", "Strangers who look alike / look-alike tries to take over", "a face match alone cannot start a recovery: 403 recovery_factor_missing with next steps; the enrolled person keeps their credential", edgeLookalikeNoTakeover},
		{"lookalike_manual_review", "Strangers who look alike", "manual review approves; the look-alike gets an operator-review anchored credential with their own nullifier", edgeLookalikeReview},
		{"lost_phone_recovery", "Lost, stolen or broken phone", "face + original email starts a recovery; it cannot finish before the 72 h window; after it, the new key gets the SAME nullifier and the old key's credential is revoked and the key barred", edgeLostPhone},
		{"stolen_phone_old_key_cancels", "Lost, stolen or broken phone (thief tries)", "the old key sees the pending recovery and cancels it; completion is then refused", edgeOldKeyCancels},
		{"recovery_by_vouchers", "Lost phone, no email", "two of the person's old vouchers re-vouch in person for the new key: recovery factor 'vouchers'", edgeRecoveryVouchers},
		{"recovery_rate_limits", "Lost phone (abuse bound)", "no second recovery within the cooldown, and after 3 cancelled attempts only manual review; both refusals name the review path", edgeRecoveryLimits},
		{"reenroll_same_key", "Lost credential, kept key", "same holder key + same face is re-issued at once with the same nullifier", edgeReenrollSameKey},
		{"shared_family_phone", "Shared family phone", "5 people, 1 phone, 1 shared inbox, 5 faces: 5 credentials with 5 distinct nullifiers; the per-IP limiter only delays the 5th", edgeSharedFamilyPhone},
		{"old_phone_no_attestation", "Very old phone (Android 6, no attestation)", "no device attestation is 'absent, not failed': the selfie anchor still issues", edgeOldPhone},
		{"wallet_double_sign_bug", "Wallet bug signs one payment twice", "equivocation bans and strikes the voucher; the refusal names the appeal path; a signed appeal approved by the operator reinstates the person, restores the voucher, and the same proof cannot ban again", edgeWalletDoubleSign},
		{"vouch_over_video", "Vouch over a video call", "a vouch from two different networks is accepted and recorded with same_network=false (relayable, as documented)", edgeVouchOverVideo},
		{"no_selfie_possible", "Blind / palsy / face covering / no camera", "without a selfie, manual review leads to an operator-review anchored credential", edgeNoSelfie},
		{"same_email_twice", "Same email many times", "one inbox is one person: the second enrollment gets the same nullifier", edgeSameEmail},
		{"flag_off_unchanged", "(compatibility)", "with NO_FALSE_LOCKOUT off a duplicate face is refused exactly as before and the new routes are absent", edgeFlagOff},
	}
	for _, c := range cases {
		c := c
		t.Run(c.id, func(t *testing.T) {
			t.Logf("row: %s\nexpect: %s", c.row, c.expect)
			c.run(t)
		})
	}
}

// ----------------------------------------------------------------------------
// Harness
// ----------------------------------------------------------------------------

type fakeClock struct {
	mu  sync.Mutex
	off time.Duration
}

func (c *fakeClock) now() time.Time {
	c.mu.Lock()
	defer c.mu.Unlock()
	return time.Now().UTC().Add(c.off)
}

func (c *fakeClock) advance(d time.Duration) {
	c.mu.Lock()
	c.off += d
	c.mu.Unlock()
}

type lockoutEnv struct {
	base  string
	srv   *Server
	email *recordingEmailSender
	clock *fakeClock
}

// newLockoutEnv: email + sms, selfie (template-only ceremony), social graph,
// in-person vouching with the anchor (K=1), holder revocation, identifier
// seeds, an admin token, and NO_FALSE_LOCKOUT with a 72 h window.
func newLockoutEnv(t *testing.T, mutate func(*Config)) *lockoutEnv {
	t.Helper()
	env := &lockoutEnv{clock: &fakeClock{}}
	relay := &SelfieMatchRelay{}
	base, srv, email, _, cleanup := newTestServerWithDeps(t, func(c *Config) {
		c.HolderRevocation = true
		c.AdminToken = testAdminToken
		c.IdentifierHMACKey = bytes.Repeat([]byte{7}, 32)
		c.NoFalseLockout = true
		c.Lockout = LockoutConfig{RecoveryDelay: 72 * time.Hour}
		if mutate != nil {
			mutate(c)
		}
	}, func(d *Dependencies) {
		if err := d.Registry.Register(fuzzyextractorselfie.NewMethod(fuzzyextractorselfie.Config{
			Accumulator: fuzzyextractorselfie.NewInMemoryAccumulator(),
			OnMatch:     relay.OnMatch,
		})); err != nil {
			t.Fatal(err)
		}
		d.SelfieMatches = relay
		graph := socialvouching.NewInMemoryGraphStore(nil)
		if err := d.Registry.Register(socialvouching.NewMethod(socialvouching.Config{Store: graph, Authenticator: socialvouching.RejectAllAuthenticator{}})); err != nil {
			t.Fatal(err)
		}
		d.VouchGraph = graph
		d.InPersonVouch = &InPersonVouchOptions{Anchor: true, DedupeMethods: DefaultDedupeMethods, Required: 1, MaxPerPeriod: 2}
	})
	t.Cleanup(cleanup)
	srv.SetNowFunc(env.clock.now)
	env.base, env.srv, env.email = base, srv, email
	return env
}

func (env *lockoutEnv) person(t *testing.T) enrollee {
	t.Helper()
	pub, priv := newHolderKey(t)
	return startWithKey(t, env.base, pub, priv)
}

// again opens a fresh session for the same key.
func (env *lockoutEnv) again(t *testing.T, e enrollee) enrollee {
	t.Helper()
	return startWithKey(t, env.base, e.pub, e.priv)
}

func (env *lockoutEnv) verifyEmail(t *testing.T, e enrollee, addr string) {
	t.Helper()
	mustPOST(t, env.base+"/v1/methods/email/begin", mustJSON(t, map[string]any{"session_id": e.session.SessionID, "user_input": addr}), nil)
	_, link, _ := env.email.lastSent()
	resp, err := http.Get(link)
	if err != nil {
		t.Fatalf("click magic link: %v", err)
	}
	resp.Body.Close()
}

func (env *lockoutEnv) selfie(t *testing.T, e enrollee, template []byte) map[string]any {
	t.Helper()
	st, out := do(t, http.MethodPost, env.base+"/v1/methods/"+fuzzyextractorselfie.MethodID+"/complete", map[string]any{
		"session_id": e.session.SessionID,
		"response":   types.ResponseData{Type: "x", Payload: map[string]any{"template_b64": base64.StdEncoding.EncodeToString(template)}},
	}, nil)
	if st != 200 {
		t.Fatalf("selfie: %d %v", st, out)
	}
	return out
}

func resultOf(out map[string]any) (bool, string) {
	r, _ := out["result"].(map[string]any)
	ok, _ := r["success"].(bool)
	reason, _ := r["error_reason"].(string)
	return ok, reason
}

func (env *lockoutEnv) mustIssue(t *testing.T, e enrollee) types.PersonhoodCredential {
	t.Helper()
	st, code, cred := e.issue(t, env.base)
	if st != 200 {
		t.Fatalf("issue: %d %s", st, code)
	}
	return cred
}

func (env *lockoutEnv) admin(t *testing.T, method, path string, body any) (int, map[string]any) {
	t.Helper()
	return do(t, method, env.base+path, body, map[string]string{"Authorization": "Bearer " + testAdminToken})
}

// enrolled: a person with an email and a face, issued.
func (env *lockoutEnv) enrolled(t *testing.T, addr string, face []byte) (enrollee, types.PersonhoodCredential) {
	t.Helper()
	e := env.person(t)
	if addr != "" {
		env.verifyEmail(t, e, addr)
	}
	if ok, reason := resultOf(env.selfie(t, e, face)); !ok {
		t.Fatalf("enroll selfie: %s", reason)
	}
	return e, env.mustIssue(t, e)
}

// voucher: an anchored member with a fresh face, ready to vouch.
type member struct {
	e    enrollee
	cred types.PersonhoodCredential
}

func (env *lockoutEnv) voucher(t *testing.T) member {
	t.Helper()
	e, cred := env.enrolled(t, "", fuzzyextractorselfie.RandomTemplateForTesting())
	return member{e, cred}
}

func (env *lockoutEnv) vouch(t *testing.T, v member, newcomer enrollee) {
	t.Helper()
	vouchCeremony(t, env.base, env.srv.IssuerDID(), v.e, v.cred, newcomer)
}

func nullifierOf(c types.PersonhoodCredential) string {
	if c.CredentialSubject.NullifierBinding == nil {
		return ""
	}
	return c.CredentialSubject.NullifierBinding.Commitment
}

func errField(out map[string]any, k string) any {
	e, _ := out["error"].(map[string]any)
	return e[k]
}

func hasNextAction(out map[string]any, action string) bool {
	steps, _ := errField(out, "next_steps").([]any)
	for _, s := range steps {
		if m, _ := s.(map[string]any); m["action"] == action {
			return true
		}
	}
	return false
}

func faceMatchActions(out map[string]any) []string {
	fm, _ := out["face_match"].(map[string]any)
	opts, _ := fm["options"].([]any)
	var acts []string
	for _, o := range opts {
		m, _ := o.(map[string]any)
		acts = append(acts, m["action"].(string))
	}
	return acts
}

func (env *lockoutEnv) credentialStillGood(t *testing.T, c types.PersonhoodCredential) bool {
	t.Helper()
	_, err := env.srv.VerifyVoucherCredential(context.Background(), mustJSON(t, c))
	return err == nil
}

func (env *lockoutEnv) startRecovery(t *testing.T, e enrollee) (int, map[string]any) {
	t.Helper()
	return do(t, http.MethodPost, env.base+"/v1/recovery/start", map[string]any{"session_id": e.session.SessionID}, nil)
}

// ----------------------------------------------------------------------------
// Rows
// ----------------------------------------------------------------------------

func edgeIdenticalTwin(t *testing.T) {
	env := newLockoutEnv(t, nil)
	face := fuzzyextractorselfie.RandomTemplateForTesting()
	_, aCred := env.enrolled(t, "ann@example.com", face)

	bea := env.person(t)
	env.verifyEmail(t, bea, "bea@example.com")
	out := env.selfie(t, bea, fuzzyextractorselfie.NoisyTemplateForTesting(face, 20))
	if ok, reason := resultOf(out); ok || reason != fuzzyextractorselfie.ReasonDuplicate {
		t.Fatalf("twin selfie: %v %s", ok, reason)
	}
	if acts := faceMatchActions(out); len(acts) != 3 || acts[0] != "recover" || acts[1] != "other_anchor" || acts[2] != "manual_review" {
		t.Fatalf("routing options = %v", acts)
	}
	if st, d := do(t, http.MethodPost, env.base+"/v1/face-match/decline", map[string]any{"session_id": bea.session.SessionID}, nil); st != 200 || d["extra_vouches"].(float64) != 2 {
		t.Fatalf("decline: %d %v", st, d)
	}
	// Having said "not me", she cannot recover her sister's identity.
	if st, o := env.startRecovery(t, bea); st != 409 || apiErrCode(o) != "face_match_declined" {
		t.Fatalf("recover after decline: %d %v", st, o)
	}
	// K=1, plus 2 for a declined match.
	v1, v2, v3 := env.voucher(t), env.voucher(t), env.voucher(t)
	env.vouch(t, v1, bea)
	if r := bea.complete(t, env.base, socialvouching.InPersonMethodID, nil); r.Result.Success || r.Result.ErrorReason != "insufficient_vouches:have=1/3" {
		t.Fatalf("one vouch: %+v", r.Result)
	}
	env.vouch(t, v2, bea)
	env.vouch(t, v3, bea)
	if r := bea.complete(t, env.base, socialvouching.InPersonMethodID, nil); !r.Result.Success {
		t.Fatalf("three vouches: %+v", r.Result)
	}
	bCred := env.mustIssue(t, bea)
	if nullifierOf(bCred) == "" || nullifierOf(bCred) == nullifierOf(aCred) {
		t.Fatalf("twin nullifier %q must exist and differ from %q", nullifierOf(bCred), nullifierOf(aCred))
	}
	if !env.credentialStillGood(t, aCred) {
		t.Fatal("first twin's credential was affected")
	}
}

func edgeTwinCap(t *testing.T) {
	env := newLockoutEnv(t, func(c *Config) { c.Lockout.FaceMatchMaxOthers = 1 })
	face := fuzzyextractorselfie.RandomTemplateForTesting()
	env.enrolled(t, "", face)
	vs := []member{env.voucher(t), env.voucher(t), env.voucher(t)}
	twin := func() (int, string, map[string]any) {
		e := env.person(t)
		env.selfie(t, e, fuzzyextractorselfie.NoisyTemplateForTesting(face, 10))
		do(t, http.MethodPost, env.base+"/v1/face-match/decline", map[string]any{"session_id": e.session.SessionID}, nil)
		for _, v := range vs {
			env.vouch(t, v, e)
		}
		if r := e.complete(t, env.base, socialvouching.InPersonMethodID, nil); !r.Result.Success {
			t.Fatalf("vouch anchor: %+v", r.Result)
		}
		sig := ed25519.Sign(e.priv, []byte(e.session.HolderProofMessage))
		st, out := do(t, http.MethodPost, env.base+"/v1/credentials/issue", map[string]any{"session_id": e.session.SessionID, "holder_proof_b64": base64.StdEncoding.EncodeToString(sig)}, nil)
		return st, apiErrCode(out), out
	}
	if st, code, _ := twin(); st != 200 {
		t.Fatalf("first other: %d %s", st, code)
	}
	st, code, out := twin()
	if st != 403 || code != "face_match_limit" || !hasNextAction(out, "manual_review") {
		t.Fatalf("second other: %d %s %v", st, code, out)
	}
}

func edgeLookalikeNoTakeover(t *testing.T) {
	env := newLockoutEnv(t, nil)
	face := fuzzyextractorselfie.RandomTemplateForTesting()
	_, aCred := env.enrolled(t, "ann@example.com", face)

	lee := env.person(t)
	env.verifyEmail(t, lee, "lee@example.com") // her own inbox, not Ann's
	env.selfie(t, lee, fuzzyextractorselfie.NoisyTemplateForTesting(face, 15))
	st, out := env.startRecovery(t, lee)
	if st != 403 || apiErrCode(out) != "recovery_factor_missing" || !hasNextAction(out, "verify_identifier") || !hasNextAction(out, "manual_review") {
		t.Fatalf("face-only recovery: %d %v", st, out)
	}
	if !env.credentialStillGood(t, aCred) {
		t.Fatal("enrolled person's credential was affected")
	}
}

func edgeLookalikeReview(t *testing.T) {
	env := newLockoutEnv(t, nil)
	face := fuzzyextractorselfie.RandomTemplateForTesting()
	_, aCred := env.enrolled(t, "ann@example.com", face)

	lee := env.person(t)
	env.selfie(t, lee, fuzzyextractorselfie.NoisyTemplateForTesting(face, 15))
	st, out := do(t, http.MethodPost, env.base+"/v1/reviews", map[string]any{"session_id": lee.session.SessionID, "kind": ReviewFaceMatch, "message": "I am not this person"}, nil)
	if st != 200 {
		t.Fatalf("review: %d %v", st, out)
	}
	id := out["review_id"].(string)
	if st, o := do(t, http.MethodPost, env.base+"/v1/reviews", map[string]any{"session_id": lee.session.SessionID, "kind": ReviewFaceMatch, "message": "again"}, nil); st != 409 || errField(o, "review_id") != id {
		t.Fatalf("duplicate review: %d %v", st, o)
	}
	// Before approval the anchor refuses.
	if r := lee.complete(t, env.base, OperatorReviewMethodID, nil); r.Result.Success || r.Result.ErrorReason != "review_not_approved" {
		t.Fatalf("before approval: %+v", r.Result)
	}
	if st, q := env.admin(t, http.MethodGet, "/v1/admin/reviews", nil); st != 200 || len(q["reviews"].([]any)) != 1 {
		t.Fatalf("queue: %d %v", st, q)
	}
	if st, d := env.admin(t, http.MethodPost, "/v1/admin/reviews/"+id+"/decide", map[string]any{"approve": true, "note": "video call, clearly a different person"}); st != 200 || d["status"] != ReviewApproved {
		t.Fatalf("decide: %d %v", st, d)
	}
	lee2 := env.again(t, lee)
	if r := lee2.complete(t, env.base, OperatorReviewMethodID, nil); !r.Result.Success {
		t.Fatalf("after approval: %+v", r.Result)
	}
	lCred := env.mustIssue(t, lee2)
	if a := lCred.CredentialSubject.AnchorMethodID; a == nil || *a != OperatorReviewMethodID {
		t.Fatalf("anchor = %v", a)
	}
	if nullifierOf(lCred) == nullifierOf(aCred) {
		t.Fatal("look-alike got the enrolled person's nullifier")
	}
	if st, s := do(t, http.MethodGet, env.base+"/v1/reviews/"+id, nil, nil); st != 200 || s["status"] != ReviewApproved {
		t.Fatalf("review status: %d %v", st, s)
	}
}

func edgeLostPhone(t *testing.T) {
	env := newLockoutEnv(t, nil)
	face := fuzzyextractorselfie.RandomTemplateForTesting()
	ann, aCred := env.enrolled(t, "ann@example.com", face)

	// New phone, new key: same inbox, same face.
	ann2 := env.person(t)
	env.verifyEmail(t, ann2, "ann@example.com")
	out := env.selfie(t, ann2, fuzzyextractorselfie.NoisyTemplateForTesting(face, 20))
	if ok, _ := resultOf(out); ok || len(faceMatchActions(out)) == 0 {
		t.Fatalf("new phone selfie: %v", out)
	}
	st, rec := env.startRecovery(t, ann2)
	if st != 200 || rec["status"] != RecoveryPending || rec["factors"].([]any)[0] != FactorIdentifier {
		t.Fatalf("start: %d %v", st, rec)
	}
	id := rec["recovery_id"].(string)
	// The old key can see it.
	if st, p := do(t, http.MethodGet, env.base+"/v1/recovery/pending?holder_did="+string(ann.session.HolderDID), nil, nil); st != 200 || p["role"] != "old_key" || len(p["pending"].([]any)) != 1 {
		t.Fatalf("pending: %d %v", st, p)
	}
	// Not before the window closes; and nothing else is issued meanwhile.
	if st, o := do(t, http.MethodPost, env.base+"/v1/recovery/"+id+"/complete", map[string]any{"session_id": ann2.session.SessionID}, nil); st != http.StatusTooEarly || apiErrCode(o) != "recovery_not_ready" {
		t.Fatalf("early complete: %d %v", st, o)
	}
	if st, code, _ := ann2.issue(t, env.base); st != 409 || code != "recovery_pending" {
		t.Fatalf("issue during window: %d %s", st, code)
	}
	env.clock.advance(73 * time.Hour)
	ann3 := env.again(t, ann2)
	if st, o := do(t, http.MethodPost, env.base+"/v1/recovery/"+id+"/complete", map[string]any{"session_id": ann3.session.SessionID}, nil); st != 200 || o["revoked_credentials"].(float64) != 1 {
		t.Fatalf("complete: %d %v", st, o)
	}
	nCred := env.mustIssue(t, ann3)
	if nullifierOf(nCred) != nullifierOf(aCred) {
		t.Fatalf("recovered nullifier %q, want the original %q", nullifierOf(nCred), nullifierOf(aCred))
	}
	if env.credentialStillGood(t, aCred) {
		t.Fatal("old credential still valid after recovery")
	}
	old := env.again(t, ann)
	env.verifyEmail(t, old, "ann@example.com")
	if st, code, _ := old.issue(t, env.base); st != 403 || code != "holder_revoked" {
		t.Fatalf("old key after recovery: %d %s", st, code)
	}
}

func edgeOldKeyCancels(t *testing.T) {
	env := newLockoutEnv(t, nil)
	face := fuzzyextractorselfie.RandomTemplateForTesting()
	ann, aCred := env.enrolled(t, "ann@example.com", face)

	thief := env.person(t)
	env.verifyEmail(t, thief, "ann@example.com") // inbox compromised too
	env.selfie(t, thief, fuzzyextractorselfie.NoisyTemplateForTesting(face, 25))
	st, rec := env.startRecovery(t, thief)
	if st != 200 {
		t.Fatalf("start: %d %v", st, rec)
	}
	id := rec["recovery_id"].(string)
	msg := RecoveryCancelMessage(env.srv.IssuerDID(), id)
	// A stranger's signature is refused.
	_, strangerPriv := newHolderKey(t)
	if st, o := do(t, http.MethodPost, env.base+"/v1/recovery/"+id+"/cancel", map[string]any{"holder_did": ann.session.HolderDID, "signature_b64": base64.StdEncoding.EncodeToString(ed25519.Sign(strangerPriv, []byte(msg)))}, nil); st != 403 || apiErrCode(o) != "bad_signature" {
		t.Fatalf("forged cancel: %d %v", st, o)
	}
	if st, o := do(t, http.MethodPost, env.base+"/v1/recovery/"+id+"/cancel", map[string]any{"holder_did": ann.session.HolderDID, "signature_b64": base64.StdEncoding.EncodeToString(ed25519.Sign(ann.priv, []byte(msg)))}, nil); st != 200 || o["status"] != RecoveryCancelled {
		t.Fatalf("cancel: %d %v", st, o)
	}
	env.clock.advance(73 * time.Hour)
	t2 := env.again(t, thief)
	if st, o := do(t, http.MethodPost, env.base+"/v1/recovery/"+id+"/complete", map[string]any{"session_id": t2.session.SessionID}, nil); st != 409 || apiErrCode(o) != "recovery_closed" {
		t.Fatalf("complete after cancel: %d %v", st, o)
	}
	if !env.credentialStillGood(t, aCred) {
		t.Fatal("owner's credential affected by a cancelled recovery")
	}
}

func edgeRecoveryVouchers(t *testing.T) {
	env := newLockoutEnv(t, nil)
	face := fuzzyextractorselfie.RandomTemplateForTesting()
	v1, v2 := env.voucher(t), env.voucher(t)
	ann := env.person(t)
	env.vouch(t, v1, ann)
	env.vouch(t, v2, ann)
	if ok, r := resultOf(env.selfie(t, ann, face)); !ok {
		t.Fatalf("selfie: %s", r)
	}
	env.mustIssue(t, ann)

	ann2 := env.person(t) // no email at all
	env.selfie(t, ann2, fuzzyextractorselfie.NoisyTemplateForTesting(face, 10))
	if st, o := env.startRecovery(t, ann2); st != 403 || !hasNextAction(o, "vouchers") {
		t.Fatalf("before re-vouch: %d %v", st, o)
	}
	env.vouch(t, v1, ann2)
	env.vouch(t, v2, ann2)
	st, rec := env.startRecovery(t, ann2)
	if st != 200 || rec["factors"].([]any)[0] != FactorVouchers {
		t.Fatalf("start with vouchers: %d %v", st, rec)
	}
}

func edgeRecoveryLimits(t *testing.T) {
	env := newLockoutEnv(t, nil)
	face := fuzzyextractorselfie.RandomTemplateForTesting()
	ann, _ := env.enrolled(t, "ann@example.com", face)

	attempt := func() (int, map[string]any, enrollee) {
		e := env.person(t)
		env.verifyEmail(t, e, "ann@example.com")
		env.selfie(t, e, fuzzyextractorselfie.NoisyTemplateForTesting(face, 5))
		st, o := env.startRecovery(t, e)
		return st, o, e
	}
	// A second attempt while one is pending is told so.
	st, rec, _ := attempt()
	if st != 200 {
		t.Fatalf("first: %d %v", st, rec)
	}
	if st, o, _ := attempt(); st != 409 || apiErrCode(o) != "recovery_pending" {
		t.Fatalf("concurrent: %d %v", st, o)
	}
	cancel := func(id string) {
		sig := ed25519.Sign(ann.priv, []byte(RecoveryCancelMessage(env.srv.IssuerDID(), id)))
		if st, o := do(t, http.MethodPost, env.base+"/v1/recovery/"+id+"/cancel", map[string]any{"holder_did": ann.session.HolderDID, "signature_b64": base64.StdEncoding.EncodeToString(sig)}, nil); st != 200 {
			t.Fatalf("cancel: %d %v", st, o)
		}
	}
	cancel(rec["recovery_id"].(string))
	for i := 0; i < 2; i++ {
		st, o, _ := attempt()
		if st != 200 {
			t.Fatalf("attempt %d: %d %v", i+2, st, o)
		}
		cancel(o["recovery_id"].(string))
	}
	if st, o, _ := attempt(); st != 403 || apiErrCode(o) != "recovery_needs_review" || !hasNextAction(o, "manual_review") {
		t.Fatalf("after 3 cancels: %d %v", st, o)
	}

	// Cooldown after a completed recovery (a fresh identity).
	face2 := fuzzyextractorselfie.RandomTemplateForTesting()
	env.enrolled(t, "bo@example.com", face2)
	b2 := env.person(t)
	env.verifyEmail(t, b2, "bo@example.com")
	env.selfie(t, b2, face2)
	st, rec = env.startRecovery(t, b2)
	if st != 200 {
		t.Fatalf("bo start: %d %v", st, rec)
	}
	env.clock.advance(73 * time.Hour)
	b3 := env.again(t, b2)
	if st, o := do(t, http.MethodPost, env.base+"/v1/recovery/"+rec["recovery_id"].(string)+"/complete", map[string]any{"session_id": b3.session.SessionID}, nil); st != 200 {
		t.Fatalf("bo complete: %d %v", st, o)
	}
	env.mustIssue(t, b3)
	b4 := env.person(t)
	env.verifyEmail(t, b4, "bo@example.com")
	env.selfie(t, b4, face2)
	if st, o := env.startRecovery(t, b4); st != 429 || apiErrCode(o) != "recovery_cooldown" || !hasNextAction(o, "manual_review") {
		t.Fatalf("within cooldown: %d %v", st, o)
	}
}

func edgeReenrollSameKey(t *testing.T) {
	env := newLockoutEnv(t, nil)
	face := fuzzyextractorselfie.RandomTemplateForTesting()
	ann, aCred := env.enrolled(t, "", face)
	again := env.again(t, ann)
	if ok, reason := resultOf(env.selfie(t, again, fuzzyextractorselfie.NoisyTemplateForTesting(face, 20))); !ok {
		t.Fatalf("same key, same face: %s", reason)
	}
	if c := env.mustIssue(t, again); nullifierOf(c) != nullifierOf(aCred) {
		t.Fatal("re-issue changed the nullifier")
	}
}

func edgeSharedFamilyPhone(t *testing.T) {
	env := newLockoutEnv(t, nil)
	seen := map[string]bool{}
	for i := 0; i < 5; i++ {
		_, c := env.enrolled(t, "family@example.com", fuzzyextractorselfie.RandomTemplateForTesting())
		n := nullifierOf(c)
		if n == "" || seen[n] {
			t.Fatalf("member %d: nullifier %q empty or shared", i, n)
		}
		seen[n] = true
	}
	// The per-IP limiter (5 selfie begins from one phone in a minute)
	// delays the 5th person by seconds; it does not refuse them.
	now := time.Unix(0, 0)
	lim := newRateLimiter(DefaultRateLimitConfig(), func() time.Time { return now })
	var wait time.Duration
	for i := 0; i < 5; i++ {
		ok, w := lim.allow("10.0.0.1", classBegin)
		if !ok {
			wait = w
		}
	}
	if wait <= 0 || wait > 15*time.Second {
		t.Fatalf("5th begin wait = %v, want a short delay", wait)
	}
	now = now.Add(wait)
	if ok, _ := lim.allow("10.0.0.1", classBegin); !ok {
		t.Fatal("5th person still refused after waiting")
	}
}

func edgeOldPhone(t *testing.T) {
	env := newLockoutEnv(t, nil)
	_, c := env.enrolled(t, "", fuzzyextractorselfie.RandomTemplateForTesting())
	if a := c.CredentialSubject.AnchorMethodID; a == nil || *a != fuzzyextractorselfie.MethodID {
		t.Fatalf("anchor = %v", a)
	}
}

func edgeWalletDoubleSign(t *testing.T) {
	env := newLockoutEnv(t, nil)
	face := fuzzyextractorselfie.RandomTemplateForTesting()
	v := env.voucher(t)
	ann := env.person(t)
	env.selfie(t, ann, face)
	env.vouch(t, v, ann)
	if r := ann.complete(t, env.base, socialvouching.InPersonMethodID, nil); !r.Result.Success {
		t.Fatalf("anchor: %+v", r.Result)
	}
	aCred := env.mustIssue(t, ann)

	// The wallet bug signs one slot twice.
	d1, d2 := sha256.Sum256([]byte("pay shop")), sha256.Sum256([]byte("pay shop, retried"))
	s1, _ := credential.SignSlotStatement(ann.priv, "openline/test/spend", "acct:7", d1[:])
	s2, _ := credential.SignSlotStatement(ann.priv, "openline/test/spend", "acct:7", d2[:])
	proof := credential.EquivocationProof{Scheme: credential.SlotStatementScheme, HolderPublicKeyB64: base64.StdEncoding.EncodeToString(ann.pub),
		Context: "openline/test/spend", Slot: "acct:7", Statements: [2]credential.SlotStatement{s1, s2}}
	if st, rep := do(t, http.MethodPost, env.base+"/v1/revocations/equivocation", proof, nil); st != 200 || rep["vouchers_penalized"].(float64) != 1 {
		t.Fatalf("equivocation: %d %v", st, rep)
	}
	if st, o := do(t, http.MethodPost, env.base+"/v1/methods/in-person-vouch/offer", map[string]any{"credential": v.cred}, nil); st != 403 || apiErrCode(o) != "voucher_suspended" {
		t.Fatalf("voucher after penalty: %d %v", st, o)
	}
	again := env.again(t, ann)
	env.selfie(t, again, face)
	sig := ed25519.Sign(again.priv, []byte(again.session.HolderProofMessage))
	st, out := do(t, http.MethodPost, env.base+"/v1/credentials/issue", map[string]any{"session_id": again.session.SessionID, "holder_proof_b64": base64.StdEncoding.EncodeToString(sig)}, nil)
	if st != 403 || apiErrCode(out) != "holder_revoked" || !hasNextAction(out, "appeal") {
		t.Fatalf("banned re-enroll: %d %v", st, out)
	}

	// Appeal, signed by the banned key.
	msg := "My wallet app crashed and re-sent the payment. Bug report attached."
	st, ap := do(t, http.MethodPost, env.base+"/v1/appeals", map[string]any{
		"holder_did": ann.session.HolderDID, "message": msg,
		"signature_b64": base64.StdEncoding.EncodeToString(ed25519.Sign(ann.priv, []byte(AppealMessage(env.srv.IssuerDID(), ann.session.HolderDID, msg)))),
	}, nil)
	if st != 200 {
		t.Fatalf("appeal: %d %v", st, ap)
	}
	st, dec := env.admin(t, http.MethodPost, "/v1/admin/reviews/"+ap["review_id"].(string)+"/decide", map[string]any{"approve": true, "note": "reproduced the wallet retry bug"})
	if st != 200 {
		t.Fatalf("decide: %d %v", st, dec)
	}
	rep := dec["reinstated"].(map[string]any)
	if rep["evidence_pardoned"] != true || rep["vouchers_restored"].(float64) != 1 || rep["nullifiers_unbanned"].(float64) < 1 {
		t.Fatalf("reinstate report: %v", rep)
	}
	// The same proof, statements swapped, does not ban again.
	proof.Statements[0], proof.Statements[1] = proof.Statements[1], proof.Statements[0]
	if st, o := do(t, http.MethodPost, env.base+"/v1/revocations/equivocation", proof, nil); st != 409 || apiErrCode(o) != "evidence_pardoned" {
		t.Fatalf("re-posted proof: %d %v", st, o)
	}
	// The voucher may vouch again; the person re-enrolls on the same identity.
	if st, o := do(t, http.MethodPost, env.base+"/v1/methods/in-person-vouch/offer", map[string]any{"credential": v.cred}, nil); st != 200 {
		t.Fatalf("voucher after reinstate: %d %v", st, o)
	}
	back := env.again(t, ann)
	if ok, reason := resultOf(env.selfie(t, back, face)); !ok {
		t.Fatalf("selfie after reinstate: %s", reason)
	}
	if c := env.mustIssue(t, back); nullifierOf(c) != nullifierOf(aCred) {
		t.Fatal("reinstated person got a different nullifier")
	}
}

func edgeVouchOverVideo(t *testing.T) {
	env := newLockoutEnv(t, func(c *Config) { c.RateLimit.TrustedProxyHops = 1 })
	v := env.voucher(t)
	n := env.person(t)
	m := env.base + "/v1/methods/in-person-vouch/"
	st, offer := do(t, http.MethodPost, m+"offer", map[string]any{"credential": v.cred}, map[string]string{"X-Forwarded-For": "198.51.100.7"})
	if st != 200 {
		t.Fatalf("offer: %d %v", st, offer)
	}
	code := offer["offer_code"].(string)
	cand := string(n.session.HolderDID)
	st, acc := do(t, http.MethodPost, m+"accept", map[string]any{
		"offer_code": code, "candidate_public_key_b64": base64.StdEncoding.EncodeToString(n.pub),
		"signature_b64": base64.StdEncoding.EncodeToString(ed25519.Sign(n.priv, []byte(socialvouching.AcceptMessage(string(env.srv.IssuerDID()), code, cand)))),
	}, map[string]string{"X-Forwarded-For": "203.0.113.50"})
	if st != 200 {
		t.Fatalf("accept: %d %v", st, acc)
	}
	ret := acc["return_code"].(string)
	st, conf := do(t, http.MethodPost, m+"confirm", map[string]any{
		"offer_code": code, "return_code": ret,
		"signature_b64": base64.StdEncoding.EncodeToString(ed25519.Sign(v.e.priv, []byte(socialvouching.ConfirmMessage(string(env.srv.IssuerDID()), code, cand, ret)))),
	}, map[string]string{"X-Forwarded-For": "198.51.100.7"})
	if st != 200 || conf["recorded"] != true || conf["same_network"] != false {
		t.Fatalf("confirm over video: %d %v", st, conf)
	}
}

func edgeNoSelfie(t *testing.T) {
	env := newLockoutEnv(t, nil)
	p := env.person(t)
	env.verifyEmail(t, p, "noselfie@example.com")
	st, out := do(t, http.MethodPost, env.base+"/v1/reviews", map[string]any{"session_id": p.session.SessionID, "kind": ReviewNoSelfie, "message": "I am blind; my neighbour can vouch for me"}, nil)
	if st != 200 {
		t.Fatalf("review: %d %v", st, out)
	}
	if st, d := env.admin(t, http.MethodPost, "/v1/admin/reviews/"+out["review_id"].(string)+"/decide", map[string]any{"approve": true, "note": "met in person at the community centre"}); st != 200 {
		t.Fatalf("decide: %d %v", st, d)
	}
	p2 := env.again(t, p)
	env.verifyEmail(t, p2, "noselfie@example.com")
	if r := p2.complete(t, env.base, OperatorReviewMethodID, nil); !r.Result.Success {
		t.Fatalf("operator-review: %+v", r.Result)
	}
	c := env.mustIssue(t, p2)
	if a := c.CredentialSubject.AnchorMethodID; a == nil || *a != OperatorReviewMethodID || nullifierOf(c) == "" {
		t.Fatalf("credential anchor %v nullifier %q", a, nullifierOf(c))
	}
}

func edgeSameEmail(t *testing.T) {
	env := newLockoutEnv(t, nil)
	issueEmail := func() string {
		p := env.person(t)
		env.verifyEmail(t, p, "one@example.com")
		return nullifierOf(env.mustIssue(t, p))
	}
	if a, b := issueEmail(), issueEmail(); a == "" || a != b {
		t.Fatalf("same inbox: %q vs %q", a, b)
	}
}

func edgeFlagOff(t *testing.T) {
	base, _, _, cleanup := newInPersonTestServer(t)
	defer cleanup()
	face := fuzzyextractorselfie.RandomTemplateForTesting()
	pub, priv := newHolderKey(t)
	startWithKey(t, base, pub, priv).selfie(t, base, face)
	pub2, priv2 := newHolderKey(t)
	e := startWithKey(t, base, pub2, priv2)
	st, out := do(t, http.MethodPost, base+"/v1/methods/"+fuzzyextractorselfie.MethodID+"/complete", map[string]any{
		"session_id": e.session.SessionID,
		"response":   types.ResponseData{Type: "x", Payload: map[string]any{"template_b64": base64.StdEncoding.EncodeToString(face)}},
	}, nil)
	if ok, reason := resultOf(out); st != 200 || ok || reason != fuzzyextractorselfie.ReasonDuplicate || out["face_match"] != nil {
		t.Fatalf("duplicate with flag off: %d %v", st, out)
	}
	for _, p := range []string{"/v1/recovery/start", "/v1/face-match/decline", "/v1/reviews", "/v1/appeals"} {
		if st, _ := do(t, http.MethodPost, base+p, map[string]any{}, nil); st != 404 && st != 405 {
			t.Fatalf("%s mounted with the flag off: %d", p, st)
		}
	}
}
