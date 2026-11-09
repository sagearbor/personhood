package server

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"testing"

	"github.com/sagearbor/personhood/pkg/types"
	"github.com/sagearbor/personhood/src/credential"
	fuzzyextractorselfie "github.com/sagearbor/personhood/src/methods/fuzzy-extractor-selfie"
	socialvouching "github.com/sagearbor/personhood/src/methods/social-vouching"
)

// newInPersonTestServer is the standard test server (email + sms) plus
// fuzzy-extractor-selfie, social-vouching-graph, in-person vouching with the
// anchor policy (K=1), holder revocation and an admin token.
func newInPersonTestServer(t *testing.T) (string, *Server, *recordingEmailSender, func()) {
	t.Helper()
	base, srv, email, _, cleanup := newTestServerWithDeps(t, func(c *Config) {
		c.HolderRevocation = true
		c.AdminToken = testAdminToken
		c.IdentifierHMACKey = bytes.Repeat([]byte{7}, 32)
	}, func(d *Dependencies) {
		if err := d.Registry.Register(fuzzyextractorselfie.NewMethod(fuzzyextractorselfie.Config{
			Accumulator: fuzzyextractorselfie.NewInMemoryAccumulator(),
		})); err != nil {
			t.Fatal(err)
		}
		graph := socialvouching.NewInMemoryGraphStore(nil)
		if err := d.Registry.Register(socialvouching.NewMethod(socialvouching.Config{Store: graph, Authenticator: socialvouching.RejectAllAuthenticator{}})); err != nil {
			t.Fatal(err)
		}
		d.VouchGraph = graph
		d.InPersonVouch = &InPersonVouchOptions{Anchor: true, DedupeMethods: DefaultDedupeMethods, Required: 1, MaxPerPeriod: 2}
	})
	return base, srv, email, cleanup
}

// do sends a JSON request and returns the status and decoded body.
func do(t *testing.T, method, url string, body any, header map[string]string) (int, map[string]any) {
	t.Helper()
	var rd io.Reader
	if body != nil {
		rd = bytes.NewReader(mustJSON(t, body))
	}
	req, _ := http.NewRequest(method, url, rd)
	req.Header.Set("Content-Type", "application/json")
	for k, v := range header {
		req.Header.Set(k, v)
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("%s %s: %v", method, url, err)
	}
	defer resp.Body.Close()
	var out map[string]any
	_ = json.NewDecoder(resp.Body).Decode(&out)
	return resp.StatusCode, out
}

func apiErrCode(out map[string]any) string {
	e, _ := out["error"].(map[string]any)
	c, _ := e["code"].(string)
	return c
}

type enrollee struct {
	pub     ed25519.PublicKey
	priv    ed25519.PrivateKey
	session startEnrollmentResponse
}

func startWithKey(t *testing.T, base string, pub ed25519.PublicKey, priv ed25519.PrivateKey) enrollee {
	t.Helper()
	var start startEnrollmentResponse
	mustPOST(t, base+"/enrollment/start", mustJSON(t, map[string]any{"holder_public_key_b64": base64.StdEncoding.EncodeToString(pub)}), &start)
	return enrollee{pub, priv, start}
}

func (e enrollee) complete(t *testing.T, base, methodID string, payload map[string]any) completeMethodResponse {
	t.Helper()
	var out completeMethodResponse
	mustPOST(t, base+"/v1/methods/"+methodID+"/complete", mustJSON(t, map[string]any{
		"session_id": e.session.SessionID,
		"response":   types.ResponseData{Type: "x", Payload: payload},
	}), &out)
	return out
}

func (e enrollee) selfie(t *testing.T, base string, template []byte) {
	t.Helper()
	if r := e.complete(t, base, fuzzyextractorselfie.MethodID, map[string]any{"template_b64": base64.StdEncoding.EncodeToString(template)}); !r.Result.Success {
		t.Fatalf("selfie: %s", r.Result.ErrorReason)
	}
}

func (e enrollee) issue(t *testing.T, base string) (int, string, types.PersonhoodCredential) {
	t.Helper()
	sig := ed25519.Sign(e.priv, []byte(e.session.HolderProofMessage))
	st, out := do(t, http.MethodPost, base+"/v1/credentials/issue", map[string]any{
		"session_id": e.session.SessionID, "holder_proof_b64": base64.StdEncoding.EncodeToString(sig),
	}, nil)
	var cred types.PersonhoodCredential
	if c, ok := out["credential"]; ok {
		b, _ := json.Marshal(c)
		_ = json.Unmarshal(b, &cred)
	}
	return st, apiErrCode(out), cred
}

// vouchCeremony runs offer -> accept -> confirm over HTTP.
func vouchCeremony(t *testing.T, base string, issuer types.DID, voucher enrollee, voucherCred types.PersonhoodCredential, newcomer enrollee) map[string]any {
	t.Helper()
	m := base + "/v1/methods/in-person-vouch/"
	st, offer := do(t, http.MethodPost, m+"offer", map[string]any{"credential": voucherCred}, nil)
	if st != 200 {
		t.Fatalf("offer: %d %v", st, offer)
	}
	code := offer["offer_code"].(string)
	candidate := string(newcomer.session.HolderDID)
	st, acc := do(t, http.MethodPost, m+"accept", map[string]any{
		"offer_code":               code,
		"candidate_public_key_b64": base64.StdEncoding.EncodeToString(newcomer.pub),
		"signature_b64":            base64.StdEncoding.EncodeToString(ed25519.Sign(newcomer.priv, []byte(socialvouching.AcceptMessage(string(issuer), code, candidate)))),
	}, nil)
	if st != 200 || acc["candidate_did"] != candidate {
		t.Fatalf("accept: %d %v", st, acc)
	}
	st, status := do(t, http.MethodGet, m+"status?code="+code, nil, nil)
	if st != 200 || status["state"] != "accepted" || status["candidate_did"] != candidate {
		t.Fatalf("status: %d %v", st, status)
	}
	ret := acc["return_code"].(string)
	st, conf := do(t, http.MethodPost, m+"confirm", map[string]any{
		"offer_code":    code,
		"return_code":   ret,
		"signature_b64": base64.StdEncoding.EncodeToString(ed25519.Sign(voucher.priv, []byte(socialvouching.ConfirmMessage(string(issuer), code, candidate, ret)))),
	}, nil)
	if st != 200 || conf["recorded"] != true {
		t.Fatalf("confirm: %d %v", st, conf)
	}
	return conf
}

func TestIntegration_InPersonVouchAnchorAndEquivocation(t *testing.T) {
	base, srv, _, cleanup := newInPersonTestServer(t)
	defer cleanup()
	ctx := context.Background()

	if st, out := do(t, http.MethodGet, base+"/v1/config", nil, nil); st != 200 || out["holder_revocation"] != true || out["in_person_vouch"] != true {
		t.Fatalf("config: %d %v", st, out)
	}

	// The voucher enrols with a selfie: an anchored credential.
	vPub, vPriv := newHolderKey(t)
	voucher := startWithKey(t, base, vPub, vPriv)
	voucher.selfie(t, base, fuzzyextractorselfie.RandomTemplateForTesting())
	st, code, vCred := voucher.issue(t, base)
	if st != 200 {
		t.Fatalf("voucher issue: %d %s", st, code)
	}

	// The newcomer: in-person-vouch refuses to complete before the selfie dedupe.
	nPub, nPriv := newHolderKey(t)
	newcomer := startWithKey(t, base, nPub, nPriv)
	if r := newcomer.complete(t, base, socialvouching.InPersonMethodID, nil); r.Result.Success || r.Result.ErrorReason != "prerequisite_missing:fuzzy-extractor-selfie" {
		t.Fatalf("before selfie: %+v", r.Result)
	}
	newcomer.selfie(t, base, fuzzyextractorselfie.RandomTemplateForTesting())
	if r := newcomer.complete(t, base, socialvouching.InPersonMethodID, nil); r.Result.Success || r.Result.ErrorReason != "insufficient_vouches:have=0/1" {
		t.Fatalf("before vouch: %+v", r.Result)
	}

	conf := vouchCeremony(t, base, srv.IssuerDID(), voucher, vCred, newcomer)
	if conf["voucher_anchored"] != true || conf["same_network"] != true {
		t.Fatalf("confirm evidence: %v", conf)
	}
	r := newcomer.complete(t, base, socialvouching.InPersonMethodID, nil)
	if !r.Result.Success || r.Session.AnchorMethodID == nil || *r.Session.AnchorMethodID != socialvouching.InPersonMethodID {
		t.Fatalf("anchor: %+v anchor=%v", r.Result, r.Session.AnchorMethodID)
	}
	st, code, nCred := newcomer.issue(t, base)
	if st != 200 {
		t.Fatalf("newcomer issue: %d %s", st, code)
	}
	if *nCred.CredentialSubject.AnchorMethodID != socialvouching.InPersonMethodID {
		t.Fatalf("credential anchor = %s", *nCred.CredentialSubject.AnchorMethodID)
	}

	// The newcomer double-spends: two conflicting slot statements.
	d1, d2 := sha256.Sum256([]byte("pay alice")), sha256.Sum256([]byte("pay bob"))
	s1, _ := credential.SignSlotStatement(nPriv, "openline/test/spend", "coin-1", d1[:])
	s2, _ := credential.SignSlotStatement(nPriv, "openline/test/spend", "coin-1", d2[:])
	proof := credential.EquivocationProof{
		Scheme: credential.SlotStatementScheme, HolderPublicKeyB64: base64.StdEncoding.EncodeToString(nPub),
		Context: "openline/test/spend", Slot: "coin-1", Statements: [2]credential.SlotStatement{s1, s2},
	}
	st, rep := do(t, http.MethodPost, base+"/v1/revocations/equivocation", proof, nil)
	if st != 200 || rep["known_holder"] != true || rep["revoked_credentials"].(float64) != 1 ||
		rep["nullifiers_banned"].(float64) != 2 || rep["vouchers_penalized"].(float64) != 1 {
		t.Fatalf("equivocation: %d %v", st, rep)
	}
	// Idempotent.
	if st, rep := do(t, http.MethodPost, base+"/v1/revocations/equivocation", proof, nil); st != 200 || rep["already_banned"] != true || rep["revoked_credentials"].(float64) != 0 {
		t.Fatalf("second equivocation: %d %v", st, rep)
	}

	// The newcomer's credential is revoked: it can no longer vouch either.
	if _, err := srv.VerifyVoucherCredential(ctx, mustJSON(t, nCred)); !errors.Is(err, socialvouching.ErrVoucherCredentialInvalid) {
		t.Fatalf("revoked credential still accepted: %v", err)
	}
	// The voucher is suspended.
	if st, out := do(t, http.MethodPost, base+"/v1/methods/in-person-vouch/offer", map[string]any{"credential": vCred}, nil); st != 403 || apiErrCode(out) != "voucher_suspended" {
		t.Fatalf("voucher offer after penalty: %d %v", st, out)
	}
	// The same key cannot enrol again.
	again := startWithKey(t, base, nPub, nPriv)
	again.selfie(t, base, fuzzyextractorselfie.RandomTemplateForTesting())
	if st, code, _ := again.issue(t, base); st != 403 || code != "holder_revoked" {
		t.Fatalf("re-enrol same key: %d %s", st, code)
	}
}

func TestIntegration_RevokeHolderBansEmailSeed(t *testing.T) {
	base, _, email, cleanup := newInPersonTestServer(t)
	defer cleanup()

	pub, priv := newHolderKey(t)
	start := startEmailSessionWithKey(t, base, email, pub)
	e := enrollee{pub, priv, start}
	if st, code, _ := e.issue(t, base); st != 200 {
		t.Fatalf("issue: %d %s", st, code)
	}

	if st, out := do(t, http.MethodPost, base+"/v1/admin/revoke-holder", map[string]any{"holder_did": start.HolderDID, "reason": "duplicate"}, nil); st != 401 {
		t.Fatalf("no token: %d %v", st, out)
	}
	st, rep := do(t, http.MethodPost, base+"/v1/admin/revoke-holder", map[string]any{"holder_did": start.HolderDID, "reason": "duplicate"},
		map[string]string{"Authorization": "Bearer " + testAdminToken})
	if st != 200 || rep["revoked_credentials"].(float64) != 1 {
		t.Fatalf("revoke-holder: %d %v", st, rep)
	}

	// A new device key with the same inbox lands on the same seed: refused.
	pub2, priv2 := newHolderKey(t)
	start2 := startEmailSessionWithKey(t, base, email, pub2)
	if st, code, _ := (enrollee{pub2, priv2, start2}).issue(t, base); st != 403 || code != "nullifier_revoked" {
		t.Fatalf("re-enrol same inbox: %d %s", st, code)
	}
}

func TestIntegration_EquivocationRejectsBadProof(t *testing.T) {
	base, _, _, cleanup := newInPersonTestServer(t)
	defer cleanup()
	pub, priv := newHolderKey(t)
	d := sha256.Sum256([]byte("pay"))
	s1, _ := credential.SignSlotStatement(priv, "c", "s", d[:])
	proof := credential.EquivocationProof{Scheme: credential.SlotStatementScheme, HolderPublicKeyB64: base64.StdEncoding.EncodeToString(pub),
		Context: "c", Slot: "s", Statements: [2]credential.SlotStatement{s1, s1}}
	if st, out := do(t, http.MethodPost, base+"/v1/revocations/equivocation", proof, nil); st != 400 || apiErrCode(out) != "proof_invalid" {
		t.Fatalf("same statement twice: %d %v", st, out)
	}
}

func TestIntegration_HolderRevocationRoutesOffByDefault(t *testing.T) {
	base, _, _, _, cleanup := newTestServer(t)
	defer cleanup()
	if st, _ := do(t, http.MethodPost, base+"/v1/revocations/equivocation", map[string]any{}, nil); st != 404 && st != 405 {
		t.Fatalf("equivocation route mounted by default: %d", st)
	}
	if st, _ := do(t, http.MethodPost, base+"/v1/methods/in-person-vouch/offer", map[string]any{}, nil); st == 200 {
		t.Fatal("in-person routes mounted by default")
	}
}

func TestNewServer_InPersonAnchorNeedsHolderRevocation(t *testing.T) {
	_, priv := newHolderKey(t)
	cfg := Config{Addr: ":0", PublicURL: "http://localhost:1", IssuerPrivateKey: priv, SessionTTL: 1e9}
	reg, err := DefaultMethods("http://localhost:1/v1/methods/email/verify")
	if err != nil {
		t.Fatal(err)
	}
	_ = reg.Register(fuzzyextractorselfie.NewMethod(fuzzyextractorselfie.Config{Accumulator: fuzzyextractorselfie.NewInMemoryAccumulator()}))
	deps := Dependencies{Registry: reg, VouchGraph: socialvouching.NewInMemoryGraphStore(nil),
		InPersonVouch: &InPersonVouchOptions{Anchor: true, DedupeMethods: DefaultDedupeMethods}}
	if _, err := NewServer(cfg, deps); err == nil {
		t.Fatal("anchor without holder revocation: want error")
	}
	cfg.HolderRevocation = true
	deps.InPersonVouch.DedupeMethods = []string{"no-such-method"}
	if _, err := NewServer(cfg, deps); err == nil {
		t.Fatal("anchor with no registered dedupe method: want error")
	}
	deps.InPersonVouch.DedupeMethods = DefaultDedupeMethods
	if _, err := NewServer(cfg, deps); err != nil {
		t.Fatalf("valid anchor config: %v", err)
	}
}

func TestBuildDependencies_InPersonVouch(t *testing.T) {
	t.Setenv("SOCIAL_VOUCHING_ENABLED", "")
	t.Setenv("IN_PERSON_VOUCH_ENABLED", "1")
	t.Setenv("IN_PERSON_VOUCH_REQUIRED", "2")
	t.Setenv("IN_PERSON_VOUCH_PERIOD_DAYS", "7")
	deps, err := BuildDependencies("http://localhost:8080/v1/methods/email/verify", "")
	if err != nil {
		t.Fatal(err)
	}
	if _, ok := deps.Registry.Get(socialvouching.MethodID); !ok {
		t.Fatal("social-vouching-graph not registered with in-person vouching on")
	}
	for _, r := range deps.MethodRoutes {
		if r.Path == "vouch" {
			t.Fatal("dev HMAC /vouch route mounted without SOCIAL_VOUCHING_ENABLED")
		}
	}
	o := deps.InPersonVouch
	if o == nil || deps.VouchGraph == nil || o.Required != 2 || o.Period != 7*24*3600e9 || o.Anchor {
		t.Fatalf("options = %+v", o)
	}

	t.Setenv("IN_PERSON_VOUCH_REQUIRED", "0")
	if _, err := BuildDependencies("http://localhost:8080/v1/methods/email/verify", ""); err == nil {
		t.Fatal("IN_PERSON_VOUCH_REQUIRED=0: want error")
	}
}
