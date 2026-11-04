package socialvouching

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/sagearbor/personhood/pkg/types"
)

const testIssuer = "did:web:issuer.test"

// fakeVerifier accepts a credential of the form {"pub":"<b64>","anchor":"<id>","anchored_at":"<rfc3339>"}.
type fakeVerifier struct{}

func (fakeVerifier) VerifyVoucherCredential(_ context.Context, raw json.RawMessage) (VoucherStanding, error) {
	var c struct {
		Pub        string    `json:"pub"`
		Anchor     string    `json:"anchor"`
		AnchoredAt time.Time `json:"anchored_at"`
	}
	if err := json.Unmarshal(raw, &c); err != nil || c.Pub == "" {
		return VoucherStanding{}, fmt.Errorf("%w: bad fake credential", ErrVoucherCredentialInvalid)
	}
	pub, _ := base64.StdEncoding.DecodeString(c.Pub)
	did, _ := testDID(pub)
	return VoucherStanding{DID: did, PublicKey: pub, AnchorMethodID: c.Anchor, AnchorVerifiedAt: c.AnchoredAt}, nil
}

func testDID(pub ed25519.PublicKey) (string, error) {
	return "did:key:test" + hex.EncodeToString(pub), nil
}

type clock struct {
	mu sync.Mutex
	t  time.Time
}

func (c *clock) Now() time.Time      { c.mu.Lock(); defer c.mu.Unlock(); return c.t }
func (c *clock) Add(d time.Duration) { c.mu.Lock(); c.t = c.t.Add(d); c.mu.Unlock() }

type person struct {
	pub  ed25519.PublicKey
	priv ed25519.PrivateKey
	did  string
}

func newPerson(t *testing.T) person {
	t.Helper()
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	did, _ := testDID(pub)
	return person{pub, priv, did}
}

func (p person) cred(anchor string, at time.Time) json.RawMessage {
	b, _ := json.Marshal(map[string]any{"pub": base64.StdEncoding.EncodeToString(p.pub), "anchor": anchor, "anchored_at": at})
	return b
}

type harness struct {
	t     *testing.T
	ip    *InPerson
	graph *InMemoryGraphStore
	store *InMemoryInPersonStore
	clk   *clock
	srv   map[string]http.HandlerFunc
	// remoteIP is what ClientIP reports for the next request.
	remoteIP string
}

func newHarness(t *testing.T, mutate func(*InPersonConfig)) *harness {
	t.Helper()
	h := &harness{t: t, graph: NewInMemoryGraphStore(nil), store: NewInMemoryInPersonStore(),
		clk: &clock{t: time.Date(2026, 11, 3, 12, 0, 0, 0, time.UTC)}, remoteIP: "203.0.113.5"}
	cfg := InPersonConfig{
		Graph: h.graph, Store: h.store, Verifier: fakeVerifier{}, IssuerDID: testIssuer,
		DIDForKey: testDID, Now: h.clk.Now, Required: 1,
		ClientIP: func(*http.Request) string { return h.remoteIP },
	}
	if mutate != nil {
		mutate(&cfg)
	}
	h.ip = NewInPerson(cfg)
	h.srv = map[string]http.HandlerFunc{
		"offer": h.ip.OfferHandler(), "accept": h.ip.AcceptHandler(),
		"confirm": h.ip.ConfirmHandler(), "status": h.ip.StatusHandler(),
	}
	return h
}

func (h *harness) post(route string, body any) (int, map[string]any) {
	h.t.Helper()
	b, _ := json.Marshal(body)
	rec := httptest.NewRecorder()
	h.srv[route](rec, httptest.NewRequest(http.MethodPost, "/"+route, bytes.NewReader(b)))
	var out map[string]any
	_ = json.Unmarshal(rec.Body.Bytes(), &out)
	return rec.Code, out
}

func (h *harness) status(code string) map[string]any {
	rec := httptest.NewRecorder()
	h.srv["status"](rec, httptest.NewRequest(http.MethodGet, "/status?code="+code, nil))
	var out map[string]any
	_ = json.Unmarshal(rec.Body.Bytes(), &out)
	return out
}

func errCode(out map[string]any) string {
	e, _ := out["error"].(map[string]any)
	s, _ := e["code"].(string)
	return s
}

func (h *harness) offer(voucher person, anchor string) (int, map[string]any) {
	return h.post("offer", map[string]any{"credential": voucher.cred(anchor, h.clk.Now().Add(-365*24*time.Hour))})
}

func (h *harness) accept(candidate person, code string) (int, map[string]any) {
	sig := ed25519.Sign(candidate.priv, []byte(AcceptMessage(testIssuer, code, candidate.did)))
	return h.post("accept", map[string]any{
		"offer_code":               code,
		"candidate_public_key_b64": base64.StdEncoding.EncodeToString(candidate.pub),
		"signature_b64":            base64.StdEncoding.EncodeToString(sig),
	})
}

func (h *harness) confirm(voucher person, code, candidateDID, ret string) (int, map[string]any) {
	sig := ed25519.Sign(voucher.priv, []byte(ConfirmMessage(testIssuer, code, candidateDID, ret)))
	return h.post("confirm", map[string]any{"offer_code": code, "return_code": ret, "signature_b64": base64.StdEncoding.EncodeToString(sig)})
}

// vouch runs the whole ceremony and fails the test unless it records.
func (h *harness) vouch(voucher, candidate person, anchor string) map[string]any {
	h.t.Helper()
	st, out := h.offer(voucher, anchor)
	if st != 200 {
		h.t.Fatalf("offer: %d %v", st, out)
	}
	code := out["offer_code"].(string)
	if out["qr_text"] != QRPrefixOffer+code {
		h.t.Fatalf("qr_text = %v", out["qr_text"])
	}
	st, acc := h.accept(candidate, code)
	if st != 200 {
		h.t.Fatalf("accept: %d %v", st, acc)
	}
	if s := h.status(code); s["state"] != OfferAccepted || s["candidate_did"] != candidate.did {
		h.t.Fatalf("status after accept = %v", s)
	}
	h.clk.Add(20 * time.Second)
	st, conf := h.confirm(voucher, code, candidate.did, acc["return_code"].(string))
	if st != 200 {
		h.t.Fatalf("confirm: %d %v", st, conf)
	}
	return conf
}

func (h *harness) completeAnchor(candidate person) types.MethodResult {
	h.t.Helper()
	res, err := NewAnchorMethod(h.ip).CompleteCeremony(context.Background(),
		types.CeremonyContext{SessionID: "s", HolderDID: types.DID(candidate.did)}, types.ResponseData{})
	if err != nil {
		h.t.Fatal(err)
	}
	return res
}

func TestInPerson_HappyPathMakesAnchor(t *testing.T) {
	h := newHarness(t, func(c *InPersonConfig) { c.Required = 2 })
	a, b, newcomer := newPerson(t), newPerson(t), newPerson(t)

	conf := h.vouch(a, newcomer, "fuzzy-extractor-selfie")
	if conf["same_network"] != true || conf["round_trip_ms"].(float64) != 20000 || conf["candidate_vouches"].(float64) != 1 {
		t.Fatalf("confirm evidence = %v", conf)
	}
	if r := h.completeAnchor(newcomer); r.Success || r.ErrorReason != "insufficient_vouches:have=1/2" {
		t.Fatalf("after 1 vouch: %+v", r)
	}
	h.vouch(b, newcomer, "government-id-liveness")
	r := h.completeAnchor(newcomer)
	if !r.Success || r.AttestationDigest == "" || r.MethodID != InPersonMethodID {
		t.Fatalf("after 2 vouches: %+v", r)
	}
	// The vouches also feed the supplementary graph.
	gv, _ := h.graph.VouchesFor(context.Background(), newcomer.did)
	if len(gv) != 2 {
		t.Fatalf("graph vouches = %d, want 2", len(gv))
	}
	// And a social-vouching-graph ceremony now passes on them.
	m := NewMethod(Config{Store: h.graph, Authenticator: RejectAllAuthenticator{}, RequiredVouches: 2, RequiredScore: 1.5})
	gr, _ := m.CompleteCeremony(context.Background(), types.CeremonyContext{SessionID: "s", HolderDID: types.DID(newcomer.did)}, types.ResponseData{})
	if !gr.Success {
		t.Fatalf("graph method: %+v", gr)
	}
}

func TestInPerson_AnchorMetadataValidates(t *testing.T) {
	h := newHarness(t, nil)
	md := NewAnchorMethod(h.ip).Metadata()
	if err := md.Validate(); err != nil || md.Type != types.MethodTypeAnchor || md.ID != "in-person-vouch" {
		t.Fatalf("metadata %+v: %v", md, err)
	}
}

func TestInPerson_BeginNeedsHolderKey(t *testing.T) {
	h := newHarness(t, nil)
	if _, err := NewAnchorMethod(h.ip).BeginCeremony(context.Background(), types.CeremonyContext{SessionID: "s", HolderDID: "did:personhood:holder:ab"}); err == nil {
		t.Fatal("begin without a did:key holder: want error")
	}
}

func TestInPerson_AcceptRejectsBadSignatureAndSelfVouch(t *testing.T) {
	h := newHarness(t, nil)
	a, newcomer := newPerson(t), newPerson(t)
	_, out := h.offer(a, "x")
	code := out["offer_code"].(string)

	st, res := h.post("accept", map[string]any{
		"offer_code":               code,
		"candidate_public_key_b64": base64.StdEncoding.EncodeToString(newcomer.pub),
		"signature_b64":            base64.StdEncoding.EncodeToString(ed25519.Sign(newcomer.priv, []byte("something else"))),
	})
	if st != 401 || errCode(res) != "signature_invalid" {
		t.Fatalf("bad signature: %d %v", st, res)
	}
	if st, res := h.accept(a, code); st != 400 || errCode(res) != "self_vouch_not_allowed" {
		t.Fatalf("self vouch: %d %v", st, res)
	}
	if st, res := h.accept(newcomer, "ZZZZZZZZ"); st != 404 || errCode(res) != "offer_not_found" {
		t.Fatalf("unknown code: %d %v", st, res)
	}
}

func TestInPerson_Deadlines(t *testing.T) {
	h := newHarness(t, nil)
	a, newcomer := newPerson(t), newPerson(t)

	_, out := h.offer(a, "x")
	h.clk.Add(DefaultOfferTTL + time.Second)
	if st, res := h.accept(newcomer, out["offer_code"].(string)); st != 410 || errCode(res) != "offer_expired" {
		t.Fatalf("late accept: %d %v", st, res)
	}

	_, out = h.offer(a, "x")
	code := out["offer_code"].(string)
	_, acc := h.accept(newcomer, code)
	h.clk.Add(DefaultReturnTTL + time.Second)
	if s := h.status(code); s["state"] != "expired" {
		t.Fatalf("status = %v", s)
	}
	if st, res := h.confirm(a, code, newcomer.did, acc["return_code"].(string)); st != 410 || errCode(res) != "offer_expired" {
		t.Fatalf("late confirm: %d %v", st, res)
	}
}

func TestInPerson_WrongReturnCodeBurnsOffer(t *testing.T) {
	h := newHarness(t, nil)
	a, newcomer := newPerson(t), newPerson(t)
	_, out := h.offer(a, "x")
	code := out["offer_code"].(string)
	_, acc := h.accept(newcomer, code)
	for i := 0; i < maxReturnCodeAttempts; i++ {
		if st, res := h.confirm(a, code, newcomer.did, "00000000"); st != 401 || errCode(res) != "return_code_wrong" {
			t.Fatalf("attempt %d: %d %v", i, st, res)
		}
	}
	if st, res := h.confirm(a, code, newcomer.did, acc["return_code"].(string)); st != 409 || errCode(res) != "offer_used" {
		t.Fatalf("after burn: %d %v", st, res)
	}
}

func TestInPerson_ConfirmSignatureMustBeVouchers(t *testing.T) {
	h := newHarness(t, nil)
	a, mallory, newcomer := newPerson(t), newPerson(t), newPerson(t)
	_, out := h.offer(a, "x")
	code := out["offer_code"].(string)
	_, acc := h.accept(newcomer, code)
	if st, res := h.confirm(mallory, code, newcomer.did, acc["return_code"].(string)); st != 401 || errCode(res) != "signature_invalid" {
		t.Fatalf("confirm by someone else: %d %v", st, res)
	}
	// The real voucher can still finish, once.
	if st, res := h.confirm(a, code, newcomer.did, acc["return_code"].(string)); st != 200 {
		t.Fatalf("confirm: %d %v", st, res)
	}
	if st, res := h.confirm(a, code, newcomer.did, acc["return_code"].(string)); st != 409 || errCode(res) != "offer_used" {
		t.Fatalf("replayed confirm: %d %v", st, res)
	}
}

func TestInPerson_QuotaPerPeriod(t *testing.T) {
	h := newHarness(t, func(c *InPersonConfig) { c.MaxPerPeriod = 1; c.Period = 24 * time.Hour })
	a, n1, n2 := newPerson(t), newPerson(t), newPerson(t)
	h.vouch(a, n1, "x")
	if st, res := h.offer(a, "x"); st != 403 || errCode(res) != "quota_exhausted" {
		t.Fatalf("second offer: %d %v", st, res)
	}
	h.clk.Add(24 * time.Hour)
	h.vouch(a, n2, "x")
}

func TestInPerson_QuotaIsCheckedAtCommit(t *testing.T) {
	// Two offers opened while one vouch is left: only the first confirm wins.
	h := newHarness(t, func(c *InPersonConfig) { c.MaxPerPeriod = 1 })
	a, n1, n2 := newPerson(t), newPerson(t), newPerson(t)
	_, o1 := h.offer(a, "x")
	_, o2 := h.offer(a, "x")
	_, a1 := h.accept(n1, o1["offer_code"].(string))
	_, a2 := h.accept(n2, o2["offer_code"].(string))
	if st, _ := h.confirm(a, o1["offer_code"].(string), n1.did, a1["return_code"].(string)); st != 200 {
		t.Fatal("first confirm failed")
	}
	if st, res := h.confirm(a, o2["offer_code"].(string), n2.did, a2["return_code"].(string)); st != 403 || errCode(res) != "quota_exhausted" {
		t.Fatalf("second confirm: %d %v", st, res)
	}
}

func TestInPerson_VoucherEligibility(t *testing.T) {
	h := newHarness(t, func(c *InPersonConfig) { c.MinVoucherAge = 30 * 24 * time.Hour })
	unanchored, graphMember, fresh, newcomer := newPerson(t), newPerson(t), newPerson(t), newPerson(t)

	if st, res := h.offer(unanchored, ""); st != 403 || errCode(res) != "voucher_not_eligible" {
		t.Fatalf("no anchor, no score: %d %v", st, res)
	}
	st, res := h.post("offer", map[string]any{"credential": fresh.cred("x", h.clk.Now().Add(-24*time.Hour))})
	if st != 403 || errCode(res) != "voucher_too_new" {
		t.Fatalf("fresh anchor: %d %v", st, res)
	}
	if st, res := h.post("offer", map[string]any{"credential": json.RawMessage(`{}`)}); st != 401 || errCode(res) != "credential_invalid" {
		t.Fatalf("bad credential: %d %v", st, res)
	}

	// A graph member with a high score may vouch, but that vouch is not an
	// anchored one and never counts toward the anchor.
	_ = h.graph.Enroll(context.Background(), graphMember.did, 0.75)
	conf := h.vouch(graphMember, newcomer, "")
	if conf["voucher_anchored"] != false || conf["weight"].(float64) != 0.75 {
		t.Fatalf("graph voucher confirm = %v", conf)
	}
	if r := h.completeAnchor(newcomer); r.Success {
		t.Fatal("anchor granted on a non-anchored vouch")
	}
	_ = h.graph.Enroll(context.Background(), graphMember.did, 0.4)
	if st, res := h.offer(graphMember, ""); st != 403 || errCode(res) != "voucher_not_eligible" {
		t.Fatalf("low score: %d %v", st, res)
	}
}

func TestInPerson_RequireSameNetwork(t *testing.T) {
	h := newHarness(t, func(c *InPersonConfig) { c.RequireSameNetwork = true })
	a, newcomer := newPerson(t), newPerson(t)
	_, out := h.offer(a, "x")
	code := out["offer_code"].(string)
	h.remoteIP = "198.51.100.7"
	_, acc := h.accept(newcomer, code)
	h.remoteIP = "203.0.113.9"
	if st, res := h.confirm(a, code, newcomer.did, acc["return_code"].(string)); st != 403 || errCode(res) != "not_same_network" {
		t.Fatalf("different networks: %d %v", st, res)
	}
	h.remoteIP = "198.51.100.200" // same /24 as the accept
	if st, res := h.confirm(a, code, newcomer.did, acc["return_code"].(string)); st != 200 || res["same_network"] != true {
		t.Fatalf("same network: %d %v", st, res)
	}
}

func TestInPerson_PenalizeCascade(t *testing.T) {
	h := newHarness(t, func(c *InPersonConfig) { c.Required = 1; c.MaxPerPeriod = 5 })
	ctx := context.Background()
	anchored, graphMember, fake, other := newPerson(t), newPerson(t), newPerson(t), newPerson(t)
	_ = h.graph.Enroll(ctx, graphMember.did, 0.8)

	h.vouch(anchored, fake, "x")
	h.vouch(graphMember, fake, "")
	h.vouch(anchored, other, "x")
	if r := h.completeAnchor(fake); !r.Success {
		t.Fatalf("fake's anchor before penalty: %+v", r)
	}
	_ = h.graph.Enroll(ctx, fake.did, 0.6) // fake graduated into the graph

	rep, err := h.ip.Penalize(ctx, fake.did)
	if err != nil {
		t.Fatal(err)
	}
	if rep.AlreadyRevoked || rep.Vouchers[anchored.did] != 1 || rep.Vouchers[graphMember.did] != 1 || len(rep.Vouchers) != 2 {
		t.Fatalf("report = %+v", rep)
	}

	// The fake loses its anchor, its graph membership, and cannot be vouched again.
	if r := h.completeAnchor(fake); r.Success || r.ErrorReason != "candidate_revoked" {
		t.Fatalf("fake's anchor after penalty: %+v", r)
	}
	if _, known, _ := h.graph.TrustOf(ctx, fake.did); known {
		t.Fatal("fake still in the graph")
	}
	_, out := h.offer(newPerson(t), "x")
	if st, res := h.accept(fake, out["offer_code"].(string)); st != 403 || errCode(res) != "candidate_revoked" {
		t.Fatalf("re-vouching the fake: %d %v", st, res)
	}

	// The vouchers are suspended and their scores drop.
	if st, res := h.offer(anchored, "x"); st != 403 || errCode(res) != "voucher_suspended" {
		t.Fatalf("anchored voucher offer: %d %v", st, res)
	}
	if tr, _, _ := h.graph.TrustOf(ctx, graphMember.did); tr != 0.4 {
		t.Fatalf("graph voucher trust = %v, want 0.4", tr)
	}
	// The innocent "other" person keeps the vouch it got from the suspended voucher.
	if r := h.completeAnchor(other); !r.Success {
		t.Fatalf("other's anchor: %+v", r)
	}

	// After the suspension, the anchored voucher's weight is halved.
	h.clk.Add(DefaultSuspendFor + time.Hour)
	if conf := h.vouch(anchored, newPerson(t), "x"); conf["weight"].(float64) != 0.5 {
		t.Fatalf("weight after one strike = %v", conf["weight"])
	}

	// Penalizing twice changes nothing.
	rep2, err := h.ip.Penalize(ctx, fake.did)
	if err != nil || !rep2.AlreadyRevoked || len(rep2.Vouchers) != 0 {
		t.Fatalf("second penalize = %+v, %v", rep2, err)
	}
	if rec, _ := h.store.Voucher(ctx, anchored.did); rec.Strikes != 1 {
		t.Fatalf("strikes = %d, want 1", rec.Strikes)
	}

}

func TestInPerson_VouchesExpire(t *testing.T) {
	h := newHarness(t, nil)
	a, newcomer := newPerson(t), newPerson(t)
	h.vouch(a, newcomer, "x")
	h.clk.Add(DefaultVouchValidity + time.Hour)
	if r := h.completeAnchor(newcomer); r.Success {
		t.Fatal("stale vouch still counts")
	}
}

func TestNormalizeCode(t *testing.T) {
	cases := map[string]string{
		"ABCD1234":         "ABCD1234",
		"abcd-1234":        "ABCD1234",
		" PHV1:O:abcd1234": "ABCD1234",
		"PHV1:R:ABCD1234":  "ABCD1234",
		"oIl0 0000":        "0110" + "0000",
		"ABCD123":          "",
		"ABCDU234":         "",
		"ABCD12345":        "",
	}
	for in, want := range cases {
		if got := NormalizeCode(in); got != want {
			t.Errorf("NormalizeCode(%q) = %q, want %q", in, got, want)
		}
	}
	for i := 0; i < 50; i++ {
		c, err := newCode()
		if err != nil || NormalizeCode(c) != c {
			t.Fatalf("newCode %q does not normalize to itself", c)
		}
	}
}

func TestMessagesAreStable(t *testing.T) {
	// app/web/lib/vouch.ts builds the same strings; keep them in sync.
	if got := AcceptMessage("did:web:i", "ABCD1234", "did:key:z6M"); got != "personhood-in-person-vouch/v1\naccept\ndid:web:i\nABCD1234\ndid:key:z6M" {
		t.Fatalf("AcceptMessage = %q", got)
	}
	want := "personhood-in-person-vouch/v1\nvouch\ndid:web:i\nABCD1234\ndid:key:z6M\nWXYZ5678\n" + VouchStatement
	if got := ConfirmMessage("did:web:i", "ABCD1234", "did:key:z6M", "WXYZ5678"); got != want {
		t.Fatalf("ConfirmMessage = %q", got)
	}
	if !strings.Contains(VouchStatement, "face to face") {
		t.Fatal("statement changed")
	}
}
