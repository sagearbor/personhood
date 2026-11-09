package documentchip

import (
	"context"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"math/big"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/sagearbor/personhood/pkg/types"
	"github.com/sagearbor/personhood/src/methods/document-chip/mdoczk"
	"github.com/sagearbor/personhood/src/methods/document-chip/zkproof"
	fes "github.com/sagearbor/personhood/src/methods/fuzzy-extractor-selfie"
)

// The fixtures (mdoczk/testdata/specimen*) are proofs of a specimen licence
// from the test issuer (Utopia, no real person), made by
// spikes/mobile-id/prove.mjs with the pinned mdoc_p256_msg_2048 circuit for
// the session challenge SHA-256("mdoc-test") and holder "session:mdoc-test".

type mobileVector struct {
	Challenge   string          `json:"challenge_hex"`
	Holder      string          `json:"holder"`
	Handover    string          `json:"handover"`
	EncInfo     string          `json:"encryption_info_b64u"`
	Origin      string          `json:"origin"`
	Thumbprint  string          `json:"jwk_thumbprint_hex"`
	Now         string          `json:"now"`
	IACAPEM     string          `json:"iaca_pem"`
	Expected    string          `json:"expected_nullifier"`
	Circuit     string          `json:"circuit"`
	Registry    mdoczk.Registry `json:"registry"`
	proof, pubs []byte
}

func loadMobileVector(t *testing.T, dir string) *mobileVector {
	t.Helper()
	base := filepath.Join("mdoczk", "testdata", dir)
	raw, err := os.ReadFile(filepath.Join(base, "vector.json"))
	if err != nil {
		t.Fatal(err)
	}
	var v mobileVector
	if err := json.Unmarshal(raw, &v); err != nil {
		t.Fatal(err)
	}
	if v.proof, err = os.ReadFile(filepath.Join(base, "proof")); err != nil {
		t.Fatal(err)
	}
	if v.pubs, err = os.ReadFile(filepath.Join(base, "public_inputs")); err != nil {
		t.Fatal(err)
	}
	return &v
}

type mobileCeremony struct {
	m   *MobileIDMethod
	v   *mobileVector
	now time.Time
}

func newMobile(t *testing.T, dir string, cfg Config, mod func(*MobileIDConfig)) *mobileCeremony {
	t.Helper()
	v := loadMobileVector(t, dir)
	now, err := time.Parse("2006-01-02T15:04:05Z", v.Now)
	if err != nil {
		t.Fatal(err)
	}
	now = now.Add(10 * time.Minute)
	cfg.Now = func() time.Time { return now }
	certs, _ := mdoczk.ParsePEMCertificates([]byte(v.IACAPEM))
	reg, err := mdoczk.BuildRegistry(certs, nil)
	if err != nil {
		t.Fatal(err)
	}
	if reg.Root != v.Registry.Root {
		t.Fatalf("registry root %s, fixture %s", reg.Root, v.Registry.Root)
	}
	circuits, vks, err := LoadMobileIDCircuits()
	if err != nil {
		t.Fatal(err)
	}
	mc := MobileIDConfig{
		BB: zkBB(t), Registry: reg, Roots: map[[zkproof.FieldSize]byte]bool{reg.RootBytes(): true},
		Circuits: circuits, VKs: vks, PublicURL: "https://issuer.example",
	}
	if mod != nil {
		mod(&mc)
	}
	m := NewMobileIDMethod(cfg, mc, nil)
	ch, _ := hex.DecodeString(v.Challenge)
	m.random = func(b []byte) error { copy(b, ch); return nil }
	return &mobileCeremony{m: m, v: v, now: now}
}

// The fixtures' holder is "session:mdoc-test": session "mdoc-test", no DID.
func (c *mobileCeremony) cc(session string) types.CeremonyContext {
	return types.CeremonyContext{SessionID: session, MethodID: MobileIDMethodID}
}

func (c *mobileCeremony) payload() map[string]any {
	p := map[string]any{
		"proof": map[string]any{
			"circuit":           c.v.Circuit,
			"proof_b64":         base64.StdEncoding.EncodeToString(c.v.proof),
			"public_inputs_b64": base64.StdEncoding.EncodeToString(c.v.pubs),
		},
		"handover":  c.v.Handover,
		"origin":    c.v.Origin,
		"face_bind": map[string]any{"match": true, "liveness": true},
	}
	if c.v.Handover == "dcapi" {
		p["encryption_info_b64u"] = c.v.EncInfo
	} else if c.v.Thumbprint != "" {
		b, _ := hex.DecodeString(c.v.Thumbprint)
		p["jwk_thumbprint_b64u"] = base64.RawURLEncoding.EncodeToString(b)
	}
	return p
}

func (c *mobileCeremony) run(t *testing.T, session string, payload map[string]any) types.MethodResult {
	t.Helper()
	if _, err := c.m.BeginCeremony(context.Background(), c.cc(session)); err != nil {
		t.Fatal(err)
	}
	res, err := c.m.CompleteCeremony(context.Background(), c.cc(session), types.ResponseData{Payload: payload})
	if err != nil {
		t.Fatal(err)
	}
	return res
}

func TestMobileIDEnrolls(t *testing.T) {
	for _, dir := range []string{"specimen", "specimen-oid4vp"} {
		t.Run(dir, func(t *testing.T) {
			c := newMobile(t, dir, Config{}, nil)
			res := c.run(t, "mdoc-test", c.payload())
			if !res.Success {
				t.Fatalf("refused: %+v", res)
			}
			want, _ := new(big.Int).SetString(c.v.Expected, 0)
			wb := zkproof.FieldBytes(want)
			wantID := "mdoc:ZK:" + hex.EncodeToString(wb[:])
			if res.VerifiedIdentifier != wantID || res.Strength != MobileIDStrength {
				t.Fatalf("identifier %s strength %d, want %s", res.VerifiedIdentifier, res.Strength, wantID)
			}
			if !IsDocumentIdentifier(res.VerifiedIdentifier) {
				t.Fatal("identifier is not a document identifier")
			}
		})
	}
}

func TestMobileIDBeginPayload(t *testing.T) {
	c := newMobile(t, "specimen", Config{}, nil)
	ch, err := c.m.BeginCeremony(context.Background(), c.cc("mdoc-test"))
	if err != nil {
		t.Fatal(err)
	}
	p := ch.Payload
	var chal [32]byte
	b, _ := hex.DecodeString(c.v.Challenge)
	copy(chal[:], b)
	n := mdoczk.Nonce(chal, "session:mdoc-test")
	if p["nonce_hex"] != hex.EncodeToString(n[:]) || p["registry_root"] != c.m.mc.Registry.Root {
		t.Fatalf("payload %+v", p)
	}
	for _, k := range []string{"registry_url", "circuits_url", "documents", "handovers", "service_scope"} {
		if p[k] == nil {
			t.Fatalf("payload lacks %s", k)
		}
	}
	if !strings.HasSuffix(p["registry_url"].(string), "/v1/methods/mobile-id-zk/registry") {
		t.Fatal(p["registry_url"])
	}
}

func TestMobileIDRefusals(t *testing.T) {
	flip := func(field string, i int) func(map[string]any) {
		return func(p map[string]any) {
			pr := p["proof"].(map[string]any)
			b, _ := base64.StdEncoding.DecodeString(pr[field].(string))
			b[i] ^= 1
			pr[field] = base64.StdEncoding.EncodeToString(b)
		}
	}
	cases := []struct {
		name    string
		dir     string
		mutate  func(map[string]any)
		setup   func(*mobileCeremony)
		cfg     func(*MobileIDConfig)
		session string
		want    string
	}{
		{name: "proof byte flipped", mutate: flip("proof_b64", 500), want: "mdoc_proof_invalid"},
		{name: "nullifier rewritten", mutate: flip("public_inputs_b64", 7*32+31), want: "mdoc_proof_invalid"},
		{name: "registry root rewritten", mutate: flip("public_inputs_b64", 31), want: "mdoc_registry_unknown"},
		{name: "scope rewritten", mutate: flip("public_inputs_b64", 6*32+31), want: "mdoc_scope_mismatch"},
		{name: "another session's challenge", setup: func(c *mobileCeremony) {
			c.m.random = func(b []byte) error { b[0] = 1; return nil }
		}, want: "mdoc_session_mismatch"},
		{name: "another holder (session)", session: "other-session", want: "mdoc_session_mismatch"},
		{name: "encryption info rewritten", mutate: func(p map[string]any) {
			p["encryption_info_b64u"] = base64.RawURLEncoding.EncodeToString(mdoczk.EncryptionInfo([32]byte{1}, mdoczk.Map{}))
		}, want: "mdoc_session_mismatch"},
		{name: "another origin", mutate: func(p map[string]any) { p["origin"] = "android:apk-key-hash:other" }, want: "mdoc_session_mismatch"},
		{name: "origin not allowed", cfg: func(mc *MobileIDConfig) { mc.AllowedOrigins = []string{"android:apk-key-hash:ours"} }, want: "mdoc_origin_not_allowed"},
		{name: "openid4vp claimed for a dcapi proof", mutate: func(p map[string]any) { p["handover"] = "openid4vp" }, want: "mdoc_session_mismatch"},
		{name: "openid4vp thumbprint changed", dir: "specimen-oid4vp", mutate: func(p map[string]any) {
			p["jwk_thumbprint_b64u"] = base64.RawURLEncoding.EncodeToString(make([]byte, 32))
		}, want: "mdoc_session_mismatch"},
		{name: "unknown handover", mutate: func(p map[string]any) { p["handover"] = "nfc" }, want: "mdoc_bundle_malformed"},
		{name: "unpinned circuit", mutate: func(p map[string]any) { p["proof"].(map[string]any)["circuit"] = "mdoc_p256_msg_9999" }, want: "mdoc_circuit_unsupported"},
		{name: "passport circuit name", mutate: func(p map[string]any) { p["proof"].(map[string]any)["circuit"] = "bind" }, want: "mdoc_circuit_unsupported"},
		{name: "doc type not accepted", cfg: func(mc *MobileIDConfig) {
			mc.DocTypes = map[string]string{"eu.europa.ec.eudi.pid.1": "eu.europa.ec.eudi.pid.1"}
		}, want: "mdoc_doc_type_unsupported"},
		{name: "phone clock 3 days off", setup: func(c *mobileCeremony) {
			later := c.now.Add(72 * time.Hour)
			c.m.verifier.Now = func() time.Time { return later }
			c.m.cfg.Now = func() time.Time { return later }
		}, want: "mdoc_date_stale"},
		{name: "no proof", mutate: func(p map[string]any) { delete(p, "proof") }, want: "mdoc_bundle_malformed"},
		{name: "proof truncated", mutate: func(p map[string]any) {
			p["proof"].(map[string]any)["proof_b64"] = base64.StdEncoding.EncodeToString(make([]byte, 100))
		}, want: "mdoc_bundle_malformed"},
		{name: "face bind missing", mutate: func(p map[string]any) { delete(p, "face_bind") }, want: "face_bind_missing"},
		{name: "face bind failed", mutate: func(p map[string]any) { p["face_bind"] = map[string]any{"match": false, "liveness": true} }, want: "face_bind_failed"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			dir := tc.dir
			if dir == "" {
				dir = "specimen"
			}
			c := newMobile(t, dir, Config{}, tc.cfg)
			if tc.setup != nil {
				tc.setup(c)
			}
			p := clonePayload(c.payload())
			if tc.mutate != nil {
				tc.mutate(p)
			}
			session := tc.session
			if session == "" {
				session = "mdoc-test"
			}
			res := c.run(t, session, p)
			if res.Success || res.ErrorReason != tc.want {
				t.Fatalf("got %+v, want %s", res, tc.want)
			}
		})
	}
}

func TestMobileIDChallengeAnswersOnce(t *testing.T) {
	c := newMobile(t, "specimen", Config{}, nil)
	if res := c.run(t, "mdoc-test", c.payload()); !res.Success {
		t.Fatalf("refused: %+v", res)
	}
	res, err := c.m.CompleteCeremony(context.Background(), c.cc("mdoc-test"), types.ResponseData{Payload: c.payload()})
	if err != nil || res.Success || res.ErrorReason != "no_challenge_issued" {
		t.Fatalf("replay: %+v %v", res, err)
	}
}

// A person who enrolled with a passport (or another licence) and now
// arrives with a mobile ID: the credential is issued and a review case is
// queued (routed, never refused).
func TestMobileIDSameFaceAnotherDocumentRoutesToReview(t *testing.T) {
	faces := fes.NewInMemoryAccumulator()
	q := &InMemoryReviewQueue{}
	tmpl := template(9)
	helper, commitment, err := fes.Gen(tmpl)
	if err != nil {
		t.Fatal(err)
	}
	if err := faces.Add(context.Background(), fes.EnrollmentRecord{Helper: helper, Commitment: commitment}); err != nil {
		t.Fatal(err)
	}
	c := newMobile(t, "specimen", Config{
		Faces: faces, Reviews: q,
		KnownIdentifier: func(context.Context, string) (bool, error) { return false, nil },
	}, nil)
	p := c.payload()
	p["face_template_b64"] = b64(tmpl)
	if res := c.run(t, "mdoc-test", p); !res.Success {
		t.Fatalf("refused: %+v", res)
	}
	cases, _ := q.List(context.Background())
	if len(cases) != 1 || cases[0].MethodID != MobileIDMethodID || cases[0].DocumentCountry != "MDOC" {
		t.Fatalf("review cases %+v", cases)
	}
}

// With a DigestKey the attestation digest depends only on the licence, so
// RECOVERY_DOCUMENT_METHODS can name mobile-id-zk; both fixtures are the
// same specimen licence (number and jurisdiction), presented in different
// ways under different IACA keys.
func TestMobileIDStableDigestForRecovery(t *testing.T) {
	key := func(mc *MobileIDConfig) { mc.DigestKey = []byte("test digest key") }
	a := newMobile(t, "specimen", Config{}, key)
	b := newMobile(t, "specimen-oid4vp", Config{}, key)
	ra := a.run(t, "mdoc-test", a.payload())
	rb := b.run(t, "mdoc-test", b.payload())
	if !ra.Success || !rb.Success || ra.AttestationDigest != rb.AttestationDigest || ra.VerifiedIdentifier != rb.VerifiedIdentifier {
		t.Fatalf("%+v\n%+v", ra, rb)
	}
	c := newMobile(t, "specimen", Config{}, nil)
	if rc := c.run(t, "mdoc-test", c.payload()); rc.AttestationDigest == ra.AttestationDigest {
		t.Fatal("unkeyed digest equals the keyed one")
	}
}

func TestMobileIDHTTPHandlers(t *testing.T) {
	c := newMobile(t, "specimen", Config{}, nil)
	rec := httptest.NewRecorder()
	c.m.RegistryHandler().ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/registry", nil))
	var reg mdoczk.Registry
	if err := json.Unmarshal(rec.Body.Bytes(), &reg); err != nil || reg.Root != c.m.mc.Registry.Root || len(reg.Entries) != 1 || reg.Entries[0].Jurisdiction != "UT" {
		t.Fatalf("registry %s %v", rec.Body.String(), err)
	}
	rec = httptest.NewRecorder()
	c.m.CircuitsHandler().ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/circuits", nil))
	var mf ZKCircuitManifest
	if err := json.Unmarshal(rec.Body.Bytes(), &mf); err != nil || mf.Circuits["mdoc_p256_msg_2048"].Gates == 0 ||
		mf.BaseURL != "https://issuer.example/v1/methods/mobile-id-zk/artifacts/" {
		t.Fatalf("circuits %s %v", rec.Body.String(), err)
	}
	rec = httptest.NewRecorder()
	c.m.ArtifactsHandler().ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/artifacts/../../etc/passwd", nil))
	if rec.Code != http.StatusNotFound {
		t.Fatal("served an unlisted file")
	}
}

func TestMobileIDMetadataAndAvailability(t *testing.T) {
	c := newMobile(t, "specimen", Config{}, nil)
	md := c.m.Metadata()
	if md.ID != MobileIDMethodID || md.Strength != 75 || md.Type != types.MethodTypeAnchor {
		t.Fatalf("%+v", md)
	}
	if ok, _ := c.m.IsAvailableForUser(types.UserContext{Platform: "web"}); ok {
		t.Fatal("offered on web")
	}
	if ok, _ := c.m.IsAvailableForUser(types.UserContext{Platform: "android"}); !ok {
		t.Fatal("not offered on android")
	}
}
