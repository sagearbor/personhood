package documentchip

import (
	"context"
	"encoding/hex"
	"encoding/json"
	"math/big"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"testing/fstest"
	"time"

	"github.com/sagearbor/personhood/pkg/types"
	"github.com/sagearbor/personhood/src/methods/document-chip/zkproof"
	fes "github.com/sagearbor/personhood/src/methods/fuzzy-extractor-selfie"
)

// The proofs in zkproof/testdata are bound to this challenge and holder DID
// (spikes/zk-passport/bind-fixtures.mjs).
var zkTestChallenge = func() (c [32]byte) {
	for i := range c {
		c[i] = 0x5a
	}
	return c
}()

const zkTestHolder = "did:key:z6MkhaXgBZDvotDkL5257faiztiGiC2QtKLGpbnnEGta2doK"

func zkBB(t *testing.T) string {
	t.Helper()
	if p := os.Getenv("BB"); p != "" {
		return p
	}
	if p, err := exec.LookPath("bb"); err == nil {
		return p
	}
	arch := map[string]string{"arm64": "arm64", "amd64": "amd64"}[runtime.GOARCH]
	osn := map[string]string{"darwin": "macos", "linux": "linux"}[runtime.GOOS]
	for _, dir := range []string{"tools/zk-circuits", "spikes/zk-passport"} {
		p, _ := filepath.Abs(filepath.Join("..", "..", "..", dir, "node_modules", "@aztec", "bb.js", "build", arch+"-"+osn, "bb"))
		if _, err := os.Stat(p); err == nil {
			return p
		}
	}
	t.Skip("bb not found: set BB or npm ci in tools/zk-circuits")
	return ""
}

type zkFixture struct {
	manifest struct {
		Circuits     map[string]string `json:"circuits"`
		RegistryRoot string            `json:"registry_root"`
		CurrentDate  int64             `json:"current_date"`
	}
	vks     map[string][]byte
	payload map[string]any
}

func loadZKFixture(t *testing.T, vector string) *zkFixture {
	t.Helper()
	dir := filepath.Join("zkproof", "testdata", vector)
	raw, err := os.ReadFile(filepath.Join(dir, "manifest.json"))
	if err != nil {
		t.Fatal(err)
	}
	f := &zkFixture{vks: map[string][]byte{}}
	if err := json.Unmarshal(raw, &f.manifest); err != nil {
		t.Fatal(err)
	}
	proofs := map[string]any{}
	for _, st := range zkproof.Stages {
		read := func(n string) []byte {
			b, err := os.ReadFile(filepath.Join(dir, st, n))
			if err != nil {
				t.Fatal(err)
			}
			return b
		}
		name := f.manifest.Circuits[st]
		f.vks[name] = read("vk")
		proofs[st] = zkEncodeSubProof(zkproof.SubProof{Circuit: name, Proof: read("proof"), PublicInputs: read("public_inputs")})
	}
	f.payload = map[string]any{
		"proofs":    proofs,
		"face_bind": map[string]any{"match": true, "liveness": true, "engine": "test"},
	}
	return f
}

type zkCeremony struct {
	m   *ZKMethod
	fix *zkFixture
	now time.Time
}

func newZK(t *testing.T, vector string, cfg Config) *zkCeremony {
	t.Helper()
	fix := loadZKFixture(t, vector)
	if cfg.Trust == nil {
		cfg.Trust = trustOf(t, "rsa-pss", "p256")
	}
	now := time.Unix(fix.manifest.CurrentDate, 0).Add(time.Hour)
	cfg.Now = func() time.Time { return now }
	reg, err := BuildZKRegistry(cfg.Trust, time.Time{})
	if err != nil {
		t.Fatal(err)
	}
	root, _ := new(big.Int).SetString(fix.manifest.RegistryRoot, 0)
	m := NewZKMethod(cfg, ZKConfig{
		BB: zkBB(t), Registry: reg,
		// The fixtures were proved against the spike's one-CSCA registry.
		Roots:     map[[zkproof.FieldSize]byte]bool{zkproof.FieldBytes(root): true},
		Circuits:  &ZKCircuitManifest{Version: 1, Circuits: map[string]ZKCircuitArtifact{}},
		VKs:       fix.vks,
		PublicURL: "https://issuer.example",
	}, nil)
	m.random = func(b []byte) error { copy(b, zkTestChallenge[:]); return nil }
	return &zkCeremony{m: m, fix: fix, now: now}
}

func (c *zkCeremony) cc(session string) types.CeremonyContext {
	return types.CeremonyContext{SessionID: session, HolderDID: types.DID(zkTestHolder), MethodID: ZKMethodID}
}

func (c *zkCeremony) run(t *testing.T, session string, payload map[string]any) types.MethodResult {
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

func clonePayload(p map[string]any) map[string]any {
	b, _ := json.Marshal(p)
	var out map[string]any
	_ = json.Unmarshal(b, &out)
	return out
}

func TestZKMetadata(t *testing.T) {
	c := newZK(t, "rsa-pss", Config{})
	md := c.m.Metadata()
	if md.ID != ZKMethodID || md.Strength != 70 || md.Type != types.MethodTypeAnchor {
		t.Fatalf("metadata %+v", md)
	}
	if ok, _ := c.m.IsAvailableForUser(types.UserContext{Platform: "web"}); ok {
		t.Fatal("web must not be offered the chip")
	}
}

func TestZKBeginPayload(t *testing.T) {
	c := newZK(t, "rsa-pss", Config{FaceBindURL: "https://web.example/face-bind"})
	ch, err := c.m.BeginCeremony(context.Background(), c.cc("s1"))
	if err != nil {
		t.Fatal(err)
	}
	p := ch.Payload
	want := zkproof.BindData(zkTestChallenge, zkTestHolder)
	if p["bind_data_hex"] != hex.EncodeToString(want[:]) {
		t.Fatalf("bind data %v", p["bind_data_hex"])
	}
	scope := zkproof.ServiceScope()
	if p["service_scope"] != "0x"+hex.EncodeToString(scope[:]) {
		t.Fatalf("scope %v", p["service_scope"])
	}
	if p["registry_url"] != "https://issuer.example/v1/methods/document-chip-zk/registry" ||
		p["circuits_url"] != "https://issuer.example/v1/methods/document-chip-zk/circuits" ||
		p["face_bind_url"] != "https://web.example/face-bind" {
		t.Fatalf("urls %+v", p)
	}
	if _, err := c.m.BeginCeremony(context.Background(), types.CeremonyContext{}); err == nil {
		t.Fatal("begin without a session must fail")
	}
}

func TestZKEnrolls(t *testing.T) {
	for _, vector := range []string{"p256", "rsa-pss"} {
		t.Run(vector, func(t *testing.T) {
			c := newZK(t, vector, Config{})
			res := c.run(t, "s-"+vector, c.fix.payload)
			if !res.Success {
				t.Fatalf("refused: %s", res.ErrorReason)
			}
			if !strings.HasPrefix(res.VerifiedIdentifier, "chip:ZK:") || !IsDocumentIdentifier(res.VerifiedIdentifier) {
				t.Fatalf("identifier %q", res.VerifiedIdentifier)
			}
			// Same passport, new session (a re-enrollment): same identifier.
			// The fixture proof is bound to the challenge, which the test
			// random source repeats.
			again := c.run(t, "s2-"+vector, c.fix.payload)
			if !again.Success || again.VerifiedIdentifier != res.VerifiedIdentifier {
				t.Fatalf("re-enrollment: %+v vs %+v", again, res)
			}
		})
	}
}

func TestZKRefusals(t *testing.T) {
	ctx := context.Background()
	cases := []struct {
		name   string
		mut    func(c *zkCeremony, p map[string]any)
		reason string
	}{
		{"no face bind", func(_ *zkCeremony, p map[string]any) { delete(p, "face_bind") }, "face_bind_missing"},
		{"face does not match", func(_ *zkCeremony, p map[string]any) {
			p["face_bind"] = map[string]any{"match": false, "liveness": true}
		}, "face_bind_failed"},
		{"missing stage", func(_ *zkCeremony, p map[string]any) { delete(p["proofs"].(map[string]any), "bind") }, "zk_bundle_malformed"},
		{"short proof", func(_ *zkCeremony, p map[string]any) {
			p["proofs"].(map[string]any)["id"].(map[string]any)["proof_b64"] = "AAAA"
		}, "zk_bundle_malformed"},
		{"circuit not pinned", func(_ *zkCeremony, p map[string]any) {
			p["proofs"].(map[string]any)["dsc"].(map[string]any)["circuit"] = "sig_check_dsc_tbs_700_rsa_pkcs_9999_sha256"
		}, "zk_circuit_unsupported"},
		{"registry root not published", func(c *zkCeremony, _ map[string]any) {
			c.m.verifier.Roots = map[[zkproof.FieldSize]byte]bool{}
		}, "zk_registry_unknown"},
		{"mixed passports", func(_ *zkCeremony, p map[string]any) {
			other := loadZKFixture(t, "p256")
			p["proofs"].(map[string]any)["bind"] = other.payload["proofs"].(map[string]any)["bind"]
		}, "zk_chain_broken"},
		{"clock far off", func(c *zkCeremony, _ map[string]any) {
			later := c.now.Add(72 * time.Hour)
			c.m.verifier.Now = func() time.Time { return later }
		}, "zk_date_stale"},
		{"challenge from another session", func(c *zkCeremony, _ map[string]any) {
			c.m.random = func(b []byte) error { b[0] = 1; return nil }
		}, "zk_bind_mismatch"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			c := newZK(t, "rsa-pss", Config{})
			p := clonePayload(c.fix.payload)
			tc.mut(c, p)
			if res := c.run(t, "s", p); res.Success || res.ErrorReason != tc.reason {
				t.Fatalf("got %+v, want %s", res, tc.reason)
			}
		})
	}

	t.Run("replay without begin", func(t *testing.T) {
		c := newZK(t, "rsa-pss", Config{})
		if res := c.run(t, "s", c.fix.payload); !res.Success {
			t.Fatalf("first: %+v", res)
		}
		res, _ := c.m.CompleteCeremony(ctx, c.cc("s"), types.ResponseData{Payload: c.fix.payload})
		if res.Success || res.ErrorReason != "no_challenge_issued" {
			t.Fatalf("replay: %+v", res)
		}
	})
	t.Run("other holder at complete", func(t *testing.T) {
		c := newZK(t, "rsa-pss", Config{})
		if _, err := c.m.BeginCeremony(ctx, c.cc("s")); err != nil {
			t.Fatal(err)
		}
		cc := c.cc("s")
		cc.HolderDID = "did:key:z6MkOther"
		res, _ := c.m.CompleteCeremony(ctx, cc, types.ResponseData{Payload: c.fix.payload})
		if res.Success || res.ErrorReason != "zk_bind_mismatch" {
			t.Fatalf("got %+v", res)
		}
	})
	t.Run("challenge expired", func(t *testing.T) {
		c := newZK(t, "rsa-pss", Config{})
		if _, err := c.m.BeginCeremony(ctx, c.cc("s")); err != nil {
			t.Fatal(err)
		}
		later := c.now.Add(31 * time.Minute)
		c.m.cfg.Now = func() time.Time { return later }
		res, _ := c.m.CompleteCeremony(ctx, c.cc("s"), types.ResponseData{Payload: c.fix.payload})
		if res.Success || res.ErrorReason != "no_challenge_issued" {
			t.Fatalf("got %+v", res)
		}
	})
}

// A renewed passport has a new SOD and so a new identifier. Its face
// matches the identity enrolled with the old passport: the enrollment goes
// through and a review case is queued (route, never refuse).
func TestZKRenewedPassportRoutesToReview(t *testing.T) {
	faces := fes.NewInMemoryAccumulator()
	q := &InMemoryReviewQueue{}
	tmpl := template(7)
	helper, commitment, err := fes.Gen(tmpl)
	if err != nil {
		t.Fatal(err)
	}
	if err := faces.Add(context.Background(), fes.EnrollmentRecord{Helper: helper, Commitment: commitment}); err != nil {
		t.Fatal(err)
	}
	c := newZK(t, "rsa-pss", Config{
		Faces: faces, Reviews: q,
		KnownIdentifier: func(context.Context, string) (bool, error) { return false, nil },
	})
	p := clonePayload(c.fix.payload)
	p["face_template_b64"] = b64(tmpl)
	res := c.run(t, "renewal", p)
	if !res.Success {
		t.Fatalf("renewed passport refused: %+v", res)
	}
	cases, _ := q.List(context.Background())
	if len(cases) != 1 || cases[0].MethodID != ZKMethodID || cases[0].DocumentCountry != "ZK" {
		t.Fatalf("review cases %+v", cases)
	}
}

func TestZKRegistryFromMasterList(t *testing.T) {
	ts, _, err := DefaultTrust()
	if err != nil {
		t.Fatal(err)
	}
	reg, err := BuildZKRegistry(ts, time.Time{})
	if err != nil {
		t.Fatal(err)
	}
	if len(reg.Certificates)+reg.Skipped != ts.Len() || len(reg.Certificates) < 500 {
		t.Fatalf("%d leaves + %d skipped of %d CSCAs", len(reg.Certificates), reg.Skipped, ts.Len())
	}
	again, _ := BuildZKRegistry(ts, time.Time{})
	if again.Root != reg.Root {
		t.Fatal("registry root is not deterministic")
	}
	seen := map[string]bool{}
	for i, c := range reg.Certificates {
		if c.Index != i || len(c.Country) != 3 {
			t.Fatalf("leaf %d: %+v", i, c)
		}
		seen[c.SubjectCountry+">"+c.Country] = true
	}
	for _, want := range []string{"US>USA", "DE>D<<", "FR>FRA", "IN>IND", "GB>GBR"} {
		if !seen[want] {
			t.Errorf("no leaf mapping %s", want)
		}
	}
	// Leaves rebuild to the published root (what the wallet does).
	leaves := make([]*big.Int, len(reg.Certificates))
	for i, c := range reg.Certificates {
		leaves[i], _ = new(big.Int).SetString(c.Leaf, 0)
	}
	tree := zkproof.NewCertificateTree(leaves)
	root := zkproof.RegistryRoot(ZKRegistrySchemaVersion, reg.Timestamp, tree.Root(), new(big.Int), new(big.Int))
	if zkproof.FieldHex(root) != reg.Root {
		t.Fatal("leaves do not rebuild the root")
	}
	t.Logf("registry: %d leaves, %d skipped, root %s", len(reg.Certificates), reg.Skipped, reg.Root)
}

// The test CSCA's leaf matches what the spike's (zkPassport-built) dsc
// inputs used: same country, key bytes and expiry.
func TestZKRegistryLeafMatchesSpike(t *testing.T) {
	reg, err := BuildZKRegistry(trustOf(t, "p256"), time.Time{})
	if err != nil {
		t.Fatal(err)
	}
	raw, _ := os.ReadFile("zkproof/testdata/p256/dsc.inputs.json")
	var in struct {
		Country string `json:"country"`
		Expiry  uint32 `json:"csc_expiry"`
		X       []int  `json:"csc_pubkey_x"`
	}
	if err := json.Unmarshal(raw, &in); err != nil {
		t.Fatal(err)
	}
	c := reg.Certificates[0]
	x := make([]byte, len(in.X))
	for i, v := range in.X {
		x[i] = byte(v)
	}
	if c.Country != in.Country || c.Expiry != in.Expiry || c.PublicKey.X != "0x"+hex.EncodeToString(x) || c.PublicKey.Curve != "P-256" {
		t.Fatalf("leaf %+v vs spike country %s expiry %d", c, in.Country, in.Expiry)
	}
}

func TestZKAcceptedRoots(t *testing.T) {
	cur := [zkproof.FieldSize]byte{1}
	roots, err := ZKAcceptedRoots(cur, time.Now(), "0x2", " ")
	if err != nil {
		t.Fatal(err)
	}
	two := [zkproof.FieldSize]byte{}
	two[31] = 2
	if !roots[cur] || !roots[two] || len(roots) < 2 {
		t.Fatalf("roots %v", roots)
	}
	if _, err := ZKAcceptedRoots(cur, time.Now(), "not-a-number"); err == nil {
		t.Fatal("bad extra root accepted")
	}
}

func TestZKHTTPHandlers(t *testing.T) {
	c := newZK(t, "rsa-pss", Config{})
	c.m.zk.Circuits = &ZKCircuitManifest{
		Version: 1,
		SRS:     map[string]ZKArtifact{"g1": {File: "bn254_g1.dat", SHA256: "x"}},
		Circuits: map[string]ZKCircuitArtifact{
			"bind": {File: "bind.json.gz", SHA256: "y"},
		},
	}
	c.m.zk.ArtifactsDir = fstest.MapFS{
		"bind.json.gz":   {Data: []byte("gz")},
		"secret.txt":     {Data: []byte("no")},
		"bn254_g1.dat":   {Data: []byte("srs")},
		"other.json.gz":  {Data: []byte("no")},
		"../escape.json": {Data: []byte("no")},
	}
	get := func(h http.Handler, path string) *httptest.ResponseRecorder {
		rr := httptest.NewRecorder()
		h.ServeHTTP(rr, httptest.NewRequest(http.MethodGet, path, nil))
		return rr
	}
	if rr := get(c.m.RegistryHandler(), "/registry"); rr.Code != 200 || !strings.Contains(rr.Body.String(), c.m.zk.Registry.Root) {
		t.Fatalf("registry: %d %s", rr.Code, rr.Body.String()[:80])
	}
	rr := get(c.m.CircuitsHandler(), "/circuits")
	if rr.Code != 200 || !strings.Contains(rr.Body.String(), `"base_url":"https://issuer.example/v1/methods/document-chip-zk/artifacts/"`) {
		t.Fatalf("circuits: %s", rr.Body.String())
	}
	art := c.m.ArtifactsHandler()
	if rr := get(art, "/v1/methods/document-chip-zk/artifacts/bind.json.gz"); rr.Code != 200 || rr.Body.String() != "gz" {
		t.Fatalf("artifact: %d", rr.Code)
	}
	for _, p := range []string{"/artifacts/secret.txt", "/artifacts/other.json.gz", "/artifacts/..%2Fescape.json"} {
		if rr := get(art, p); rr.Code != 404 {
			t.Fatalf("%s served: %d", p, rr.Code)
		}
	}
	if m := MissingZKArtifacts(c.m.zk.ArtifactsDir, c.m.zk.Circuits); len(m) != 2 {
		t.Fatalf("hash mismatches not reported: %v", m)
	}
}
