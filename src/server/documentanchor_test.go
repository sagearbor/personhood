package server

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"

	"github.com/sagearbor/personhood/pkg/types"
	documentchip "github.com/sagearbor/personhood/src/methods/document-chip"
)

const docVectors = "../methods/document-chip/icao/testdata"

func setDocumentEnv(t *testing.T) {
	t.Setenv("DOCUMENT_CHIP_ANCHOR", "1")
	t.Setenv(IdentifierKeyEnv, base64.StdEncoding.EncodeToString(make([]byte, 32)))
	t.Setenv("DOCUMENT_CHIP_CSCA_PEM", filepath.Join(docVectors, "p256", "csca.pem"))
	t.Setenv("DOCUMENT_CHIP_ALLOW_PASSIVE_ONLY", "1")
	t.Setenv("FIRESTORE_PROJECT_ID", "")
	t.Setenv("REDIS_URL", "")
}

func TestBuildDependencies_DocumentAnchorOff(t *testing.T) {
	t.Setenv("DOCUMENT_CHIP_ANCHOR", "")
	deps, err := BuildDependencies("http://example.invalid/v1/methods/email/verify", "")
	if err != nil {
		t.Fatal(err)
	}
	if _, ok := deps.Registry.Get(documentchip.ChipMethodID); ok {
		t.Fatal("document-chip registered without DOCUMENT_CHIP_ANCHOR=1")
	}
}

func TestBuildDependencies_DocumentAnchorNeedsIdentifierKey(t *testing.T) {
	setDocumentEnv(t)
	t.Setenv(IdentifierKeyEnv, "")
	if _, err := BuildDependencies("http://example.invalid/v1/methods/email/verify", ""); err == nil {
		t.Fatal("DOCUMENT_CHIP_ANCHOR=1 without IDENTIFIER_HMAC_KEY must fail at startup")
	}
}

// TestIntegration_DocumentChip_OneDocumentOneIdentity enrolls the same
// (specimen) passport twice through the HTTP API and requires the same
// nullifier commitment both times: re-enrolling is a re-issue, not a new
// person.
func TestIntegration_DocumentChip_OneDocumentOneIdentity(t *testing.T) {
	setDocumentEnv(t)
	deps, err := BuildDependencies("http://example.invalid/v1/methods/email/verify", "")
	if err != nil {
		t.Fatal(err)
	}
	for _, id := range []string{documentchip.ChipMethodID, documentchip.QRMethodID} {
		m, ok := deps.Registry.Get(id)
		if !ok || m.Metadata().Type != types.MethodTypeAnchor {
			t.Fatalf("%s not registered as an anchor", id)
		}
	}
	listener, err := newLocalListener()
	if err != nil {
		t.Fatal(err)
	}
	_, priv, _ := ed25519.GenerateKey(rand.Reader)
	key := make([]byte, 32)
	srv, err := NewServer(Config{
		Addr:              listener.Addr().String(),
		PublicURL:         "http://" + listener.Addr().String(),
		IssuerPrivateKey:  priv,
		SessionTTL:        10 * time.Minute,
		IdentifierHMACKey: key,
	}, deps)
	if err != nil {
		t.Fatal(err)
	}
	httpServer := &http.Server{Handler: srv.Router()}
	go func() { _ = httpServer.Serve(listener) }()
	defer httpServer.Close()
	base := "http://" + listener.Addr().String()

	read := func(name string) string {
		b, err := os.ReadFile(filepath.Join(docVectors, "p256", name))
		if err != nil {
			t.Fatal(err)
		}
		return base64.StdEncoding.EncodeToString(b)
	}
	enroll := func() string {
		var start startEnrollmentResponse
		mustPOST(t, base+"/enrollment/start", mustJSON(t, map[string]any{}), &start)
		var begin beginMethodResponse
		mustPOST(t, base+"/v1/methods/document-chip/begin", mustJSON(t, map[string]any{"session_id": start.SessionID, "user_input": ""}), &begin)
		if begin.Challenge.Payload["aa_challenge_hex"] == nil {
			t.Fatalf("begin payload %+v", begin.Challenge.Payload)
		}
		var complete completeMethodResponse
		mustPOST(t, base+"/v1/methods/document-chip/complete", mustJSON(t, map[string]any{
			"session_id": start.SessionID,
			"response": types.ResponseData{Type: "document-chip", Payload: map[string]any{
				"sod_b64":   read("EF.SOD"),
				"dg1_b64":   read("EF.DG1"),
				"face_bind": map[string]any{"match": true, "liveness": true},
			}},
		}), &complete)
		if !complete.Result.Success {
			t.Fatalf("complete: %+v", complete.Result)
		}
		var issued issueCredentialResponse
		mustPOST(t, base+"/v1/credentials/issue", mustJSON(t, map[string]any{"session_id": start.SessionID}), &issued)
		subj := issued.Credential.CredentialSubject
		if subj.AnchorMethodID == nil || *subj.AnchorMethodID != documentchip.ChipMethodID {
			t.Fatalf("anchor = %v", subj.AnchorMethodID)
		}
		if subj.NullifierBinding == nil {
			t.Fatal("no nullifier binding")
		}
		return subj.NullifierBinding.Commitment
	}
	first, second := enroll(), enroll()
	if first != second {
		t.Fatalf("same document, different commitments: %s vs %s", first, second)
	}
}

func TestBuildDependencies_ZKNeedsDocumentAnchor(t *testing.T) {
	t.Setenv("DOCUMENT_CHIP_ANCHOR", "")
	t.Setenv("DOCUMENT_CHIP_ZK", "1")
	if _, err := BuildDependencies("http://example.invalid/v1/methods/email/verify", ""); err == nil {
		t.Fatal("DOCUMENT_CHIP_ZK=1 without DOCUMENT_CHIP_ANCHOR=1 must fail at startup")
	}
}

func TestBuildDependencies_ZKOffByDefault(t *testing.T) {
	setDocumentEnv(t)
	t.Setenv("DOCUMENT_CHIP_ZK", "")
	deps, err := BuildDependencies("http://example.invalid/v1/methods/email/verify", "")
	if err != nil {
		t.Fatal(err)
	}
	if _, ok := deps.Registry.Get(documentchip.ZKMethodID); ok {
		t.Fatal("document-chip-zk registered without DOCUMENT_CHIP_ZK=1")
	}
	for _, r := range deps.MethodRoutes {
		if r.MethodID == documentchip.ZKMethodID {
			t.Fatalf("zk route %s mounted while off", r.Path)
		}
	}
}

func TestBuildDependencies_ZKNeedsBB(t *testing.T) {
	setDocumentEnv(t)
	t.Setenv("DOCUMENT_CHIP_ZK", "1")
	t.Setenv("DOCUMENT_CHIP_ZK_BB", filepath.Join(t.TempDir(), "no-such-bb"))
	if _, err := BuildDependencies("http://example.invalid/v1/methods/email/verify", ""); err == nil {
		t.Fatal("DOCUMENT_CHIP_ZK=1 without a bb binary must fail at startup")
	}
}

func zkTestBB(t *testing.T) string {
	t.Helper()
	if p := os.Getenv("BB"); p != "" {
		return p
	}
	arch := map[string]string{"arm64": "arm64", "amd64": "amd64"}[runtime.GOARCH]
	osn := map[string]string{"darwin": "macos", "linux": "linux"}[runtime.GOOS]
	p, _ := filepath.Abs(filepath.Join("..", "..", "tools", "zk-circuits", "node_modules", "@aztec", "bb.js", "build", arch+"-"+osn, "bb"))
	if _, err := os.Stat(p); err != nil {
		t.Skip("bb not found: set BB or npm ci in tools/zk-circuits")
	}
	return p
}

// TestIntegration_DocumentChipZK_Wiring runs the issuer with
// DOCUMENT_CHIP_ZK=1 over HTTP: the method is offered, the registry and
// circuit manifest are served, begin hands out bind data, and a valid proof
// bundle made for a different session is refused as zk_bind_mismatch (the
// session binding at work). A full prove-and-enroll run is
// tools/zk-circuits/e2e.sh.
func TestIntegration_DocumentChipZK_Wiring(t *testing.T) {
	setDocumentEnv(t)
	t.Setenv("DOCUMENT_CHIP_ZK", "1")
	t.Setenv("DOCUMENT_CHIP_ZK_BB", zkTestBB(t))
	t.Setenv("DOCUMENT_CHIP_ZK_ARTIFACTS_DIR", t.TempDir())
	// The fixture proofs used the spike's one-CSCA registry root.
	var fixRoot struct {
		Root string `json:"registry_root"`
	}
	rawRoot, _ := os.ReadFile("../methods/document-chip/zkproof/testdata/rsa-pss/manifest.json")
	_ = json.Unmarshal(rawRoot, &fixRoot)
	t.Setenv("DOCUMENT_CHIP_ZK_EXTRA_ROOTS", fixRoot.Root)
	listener, err := newLocalListener()
	if err != nil {
		t.Fatal(err)
	}
	base := "http://" + listener.Addr().String()
	t.Setenv("SERVER_PUBLIC_URL", base)
	deps, err := BuildDependencies("http://example.invalid/v1/methods/email/verify", "")
	if err != nil {
		t.Fatal(err)
	}
	m, ok := deps.Registry.Get(documentchip.ZKMethodID)
	if !ok || m.Metadata().Strength != 70 || m.Metadata().Type != types.MethodTypeAnchor {
		t.Fatal("document-chip-zk not registered as a strength-70 anchor")
	}
	_, priv, _ := ed25519.GenerateKey(rand.Reader)
	srv, err := NewServer(Config{
		Addr: listener.Addr().String(), PublicURL: base, IssuerPrivateKey: priv,
		SessionTTL: 10 * time.Minute, IdentifierHMACKey: make([]byte, 32),
	}, deps)
	if err != nil {
		t.Fatal(err)
	}
	httpServer := &http.Server{Handler: srv.Router()}
	go func() { _ = httpServer.Serve(listener) }()
	defer httpServer.Close()

	getJSON := func(path string, out any) {
		t.Helper()
		resp, err := http.Get(base + path)
		if err != nil {
			t.Fatal(err)
		}
		defer resp.Body.Close()
		if resp.StatusCode != 200 {
			t.Fatalf("GET %s: %d", path, resp.StatusCode)
		}
		if err := json.NewDecoder(resp.Body).Decode(out); err != nil {
			t.Fatal(err)
		}
	}
	var reg documentchip.ZKRegistry
	getJSON("/v1/methods/document-chip-zk/registry", &reg)
	if len(reg.Certificates) < 500 || !strings.HasPrefix(reg.Root, "0x") {
		t.Fatalf("registry: %d leaves, root %q", len(reg.Certificates), reg.Root)
	}
	var mf documentchip.ZKCircuitManifest
	getJSON("/v1/methods/document-chip-zk/circuits", &mf)
	if mf.BaseURL != base+"/v1/methods/document-chip-zk/artifacts/" || mf.Circuits["bind"].File == "" {
		t.Fatalf("manifest base %q, %d circuits", mf.BaseURL, len(mf.Circuits))
	}

	var start startEnrollmentResponse
	mustPOST(t, base+"/enrollment/start", mustJSON(t, map[string]any{}), &start)
	found := false
	for _, am := range start.AvailableMethods {
		found = found || am.ID == documentchip.ZKMethodID
	}
	if !found {
		t.Fatalf("document-chip-zk not offered: %+v", start.AvailableMethods)
	}
	var begin beginMethodResponse
	mustPOST(t, base+"/v1/methods/document-chip-zk/begin", mustJSON(t, map[string]any{"session_id": start.SessionID, "user_input": ""}), &begin)
	if s, _ := begin.Challenge.Payload["bind_data_hex"].(string); len(s) != 2*509 {
		t.Fatalf("bind data %v", begin.Challenge.Payload["bind_data_hex"])
	}
	proofs := map[string]any{}
	dir := "../methods/document-chip/zkproof/testdata/rsa-pss"
	var fm struct {
		Circuits map[string]string `json:"circuits"`
	}
	raw, _ := os.ReadFile(filepath.Join(dir, "manifest.json"))
	_ = json.Unmarshal(raw, &fm)
	for _, st := range []string{"dsc", "id", "integrity", "bind"} {
		p, _ := os.ReadFile(filepath.Join(dir, st, "proof"))
		pi, _ := os.ReadFile(filepath.Join(dir, st, "public_inputs"))
		proofs[st] = map[string]any{"circuit": fm.Circuits[st], "proof_b64": base64.StdEncoding.EncodeToString(p), "public_inputs_b64": base64.StdEncoding.EncodeToString(pi)}
	}
	var complete completeMethodResponse
	mustPOST(t, base+"/v1/methods/document-chip-zk/complete", mustJSON(t, map[string]any{
		"session_id": start.SessionID,
		"response": types.ResponseData{Type: documentchip.ZKMethodID, Payload: map[string]any{
			"proofs": proofs, "face_bind": map[string]any{"match": true, "liveness": true},
		}},
	}), &complete)
	if complete.Result.Success || complete.Result.ErrorReason != "zk_bind_mismatch" {
		t.Fatalf("bundle from another session: %+v", complete.Result)
	}
}
