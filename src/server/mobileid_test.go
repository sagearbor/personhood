package server

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/sagearbor/personhood/pkg/types"
	documentchip "github.com/sagearbor/personhood/src/methods/document-chip"
	"github.com/sagearbor/personhood/src/methods/document-chip/mdoczk"
)

const mobileIDVector = "../methods/document-chip/mdoczk/testdata/specimen"

// setMobileIDEnv writes the specimen IACA (test issuer, no real issuer) to
// a PEM file and points MOBILE_ID_IACA_PEM at it.
func setMobileIDEnv(t *testing.T) string {
	t.Helper()
	setDocumentEnv(t)
	t.Setenv("MOBILE_ID_ZK", "1")
	var v struct {
		IACAPEM string `json:"iaca_pem"`
	}
	raw, err := os.ReadFile(filepath.Join(mobileIDVector, "vector.json"))
	if err != nil {
		t.Fatal(err)
	}
	_ = json.Unmarshal(raw, &v)
	p := filepath.Join(t.TempDir(), "iaca.pem")
	if err := os.WriteFile(p, []byte(v.IACAPEM), 0o600); err != nil {
		t.Fatal(err)
	}
	t.Setenv("MOBILE_ID_IACA_PEM", p)
	return p
}

func TestBuildDependencies_MobileIDNeedsDocumentAnchor(t *testing.T) {
	t.Setenv("DOCUMENT_CHIP_ANCHOR", "")
	t.Setenv("DOCUMENT_CHIP_ZK", "")
	t.Setenv("MOBILE_ID_ZK", "1")
	if _, err := BuildDependencies("http://example.invalid/v1/methods/email/verify", ""); err == nil {
		t.Fatal("MOBILE_ID_ZK=1 without DOCUMENT_CHIP_ANCHOR=1 must fail at startup")
	}
}

func TestBuildDependencies_MobileIDOffByDefault(t *testing.T) {
	setDocumentEnv(t)
	t.Setenv("MOBILE_ID_ZK", "")
	deps, err := BuildDependencies("http://example.invalid/v1/methods/email/verify", "")
	if err != nil {
		t.Fatal(err)
	}
	if _, ok := deps.Registry.Get(documentchip.MobileIDMethodID); ok {
		t.Fatal("mobile-id-zk registered without MOBILE_ID_ZK=1")
	}
	for _, r := range deps.MethodRoutes {
		if r.MethodID == documentchip.MobileIDMethodID {
			t.Fatalf("mobile-id route %s mounted while off", r.Path)
		}
	}
}

func TestBuildDependencies_MobileIDNeedsIACAs(t *testing.T) {
	setMobileIDEnv(t)
	t.Setenv("MOBILE_ID_ZK_BB", zkTestBB(t))
	t.Setenv("MOBILE_ID_IACA_PEM", "")
	if _, err := BuildDependencies("http://example.invalid/v1/methods/email/verify", ""); err == nil {
		t.Fatal("MOBILE_ID_ZK=1 without MOBILE_ID_IACA_PEM must fail at startup")
	}
	empty := filepath.Join(t.TempDir(), "empty.pem")
	_ = os.WriteFile(empty, []byte("nothing"), 0o600)
	t.Setenv("MOBILE_ID_IACA_PEM", empty)
	if _, err := BuildDependencies("http://example.invalid/v1/methods/email/verify", ""); err == nil {
		t.Fatal("MOBILE_ID_ZK=1 with no usable IACA must fail at startup")
	}
}

// TestIntegration_MobileID_Wiring runs the issuer with MOBILE_ID_ZK=1 over
// HTTP: the method is offered as an anchor of strength 75, the registry and
// circuit manifest are served, begin hands out a nonce, and a valid proof
// made for another session is refused as mdoc_session_mismatch.
func TestIntegration_MobileID_Wiring(t *testing.T) {
	setMobileIDEnv(t)
	t.Setenv("MOBILE_ID_ZK_BB", zkTestBB(t))
	t.Setenv("MOBILE_ID_ZK_ARTIFACTS_DIR", t.TempDir())
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
	m, ok := deps.Registry.Get(documentchip.MobileIDMethodID)
	if !ok || m.Metadata().Strength != 75 || m.Metadata().Type != types.MethodTypeAnchor {
		t.Fatal("mobile-id-zk not registered as an anchor of strength 75")
	}
	if identifierKindForMethod(documentchip.MobileIDMethodID) != identifierKindDocument {
		t.Fatal("mobile-id-zk does not feed the document identifier store")
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
	var reg mdoczk.Registry
	getJSON("/v1/methods/mobile-id-zk/registry", &reg)
	if len(reg.Entries) != 1 || reg.Entries[0].Jurisdiction != "UT" {
		t.Fatalf("registry %+v", reg)
	}
	var mf documentchip.ZKCircuitManifest
	getJSON("/v1/methods/mobile-id-zk/circuits", &mf)
	if mf.BaseURL != base+"/v1/methods/mobile-id-zk/artifacts/" || mf.Circuits["mdoc_p256_msg_2048"].File == "" {
		t.Fatalf("manifest %+v", mf)
	}

	var start startEnrollmentResponse
	mustPOST(t, base+"/enrollment/start", mustJSON(t, map[string]any{}), &start)
	found := false
	for _, am := range start.AvailableMethods {
		found = found || am.ID == documentchip.MobileIDMethodID
	}
	if !found {
		t.Fatalf("mobile-id-zk not offered: %+v", start.AvailableMethods)
	}
	var begin beginMethodResponse
	mustPOST(t, base+"/v1/methods/mobile-id-zk/begin", mustJSON(t, map[string]any{"session_id": start.SessionID, "user_input": ""}), &begin)
	if s, _ := begin.Challenge.Payload["nonce_hex"].(string); len(s) != 64 {
		t.Fatalf("nonce %v", begin.Challenge.Payload["nonce_hex"])
	}
	var v struct {
		Circuit string `json:"circuit"`
		EncInfo string `json:"encryption_info_b64u"`
		Origin  string `json:"origin"`
	}
	raw, _ := os.ReadFile(filepath.Join(mobileIDVector, "vector.json"))
	_ = json.Unmarshal(raw, &v)
	p, _ := os.ReadFile(filepath.Join(mobileIDVector, "proof"))
	pi, _ := os.ReadFile(filepath.Join(mobileIDVector, "public_inputs"))
	var complete completeMethodResponse
	mustPOST(t, base+"/v1/methods/mobile-id-zk/complete", mustJSON(t, map[string]any{
		"session_id": start.SessionID,
		"response": types.ResponseData{Type: documentchip.MobileIDMethodID, Payload: map[string]any{
			"proof":                map[string]any{"circuit": v.Circuit, "proof_b64": base64.StdEncoding.EncodeToString(p), "public_inputs_b64": base64.StdEncoding.EncodeToString(pi)},
			"handover":             "dcapi",
			"encryption_info_b64u": v.EncInfo,
			"origin":               v.Origin,
			"face_bind":            map[string]any{"match": true, "liveness": true},
		}},
	}), &complete)
	if complete.Result.Success || complete.Result.ErrorReason != "mdoc_session_mismatch" {
		t.Fatalf("proof from another session: %+v", complete.Result)
	}
}
