// Package tests holds end-to-end tests that run against a REAL server
// process — the compiled src/server binary listening on a loopback port —
// rather than an in-process httptest handler. They would fail if the
// deployable artifact were broken even when unit tests pass.
//
// Run with:  cd tests && go test -race -count=1 ./...
// (scripts/test-all.sh includes this module; CI runs it on every PR.)
package tests

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/sagearbor/personhood/pkg/types"
)

// TestE2E_EmailOnlyEnrollment is the round-1 path a friend takes: start a
// session, request a magic link, click it (we scrape it from the server log,
// standing in for the inbox), poll the session, issue the credential, and
// verify it with tools/verify-credential exactly as an integrator would.
func TestE2E_EmailOnlyEnrollment(t *testing.T) {
	if testing.Short() {
		t.Skip("e2e: skipped in -short mode")
	}
	root := repoRoot(t)
	work := t.TempDir()

	// 1. Build the real binaries.
	serverBin := filepath.Join(work, "personhood-server")
	verifyBin := filepath.Join(work, "verify-credential")
	goBuild(t, filepath.Join(root, "src", "server"), serverBin, "./cmd/server")
	goBuild(t, filepath.Join(root, "tools", "verify-credential"), verifyBin, ".")

	// 2. Start the server on a free loopback port with the LogSender and
	//    WITHOUT DEV_EXPOSE_CHALLENGE_SECRETS — the production posture.
	port := freePort(t)
	base := fmt.Sprintf("http://127.0.0.1:%d", port)
	seed := genKey(t, filepath.Join(root, "src", "server"))

	logBuf := &syncBuffer{}
	cmd := exec.Command(serverBin)
	cmd.Env = append(os.Environ(),
		"ISSUER_ED25519_SK_B64="+seed,
		fmt.Sprintf("SERVER_ADDR=127.0.0.1:%d", port),
		"SERVER_PUBLIC_URL="+base,
		"CORS_ALLOWED_ORIGINS=http://localhost:3000",
		"DEV_EXPOSE_CHALLENGE_SECRETS=",
	)
	cmd.Stdout = logBuf
	cmd.Stderr = logBuf
	if err := cmd.Start(); err != nil {
		t.Fatalf("start server: %v", err)
	}
	t.Cleanup(func() {
		_ = cmd.Process.Kill()
		_, _ = cmd.Process.Wait()
		if t.Failed() {
			t.Logf("--- server log ---\n%s", logBuf.String())
		}
	})
	waitHealthy(t, base)

	// 3. Methods: email must be registered.
	var methods struct {
		Methods []struct {
			ID string `json:"id"`
		} `json:"methods"`
	}
	getJSON(t, base+"/v1/methods", &methods)
	ids := make([]string, 0, len(methods.Methods))
	for _, m := range methods.Methods {
		ids = append(ids, m.ID)
	}
	if !contains(ids, "email") {
		t.Fatalf("email method not registered; have %v", ids)
	}
	t.Logf("methods: %v", ids)

	// 4. Start enrollment.
	var start struct {
		SessionID string    `json:"session_id"`
		HolderDID types.DID `json:"holder_did"`
		IssuerDID types.DID `json:"issuer_did"`
	}
	postJSON(t, base+"/enrollment/start", map[string]any{"platform": "e2e"}, &start)
	if start.SessionID == "" {
		t.Fatal("empty session_id")
	}

	// 5. Begin email; the client response must NOT carry the magic link.
	var begin struct {
		Challenge types.ChallengeData `json:"challenge"`
	}
	raw := postJSON(t, base+"/v1/methods/email/begin",
		map[string]any{"session_id": start.SessionID, "user_input": "friend@example.com"}, &begin)
	if begin.Challenge.Type != "magic-link" {
		t.Fatalf("expected magic-link challenge, got %q", begin.Challenge.Type)
	}
	if bytes.Contains(raw, []byte("magic_link_url")) {
		t.Fatalf("SECURITY: /begin leaked magic_link_url to the client: %s", raw)
	}

	// 6. Scrape the link from the server log — that is where LogSender
	//    "delivers" it; a real deployment emails it.
	link := waitForLink(t, logBuf)
	t.Logf("magic link: %s", link)

	// 7. Session shows nothing verified before the click, email after.
	var view struct {
		VerifiedMethods []types.VerifiedMethod `json:"verified_methods"`
	}
	getJSON(t, base+"/v1/sessions/"+start.SessionID, &view)
	if len(view.VerifiedMethods) != 0 {
		t.Fatalf("expected no verified methods before click: %+v", view.VerifiedMethods)
	}
	resp, err := http.Get(link)
	if err != nil {
		t.Fatalf("click link: %v", err)
	}
	body, _ := io.ReadAll(resp.Body)
	resp.Body.Close()
	if resp.StatusCode != 200 || !strings.Contains(string(body), "Email verified") {
		t.Fatalf("magic-link landing: %d %s", resp.StatusCode, body)
	}
	getJSON(t, base+"/v1/sessions/"+start.SessionID, &view)
	if len(view.VerifiedMethods) != 1 || view.VerifiedMethods[0].MethodID != "email" {
		t.Fatalf("expected email verified after click: %+v", view.VerifiedMethods)
	}

	// 8. Issue.
	var issued struct {
		Credential json.RawMessage `json:"credential"`
	}
	postJSON(t, base+"/v1/credentials/issue", map[string]any{"session_id": start.SessionID}, &issued)
	credPath := filepath.Join(work, "credential.json")
	if err := os.WriteFile(credPath, issued.Credential, 0o600); err != nil {
		t.Fatal(err)
	}
	var cred types.PersonhoodCredential
	if err := json.Unmarshal(issued.Credential, &cred); err != nil {
		t.Fatalf("decode credential: %v", err)
	}
	if cred.Issuer != start.IssuerDID || cred.CredentialSubject.ID != start.HolderDID {
		t.Fatalf("issuer/holder mismatch: %+v", cred)
	}
	if cred.Proof == nil || cred.Proof.ProofValue == "" {
		t.Fatal("credential has no proof")
	}

	// 9. Verify as an integrator would, trusting the issuer via its did.json.
	policies := filepath.Join(root, "docs", "policies")
	out, code := runVerify(t, verifyBin, credPath, filepath.Join(policies, "round1-email.yaml"), base)
	if code != 0 || !out.OK || out.Code != types.EvalOK {
		t.Fatalf("round1-email.yaml should accept the credential: exit=%d %+v", code, out)
	}
	t.Logf("round1-email.yaml: ok (issuer %s)", out.Issuer)

	out, code = runVerify(t, verifyBin, credPath, filepath.Join(policies, "default-floor.yaml"), base)
	if code != 1 || out.OK || out.Code != types.EvalAnchorMissing {
		t.Fatalf("default-floor.yaml should reject with anchor_missing: exit=%d %+v", code, out)
	}
	t.Logf("default-floor.yaml: rejected with %s (expected until an anchor ships)", out.Code)

	// 10. Tamper → signature_invalid.
	tampered := bytes.Replace(issued.Credential, []byte(`"strength":8`), []byte(`"strength":99`), 1)
	if bytes.Equal(tampered, issued.Credential) {
		t.Fatal("tamper substitution did not apply; credential JSON shape changed?")
	}
	tamperedPath := filepath.Join(work, "tampered.json")
	_ = os.WriteFile(tamperedPath, tampered, 0o600)
	out, code = runVerify(t, verifyBin, tamperedPath, filepath.Join(policies, "round1-email.yaml"), base)
	if code != 1 || out.Code != types.EvalSignatureInvalid {
		t.Fatalf("tampered credential should be signature_invalid: exit=%d %+v", code, out)
	}

	// 11. Second issue on the same session is refused.
	req, _ := http.NewRequest(http.MethodPost, base+"/v1/credentials/issue",
		strings.NewReader(fmt.Sprintf(`{"session_id":%q}`, start.SessionID)))
	req.Header.Set("Content-Type", "application/json")
	resp2, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	resp2.Body.Close()
	if resp2.StatusCode != http.StatusConflict {
		t.Fatalf("second issue: want 409, got %d", resp2.StatusCode)
	}
}

// ---------------------------------------------------------------------------
// helpers
// ---------------------------------------------------------------------------

type verifyOutput struct {
	OK        bool                 `json:"ok"`
	Code      types.EvaluationCode `json:"code"`
	Human     string               `json:"human"`
	Issuer    types.DID            `json:"issuer"`
	Nullifier string               `json:"nullifier,omitempty"`
}

func runVerify(t *testing.T, bin, cred, policy, issuerURL string) (verifyOutput, int) {
	t.Helper()
	cmd := exec.Command(bin, "-cred", cred, "-policy", policy, "-issuer-url", issuerURL)
	var stdout, stderr bytes.Buffer
	cmd.Stdout, cmd.Stderr = &stdout, &stderr
	err := cmd.Run()
	code := 0
	if ee, ok := err.(*exec.ExitError); ok {
		code = ee.ExitCode()
	} else if err != nil {
		t.Fatalf("run verify: %v\n%s", err, stderr.String())
	}
	var out verifyOutput
	if stdout.Len() > 0 {
		if err := json.Unmarshal(stdout.Bytes(), &out); err != nil {
			t.Fatalf("decode verify output: %v\n%s", err, stdout.String())
		}
	} else {
		t.Fatalf("verify produced no output (exit %d): %s", code, stderr.String())
	}
	return out, code
}

func repoRoot(t *testing.T) string {
	t.Helper()
	wd, err := os.Getwd()
	if err != nil {
		t.Fatal(err)
	}
	root := filepath.Dir(wd) // tests/ -> repo root
	if _, err := os.Stat(filepath.Join(root, "go.work")); err != nil {
		t.Fatalf("repo root not found from %s: %v", wd, err)
	}
	return root
}

func goBuild(t *testing.T, dir, out, pkg string) {
	t.Helper()
	cmd := exec.Command("go", "build", "-o", out, pkg)
	cmd.Dir = dir
	if b, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("go build %s in %s: %v\n%s", pkg, dir, err, b)
	}
}

func genKey(t *testing.T, serverDir string) string {
	t.Helper()
	cmd := exec.Command("go", "run", "./cmd/gen-key")
	cmd.Dir = serverDir
	b, err := cmd.Output()
	if err != nil {
		t.Fatalf("gen-key: %v", err)
	}
	for _, line := range strings.Split(string(b), "\n") {
		if strings.HasPrefix(line, "ISSUER_ED25519_SK_B64=") {
			return strings.TrimPrefix(line, "ISSUER_ED25519_SK_B64=")
		}
	}
	t.Fatalf("gen-key printed no ISSUER_ED25519_SK_B64 line:\n%s", b)
	return ""
}

func freePort(t *testing.T) int {
	t.Helper()
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer l.Close()
	return l.Addr().(*net.TCPAddr).Port
}

func waitHealthy(t *testing.T, base string) {
	t.Helper()
	deadline := time.Now().Add(15 * time.Second)
	for time.Now().Before(deadline) {
		resp, err := http.Get(base + "/healthz")
		if err == nil {
			resp.Body.Close()
			if resp.StatusCode == 200 {
				return
			}
		}
		time.Sleep(100 * time.Millisecond)
	}
	t.Fatal("server did not become healthy within 15s")
}

var linkRe = regexp.MustCompile(`link=(http\S+)`)

func waitForLink(t *testing.T, buf *syncBuffer) string {
	t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		if m := linkRe.FindStringSubmatch(buf.String()); m != nil {
			return m[1]
		}
		time.Sleep(50 * time.Millisecond)
	}
	t.Fatalf("magic link never appeared in server log:\n%s", buf.String())
	return ""
}

func getJSON(t *testing.T, url string, dst any) {
	t.Helper()
	resp, err := http.Get(url)
	if err != nil {
		t.Fatalf("GET %s: %v", url, err)
	}
	defer resp.Body.Close()
	b, _ := io.ReadAll(resp.Body)
	if resp.StatusCode != 200 {
		t.Fatalf("GET %s -> %d %s", url, resp.StatusCode, b)
	}
	if err := json.Unmarshal(b, dst); err != nil {
		t.Fatalf("decode %s: %v\n%s", url, err, b)
	}
}

func postJSON(t *testing.T, url string, body any, dst any) []byte {
	t.Helper()
	payload, _ := json.Marshal(body)
	resp, err := http.Post(url, "application/json", bytes.NewReader(payload))
	if err != nil {
		t.Fatalf("POST %s: %v", url, err)
	}
	defer resp.Body.Close()
	b, _ := io.ReadAll(resp.Body)
	if resp.StatusCode != 200 {
		t.Fatalf("POST %s -> %d %s", url, resp.StatusCode, b)
	}
	if dst != nil {
		if err := json.Unmarshal(b, dst); err != nil {
			t.Fatalf("decode %s: %v\n%s", url, err, b)
		}
	}
	return b
}

func contains(xs []string, s string) bool {
	for _, x := range xs {
		if x == s {
			return true
		}
	}
	return false
}

// syncBuffer is a goroutine-safe bytes.Buffer for capturing subprocess output.
type syncBuffer struct {
	mu sync.Mutex
	b  bytes.Buffer
}

func (s *syncBuffer) Write(p []byte) (int, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.b.Write(p)
}

func (s *syncBuffer) String() string {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.b.String()
}
