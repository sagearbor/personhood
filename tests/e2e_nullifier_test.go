// This file proves the holder-key + nullifierBinding wiring end to end
// against a REAL server process, the same way TestE2E_EmailOnlyEnrollment
// proves the round-1 path: a client that supplies an Ed25519 holder public
// key in POST /enrollment/start gets back a real did:key holder DID and an
// issued credential carrying a nullifierBinding, which satisfies a policy
// with nullifier_required: true; a client that supplies no key gets the v0.1
// placeholder DID and a credential with no nullifierBinding, which the same
// policy rejects with nullifier_missing.
package tests

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/sagearbor/personhood/pkg/types"
)

func TestE2E_HolderKeyBindingAndNullifier(t *testing.T) {
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

	// 2. Start one server; both sessions below share it.
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

	nullifierPolicy := filepath.Join(root, "docs", "policies", "nullifier-example.yaml")

	// --- Session A: client supplies a holder Ed25519 public key ("bound"). ---
	pub, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("generate holder key: %v", err)
	}
	holderPubB64 := base64.StdEncoding.EncodeToString(pub)

	var startA struct {
		SessionID string    `json:"session_id"`
		HolderDID types.DID `json:"holder_did"`
		IssuerDID types.DID `json:"issuer_did"`
	}
	postJSON(t, base+"/enrollment/start", map[string]any{
		"platform":              "e2e",
		"holder_public_key_b64": holderPubB64,
	}, &startA)
	if !strings.HasPrefix(string(startA.HolderDID), "did:key:z") {
		t.Fatalf("expected a did:key holder DID for a client-supplied key, got %q", startA.HolderDID)
	}

	credA := enrollAndIssueByEmail(t, base, logBuf, startA.SessionID, "bound-e2e@example.com")
	if credA.CredentialSubject.NullifierBinding == nil {
		t.Fatalf("bound session's credential has no nullifierBinding: %+v", credA)
	}
	if credA.CredentialSubject.NullifierBinding.Commitment == "" ||
		credA.CredentialSubject.NullifierBinding.Curve != "bn254" ||
		credA.CredentialSubject.NullifierBinding.Scheme != "pedersen-v1" {
		t.Fatalf("unexpected nullifierBinding shape: %+v", credA.CredentialSubject.NullifierBinding)
	}
	if credA.CredentialSubject.ID != startA.HolderDID {
		t.Fatalf("credential subject != holder DID: %q vs %q", credA.CredentialSubject.ID, startA.HolderDID)
	}

	credAPath := filepath.Join(work, "credential-bound.json")
	writeCredentialJSON(t, credAPath, credA)
	out, code := runVerify(t, verifyBin, credAPath, nullifierPolicy, base)
	if code != 0 || !out.OK || out.Code != types.EvalOK {
		t.Fatalf("nullifier-example.yaml should accept the bound credential: exit=%d %+v", code, out)
	}
	if out.Nullifier == "" {
		t.Fatalf("expected a derived nullifier for the bound credential, got none: %+v", out)
	}
	t.Logf("bound credential: ok, nullifier=%s", out.Nullifier)

	// --- Session B: client supplies no holder key ("unbound"). ---
	var startB struct {
		SessionID string    `json:"session_id"`
		HolderDID types.DID `json:"holder_did"`
		IssuerDID types.DID `json:"issuer_did"`
	}
	postJSON(t, base+"/enrollment/start", map[string]any{"platform": "e2e"}, &startB)
	if !strings.HasPrefix(string(startB.HolderDID), "did:personhood:holder:") {
		t.Fatalf("expected the v0.1 placeholder holder DID with no client key, got %q", startB.HolderDID)
	}

	credB := enrollAndIssueByEmail(t, base, logBuf, startB.SessionID, "unbound-e2e@example.com")
	if credB.CredentialSubject.NullifierBinding != nil {
		t.Fatalf("unbound session's credential should have no nullifierBinding, got %+v", credB.CredentialSubject.NullifierBinding)
	}

	credBPath := filepath.Join(work, "credential-unbound.json")
	writeCredentialJSON(t, credBPath, credB)
	out, code = runVerify(t, verifyBin, credBPath, nullifierPolicy, base)
	if code != 1 || out.OK || out.Code != types.EvalNullifierMissing {
		t.Fatalf("nullifier-example.yaml should reject the unbound credential with nullifier_missing: exit=%d %+v", code, out)
	}
	if out.Nullifier != "" {
		t.Fatalf("no nullifier should be derived for the unbound (rejected) credential, got %q", out.Nullifier)
	}
	t.Logf("unbound credential: rejected with %s (expected)", out.Code)
}

// enrollAndIssueByEmail begins + completes the email ceremony for an
// already-started session, then issues and returns the credential. `since`
// tracking is handled internally by scoping the magic-link search to the log
// written after this call began, so it is safe to call twice against one
// shared server log buffer.
func enrollAndIssueByEmail(t *testing.T, base string, logBuf *syncBuffer, sessionID, email string) types.PersonhoodCredential {
	t.Helper()
	since := len(logBuf.String())

	var begin struct {
		Challenge types.ChallengeData `json:"challenge"`
	}
	postJSON(t, base+"/v1/methods/email/begin",
		map[string]any{"session_id": sessionID, "user_input": email}, &begin)
	if begin.Challenge.Type != "magic-link" {
		t.Fatalf("expected magic-link challenge, got %q", begin.Challenge.Type)
	}

	link := waitForLinkSince(t, logBuf, since)
	resp, err := http.Get(link)
	if err != nil {
		t.Fatalf("click magic link: %v", err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("magic-link click returned %d", resp.StatusCode)
	}

	var view struct {
		VerifiedMethods []types.VerifiedMethod `json:"verified_methods"`
	}
	getJSON(t, base+"/v1/sessions/"+sessionID, &view)
	if len(view.VerifiedMethods) != 1 || view.VerifiedMethods[0].MethodID != "email" {
		t.Fatalf("expected email verified after click: %+v", view.VerifiedMethods)
	}

	var issued struct {
		Credential json.RawMessage `json:"credential"`
	}
	postJSON(t, base+"/v1/credentials/issue", map[string]any{"session_id": sessionID}, &issued)
	var cred types.PersonhoodCredential
	if err := json.Unmarshal(issued.Credential, &cred); err != nil {
		t.Fatalf("decode credential: %v", err)
	}
	if cred.Proof == nil || cred.Proof.ProofValue == "" {
		t.Fatal("credential has no proof")
	}
	return cred
}

func writeCredentialJSON(t *testing.T, path string, cred types.PersonhoodCredential) {
	t.Helper()
	b, err := json.Marshal(cred)
	if err != nil {
		t.Fatalf("marshal credential: %v", err)
	}
	if err := os.WriteFile(path, b, 0o600); err != nil {
		t.Fatalf("write %s: %v", path, err)
	}
}

// waitForLinkSince is waitForLink scoped to log content written after byte
// offset `since`, so it can be called more than once against one shared
// server log buffer without re-matching an earlier session's link.
func waitForLinkSince(t *testing.T, buf *syncBuffer, since int) string {
	t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		s := buf.String()
		if since <= len(s) {
			if m := linkRe.FindStringSubmatch(s[since:]); m != nil {
				return m[1]
			}
		}
		time.Sleep(50 * time.Millisecond)
	}
	t.Fatalf("magic link never appeared in server log after offset %d:\n%s", since, buf.String())
	return ""
}
