// This file proves STATUS.md checklist #10a (fuzzy-extractor-selfie) and
// #10b (social-vouching-graph) — the airdrop-test-compatible methods for
// OpenLine's UBI-claim / vote-eligibility use cases — end to end against a
// REAL server process, the same way TestE2E_EmailOnlyEnrollment proves the
// round-1 path: no vendor account, no ID, no bank, no fixed address.
package tests

import (
	"crypto/ed25519"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"testing"

	"github.com/sagearbor/personhood/pkg/types"
)

// signVouchProofForTesting reimplements social-vouching's HMACDevAuthenticator
// scheme (hex(HMAC-SHA256(secret, voucherID + "." + candidateID)), see
// src/methods/social-vouching/authenticator.go's SignVouchForTesting)
// directly in this e2e test rather than importing that method package —
// consistent with this test file treating the server as a real, opaque
// binary reached only over HTTP (the same reason TestE2E_EmailOnlyEnrollment
// scrapes the magic link from the server's log instead of importing the
// email method's internals).
func signVouchProofForTesting(secret, voucherID, candidateID string) string {
	mac := hmac.New(sha256.New, []byte(secret))
	mac.Write([]byte(voucherID + "." + candidateID))
	return hex.EncodeToString(mac.Sum(nil))
}

// randomTemplateForTesting mirrors
// fuzzy-extractor-selfie.RandomTemplateForTesting (32 random bytes standing
// in for an on-device face-embedding template) without importing that
// method package, for the same reason as signVouchProofForTesting above.
func randomTemplateForTesting(t *testing.T) []byte {
	t.Helper()
	b := make([]byte, 32)
	if _, err := rand.Read(b); err != nil {
		t.Fatalf("generate random template: %v", err)
	}
	return b
}

func TestE2E_AirdropTestAnchors(t *testing.T) {
	if testing.Short() {
		t.Skip("e2e: skipped in -short mode")
	}
	root := repoRoot(t)
	work := t.TempDir()

	serverBin := filepath.Join(work, "personhood-server")
	verifyBin := filepath.Join(work, "verify-credential")
	goBuild(t, filepath.Join(root, "src", "server"), serverBin, "./cmd/server")
	goBuild(t, filepath.Join(root, "tools", "verify-credential"), verifyBin, ".")

	port := freePort(t)
	base := fmt.Sprintf("http://127.0.0.1:%d", port)
	seed := genKey(t, filepath.Join(root, "src", "server"))
	const vouchSecret = "e2e-test-social-vouching-secret"

	logBuf := &syncBuffer{}
	cmd := exec.Command(serverBin)
	cmd.Env = append(os.Environ(),
		"ISSUER_ED25519_SK_B64="+seed,
		fmt.Sprintf("SERVER_ADDR=127.0.0.1:%d", port),
		"SERVER_PUBLIC_URL="+base,
		"CORS_ALLOWED_ORIGINS=http://localhost:3000",
		"DEV_EXPOSE_CHALLENGE_SECRETS=",
		"FUZZY_EXTRACTOR_ENABLED=1",
		"SOCIAL_VOUCHING_ENABLED=1",
		"SOCIAL_VOUCHING_SECRET="+vouchSecret,
		"SOCIAL_VOUCHING_SEED_IDS=seed-1,seed-2,seed-3",
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

	var methods struct {
		Methods []struct {
			ID       string `json:"id"`
			Type     string `json:"type"`
			Strength int    `json:"strength"`
		} `json:"methods"`
	}
	getJSON(t, base+"/v1/methods", &methods)
	byID := make(map[string]struct {
		Type     string
		Strength int
	})
	for _, m := range methods.Methods {
		byID[m.ID] = struct {
			Type     string
			Strength int
		}{m.Type, m.Strength}
	}
	if got, ok := byID["fuzzy-extractor-selfie"]; !ok || got.Type != "anchor" || got.Strength < 50 {
		t.Fatalf("fuzzy-extractor-selfie not registered as an anchor with strength>=50: %+v (have %v)", got, byID)
	}
	if got, ok := byID["social-vouching-graph"]; !ok || got.Type != "supplementary" || got.Strength >= 50 {
		t.Fatalf("social-vouching-graph not registered as supplementary with strength<50: %+v (have %v)", got, byID)
	}

	policies := filepath.Join(root, "docs", "policies")
	airdropPolicy := filepath.Join(policies, "airdrop-anchor-example.yaml")

	// --- Part 1: fuzzy-extractor-selfie alone satisfies the airdrop-anchor
	// policy, including its nullifier_required clause. ---
	t.Run("fuzzy-extractor-selfie anchor", func(t *testing.T) {
		var start struct {
			SessionID string    `json:"session_id"`
			HolderDID types.DID `json:"holder_did"`
		}
		holderPub, _, err := ed25519.GenerateKey(rand.Reader)
		if err != nil {
			t.Fatalf("generate holder key: %v", err)
		}
		postJSON(t, base+"/enrollment/start", map[string]any{
			"holder_public_key_b64": base64.StdEncoding.EncodeToString(holderPub),
		}, &start)

		var begin struct {
			Challenge types.ChallengeData `json:"challenge"`
		}
		postJSON(t, base+"/v1/methods/fuzzy-extractor-selfie/begin",
			map[string]any{"session_id": start.SessionID}, &begin)
		if begin.Challenge.Type != "fuzzy-extractor-challenge" {
			t.Fatalf("expected fuzzy-extractor-challenge, got %q", begin.Challenge.Type)
		}

		template := randomTemplateForTesting(t)
		var complete struct {
			Result types.MethodResult `json:"result"`
		}
		postJSON(t, base+"/v1/methods/fuzzy-extractor-selfie/complete", map[string]any{
			"session_id": start.SessionID,
			"response": types.ResponseData{
				Type:    "fuzzy-extractor-response",
				Payload: map[string]any{"template_b64": base64.StdEncoding.EncodeToString(template)},
			},
		}, &complete)
		if !complete.Result.Success {
			t.Fatalf("fuzzy-extractor-selfie complete failed: %s", complete.Result.ErrorReason)
		}

		var issued struct {
			Credential json.RawMessage `json:"credential"`
		}
		postJSON(t, base+"/v1/credentials/issue", map[string]any{"session_id": start.SessionID}, &issued)
		credPath := filepath.Join(work, "fuzzy-credential.json")
		if err := os.WriteFile(credPath, issued.Credential, 0o600); err != nil {
			t.Fatal(err)
		}
		var cred types.PersonhoodCredential
		if err := json.Unmarshal(issued.Credential, &cred); err != nil {
			t.Fatalf("decode credential: %v", err)
		}
		if cred.CredentialSubject.AnchorMethodID == nil || *cred.CredentialSubject.AnchorMethodID != "fuzzy-extractor-selfie" {
			t.Fatalf("expected fuzzy-extractor-selfie as anchor, got %+v", cred.CredentialSubject.AnchorMethodID)
		}
		if cred.CredentialSubject.NullifierBinding == nil {
			t.Fatal("credential has no nullifierBinding")
		}

		out, code := runVerify(t, verifyBin, credPath, airdropPolicy, base)
		if code != 0 || !out.OK || out.Code != types.EvalOK {
			t.Fatalf("airdrop-anchor-example.yaml should accept a fuzzy-extractor-selfie credential: exit=%d %+v", code, out)
		}
		if out.Nullifier == "" {
			t.Fatal("verify-credential reported no nullifier despite nullifier_required: true")
		}
		t.Logf("fuzzy-extractor-selfie: ok, nullifier=%s", out.Nullifier)

		// A second, independent session presenting the SAME biometric is
		// rejected as a duplicate (the accumulator's Sybil defense), proven
		// against the real running server, not just the unit tests.
		var start2 struct {
			SessionID string `json:"session_id"`
		}
		postJSON(t, base+"/enrollment/start", map[string]any{}, &start2)
		postJSON(t, base+"/v1/methods/fuzzy-extractor-selfie/begin",
			map[string]any{"session_id": start2.SessionID}, &begin)
		var complete2 struct {
			Result types.MethodResult `json:"result"`
		}
		postJSON(t, base+"/v1/methods/fuzzy-extractor-selfie/complete", map[string]any{
			"session_id": start2.SessionID,
			"response": types.ResponseData{
				Type:    "fuzzy-extractor-response",
				Payload: map[string]any{"template_b64": base64.StdEncoding.EncodeToString(template)},
			},
		}, &complete2)
		if complete2.Result.Success {
			t.Fatal("a second session presenting the identical biometric should have been rejected as a duplicate")
		}
		if complete2.Result.ErrorReason != "duplicate_person_detected" {
			t.Fatalf("ErrorReason = %q, want duplicate_person_detected", complete2.Result.ErrorReason)
		}
	})

	// --- Part 2: social-vouching-graph alone is supplementary, not an
	// anchor — the airdrop-anchor policy (anchor_required: true) must
	// reject it with anchor_missing even though the method itself succeeds. ---
	t.Run("social-vouching-graph alone does not satisfy anchor_required", func(t *testing.T) {
		var start struct {
			SessionID string `json:"session_id"`
		}
		postJSON(t, base+"/enrollment/start", map[string]any{}, &start)
		candidateID := start.SessionID

		var begin struct {
			Challenge types.ChallengeData `json:"challenge"`
		}
		postJSON(t, base+"/v1/methods/social-vouching-graph/begin",
			map[string]any{"session_id": start.SessionID}, &begin)
		if begin.Challenge.Payload["candidate_code"] != candidateID {
			t.Fatalf("candidate_code = %v, want %v", begin.Challenge.Payload["candidate_code"], candidateID)
		}

		for _, voucherID := range []string{"seed-1", "seed-2", "seed-3"} {
			proof := signVouchProofForTesting(vouchSecret, voucherID, candidateID)
			var vouchResp struct {
				Recorded     bool    `json:"recorded"`
				VoucherTrust float64 `json:"voucher_trust"`
				Error        string  `json:"error"`
			}
			postJSON(t, base+"/v1/methods/social-vouching-graph/vouch", map[string]any{
				"candidate_id": candidateID,
				"voucher_id":   voucherID,
				"proof":        proof,
			}, &vouchResp)
			if !vouchResp.Recorded {
				t.Fatalf("vouch from %s not recorded: %s", voucherID, vouchResp.Error)
			}
		}

		var complete struct {
			Result types.MethodResult `json:"result"`
		}
		postJSON(t, base+"/v1/methods/social-vouching-graph/complete",
			map[string]any{"session_id": start.SessionID}, &complete)
		if !complete.Result.Success {
			t.Fatalf("social-vouching-graph complete failed after 3 seed vouches: %s", complete.Result.ErrorReason)
		}

		var issued struct {
			Credential json.RawMessage `json:"credential"`
		}
		postJSON(t, base+"/v1/credentials/issue", map[string]any{"session_id": start.SessionID}, &issued)
		credPath := filepath.Join(work, "vouching-only-credential.json")
		if err := os.WriteFile(credPath, issued.Credential, 0o600); err != nil {
			t.Fatal(err)
		}

		out, code := runVerify(t, verifyBin, credPath, airdropPolicy, base)
		if code != 1 || out.OK || out.Code != types.EvalAnchorMissing {
			t.Fatalf("airdrop-anchor-example.yaml should reject a vouching-only credential with anchor_missing: exit=%d %+v", code, out)
		}
		t.Logf("social-vouching-graph alone: correctly rejected with %s", out.Code)
	})

	// --- Part 3: combining fuzzy-extractor-selfie (anchor) with
	// social-vouching-graph (supplementary) in ONE session composes — the
	// credential records both methods and still satisfies the policy. ---
	t.Run("anchor plus supplementary compose", func(t *testing.T) {
		var start struct {
			SessionID string `json:"session_id"`
		}
		postJSON(t, base+"/enrollment/start", map[string]any{}, &start)
		candidateID := start.SessionID

		var begin struct {
			Challenge types.ChallengeData `json:"challenge"`
		}
		postJSON(t, base+"/v1/methods/fuzzy-extractor-selfie/begin",
			map[string]any{"session_id": start.SessionID}, &begin)
		template := randomTemplateForTesting(t)
		var completeFuzzy struct {
			Result types.MethodResult `json:"result"`
		}
		postJSON(t, base+"/v1/methods/fuzzy-extractor-selfie/complete", map[string]any{
			"session_id": start.SessionID,
			"response": types.ResponseData{
				Type:    "fuzzy-extractor-response",
				Payload: map[string]any{"template_b64": base64.StdEncoding.EncodeToString(template)},
			},
		}, &completeFuzzy)
		if !completeFuzzy.Result.Success {
			t.Fatalf("fuzzy-extractor-selfie complete failed: %s", completeFuzzy.Result.ErrorReason)
		}

		postJSON(t, base+"/v1/methods/social-vouching-graph/begin",
			map[string]any{"session_id": start.SessionID}, &begin)
		for _, voucherID := range []string{"seed-1", "seed-2", "seed-3"} {
			proof := signVouchProofForTesting(vouchSecret, voucherID, candidateID)
			var vouchResp struct {
				Recorded bool `json:"recorded"`
			}
			postJSON(t, base+"/v1/methods/social-vouching-graph/vouch", map[string]any{
				"candidate_id": candidateID,
				"voucher_id":   voucherID,
				"proof":        proof,
			}, &vouchResp)
			if !vouchResp.Recorded {
				t.Fatalf("vouch from %s not recorded", voucherID)
			}
		}
		var completeVouch struct {
			Result types.MethodResult `json:"result"`
		}
		postJSON(t, base+"/v1/methods/social-vouching-graph/complete",
			map[string]any{"session_id": start.SessionID}, &completeVouch)
		if !completeVouch.Result.Success {
			t.Fatalf("social-vouching-graph complete failed: %s", completeVouch.Result.ErrorReason)
		}

		var issued struct {
			Credential json.RawMessage `json:"credential"`
		}
		postJSON(t, base+"/v1/credentials/issue", map[string]any{"session_id": start.SessionID}, &issued)
		var cred types.PersonhoodCredential
		if err := json.Unmarshal(issued.Credential, &cred); err != nil {
			t.Fatalf("decode credential: %v", err)
		}
		if len(cred.CredentialSubject.VerifiedMethods) != 2 {
			t.Fatalf("expected 2 verified methods (anchor + supplementary), got %d: %+v",
				len(cred.CredentialSubject.VerifiedMethods), cred.CredentialSubject.VerifiedMethods)
		}
		credPath := filepath.Join(work, "composed-credential.json")
		if err := os.WriteFile(credPath, issued.Credential, 0o600); err != nil {
			t.Fatal(err)
		}
		out, code := runVerify(t, verifyBin, credPath, airdropPolicy, base)
		if code != 0 || !out.OK || out.Code != types.EvalOK {
			t.Fatalf("airdrop-anchor-example.yaml should accept the composed credential: exit=%d %+v", code, out)
		}
		t.Logf("anchor + supplementary composed: ok")
	})
}
