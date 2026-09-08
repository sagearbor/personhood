package server

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"testing"

	"github.com/sagearbor/personhood/pkg/types"
	"github.com/sagearbor/personhood/src/credential"
	"github.com/sagearbor/personhood/src/policy"
)

// These tests cover the "round 1" enrollment path: a friend with nothing but
// an email address enrolls, clicks the magic link, and receives a credential
// that satisfies docs/policies/round1-email.yaml — and, just as importantly,
// that the server never hands the magic link to the client that asked for it.

func startAndBeginEmail(t *testing.T, base, email string) (startEnrollmentResponse, beginMethodResponse) {
	t.Helper()
	var start startEnrollmentResponse
	mustPOST(t, base+"/enrollment/start", mustJSON(t, map[string]any{"platform": "test"}), &start)
	var begin beginMethodResponse
	mustPOST(t, base+"/v1/methods/email/begin",
		mustJSON(t, map[string]any{"session_id": start.SessionID, "user_input": email}), &begin)
	return start, begin
}

func mustGET(t *testing.T, url string, dst any) int {
	t.Helper()
	resp, err := http.Get(url)
	if err != nil {
		t.Fatalf("GET %s: %v", url, err)
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(resp.Body)
	if dst != nil && resp.StatusCode == http.StatusOK {
		if err := jsonUnmarshal(body, dst); err != nil {
			t.Fatalf("decode %s: %v\n%s", url, err, body)
		}
	}
	return resp.StatusCode
}

func TestRound1_BeginEmailRedactsMagicLink(t *testing.T) {
	base, _, emailSender, _, cleanup := newTestServer(t)
	defer cleanup()

	_, begin := startAndBeginEmail(t, base, "friend@example.com")

	if _, leaked := begin.Challenge.Payload["magic_link_url"]; leaked {
		t.Fatalf("magic_link_url must not be returned to the client: %v", begin.Challenge.Payload)
	}
	if got := begin.Challenge.Payload["email_address"]; got != "friend@example.com" {
		t.Errorf("non-secret payload fields should survive redaction; email_address=%v", got)
	}
	if _, ok := begin.Challenge.Payload["expires_in_seconds"]; !ok {
		t.Errorf("expires_in_seconds missing from redacted payload: %v", begin.Challenge.Payload)
	}
	// The link still went out through the sender (i.e. redaction is
	// client-facing only).
	if _, link, n := emailSender.lastSent(); n != 1 || link == "" {
		t.Fatalf("sender should have received the magic link exactly once (n=%d link=%q)", n, link)
	}
}

func TestRound1_BeginEmailExposesLinkInDevMode(t *testing.T) {
	base, _, emailSender, _, cleanup := newTestServerWith(t, func(c *Config) { c.ExposeChallengeSecrets = true })
	defer cleanup()

	_, begin := startAndBeginEmail(t, base, "dev@example.com")
	_, link, _ := emailSender.lastSent()
	if got, _ := begin.Challenge.Payload["magic_link_url"].(string); got == "" || got != link {
		t.Fatalf("dev mode should expose the exact magic link; got %q want %q", got, link)
	}
}

func TestRound1_GetSessionPollsEmailVerification(t *testing.T) {
	base, _, emailSender, _, cleanup := newTestServer(t)
	defer cleanup()

	start, _ := startAndBeginEmail(t, base, "poll@example.com")

	var before SessionView
	if code := mustGET(t, base+"/v1/sessions/"+start.SessionID, &before); code != http.StatusOK {
		t.Fatalf("GET session before click -> %d", code)
	}
	if len(before.VerifiedMethods) != 0 {
		t.Fatalf("no methods should be verified before the click: %+v", before.VerifiedMethods)
	}

	_, link, _ := emailSender.lastSent()
	if code := mustGET(t, link, nil); code != http.StatusOK {
		t.Fatalf("magic link click -> %d", code)
	}

	var after SessionView
	mustGET(t, base+"/v1/sessions/"+start.SessionID, &after)
	if len(after.VerifiedMethods) != 1 || after.VerifiedMethods[0].MethodID != "email" {
		t.Fatalf("expected exactly the email method verified after click: %+v", after.VerifiedMethods)
	}
	if after.HolderDID != start.HolderDID {
		t.Errorf("holder DID drifted: %q vs %q", after.HolderDID, start.HolderDID)
	}

	if code := mustGET(t, base+"/v1/sessions/does-not-exist", nil); code != http.StatusNotFound {
		t.Errorf("unknown session should be 404, got %d", code)
	}
}

func TestRound1_EmailOnlyCredentialSatisfiesRound1Policy(t *testing.T) {
	base, srv, emailSender, _, cleanup := newTestServer(t)
	defer cleanup()

	start, _ := startAndBeginEmail(t, base, "round1@example.com")
	_, link, _ := emailSender.lastSent()
	if code := mustGET(t, link, nil); code != http.StatusOK {
		t.Fatalf("magic link click -> %d", code)
	}

	var issued issueCredentialResponse
	mustPOST(t, base+"/v1/credentials/issue", mustJSON(t, map[string]any{"session_id": start.SessionID}), &issued)
	cred := issued.Credential
	if len(cred.CredentialSubject.VerifiedMethods) != 1 || cred.CredentialSubject.VerifiedMethods[0].MethodID != "email" {
		t.Fatalf("expected an email-only credential, got %+v", cred.CredentialSubject.VerifiedMethods)
	}
	if cred.CredentialSubject.AnchorMethodID != nil {
		t.Fatalf("round-1 credential must not claim an anchor: %q", *cred.CredentialSubject.AnchorMethodID)
	}

	// Signature check against the issuer key the server publishes.
	resolver := credential.MapResolver{srv.IssuerDID(): srv.IssuerPublicKey()}
	if err := credential.NewVerifier(resolver).Verify(context.Background(), cred); err != nil {
		t.Fatalf("signature verify: %v", err)
	}

	// The round-1 policy file in docs/ must accept it ...
	round1 := loadPolicy(t, "round1-email.yaml")
	if res := policy.Evaluate(cred, round1, srv.nowFunc()); !res.OK {
		t.Fatalf("round1-email.yaml rejected an email-only credential: %s %s %v", res.Code, res.Human, res.Details)
	}
	// ... and the anchor-requiring default policy must reject it, with the
	// code integrators (OpenLine) will see until an anchor is available.
	floor := loadPolicy(t, "default-floor.yaml")
	if res := policy.Evaluate(cred, floor, srv.nowFunc()); res.OK || res.Code != types.EvalAnchorMissing {
		t.Fatalf("default-floor.yaml should reject with anchor_missing, got ok=%v code=%s", res.OK, res.Code)
	}
}

func jsonUnmarshal(b []byte, dst any) error { return json.Unmarshal(b, dst) }

// loadPolicy reads docs/policies/<name> relative to this package.
func loadPolicy(t *testing.T, name string) types.Policy {
	t.Helper()
	path := filepath.Join("..", "..", "docs", "policies", name)
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read %s: %v", path, err)
	}
	pol, err := policy.ParseYAML(raw)
	if err != nil {
		t.Fatalf("parse %s: %v", path, err)
	}
	return pol
}
