package server

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"testing"
)

// startEmailSessionWithKey runs start (declaring pub) → email begin → click
// and returns the start response, ready for issuance.
func startEmailSessionWithKey(t *testing.T, base string, emailSender *recordingEmailSender, pub ed25519.PublicKey) startEnrollmentResponse {
	t.Helper()
	var start startEnrollmentResponse
	mustPOST(t, base+"/enrollment/start", mustJSON(t, map[string]any{
		"platform":              "web",
		"holder_public_key_b64": base64.StdEncoding.EncodeToString(pub),
	}), &start)
	var begin beginMethodResponse
	mustPOST(t, base+"/v1/methods/email/begin", mustJSON(t, map[string]any{
		"session_id": start.SessionID,
		"user_input": "pop@example.com",
	}), &begin)
	_, link, _ := emailSender.lastSent()
	resp, err := http.Get(link)
	if err != nil {
		t.Fatalf("click magic link: %v", err)
	}
	resp.Body.Close()
	return start
}

// postIssue posts to /v1/credentials/issue and returns the status code and
// error code (empty on success).
func postIssue(t *testing.T, base string, body map[string]any) (int, string) {
	t.Helper()
	resp, err := http.Post(base+"/v1/credentials/issue", "application/json", bytes.NewReader(mustJSON(t, body)))
	if err != nil {
		t.Fatalf("issue: %v", err)
	}
	defer resp.Body.Close()
	var out struct {
		Error struct {
			Code string `json:"code"`
		} `json:"error"`
	}
	_ = json.NewDecoder(resp.Body).Decode(&out)
	return resp.StatusCode, out.Error.Code
}

func newHolderKey(t *testing.T) (ed25519.PublicKey, ed25519.PrivateKey) {
	t.Helper()
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	return pub, priv
}

func TestIntegration_HolderPoPRequired(t *testing.T) {
	base, srv, emailSender, _, cleanup := newTestServerWith(t, func(c *Config) { c.RequireHolderPoP = true })
	defer cleanup()
	pub, priv := newHolderKey(t)

	start := startEmailSessionWithKey(t, base, emailSender, pub)
	if want := HolderPoPMessage(srv.issuerDID, start.SessionID); start.HolderProofMessage != want {
		t.Fatalf("holder_proof_message = %q, want %q", start.HolderProofMessage, want)
	}

	if code, ec := postIssue(t, base, map[string]any{"session_id": start.SessionID}); code != http.StatusForbidden || ec != errCodeHolderProofRequired {
		t.Errorf("no proof: got %d %q, want 403 %s", code, ec, errCodeHolderProofRequired)
	}

	// A signature by some other key, or over another session's message,
	// doesn't count.
	_, otherPriv := newHolderKey(t)
	wrongKey := ed25519.Sign(otherPriv, []byte(start.HolderProofMessage))
	wrongMsg := ed25519.Sign(priv, []byte(HolderPoPMessage(srv.issuerDID, "another-session")))
	for name, sig := range map[string][]byte{"wrong key": wrongKey, "wrong message": wrongMsg, "garbage": []byte("xx")} {
		code, ec := postIssue(t, base, map[string]any{
			"session_id":       start.SessionID,
			"holder_proof_b64": base64.StdEncoding.EncodeToString(sig),
		})
		if code != http.StatusForbidden || ec != errCodeHolderProofInvalid {
			t.Errorf("%s: got %d %q, want 403 %s", name, code, ec, errCodeHolderProofInvalid)
		}
	}

	good := ed25519.Sign(priv, []byte(start.HolderProofMessage))
	if code, ec := postIssue(t, base, map[string]any{
		"session_id":       start.SessionID,
		"holder_proof_b64": base64.StdEncoding.EncodeToString(good),
	}); code != http.StatusOK {
		t.Errorf("valid proof: got %d %q, want 200", code, ec)
	}
}

func TestIntegration_HolderPoPOptionalByDefault(t *testing.T) {
	base, srv, emailSender, _, cleanup := newTestServer(t)
	defer cleanup()
	pub, _ := newHolderKey(t)

	// Clients that predate the proof keep working...
	start := startEmailSessionWithKey(t, base, emailSender, pub)
	if code, ec := postIssue(t, base, map[string]any{"session_id": start.SessionID}); code != http.StatusOK {
		t.Errorf("no proof, not required: got %d %q, want 200", code, ec)
	}

	// ...but a proof that is sent is still checked.
	start = startEmailSessionWithKey(t, base, emailSender, pub)
	_, otherPriv := newHolderKey(t)
	bad := ed25519.Sign(otherPriv, []byte(HolderPoPMessage(srv.issuerDID, start.SessionID)))
	if code, ec := postIssue(t, base, map[string]any{
		"session_id":       start.SessionID,
		"holder_proof_b64": base64.StdEncoding.EncodeToString(bad),
	}); code != http.StatusForbidden || ec != errCodeHolderProofInvalid {
		t.Errorf("bad proof, not required: got %d %q, want 403 %s", code, ec, errCodeHolderProofInvalid)
	}
}

func TestIntegration_HolderPoPNotNeededWithoutHolderKey(t *testing.T) {
	base, _, emailSender, _, cleanup := newTestServerWith(t, func(c *Config) { c.RequireHolderPoP = true })
	defer cleanup()
	cred := issueEmailCredential(t, base, emailSender)
	if cred.ID == "" {
		t.Fatal("email-only session without a holder key should still issue")
	}
}
