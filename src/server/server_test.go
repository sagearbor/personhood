package server

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"io"
	"net"
	"net/http"
	"regexp"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/sagearbor/personhood/pkg/types"
	"github.com/sagearbor/personhood/src/credential"
	emailmethod "github.com/sagearbor/personhood/src/methods/email"
	smsmethod "github.com/sagearbor/personhood/src/methods/sms"
	"github.com/sagearbor/personhood/src/registry"
)

// recordingEmailSender captures the magic link URL the server would have
// emailed so the test can simulate the user clicking it.
type recordingEmailSender struct {
	mu        sync.Mutex
	lastTo    string
	lastLink  string
	callCount int
}

func (s *recordingEmailSender) Send(_ context.Context, to string, _ string, link string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.lastTo = to
	s.lastLink = link
	s.callCount++
	return nil
}

func (s *recordingEmailSender) lastSent() (string, string, int) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.lastTo, s.lastLink, s.callCount
}

// recordingSMSSender captures the SMS body so the test can extract the OTP.
type recordingSMSSender struct {
	mu       sync.Mutex
	lastTo   string
	lastBody string
}

func (s *recordingSMSSender) Send(_ context.Context, to string, body string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.lastTo = to
	s.lastBody = body
	return nil
}

func (s *recordingSMSSender) lastOTP() string {
	s.mu.Lock()
	defer s.mu.Unlock()
	m := regexp.MustCompile(`\b\d{6}\b`).FindString(s.lastBody)
	return m
}

// newTestServer builds an httptest-backed server with recording senders and a
// fixed issuer key, returning the live URL and the bits the test needs to
// inspect ceremonies + verify the issued credential.
func newTestServer(t *testing.T) (string, *Server, *recordingEmailSender, *recordingSMSSender, func()) {
	t.Helper()

	emailSender := &recordingEmailSender{}
	smsSender := &recordingSMSSender{}

	reg := registry.New()
	// We construct the methods directly so we can inject the recording senders.
	// The magic-link base URL is set after we know the httptest URL — populate
	// it via a small re-wire trick: build the email method twice. First with a
	// placeholder, then replace once we know the real test URL. Simpler: spin
	// up a placeholder server, learn its URL, swap in a method bound to it.
	//
	// Cleaner alternative used here: configure the email method's magic-link
	// base URL with the httptest URL we're about to serve from. We get there
	// by allocating a listener up front.
	listener, err := newLocalListener()
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	publicURL := "http://" + listener.Addr().String()

	emailM := emailmethod.NewMethod(emailSender, publicURL+"/v1/methods/email/verify", emailmethod.NewInMemoryStore())
	if err := reg.Register(emailM); err != nil {
		t.Fatalf("register email: %v", err)
	}
	smsM := smsmethod.NewMethod(smsSender, smsmethod.NewInMemoryStore())
	if err := reg.Register(smsM); err != nil {
		t.Fatalf("register sms: %v", err)
	}

	// Deterministic issuer key so tests can construct a MapResolver matching it.
	_, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("gen key: %v", err)
	}

	cfg := Config{
		Addr:               listener.Addr().String(),
		PublicURL:          publicURL,
		IssuerPrivateKey:   priv,
		CORSAllowedOrigins: []string{"http://localhost:3000"},
		SessionTTL:         10 * time.Minute,
	}
	srv, err := NewServer(cfg, Dependencies{Registry: reg})
	if err != nil {
		t.Fatalf("new server: %v", err)
	}

	httpServer := &http.Server{Handler: srv.Router()}
	go func() { _ = httpServer.Serve(listener) }()

	cleanup := func() {
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		_ = httpServer.Shutdown(ctx)
	}
	return publicURL, srv, emailSender, smsSender, cleanup
}

func TestIntegration_FullEnrollmentToIssuance(t *testing.T) {
	base, srv, emailSender, smsSender, cleanup := newTestServer(t)
	defer cleanup()

	// 1. /enrollment/start
	startBody := mustJSON(t, map[string]any{
		"user_agent": "go-test",
		"platform":   "web",
	})
	var start startEnrollmentResponse
	mustPOST(t, base+"/enrollment/start", startBody, &start)
	if start.SessionID == "" {
		t.Fatal("session_id is empty")
	}
	if !strings.HasPrefix(string(start.HolderDID), "did:personhood:holder:") {
		t.Errorf("unexpected holder DID format: %q", start.HolderDID)
	}
	if !strings.HasPrefix(string(start.IssuerDID), "did:web:") {
		t.Errorf("unexpected issuer DID format: %q", start.IssuerDID)
	}
	if len(start.AvailableMethods) != 2 {
		t.Errorf("want 2 methods (email + sms), got %d", len(start.AvailableMethods))
	}

	// 2. email begin
	emailUser := "alice@example.com"
	beginBody := mustJSON(t, map[string]any{
		"session_id": start.SessionID,
		"user_input": emailUser,
	})
	var beginResp beginMethodResponse
	mustPOST(t, base+"/v1/methods/email/begin", beginBody, &beginResp)
	if beginResp.Challenge.Type != "magic-link" {
		t.Errorf("expected magic-link challenge, got %q", beginResp.Challenge.Type)
	}
	to, link, count := emailSender.lastSent()
	if to != emailUser {
		t.Errorf("email recipient mismatch: want %q, got %q", emailUser, to)
	}
	if count != 1 {
		t.Errorf("expected one send, got %d", count)
	}
	if !strings.Contains(link, "/v1/methods/email/verify") {
		t.Errorf("magic link does not point at /v1/methods/email/verify: %s", link)
	}

	// 3. simulate user clicking the magic link — GET the URL the email contained
	resp, err := http.Get(link)
	if err != nil {
		t.Fatalf("click magic link: %v", err)
	}
	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		t.Fatalf("magic-link click returned %d: %s", resp.StatusCode, body)
	}
	body, _ := io.ReadAll(resp.Body)
	resp.Body.Close()
	if !strings.Contains(string(body), "Email verified") {
		t.Errorf("magic-link landing did not render success: %s", body)
	}

	// 4. sms begin
	smsUser := "+15551234567"
	smsBeginBody := mustJSON(t, map[string]any{
		"session_id": start.SessionID,
		"user_input": smsUser,
	})
	var smsBegin beginMethodResponse
	mustPOST(t, base+"/v1/methods/sms/begin", smsBeginBody, &smsBegin)
	if smsBegin.Challenge.Type != "otp" {
		t.Errorf("expected otp challenge, got %q", smsBegin.Challenge.Type)
	}
	otp := smsSender.lastOTP()
	if otp == "" {
		t.Fatal("did not capture an OTP from sms sender body")
	}

	// 5. sms complete
	smsCompleteBody := mustJSON(t, map[string]any{
		"session_id": start.SessionID,
		"response": types.ResponseData{
			Type:    "otp",
			Payload: map[string]any{"phone_number": smsUser, "code": otp},
		},
	})
	var smsComplete completeMethodResponse
	mustPOST(t, base+"/v1/methods/sms/complete", smsCompleteBody, &smsComplete)
	if !smsComplete.Result.Success {
		t.Errorf("sms complete failed: %s", smsComplete.Result.ErrorReason)
	}
	if len(smsComplete.Session.VerifiedMethods) != 2 {
		t.Errorf("expected 2 verified methods after sms, got %d", len(smsComplete.Session.VerifiedMethods))
	}

	// 6. issue credential
	issueBody := mustJSON(t, map[string]any{"session_id": start.SessionID})
	var issued issueCredentialResponse
	mustPOST(t, base+"/v1/credentials/issue", issueBody, &issued)
	cred := issued.Credential
	if cred.Issuer != srv.IssuerDID() {
		t.Errorf("credential issuer mismatch: want %q, got %q", srv.IssuerDID(), cred.Issuer)
	}
	if cred.CredentialSubject.ID != start.HolderDID {
		t.Errorf("credential subject mismatch: want %q, got %q", start.HolderDID, cred.CredentialSubject.ID)
	}
	if len(cred.CredentialSubject.VerifiedMethods) != 2 {
		t.Errorf("credential should record 2 methods, got %d", len(cred.CredentialSubject.VerifiedMethods))
	}
	if cred.CredentialSubject.AnchorMethodID != nil {
		t.Errorf("v0.1 stub has no anchor methods registered; expected nil AnchorMethodID, got %q", *cred.CredentialSubject.AnchorMethodID)
	}
	if cred.Proof == nil || cred.Proof.ProofValue == "" {
		t.Fatal("issued credential has no proof / empty proofValue")
	}

	// 7. verify the signature using a MapResolver pointing at the test issuer key.
	resolver := credential.MapResolver{srv.IssuerDID(): srv.IssuerPublicKey()}
	verifier := credential.NewVerifier(resolver)
	if err := verifier.Verify(context.Background(), cred); err != nil {
		t.Errorf("credential verify failed: %v", err)
	}

	// 8. second issue should fail with 409.
	req, _ := http.NewRequest(http.MethodPost, base+"/v1/credentials/issue", bytes.NewReader(issueBody))
	req.Header.Set("Content-Type", "application/json")
	resp2, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("second issue request: %v", err)
	}
	if resp2.StatusCode != http.StatusConflict {
		t.Errorf("second issuance want 409, got %d", resp2.StatusCode)
	}
	resp2.Body.Close()
}

func TestIntegration_SessionNotFound(t *testing.T) {
	base, _, _, _, cleanup := newTestServer(t)
	defer cleanup()

	body := mustJSON(t, map[string]any{
		"session_id": "nope",
		"user_input": "alice@example.com",
	})
	req, _ := http.NewRequest(http.MethodPost, base+"/v1/methods/email/begin", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("post: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusNotFound {
		t.Errorf("want 404, got %d", resp.StatusCode)
	}
}

func TestIntegration_MagicLinkBadToken(t *testing.T) {
	base, _, _, _, cleanup := newTestServer(t)
	defer cleanup()

	startBody := mustJSON(t, map[string]any{})
	var start startEnrollmentResponse
	mustPOST(t, base+"/enrollment/start", startBody, &start)

	// Begin a real ceremony (so the session has stored state) ...
	beginBody := mustJSON(t, map[string]any{
		"session_id": start.SessionID,
		"user_input": "alice@example.com",
	})
	var beginResp beginMethodResponse
	mustPOST(t, base+"/v1/methods/email/begin", beginBody, &beginResp)

	// ... then click with a wrong token.
	resp, err := http.Get(base + "/v1/methods/email/verify?session=" + start.SessionID + "&token=wrong")
	if err != nil {
		t.Fatalf("click bad link: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Errorf("want 200 (with failure HTML), got %d", resp.StatusCode)
	}
	body, _ := io.ReadAll(resp.Body)
	if !strings.Contains(string(body), "Email verification failed") {
		t.Errorf("expected failure HTML, got: %s", body)
	}
}

func TestIntegration_IssueWithNoMethodsFails(t *testing.T) {
	base, _, _, _, cleanup := newTestServer(t)
	defer cleanup()

	startBody := mustJSON(t, map[string]any{})
	var start startEnrollmentResponse
	mustPOST(t, base+"/enrollment/start", startBody, &start)

	body := mustJSON(t, map[string]any{"session_id": start.SessionID})
	req, _ := http.NewRequest(http.MethodPost, base+"/v1/credentials/issue", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("post: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusUnprocessableEntity {
		t.Errorf("want 422, got %d", resp.StatusCode)
	}
}

func TestIntegration_DIDDocument(t *testing.T) {
	base, srv, _, _, cleanup := newTestServer(t)
	defer cleanup()

	resp, err := http.Get(base + "/.well-known/did.json")
	if err != nil {
		t.Fatalf("did: %v", err)
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(resp.Body)
	var doc IssuerDIDDocument
	if err := json.Unmarshal(body, &doc); err != nil {
		t.Fatalf("decode did doc: %v\n%s", err, body)
	}
	if doc.ID != srv.IssuerDID() {
		t.Errorf("did doc id mismatch: want %q, got %q", srv.IssuerDID(), doc.ID)
	}
	if len(doc.VerificationMethod) != 1 {
		t.Fatalf("expected 1 verification method, got %d", len(doc.VerificationMethod))
	}
	// JWK x must match the public key.
	x, _ := doc.VerificationMethod[0].PublicKeyJwk["x"].(string)
	want := base64.RawURLEncoding.EncodeToString(srv.IssuerPublicKey())
	if x != want {
		t.Errorf("did doc public key mismatch: want %q, got %q", want, x)
	}
}

func TestIntegration_HealthAndMethods(t *testing.T) {
	base, _, _, _, cleanup := newTestServer(t)
	defer cleanup()

	resp, err := http.Get(base + "/healthz")
	if err != nil || resp.StatusCode != http.StatusOK {
		t.Fatalf("healthz: %v %d", err, resp.StatusCode)
	}
	resp.Body.Close()

	resp, err = http.Get(base + "/v1/methods")
	if err != nil || resp.StatusCode != http.StatusOK {
		t.Fatalf("methods: %v %d", err, resp.StatusCode)
	}
	body, _ := io.ReadAll(resp.Body)
	resp.Body.Close()
	var out struct {
		Methods []methodSummary `json:"methods"`
	}
	if err := json.Unmarshal(body, &out); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if len(out.Methods) != 2 {
		t.Errorf("expected 2 methods, got %d", len(out.Methods))
	}
}

func TestIntegration_StatusList(t *testing.T) {
	base, _, _, _, cleanup := newTestServer(t)
	defer cleanup()

	resp, err := http.Get(base + "/v1/status-list/default")
	if err != nil {
		t.Fatalf("status list: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("want 200, got %d", resp.StatusCode)
	}
	body, _ := io.ReadAll(resp.Body)
	var out struct {
		CredentialSubject struct {
			EncodedList string `json:"encodedList"`
		} `json:"credentialSubject"`
	}
	if err := json.Unmarshal(body, &out); err != nil {
		t.Fatalf("decode: %v\n%s", err, body)
	}
	bits, err := credential.DecodeBitString(out.CredentialSubject.EncodedList)
	if err != nil {
		t.Fatalf("decode bitstring: %v", err)
	}
	if bits.Get(0) {
		t.Error("v0.1 status list should have bit 0 cleared")
	}
}

func TestConfig_DecodeIssuerKey(t *testing.T) {
	seed := make([]byte, ed25519.SeedSize)
	for i := range seed {
		seed[i] = byte(i)
	}
	priv := ed25519.NewKeyFromSeed(seed)

	cases := []struct {
		name string
		b64  string
	}{
		{"raw-url seed", base64.RawURLEncoding.EncodeToString(seed)},
		{"std seed", base64.StdEncoding.EncodeToString(seed)},
		{"raw-url full key", base64.RawURLEncoding.EncodeToString(priv)},
		{"std full key", base64.StdEncoding.EncodeToString(priv)},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got, err := DecodeIssuerKey(tc.b64)
			if err != nil {
				t.Fatalf("decode: %v", err)
			}
			if !bytes.Equal(got, priv) {
				t.Errorf("decoded key mismatch")
			}
		})
	}
}

func TestSession_RecordRejectsAfterIssued(t *testing.T) {
	store := NewSessionStore(time.Minute)
	sess, err := store.Create("did:test:holder:1", time.Now())
	if err != nil {
		t.Fatalf("create: %v", err)
	}
	if err := store.MarkIssued(sess.ID, "urn:fake:1"); err != nil {
		t.Fatalf("mark issued: %v", err)
	}
	err = store.RecordMethodResult(sess.ID, types.MethodResult{
		Success:    true,
		MethodID:   "email",
		VerifiedAt: time.Now(),
	}, types.MethodMetadata{ID: "email", Type: types.MethodTypeSupplementary, Strength: 8})
	if err == nil {
		t.Error("expected RecordMethodResult to fail after MarkIssued")
	}
}

// ----------------------------------------------------------------------------
// Test helpers
// ----------------------------------------------------------------------------

func mustJSON(t *testing.T, v any) []byte {
	t.Helper()
	b, err := json.Marshal(v)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	return b
}

func mustPOST(t *testing.T, url string, body []byte, dst any) {
	t.Helper()
	req, err := http.NewRequest(http.MethodPost, url, bytes.NewReader(body))
	if err != nil {
		t.Fatalf("new request: %v", err)
	}
	req.Header.Set("Content-Type", "application/json")
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("do %s: %v", url, err)
	}
	defer resp.Body.Close()
	respBody, _ := io.ReadAll(resp.Body)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("POST %s -> %d\n%s", url, resp.StatusCode, respBody)
	}
	if dst != nil {
		if err := json.Unmarshal(respBody, dst); err != nil {
			t.Fatalf("decode %s: %v\n%s", url, err, respBody)
		}
	}
}

// newLocalListener binds to a random loopback port and returns the listener
// so the test can compute the URL before the server starts.
func newLocalListener() (net.Listener, error) {
	return net.Listen("tcp", "127.0.0.1:0")
}
