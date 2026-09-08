package server

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/json"
	"io"
	"net/http"
	"net/url"
	"strings"
	"testing"
	"time"

	emailmethod "github.com/sagearbor/personhood/src/methods/email"
	emailtiermethod "github.com/sagearbor/personhood/src/methods/email-tier"
	"github.com/sagearbor/personhood/src/registry"
)

// TestIntegration_EmailTierMagicLink_SharedRoute is a regression test for the
// bug fixed alongside app/web's tier wiring (checklist #8): the GET
// /v1/methods/email/verify landing route used to hardcode
// s.registry.Get("email"), so an email-tier magic link (whose token lives in
// email-tier's OWN in-memory store) would silently fail to verify — the
// handler would look the token up in the wrong method's store and always
// report invalid_or_expired_token.
//
// It now reads an optional `method` query parameter (BuildDependencies sets
// it to "email-tier" when constructing that method's base URL) and dispatches
// to the right registered method. This test proves both directions:
//   - a link with method=email-tier completes the email-tier ceremony
//   - a link with no method param still defaults to plain "email" (backward
//     compatible with links minted before this parameter existed)
func TestIntegration_EmailTierMagicLink_SharedRoute(t *testing.T) {
	emailSender := &recordingEmailSender{}
	emailTierSender := &recordingEmailSender{}

	listener, err := newLocalListener()
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	publicURL := "http://" + listener.Addr().String()
	verifyBase := publicURL + "/v1/methods/email/verify"

	reg := registry.New()

	emailM := emailmethod.NewMethod(emailSender, verifyBase, emailmethod.NewInMemoryStore())
	if err := reg.Register(emailM); err != nil {
		t.Fatalf("register email: %v", err)
	}

	// Mirror BuildDependencies: email-tier's base URL carries an explicit
	// method= query param pointing back at itself.
	tierBaseURL := verifyBase
	if u, err := url.Parse(verifyBase); err == nil {
		q := u.Query()
		q.Set("method", emailtiermethod.MethodID)
		u.RawQuery = q.Encode()
		tierBaseURL = u.String()
	}
	emailTierM := emailtiermethod.NewMethod(emailtiermethod.Config{
		Sender:  emailTierSender,
		BaseURL: tierBaseURL,
		Store:   emailtiermethod.NewInMemoryStore(),
	})
	if err := reg.Register(emailTierM); err != nil {
		t.Fatalf("register email-tier: %v", err)
	}

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
	defer func() {
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		_ = httpServer.Shutdown(ctx)
	}()

	client := &http.Client{Timeout: 5 * time.Second}

	start := postJSONTest(t, client, publicURL+"/enrollment/start", map[string]any{
		"user_agent": "test", "platform": "web",
	})
	sessionID := start["session_id"].(string)

	// --- email-tier: begin, extract link, click it, expect success + the
	// verified method to be "email-tier" specifically. ---
	beginBody := postJSONTest(t, client, publicURL+"/v1/methods/email-tier/begin", map[string]any{
		"session_id": sessionID,
		"user_input": "alice@example.com",
	})
	_ = beginBody
	_, tierLink, _ := emailTierSender.lastSent()
	if tierLink == "" {
		t.Fatal("email-tier sender never captured a magic link")
	}
	if !strings.Contains(tierLink, "method=email-tier") {
		t.Fatalf("email-tier magic link missing method=email-tier query param: %s", tierLink)
	}

	resp, err := client.Get(tierLink)
	if err != nil {
		t.Fatalf("GET magic link: %v", err)
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(resp.Body)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("magic link click: status %d body %s", resp.StatusCode, body)
	}
	if strings.Contains(strings.ToLower(string(body)), "invalid") || strings.Contains(strings.ToLower(string(body)), "fail") {
		t.Fatalf("magic link click reported failure: %s", body)
	}

	view := getJSONTest(t, client, publicURL+"/v1/sessions/"+sessionID)
	verified, _ := view["verified_methods"].([]any)
	found := false
	for _, v := range verified {
		m, _ := v.(map[string]any)
		if m["method_id"] == "email-tier" {
			found = true
		}
	}
	if !found {
		t.Fatalf("session does not show email-tier as verified: %+v", view)
	}

	// --- plain email on the SAME server: a link with no method= param must
	// still default to "email" and complete against the plain method's
	// store (proves the default branch, not just the explicit one). ---
	start2 := postJSONTest(t, client, publicURL+"/enrollment/start", map[string]any{
		"user_agent": "test", "platform": "web",
	})
	sessionID2 := start2["session_id"].(string)
	postJSONTest(t, client, publicURL+"/v1/methods/email/begin", map[string]any{
		"session_id": sessionID2,
		"user_input": "bob@example.com",
	})
	_, plainLink, _ := emailSender.lastSent()
	if plainLink == "" {
		t.Fatal("plain email sender never captured a magic link")
	}
	if strings.Contains(plainLink, "method=") {
		t.Fatalf("plain email magic link unexpectedly carries a method= param: %s", plainLink)
	}
	resp2, err := client.Get(plainLink)
	if err != nil {
		t.Fatalf("GET plain magic link: %v", err)
	}
	defer resp2.Body.Close()
	body2, _ := io.ReadAll(resp2.Body)
	if resp2.StatusCode != http.StatusOK {
		t.Fatalf("plain magic link click: status %d body %s", resp2.StatusCode, body2)
	}

	view2 := getJSONTest(t, client, publicURL+"/v1/sessions/"+sessionID2)
	verified2, _ := view2["verified_methods"].([]any)
	foundPlain := false
	for _, v := range verified2 {
		m, _ := v.(map[string]any)
		if m["method_id"] == "email" {
			foundPlain = true
		}
	}
	if !foundPlain {
		t.Fatalf("session does not show plain email as verified: %+v", view2)
	}
}

func postJSONTest(t *testing.T, client *http.Client, url string, body map[string]any) map[string]any {
	t.Helper()
	raw, err := json.Marshal(body)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	resp, err := client.Post(url, "application/json", strings.NewReader(string(raw)))
	if err != nil {
		t.Fatalf("POST %s: %v", url, err)
	}
	defer resp.Body.Close()
	respBody, _ := io.ReadAll(resp.Body)
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		t.Fatalf("POST %s: status %d body %s", url, resp.StatusCode, respBody)
	}
	var out map[string]any
	if err := json.Unmarshal(respBody, &out); err != nil {
		t.Fatalf("decode POST %s response: %v (body %s)", url, err, respBody)
	}
	return out
}

func getJSONTest(t *testing.T, client *http.Client, url string) map[string]any {
	t.Helper()
	resp, err := client.Get(url)
	if err != nil {
		t.Fatalf("GET %s: %v", url, err)
	}
	defer resp.Body.Close()
	respBody, _ := io.ReadAll(resp.Body)
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		t.Fatalf("GET %s: status %d body %s", url, resp.StatusCode, respBody)
	}
	var out map[string]any
	if err := json.Unmarshal(respBody, &out); err != nil {
		t.Fatalf("decode GET %s response: %v (body %s)", url, err, respBody)
	}
	return out
}
