package captchaturnstile

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/sagearbor/personhood/pkg/types"
)

func TestMetadata(t *testing.T) {
	m := newTestMethod(t, "https://fake.example")
	md := m.Metadata()
	if md.ID != MethodID {
		t.Errorf("id mismatch: %q", md.ID)
	}
	if md.Type != types.MethodTypeSupplementary {
		t.Errorf("expected supplementary type, got %q", md.Type)
	}
	if md.Strength != 4 || md.Strength >= 50 {
		t.Errorf("strength must be 4 and <50, got %d", md.Strength)
	}
	if md.UXFriction != types.FrictionLow {
		t.Errorf("expected low friction, got %q", md.UXFriction)
	}
	if md.FreshnessLifetime <= 0 {
		t.Error("freshness lifetime must be positive")
	}
}

func TestIsAvailableForUser(t *testing.T) {
	m := newTestMethod(t, "https://fake.example")
	if ok, _ := m.IsAvailableForUser(types.UserContext{}); !ok {
		t.Error("turnstile should always be available")
	}
	if ok, _ := m.IsAvailableForUser(types.UserContext{CountryCode: "DE", Platform: "web"}); !ok {
		t.Error("turnstile should be available regardless of country/platform")
	}
}

func TestBeginCeremony_ReturnsSiteKey(t *testing.T) {
	m := newTestMethod(t, "https://fake.example")
	cc := types.CeremonyContext{SessionID: "session-123", MethodID: MethodID}
	challenge, err := m.BeginCeremony(context.Background(), cc)
	if err != nil {
		t.Fatalf("begin: %v", err)
	}
	if challenge.Type != "turnstile" {
		t.Errorf("challenge type mismatch: %q", challenge.Type)
	}
	if sk, _ := challenge.Payload["site_key"].(string); sk != "test-site-key" {
		t.Errorf("site_key mismatch: %q", sk)
	}
	if action, _ := challenge.Payload["verify_action"].(string); action != "enroll" {
		t.Errorf("verify_action mismatch: %q", action)
	}
}

func TestBeginCeremony_RequiresSessionID(t *testing.T) {
	m := newTestMethod(t, "https://fake.example")
	if _, err := m.BeginCeremony(context.Background(), types.CeremonyContext{}); err == nil {
		t.Fatal("expected error when SessionID is empty")
	}
}

func TestCompleteCeremony_Success(t *testing.T) {
	fake := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/siteverify" || r.Method != http.MethodPost {
			http.Error(w, "unexpected request", http.StatusBadRequest)
			return
		}
		if err := r.ParseForm(); err != nil {
			http.Error(w, "bad form", http.StatusBadRequest)
			return
		}
		if r.Form.Get("secret") != "test-secret-key" {
			t.Errorf("secret not forwarded: %q", r.Form.Get("secret"))
		}
		if r.Form.Get("response") != "good-token" {
			t.Errorf("response token not forwarded: %q", r.Form.Get("response"))
		}
		if r.Form.Get("remoteip") != "203.0.113.5" {
			t.Errorf("remoteip not forwarded: %q", r.Form.Get("remoteip"))
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"success":true,"challenge_ts":"2026-06-15T12:00:00Z","hostname":"app.example"}`))
	}))
	defer fake.Close()

	m := newTestMethod(t, fake.URL)
	resp := types.ResponseData{Type: "turnstile", Payload: map[string]any{"token": "good-token", "ip": "203.0.113.5"}}
	result, err := m.CompleteCeremony(context.Background(), types.CeremonyContext{SessionID: "s1"}, resp)
	if err != nil {
		t.Fatalf("complete: %v", err)
	}
	if !result.Success {
		t.Errorf("expected success, got %+v", result)
	}
	if result.MethodID != MethodID {
		t.Errorf("method id mismatch: %q", result.MethodID)
	}
	if result.AttestationDigest == "" {
		t.Error("attestation digest must be non-empty on success")
	}
	if result.VerifiedAt.IsZero() {
		t.Error("verified_at must be set on success")
	}
}

func TestCompleteCeremony_Failure(t *testing.T) {
	fake := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"success":false,"error-codes":["invalid-input-response","timeout-or-duplicate"]}`))
	}))
	defer fake.Close()

	m := newTestMethod(t, fake.URL)
	resp := types.ResponseData{Type: "turnstile", Payload: map[string]any{"token": "bad-token"}}
	result, err := m.CompleteCeremony(context.Background(), types.CeremonyContext{SessionID: "s1"}, resp)
	if err != nil {
		t.Fatalf("complete: %v", err)
	}
	if result.Success {
		t.Errorf("expected failure, got %+v", result)
	}
	if !strings.Contains(result.ErrorReason, "invalid-input-response") {
		t.Errorf("error reason should mention the codes, got %q", result.ErrorReason)
	}
	if !strings.HasPrefix(result.ErrorReason, "turnstile_failed:") {
		t.Errorf("error reason should be turnstile_failed:..., got %q", result.ErrorReason)
	}
}

func TestCompleteCeremony_MissingToken(t *testing.T) {
	m := newTestMethod(t, "https://fake.example")
	result, err := m.CompleteCeremony(context.Background(), types.CeremonyContext{SessionID: "s1"}, types.ResponseData{Type: "turnstile", Payload: map[string]any{}})
	if err != nil {
		t.Fatalf("complete: %v", err)
	}
	if result.Success || result.ErrorReason != "missing_turnstile_token" {
		t.Errorf("expected missing_turnstile_token, got %+v", result)
	}
}

func TestCompleteCeremony_TransportError(t *testing.T) {
	fake := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		http.Error(w, "boom", http.StatusInternalServerError)
	}))
	defer fake.Close()

	m := newTestMethod(t, fake.URL)
	resp := types.ResponseData{Type: "turnstile", Payload: map[string]any{"token": "x"}}
	if _, err := m.CompleteCeremony(context.Background(), types.CeremonyContext{SessionID: "s1"}, resp); err == nil {
		t.Fatal("expected error on non-2xx siteverify response")
	}
}

// ----------------------------------------------------------------------------
// helpers
// ----------------------------------------------------------------------------

func newTestMethod(t *testing.T, baseURL string) *Method {
	t.Helper()
	c, err := NewTurnstileClient("test-site-key", "test-secret-key", http.DefaultClient)
	if err != nil {
		t.Fatalf("new client: %v", err)
	}
	c.BaseURL = baseURL
	return NewMethod(Config{TurnstileClient: c})
}
