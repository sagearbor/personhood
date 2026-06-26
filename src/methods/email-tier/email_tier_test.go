package emailtier

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/sagearbor/personhood/pkg/types"
)

// captureSender records the last magic link so tests can complete the ceremony.
type captureSender struct {
	lastTo   string
	lastLink string
	err      error
}

func (c *captureSender) Send(_ context.Context, to, _, link string) error {
	if c.err != nil {
		return c.err
	}
	c.lastTo, c.lastLink = to, link
	return nil
}

func newTestMethod(t *testing.T, provider EnrichmentProvider) (*Method, *captureSender) {
	t.Helper()
	cs := &captureSender{}
	m := NewMethod(Config{
		Sender:   cs,
		BaseURL:  "https://issuer.example/v1/methods/email-tier/verify",
		Store:    NewInMemoryStore(),
		Provider: provider,
	})
	return m, cs
}

func TestMetadata(t *testing.T) {
	m, _ := newTestMethod(t, nil) // nil provider -> NeutralProvider
	md := m.Metadata()
	if md.ID != MethodID {
		t.Errorf("id mismatch: %q", md.ID)
	}
	if md.Type != types.MethodTypeSupplementary {
		t.Errorf("expected supplementary, got %q", md.Type)
	}
	if md.Strength != 22 || md.Strength >= 50 {
		t.Errorf("strength must be 22 and <50, got %d", md.Strength)
	}
	if md.UXFriction != types.FrictionLow {
		t.Errorf("expected low friction, got %q", md.UXFriction)
	}
	if m.ProviderName() != "neutral" {
		t.Errorf("nil provider should default to neutral, got %q", m.ProviderName())
	}
}

func TestBeginCeremony_RejectsDisposable(t *testing.T) {
	m, _ := newTestMethod(t, nil)
	cc := types.CeremonyContext{SessionID: "s1", UserID: "bot@mailinator.com"}
	if _, err := m.BeginCeremony(context.Background(), cc); err == nil {
		t.Fatal("expected disposable address to be rejected")
	}
}

func TestBeginCeremony_RejectsMalformed(t *testing.T) {
	m, _ := newTestMethod(t, nil)
	cc := types.CeremonyContext{SessionID: "s1", UserID: "not-an-email"}
	if _, err := m.BeginCeremony(context.Background(), cc); err == nil {
		t.Fatal("expected malformed address to be rejected")
	}
}

func TestBeginCeremony_RequiresUserID(t *testing.T) {
	m, _ := newTestMethod(t, nil)
	if _, err := m.BeginCeremony(context.Background(), types.CeremonyContext{SessionID: "s1"}); err == nil {
		t.Fatal("expected error when UserID is empty")
	}
}

func TestFullCeremony_SuccessWithNeutralProvider(t *testing.T) {
	m, cs := newTestMethod(t, nil)
	cc := types.CeremonyContext{SessionID: "sess-1", UserID: "alice@example.com"}

	challenge, err := m.BeginCeremony(context.Background(), cc)
	if err != nil {
		t.Fatalf("begin: %v", err)
	}
	if challenge.Type != "magic-link" {
		t.Errorf("challenge type: %q", challenge.Type)
	}
	if challenge.Payload["domain_reputation"] == nil {
		t.Error("expected domain_reputation in payload")
	}
	if cs.lastTo != "alice@example.com" {
		t.Errorf("sender not invoked with address: %q", cs.lastTo)
	}

	// extract the token from the magic link
	token := tokenFromLink(t, cs.lastLink)
	resp := types.ResponseData{Type: "magic-link-click", Payload: map[string]any{"token": token}}
	result, err := m.CompleteCeremony(context.Background(), cc, resp)
	if err != nil {
		t.Fatalf("complete: %v", err)
	}
	if !result.Success {
		t.Errorf("expected success, got %+v", result)
	}
	if result.AttestationDigest == "" {
		t.Error("attestation digest must be non-empty on success")
	}
	if result.VerifiedAt.IsZero() {
		t.Error("verified_at must be set on success")
	}

	// token is single-use: a replay must fail
	replay, _ := m.CompleteCeremony(context.Background(), cc, resp)
	if replay.Success {
		t.Error("token replay should fail (single-use)")
	}
}

func TestCompleteCeremony_WrongToken(t *testing.T) {
	m, _ := newTestMethod(t, nil)
	cc := types.CeremonyContext{SessionID: "sess-2", UserID: "bob@example.com"}
	if _, err := m.BeginCeremony(context.Background(), cc); err != nil {
		t.Fatalf("begin: %v", err)
	}
	resp := types.ResponseData{Type: "magic-link-click", Payload: map[string]any{"token": "wrong"}}
	result, _ := m.CompleteCeremony(context.Background(), cc, resp)
	if result.Success || result.ErrorReason != "invalid_or_expired_token" {
		t.Errorf("expected invalid_or_expired_token, got %+v", result)
	}
}

func TestCompleteCeremony_WrongResponseType(t *testing.T) {
	m, _ := newTestMethod(t, nil)
	result, _ := m.CompleteCeremony(context.Background(), types.CeremonyContext{SessionID: "x"}, types.ResponseData{Type: "otp"})
	if result.Success || !strings.Contains(result.ErrorReason, "unexpected response type") {
		t.Errorf("expected unexpected-response-type failure, got %+v", result)
	}
}

func TestDomainReputation(t *testing.T) {
	cases := []struct {
		domain string
		want   int
	}{
		{"mailinator.com", 0},
		{"gmail.com", 60},
		{"icloud.com", 62},
		{"my-startup.io", 55},
		{"", 50},
	}
	for _, tc := range cases {
		if got := DomainReputation(tc.domain); got != tc.want {
			t.Errorf("DomainReputation(%q) = %d, want %d", tc.domain, got, tc.want)
		}
	}
}

func TestHIBPProvider_BreachPresent(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("hibp-api-key") != "test-key" {
			t.Errorf("missing api key header")
		}
		if r.Header.Get("user-agent") == "" {
			t.Error("HIBP requires a user-agent")
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`[{"Name":"Adobe"},{"Name":"LinkedIn"}]`))
	}))
	defer srv.Close()

	p, err := NewHIBPProvider("test-key", srv.Client())
	if err != nil {
		t.Fatal(err)
	}
	p.BaseURL = srv.URL
	sig, err := p.Enrich(context.Background(), "real@gmail.com")
	if err != nil {
		t.Fatalf("enrich: %v", err)
	}
	if !sig.BreachPresence || sig.BreachCount != 2 {
		t.Errorf("expected breach presence with 2 breaches, got %+v", sig)
	}
	if sig.Provider != "haveibeenpwned" {
		t.Errorf("provider name mismatch: %q", sig.Provider)
	}
}

func TestHIBPProvider_NoBreach404(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		http.Error(w, "not found", http.StatusNotFound)
	}))
	defer srv.Close()

	p, _ := NewHIBPProvider("k", srv.Client())
	p.BaseURL = srv.URL
	sig, err := p.Enrich(context.Background(), "fresh@example.com")
	if err != nil {
		t.Fatalf("404 should not be an error: %v", err)
	}
	if sig.BreachPresence {
		t.Error("404 means no breaches")
	}
}

func TestHIBPProvider_ServerError(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		http.Error(w, "rate limited", http.StatusTooManyRequests)
	}))
	defer srv.Close()
	p, _ := NewHIBPProvider("k", srv.Client())
	p.BaseURL = srv.URL
	if _, err := p.Enrich(context.Background(), "a@b.com"); err == nil {
		t.Fatal("expected error on 429")
	}
}

func TestBeginCeremony_HIBPDisposableStillRejected(t *testing.T) {
	// Even with a real provider, the static disposable list must reject.
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		http.Error(w, "nf", http.StatusNotFound)
	}))
	defer srv.Close()
	p, _ := NewHIBPProvider("k", srv.Client())
	p.BaseURL = srv.URL
	m, _ := newTestMethod(t, p)
	cc := types.CeremonyContext{SessionID: "s", UserID: "x@guerrillamail.com"}
	if _, err := m.BeginCeremony(context.Background(), cc); err == nil {
		t.Fatal("disposable must be rejected even with HIBP provider")
	}
}

// tokenFromLink extracts the magic-link token query param.
func tokenFromLink(t *testing.T, link string) string {
	t.Helper()
	i := strings.Index(link, "token=")
	if i < 0 {
		t.Fatalf("no token in link: %s", link)
	}
	tok := link[i+len("token="):]
	if amp := strings.IndexByte(tok, '&'); amp >= 0 {
		tok = tok[:amp]
	}
	return tok
}
