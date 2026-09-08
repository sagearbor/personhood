package phonecarriertier

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/sagearbor/personhood/pkg/types"
)

// captureSender records the last OTP body so tests can complete the ceremony.
type captureSender struct {
	lastTo   string
	lastBody string
	err      error
}

func (c *captureSender) Send(_ context.Context, to, body string) error {
	if c.err != nil {
		return c.err
	}
	c.lastTo, c.lastBody = to, body
	return nil
}

func newTestMethod(t *testing.T, provider CarrierProvider) (*Method, *captureSender) {
	t.Helper()
	cs := &captureSender{}
	m := NewMethod(Config{Sender: cs, Store: NewInMemoryStore(), Provider: provider})
	return m, cs
}

// otpFromBody extracts the 6-digit code from the captured SMS body.
func otpFromBody(t *testing.T, body string) string {
	t.Helper()
	fields := strings.Fields(body)
	code := fields[len(fields)-1]
	if len(code) != 6 {
		t.Fatalf("expected 6-digit code, got %q from %q", code, body)
	}
	return code
}

func TestMetadata(t *testing.T) {
	m, _ := newTestMethod(t, nil) // nil -> NeutralProvider
	md := m.Metadata()
	if md.ID != MethodID {
		t.Errorf("id mismatch: %q", md.ID)
	}
	if md.Type != types.MethodTypeSupplementary {
		t.Errorf("expected supplementary, got %q", md.Type)
	}
	if md.Strength != 28 || md.Strength >= 50 {
		t.Errorf("strength must be 28 and <50, got %d", md.Strength)
	}
	if md.UXFriction != types.FrictionMed {
		t.Errorf("expected med friction, got %q", md.UXFriction)
	}
	if m.ProviderName() != "neutral" {
		t.Errorf("nil provider should default to neutral, got %q", m.ProviderName())
	}
}

func TestIsAvailableForUser(t *testing.T) {
	m, _ := newTestMethod(t, nil)
	if ok, _ := m.IsAvailableForUser(types.UserContext{Platform: "android"}); !ok {
		t.Error("android should be available")
	}
	if ok, reason := m.IsAvailableForUser(types.UserContext{Platform: "kiosk"}); ok || reason == "" {
		t.Errorf("kiosk should be unavailable with a reason, got ok=%v reason=%q", ok, reason)
	}
}

func TestBeginCeremony_RejectsFictionalVOIP(t *testing.T) {
	m, _ := newTestMethod(t, nil)
	cc := types.CeremonyContext{SessionID: "s", UserID: "+12025550100"}
	if _, err := m.BeginCeremony(context.Background(), cc); err == nil {
		t.Fatal("fictional 555 number should be rejected by the offline pre-check")
	}
}

func TestBeginCeremony_RequiresUserID(t *testing.T) {
	m, _ := newTestMethod(t, nil)
	if _, err := m.BeginCeremony(context.Background(), types.CeremonyContext{SessionID: "s"}); err == nil {
		t.Fatal("expected error when UserID is empty")
	}
}

func TestFullCeremony_SuccessWithNeutralProvider(t *testing.T) {
	m, cs := newTestMethod(t, nil)
	// A UK mobile-shaped number: the offline LooksLikeVOIP pre-check only fires
	// on +1 fictional/unassigned bands, so a +44 number passes it cleanly.
	cc := types.CeremonyContext{SessionID: "sess-1", UserID: "+447911123456"}

	challenge, err := m.BeginCeremony(context.Background(), cc)
	if err != nil {
		t.Fatalf("begin: %v", err)
	}
	if challenge.Type != "otp" {
		t.Errorf("challenge type: %q", challenge.Type)
	}
	if challenge.Payload["line_type"] != string(LineTypeUnknown) {
		t.Errorf("neutral provider should report unknown line type, got %v", challenge.Payload["line_type"])
	}

	code := otpFromBody(t, cs.lastBody)
	resp := types.ResponseData{Type: "otp", Payload: map[string]any{"phone_number": cc.UserID, "code": code}}
	result, err := m.CompleteCeremony(context.Background(), cc, resp)
	if err != nil {
		t.Fatalf("complete: %v", err)
	}
	if !result.Success {
		t.Errorf("expected success, got %+v", result)
	}
	if result.AttestationDigest == "" || result.VerifiedAt.IsZero() {
		t.Errorf("success must set digest + verified_at, got %+v", result)
	}

	// replay must fail (OTP single-use)
	replay, _ := m.CompleteCeremony(context.Background(), cc, resp)
	if replay.Success {
		t.Error("OTP replay should fail")
	}
}

func TestCompleteCeremony_WrongCodeThenLockout(t *testing.T) {
	m, _ := newTestMethod(t, nil)
	cc := types.CeremonyContext{SessionID: "sess-2", UserID: "+447911123457"}
	if _, err := m.BeginCeremony(context.Background(), cc); err != nil {
		t.Fatalf("begin: %v", err)
	}
	bad := types.ResponseData{Type: "otp", Payload: map[string]any{"phone_number": cc.UserID, "code": "000000"}}
	// MaxAttempts wrong tries -> lockout
	var last types.MethodResult
	for i := 0; i < MaxAttempts; i++ {
		last, _ = m.CompleteCeremony(context.Background(), cc, bad)
	}
	if last.Success || last.ErrorReason != "too_many_attempts" {
		t.Errorf("expected too_many_attempts after %d wrong tries, got %+v", MaxAttempts, last)
	}
}

func TestBeginCeremony_RejectsVOIPFromProvider(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"line_type_intelligence":{"type":"nonFixedVoip","carrier_name":"BurnerVOIP"}}`))
	}))
	defer srv.Close()
	p, _ := NewTwilioLookupProvider("AC123", "token", srv.Client())
	p.BaseURL = srv.URL
	m, _ := newTestMethod(t, p)
	cc := types.CeremonyContext{SessionID: "s", UserID: "+447911123458"}
	if _, err := m.BeginCeremony(context.Background(), cc); err == nil {
		t.Fatal("a carrier-reported VOIP line must be rejected")
	}
}

func TestBeginCeremony_RejectsRecentlyPorted(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte(`{"line_type_intelligence":{"type":"mobile","carrier_name":"RealMobile"},"sim_swap":{"last_sim_swap":{"swapped_in_period":true}}}`))
	}))
	defer srv.Close()
	p, _ := NewTwilioLookupProvider("AC123", "token", srv.Client())
	p.BaseURL = srv.URL
	p.IncludeSimSwap = true
	m, _ := newTestMethod(t, p)
	cc := types.CeremonyContext{SessionID: "s", UserID: "+447911123459"}
	if _, err := m.BeginCeremony(context.Background(), cc); err == nil {
		t.Fatal("a recently-ported (SIM-swap) line must be rejected")
	}
}

func TestTwilioLookupProvider_Mobile(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if u, _, ok := r.BasicAuth(); !ok || u != "AC123" {
			t.Errorf("missing/incorrect basic auth: %q", u)
		}
		_, _ = w.Write([]byte(`{"line_type_intelligence":{"type":"mobile","carrier_name":"AT&T"}}`))
	}))
	defer srv.Close()
	p, err := NewTwilioLookupProvider("AC123", "token", srv.Client())
	if err != nil {
		t.Fatal(err)
	}
	p.BaseURL = srv.URL
	sig, err := p.Lookup(context.Background(), "+14155550000")
	if err != nil {
		t.Fatalf("lookup: %v", err)
	}
	if sig.LineType != LineTypeMobile || sig.Carrier != "AT&T" {
		t.Errorf("unexpected signal: %+v", sig)
	}
}

func TestTwilioLookupProvider_NotFoundIsUnknown(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		http.Error(w, "not found", http.StatusNotFound)
	}))
	defer srv.Close()
	p, _ := NewTwilioLookupProvider("AC123", "token", srv.Client())
	p.BaseURL = srv.URL
	sig, err := p.Lookup(context.Background(), "+10000000000")
	if err != nil {
		t.Fatalf("404 should not be an error: %v", err)
	}
	if sig.LineType != LineTypeUnknown {
		t.Errorf("404 should map to unknown, got %q", sig.LineType)
	}
}

func TestTwilioLookupProvider_ServerError(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		http.Error(w, "boom", http.StatusInternalServerError)
	}))
	defer srv.Close()
	p, _ := NewTwilioLookupProvider("AC123", "token", srv.Client())
	p.BaseURL = srv.URL
	if _, err := p.Lookup(context.Background(), "+14155550000"); err == nil {
		t.Fatal("expected error on 500")
	}
}

func TestMapTwilioLineType(t *testing.T) {
	cases := map[string]LineType{
		"mobile":       LineTypeMobile,
		"landline":     LineTypeLandline,
		"fixedVoip":    LineTypeVOIP,
		"nonFixedVoip": LineTypeVOIP,
		"tollFree":     LineTypeUnknown,
		"":             LineTypeUnknown,
	}
	for in, want := range cases {
		if got := mapTwilioLineType(in); got != want {
			t.Errorf("mapTwilioLineType(%q) = %q, want %q", in, got, want)
		}
	}
}
