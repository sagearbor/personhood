package paidbillingcard

import (
	"bytes"
	"context"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/sagearbor/personhood/pkg/types"
)

func newTestMethod(t *testing.T, stripeBaseURL string) *Method {
	t.Helper()
	sc := &StripeClient{
		SecretKey:           "sk_test_123",
		BaseURL:             stripeBaseURL,
		HTTPClient:          http.DefaultClient,
		RequestThreeDSecure: "any",
	}
	return NewMethod(Config{StripeClient: sc, Store: NewInMemoryStore(), PublishableKey: "pk_test_abc"})
}

func TestMetadata(t *testing.T) {
	m := newTestMethod(t, "https://fake.example")
	md := m.Metadata()
	if md.ID != MethodID {
		t.Errorf("id mismatch: %q", md.ID)
	}
	if md.Type != types.MethodTypeSupplementary {
		t.Errorf("expected supplementary (NOT an anchor), got %q", md.Type)
	}
	if md.Strength != 35 || md.Strength >= 50 {
		t.Errorf("strength must be 35 and <50, got %d", md.Strength)
	}
	if md.UXFriction != types.FrictionMed {
		t.Errorf("expected med friction, got %q", md.UXFriction)
	}
}

func TestBeginCeremony_CreatesSetupIntent(t *testing.T) {
	fakeStripe := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/v1/setup_intents" || r.Method != http.MethodPost {
			http.Error(w, "unexpected request", http.StatusBadRequest)
			return
		}
		if got := r.Header.Get("Authorization"); got != "Bearer sk_test_123" {
			t.Errorf("missing/incorrect auth header: %q", got)
		}
		body, _ := io.ReadAll(r.Body)
		if !strings.Contains(string(body), "request_three_d_secure") {
			t.Errorf("body should force 3DS: %s", body)
		}
		if !strings.Contains(string(body), "session-123") {
			t.Errorf("body should carry session id in metadata: %s", body)
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"id":"seti_abc","client_secret":"seti_abc_secret_xyz","status":"requires_payment_method"}`))
	}))
	defer fakeStripe.Close()

	m := newTestMethod(t, fakeStripe.URL)
	cc := types.CeremonyContext{SessionID: "session-123", MethodID: MethodID}
	challenge, err := m.BeginCeremony(context.Background(), cc)
	if err != nil {
		t.Fatalf("begin: %v", err)
	}
	if challenge.Type != "stripe-setup-intent" {
		t.Errorf("challenge type mismatch: %q", challenge.Type)
	}
	if cs, _ := challenge.Payload["client_secret"].(string); cs != "seti_abc_secret_xyz" {
		t.Errorf("client_secret mismatch: %q", cs)
	}
	if pk, _ := challenge.Payload["publishable_key"].(string); pk != "pk_test_abc" {
		t.Errorf("publishable_key missing: %q", pk)
	}
	sid, _ := m.store.LookupSessionBySetupIntent(context.Background(), "seti_abc")
	if sid != "session-123" {
		t.Errorf("setup intent binding not stored: got %q", sid)
	}
}

func TestBeginCeremony_StripeError(t *testing.T) {
	fakeStripe := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		http.Error(w, `{"error":{"type":"invalid_request_error"}}`, http.StatusBadRequest)
	}))
	defer fakeStripe.Close()
	m := newTestMethod(t, fakeStripe.URL)
	_, err := m.BeginCeremony(context.Background(), types.CeremonyContext{SessionID: "s"})
	if err == nil || !strings.Contains(err.Error(), "400") {
		t.Fatalf("expected 400 error, got %v", err)
	}
}

func TestCompleteCeremony_PendingWhenNoWebhook(t *testing.T) {
	m := newTestMethod(t, "https://fake.example")
	result, err := m.CompleteCeremony(context.Background(), types.CeremonyContext{SessionID: "s"}, types.ResponseData{})
	if err != nil {
		t.Fatalf("complete: %v", err)
	}
	if result.Success || result.ErrorReason != "pending_stripe_webhook" {
		t.Errorf("expected pending, got %+v", result)
	}
}

func TestCompleteCeremony_AfterApprovedWebhook(t *testing.T) {
	m := newTestMethod(t, "https://fake.example")
	const sessionID = "session-xyz"
	_ = m.store.PutResult(context.Background(), sessionID, Result{
		SetupIntentID:   "seti_ok",
		CardFingerprint: "fp_card_123",
		Status:          StatusApproved,
		RawStatus:       "setup_intent.succeeded",
		CompletedAt:     time.Now().UTC(),
	})
	result, err := m.CompleteCeremony(context.Background(), types.CeremonyContext{SessionID: sessionID}, types.ResponseData{})
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
}

func TestCompleteCeremony_AfterDeclinedWebhook(t *testing.T) {
	m := newTestMethod(t, "https://fake.example")
	const sessionID = "session-fail"
	_ = m.store.PutResult(context.Background(), sessionID, Result{
		SetupIntentID: "seti_d", Status: StatusDeclined, RawStatus: "setup_intent.setup_failed",
		CompletedAt: time.Now(),
	})
	result, _ := m.CompleteCeremony(context.Background(), types.CeremonyContext{SessionID: sessionID}, types.ResponseData{})
	if result.Success || result.ErrorReason != "card_declined" {
		t.Errorf("expected card_declined, got %+v", result)
	}
}

func TestWebhook_VerifySignature_RoundTrip(t *testing.T) {
	secret := "whsec_test"
	body := []byte(`{"type":"setup_intent.succeeded"}`)
	now := time.Now()
	header := SignWebhookForTesting(secret, body, now)
	if err := VerifyWebhookSignature(secret, header, body, now); err != nil {
		t.Errorf("round-trip failed: %v", err)
	}
}

func TestWebhook_VerifySignature_BadSecret(t *testing.T) {
	header := SignWebhookForTesting("a", []byte("b"), time.Now())
	if err := VerifyWebhookSignature("different", header, []byte("b"), time.Now()); err == nil {
		t.Error("verification should fail with wrong secret")
	}
}

func TestWebhook_VerifySignature_OutOfWindow(t *testing.T) {
	secret := "s"
	body := []byte(`{}`)
	old := time.Now().Add(-10 * time.Minute)
	header := SignWebhookForTesting(secret, body, old)
	if err := VerifyWebhookSignature(secret, header, body, time.Now()); err == nil {
		t.Error("verification should fail for stale timestamp")
	}
}

func TestWebhookHandler_Success_ExpandedFingerprint(t *testing.T) {
	m := newTestMethod(t, "https://fake.example")
	const sessionID = "session-w1"
	const setupIntentID = "seti_wh"
	_ = m.store.PutSetupIntent(context.Background(), sessionID, setupIntentID)

	secret := "whsec_test"
	now := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	handler := m.WebhookHandler(secret, func() time.Time { return now })

	body := []byte(`{"type":"setup_intent.succeeded","data":{"object":{"id":"seti_wh","status":"succeeded","payment_method":{"id":"pm_1","card":{"fingerprint":"fp_unique_card"}},"metadata":{"session_id":"session-w1"}}}}`)
	sig := SignWebhookForTesting(secret, body, now)
	req := httptest.NewRequest(http.MethodPost, "/webhook", bytes.NewReader(body))
	req.Header.Set("Stripe-Signature", sig)
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("want 200, got %d: %s", rec.Code, rec.Body.String())
	}
	result, err := m.store.GetResult(context.Background(), sessionID)
	if err != nil {
		t.Fatalf("GetResult: %v", err)
	}
	if result.Status != StatusApproved || result.CardFingerprint != "fp_unique_card" {
		t.Errorf("unexpected result: %+v", result)
	}
}

func TestWebhookHandler_ResolvesViaMetadataFallback(t *testing.T) {
	// No PutSetupIntent binding: the handler must fall back to metadata.session_id.
	m := newTestMethod(t, "https://fake.example")
	secret := "whsec_test"
	now := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	handler := m.WebhookHandler(secret, func() time.Time { return now })

	body := []byte(`{"type":"setup_intent.succeeded","data":{"object":{"id":"seti_meta","status":"succeeded","payment_method":"pm_2","metadata":{"session_id":"session-meta"}}}}`)
	sig := SignWebhookForTesting(secret, body, now)
	req := httptest.NewRequest(http.MethodPost, "/webhook", bytes.NewReader(body))
	req.Header.Set("Stripe-Signature", sig)
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("want 200, got %d: %s", rec.Code, rec.Body.String())
	}
	result, err := m.store.GetResult(context.Background(), "session-meta")
	if err != nil {
		t.Fatalf("GetResult via metadata fallback: %v", err)
	}
	// Unexpanded payment_method -> fingerprint falls back to the pm id.
	if result.CardFingerprint != "pm_2" {
		t.Errorf("expected fallback fingerprint pm_2, got %q", result.CardFingerprint)
	}
}

func TestWebhookHandler_RejectsBadSignature(t *testing.T) {
	m := newTestMethod(t, "https://fake.example")
	handler := m.WebhookHandler("real", func() time.Time { return time.Now() })
	body := []byte(`{"type":"setup_intent.succeeded","data":{"object":{"id":"seti_x"}}}`)
	req := httptest.NewRequest(http.MethodPost, "/webhook", bytes.NewReader(body))
	req.Header.Set("Stripe-Signature", "t=0,v1=deadbeef")
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)
	if rec.Code != http.StatusUnauthorized {
		t.Errorf("want 401, got %d", rec.Code)
	}
}

func TestWebhookHandler_IgnoresNonTerminalEvent(t *testing.T) {
	m := newTestMethod(t, "https://fake.example")
	secret := "whsec_test"
	now := time.Now()
	handler := m.WebhookHandler(secret, func() time.Time { return now })
	body := []byte(`{"type":"setup_intent.created","data":{"object":{"id":"seti_c"}}}`)
	sig := SignWebhookForTesting(secret, body, now)
	req := httptest.NewRequest(http.MethodPost, "/webhook", bytes.NewReader(body))
	req.Header.Set("Stripe-Signature", sig)
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK || !strings.Contains(rec.Body.String(), "ignored") {
		t.Errorf("non-terminal event should be acknowledged+ignored, got %d %s", rec.Code, rec.Body.String())
	}
}

func TestParseWebhookBody_EventMapping(t *testing.T) {
	cases := []struct {
		eventType string
		want      Status
	}{
		{"setup_intent.succeeded", StatusApproved},
		{"setup_intent.setup_failed", StatusDeclined},
		{"setup_intent.canceled", StatusCanceled},
		{"setup_intent.created", ""},
	}
	for _, tc := range cases {
		body := []byte(`{"type":"` + tc.eventType + `","data":{"object":{"id":"seti_1"}}}`)
		parsed, err := ParseWebhookBody(body)
		if err != nil {
			t.Fatalf("parse %q: %v", tc.eventType, err)
		}
		if parsed.Status != tc.want {
			t.Errorf("%q -> %q, want %q", tc.eventType, parsed.Status, tc.want)
		}
	}
}
