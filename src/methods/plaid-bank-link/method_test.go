package plaidbanklink

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/sagearbor/personhood/pkg/types"
)

func TestMetadata(t *testing.T) {
	m := newTestMethod(t, "https://fake.example")
	md := m.Metadata()
	if md.ID != MethodID {
		t.Errorf("id mismatch: %q", md.ID)
	}
	if md.Type != types.MethodTypeAnchor {
		t.Errorf("expected anchor type, got %q", md.Type)
	}
	if md.Strength != 88 || md.Strength < 50 {
		t.Errorf("strength must be 88 and >=50, got %d", md.Strength)
	}
	if md.UXFriction != types.FrictionMed {
		t.Errorf("expected med friction, got %q", md.UXFriction)
	}
	if md.FreshnessLifetime <= 0 {
		t.Error("freshness lifetime must be positive")
	}
}

func TestIsAvailableForUser(t *testing.T) {
	m := newTestMethod(t, "https://fake.example")
	if ok, _ := m.IsAvailableForUser(types.UserContext{CountryCode: "US"}); !ok {
		t.Error("US should be available")
	}
	if ok, _ := m.IsAvailableForUser(types.UserContext{}); !ok {
		t.Error("empty country should be available")
	}
	ok, reason := m.IsAvailableForUser(types.UserContext{CountryCode: "DE"})
	if ok || reason == "" {
		t.Errorf("non-US should be denied with a reason, got ok=%v reason=%q", ok, reason)
	}
}

func TestBeginCeremony_CreatesLinkSession(t *testing.T) {
	fakePlaid := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/link/token/create" || r.Method != http.MethodPost {
			http.Error(w, "unexpected request", http.StatusBadRequest)
			return
		}
		body, _ := io.ReadAll(r.Body)
		if !strings.Contains(string(body), "session-123") {
			t.Errorf("body missing client_user_id: %s", body)
		}
		if !strings.Contains(string(body), "hosted_link") {
			t.Errorf("body should enable hosted_link: %s", body)
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"link_token":"link-sandbox-abc","hosted_link_url":"https://hosted.plaid.com/?link_token=link-sandbox-abc","expiration":"2026-06-15T13:00:00Z"}`))
	}))
	defer fakePlaid.Close()

	m := newTestMethod(t, fakePlaid.URL)
	cc := types.CeremonyContext{SessionID: "session-123", MethodID: MethodID}
	challenge, err := m.BeginCeremony(context.Background(), cc)
	if err != nil {
		t.Fatalf("begin: %v", err)
	}
	if challenge.Type != "plaid-hosted-link" {
		t.Errorf("challenge type mismatch: %q", challenge.Type)
	}
	if lt, _ := challenge.Payload["link_token"].(string); lt != "link-sandbox-abc" {
		t.Errorf("link_token mismatch: %q", lt)
	}
	hosted, _ := challenge.Payload["hosted_link_url"].(string)
	if !strings.Contains(hosted, "link-sandbox-abc") {
		t.Errorf("hosted_link_url missing token: %q", hosted)
	}
	sid, _ := m.store.LookupSessionByLinkToken(context.Background(), "link-sandbox-abc")
	if sid != "session-123" {
		t.Errorf("link token binding not stored: got %q", sid)
	}
}

func TestBeginCeremony_PlaidError(t *testing.T) {
	fakePlaid := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		http.Error(w, `{"error_code":"INVALID_API_KEYS"}`, http.StatusBadRequest)
	}))
	defer fakePlaid.Close()

	m := newTestMethod(t, fakePlaid.URL)
	_, err := m.BeginCeremony(context.Background(), types.CeremonyContext{SessionID: "s"})
	if err == nil {
		t.Fatal("expected error from Plaid 400")
	}
	if !strings.Contains(err.Error(), "400") {
		t.Errorf("error should mention the status code: %v", err)
	}
}

func TestBeginCeremony_NoHostedURL(t *testing.T) {
	fakePlaid := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte(`{"link_token":"link-x"}`)) // missing hosted_link_url
	}))
	defer fakePlaid.Close()
	m := newTestMethod(t, fakePlaid.URL)
	if _, err := m.BeginCeremony(context.Background(), types.CeremonyContext{SessionID: "s"}); err == nil {
		t.Fatal("expected error when hosted_link_url is missing")
	}
}

func TestCompleteCeremony_PendingWhenNoWebhook(t *testing.T) {
	m := newTestMethod(t, "https://fake.example")
	result, err := m.CompleteCeremony(context.Background(), types.CeremonyContext{SessionID: "s"}, types.ResponseData{})
	if err != nil {
		t.Fatalf("complete: %v", err)
	}
	if result.Success || result.ErrorReason != "pending_plaid_webhook" {
		t.Errorf("expected pending, got %+v", result)
	}
}

func TestCompleteCeremony_AfterApprovedWebhook(t *testing.T) {
	m := newTestMethod(t, "https://fake.example")
	const sessionID = "session-xyz"
	_ = m.store.PutResult(context.Background(), sessionID, Result{
		LinkSessionID: "lcs_ok",
		Status:        StatusApproved,
		RawStatus:     "SUCCESS",
		CompletedAt:   time.Now().UTC(),
		EventName:     "SESSION_FINISHED",
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
	const sessionID = "session-exited"
	_ = m.store.PutResult(context.Background(), sessionID, Result{
		LinkSessionID: "lcs_d", Status: StatusDeclined, RawStatus: "EXITED",
		CompletedAt: time.Now(), EventName: "SESSION_FINISHED",
	})
	result, _ := m.CompleteCeremony(context.Background(), types.CeremonyContext{SessionID: sessionID}, types.ResponseData{})
	if result.Success || result.ErrorReason != "plaid_declined" {
		t.Errorf("expected plaid_declined, got %+v", result)
	}
}

func TestWebhook_VerifySignature_RoundTrip(t *testing.T) {
	secret := "whsec_test"
	body := []byte(`{"webhook_type":"LINK"}`)
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

func TestWebhookHandler_Success(t *testing.T) {
	m := newTestMethod(t, "https://fake.example")
	const sessionID = "session-w1"
	const linkToken = "link-wh"
	_ = m.store.PutLinkToken(context.Background(), sessionID, linkToken)

	secret := "whsec_test"
	now := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	handler := m.WebhookHandler(secret, func() time.Time { return now })

	body := webhookBody(t, "SESSION_FINISHED", linkToken, "lcs_1", "SUCCESS")
	sig := SignWebhookForTesting(secret, body, now)
	req := httptest.NewRequest(http.MethodPost, "/webhook", bytes.NewReader(body))
	req.Header.Set("Plaid-Signature", sig)
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("want 200, got %d: %s", rec.Code, rec.Body.String())
	}
	result, err := m.store.GetResult(context.Background(), sessionID)
	if err != nil {
		t.Fatalf("GetResult: %v", err)
	}
	if result.Status != StatusApproved || result.RawStatus != "SUCCESS" {
		t.Errorf("unexpected result: %+v", result)
	}
}

func TestWebhookHandler_RejectsBadSignature(t *testing.T) {
	m := newTestMethod(t, "https://fake.example")
	handler := m.WebhookHandler("real", func() time.Time { return time.Now() })
	body := webhookBody(t, "SESSION_FINISHED", "link", "lcs", "SUCCESS")
	req := httptest.NewRequest(http.MethodPost, "/webhook", bytes.NewReader(body))
	req.Header.Set("Plaid-Signature", "t=0,v1=deadbeef")
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)
	if rec.Code != http.StatusUnauthorized {
		t.Errorf("want 401, got %d", rec.Code)
	}
}

func TestParseWebhookBody_StatusMapping(t *testing.T) {
	cases := []struct {
		code string
		raw  string
		want Status
	}{
		{"SESSION_FINISHED", "SUCCESS", StatusApproved},
		{"SESSION_FINISHED", "EXITED", StatusDeclined},
		{"SESSION_FINISHED", "REQUIRES_REVIEW", StatusNeedsReview},
		{"SESSION_FINISHED", "PENDING", StatusNeedsReview},
		{"SESSION_EXPIRED", "", StatusExpired},
		{"SESSION_FINISHED", "WAT", "wat"},
	}
	for _, tc := range cases {
		body := webhookBody(t, tc.code, "link", "lcs", tc.raw)
		parsed, err := ParseWebhookBody(body)
		if err != nil {
			t.Fatalf("parse %q/%q: %v", tc.code, tc.raw, err)
		}
		if parsed.Status != tc.want {
			t.Errorf("%q/%q -> %q, want %q", tc.code, tc.raw, parsed.Status, tc.want)
		}
	}
}

// ----------------------------------------------------------------------------
// helpers
// ----------------------------------------------------------------------------

func newTestMethod(t *testing.T, plaidBaseURL string) *Method {
	t.Helper()
	pc := &PlaidClient{
		ClientID:   "test-client",
		Secret:     "test-secret",
		BaseURL:    plaidBaseURL,
		HTTPClient: http.DefaultClient,
		Products:   []string{"auth", "identity"},
	}
	return NewMethod(Config{PlaidClient: pc, Store: NewInMemoryStore()})
}

func webhookBody(t *testing.T, code, linkToken, linkSessionID, status string) []byte {
	t.Helper()
	payload := map[string]any{
		"webhook_type":    "LINK",
		"webhook_code":    code,
		"link_token":      linkToken,
		"link_session_id": linkSessionID,
		"status":          status,
	}
	b, err := json.Marshal(payload)
	if err != nil {
		t.Fatal(err)
	}
	return b
}
