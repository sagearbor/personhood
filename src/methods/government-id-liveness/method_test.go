package governmentidliveness

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
	m := newTestMethod(t, "https://fake.example", "")
	md := m.Metadata()
	if md.ID != MethodID {
		t.Errorf("id mismatch: %q", md.ID)
	}
	if md.Type != types.MethodTypeAnchor {
		t.Errorf("expected anchor type, got %q", md.Type)
	}
	if md.Strength != 90 || md.Strength < 50 {
		t.Errorf("strength must be 90 and >=50, got %d", md.Strength)
	}
	if md.UXFriction != types.FrictionHigh {
		t.Errorf("expected high friction, got %q", md.UXFriction)
	}
	if md.FreshnessLifetime <= 0 {
		t.Error("freshness lifetime must be positive")
	}
}

func TestIsAvailableForUser_KioskDenied(t *testing.T) {
	m := newTestMethod(t, "https://fake.example", "")
	ok, reason := m.IsAvailableForUser(types.UserContext{Platform: "kiosk"})
	if ok {
		t.Error("kiosk platform should be denied")
	}
	if reason == "" {
		t.Error("denial should include a reason")
	}
}

func TestBeginCeremony_CreatesInquiry(t *testing.T) {
	// Fake Persona server: accept POST /inquiries and return a fixed inquiry.
	fakePersona := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/inquiries" || r.Method != http.MethodPost {
			http.Error(w, "unexpected request", http.StatusBadRequest)
			return
		}
		if r.Header.Get("Authorization") != "Bearer sandbox-key" {
			http.Error(w, "bad auth", http.StatusUnauthorized)
			return
		}
		body, _ := io.ReadAll(r.Body)
		if !strings.Contains(string(body), "itmpl_fake") {
			t.Errorf("body missing template id: %s", body)
		}
		if !strings.Contains(string(body), "session-123") {
			t.Errorf("body missing reference-id: %s", body)
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"data":{"id":"inq_abc","attributes":{"status":"created","session-token":"st_xxx"}}}`))
	}))
	defer fakePersona.Close()

	m := newTestMethod(t, fakePersona.URL, "https://app.example/return")
	cc := types.CeremonyContext{SessionID: "session-123", MethodID: MethodID}
	challenge, err := m.BeginCeremony(context.Background(), cc)
	if err != nil {
		t.Fatalf("begin: %v", err)
	}
	if challenge.Type != "persona-hosted-flow" {
		t.Errorf("challenge type mismatch: %q", challenge.Type)
	}
	inquiryID, _ := challenge.Payload["inquiry_id"].(string)
	if inquiryID != "inq_abc" {
		t.Errorf("inquiry_id mismatch: %q", inquiryID)
	}
	hosted, _ := challenge.Payload["hosted_flow_url"].(string)
	if !strings.Contains(hosted, "inquiry-id=inq_abc") {
		t.Errorf("hosted_flow_url missing inquiry-id param: %q", hosted)
	}
	if !strings.Contains(hosted, "redirect-uri=") {
		t.Errorf("hosted_flow_url missing redirect-uri: %q", hosted)
	}

	// Inquiry-to-session binding must be stored.
	sid, _ := m.store.LookupSessionByInquiry(context.Background(), "inq_abc")
	if sid != "session-123" {
		t.Errorf("inquiry binding not stored: got %q", sid)
	}
}

func TestBeginCeremony_PersonaError(t *testing.T) {
	fakePersona := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		http.Error(w, `{"errors":[{"detail":"template not found"}]}`, http.StatusUnprocessableEntity)
	}))
	defer fakePersona.Close()

	m := newTestMethod(t, fakePersona.URL, "")
	_, err := m.BeginCeremony(context.Background(), types.CeremonyContext{SessionID: "s"})
	if err == nil {
		t.Fatal("expected error from Persona 422")
	}
	if !strings.Contains(err.Error(), "422") {
		t.Errorf("error should mention the status code: %v", err)
	}
}

func TestCompleteCeremony_PendingWhenNoWebhook(t *testing.T) {
	m := newTestMethod(t, "https://fake.example", "")
	result, err := m.CompleteCeremony(context.Background(), types.CeremonyContext{SessionID: "s"}, types.ResponseData{})
	if err != nil {
		t.Fatalf("complete: %v", err)
	}
	if result.Success {
		t.Error("must not succeed without a webhook")
	}
	if result.ErrorReason != "pending_persona_webhook" {
		t.Errorf("error_reason mismatch: %q", result.ErrorReason)
	}
}

func TestCompleteCeremony_AfterApprovedWebhook(t *testing.T) {
	m := newTestMethod(t, "https://fake.example", "")
	const sessionID = "session-xyz"
	const inquiryID = "inq_approved"

	// Bind the inquiry and pre-populate the store as if the webhook arrived.
	if err := m.store.PutInquiry(context.Background(), sessionID, inquiryID); err != nil {
		t.Fatal(err)
	}
	if err := m.store.PutResult(context.Background(), sessionID, Result{
		InquiryID:   inquiryID,
		Status:      StatusApproved,
		RawStatus:   "approved",
		CompletedAt: time.Now().UTC(),
		EventName:   "inquiry.completed",
	}); err != nil {
		t.Fatal(err)
	}

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
	m := newTestMethod(t, "https://fake.example", "")
	const sessionID = "session-declined"
	_ = m.store.PutResult(context.Background(), sessionID, Result{
		InquiryID: "inq_d", Status: StatusDeclined, RawStatus: "declined",
		CompletedAt: time.Now(), EventName: "inquiry.completed",
	})
	result, _ := m.CompleteCeremony(context.Background(), types.CeremonyContext{SessionID: sessionID}, types.ResponseData{})
	if result.Success {
		t.Error("declined inquiry must not succeed")
	}
	if result.ErrorReason != "persona_declined" {
		t.Errorf("error_reason mismatch: %q", result.ErrorReason)
	}
}

func TestWebhook_VerifySignature_Round_Trip(t *testing.T) {
	secret := "whsec_test"
	body := []byte(`{"data":{}}`)
	now := time.Now()
	header := SignWebhookForTesting(secret, body, now)
	if err := VerifyWebhookSignature(secret, header, body, now); err != nil {
		t.Errorf("round-trip failed: %v", err)
	}
}

func TestWebhook_VerifySignature_BadSecret(t *testing.T) {
	header := SignWebhookForTesting("a", []byte("b"), time.Now())
	err := VerifyWebhookSignature("different", header, []byte("b"), time.Now())
	if err == nil {
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
	m := newTestMethod(t, "https://fake.example", "")
	const sessionID = "session-w1"
	const inquiryID = "inq_wh"
	_ = m.store.PutInquiry(context.Background(), sessionID, inquiryID)

	secret := "whsec_test"
	now := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	handler := m.WebhookHandler(secret, func() time.Time { return now })

	body := webhookBody(t, "inquiry.completed", inquiryID, sessionID, "approved")
	sig := SignWebhookForTesting(secret, body, now)
	req := httptest.NewRequest(http.MethodPost, "/webhook", bytes.NewReader(body))
	req.Header.Set("Persona-Signature", sig)
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("want 200, got %d: %s", rec.Code, rec.Body.String())
	}
	result, err := m.store.GetResult(context.Background(), sessionID)
	if err != nil {
		t.Fatalf("GetResult: %v", err)
	}
	if result.Status != StatusApproved {
		t.Errorf("status mismatch: %q", result.Status)
	}
	if result.RawStatus != "approved" {
		t.Errorf("raw_status mismatch: %q", result.RawStatus)
	}
}

func TestWebhookHandler_RejectsBadSignature(t *testing.T) {
	m := newTestMethod(t, "https://fake.example", "")
	handler := m.WebhookHandler("real", func() time.Time { return time.Now() })

	body := webhookBody(t, "inquiry.completed", "inq", "session", "approved")
	req := httptest.NewRequest(http.MethodPost, "/webhook", bytes.NewReader(body))
	req.Header.Set("Persona-Signature", "t=0,v1=deadbeef")
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)
	if rec.Code != http.StatusUnauthorized {
		t.Errorf("want 401, got %d", rec.Code)
	}
}

func TestWebhookHandler_ResolvesInquiryWhenReferenceMissing(t *testing.T) {
	m := newTestMethod(t, "https://fake.example", "")
	const sessionID = "session-fallback"
	const inquiryID = "inq_fallback"
	_ = m.store.PutInquiry(context.Background(), sessionID, inquiryID)

	secret := "whsec"
	now := time.Now()
	handler := m.WebhookHandler(secret, func() time.Time { return now })

	// Send a webhook body that OMITS reference-id; the handler should fall back
	// to LookupSessionByInquiry using the inquiry id alone.
	body := []byte(`{"data":{"attributes":{"name":"inquiry.completed","payload":{"data":{"id":"` + inquiryID + `","type":"inquiry","attributes":{"status":"approved"}}}}}}`)
	sig := SignWebhookForTesting(secret, body, now)
	req := httptest.NewRequest(http.MethodPost, "/webhook", bytes.NewReader(body))
	req.Header.Set("Persona-Signature", sig)
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("want 200, got %d: %s", rec.Code, rec.Body.String())
	}
	r, err := m.store.GetResult(context.Background(), sessionID)
	if err != nil {
		t.Fatalf("GetResult: %v", err)
	}
	if r.Status != StatusApproved {
		t.Errorf("status mismatch: %q", r.Status)
	}
}

func TestParseWebhookBody_StatusMapping(t *testing.T) {
	cases := []struct {
		raw  string
		want Status
	}{
		{"approved", StatusApproved},
		{"declined", StatusDeclined},
		{"needs_review", StatusNeedsReview},
		{"pending", StatusNeedsReview},
		{"completed", StatusApproved},
		{"something_else", "something_else"},
	}
	for _, tc := range cases {
		body := webhookBody(t, "inquiry.completed", "inq", "session", tc.raw)
		parsed, err := ParseWebhookBody(body)
		if err != nil {
			t.Fatalf("parse %q: %v", tc.raw, err)
		}
		if parsed.Status != tc.want {
			t.Errorf("%q -> %q, want %q", tc.raw, parsed.Status, tc.want)
		}
	}
}

// ----------------------------------------------------------------------------
// helpers
// ----------------------------------------------------------------------------

func newTestMethod(t *testing.T, personaBaseURL, returnURL string) *Method {
	t.Helper()
	pc := &PersonaClient{
		APIKey:     "sandbox-key",
		TemplateID: "itmpl_fake",
		BaseURL:    personaBaseURL,
		HTTPClient: http.DefaultClient,
	}
	store := NewInMemoryStore()
	return NewMethod(Config{PersonaClient: pc, Store: store, ReturnURL: returnURL})
}

func webhookBody(t *testing.T, eventName, inquiryID, referenceID, rawStatus string) []byte {
	t.Helper()
	payload := map[string]any{
		"data": map[string]any{
			"attributes": map[string]any{
				"name": eventName,
				"payload": map[string]any{
					"data": map[string]any{
						"id":   inquiryID,
						"type": "inquiry",
						"attributes": map[string]any{
							"status":       rawStatus,
							"reference-id": referenceID,
						},
					},
				},
			},
		},
	}
	b, err := json.Marshal(payload)
	if err != nil {
		t.Fatal(err)
	}
	return b
}
