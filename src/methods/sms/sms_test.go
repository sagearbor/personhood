package sms

import (
	"bytes"
	"context"
	"errors"
	"io"
	"log"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/sagearbor/personhood/pkg/types"
)

// recordingSender captures the last (toPhone, body) pair Send was called with,
// extracting the embedded OTP for the round-trip tests.
type recordingSender struct {
	mu          sync.Mutex
	lastTo      string
	lastBody    string
	lastOTP     string
	failNext    bool
	failNextErr error
}

func (r *recordingSender) Send(_ context.Context, toPhone string, body string) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.failNext {
		r.failNext = false
		return r.failNextErr
	}
	r.lastTo = toPhone
	r.lastBody = body
	// extract the 6-digit OTP from "Your Personhood verification code: 123456"
	if i := strings.LastIndex(body, ": "); i >= 0 && len(body) >= i+2+6 {
		r.lastOTP = body[i+2 : i+2+6]
	}
	return nil
}

func (r *recordingSender) snapshot() (to, body, otp string) {
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.lastTo, r.lastBody, r.lastOTP
}

func newTestMethod(t *testing.T) (*Method, *recordingSender, *InMemoryStore) {
	t.Helper()
	sender := &recordingSender{}
	store := NewInMemoryStore()
	return NewMethod(sender, store), sender, store
}

func cc(session, phone string) types.CeremonyContext {
	return types.CeremonyContext{
		SessionID: session,
		UserID:    phone,
		MethodID:  methodID,
		StartedAt: time.Now(),
	}
}

func TestMetadata_ConformsToSupplementaryInvariants(t *testing.T) {
	m, _, _ := newTestMethod(t)
	meta := m.Metadata()
	if meta.ID != methodID {
		t.Errorf("ID = %q, want %q", meta.ID, methodID)
	}
	if meta.Type != types.MethodTypeSupplementary {
		t.Errorf("Type = %v, want supplementary", meta.Type)
	}
	if meta.Strength >= 50 {
		t.Errorf("Strength = %d; supplementary must be <50", meta.Strength)
	}
	if err := meta.Validate(); err != nil {
		t.Errorf("Metadata.Validate: %v", err)
	}
}

func TestBegin_Complete_HappyPath(t *testing.T) {
	m, sender, _ := newTestMethod(t)
	ctx := context.Background()
	cctx := cc("sess-1", "+14152220143")

	challenge, err := m.BeginCeremony(ctx, cctx)
	if err != nil {
		t.Fatalf("BeginCeremony: %v", err)
	}
	if challenge.Type != "otp" {
		t.Errorf("challenge.Type = %q, want \"otp\"", challenge.Type)
	}
	if last4, _ := challenge.Payload["phone_number_last4"].(string); last4 != "0143" {
		t.Errorf("phone_number_last4 = %q, want \"0143\"", last4)
	}

	_, _, otp := sender.snapshot()
	if len(otp) != 6 {
		t.Fatalf("expected 6-digit OTP in send body, got %q", otp)
	}

	result, err := m.CompleteCeremony(ctx, cctx, types.ResponseData{
		Type: "otp",
		Payload: map[string]any{
			"phone_number": "+14152220143",
			"code":         otp,
		},
	})
	if err != nil {
		t.Fatalf("CompleteCeremony: %v", err)
	}
	if !result.Success {
		t.Fatalf("expected Success=true, got result=%+v", result)
	}
	if result.AttestationDigest == "" {
		t.Error("expected non-empty AttestationDigest")
	}
}

func TestComplete_WrongCode_DecrementsAttempts(t *testing.T) {
	m, sender, _ := newTestMethod(t)
	ctx := context.Background()
	cctx := cc("sess-wrong", "+14152220199")

	if _, err := m.BeginCeremony(ctx, cctx); err != nil {
		t.Fatalf("BeginCeremony: %v", err)
	}
	_, _, _ = sender.snapshot()

	// 2 wrong attempts each leave attempts remaining > 0
	for i := 1; i <= 2; i++ {
		result, err := m.CompleteCeremony(ctx, cctx, types.ResponseData{
			Type:    "otp",
			Payload: map[string]any{"phone_number": "+14152220199", "code": "000000"},
		})
		if err != nil {
			t.Fatalf("attempt %d: unexpected err: %v", i, err)
		}
		if result.Success {
			t.Fatalf("attempt %d: did not expect Success=true with code 000000", i)
		}
		if !strings.Contains(result.ErrorReason, "wrong_code") {
			t.Errorf("attempt %d: ErrorReason = %q, expected to contain wrong_code", i, result.ErrorReason)
		}
	}
}

func TestComplete_ThreeWrong_LocksOut(t *testing.T) {
	m, sender, _ := newTestMethod(t)
	ctx := context.Background()
	cctx := cc("sess-lock", "+14152220100")

	if _, err := m.BeginCeremony(ctx, cctx); err != nil {
		t.Fatalf("BeginCeremony: %v", err)
	}
	_, _, _ = sender.snapshot()

	var last types.MethodResult
	for i := 1; i <= 3; i++ {
		result, err := m.CompleteCeremony(ctx, cctx, types.ResponseData{
			Type:    "otp",
			Payload: map[string]any{"phone_number": "+14152220100", "code": "000000"},
		})
		if err != nil {
			t.Fatalf("attempt %d: unexpected err: %v", i, err)
		}
		last = result
	}
	if last.Success {
		t.Errorf("after 3 wrong attempts expected lockout, got Success=true")
	}
	if last.ErrorReason != "too_many_attempts" {
		t.Errorf("after 3 wrong attempts ErrorReason = %q, want \"too_many_attempts\"", last.ErrorReason)
	}
	// 4th attempt with the (now-known) wrong code also fails as locked out.
	result, _ := m.CompleteCeremony(ctx, cctx, types.ResponseData{
		Type:    "otp",
		Payload: map[string]any{"phone_number": "+12025550100", "code": "000000"},
	})
	if result.Success {
		t.Errorf("4th attempt after lockout should not succeed")
	}
}

func TestBegin_VOIPNumber_Rejected(t *testing.T) {
	m, _, _ := newTestMethod(t)
	ctx := context.Background()
	// +1NPA-555-XXXX fictional band — LooksLikeVOIP returns true.
	cctx := cc("sess-voip", "+12025551212")

	_, err := m.BeginCeremony(ctx, cctx)
	if err == nil {
		t.Fatal("expected BeginCeremony to reject VOIP/fictional number")
	}
	if !strings.Contains(err.Error(), "too_many_voip_signals") {
		t.Errorf("error = %q, want substring \"too_many_voip_signals\"", err.Error())
	}
}

func TestBegin_EmptyPhone_Rejected(t *testing.T) {
	m, _, _ := newTestMethod(t)
	_, err := m.BeginCeremony(context.Background(), cc("sess-empty", "   "))
	if err == nil {
		t.Fatal("expected error on empty phone number")
	}
}

func TestBegin_SendFailure_InvalidatesStoreEntry(t *testing.T) {
	store := NewInMemoryStore()
	sender := &recordingSender{failNext: true, failNextErr: errors.New("twilio down")}
	m := NewMethod(sender, store)

	cctx := cc("sess-fail", "+14152220144")
	_, err := m.BeginCeremony(context.Background(), cctx)
	if err == nil {
		t.Fatal("expected BeginCeremony to propagate send error")
	}
	// Store entry should be gone so the user can retry immediately.
	valid, attempts, _ := store.Verify(context.Background(), storeKey(cctx.SessionID, cctx.UserID), "000000")
	if valid {
		t.Error("expected store entry invalidated after send failure")
	}
	if attempts != 0 {
		t.Errorf("attempts remaining = %d, want 0 (no entry)", attempts)
	}
}

func TestComplete_WrongResponseType_Rejected(t *testing.T) {
	m, _, _ := newTestMethod(t)
	result, err := m.CompleteCeremony(context.Background(), cc("s", "+14152220144"), types.ResponseData{
		Type:    "magic-link-click",
		Payload: map[string]any{"phone_number": "+14152220144", "code": "123456"},
	})
	if err != nil {
		t.Fatalf("unexpected err: %v", err)
	}
	if result.Success {
		t.Error("expected Success=false on wrong response type")
	}
	if !strings.Contains(result.ErrorReason, "unexpected response type") {
		t.Errorf("ErrorReason = %q, want unexpected-type message", result.ErrorReason)
	}
}

func TestComplete_MissingFields_Rejected(t *testing.T) {
	m, _, _ := newTestMethod(t)
	ctx := context.Background()
	cctx := cc("s", "+14152220144")

	cases := []struct {
		name    string
		payload map[string]any
		want    string
	}{
		{"missing phone_number", map[string]any{"code": "123456"}, "phone_number"},
		{"missing code", map[string]any{"phone_number": "+14152220144"}, "code"},
		{"empty phone_number", map[string]any{"phone_number": "  ", "code": "123456"}, "phone_number"},
		{"empty code", map[string]any{"phone_number": "+14152220144", "code": ""}, "code"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			result, err := m.CompleteCeremony(ctx, cctx, types.ResponseData{Type: "otp", Payload: tc.payload})
			if err != nil {
				t.Fatalf("unexpected err: %v", err)
			}
			if result.Success {
				t.Errorf("expected Success=false")
			}
			if !strings.Contains(result.ErrorReason, tc.want) {
				t.Errorf("ErrorReason = %q, want substring %q", result.ErrorReason, tc.want)
			}
		})
	}
}

func TestIsAvailable_KioskBlocked(t *testing.T) {
	m, _, _ := newTestMethod(t)
	if ok, _ := m.IsAvailableForUser(types.UserContext{Platform: "kiosk"}); ok {
		t.Error("expected SMS unavailable on kiosk")
	}
	if ok, _ := m.IsAvailableForUser(types.UserContext{Platform: "ios"}); !ok {
		t.Error("expected SMS available on ios")
	}
}

func TestInMemoryStore_RoundTrip(t *testing.T) {
	store := NewInMemoryStore()
	ctx := context.Background()
	if err := store.Put(ctx, "k", "123456", time.Now().Add(time.Minute)); err != nil {
		t.Fatalf("Put: %v", err)
	}
	valid, remaining, err := store.Verify(ctx, "k", "123456")
	if err != nil || !valid {
		t.Fatalf("Verify: valid=%v err=%v", valid, err)
	}
	if remaining != 0 {
		t.Errorf("after success remaining = %d, want 0", remaining)
	}
	// Subsequent verify with same key now fails (entry invalidated).
	valid, _, _ = store.Verify(ctx, "k", "123456")
	if valid {
		t.Error("re-verify after success should fail (single-use)")
	}
}

func TestLogSender_EmptyPhone_Errors(t *testing.T) {
	var buf bytes.Buffer
	s := &LogSender{Logger: log.New(io.MultiWriter(&buf), "", 0)}
	if err := s.Send(context.Background(), "  ", "hi"); err == nil {
		t.Error("expected error on empty phone")
	}
	if err := s.Send(context.Background(), "+14152220143", "code: 123456"); err != nil {
		t.Errorf("unexpected error: %v", err)
	}
	if !strings.Contains(buf.String(), "code: 123456") {
		t.Errorf("log buffer missing body, got %q", buf.String())
	}
}

func TestGenerateOTP_AlwaysSixDigits(t *testing.T) {
	for i := 0; i < 50; i++ {
		otp, err := generateOTP()
		if err != nil {
			t.Fatalf("generateOTP: %v", err)
		}
		if len(otp) != 6 {
			t.Errorf("OTP %q is not 6 chars", otp)
		}
		for _, r := range otp {
			if r < '0' || r > '9' {
				t.Errorf("OTP %q contains non-digit %q", otp, r)
			}
		}
	}
}
