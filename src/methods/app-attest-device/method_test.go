package appattestdevice

import (
	"context"
	"testing"

	"github.com/sagearbor/personhood/pkg/types"
)

const testSecret = "app-attest-dev-secret"

func newTestMethod(t *testing.T) *Method {
	t.Helper()
	return NewMethod(Config{
		Verifier: NewHMACDevVerifier(testSecret),
		Store:    NewInMemoryStore(),
	})
}

func TestMetadata(t *testing.T) {
	md := newTestMethod(t).Metadata()
	if md.ID != MethodID {
		t.Errorf("id mismatch: %q", md.ID)
	}
	if md.Type != types.MethodTypeSupplementary {
		t.Errorf("expected supplementary type, got %q", md.Type)
	}
	if md.Strength != 18 || md.Strength >= 50 {
		t.Errorf("strength must be 18 and <50, got %d", md.Strength)
	}
	if md.UXFriction != types.FrictionLow {
		t.Errorf("expected low friction, got %q", md.UXFriction)
	}
	if md.FreshnessLifetime <= 0 {
		t.Error("freshness lifetime must be positive")
	}
}

func TestIsAvailableForUser(t *testing.T) {
	m := newTestMethod(t)

	if ok, reason := m.IsAvailableForUser(types.UserContext{Platform: "web"}); ok || reason == "" {
		t.Errorf("web should be denied with a reason, got ok=%v reason=%q", ok, reason)
	}
	if ok, reason := m.IsAvailableForUser(types.UserContext{Platform: "Kiosk"}); ok || reason == "" {
		t.Errorf("kiosk (case-insensitive) should be denied, got ok=%v reason=%q", ok, reason)
	}
	if ok, _ := m.IsAvailableForUser(types.UserContext{Platform: "ios"}); !ok {
		t.Error("ios should be available")
	}
	if ok, _ := m.IsAvailableForUser(types.UserContext{Platform: "android"}); !ok {
		t.Error("android should be available")
	}
}

func TestBeginCeremony_IssuesAndStoresNonce(t *testing.T) {
	store := NewInMemoryStore()
	m := NewMethod(Config{Verifier: NewHMACDevVerifier(testSecret), Store: store})
	m.newNonce = func() (string, error) { return "fixed-nonce-abc", nil }

	cc := types.CeremonyContext{SessionID: "sess-1", MethodID: MethodID}
	challenge, err := m.BeginCeremony(context.Background(), cc)
	if err != nil {
		t.Fatalf("begin: %v", err)
	}
	if challenge.Type != "app-attest-challenge" {
		t.Errorf("challenge type mismatch: %q", challenge.Type)
	}
	if n, _ := challenge.Payload["nonce"].(string); n != "fixed-nonce-abc" {
		t.Errorf("nonce in payload mismatch: %q", n)
	}
	if ep, _ := challenge.Payload["complete_endpoint"].(string); ep == "" {
		t.Error("complete_endpoint should be present")
	}
	stored, err := store.GetChallenge(context.Background(), "sess-1")
	if err != nil {
		t.Fatalf("nonce not stored: %v", err)
	}
	if stored != "fixed-nonce-abc" {
		t.Errorf("stored nonce mismatch: %q", stored)
	}
}

func TestBeginCeremony_RequiresSessionID(t *testing.T) {
	m := newTestMethod(t)
	if _, err := m.BeginCeremony(context.Background(), types.CeremonyContext{}); err == nil {
		t.Fatal("expected error for empty SessionID")
	}
}

func TestCompleteCeremony_HappyPath(t *testing.T) {
	m := newTestMethod(t)
	cc := types.CeremonyContext{SessionID: "sess-happy", MethodID: MethodID}

	challenge, err := m.BeginCeremony(context.Background(), cc)
	if err != nil {
		t.Fatalf("begin: %v", err)
	}
	nonce := challenge.Payload["nonce"].(string)

	token := SignDeviceTokenForTesting(testSecret, PlatformIOS, nonce, "keyid-123")
	resp := types.ResponseData{
		Type: "app-attest-challenge",
		Payload: map[string]any{
			"platform": string(PlatformIOS),
			"token":    token,
			"key_id":   "keyid-123",
		},
	}
	result, err := m.CompleteCeremony(context.Background(), cc, resp)
	if err != nil {
		t.Fatalf("complete: %v", err)
	}
	if !result.Success {
		t.Fatalf("expected success, got %+v", result)
	}
	if result.MethodID != MethodID {
		t.Errorf("method id mismatch: %q", result.MethodID)
	}
	if result.AttestationDigest == "" {
		t.Error("expected non-empty attestation digest")
	}
	if result.VerifiedAt.IsZero() {
		t.Error("expected VerifiedAt to be set")
	}
}

func TestCompleteCeremony_WrongSecret(t *testing.T) {
	m := newTestMethod(t)
	cc := types.CeremonyContext{SessionID: "sess-bad", MethodID: MethodID}

	challenge, err := m.BeginCeremony(context.Background(), cc)
	if err != nil {
		t.Fatalf("begin: %v", err)
	}
	nonce := challenge.Payload["nonce"].(string)

	// Token signed with the wrong secret -> verifier rejects.
	token := SignDeviceTokenForTesting("not-the-secret", PlatformIOS, nonce, "keyid-123")
	resp := types.ResponseData{Payload: map[string]any{
		"platform": string(PlatformIOS),
		"token":    token,
		"key_id":   "keyid-123",
	}}
	result, err := m.CompleteCeremony(context.Background(), cc, resp)
	if err != nil {
		t.Fatalf("complete: %v", err)
	}
	if result.Success || result.ErrorReason != "attestation_invalid" {
		t.Errorf("expected attestation_invalid failure, got %+v", result)
	}
}

func TestCompleteCeremony_NoPriorChallenge(t *testing.T) {
	m := newTestMethod(t)
	cc := types.CeremonyContext{SessionID: "never-began", MethodID: MethodID}
	resp := types.ResponseData{Payload: map[string]any{
		"platform": string(PlatformIOS),
		"token":    "anything",
	}}
	result, err := m.CompleteCeremony(context.Background(), cc, resp)
	if err != nil {
		t.Fatalf("complete: %v", err)
	}
	if result.Success || result.ErrorReason != "no_challenge_issued" {
		t.Errorf("expected no_challenge_issued, got %+v", result)
	}
}

func TestCompleteCeremony_MissingToken(t *testing.T) {
	m := newTestMethod(t)
	cc := types.CeremonyContext{SessionID: "sess-notoken", MethodID: MethodID}
	if _, err := m.BeginCeremony(context.Background(), cc); err != nil {
		t.Fatalf("begin: %v", err)
	}
	resp := types.ResponseData{Payload: map[string]any{
		"platform": string(PlatformIOS),
	}}
	result, err := m.CompleteCeremony(context.Background(), cc, resp)
	if err != nil {
		t.Fatalf("complete: %v", err)
	}
	if result.Success || result.ErrorReason != "missing_attestation_token" {
		t.Errorf("expected missing_attestation_token, got %+v", result)
	}
}

func TestCompleteCeremony_MissingSessionID(t *testing.T) {
	m := newTestMethod(t)
	result, err := m.CompleteCeremony(context.Background(), types.CeremonyContext{}, types.ResponseData{})
	if err != nil {
		t.Fatalf("complete: %v", err)
	}
	if result.Success || result.ErrorReason != "missing_session_id" {
		t.Errorf("expected missing_session_id, got %+v", result)
	}
}
