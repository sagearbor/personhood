package fuzzyextractorselfie

import (
	"context"
	"encoding/base64"
	"testing"

	"github.com/sagearbor/personhood/pkg/types"
)

func newTestMethod() *Method {
	return NewMethod(Config{Accumulator: NewInMemoryAccumulator()})
}

func TestMethod_Metadata(t *testing.T) {
	t.Parallel()
	m := newTestMethod()
	md := m.Metadata()
	if md.ID != MethodID {
		t.Fatalf("ID = %q, want %q", md.ID, MethodID)
	}
	if md.Type != types.MethodTypeAnchor {
		t.Fatalf("Type = %q, want anchor", md.Type)
	}
	if md.Strength != MethodStrength || md.Strength < 50 {
		t.Fatalf("Strength = %d, want %d (>= 50 for an anchor)", md.Strength, MethodStrength)
	}
	if err := md.Validate(); err != nil {
		t.Fatalf("Metadata().Validate(): %v", err)
	}
}

func TestMethod_IsAvailableForUser_AlwaysTrue(t *testing.T) {
	t.Parallel()
	m := newTestMethod()
	for _, platform := range []string{"web", "ios", "android", "kiosk", ""} {
		ok, reason := m.IsAvailableForUser(types.UserContext{Platform: platform})
		if !ok {
			t.Fatalf("IsAvailableForUser(%q) = false (%s), want true", platform, reason)
		}
	}
}

func TestMethod_BeginCeremony_RequiresSessionID(t *testing.T) {
	t.Parallel()
	m := newTestMethod()
	_, err := m.BeginCeremony(context.Background(), types.CeremonyContext{})
	if err == nil {
		t.Fatal("BeginCeremony with empty SessionID: want error, got nil")
	}
}

func TestMethod_BeginCeremony_ReturnsInstructions(t *testing.T) {
	t.Parallel()
	m := newTestMethod()
	challenge, err := m.BeginCeremony(context.Background(), types.CeremonyContext{SessionID: "sess-1"})
	if err != nil {
		t.Fatalf("BeginCeremony: %v", err)
	}
	if challenge.Type != "fuzzy-extractor-challenge" {
		t.Fatalf("challenge.Type = %q", challenge.Type)
	}
	if challenge.Payload["template_bytes"] != TemplateBytes {
		t.Fatalf("challenge.Payload[template_bytes] = %v, want %d", challenge.Payload["template_bytes"], TemplateBytes)
	}
}

func completeWithTemplate(t *testing.T, m *Method, sessionID string, template []byte) types.MethodResult {
	t.Helper()
	cc := types.CeremonyContext{SessionID: sessionID, MethodID: MethodID}
	resp := types.ResponseData{
		Type:    "fuzzy-extractor-response",
		Payload: map[string]any{"template_b64": base64.StdEncoding.EncodeToString(template)},
	}
	result, err := m.CompleteCeremony(context.Background(), cc, resp)
	if err != nil {
		t.Fatalf("CompleteCeremony: %v", err)
	}
	return result
}

func TestMethod_CompleteCeremony_NewPersonSucceeds(t *testing.T) {
	t.Parallel()
	m := newTestMethod()
	template := RandomTemplateForTesting()

	result := completeWithTemplate(t, m, "sess-1", template)
	if !result.Success {
		t.Fatalf("CompleteCeremony: Success = false, ErrorReason = %q", result.ErrorReason)
	}
	if result.MethodID != MethodID {
		t.Fatalf("MethodID = %q, want %q", result.MethodID, MethodID)
	}
	if len(result.AttestationDigest) != 64 {
		t.Fatalf("AttestationDigest = %q, want 64 hex chars", result.AttestationDigest)
	}
	if result.VerifiedAt.IsZero() {
		t.Fatal("VerifiedAt is zero on success")
	}
}

func TestMethod_CompleteCeremony_DuplicatePersonRejected(t *testing.T) {
	t.Parallel()
	m := newTestMethod()
	template := RandomTemplateForTesting()

	first := completeWithTemplate(t, m, "sess-1", template)
	if !first.Success {
		t.Fatalf("first enrollment: Success = false, ErrorReason = %q", first.ErrorReason)
	}

	// A second session presenting the SAME biometric (even with light noise,
	// simulating a second selfie of the same person) must be rejected as a
	// duplicate, regardless of which session/holder key is driving it — this
	// is the anti-Sybil property the accumulator exists for.
	noisy := NoisyTemplateForTesting(template, 5)
	second := completeWithTemplate(t, m, "sess-2", noisy)
	if second.Success {
		t.Fatal("second enrollment with the same (noisy) biometric: want Success = false, got true")
	}
	if second.ErrorReason != "duplicate_person_detected" {
		t.Fatalf("ErrorReason = %q, want duplicate_person_detected", second.ErrorReason)
	}
}

func TestMethod_CompleteCeremony_DistinctPeopleBothSucceed(t *testing.T) {
	t.Parallel()
	m := newTestMethod()

	first := completeWithTemplate(t, m, "sess-1", RandomTemplateForTesting())
	if !first.Success {
		t.Fatalf("first enrollment: Success = false, ErrorReason = %q", first.ErrorReason)
	}
	second := completeWithTemplate(t, m, "sess-2", RandomTemplateForTesting())
	if !second.Success {
		t.Fatalf("second enrollment (distinct person): Success = false, ErrorReason = %q", second.ErrorReason)
	}
	if first.AttestationDigest == second.AttestationDigest {
		t.Fatal("two distinct people produced the same AttestationDigest")
	}
}

func TestMethod_CompleteCeremony_MissingTemplate(t *testing.T) {
	t.Parallel()
	m := newTestMethod()
	cc := types.CeremonyContext{SessionID: "sess-1", MethodID: MethodID}
	result, err := m.CompleteCeremony(context.Background(), cc, types.ResponseData{})
	if err != nil {
		t.Fatalf("CompleteCeremony: %v", err)
	}
	if result.Success {
		t.Fatal("CompleteCeremony with no template: want Success = false")
	}
	if result.ErrorReason != "missing_template" {
		t.Fatalf("ErrorReason = %q, want missing_template", result.ErrorReason)
	}
}

func TestMethod_CompleteCeremony_BadTemplateEncoding(t *testing.T) {
	t.Parallel()
	m := newTestMethod()
	cc := types.CeremonyContext{SessionID: "sess-1", MethodID: MethodID}
	resp := types.ResponseData{Payload: map[string]any{"template_b64": "not-valid-base64!!"}}
	result, err := m.CompleteCeremony(context.Background(), cc, resp)
	if err != nil {
		t.Fatalf("CompleteCeremony: %v", err)
	}
	if result.Success || result.ErrorReason != "invalid_template_encoding" {
		t.Fatalf("result = %+v, want ErrorReason invalid_template_encoding", result)
	}
}

func TestMethod_CompleteCeremony_WrongTemplateLength(t *testing.T) {
	t.Parallel()
	m := newTestMethod()
	cc := types.CeremonyContext{SessionID: "sess-1", MethodID: MethodID}
	resp := types.ResponseData{Payload: map[string]any{"template_b64": base64.StdEncoding.EncodeToString([]byte("too-short"))}}
	result, err := m.CompleteCeremony(context.Background(), cc, resp)
	if err != nil {
		t.Fatalf("CompleteCeremony: %v", err)
	}
	if result.Success {
		t.Fatal("CompleteCeremony with wrong-length template: want Success = false")
	}
}

func TestMethod_CompleteCeremony_MissingSessionID(t *testing.T) {
	t.Parallel()
	m := newTestMethod()
	result, err := m.CompleteCeremony(context.Background(), types.CeremonyContext{}, types.ResponseData{})
	if err != nil {
		t.Fatalf("CompleteCeremony: %v", err)
	}
	if result.Success || result.ErrorReason != "missing_session_id" {
		t.Fatalf("result = %+v, want ErrorReason missing_session_id", result)
	}
}

func TestMethod_HealthCheck(t *testing.T) {
	t.Parallel()
	m := newTestMethod()
	if err := m.HealthCheck(context.Background()); err != nil {
		t.Fatalf("HealthCheck: %v", err)
	}
}

func TestNewMethod_PanicsOnNilAccumulator(t *testing.T) {
	t.Parallel()
	defer func() {
		if recover() == nil {
			t.Fatal("NewMethod with nil Accumulator: want panic")
		}
	}()
	NewMethod(Config{})
}
