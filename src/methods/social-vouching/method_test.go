package socialvouching

import (
	"context"
	"testing"

	"github.com/sagearbor/personhood/pkg/types"
)

const testSecret = "test-vouch-secret"

func newTestMethod(seeds map[string]float64) *Method {
	return NewMethod(Config{
		Store:         NewInMemoryGraphStore(seeds),
		Authenticator: NewHMACDevAuthenticator(testSecret),
	})
}

func TestMethod_Metadata(t *testing.T) {
	t.Parallel()
	m := newTestMethod(nil)
	md := m.Metadata()
	if md.ID != MethodID {
		t.Fatalf("ID = %q, want %q", md.ID, MethodID)
	}
	if md.Type != types.MethodTypeSupplementary {
		t.Fatalf("Type = %q, want supplementary", md.Type)
	}
	if md.Strength != MethodStrength || md.Strength >= 50 {
		t.Fatalf("Strength = %d, want %d (< 50 for a supplementary method)", md.Strength, MethodStrength)
	}
	if err := md.Validate(); err != nil {
		t.Fatalf("Metadata().Validate(): %v", err)
	}
}

func TestMethod_BeginCeremony_RequiresSessionID(t *testing.T) {
	t.Parallel()
	m := newTestMethod(nil)
	if _, err := m.BeginCeremony(context.Background(), types.CeremonyContext{}); err == nil {
		t.Fatal("BeginCeremony with empty SessionID: want error, got nil")
	}
}

func TestMethod_BeginCeremony_ReturnsCandidateCode(t *testing.T) {
	t.Parallel()
	m := newTestMethod(nil)
	challenge, err := m.BeginCeremony(context.Background(), types.CeremonyContext{SessionID: "sess-1"})
	if err != nil {
		t.Fatalf("BeginCeremony: %v", err)
	}
	if challenge.Payload["candidate_code"] != "sess-1" {
		t.Fatalf("candidate_code = %v, want sess-1", challenge.Payload["candidate_code"])
	}
	if challenge.Payload["vouch_endpoint"] != "/v1/methods/"+MethodID+"/vouch" {
		t.Fatalf("vouch_endpoint = %v", challenge.Payload["vouch_endpoint"])
	}
}

func vouchFor(t *testing.T, m *Method, candidateID, voucherID string) error {
	t.Helper()
	proof := SignVouchForTesting(testSecret, voucherID, candidateID)
	return m.auth.Authenticate(context.Background(), voucherID, candidateID, proof)
}

// recordVouch drives the same logic VouchHandler would, without going
// through HTTP — used by tests that only care about CompleteCeremony's
// threshold math.
func recordVouch(t *testing.T, m *Method, candidateID, voucherID string) {
	t.Helper()
	if err := vouchFor(t, m, candidateID, voucherID); err != nil {
		t.Fatalf("vouch auth for %s -> %s: %v", voucherID, candidateID, err)
	}
	trust, known, err := m.store.TrustOf(context.Background(), voucherID)
	if err != nil {
		t.Fatalf("TrustOf(%s): %v", voucherID, err)
	}
	if !known {
		t.Fatalf("voucher %s is not known to the graph", voucherID)
	}
	if err := m.store.RecordVouch(context.Background(), candidateID, Vouch{VoucherID: voucherID, Weight: trust}); err != nil {
		t.Fatalf("RecordVouch: %v", err)
	}
}

func TestMethod_CompleteCeremony_InsufficientVouches(t *testing.T) {
	t.Parallel()
	m := newTestMethod(map[string]float64{"seed-1": 1.0})
	recordVouch(t, m, "sess-1", "seed-1") // only 1 of the default 3 required

	result, err := m.CompleteCeremony(context.Background(), types.CeremonyContext{SessionID: "sess-1"}, types.ResponseData{})
	if err != nil {
		t.Fatalf("CompleteCeremony: %v", err)
	}
	if result.Success {
		t.Fatal("CompleteCeremony with 1 vouch: want Success = false")
	}
	if result.ErrorReason == "" {
		t.Fatal("ErrorReason is empty on insufficient vouches")
	}
}

func TestMethod_CompleteCeremony_EnoughVouchesSucceeds(t *testing.T) {
	t.Parallel()
	m := newTestMethod(map[string]float64{
		"seed-1": 1.0,
		"seed-2": 1.0,
		"seed-3": 1.0,
	})
	recordVouch(t, m, "sess-1", "seed-1")
	recordVouch(t, m, "sess-1", "seed-2")
	recordVouch(t, m, "sess-1", "seed-3")

	result, err := m.CompleteCeremony(context.Background(), types.CeremonyContext{SessionID: "sess-1"}, types.ResponseData{})
	if err != nil {
		t.Fatalf("CompleteCeremony: %v", err)
	}
	if !result.Success {
		t.Fatalf("CompleteCeremony: Success = false, ErrorReason = %q", result.ErrorReason)
	}
	if result.AttestationDigest == "" {
		t.Fatal("AttestationDigest is empty on success")
	}

	// The candidate should now be enrolled with a decayed trust score and
	// able to vouch for someone else.
	trust, known, err := m.store.TrustOf(context.Background(), "sess-1")
	if err != nil {
		t.Fatalf("TrustOf: %v", err)
	}
	if !known {
		t.Fatal("candidate was not enrolled after a successful ceremony")
	}
	wantTrust := 1.0 * DefaultDecayFactor // avg voucher weight (1.0) * decay
	if trust != wantTrust {
		t.Fatalf("candidate trust = %v, want %v", trust, wantTrust)
	}
}

func TestMethod_CompleteCeremony_ScoreThresholdNotJustCount(t *testing.T) {
	t.Parallel()
	// 3 distinct low-trust vouchers (0.1 each = 0.3 total) satisfy the COUNT
	// requirement but not the DEFAULT SCORE requirement (1.5).
	m := newTestMethod(map[string]float64{
		"low-1": 0.1,
		"low-2": 0.1,
		"low-3": 0.1,
	})
	recordVouch(t, m, "sess-1", "low-1")
	recordVouch(t, m, "sess-1", "low-2")
	recordVouch(t, m, "sess-1", "low-3")

	result, err := m.CompleteCeremony(context.Background(), types.CeremonyContext{SessionID: "sess-1"}, types.ResponseData{})
	if err != nil {
		t.Fatalf("CompleteCeremony: %v", err)
	}
	if result.Success {
		t.Fatal("CompleteCeremony with low cumulative score: want Success = false")
	}
}

func TestMethod_CompleteCeremony_ChainedVouchingThroughGraduate(t *testing.T) {
	t.Parallel()
	// Only 2 seeds, but a candidate who already graduated can vouch for a
	// third person — proving trust actually propagates through the graph,
	// not just from the fixed seed set.
	m := NewMethod(Config{
		Store:           NewInMemoryGraphStore(map[string]float64{"seed-1": 1.0, "seed-2": 1.0}),
		Authenticator:   NewHMACDevAuthenticator(testSecret),
		RequiredVouches: 2,
		RequiredScore:   1.5,
	})
	recordVouch(t, m, "sess-A", "seed-1")
	recordVouch(t, m, "sess-A", "seed-2")
	resultA, err := m.CompleteCeremony(context.Background(), types.CeremonyContext{SessionID: "sess-A"}, types.ResponseData{})
	if err != nil {
		t.Fatalf("CompleteCeremony A: %v", err)
	}
	if !resultA.Success {
		t.Fatalf("CompleteCeremony A: Success = false, ErrorReason = %q", resultA.ErrorReason)
	}

	recordVouch(t, m, "sess-B", "sess-A") // sess-A, now enrolled, vouches for sess-B
	recordVouch(t, m, "sess-B", "seed-1")
	resultB, err := m.CompleteCeremony(context.Background(), types.CeremonyContext{SessionID: "sess-B"}, types.ResponseData{})
	if err != nil {
		t.Fatalf("CompleteCeremony B: %v", err)
	}
	if !resultB.Success {
		t.Fatalf("CompleteCeremony B: Success = false, ErrorReason = %q", resultB.ErrorReason)
	}
}

func TestMethod_CompleteCeremony_MissingSessionID(t *testing.T) {
	t.Parallel()
	m := newTestMethod(nil)
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
	m := newTestMethod(nil)
	if err := m.HealthCheck(context.Background()); err != nil {
		t.Fatalf("HealthCheck: %v", err)
	}
}

func TestNewMethod_PanicsOnNilDeps(t *testing.T) {
	t.Parallel()
	t.Run("nil store", func(t *testing.T) {
		defer func() {
			if recover() == nil {
				t.Fatal("want panic")
			}
		}()
		NewMethod(Config{Authenticator: NewHMACDevAuthenticator(testSecret)})
	})
	t.Run("nil authenticator", func(t *testing.T) {
		defer func() {
			if recover() == nil {
				t.Fatal("want panic")
			}
		}()
		NewMethod(Config{Store: NewInMemoryGraphStore(nil)})
	})
}
