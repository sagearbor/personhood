package ipasnreputation

import (
	"context"
	"errors"
	"testing"

	"github.com/sagearbor/personhood/pkg/types"
)

const (
	cleanIP      = "203.0.113.7"  // residential
	datacenterIP = "198.51.100.4" // hosting / cloud
	proxyIP      = "192.0.2.9"    // open proxy
	torIP        = "192.0.2.55"   // tor exit
	vpnIP        = "203.0.113.99" // commercial VPN only
)

func testProvider() *StaticProvider {
	return NewStaticProvider(map[string]Reputation{
		cleanIP:      {ASN: 64500, Org: "Example Residential ISP"},
		datacenterIP: {ASN: 16509, Org: "Amazon.com, Inc.", IsDatacenter: true},
		proxyIP:      {ASN: 64501, Org: "Open Proxy Co", IsProxy: true},
		torIP:        {ASN: 64502, Org: "Tor Exit", IsTor: true},
		vpnIP:        {ASN: 64503, Org: "Commercial VPN", IsVPN: true},
	})
}

func newDefaultMethod() *Method {
	return NewMethod(DefaultConfig(testProvider()))
}

func ceremony() types.CeremonyContext {
	return types.CeremonyContext{SessionID: "sess-1", MethodID: MethodID}
}

func TestMetadata(t *testing.T) {
	md := newDefaultMethod().Metadata()
	if md.ID != MethodID {
		t.Errorf("ID = %q, want %q", md.ID, MethodID)
	}
	if md.Type != types.MethodTypeSupplementary {
		t.Errorf("Type = %q, want supplementary", md.Type)
	}
	if md.Strength != 10 {
		t.Errorf("Strength = %d, want 10", md.Strength)
	}
	if md.Strength >= 50 {
		t.Errorf("supplementary strength must be < 50, got %d", md.Strength)
	}
	if md.UXFriction != types.FrictionLow {
		t.Errorf("UXFriction = %q, want low", md.UXFriction)
	}
	if md.FreshnessLifetime <= 0 {
		t.Errorf("FreshnessLifetime = %v, want positive", md.FreshnessLifetime)
	}
	if md.Version != MethodVersion {
		t.Errorf("Version = %q, want %q", md.Version, MethodVersion)
	}
}

func TestIsAvailableForUser(t *testing.T) {
	ok, reason := newDefaultMethod().IsAvailableForUser(types.UserContext{})
	if !ok || reason != "" {
		t.Errorf("IsAvailableForUser = (%v, %q), want (true, \"\")", ok, reason)
	}
}

func TestBeginCeremony(t *testing.T) {
	m := newDefaultMethod()

	if _, err := m.BeginCeremony(context.Background(), types.CeremonyContext{}); err == nil {
		t.Fatal("BeginCeremony with empty SessionID: want error, got nil")
	}

	ch, err := m.BeginCeremony(context.Background(), ceremony())
	if err != nil {
		t.Fatalf("BeginCeremony: unexpected error: %v", err)
	}
	if ch.Type != "ip-asn" {
		t.Errorf("ChallengeData.Type = %q, want \"ip-asn\"", ch.Type)
	}
	if ch.Payload["note"] == nil {
		t.Error("ChallengeData.Payload missing \"note\"")
	}
}

func TestCompleteCeremonyCleanIP(t *testing.T) {
	m := newDefaultMethod()
	resp := types.ResponseData{Type: "ip-asn", Payload: map[string]any{"ip": cleanIP}}

	res, err := m.CompleteCeremony(context.Background(), ceremony(), resp)
	if err != nil {
		t.Fatalf("CompleteCeremony: unexpected error: %v", err)
	}
	if !res.Success {
		t.Fatalf("clean IP: Success = false, ErrorReason = %q", res.ErrorReason)
	}
	if res.MethodID != MethodID {
		t.Errorf("MethodID = %q, want %q", res.MethodID, MethodID)
	}
	if res.AttestationDigest == "" {
		t.Error("clean IP: AttestationDigest is empty, want non-empty")
	}
	if res.VerifiedAt.IsZero() {
		t.Error("clean IP: VerifiedAt is zero, want set")
	}
}

func TestCompleteCeremonyDatacenter(t *testing.T) {
	m := newDefaultMethod()
	resp := types.ResponseData{Type: "ip-asn", Payload: map[string]any{"ip": datacenterIP}}

	res, err := m.CompleteCeremony(context.Background(), ceremony(), resp)
	if err != nil {
		t.Fatalf("CompleteCeremony: unexpected error: %v", err)
	}
	if res.Success {
		t.Fatal("datacenter IP: Success = true, want false")
	}
	if res.ErrorReason != "ip_datacenter" {
		t.Errorf("ErrorReason = %q, want \"ip_datacenter\"", res.ErrorReason)
	}
}

func TestCompleteCeremonyProxyAndTor(t *testing.T) {
	m := newDefaultMethod()

	for _, tc := range []struct{ ip, want string }{
		{proxyIP, "ip_proxy"},
		{torIP, "ip_tor"},
	} {
		resp := types.ResponseData{Type: "ip-asn", Payload: map[string]any{"ip": tc.ip}}
		res, err := m.CompleteCeremony(context.Background(), ceremony(), resp)
		if err != nil {
			t.Fatalf("CompleteCeremony(%s): unexpected error: %v", tc.ip, err)
		}
		if res.Success || res.ErrorReason != tc.want {
			t.Errorf("CompleteCeremony(%s) = (success=%v, %q), want (false, %q)", tc.ip, res.Success, res.ErrorReason, tc.want)
		}
	}
}

func TestCompleteCeremonyMissingIP(t *testing.T) {
	m := newDefaultMethod()
	res, err := m.CompleteCeremony(context.Background(), ceremony(), types.ResponseData{Type: "ip-asn"})
	if err != nil {
		t.Fatalf("CompleteCeremony: unexpected error: %v", err)
	}
	if res.Success || res.ErrorReason != "missing_ip" {
		t.Errorf("missing ip = (success=%v, %q), want (false, \"missing_ip\")", res.Success, res.ErrorReason)
	}
}

// VPN must pass under the default config (RejectVPN=false).
func TestCompleteCeremonyVPNAllowedByDefault(t *testing.T) {
	m := newDefaultMethod()
	resp := types.ResponseData{Type: "ip-asn", Payload: map[string]any{"ip": vpnIP}}

	res, err := m.CompleteCeremony(context.Background(), ceremony(), resp)
	if err != nil {
		t.Fatalf("CompleteCeremony: unexpected error: %v", err)
	}
	if !res.Success {
		t.Fatalf("VPN IP under default config: Success = false (ErrorReason=%q), want true", res.ErrorReason)
	}
}

// With RejectVPN explicitly enabled, the same VPN IP is rejected.
func TestCompleteCeremonyVPNRejectedWhenConfigured(t *testing.T) {
	cfg := DefaultConfig(testProvider())
	cfg.RejectVPN = true
	m := NewMethod(cfg)
	resp := types.ResponseData{Type: "ip-asn", Payload: map[string]any{"ip": vpnIP}}

	res, err := m.CompleteCeremony(context.Background(), ceremony(), resp)
	if err != nil {
		t.Fatalf("CompleteCeremony: unexpected error: %v", err)
	}
	if res.Success || res.ErrorReason != "ip_vpn" {
		t.Errorf("VPN IP with RejectVPN=true = (success=%v, %q), want (false, \"ip_vpn\")", res.Success, res.ErrorReason)
	}
}

// errProvider always fails lookups.
type errProvider struct{}

func (errProvider) Lookup(context.Context, string) (Reputation, error) {
	return Reputation{}, errors.New("lookup backend unavailable")
}

func TestCompleteCeremonyProviderError(t *testing.T) {
	m := NewMethod(Config{Provider: errProvider{}, RejectDatacenter: true})
	resp := types.ResponseData{Type: "ip-asn", Payload: map[string]any{"ip": cleanIP}}

	res, err := m.CompleteCeremony(context.Background(), ceremony(), resp)
	if err == nil {
		t.Fatal("provider error: want non-nil error, got nil")
	}
	if res.Success {
		t.Error("provider error: Success = true, want false")
	}
}

func TestNewMethodNilProviderPanics(t *testing.T) {
	defer func() {
		if recover() == nil {
			t.Error("NewMethod with nil Provider: want panic, got none")
		}
	}()
	NewMethod(Config{})
}

func TestHealthCheck(t *testing.T) {
	if err := newDefaultMethod().HealthCheck(context.Background()); err != nil {
		t.Errorf("HealthCheck = %v, want nil", err)
	}
}

func TestStaticProviderUnknownIPIsClean(t *testing.T) {
	p := NewStaticProvider(nil)
	rep, err := p.Lookup(context.Background(), "10.0.0.1")
	if err != nil {
		t.Fatalf("Lookup: unexpected error: %v", err)
	}
	if rep.IsDatacenter || rep.IsVPN || rep.IsProxy || rep.IsTor {
		t.Errorf("unknown IP should be clean, got %+v", rep)
	}
}
