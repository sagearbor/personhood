// Package ipasnreputation implements the Personhood "ip-asn-reputation"
// supplementary verification method: a near-free anti-bot floor that scores the
// client's IP / ASN to catch datacenter, VPN, proxy, and Tor signups.
//
// The method is evaluated entirely server-side — the client performs no action.
// The reference server is responsible for resolving the real client IP (from
// X-Forwarded-For / RemoteAddr) and passing it to CompleteCeremony via
// ResponseData.Payload["ip"].
//
// On-credential strength: 10 points. IP/ASN reputation catches the large
// majority of naive bot signups but is cheaply defeated (residential proxies,
// rotating mobile IPs); it MUST never satisfy a policy that requires an anchor,
// and the policy DSL enforces this independently.
package ipasnreputation

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"strconv"
	"time"

	"github.com/sagearbor/personhood/pkg/types"
)

// methodPlugin is a local mirror of registry.Method. The registry package is a
// sibling module; to keep this module independently compilable we redeclare the
// contract here. The blank-identifier assertion below enforces it at build time.
type methodPlugin interface {
	Metadata() types.MethodMetadata
	IsAvailableForUser(ctx types.UserContext) (available bool, reason string)
	BeginCeremony(ctx context.Context, cc types.CeremonyContext) (types.ChallengeData, error)
	CompleteCeremony(ctx context.Context, cc types.CeremonyContext, resp types.ResponseData) (types.MethodResult, error)
	HealthCheck(ctx context.Context) error
}

var _ methodPlugin = (*Method)(nil)

const (
	// MethodID is the stable plugin identifier.
	MethodID = "ip-asn-reputation"

	// MethodVersion tracks the plugin implementation version.
	MethodVersion = "0.1.0"

	// MethodStrength is the supplementary point value (must be < 50). 10 matches
	// the docs/06-methods-catalog.md "near-free mandatory floor" tier.
	MethodStrength = 10

	// MethodCostUSD is the illustrative per-lookup cost (~$0.001 with MaxMind /
	// IPQualityScore at volume).
	MethodCostUSD = 0.001

	// MethodFreshnessLifetime is the on-credential freshness window. IPs change
	// frequently, so the recency window is short.
	MethodFreshnessLifetime = 7 * 24 * time.Hour
)

// Method implements the Personhood "ip-asn-reputation" supplementary method.
//
// It is stateless and safe for concurrent use: the injected ReputationProvider
// holds all data, and the disqualifier policy is read-only after construction.
type Method struct {
	provider         ReputationProvider
	rejectDatacenter bool
	rejectVPN        bool
	rejectProxy      bool
	rejectTor        bool
}

// Config bundles NewMethod's dependencies. Provider is required. The Reject*
// flags select which signals disqualify a signup.
//
// Because Go booleans cannot distinguish "unset" from "false", callers that
// want the recommended posture should start from DefaultConfig rather than a
// zero Config.
type Config struct {
	// Provider resolves IPs to reputation. Required.
	Provider ReputationProvider

	// RejectDatacenter fails IPs in hosting / cloud ranges.
	RejectDatacenter bool

	// RejectVPN fails commercial VPN exits. Off in the recommended default:
	// VPNs are common for privacy-conscious legitimate users.
	RejectVPN bool

	// RejectProxy fails open / anonymizing proxies.
	RejectProxy bool

	// RejectTor fails Tor exit nodes.
	RejectTor bool
}

// DefaultConfig returns the recommended Config for the given provider:
// datacenter, proxy, and Tor are disqualifying; VPN is allowed (privacy-aware
// legitimate users frequently use VPNs).
func DefaultConfig(provider ReputationProvider) Config {
	return Config{
		Provider:         provider,
		RejectDatacenter: true,
		RejectVPN:        false,
		RejectProxy:      true,
		RejectTor:        true,
	}
}

// NewMethod constructs a Method from cfg. A nil Provider is a programmer error
// and panics. The Reject* flags are used exactly as supplied — pass
// DefaultConfig(provider) for the recommended posture.
func NewMethod(cfg Config) *Method {
	if cfg.Provider == nil {
		panic("ip-asn-reputation.NewMethod: Config.Provider must not be nil")
	}
	return &Method{
		provider:         cfg.Provider,
		rejectDatacenter: cfg.RejectDatacenter,
		rejectVPN:        cfg.RejectVPN,
		rejectProxy:      cfg.RejectProxy,
		rejectTor:        cfg.RejectTor,
	}
}

// Metadata implements registry.Method.
func (m *Method) Metadata() types.MethodMetadata {
	return types.MethodMetadata{
		ID:                MethodID,
		Type:              types.MethodTypeSupplementary,
		Strength:          MethodStrength,
		CostUSD:           MethodCostUSD,
		UXFriction:        types.FrictionLow,
		FreshnessLifetime: MethodFreshnessLifetime,
		Version:           MethodVersion,
	}
}

// IsAvailableForUser implements registry.Method. The check is server-side and
// imposes no client requirement, so it is always available.
func (m *Method) IsAvailableForUser(_ types.UserContext) (bool, string) {
	return true, ""
}

// BeginCeremony implements registry.Method. There is nothing for the client to
// do — the server supplies the IP at completion — so the challenge is purely
// informational. SessionID is required.
func (m *Method) BeginCeremony(_ context.Context, cc types.CeremonyContext) (types.ChallengeData, error) {
	if cc.SessionID == "" {
		return types.ChallengeData{}, errors.New("ip-asn-reputation: CeremonyContext.SessionID is required")
	}
	return types.ChallengeData{
		Type: "ip-asn",
		Payload: map[string]any{
			"note": "server-evaluated; client action not required",
		},
	}, nil
}

// CompleteCeremony implements registry.Method. It reads the client IP the
// server resolved from ResponseData.Payload["ip"], looks up its reputation, and
// applies the configured disqualifiers.
//
// A provider error is unattributable (the user did nothing wrong) and is
// returned as a non-nil error so the caller can retry or skip the method.
// Logical failures (missing IP, disqualifying signal) return a MethodResult with
// Success=false and a populated ErrorReason.
func (m *Method) CompleteCeremony(ctx context.Context, cc types.CeremonyContext, resp types.ResponseData) (types.MethodResult, error) {
	ip, _ := resp.Payload["ip"].(string)
	if ip == "" {
		return types.MethodResult{Success: false, MethodID: MethodID, ErrorReason: "missing_ip"}, nil
	}

	rep, err := m.provider.Lookup(ctx, ip)
	if err != nil {
		return types.MethodResult{}, err
	}

	if m.rejectDatacenter && rep.IsDatacenter {
		return types.MethodResult{Success: false, MethodID: MethodID, ErrorReason: "ip_datacenter"}, nil
	}
	if m.rejectProxy && rep.IsProxy {
		return types.MethodResult{Success: false, MethodID: MethodID, ErrorReason: "ip_proxy"}, nil
	}
	if m.rejectTor && rep.IsTor {
		return types.MethodResult{Success: false, MethodID: MethodID, ErrorReason: "ip_tor"}, nil
	}
	if m.rejectVPN && rep.IsVPN {
		return types.MethodResult{Success: false, MethodID: MethodID, ErrorReason: "ip_vpn"}, nil
	}

	return types.MethodResult{
		Success:           true,
		MethodID:          MethodID,
		VerifiedAt:        time.Now().UTC(),
		AttestationDigest: attestationDigest(cc.SessionID, ip, rep.ASN),
	}, nil
}

// HealthCheck implements registry.Method. There is no external dependency to
// probe at the method level (the provider is opaque); v0.1 is a no-op success.
func (m *Method) HealthCheck(_ context.Context) error { return nil }

// attestationDigest is the SHA-256 over the canonical
// session_id || ip || asn triple. Lands on the issued credential; the raw IP
// never does.
func attestationDigest(sessionID, ip string, asn int) string {
	h := sha256.New()
	h.Write([]byte(sessionID))
	h.Write([]byte{0})
	h.Write([]byte(ip))
	h.Write([]byte{0})
	h.Write([]byte(strconv.Itoa(asn)))
	return hex.EncodeToString(h.Sum(nil))
}
