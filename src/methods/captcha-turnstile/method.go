package captchaturnstile

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"strings"
	"time"

	"github.com/sagearbor/personhood/pkg/types"
)

// methodPlugin mirrors registry.Method (which lives in a sibling module) so
// this module stays independently compilable. The assertion below enforces the
// contract at build time.
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
	MethodID = "captcha-turnstile"

	// MethodVersion tracks the plugin implementation version.
	MethodVersion = "0.1.0"

	// MethodStrength is the on-credential strength. 4 matches the
	// docs/06-methods-catalog.md "captcha-turnstile" tier and is well below the
	// 50-point anchor threshold (supplementary only).
	MethodStrength = 4

	// MethodCostUSD is the per-verification cost. Cloudflare Turnstile is free.
	MethodCostUSD = 0.00

	// MethodFreshnessLifetime is the on-credential freshness window. A Turnstile
	// token only proves a human solved a fresh challenge at signup, so the
	// window is short.
	MethodFreshnessLifetime = 24 * time.Hour
)

// Method implements the Personhood captcha-turnstile supplementary method. It
// is safe for concurrent use: the verification is synchronous and stateless,
// with no per-ceremony state stored server-side.
type Method struct {
	client *TurnstileClient
}

// Config bundles NewMethod's dependencies. TurnstileClient is required.
type Config struct {
	TurnstileClient *TurnstileClient
}

// NewMethod constructs a Method. A nil TurnstileClient is a programmer error
// and panics.
func NewMethod(cfg Config) *Method {
	if cfg.TurnstileClient == nil {
		panic("captcha-turnstile.NewMethod: TurnstileClient must not be nil")
	}
	return &Method{client: cfg.TurnstileClient}
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

// IsAvailableForUser implements registry.Method. Turnstile is a universal,
// browser-based floor, so it is always available.
func (m *Method) IsAvailableForUser(_ types.UserContext) (bool, string) {
	return true, ""
}

// BeginCeremony implements registry.Method by returning the public site key the
// client embeds in the Turnstile widget. There is no server-side state to bind;
// the token is validated synchronously in CompleteCeremony.
func (m *Method) BeginCeremony(_ context.Context, cc types.CeremonyContext) (types.ChallengeData, error) {
	if cc.SessionID == "" {
		return types.ChallengeData{}, errors.New("captcha-turnstile: CeremonyContext.SessionID is required")
	}
	return types.ChallengeData{
		Type: "turnstile",
		Payload: map[string]any{
			"site_key":      m.client.SiteKey,
			"verify_action": "enroll",
		},
	}, nil
}

// CompleteCeremony implements registry.Method by validating the Turnstile token
// from the client against Cloudflare's siteverify endpoint. A missing token or
// a Cloudflare-reported failure returns a non-error MethodResult with Success
// false; an HTTP/transport error returns a non-nil error so the caller sees an
// unattributable failure.
func (m *Method) CompleteCeremony(ctx context.Context, cc types.CeremonyContext, resp types.ResponseData) (types.MethodResult, error) {
	token, _ := resp.Payload["token"].(string)
	if token == "" {
		return types.MethodResult{Success: false, MethodID: MethodID, ErrorReason: "missing_turnstile_token"}, nil
	}

	remoteIP, _ := resp.Payload["ip"].(string)

	verify, err := m.client.SiteVerify(ctx, token, remoteIP)
	if err != nil {
		return types.MethodResult{}, err
	}

	if !verify.Success {
		reason := "turnstile_failed:" + strings.Join(verify.ErrorCodes, ",")
		return types.MethodResult{Success: false, MethodID: MethodID, ErrorReason: reason}, nil
	}

	return types.MethodResult{
		Success:           true,
		MethodID:          MethodID,
		VerifiedAt:        time.Now().UTC(),
		AttestationDigest: attestationDigest(cc.SessionID, token, verify.Hostname),
	}, nil
}

// HealthCheck implements registry.Method. v0.1 ships a no-op success to avoid
// spending API quota; a real probe would call a lightweight Turnstile endpoint.
func (m *Method) HealthCheck(_ context.Context) error { return nil }

// attestationDigest mirrors the other methods: SHA-256 over a
// session_id || token || hostname triple. The raw token never lands on the
// credential.
func attestationDigest(sessionID, token, hostname string) string {
	h := sha256.New()
	h.Write([]byte(sessionID))
	h.Write([]byte{0})
	h.Write([]byte(token))
	h.Write([]byte{0})
	h.Write([]byte(hostname))
	return hex.EncodeToString(h.Sum(nil))
}
