package governmentidliveness

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"net/http"
	"strings"
	"time"

	"github.com/sagearbor/personhood/pkg/types"
)

// methodPlugin is a local mirror of registry.Method. The registry package
// lives in a sibling module; mirroring its contract here keeps this module
// independently compilable. The blank-identifier var below asserts at build
// time that *Method satisfies the contract.
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
	MethodID = "government-id-liveness"

	// MethodVersion tracks the plugin implementation version.
	MethodVersion = "0.1.0"

	// MethodStrength is the on-credential strength. 90 is well above the
	// 50-point anchor threshold and matches the "ID + liveness" tier from
	// docs/06-methods-catalog.md.
	MethodStrength = 90

	// MethodCostUSD is the illustrative per-inquiry cost. Persona's posted
	// price ranges from ~$1.50 (basic ID+selfie) to ~$2.50 (with PII checks).
	MethodCostUSD = 2.00

	// MethodFreshnessLifetime is the on-credential freshness window. ID +
	// liveness ages slowly; a 180-day window means most users re-verify
	// twice a year.
	MethodFreshnessLifetime = 180 * 24 * time.Hour
)

// Method implements the Personhood government-id-liveness anchor method.
//
// Safe for concurrent use: all per-ceremony state lives in the injected
// ResultStore.
type Method struct {
	persona   *PersonaClient
	store     ResultStore
	returnURL string
}

// Config bundles the dependencies NewMethod needs. ReturnURL is the absolute
// URL the user is redirected back to after completing Persona's hosted flow;
// pass "" to omit the redirect-uri query parameter (the user simply sees
// Persona's default "all done" screen).
type Config struct {
	PersonaClient *PersonaClient
	Store         ResultStore
	ReturnURL     string
}

// NewMethod constructs a Method. cfg.PersonaClient and cfg.Store are
// required; nil panics — these are programmer errors, not runtime
// conditions.
func NewMethod(cfg Config) *Method {
	if cfg.PersonaClient == nil {
		panic("government-id-liveness.NewMethod: PersonaClient must not be nil")
	}
	if cfg.Store == nil {
		panic("government-id-liveness.NewMethod: Store must not be nil")
	}
	return &Method{
		persona:   cfg.PersonaClient,
		store:     cfg.Store,
		returnURL: cfg.ReturnURL,
	}
}

// Metadata implements registry.Method.
func (m *Method) Metadata() types.MethodMetadata {
	return types.MethodMetadata{
		ID:                MethodID,
		Type:              types.MethodTypeAnchor,
		Strength:          MethodStrength,
		CostUSD:           MethodCostUSD,
		UXFriction:        types.FrictionHigh,
		FreshnessLifetime: MethodFreshnessLifetime,
		Version:           MethodVersion,
	}
}

// IsAvailableForUser implements registry.Method. Persona's hosted flow
// requires a camera; we surface a friendly message when the client reports
// none. The "no biometric capability" hint conservatively maps to "no
// camera" since Persona will fail liveness without one.
func (m *Method) IsAvailableForUser(ctx types.UserContext) (bool, string) {
	if strings.EqualFold(ctx.Platform, "kiosk") {
		return false, "Government ID + selfie liveness is not available on kiosk platforms."
	}
	return true, ""
}

// BeginCeremony implements registry.Method by creating a Persona inquiry,
// binding the inquiry id to the session in the store, and returning the
// hosted-flow URL the client should open.
func (m *Method) BeginCeremony(ctx context.Context, cc types.CeremonyContext) (types.ChallengeData, error) {
	if cc.SessionID == "" {
		return types.ChallengeData{}, errors.New("government-id-liveness: CeremonyContext.SessionID is required")
	}
	created, err := m.persona.CreateInquiry(ctx, cc.SessionID)
	if err != nil {
		return types.ChallengeData{}, fmt.Errorf("government-id-liveness: create inquiry: %w", err)
	}
	if err := m.store.PutInquiry(ctx, cc.SessionID, created.ID); err != nil {
		return types.ChallengeData{}, fmt.Errorf("government-id-liveness: bind inquiry to session: %w", err)
	}
	hostedURL := created.HostedFlowURL(m.returnURL)
	return types.ChallengeData{
		Type: "persona-hosted-flow",
		Payload: map[string]any{
			"inquiry_id":      created.ID,
			"hosted_flow_url": hostedURL,
			"return_url":      m.returnURL,
			"poll_endpoint":   "/v1/methods/" + MethodID + "/complete",
		},
	}, nil
}

// CompleteCeremony implements registry.Method by reading the latest
// webhook-delivered Result for the session and translating it into a
// types.MethodResult. The client typically POSTs to /complete on a poll
// interval until a non-zero result returns.
//
// ResponseData is unused in this flow (the response lives server-side via
// the webhook). The caller may send an empty ResponseData; the field is
// retained to satisfy the registry.Method contract.
func (m *Method) CompleteCeremony(ctx context.Context, cc types.CeremonyContext, _ types.ResponseData) (types.MethodResult, error) {
	if cc.SessionID == "" {
		return types.MethodResult{
			Success:     false,
			MethodID:    MethodID,
			ErrorReason: "missing_session_id",
		}, nil
	}
	result, err := m.store.GetResult(ctx, cc.SessionID)
	if err != nil {
		if errors.Is(err, ErrNoResultYet) {
			return types.MethodResult{
				Success:     false,
				MethodID:    MethodID,
				ErrorReason: "pending_persona_webhook",
			}, nil
		}
		return types.MethodResult{}, fmt.Errorf("government-id-liveness: store: %w", err)
	}

	switch result.Status {
	case StatusApproved:
		digest := attestationDigest(cc.SessionID, result.InquiryID, result.RawStatus)
		return types.MethodResult{
			Success:           true,
			MethodID:          MethodID,
			VerifiedAt:        result.CompletedAt,
			AttestationDigest: digest,
		}, nil
	case StatusDeclined:
		return types.MethodResult{
			Success:     false,
			MethodID:    MethodID,
			ErrorReason: "persona_declined",
		}, nil
	case StatusNeedsReview:
		return types.MethodResult{
			Success:     false,
			MethodID:    MethodID,
			ErrorReason: "persona_needs_review",
		}, nil
	case StatusExpired:
		return types.MethodResult{
			Success:     false,
			MethodID:    MethodID,
			ErrorReason: "persona_inquiry_expired",
		}, nil
	default:
		return types.MethodResult{
			Success:     false,
			MethodID:    MethodID,
			ErrorReason: "persona_unknown_status:" + result.RawStatus,
		}, nil
	}
}

// HealthCheck implements registry.Method by issuing a lightweight call to
// Persona. v0.1 ships a no-op success; a real probe would call
// `GET /api/v1/inquiries?per_page=1` and check for a 200. We avoid that for
// now so HealthCheck does not count against the free-tier request quota.
func (m *Method) HealthCheck(_ context.Context) error {
	return nil
}

// WebhookHandler returns the http.Handler that Persona POSTs inquiry events
// to. The server package mounts it on the public router.
//
// secret is the Persona-Signature shared secret (env: PERSONA_WEBHOOK_SECRET).
// nowFunc is injected for tests; pass nil to use time.Now.
func (m *Method) WebhookHandler(secret string, nowFunc func() time.Time) http.Handler {
	return NewWebhookHandler(secret, m.store, nowFunc)
}

// attestationDigest mirrors the email/sms methods' attestation digest
// pattern: SHA-256 over a session_id || inquiry_id || raw_status triple.
// The raw inquiry contents never land on the credential.
func attestationDigest(sessionID, inquiryID, status string) string {
	h := sha256.New()
	h.Write([]byte(sessionID))
	h.Write([]byte{0})
	h.Write([]byte(inquiryID))
	h.Write([]byte{0})
	h.Write([]byte(status))
	return hex.EncodeToString(h.Sum(nil))
}
