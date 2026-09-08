package paidbillingcard

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"net/http"
	"time"

	"github.com/sagearbor/personhood/pkg/types"
)

// methodPlugin mirrors registry.Method so this module stays independently
// compilable. The assertion below enforces the contract at build time.
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
	MethodID = "paid-billing-card"

	// MethodVersion tracks the plugin implementation version.
	MethodVersion = "0.1.0"

	// MethodStrength is the on-credential strength. 35 per the methods catalog
	// — the strongest single supplementary, but still < 50 (it is NOT an
	// anchor).
	MethodStrength = 35

	// MethodCostUSD is the illustrative per-verification cost (~$0.30).
	MethodCostUSD = 0.30

	// MethodFreshnessLifetime is the on-credential freshness window. Card
	// ownership is fairly stable, so 180 days means users re-verify ~twice/year.
	MethodFreshnessLifetime = 180 * 24 * time.Hour
)

// Method implements the Personhood paid-billing-card supplementary method.
// Safe for concurrent use: all per-ceremony state lives in the injected
// ResultStore.
type Method struct {
	stripe         *StripeClient
	store          ResultStore
	publishableKey string
}

// Config bundles NewMethod's dependencies.
type Config struct {
	// StripeClient creates SetupIntents. Required.
	StripeClient *StripeClient

	// Store binds SetupIntents to sessions and holds webhook results. Required.
	Store ResultStore

	// PublishableKey (pk_test_... / pk_live_...) is returned to the client so
	// Stripe.js can confirm the card. Optional but recommended; the client
	// cannot complete the flow without it.
	PublishableKey string
}

// NewMethod constructs a Method. A nil StripeClient or Store is a programmer
// error and panics.
func NewMethod(cfg Config) *Method {
	if cfg.StripeClient == nil {
		panic("paid-billing-card.NewMethod: StripeClient must not be nil")
	}
	if cfg.Store == nil {
		panic("paid-billing-card.NewMethod: Store must not be nil")
	}
	return &Method{stripe: cfg.StripeClient, store: cfg.Store, publishableKey: cfg.PublishableKey}
}

// Metadata implements registry.Method.
func (m *Method) Metadata() types.MethodMetadata {
	return types.MethodMetadata{
		ID:                MethodID,
		Type:              types.MethodTypeSupplementary,
		Strength:          MethodStrength,
		CostUSD:           MethodCostUSD,
		UXFriction:        types.FrictionMed,
		FreshnessLifetime: MethodFreshnessLifetime,
		Version:           MethodVersion,
	}
}

// IsAvailableForUser implements registry.Method. A payment card is broadly
// available; we surface no platform gate. (Integrators serving the unbanked
// should not *require* this method — it does not pass the airdrop test.)
func (m *Method) IsAvailableForUser(_ types.UserContext) (bool, string) {
	return true, ""
}

// BeginCeremony implements registry.Method by creating a $0 SetupIntent bound
// to the session and returning the client_secret the client uses to confirm
// the card (with 3DS/SCA).
func (m *Method) BeginCeremony(ctx context.Context, cc types.CeremonyContext) (types.ChallengeData, error) {
	if cc.SessionID == "" {
		return types.ChallengeData{}, errors.New("paid-billing-card: CeremonyContext.SessionID is required")
	}
	created, err := m.stripe.CreateSetupIntent(ctx, cc.SessionID)
	if err != nil {
		return types.ChallengeData{}, fmt.Errorf("paid-billing-card: create setup intent: %w", err)
	}
	if err := m.store.PutSetupIntent(ctx, cc.SessionID, created.ID); err != nil {
		return types.ChallengeData{}, fmt.Errorf("paid-billing-card: bind setup intent to session: %w", err)
	}
	return types.ChallengeData{
		Type: "stripe-setup-intent",
		Payload: map[string]any{
			"setup_intent_id": created.ID,
			"client_secret":   created.ClientSecret,
			"publishable_key": m.publishableKey,
			"status":          created.Status,
			"poll_endpoint":   "/v1/methods/" + MethodID + "/complete",
		},
	}, nil
}

// CompleteCeremony implements registry.Method by reading the latest
// webhook-delivered Result for the session and translating it into a
// types.MethodResult. ResponseData is unused (the result arrives server-side
// via the webhook); the client polls until a terminal result returns.
func (m *Method) CompleteCeremony(ctx context.Context, cc types.CeremonyContext, _ types.ResponseData) (types.MethodResult, error) {
	if cc.SessionID == "" {
		return types.MethodResult{Success: false, MethodID: MethodID, ErrorReason: "missing_session_id"}, nil
	}
	result, err := m.store.GetResult(ctx, cc.SessionID)
	if err != nil {
		if errors.Is(err, ErrNoResultYet) {
			return types.MethodResult{Success: false, MethodID: MethodID, ErrorReason: "pending_stripe_webhook"}, nil
		}
		return types.MethodResult{}, fmt.Errorf("paid-billing-card: store: %w", err)
	}

	switch result.Status {
	case StatusApproved:
		return types.MethodResult{
			Success:           true,
			MethodID:          MethodID,
			VerifiedAt:        result.CompletedAt,
			AttestationDigest: attestationDigest(cc.SessionID, result.SetupIntentID, result.CardFingerprint),
		}, nil
	case StatusDeclined:
		return types.MethodResult{Success: false, MethodID: MethodID, ErrorReason: "card_declined"}, nil
	case StatusCanceled:
		return types.MethodResult{Success: false, MethodID: MethodID, ErrorReason: "setup_canceled"}, nil
	default:
		return types.MethodResult{Success: false, MethodID: MethodID, ErrorReason: "stripe_unknown_status:" + result.RawStatus}, nil
	}
}

// HealthCheck implements registry.Method. v0.1 ships a no-op success to avoid
// spending API quota.
func (m *Method) HealthCheck(_ context.Context) error { return nil }

// WebhookHandler returns the http.Handler that Stripe POSTs setup_intent.*
// events to. The server package mounts it on the public router. secret is the
// Stripe webhook signing secret; nowFunc is injected for tests (pass nil for
// time.Now).
func (m *Method) WebhookHandler(secret string, nowFunc func() time.Time) http.Handler {
	return NewWebhookHandler(secret, m.store, nowFunc)
}

// attestationDigest is the SHA-256 over the canonical
// session_id || setup_intent_id || card_fingerprint triple. The card
// fingerprint provides the cross-identity dedup signal; the raw card details
// never land on the credential.
func attestationDigest(sessionID, setupIntentID, cardFingerprint string) string {
	h := sha256.New()
	h.Write([]byte(sessionID))
	h.Write([]byte{0})
	h.Write([]byte(setupIntentID))
	h.Write([]byte{0})
	h.Write([]byte(cardFingerprint))
	return hex.EncodeToString(h.Sum(nil))
}
