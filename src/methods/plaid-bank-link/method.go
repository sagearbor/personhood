package plaidbanklink

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
	MethodID = "plaid-bank-link"

	// MethodVersion tracks the plugin implementation version.
	MethodVersion = "0.1.0"

	// MethodStrength is the on-credential strength. 88 matches the
	// docs/06-methods-catalog.md "anchor #3" tier and is well above the
	// 50-point anchor threshold.
	MethodStrength = 88

	// MethodCostUSD is the illustrative per-link cost (~$1.50 per the catalog).
	MethodCostUSD = 1.50

	// MethodFreshnessLifetime is the on-credential freshness window. Bank
	// ownership is stable, so a 180-day window means most users re-link about
	// twice a year.
	MethodFreshnessLifetime = 180 * 24 * time.Hour
)

// Method implements the Personhood plaid-bank-link anchor method. Safe for
// concurrent use: all per-ceremony state lives in the injected ResultStore.
type Method struct {
	plaid *PlaidClient
	store ResultStore
}

// Config bundles NewMethod's dependencies. Both fields are required.
type Config struct {
	PlaidClient *PlaidClient
	Store       ResultStore
}

// NewMethod constructs a Method. A nil PlaidClient or Store is a programmer
// error and panics.
func NewMethod(cfg Config) *Method {
	if cfg.PlaidClient == nil {
		panic("plaid-bank-link.NewMethod: PlaidClient must not be nil")
	}
	if cfg.Store == nil {
		panic("plaid-bank-link.NewMethod: Store must not be nil")
	}
	return &Method{plaid: cfg.PlaidClient, store: cfg.Store}
}

// Metadata implements registry.Method.
func (m *Method) Metadata() types.MethodMetadata {
	return types.MethodMetadata{
		ID:                MethodID,
		Type:              types.MethodTypeAnchor,
		Strength:          MethodStrength,
		CostUSD:           MethodCostUSD,
		UXFriction:        types.FrictionMed,
		FreshnessLifetime: MethodFreshnessLifetime,
		Version:           MethodVersion,
	}
}

// IsAvailableForUser implements registry.Method. Plaid bank linking requires a
// bank account and is US-centric in v0.1; we surface a friendly message for
// users whose country we cannot serve. An empty CountryCode is allowed (Plaid
// itself will gate by available institutions).
func (m *Method) IsAvailableForUser(ctx types.UserContext) (bool, string) {
	if ctx.CountryCode != "" && ctx.CountryCode != "US" {
		return false, "Bank linking is currently available only in the US."
	}
	return true, ""
}

// BeginCeremony implements registry.Method by creating a Plaid Hosted Link
// session, binding the link token to the session, and returning the
// hosted_link_url the client should open.
func (m *Method) BeginCeremony(ctx context.Context, cc types.CeremonyContext) (types.ChallengeData, error) {
	if cc.SessionID == "" {
		return types.ChallengeData{}, errors.New("plaid-bank-link: CeremonyContext.SessionID is required")
	}
	created, err := m.plaid.CreateLinkSession(ctx, cc.SessionID)
	if err != nil {
		return types.ChallengeData{}, fmt.Errorf("plaid-bank-link: create link session: %w", err)
	}
	if err := m.store.PutLinkToken(ctx, cc.SessionID, created.LinkToken); err != nil {
		return types.ChallengeData{}, fmt.Errorf("plaid-bank-link: bind link token to session: %w", err)
	}
	return types.ChallengeData{
		Type: "plaid-hosted-link",
		Payload: map[string]any{
			"link_token":      created.LinkToken,
			"hosted_link_url": created.HostedLinkURL,
			"expiration":      created.Expiration,
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
			return types.MethodResult{Success: false, MethodID: MethodID, ErrorReason: "pending_plaid_webhook"}, nil
		}
		return types.MethodResult{}, fmt.Errorf("plaid-bank-link: store: %w", err)
	}

	switch result.Status {
	case StatusApproved:
		return types.MethodResult{
			Success:           true,
			MethodID:          MethodID,
			VerifiedAt:        result.CompletedAt,
			AttestationDigest: attestationDigest(cc.SessionID, result.LinkSessionID, result.RawStatus),
		}, nil
	case StatusDeclined:
		return types.MethodResult{Success: false, MethodID: MethodID, ErrorReason: "plaid_declined"}, nil
	case StatusNeedsReview:
		return types.MethodResult{Success: false, MethodID: MethodID, ErrorReason: "plaid_needs_review"}, nil
	case StatusExpired:
		return types.MethodResult{Success: false, MethodID: MethodID, ErrorReason: "plaid_session_expired"}, nil
	default:
		return types.MethodResult{Success: false, MethodID: MethodID, ErrorReason: "plaid_unknown_status:" + result.RawStatus}, nil
	}
}

// HealthCheck implements registry.Method. v0.1 ships a no-op success to avoid
// spending API quota; a real probe would call a lightweight Plaid endpoint.
func (m *Method) HealthCheck(_ context.Context) error { return nil }

// WebhookHandler returns the http.Handler that Plaid POSTs LINK events to. The
// server package mounts it on the public router. secret is the shared webhook
// secret; nowFunc is injected for tests (pass nil for time.Now).
func (m *Method) WebhookHandler(secret string, nowFunc func() time.Time) http.Handler {
	return NewWebhookHandler(secret, m.store, nowFunc)
}

// attestationDigest mirrors the other methods: SHA-256 over a
// session_id || link_session_id || raw_status triple. The raw Plaid contents
// never land on the credential.
func attestationDigest(sessionID, linkSessionID, status string) string {
	h := sha256.New()
	h.Write([]byte(sessionID))
	h.Write([]byte{0})
	h.Write([]byte(linkSessionID))
	h.Write([]byte{0})
	h.Write([]byte(status))
	return hex.EncodeToString(h.Sum(nil))
}
