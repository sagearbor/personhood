// Package paidbillingcard implements the Personhood "paid-billing-card"
// supplementary method, wrapping Stripe SetupIntent ($0 card pre-auth with
// 3-D Secure / SCA).
//
// Strength: 35 (supplementary; the strongest single supplementary per
// docs/06-methods-catalog.md — the "Twitter Blue / OpenAI tier-1" pattern). A
// real card that passes an SCA challenge is expensive to mint at scale and the
// card fingerprint gives a strong cross-identity dedup signal. It is NOT an
// anchor (it never satisfies anchor_required) and does NOT pass the airdrop
// test (it requires a payment card).
//
// Cost   : ~$0.30 per verification.
// Friction: med — the user enters card details and completes a 3DS challenge.
//
// Wire model (mirrors plaid-bank-link / government-id-liveness):
//  1. BeginCeremony creates a $0 SetupIntent bound to the session (via
//     metadata.session_id), returns the client_secret + publishable key.
//  2. The client confirms the card with Stripe.js / the mobile SDK, running
//     the 3DS challenge.
//  3. Stripe POSTs a setup_intent.succeeded / .setup_failed webhook. The
//     Method's WebhookHandler verifies the Stripe-Signature and writes the
//     result into ResultStore keyed by the session id.
//  4. The client polls CompleteCeremony, which succeeds iff the SetupIntent
//     succeeded.
package paidbillingcard

import (
	"context"
	"errors"
	"sync"
	"time"
)

// ErrNoResultYet is returned by ResultStore.GetResult when the webhook has not
// yet reported a final state for the session.
var ErrNoResultYet = errors.New("paid-billing-card: no Stripe result yet")

// Status narrows the Stripe SetupIntent outcomes that matter for issuance.
type Status string

const (
	// StatusApproved is a succeeded SetupIntent: the card was saved and (when
	// requested) passed the 3DS/SCA challenge.
	StatusApproved Status = "approved"

	// StatusDeclined is a failed SetupIntent (setup_intent.setup_failed): the
	// card was declined or the 3DS challenge failed.
	StatusDeclined Status = "declined"

	// StatusCanceled is recorded when the SetupIntent is canceled before the
	// user completes it.
	StatusCanceled Status = "canceled"
)

// Result is the per-session outcome stored after a Stripe webhook fires.
type Result struct {
	// SetupIntentID is Stripe's SetupIntent id ("seti_...").
	SetupIntentID string

	// CardFingerprint is the Stripe payment-method card fingerprint, a stable
	// per-card identifier used for cross-identity dedup. Empty when the webhook
	// payload did not include an expanded payment_method (see WebhookHandler).
	CardFingerprint string

	// Status is the narrowed Stripe status.
	Status Status

	// RawStatus is the verbatim Stripe event type, for audit logs.
	RawStatus string

	// CompletedAt is when the webhook delivered the terminal status.
	CompletedAt time.Time
}

// ResultStore receives results from the webhook handler and surfaces them to
// CompleteCeremony. Implementations MUST be safe for concurrent use.
//
// Sessions are bound by SetupIntent id (which the issuer holds from
// BeginCeremony and which the webhook echoes), so the handler can resolve an
// incoming webhook back to the Personhood session.
type ResultStore interface {
	// PutSetupIntent binds setupIntentID to sessionID at BeginCeremony time.
	PutSetupIntent(ctx context.Context, sessionID, setupIntentID string) error

	// LookupSessionBySetupIntent returns the sessionID associated with a
	// setupIntentID, or an empty string + nil error if no binding exists.
	LookupSessionBySetupIntent(ctx context.Context, setupIntentID string) (string, error)

	// PutResult writes a final webhook result against its session.
	PutResult(ctx context.Context, sessionID string, result Result) error

	// GetResult fetches the latest stored result, or ErrNoResultYet when no
	// webhook has fired for the session.
	GetResult(ctx context.Context, sessionID string) (Result, error)
}

// InMemoryStore is a sync.Map-backed ResultStore for dev, tests, and
// single-process deployments. Production should swap in a shared backend.
type InMemoryStore struct {
	bySession     sync.Map // sessionID -> Result
	bySetupIntent sync.Map // setupIntentID -> sessionID
}

// NewInMemoryStore returns an empty InMemoryStore.
func NewInMemoryStore() *InMemoryStore { return &InMemoryStore{} }

// PutSetupIntent implements ResultStore.
func (s *InMemoryStore) PutSetupIntent(_ context.Context, sessionID, setupIntentID string) error {
	if sessionID == "" || setupIntentID == "" {
		return errors.New("paid-billing-card: PutSetupIntent requires non-empty sessionID and setupIntentID")
	}
	s.bySetupIntent.Store(setupIntentID, sessionID)
	return nil
}

// LookupSessionBySetupIntent implements ResultStore.
func (s *InMemoryStore) LookupSessionBySetupIntent(_ context.Context, setupIntentID string) (string, error) {
	v, ok := s.bySetupIntent.Load(setupIntentID)
	if !ok {
		return "", nil
	}
	return v.(string), nil
}

// PutResult implements ResultStore.
func (s *InMemoryStore) PutResult(_ context.Context, sessionID string, result Result) error {
	if sessionID == "" {
		return errors.New("paid-billing-card: PutResult requires non-empty sessionID")
	}
	s.bySession.Store(sessionID, result)
	return nil
}

// GetResult implements ResultStore.
func (s *InMemoryStore) GetResult(_ context.Context, sessionID string) (Result, error) {
	v, ok := s.bySession.Load(sessionID)
	if !ok {
		return Result{}, ErrNoResultYet
	}
	return v.(Result), nil
}
