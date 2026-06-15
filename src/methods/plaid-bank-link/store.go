// Package plaidbanklink implements the Personhood "plaid-bank-link" anchor
// method, wrapping Plaid's Hosted Link flow (bank-account OAuth + identity).
//
// Strength: 88 (anchor; well above the 50 anchor threshold). Per
// docs/06-methods-catalog.md this is "anchor #3" — bank OAuth via Plaid, fast
// to integrate and well understood. Note it does NOT pass the airdrop test (it
// requires a bank), so policies aimed at the unbanked should not require it.
//
// Cost   : ~$1.50 per successful link.
// Friction: med — the user authenticates with their bank via Plaid.
//
// Wire model (mirrors the government-id-liveness method):
//   1. BeginCeremony creates a Plaid Hosted Link session bound to
//      CeremonyContext.SessionID, returns the link token + hosted_link_url in
//      ChallengeData.
//   2. The client opens hosted_link_url; the user links their bank on Plaid's
//      domain.
//   3. Plaid POSTs a LINK / SESSION_FINISHED webhook to the issuer. The
//      Method's WebhookHandler validates the signature and writes the result
//      into ResultStore keyed by the original SessionID.
//   4. The client polls CompleteCeremony, which returns success iff Plaid
//      reported the session SUCCESS.
package plaidbanklink

import (
	"context"
	"errors"
	"sync"
	"time"
)

// ErrNoResultYet is returned by ResultStore.GetResult when the webhook has not
// yet reported a final state for the given session.
var ErrNoResultYet = errors.New("plaid-bank-link: no Plaid result yet")

// Status narrows Plaid's Hosted Link session outcomes to the values that
// matter for an issuance decision.
type Status string

const (
	// StatusApproved is a completed link (Plaid status "SUCCESS"): the user
	// authenticated with their bank and Plaid returned public tokens.
	StatusApproved Status = "approved"

	// StatusDeclined is an abandoned/failed link (Plaid status "EXITED" or a
	// hard failure): the user did not complete bank authentication.
	StatusDeclined Status = "declined"

	// StatusNeedsReview is a soft/ambiguous outcome (e.g. identity mismatch
	// that a human could resolve). v0.1 treats it as a failure for
	// auto-issuance.
	StatusNeedsReview Status = "needs_review"

	// StatusExpired is recorded when the Hosted Link session times out before
	// the user completes it.
	StatusExpired Status = "expired"
)

// Result is the per-session outcome stored after a Plaid webhook fires.
type Result struct {
	// LinkSessionID is Plaid's link session identifier (e.g. "lcs-...").
	LinkSessionID string

	// Status is the narrowed Plaid status.
	Status Status

	// RawStatus is the verbatim status string Plaid reported, for audit logs.
	RawStatus string

	// CompletedAt is when the webhook delivered the terminal status.
	CompletedAt time.Time

	// EventName is the Plaid webhook_code that produced this result
	// (e.g. "SESSION_FINISHED").
	EventName string
}

// ResultStore receives results from the webhook handler and surfaces them to
// CompleteCeremony. Implementations MUST be safe for concurrent use.
//
// Sessions are bound by Plaid link token (which the issuer holds from
// BeginCeremony and which the webhook echoes), so the handler can resolve an
// incoming webhook back to the Personhood session.
type ResultStore interface {
	// PutLinkToken binds linkToken to sessionID at BeginCeremony time.
	PutLinkToken(ctx context.Context, sessionID, linkToken string) error

	// LookupSessionByLinkToken returns the sessionID associated with a
	// linkToken, or an empty string + nil error if no binding exists.
	LookupSessionByLinkToken(ctx context.Context, linkToken string) (string, error)

	// PutResult writes a final webhook result against its session.
	PutResult(ctx context.Context, sessionID string, result Result) error

	// GetResult fetches the latest stored result, or ErrNoResultYet when no
	// webhook has fired for the session.
	GetResult(ctx context.Context, sessionID string) (Result, error)
}

// InMemoryStore is a sync.Map-backed ResultStore suitable for dev, tests, and
// single-process deployments. Production should swap in a shared backend.
type InMemoryStore struct {
	bySession   sync.Map // sessionID -> Result
	byLinkToken sync.Map // linkToken -> sessionID
}

// NewInMemoryStore returns an empty InMemoryStore.
func NewInMemoryStore() *InMemoryStore { return &InMemoryStore{} }

// PutLinkToken implements ResultStore.
func (s *InMemoryStore) PutLinkToken(_ context.Context, sessionID, linkToken string) error {
	if sessionID == "" || linkToken == "" {
		return errors.New("plaid-bank-link: PutLinkToken requires non-empty sessionID and linkToken")
	}
	s.byLinkToken.Store(linkToken, sessionID)
	return nil
}

// LookupSessionByLinkToken implements ResultStore.
func (s *InMemoryStore) LookupSessionByLinkToken(_ context.Context, linkToken string) (string, error) {
	v, ok := s.byLinkToken.Load(linkToken)
	if !ok {
		return "", nil
	}
	return v.(string), nil
}

// PutResult implements ResultStore.
func (s *InMemoryStore) PutResult(_ context.Context, sessionID string, result Result) error {
	if sessionID == "" {
		return errors.New("plaid-bank-link: PutResult requires non-empty sessionID")
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
