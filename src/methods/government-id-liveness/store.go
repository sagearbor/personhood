// Package governmentidliveness implements the Personhood
// "government-id-liveness" anchor method, wrapping Persona's hosted
// Inquiries flow (government ID document capture + selfie liveness check).
//
// Strength: 90 (anchor; significantly above the 50 anchor threshold).
// Cost   : ~$1.50–$2.50 per inquiry, depending on Persona contract.
// Friction: high — user uploads ID + completes liveness.
//
// Wire model:
//   1. BeginCeremony creates a Persona Inquiry with reference-id =
//      CeremonyContext.SessionID, returns the inquiry id + hosted-flow URL
//      in ChallengeData.
//   2. The client opens the hosted URL; the user completes the flow on
//      Persona's domain.
//   3. Persona POSTs an inquiry.completed webhook to the issuer. The
//      Method's HTTPHandler (registered separately on the server router)
//      validates the HMAC signature and writes the result into ResultStore
//      keyed by the original SessionID.
//   4. The client polls CompleteCeremony, which reads the latest result
//      from ResultStore and returns success iff Persona marked the inquiry
//      "approved".
package governmentidliveness

import (
	"context"
	"errors"
	"sync"
	"time"
)

// ErrNoResultYet is returned by ResultStore.Get when the webhook has not yet
// reported a final state for the given session.
var ErrNoResultYet = errors.New("government-id-liveness: no Persona result yet")

// Status mirrors the Persona inquiry-status enum, narrowed to the values
// that matter for issuance decisions.
type Status string

const (
	// StatusApproved is Persona's "approved" terminal state. The user passed
	// every check the template runs (document validity, face match, liveness).
	StatusApproved Status = "approved"

	// StatusDeclined is Persona's "declined" terminal state. The user failed
	// at least one check.
	StatusDeclined Status = "declined"

	// StatusNeedsReview is Persona's "needs_review" terminal state — the
	// automated pipeline could not decide. v0.1 treats this as failure for
	// auto-issuance; production deployments may route to a human reviewer
	// and re-issue later.
	StatusNeedsReview Status = "needs_review"

	// StatusExpired is what we record when the webhook reports
	// inquiry.expired (the user abandoned the flow past Persona's TTL).
	StatusExpired Status = "expired"
)

// Result is the per-session outcome stored after a Persona webhook fires.
type Result struct {
	// InquiryID is the Persona inquiry identifier (e.g. "inq_...").
	InquiryID string

	// Status is the narrowed Persona status.
	Status Status

	// RawStatus is the verbatim status string Persona reported, for audit logs.
	RawStatus string

	// CompletedAt is when the webhook delivered the terminal status.
	CompletedAt time.Time

	// EventName is the Persona event name that produced this result
	// (e.g. "inquiry.completed", "inquiry.expired"). Kept so callers can
	// distinguish auto-decline from timeout.
	EventName string
}

// ResultStore is the abstraction the method uses to receive results from
// the webhook handler and surface them to CompleteCeremony.
//
// Implementations MUST be safe for concurrent use.
type ResultStore interface {
	// PutInquiry binds inquiryID to sessionID at BeginCeremony time. The
	// webhook handler uses inquiryID-> sessionID to look up which session
	// a webhook belongs to.
	PutInquiry(ctx context.Context, sessionID, inquiryID string) error

	// LookupSessionByInquiry returns the sessionID associated with an
	// inquiryID, or an empty string + nil error if no binding exists.
	LookupSessionByInquiry(ctx context.Context, inquiryID string) (string, error)

	// PutResult writes a final webhook result against the session it was
	// created under. PutResult is called by the webhook handler.
	PutResult(ctx context.Context, sessionID string, result Result) error

	// GetResult fetches the latest stored result. Returns ErrNoResultYet
	// when no webhook has fired for the session.
	GetResult(ctx context.Context, sessionID string) (Result, error)
}

// InMemoryStore is a sync.Map-backed ResultStore suitable for dev, tests,
// and single-process deployments.
//
// Production should swap in a Redis or Postgres-backed implementation so the
// webhook handler and the API handler can be scaled horizontally.
type InMemoryStore struct {
	bySession sync.Map // sessionID -> Result
	byInquiry sync.Map // inquiryID -> sessionID
}

// NewInMemoryStore returns an empty InMemoryStore.
func NewInMemoryStore() *InMemoryStore {
	return &InMemoryStore{}
}

// PutInquiry implements ResultStore.
func (s *InMemoryStore) PutInquiry(_ context.Context, sessionID, inquiryID string) error {
	if sessionID == "" || inquiryID == "" {
		return errors.New("government-id-liveness: PutInquiry requires non-empty sessionID and inquiryID")
	}
	s.byInquiry.Store(inquiryID, sessionID)
	return nil
}

// LookupSessionByInquiry implements ResultStore.
func (s *InMemoryStore) LookupSessionByInquiry(_ context.Context, inquiryID string) (string, error) {
	v, ok := s.byInquiry.Load(inquiryID)
	if !ok {
		return "", nil
	}
	return v.(string), nil
}

// PutResult implements ResultStore.
func (s *InMemoryStore) PutResult(_ context.Context, sessionID string, result Result) error {
	if sessionID == "" {
		return errors.New("government-id-liveness: PutResult requires non-empty sessionID")
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
