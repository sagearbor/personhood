package socialvouching

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/sagearbor/personhood/pkg/types"
)

// methodPlugin mirrors registry.Method so this module stays independently
// compilable (see the same pattern in every other method package).
type methodPlugin interface {
	Metadata() types.MethodMetadata
	IsAvailableForUser(ctx types.UserContext) (available bool, reason string)
	BeginCeremony(ctx context.Context, cc types.CeremonyContext) (types.ChallengeData, error)
	CompleteCeremony(ctx context.Context, cc types.CeremonyContext, resp types.ResponseData) (types.MethodResult, error)
	HealthCheck(ctx context.Context) error
}

var _ methodPlugin = (*Method)(nil)

const (
	// MethodID is the stable plugin identifier, matching
	// docs/06-methods-catalog.md's `social-vouching-graph` row.
	MethodID = "social-vouching-graph"

	// MethodVersion tracks the plugin implementation version.
	MethodVersion = "0.1.0"

	// MethodStrength is the on-credential supplementary point value. 35 per
	// docs/06-methods-catalog.md Table 2 (below the 50-point anchor floor —
	// see the package doc comment for why this stays supplementary despite
	// STATUS.md checklist #10b calling it "the ... anchor").
	MethodStrength = 35

	// MethodCostUSD is the per-verification cost: free, self-hosted.
	MethodCostUSD = 0.00

	// MethodFreshnessLifetime: a web-of-trust relationship doesn't expire on
	// the same cadence as a KYC check, but per-context re-verification still
	// matters for the credential's overall freshness story. 90 days.
	MethodFreshnessLifetime = 90 * 24 * time.Hour

	// DefaultRequiredVouches is the minimum number of DISTINCT vouchers a
	// candidate needs before CompleteCeremony succeeds, regardless of their
	// combined weight. Prevents a single high-trust voucher from unilaterally
	// admitting new members.
	DefaultRequiredVouches = 3

	// DefaultRequiredScore is the minimum cumulative vouch weight (sum of
	// each distinct voucher's trust score at vouch time) a candidate needs.
	// 1.5 means, e.g., three vouchers averaging trust 0.5 each, or two
	// full-trust (1.0) seed members plus one partial.
	DefaultRequiredScore = 1.5

	// DefaultDecayFactor scales a newly-admitted member's own trust score
	// down from the average of their vouchers' weights, so trust degrades
	// (rather than staying at 1.0 indefinitely) as it propagates further
	// from the seed set — the same intuition SybilRank's decayed random walk
	// captures, simplified here to one multiplicative step per admission.
	DefaultDecayFactor = 0.75
)

// Method implements the Personhood social-vouching-graph supplementary
// method. Safe for concurrent use: all state lives in the injected
// GraphStore.
type Method struct {
	store           GraphStore
	auth            VoucherAuthenticator
	requiredVouches int
	requiredScore   float64
	decayFactor     float64
}

// Config bundles NewMethod's dependencies and tunables. Store and
// Authenticator are required; the numeric fields default per the
// Default* constants when zero.
type Config struct {
	Store           GraphStore
	Authenticator   VoucherAuthenticator
	RequiredVouches int
	RequiredScore   float64
	DecayFactor     float64
}

// NewMethod constructs a Method. A nil Store or Authenticator is a
// programmer error and panics.
func NewMethod(cfg Config) *Method {
	if cfg.Store == nil {
		panic("social-vouching.NewMethod: Store must not be nil")
	}
	if cfg.Authenticator == nil {
		panic("social-vouching.NewMethod: Authenticator must not be nil")
	}
	m := &Method{
		store:           cfg.Store,
		auth:            cfg.Authenticator,
		requiredVouches: cfg.RequiredVouches,
		requiredScore:   cfg.RequiredScore,
		decayFactor:     cfg.DecayFactor,
	}
	if m.requiredVouches <= 0 {
		m.requiredVouches = DefaultRequiredVouches
	}
	if m.requiredScore <= 0 {
		m.requiredScore = DefaultRequiredScore
	}
	if m.decayFactor <= 0 {
		m.decayFactor = DefaultDecayFactor
	}
	return m
}

// Metadata implements registry.Method.
func (m *Method) Metadata() types.MethodMetadata {
	return types.MethodMetadata{
		ID:                MethodID,
		Type:              types.MethodTypeSupplementary,
		Strength:          MethodStrength,
		CostUSD:           MethodCostUSD,
		UXFriction:        types.FrictionHigh,
		FreshnessLifetime: MethodFreshnessLifetime,
		Version:           MethodVersion,
	}
}

// IsAvailableForUser implements registry.Method. Vouching is a social
// process, not a device capability — available on any platform.
func (m *Method) IsAvailableForUser(_ types.UserContext) (bool, string) {
	return true, ""
}

// BeginCeremony implements registry.Method. It returns the candidate's
// vouch code — the candidate's stable holder DID when available (see
// candidateKey), falling back to the ceremony's own SessionID otherwise —
// and the out-of-band vouch endpoint an existing member POSTs a vouch to.
func (m *Method) BeginCeremony(_ context.Context, cc types.CeremonyContext) (types.ChallengeData, error) {
	if cc.SessionID == "" {
		return types.ChallengeData{}, errors.New("social-vouching: CeremonyContext.SessionID is required")
	}
	return types.ChallengeData{
		Type: "social-vouching-challenge",
		Payload: map[string]any{
			"candidate_code":    candidateKey(cc),
			"vouch_endpoint":    "/v1/methods/" + MethodID + "/vouch",
			"complete_endpoint": "/v1/methods/" + MethodID + "/complete",
			"required_vouches":  m.requiredVouches,
			"required_score":    m.requiredScore,
			"instructions":      "Share candidate_code with an existing vouched member; once enough members vouch for you at vouch_endpoint, complete_endpoint will report success.",
		},
	}, nil
}

// CompleteCeremony implements registry.Method. It ignores resp (vouches
// arrive out-of-band via VouchHandler, not in the completing client's own
// payload — see the package doc) and evaluates whatever vouches have
// accumulated so far for cc.SessionID against the configured thresholds. A
// client is expected to poll this (the same pattern the web app already
// uses for /v1/sessions/{id}), so an insufficient-vouches result is not a
// permanent failure — the candidate can complete again later once more
// vouches land.
func (m *Method) CompleteCeremony(ctx context.Context, cc types.CeremonyContext, _ types.ResponseData) (types.MethodResult, error) {
	if cc.SessionID == "" {
		return types.MethodResult{Success: false, MethodID: MethodID, ErrorReason: "missing_session_id"}, nil
	}
	candidate := candidateKey(cc)

	vouches, err := m.store.VouchesFor(ctx, candidate)
	if err != nil {
		return types.MethodResult{}, fmt.Errorf("social-vouching: vouches lookup: %w", err)
	}

	score := 0.0
	for _, v := range vouches {
		score += v.Weight
	}

	if len(vouches) < m.requiredVouches || score < m.requiredScore {
		return types.MethodResult{
			Success:  false,
			MethodID: MethodID,
			ErrorReason: fmt.Sprintf("insufficient_vouches:have=%d/%d,score=%.2f/%.2f",
				len(vouches), m.requiredVouches, score, m.requiredScore),
		}, nil
	}

	avg := score / float64(len(vouches))
	candidateTrust := avg * m.decayFactor
	if candidateTrust > 1.0 {
		candidateTrust = 1.0
	}
	if err := m.store.Enroll(ctx, candidate, candidateTrust); err != nil {
		return types.MethodResult{}, fmt.Errorf("social-vouching: enroll: %w", err)
	}

	now := time.Now().UTC()
	return types.MethodResult{
		Success:           true,
		MethodID:          MethodID,
		VerifiedAt:        now,
		AttestationDigest: vouchDigest(candidate, vouches),
	}, nil
}

// HealthCheck implements registry.Method. No external dependency to probe;
// the in-memory graph store is local. v0.1 is a no-op success.
func (m *Method) HealthCheck(_ context.Context) error { return nil }

// candidateKey returns the identity key this method uses to track a
// candidate/graduate in the GraphStore: cc.HolderDID (the stable did:key
// holder DID introduced in PR #35 — see src/server/did.go
// HolderDIDForSession) when the CeremonyContext carries one, falling back
// to cc.SessionID otherwise.
//
// This replaces v0.1's original "always key by SessionID" design (see the
// package doc's history): a bare SessionID only exists for the lifetime of
// one enrollment ceremony, so a candidate who later wanted to vouch for
// someone else in a SEPARATE session had no stable identity to present as
// voucher_id, and a candidate who re-enrolled would lose any vouches
// accumulated under their old SessionID. Keying by holder DID instead means
// the same holder keypair always resolves to the same graph identity across
// separate sessions — as long as the client persists and resubmits the same
// Ed25519 public key each time (see app/web/lib/holderkey.ts), which is
// exactly what the web app already does.
//
// The SessionID fallback is intentionally kept, not removed: a
// CeremonyContext with no HolderDID (e.g. a session started without
// holder_public_key_b64 — the round-1 email-only flow — or any
// CeremonyContext a test constructs directly without going through the
// server's handlers) still gets an internally-consistent identity key for
// that ceremony's own lifetime, matching the old behavior exactly. It is
// just no longer stable across separate sessions, which is the same
// limitation every other placeholder-DID-derived identity in this repo
// already has (see HolderDIDForSession's doc comment).
func candidateKey(cc types.CeremonyContext) string {
	if cc.HolderDID != "" {
		return string(cc.HolderDID)
	}
	return cc.SessionID
}
