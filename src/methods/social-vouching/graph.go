// Package socialvouching implements the Personhood "social-vouching-graph"
// SUPPLEMENTARY verification method (STATUS.md checklist #10b): a BrightID-
// style web-of-trust where already-trusted members vouch for new members in
// connection ceremonies, and a simplified SybilRank-style trust-propagation
// score decides whether the candidate has accumulated enough (weighted,
// distinct) vouches to pass.
//
// Strength 35 per docs/06-methods-catalog.md Table 2 (supplementary
// methods) — NOT the 50+ an anchor requires. STATUS.md's checklist text
// calls this "the social-vouching-graph anchor," but the catalog's own
// scoring (Agent B: 35) places it below the registry's hard-enforced
// anchor floor of 50 (pkg/types/validation.go: MethodMetadata.Validate()
// rejects an anchor with strength < 50 — registering this method as an
// anchor would fail at startup). This implementation follows the catalog's
// number rather than the checklist's wording: web-of-trust vouching alone
// cannot defeat a well-resourced attacker who bootstraps their own vouching
// ring (the catalog's own "cold-start hard" note), so it composes with
// other methods (e.g. fuzzy-extractor-selfie) rather than substituting for
// an anchor — consistent with this repo's core "anchor + supplementary,
// never naive stacking" design constraint (see CLAUDE.md). See this
// session's wrapup for the full decision record.
//
// Cost: $0.00. Friction: high (per the catalog — coordinating an in-person
// or synchronous vouching ceremony with an existing member is real
// friction). Airdrop test: ✅ passes (no ID/bank/address required).
package socialvouching

import (
	"context"
	"sync"
	"time"
)

// Vouch is one recorded vouch for a candidate.
type Vouch struct {
	// VoucherID identifies who vouched. v0.1 keys this by the voucher's own
	// enrollment SessionID (see method.go's doc comment for the scope note
	// on why — this is a v0.1 simplification, not a stable long-term
	// identity key).
	VoucherID string

	// Weight is the voucher's trust score AT THE TIME they vouched (not
	// re-evaluated later if the voucher's own trust changes).
	Weight float64

	// At is when the vouch was recorded.
	At time.Time
}

// GraphStore is the web-of-trust persistence layer: it tracks each known
// member's trust score (seed members plus anyone who has themselves passed
// the ceremony) and the vouches accumulated so far for each in-flight
// candidate.
//
// Implementations MUST be safe for concurrent use.
type GraphStore interface {
	// TrustOf returns id's current trust score and whether id is known at
	// all (a configured seed, or a past graduate of this ceremony). Unknown
	// ids return (0, false, nil) — they cannot vouch for anyone until they
	// themselves pass the ceremony.
	TrustOf(ctx context.Context, id string) (trust float64, known bool, err error)

	// RecordVouch appends (or, for a repeat vouch from the same VoucherID,
	// overwrites) a vouch for candidateID. A given voucher counts at most
	// once per candidate — vouching twice does not let one member simulate
	// two distinct vouchers.
	RecordVouch(ctx context.Context, candidateID string, v Vouch) error

	// VouchesFor returns every distinct-voucher vouch recorded for
	// candidateID, in no particular order.
	VouchesFor(ctx context.Context, candidateID string) ([]Vouch, error)

	// Enroll records id's own trust score once its ceremony has succeeded,
	// so it can vouch for others afterwards.
	Enroll(ctx context.Context, id string, trust float64) error
}

// InMemoryGraphStore is a mutex-protected GraphStore suitable for dev,
// tests, and single-process deployments — like every other InMemory* store
// in this repo, it does not survive a restart or share state across
// replicas.
type InMemoryGraphStore struct {
	mu      sync.Mutex
	trust   map[string]float64          // member id -> trust score
	vouches map[string]map[string]Vouch // candidate id -> voucher id -> Vouch
}

var _ GraphStore = (*InMemoryGraphStore)(nil)

// NewInMemoryGraphStore returns a GraphStore seeded with the given trust
// scores (e.g. `{"seed-member-1": 1.0}`). Seed members are the bootstrap set
// every web-of-trust needs — see method.go's Config.Seeds.
func NewInMemoryGraphStore(seeds map[string]float64) *InMemoryGraphStore {
	trust := make(map[string]float64, len(seeds))
	for id, t := range seeds {
		trust[id] = t
	}
	return &InMemoryGraphStore{
		trust:   trust,
		vouches: make(map[string]map[string]Vouch),
	}
}

// TrustOf implements GraphStore.
func (g *InMemoryGraphStore) TrustOf(_ context.Context, id string) (float64, bool, error) {
	g.mu.Lock()
	defer g.mu.Unlock()
	t, ok := g.trust[id]
	return t, ok, nil
}

// RecordVouch implements GraphStore.
func (g *InMemoryGraphStore) RecordVouch(_ context.Context, candidateID string, v Vouch) error {
	g.mu.Lock()
	defer g.mu.Unlock()
	byVoucher, ok := g.vouches[candidateID]
	if !ok {
		byVoucher = make(map[string]Vouch)
		g.vouches[candidateID] = byVoucher
	}
	byVoucher[v.VoucherID] = v
	return nil
}

// VouchesFor implements GraphStore.
func (g *InMemoryGraphStore) VouchesFor(_ context.Context, candidateID string) ([]Vouch, error) {
	g.mu.Lock()
	defer g.mu.Unlock()
	byVoucher := g.vouches[candidateID]
	out := make([]Vouch, 0, len(byVoucher))
	for _, v := range byVoucher {
		out = append(out, v)
	}
	return out, nil
}

// Enroll implements GraphStore.
func (g *InMemoryGraphStore) Enroll(_ context.Context, id string, trust float64) error {
	g.mu.Lock()
	defer g.mu.Unlock()
	g.trust[id] = trust
	return nil
}
