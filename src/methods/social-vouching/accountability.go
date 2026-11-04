package socialvouching

import (
	"context"
	"fmt"
	"sort"
)

// Accountability: when a person is proven a duplicate or a cheater, the
// people who vouched for them pay.
//
// Penalize is called by the issuer when it revokes a holder (an
// equivocation proof, or an operator's revoke-holder call; see
// src/server/holderrevoke.go). For the revoked candidate it:
//
//   - marks the candidate revoked: it can never vouch, or be vouched for,
//     again, and its own past vouches stop counting toward anyone's anchor;
//   - removes the candidate from the trust graph;
//
// and for every voucher who vouched for the candidate (in person, or through
// the dev HMAC route):
//
//   - adds a strike and suspends the voucher for SuspendFor x strikes
//     (180 days for a first strike, matching OpenLine's suspendSec);
//   - multiplies the voucher's graph trust by PenaltyFactor (0.5), and an
//     anchored voucher's vouch weight by PenaltyFactor^strikes, so repeat
//     offenders' vouches count for less and less toward the supplementary
//     score.
//
// It does not revoke the vouchers' own credentials: a voucher may have been
// fooled. It does not cascade further than one hop.

// PenaltyReport says what Penalize did.
type PenaltyReport struct {
	CandidateDID string `json:"candidate_did"`
	// AlreadyRevoked is true when the candidate had been penalized before;
	// nothing was changed the second time.
	AlreadyRevoked bool `json:"already_revoked"`
	// Vouchers maps each penalized voucher to its strike count.
	Vouchers map[string]int `json:"vouchers"`
}

// Penalize applies the rules above. It is idempotent per candidate.
func (p *InPerson) Penalize(ctx context.Context, candidateDID string) (PenaltyReport, error) {
	vouchers := map[string]bool{}
	inPerson, err := p.cfg.Store.VouchesFor(ctx, candidateDID)
	if err != nil {
		return PenaltyReport{}, fmt.Errorf("social-vouching: penalize: %w", err)
	}
	for _, v := range inPerson {
		vouchers[v.VoucherDID] = true
	}
	graphVouches, err := p.cfg.Graph.VouchesFor(ctx, candidateDID)
	if err != nil {
		return PenaltyReport{}, fmt.Errorf("social-vouching: penalize: %w", err)
	}
	for _, v := range graphVouches {
		vouchers[v.VoucherID] = true
	}
	list := make([]string, 0, len(vouchers))
	for did := range vouchers {
		list = append(list, did)
	}
	sort.Strings(list)

	strikes, err := p.cfg.Store.Penalize(ctx, candidateDID, list, p.cfg.Now().UTC(), p.cfg.SuspendFor)
	if err != nil {
		return PenaltyReport{}, fmt.Errorf("social-vouching: penalize: %w", err)
	}
	report := PenaltyReport{CandidateDID: candidateDID, AlreadyRevoked: strikes == nil, Vouchers: strikes}
	if strikes == nil {
		report.Vouchers = map[string]int{}
		return report, nil
	}
	if err := p.cfg.Graph.Remove(ctx, candidateDID); err != nil {
		return report, fmt.Errorf("social-vouching: penalize: %w", err)
	}
	for did := range strikes {
		trust, known, err := p.cfg.Graph.TrustOf(ctx, did)
		if err != nil {
			return report, fmt.Errorf("social-vouching: penalize: %w", err)
		}
		if known {
			if err := p.cfg.Graph.Enroll(ctx, did, trust*p.cfg.PenaltyFactor); err != nil {
				return report, fmt.Errorf("social-vouching: penalize: %w", err)
			}
		}
	}
	return report, nil
}
