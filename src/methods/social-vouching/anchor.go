package socialvouching

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"sort"
	"strings"
	"time"

	"github.com/sagearbor/personhood/pkg/types"
)

// AnchorStrength is the in-person-vouch anchor's strength: 55, just over the
// 50-point anchor floor and below fuzzy-extractor-selfie (70).
//
// Why it may be an anchor at all: the issuer only grants it when K distinct
// vouchers who each hold an ANCHORED credential confirmed a live QR round
// trip with the newcomer, AND the newcomer's own session passed a selfie
// dedupe (the server enforces that prerequisite, see
// src/server/inperson.go). To mint a fake, an attacker needs K anchored
// accomplices who each spend one of a few vouches per period and each take
// a strike, a 180-day suspension and a halved weight when the fake is
// caught, plus a face the dedupe has not seen. That is the same cost
// structure OpenLine's on-chain vouching relies on.
//
// Why it is not higher: the round trip proves a live exchange, not
// proximity (a QR relays over a video call), so a ring of K colluding
// anchored members can still admit people remotely until they are caught.
// The strength rests on human accountability, which is slower than a
// cryptographic check.
const AnchorStrength = 55

// AnchorFreshness: vouches are a point-in-time judgement; re-vouch twice a
// year, like the other anchors' 180 days.
const AnchorFreshness = 180 * 24 * time.Hour

// AnchorMethod is the in-person-vouch ANCHOR: success needs K distinct
// anchored in-person vouchers within VouchValidity. Register it only behind
// the operator's explicit anchor-policy flag.
type AnchorMethod struct {
	p *InPerson
}

var _ methodPlugin = (*AnchorMethod)(nil)

// NewAnchorMethod wraps p's vouch store as an anchor method.
func NewAnchorMethod(p *InPerson) *AnchorMethod {
	if p == nil {
		panic("social-vouching.NewAnchorMethod: InPerson must not be nil")
	}
	return &AnchorMethod{p: p}
}

// Metadata implements registry.Method.
func (a *AnchorMethod) Metadata() types.MethodMetadata {
	return types.MethodMetadata{
		ID:                InPersonMethodID,
		Type:              types.MethodTypeAnchor,
		Strength:          AnchorStrength,
		CostUSD:           0,
		UXFriction:        types.FrictionHigh,
		FreshnessLifetime: AnchorFreshness,
		Version:           MethodVersion,
	}
}

// IsAvailableForUser implements registry.Method.
func (a *AnchorMethod) IsAvailableForUser(_ types.UserContext) (bool, string) { return true, "" }

// HealthCheck implements registry.Method.
func (a *AnchorMethod) HealthCheck(_ context.Context) error { return nil }

var errNoHolderKey = errors.New("in-person vouching needs a holder key: restart enrollment in a browser that supports Ed25519")

// BeginCeremony implements registry.Method. The newcomer's identity is its
// holder did:key; vouches are recorded against it through the ceremony
// routes, not through this call.
func (a *AnchorMethod) BeginCeremony(_ context.Context, cc types.CeremonyContext) (types.ChallengeData, error) {
	if !strings.HasPrefix(string(cc.HolderDID), "did:key:") {
		return types.ChallengeData{}, errNoHolderKey
	}
	base := "/v1/methods/" + InPersonMethodID + "/"
	return types.ChallengeData{
		Type: "in-person-vouch-challenge",
		Payload: map[string]any{
			"candidate_did":   string(cc.HolderDID),
			"required":        a.p.cfg.Required,
			"accept_endpoint": base + "accept",
			"status_endpoint": base + "status",
			"instructions":    "Meet each voucher in person. Scan the code on their phone, then let them scan the code on yours.",
		},
	}, nil
}

// CompleteCeremony implements registry.Method. Poll it after each vouch.
func (a *AnchorMethod) CompleteCeremony(ctx context.Context, cc types.CeremonyContext, _ types.ResponseData) (types.MethodResult, error) {
	fail := func(reason string) (types.MethodResult, error) {
		return types.MethodResult{Success: false, MethodID: InPersonMethodID, ErrorReason: reason}, nil
	}
	candidate := string(cc.HolderDID)
	if !strings.HasPrefix(candidate, "did:key:") {
		return fail("holder_key_required")
	}
	store := a.p.cfg.Store
	if rec, err := store.Voucher(ctx, candidate); err != nil {
		return types.MethodResult{}, fmt.Errorf("social-vouching: candidate lookup: %w", err)
	} else if rec.Revoked {
		return fail("candidate_revoked")
	}
	counted, err := a.p.anchorVouchers(ctx, candidate)
	if err != nil {
		return types.MethodResult{}, err
	}
	if len(counted) < a.p.cfg.Required {
		return fail(fmt.Sprintf("insufficient_vouches:have=%d/%d", len(counted), a.p.cfg.Required))
	}
	h := sha256.New()
	h.Write([]byte(InPersonTag))
	h.Write([]byte{0})
	h.Write([]byte(candidate))
	for _, v := range counted {
		h.Write([]byte{0})
		h.Write([]byte(v))
	}
	return types.MethodResult{
		Success:           true,
		MethodID:          InPersonMethodID,
		VerifiedAt:        a.p.cfg.Now().UTC(),
		AttestationDigest: hex.EncodeToString(h.Sum(nil)),
	}, nil
}

// anchorVouchers returns the sorted DIDs of the vouchers whose in-person
// vouch for candidate counts toward the anchor: anchored at vouch time,
// within VouchValidity, and not themselves revoked since.
func (p *InPerson) anchorVouchers(ctx context.Context, candidate string) ([]string, error) {
	vouches, err := p.cfg.Store.VouchesFor(ctx, candidate)
	if err != nil {
		return nil, fmt.Errorf("social-vouching: vouches lookup: %w", err)
	}
	now := p.cfg.Now()
	var out []string
	for _, v := range vouches {
		if !v.VoucherAnchored || now.Sub(v.At) > p.cfg.VouchValidity {
			continue
		}
		rec, err := p.cfg.Store.Voucher(ctx, v.VoucherDID)
		if err != nil {
			return nil, err
		}
		if rec.Revoked {
			continue
		}
		out = append(out, v.VoucherDID)
	}
	sort.Strings(out)
	return out, nil
}
