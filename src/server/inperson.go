package server

// In-person vouching wiring (src/methods/social-vouching/inperson.go).
//
// Off unless IN_PERSON_VOUCH_ENABLED is set. Then:
//
//   - the ceremony routes are mounted under /v1/methods/in-person-vouch/
//     (offer, accept, confirm, status);
//   - social-vouching-graph (supplementary, 35) is registered if it was not
//     already, sharing one graph with the ceremony, so in-person vouches
//     count as supplementary points;
//   - the issuer verifies vouchers' credentials (VerifyVoucherCredential).
//
// IN_PERSON_VOUCH_ANCHOR additionally registers the in-person-vouch ANCHOR
// (strength 55). This is the "anchor policy" for people with no documents:
// K vouches from distinct anchored vouchers PLUS a selfie dedupe in the
// same session. The dedupe is enforced here, by method prerequisites: the
// issuer refuses to complete in-person-vouch for a session that has not
// already passed one of IN_PERSON_VOUCH_DEDUPE_METHODS (default
// fuzzy-extractor-selfie). The dedupe method itself is untouched. The
// anchor also requires HOLDER_REVOCATION_ENABLED, because its strength
// rests on vouchers being penalized when a fake is caught.

import (
	"context"
	"crypto/ed25519"
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/sagearbor/personhood/pkg/types"
	"github.com/sagearbor/personhood/src/credential"
	socialvouching "github.com/sagearbor/personhood/src/methods/social-vouching"
)

// InPersonVouchOptions are the operator's in-person vouching settings.
// Zero numeric fields take socialvouching's defaults.
type InPersonVouchOptions struct {
	// Anchor registers the in-person-vouch anchor (the anchor policy).
	Anchor bool
	// DedupeMethods: the session must already hold one of these before
	// in-person-vouch can complete. Used only with Anchor.
	DedupeMethods      []string
	Required           int
	MaxPerPeriod       int
	Period             time.Duration
	MinVoucherAge      time.Duration
	RequireSameNetwork bool
}

// DefaultDedupeMethods is IN_PERSON_VOUCH_DEDUPE_METHODS' default.
var DefaultDedupeMethods = []string{"fuzzy-extractor-selfie"}

// inPersonOptionsFromEnv returns nil when IN_PERSON_VOUCH_ENABLED is unset.
func inPersonOptionsFromEnv() (*InPersonVouchOptions, error) {
	if !envBool(os.Getenv("IN_PERSON_VOUCH_ENABLED")) {
		return nil, nil
	}
	o := &InPersonVouchOptions{
		Anchor:             envBool(os.Getenv("IN_PERSON_VOUCH_ANCHOR")),
		DedupeMethods:      splitCSV(os.Getenv("IN_PERSON_VOUCH_DEDUPE_METHODS")),
		RequireSameNetwork: envBool(os.Getenv("IN_PERSON_VOUCH_REQUIRE_SAME_NETWORK")),
	}
	if len(o.DedupeMethods) == 0 {
		o.DedupeMethods = DefaultDedupeMethods
	}
	ints := []struct {
		env string
		dst *int
		max int
	}{
		{"IN_PERSON_VOUCH_REQUIRED", &o.Required, 16},
		{"IN_PERSON_VOUCH_MAX_PER_PERIOD", &o.MaxPerPeriod, 100},
	}
	for _, f := range ints {
		if v := strings.TrimSpace(os.Getenv(f.env)); v != "" {
			n, err := strconv.Atoi(v)
			if err != nil || n < 1 || n > f.max {
				return nil, fmt.Errorf("%s: want an integer 1..%d, got %q", f.env, f.max, v)
			}
			*f.dst = n
		}
	}
	days := []struct {
		env string
		dst *time.Duration
		min int
	}{
		{"IN_PERSON_VOUCH_PERIOD_DAYS", &o.Period, 1},
		{"IN_PERSON_VOUCH_MIN_VOUCHER_AGE_DAYS", &o.MinVoucherAge, 0},
	}
	for _, f := range days {
		if v := strings.TrimSpace(os.Getenv(f.env)); v != "" {
			n, err := strconv.Atoi(v)
			if err != nil || n < f.min || n > 3650 {
				return nil, fmt.Errorf("%s: want a number of days %d..3650, got %q", f.env, f.min, v)
			}
			*f.dst = time.Duration(n) * 24 * time.Hour
		}
	}
	return o, nil
}

// wireInPersonVouch builds the ceremony, mounts its routes and, with the
// anchor policy on, registers the anchor and its dedupe prerequisite.
func (s *Server) wireInPersonVouch(opts *InPersonVouchOptions, graph socialvouching.GraphStore) error {
	if graph == nil {
		return fmt.Errorf("server: in-person vouching needs Dependencies.VouchGraph (BuildDependencies sets it)")
	}
	if opts.Anchor {
		if !s.cfg.HolderRevocation {
			return fmt.Errorf("server: IN_PERSON_VOUCH_ANCHOR needs HOLDER_REVOCATION_ENABLED: the anchor's strength rests on penalizing vouchers when a fake is caught")
		}
		var found []string
		for _, id := range opts.DedupeMethods {
			if _, ok := s.registry.Get(id); ok {
				found = append(found, id)
			}
		}
		if len(found) == 0 {
			return fmt.Errorf("server: IN_PERSON_VOUCH_ANCHOR: none of the dedupe methods %v is registered, so nobody could ever complete in-person-vouch", opts.DedupeMethods)
		}
	}

	p := socialvouching.NewInPerson(socialvouching.InPersonConfig{
		Graph:     graph,
		Store:     socialvouching.NewInMemoryInPersonStore(),
		Verifier:  s,
		IssuerDID: string(s.issuerDID),
		DIDForKey: func(pub ed25519.PublicKey) (string, error) {
			did, err := DIDKeyFromEd25519(pub)
			return string(did), err
		},
		ClientIP:           func(r *http.Request) string { return clientIP(r, s.cfg.RateLimit.TrustedProxyHops) },
		Now:                func() time.Time { return s.nowFunc() },
		Required:           opts.Required,
		MaxPerPeriod:       opts.MaxPerPeriod,
		Period:             opts.Period,
		MinVoucherAge:      opts.MinVoucherAge,
		RequireSameNetwork: opts.RequireSameNetwork,
	})
	s.inPerson = p
	id := socialvouching.InPersonMethodID
	s.methodRoutes = append(s.methodRoutes,
		methodRoute{MethodID: id, Path: "offer", Method: http.MethodPost, Handler: p.OfferHandler()},
		methodRoute{MethodID: id, Path: "accept", Method: http.MethodPost, Handler: p.AcceptHandler()},
		methodRoute{MethodID: id, Path: "confirm", Method: http.MethodPost, Handler: p.ConfirmHandler()},
		methodRoute{MethodID: id, Path: "status", Method: http.MethodGet, Handler: p.StatusHandler()},
	)
	if opts.Anchor {
		if err := s.registry.Register(socialvouching.NewAnchorMethod(p)); err != nil {
			return fmt.Errorf("register in-person-vouch: %w", err)
		}
		s.methodPrerequisites = map[string][]string{id: opts.DedupeMethods}
	}
	return nil
}

// VerifyVoucherCredential implements socialvouching.VoucherVerifier: the
// credential must be this issuer's, correctly signed, unexpired,
// unrevoked, held by a did:key, and its holder not revoked. The anchor is
// reported only while it is within its freshness window.
func (s *Server) VerifyVoucherCredential(ctx context.Context, raw json.RawMessage) (socialvouching.VoucherStanding, error) {
	invalid := func(format string, a ...any) (socialvouching.VoucherStanding, error) {
		return socialvouching.VoucherStanding{}, fmt.Errorf("%w: %s", socialvouching.ErrVoucherCredentialInvalid, fmt.Sprintf(format, a...))
	}
	var cred types.PersonhoodCredential
	if err := json.Unmarshal(raw, &cred); err != nil {
		return invalid("not a Personhood credential")
	}
	if cred.Issuer != s.issuerDID {
		return invalid("issued by %s; only credentials from this issuer can vouch here", cred.Issuer)
	}
	if err := credential.NewVerifier(credential.MapResolver{s.issuerDID: s.issuerPublicKey}).Verify(ctx, cred); err != nil {
		return invalid("%v", err)
	}
	now := s.nowFunc()
	if !now.Before(cred.ExpirationDate) {
		return invalid("expired")
	}
	if cs := cred.CredentialStatus; cs != nil {
		revoked, err := s.revocations.Revoked(ctx)
		if err != nil {
			return socialvouching.VoucherStanding{}, err
		}
		if i := sort.SearchInts(revoked, cs.StatusListIndex); i < len(revoked) && revoked[i] == cs.StatusListIndex {
			return invalid("revoked")
		}
	}
	holder := cred.CredentialSubject.ID
	pub, err := Ed25519FromDIDKey(holder)
	if err != nil {
		return invalid("holder is not a did:key")
	}
	if s.holders != nil {
		banned, err := s.holders.Banned(ctx, BanKindHolder, string(holder))
		if err != nil {
			return socialvouching.VoucherStanding{}, err
		}
		if banned {
			return invalid("holder revoked")
		}
	}
	st := socialvouching.VoucherStanding{DID: string(holder), PublicKey: pub}
	if a := cred.CredentialSubject.AnchorMethodID; a != nil {
		for _, vm := range cred.CredentialSubject.VerifiedMethods {
			if vm.MethodID == *a && (vm.FreshnessLifetime <= 0 || now.Sub(vm.VerifiedAt) <= vm.FreshnessLifetime) {
				st.AnchorMethodID, st.AnchorVerifiedAt = vm.MethodID, vm.VerifiedAt
				break
			}
		}
	}
	return st, nil
}

// missingPrerequisite returns the prerequisite list methodID still lacks in
// view, or nil when it has none or one is satisfied.
func (s *Server) missingPrerequisite(methodID string, view SessionView) []string {
	need := s.methodPrerequisites[methodID]
	if len(need) == 0 {
		return nil
	}
	for _, vm := range view.VerifiedMethods {
		for _, id := range need {
			if vm.MethodID == id {
				return nil
			}
		}
	}
	return need
}
