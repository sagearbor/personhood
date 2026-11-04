package socialvouching

// In-person vouching: a QR round trip between two phones.
//
// The ceremony (see README.md "In-person vouching" for the full design and
// what it does and does not prove):
//
//  1. OFFER. The voucher's app POSTs its own Personhood credential to
//     /offer. The issuer checks the credential (its own signature, not
//     expired, not revoked, holder is a did:key) and the voucher's standing
//     (anchored credential or a high enough graph score, not suspended,
//     vouches left this period), and returns a short-lived offer code. The
//     voucher's phone shows it as a QR.
//  2. ACCEPT. The newcomer's phone scans the QR, signs AcceptMessage with
//     its holder key and POSTs it to /accept. The issuer returns a return
//     code, which the newcomer's phone shows as a QR.
//  3. CONFIRM. The voucher's phone, which has been polling /status and now
//     knows the newcomer's DID, scans the return code, signs ConfirmMessage
//     (which names the newcomer and the return code) with its holder key and
//     POSTs it to /confirm. The issuer checks the signature, the deadlines,
//     and the voucher's quota, then records the vouch.
//
// Each side signs a value only the other side's screen showed it, so both
// keys took part in one live exchange. The deadlines (OfferTTL for the
// scan, ReturnTTL for the scan back) stop vouches being prepared in advance
// or in bulk. None of this proves the two phones were in the same place:
// a camera pointed at a video call relays a QR in seconds. What makes a
// remote vouch costly is the voucher's accountability: a few vouches per
// period, and a strike, a suspension and a lower score for every person
// they vouched for who is later proven fake (Penalize).

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/subtle"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"math"
	"net"
	"net/http"
	"strings"
	"time"
)

// InPersonMethodID is the anchor method an in-person-vouched newcomer
// completes (see anchor.go). The ceremony routes are mounted under it.
const InPersonMethodID = "in-person-vouch"

// InPersonTag starts every message a holder key signs in this ceremony.
const InPersonTag = "personhood-in-person-vouch/v1"

// VouchStatement is the sentence the voucher's signature commits to.
const VouchStatement = "I met this person face to face and I believe they hold no other credential."

// QR payload prefixes. The voucher's phone shows QRPrefixOffer+code; the
// newcomer's phone shows QRPrefixReturn+code.
const (
	QRPrefixOffer  = "PHV1:O:"
	QRPrefixReturn = "PHV1:R:"
)

// Defaults for InPersonConfig's zero fields. MaxPerPeriod, Period and
// SuspendFor match OpenLine's on-chain vouching defaults
// (cmd/openline-node/chain/vouch.go), so one person faces the same limits
// on both.
const (
	DefaultInPersonRequired = 3
	DefaultMaxPerPeriod     = 2
	DefaultPeriod           = 30 * 24 * time.Hour
	DefaultMinVoucherScore  = 0.5
	DefaultOfferTTL         = 2 * time.Minute
	DefaultReturnTTL        = 90 * time.Second
	DefaultVouchValidity    = 30 * 24 * time.Hour
	DefaultSuspendFor       = 180 * 24 * time.Hour
	DefaultPenaltyFactor    = 0.5

	// maxReturnCodeAttempts burns an offer after this many wrong return
	// codes, so the 40-bit code cannot be guessed online.
	maxReturnCodeAttempts = 5
)

// VoucherStanding is what a VoucherVerifier learned from a voucher's
// credential.
type VoucherStanding struct {
	// DID is the credential's subject, a did:key.
	DID string
	// PublicKey is the Ed25519 key DID encodes. The voucher's confirm
	// signature must verify under it.
	PublicKey ed25519.PublicKey
	// AnchorMethodID is the credential's anchor, "" when it has none or the
	// anchor's freshness window has passed.
	AnchorMethodID string
	// AnchorVerifiedAt is when that anchor was verified.
	AnchorVerifiedAt time.Time
}

// ErrVoucherCredentialInvalid is what a VoucherVerifier wraps when the
// presented credential is not one the issuer accepts.
var ErrVoucherCredentialInvalid = errors.New("social-vouching: voucher credential invalid")

// VoucherVerifier checks a credential a would-be voucher presents. The
// issuer implements it (src/server/inperson.go), since only the issuer
// knows its own key and revocation list.
type VoucherVerifier interface {
	VerifyVoucherCredential(ctx context.Context, raw json.RawMessage) (VoucherStanding, error)
}

// InPersonConfig configures InPerson. Graph, Store, Verifier, IssuerDID and
// DIDForKey are required; zero numeric fields take the Default* values.
type InPersonConfig struct {
	Graph     GraphStore
	Store     InPersonStore
	Verifier  VoucherVerifier
	IssuerDID string
	// DIDForKey maps an Ed25519 public key to its did:key (the issuer's own
	// derivation, src/server/did.go).
	DIDForKey func(ed25519.PublicKey) (string, error)
	// ClientIP returns the caller's address, honouring the issuer's proxy
	// settings. Optional; without it no network evidence is recorded.
	ClientIP func(*http.Request) string
	// Now defaults to time.Now.
	Now func() time.Time

	// Required is K, the distinct anchored vouchers the in-person-vouch
	// anchor needs.
	Required int
	// MaxPerPeriod vouches per voucher per Period.
	MaxPerPeriod int
	Period       time.Duration
	// MinVoucherAge: an anchored voucher's anchor must be at least this old.
	// 0 (the default) allows a brand-new member to vouch at once; a real
	// deployment should set it (OpenLine recommends 30 days) so a fake
	// cannot immediately vouch for more fakes.
	MinVoucherAge time.Duration
	// MinVoucherScore lets a voucher with no anchored credential vouch when
	// its graph trust is at least this. Such vouches count toward
	// social-vouching-graph but never toward the in-person-vouch anchor.
	MinVoucherScore float64
	OfferTTL        time.Duration
	ReturnTTL       time.Duration
	// VouchValidity: vouches older than this no longer count toward the
	// anchor, so vouches cannot be banked.
	VouchValidity time.Duration
	// SuspendFor is the suspension per strike; PenaltyFactor scales a
	// voucher's weight per strike.
	SuspendFor    time.Duration
	PenaltyFactor float64
	// RequireSameNetwork refuses a confirm unless the newcomer's accept and
	// the voucher's confirm came from the same /24 (IPv4) or /48 (IPv6).
	// Off by default: two phones on mobile data rarely share one.
	RequireSameNetwork bool
}

// InPerson runs the in-person ceremony and the accountability rules.
type InPerson struct {
	cfg InPersonConfig
}

// NewInPerson validates cfg, fills defaults and returns an InPerson. Missing
// required dependencies are a programmer error and panic, like NewMethod.
func NewInPerson(cfg InPersonConfig) *InPerson {
	switch {
	case cfg.Graph == nil:
		panic("social-vouching.NewInPerson: Graph must not be nil")
	case cfg.Store == nil:
		panic("social-vouching.NewInPerson: Store must not be nil")
	case cfg.Verifier == nil:
		panic("social-vouching.NewInPerson: Verifier must not be nil")
	case cfg.IssuerDID == "":
		panic("social-vouching.NewInPerson: IssuerDID must not be empty")
	case cfg.DIDForKey == nil:
		panic("social-vouching.NewInPerson: DIDForKey must not be nil")
	}
	if cfg.Now == nil {
		cfg.Now = time.Now
	}
	setDefault(&cfg.Required, DefaultInPersonRequired)
	setDefault(&cfg.MaxPerPeriod, DefaultMaxPerPeriod)
	setDefault(&cfg.Period, DefaultPeriod)
	setDefault(&cfg.MinVoucherScore, DefaultMinVoucherScore)
	setDefault(&cfg.OfferTTL, DefaultOfferTTL)
	setDefault(&cfg.ReturnTTL, DefaultReturnTTL)
	setDefault(&cfg.VouchValidity, DefaultVouchValidity)
	setDefault(&cfg.SuspendFor, DefaultSuspendFor)
	setDefault(&cfg.PenaltyFactor, DefaultPenaltyFactor)
	return &InPerson{cfg: cfg}
}

func setDefault[T int | float64 | time.Duration](v *T, def T) {
	if *v <= 0 {
		*v = def
	}
}

// Required returns K.
func (p *InPerson) Required() int { return p.cfg.Required }

// AcceptMessage is the text the newcomer's holder key signs at /accept.
func AcceptMessage(issuerDID, offerCode, candidateDID string) string {
	return strings.Join([]string{InPersonTag, "accept", issuerDID, offerCode, candidateDID}, "\n")
}

// ConfirmMessage is the text the voucher's holder key signs at /confirm.
func ConfirmMessage(issuerDID, offerCode, candidateDID, returnCode string) string {
	return strings.Join([]string{InPersonTag, "vouch", issuerDID, offerCode, candidateDID, returnCode, VouchStatement}, "\n")
}

// ----------------------------------------------------------------------------
// Codes
// ----------------------------------------------------------------------------

// crockford is Crockford's base32 alphabet: no I, L, O or U, so a code read
// aloud or typed is hard to get wrong.
const crockford = "0123456789ABCDEFGHJKMNPQRSTVWXYZ"

// newCode returns 8 Crockford base32 characters (40 random bits).
func newCode() (string, error) {
	var b [5]byte
	if _, err := rand.Read(b[:]); err != nil {
		return "", err
	}
	v := uint64(b[0])<<32 | uint64(b[1])<<24 | uint64(b[2])<<16 | uint64(b[3])<<8 | uint64(b[4])
	out := make([]byte, 8)
	for i := 7; i >= 0; i-- {
		out[i] = crockford[v&31]
		v >>= 5
	}
	return string(out), nil
}

// NormalizeCode accepts a code as typed or scanned: an optional QR prefix,
// any case, spaces and dashes, and the letters Crockford folds (O->0,
// I/L->1). It returns "" when the result is not 8 alphabet characters.
func NormalizeCode(s string) string {
	s = strings.TrimSpace(s)
	for _, pre := range []string{QRPrefixOffer, QRPrefixReturn} {
		s = strings.TrimPrefix(s, pre)
	}
	var b strings.Builder
	for _, r := range strings.ToUpper(s) {
		switch r {
		case ' ', '-':
			continue
		case 'O':
			r = '0'
		case 'I', 'L':
			r = '1'
		}
		b.WriteRune(r)
	}
	out := b.String()
	if len(out) != 8 {
		return ""
	}
	for i := 0; i < len(out); i++ {
		if !strings.ContainsRune(crockford, rune(out[i])) {
			return ""
		}
	}
	return out
}

// ----------------------------------------------------------------------------
// Voucher standing
// ----------------------------------------------------------------------------

// eligibility is a voucher's standing at one moment.
type eligibility struct {
	anchored bool
	weight   float64
	left     int // vouches left this period
}

// vouchError is an HTTP error the ceremony handlers return.
type vouchError struct {
	status int
	code   string
	msg    string
}

func (e *vouchError) Error() string { return e.code + ": " + e.msg }

func vErr(status int, code, msg string) *vouchError { return &vouchError{status, code, msg} }

// eligible decides whether st may vouch at now.
func (p *InPerson) eligible(ctx context.Context, st VoucherStanding, now time.Time) (eligibility, error) {
	rec, err := p.cfg.Store.Voucher(ctx, st.DID)
	if err != nil {
		return eligibility{}, err
	}
	switch {
	case rec.Revoked:
		return eligibility{}, vErr(http.StatusForbidden, "voucher_revoked", "this credential's holder was found to be a duplicate or a cheater and can no longer vouch")
	case now.Before(rec.SuspendedUntil):
		return eligibility{}, vErr(http.StatusForbidden, "voucher_suspended",
			"someone you vouched for was found to be fake; you can vouch again after "+rec.SuspendedUntil.UTC().Format("2006-01-02")+". "+AppealNote)
	}
	used := 0
	for _, t := range rec.VouchTimes {
		if now.Sub(t) < p.cfg.Period {
			used++
		}
	}
	left := p.cfg.MaxPerPeriod - used
	if left <= 0 {
		return eligibility{}, vErr(http.StatusForbidden, "quota_exhausted",
			fmt.Sprintf("you have used all %d vouches for this %d-day period", p.cfg.MaxPerPeriod, int(p.cfg.Period.Hours()/24)))
	}

	penalty := math.Pow(p.cfg.PenaltyFactor, float64(rec.Strikes))
	if st.AnchorMethodID != "" {
		if now.Sub(st.AnchorVerifiedAt) < p.cfg.MinVoucherAge {
			return eligibility{}, vErr(http.StatusForbidden, "voucher_too_new",
				fmt.Sprintf("your anchor must be at least %d days old before you can vouch", int(p.cfg.MinVoucherAge.Hours()/24)))
		}
		return eligibility{anchored: true, weight: penalty, left: left}, nil
	}
	trust, known, err := p.cfg.Graph.TrustOf(ctx, st.DID)
	if err != nil {
		return eligibility{}, err
	}
	if !known || trust < p.cfg.MinVoucherScore {
		return eligibility{}, vErr(http.StatusForbidden, "voucher_not_eligible",
			"to vouch you need a credential with an anchor (for example a selfie or ID check), or a high enough vouch score")
	}
	// Graph trust already dropped at each strike (Penalize), so no extra
	// penalty here.
	return eligibility{anchored: false, weight: trust, left: left}, nil
}

// ----------------------------------------------------------------------------
// HTTP handlers (mounted by the issuer under /v1/methods/in-person-vouch/)
// ----------------------------------------------------------------------------

type offerRequest struct {
	Credential json.RawMessage `json:"credential"`
}

type offerResponse struct {
	OfferCode       string    `json:"offer_code"`
	QRText          string    `json:"qr_text"`
	ExpiresAt       time.Time `json:"expires_at"`
	VoucherDID      string    `json:"voucher_did"`
	VoucherAnchored bool      `json:"voucher_anchored"`
	VouchesLeft     int       `json:"vouches_left"`
}

// OfferHandler is POST /v1/methods/in-person-vouch/offer.
func (p *InPerson) OfferHandler() http.HandlerFunc {
	return p.handle(func(r *http.Request) (any, error) {
		var req offerRequest
		if err := decodeStrict(r, &req); err != nil || len(req.Credential) == 0 {
			return nil, vErr(http.StatusBadRequest, "invalid_request", "body must be {\"credential\": <your Personhood credential>}")
		}
		ctx := r.Context()
		st, err := p.cfg.Verifier.VerifyVoucherCredential(ctx, req.Credential)
		if err != nil {
			if errors.Is(err, ErrVoucherCredentialInvalid) {
				return nil, vErr(http.StatusUnauthorized, "credential_invalid", err.Error())
			}
			return nil, err
		}
		now := p.cfg.Now().UTC()
		el, err := p.eligible(ctx, st, now)
		if err != nil {
			return nil, err
		}
		code, err := newCode()
		if err != nil {
			return nil, err
		}
		o := Offer{
			Code:            code,
			VoucherDID:      st.DID,
			VoucherPub:      st.PublicKey,
			VoucherAnchored: el.anchored,
			VoucherWeight:   el.weight,
			OfferIP:         p.clientIP(r),
			CreatedAt:       now,
			ExpiresAt:       now.Add(p.cfg.OfferTTL),
			State:           OfferOpen,
		}
		if err := p.cfg.Store.PutOffer(ctx, o); err != nil {
			return nil, err
		}
		return offerResponse{
			OfferCode:       code,
			QRText:          QRPrefixOffer + code,
			ExpiresAt:       o.ExpiresAt,
			VoucherDID:      st.DID,
			VoucherAnchored: el.anchored,
			VouchesLeft:     el.left,
		}, nil
	})
}

type acceptRequest struct {
	OfferCode             string `json:"offer_code"`
	CandidatePublicKeyB64 string `json:"candidate_public_key_b64"`
	SignatureB64          string `json:"signature_b64"`
}

type acceptResponse struct {
	ReturnCode      string    `json:"return_code"`
	QRText          string    `json:"qr_text"`
	ExpiresAt       time.Time `json:"expires_at"`
	CandidateDID    string    `json:"candidate_did"`
	VoucherDID      string    `json:"voucher_did"`
	VoucherAnchored bool      `json:"voucher_anchored"`
}

// AcceptHandler is POST /v1/methods/in-person-vouch/accept.
func (p *InPerson) AcceptHandler() http.HandlerFunc {
	return p.handle(func(r *http.Request) (any, error) {
		var req acceptRequest
		if err := decodeStrict(r, &req); err != nil {
			return nil, vErr(http.StatusBadRequest, "invalid_request", err.Error())
		}
		code := NormalizeCode(req.OfferCode)
		if code == "" {
			return nil, vErr(http.StatusBadRequest, "invalid_code", "that is not a vouch code")
		}
		pub, err := decodeB64(req.CandidatePublicKeyB64)
		if err != nil || len(pub) != ed25519.PublicKeySize {
			return nil, vErr(http.StatusBadRequest, "invalid_holder_key", "candidate_public_key_b64 must be a base64 32-byte Ed25519 key")
		}
		candidate, err := p.cfg.DIDForKey(ed25519.PublicKey(pub))
		if err != nil {
			return nil, vErr(http.StatusBadRequest, "invalid_holder_key", err.Error())
		}
		sig, err := decodeB64(req.SignatureB64)
		if err != nil || !ed25519.Verify(ed25519.PublicKey(pub), []byte(AcceptMessage(p.cfg.IssuerDID, code, candidate)), sig) {
			return nil, vErr(http.StatusUnauthorized, "signature_invalid", "the signature does not match this phone's key")
		}
		ctx := r.Context()
		if rec, err := p.cfg.Store.Voucher(ctx, candidate); err != nil {
			return nil, err
		} else if rec.Revoked {
			return nil, vErr(http.StatusForbidden, "candidate_revoked", "this key was found to belong to a duplicate or a cheater. "+AppealNote)
		}
		returnCode, err := newCode()
		if err != nil {
			return nil, err
		}
		now := p.cfg.Now().UTC()
		ip := p.clientIP(r)
		o, err := p.cfg.Store.UpdateOffer(ctx, code, func(o *Offer) error {
			switch {
			case o.State != OfferOpen:
				return vErr(http.StatusConflict, "offer_used", "this code was already scanned; ask the voucher for a new one")
			case now.After(o.ExpiresAt):
				return vErr(http.StatusGone, "offer_expired", "this code has expired; ask the voucher for a new one")
			case o.VoucherDID == candidate:
				return vErr(http.StatusBadRequest, "self_vouch_not_allowed", "you cannot vouch for yourself")
			}
			o.State = OfferAccepted
			o.CandidateDID = candidate
			o.AcceptedAt = now
			o.AcceptIP = ip
			o.ReturnCode = returnCode
			o.ReturnExpiry = now.Add(p.cfg.ReturnTTL)
			return nil
		})
		if errors.Is(err, ErrOfferNotFound) {
			return nil, vErr(http.StatusNotFound, "offer_not_found", "no vouch offer has this code")
		}
		if err != nil {
			return nil, err
		}
		return acceptResponse{
			ReturnCode:      returnCode,
			QRText:          QRPrefixReturn + returnCode,
			ExpiresAt:       o.ReturnExpiry,
			CandidateDID:    candidate,
			VoucherDID:      o.VoucherDID,
			VoucherAnchored: o.VoucherAnchored,
		}, nil
	})
}

type statusResponse struct {
	State           string     `json:"state"`
	ExpiresAt       time.Time  `json:"expires_at"`
	VoucherDID      string     `json:"voucher_did"`
	VoucherAnchored bool       `json:"voucher_anchored"`
	CandidateDID    string     `json:"candidate_did,omitempty"`
	ReturnExpiresAt *time.Time `json:"return_expires_at,omitempty"`
}

// StatusHandler is GET /v1/methods/in-person-vouch/status?code=<offer code>.
// Both phones poll it: the voucher to learn who scanned its code, the
// newcomer to learn when the voucher confirmed. Knowing the code is the
// authorization; it reveals only DIDs, which are public keys.
func (p *InPerson) StatusHandler() http.HandlerFunc {
	return p.handle(func(r *http.Request) (any, error) {
		code := NormalizeCode(r.URL.Query().Get("code"))
		if code == "" {
			return nil, vErr(http.StatusBadRequest, "invalid_code", "that is not a vouch code")
		}
		o, err := p.cfg.Store.GetOffer(r.Context(), code)
		if errors.Is(err, ErrOfferNotFound) {
			return nil, vErr(http.StatusNotFound, "offer_not_found", "no vouch offer has this code")
		}
		if err != nil {
			return nil, err
		}
		now := p.cfg.Now().UTC()
		state := o.State
		if (state == OfferOpen && now.After(o.ExpiresAt)) || (state == OfferAccepted && now.After(o.ReturnExpiry)) {
			state = "expired"
		}
		resp := statusResponse{State: state, ExpiresAt: o.ExpiresAt, VoucherDID: o.VoucherDID, VoucherAnchored: o.VoucherAnchored, CandidateDID: o.CandidateDID}
		if !o.ReturnExpiry.IsZero() {
			t := o.ReturnExpiry
			resp.ReturnExpiresAt = &t
		}
		return resp, nil
	})
}

type confirmRequest struct {
	OfferCode    string `json:"offer_code"`
	ReturnCode   string `json:"return_code"`
	SignatureB64 string `json:"signature_b64"`
}

type confirmResponse struct {
	Recorded         bool    `json:"recorded"`
	CandidateDID     string  `json:"candidate_did"`
	VoucherAnchored  bool    `json:"voucher_anchored"`
	Weight           float64 `json:"weight"`
	RoundTripMS      int64   `json:"round_trip_ms"`
	SameNetwork      bool    `json:"same_network"`
	CandidateVouches int     `json:"candidate_vouches"`
	Required         int     `json:"required"`
}

// ConfirmHandler is POST /v1/methods/in-person-vouch/confirm.
func (p *InPerson) ConfirmHandler() http.HandlerFunc {
	return p.handle(func(r *http.Request) (any, error) {
		var req confirmRequest
		if err := decodeStrict(r, &req); err != nil {
			return nil, vErr(http.StatusBadRequest, "invalid_request", err.Error())
		}
		code, ret := NormalizeCode(req.OfferCode), NormalizeCode(req.ReturnCode)
		if code == "" || ret == "" {
			return nil, vErr(http.StatusBadRequest, "invalid_code", "offer_code and return_code must be vouch codes")
		}
		sig, err := decodeB64(req.SignatureB64)
		if err != nil {
			return nil, vErr(http.StatusBadRequest, "invalid_request", "signature_b64 must be base64")
		}
		ctx := r.Context()
		now := p.cfg.Now().UTC()
		ip := p.clientIP(r)

		// Check the return code and signature, and claim the offer, in one
		// atomic step so a confirm can't be replayed.
		var sameNetwork bool
		o, err := p.cfg.Store.UpdateOffer(ctx, code, func(o *Offer) error {
			switch {
			case o.State == OfferOpen:
				return vErr(http.StatusConflict, "offer_not_accepted", "the newcomer has not scanned your code yet")
			case o.State != OfferAccepted:
				return vErr(http.StatusConflict, "offer_used", "this ceremony is finished; start a new one")
			case now.After(o.ReturnExpiry):
				return vErr(http.StatusGone, "offer_expired", "too slow: scan the newcomer's code within the time limit; start again")
			}
			if subtle.ConstantTimeCompare([]byte(o.ReturnCode), []byte(ret)) != 1 {
				return errWrongReturnCode
			}
			msg := ConfirmMessage(p.cfg.IssuerDID, code, o.CandidateDID, ret)
			if !ed25519.Verify(o.VoucherPub, []byte(msg), sig) {
				return vErr(http.StatusUnauthorized, "signature_invalid", "the signature does not match the voucher's key")
			}
			sameNetwork = samePrefix(o.AcceptIP, ip)
			if p.cfg.RequireSameNetwork && !sameNetwork {
				return vErr(http.StatusForbidden, "not_same_network", "both phones must be on the same Wi-Fi network for this issuer")
			}
			o.State = OfferConfirmed
			return nil
		})
		if errors.Is(err, errWrongReturnCode) {
			// UpdateOffer saves nothing when fn fails, so count the wrong
			// attempt in a second update.
			_, _ = p.cfg.Store.UpdateOffer(ctx, code, func(o *Offer) error {
				o.BadAttempts++
				if o.BadAttempts >= maxReturnCodeAttempts {
					o.State = OfferBurned
				}
				return nil
			})
			return nil, vErr(http.StatusUnauthorized, "return_code_wrong", "that is not the code on the newcomer's screen")
		}
		if errors.Is(err, ErrOfferNotFound) {
			return nil, vErr(http.StatusNotFound, "offer_not_found", "no vouch offer has this code")
		}
		if err != nil {
			return nil, err
		}

		v := InPersonVouch{
			CandidateDID:    o.CandidateDID,
			VoucherDID:      o.VoucherDID,
			VoucherAnchored: o.VoucherAnchored,
			Weight:          o.VoucherWeight,
			At:              now,
			RoundTrip:       now.Sub(o.CreatedAt),
			SameNetwork:     sameNetwork,
		}
		if err := p.cfg.Store.CommitVouch(ctx, v, p.cfg.MaxPerPeriod, p.cfg.Period); err != nil {
			return nil, commitError(err)
		}
		// Feed the supplementary graph too, so social-vouching-graph counts
		// in-person vouches (and only in-person vouches when the dev HMAC
		// route is off).
		if err := p.cfg.Graph.RecordVouch(ctx, v.CandidateDID, Vouch{VoucherID: v.VoucherDID, Weight: v.Weight, At: now}); err != nil {
			return nil, err
		}
		all, err := p.cfg.Store.VouchesFor(ctx, v.CandidateDID)
		if err != nil {
			return nil, err
		}
		return confirmResponse{
			Recorded:         true,
			CandidateDID:     v.CandidateDID,
			VoucherAnchored:  v.VoucherAnchored,
			Weight:           v.Weight,
			RoundTripMS:      v.RoundTrip.Milliseconds(),
			SameNetwork:      sameNetwork,
			CandidateVouches: len(all),
			Required:         p.cfg.Required,
		}, nil
	})
}

var errWrongReturnCode = errors.New("wrong return code")

// AppealNote ends refusals that come from a revocation, which a review can
// undo: if the revoked person was honest, reinstating them also lifts the
// strikes their vouchers took.
const AppealNote = "If this is a mistake, the person who was revoked can appeal to the issuer; reinstating them also lifts their vouchers' strikes."

func commitError(err error) error {
	switch {
	case errors.Is(err, ErrVoucherSuspended):
		return vErr(http.StatusForbidden, "voucher_suspended", "you are suspended from vouching")
	case errors.Is(err, ErrVoucherRevoked):
		return vErr(http.StatusForbidden, "voucher_revoked", "you can no longer vouch")
	case errors.Is(err, ErrQuotaExhausted):
		return vErr(http.StatusForbidden, "quota_exhausted", "you have no vouches left this period")
	case errors.Is(err, ErrAlreadyVouched):
		return vErr(http.StatusConflict, "already_vouched", "you already vouched for this person")
	case errors.Is(err, ErrCandidateRevoked):
		return vErr(http.StatusForbidden, "candidate_revoked", "this person was found to be a duplicate or a cheater. "+AppealNote)
	}
	return err
}

func (p *InPerson) clientIP(r *http.Request) string {
	if p.cfg.ClientIP == nil {
		return ""
	}
	return p.cfg.ClientIP(r)
}

// samePrefix reports whether a and b share an IPv4 /24 or IPv6 /48. Empty or
// unparseable addresses never match.
func samePrefix(a, b string) bool {
	ia, ib := net.ParseIP(a), net.ParseIP(b)
	if ia == nil || ib == nil {
		return false
	}
	if a4, b4 := ia.To4(), ib.To4(); a4 != nil || b4 != nil {
		if a4 == nil || b4 == nil {
			return false
		}
		m := net.CIDRMask(24, 32)
		return a4.Mask(m).Equal(b4.Mask(m))
	}
	m := net.CIDRMask(48, 128)
	return ia.Mask(m).Equal(ib.Mask(m))
}

// handle adapts fn to an http.HandlerFunc that writes JSON: fn's result with
// 200, a *vouchError with its own status, anything else as 500.
func (p *InPerson) handle(fn func(r *http.Request) (any, error)) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		r.Body = http.MaxBytesReader(w, r.Body, VouchMaxBodyBytes)
		out, err := fn(r)
		w.Header().Set("Content-Type", "application/json")
		w.Header().Set("Cache-Control", "no-store")
		if err != nil {
			var ve *vouchError
			if !errors.As(err, &ve) {
				ve = vErr(http.StatusInternalServerError, "internal_error", "the issuer could not record this vouch; try again")
			}
			w.WriteHeader(ve.status)
			_ = json.NewEncoder(w).Encode(map[string]any{"error": map[string]string{"code": ve.code, "message": ve.msg}})
			return
		}
		w.WriteHeader(http.StatusOK)
		_ = json.NewEncoder(w).Encode(out)
	}
}

func decodeStrict(r *http.Request, dst any) error {
	if r.Body == nil {
		return errors.New("empty body")
	}
	dec := json.NewDecoder(r.Body)
	dec.DisallowUnknownFields()
	return dec.Decode(dst)
}

// decodeB64 accepts standard or URL-safe base64, padded or not.
func decodeB64(s string) ([]byte, error) {
	s = strings.TrimSpace(s)
	for _, enc := range []*base64.Encoding{base64.StdEncoding, base64.RawStdEncoding, base64.URLEncoding, base64.RawURLEncoding} {
		if b, err := enc.DecodeString(s); err == nil {
			return b, nil
		}
	}
	return nil, errors.New("not base64")
}
