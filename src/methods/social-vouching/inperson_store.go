package socialvouching

import (
	"context"
	"crypto/ed25519"
	"errors"
	"sync"
	"time"
)

// Offer is one in-person vouch ceremony in flight: the voucher's phone
// showed Code as a QR, and the state moves open -> accepted -> confirmed.
type Offer struct {
	Code            string
	VoucherDID      string
	VoucherPub      ed25519.PublicKey
	VoucherAnchored bool
	VoucherWeight   float64
	OfferIP         string
	CreatedAt       time.Time
	ExpiresAt       time.Time // accept deadline

	State        string // OfferOpen | OfferAccepted | OfferConfirmed | OfferBurned
	CandidateDID string
	AcceptedAt   time.Time
	AcceptIP     string
	ReturnCode   string
	ReturnExpiry time.Time // confirm deadline
	BadAttempts  int       // wrong return codes so far
}

// Offer states.
const (
	OfferOpen      = "open"
	OfferAccepted  = "accepted"
	OfferConfirmed = "confirmed"
	OfferBurned    = "burned"
)

// InPersonVouch is one confirmed in-person vouch, with the evidence the
// ceremony gathered.
type InPersonVouch struct {
	CandidateDID    string        `json:"candidate_did"`
	VoucherDID      string        `json:"voucher_did"`
	VoucherAnchored bool          `json:"voucher_anchored"`
	Weight          float64       `json:"weight"`
	At              time.Time     `json:"at"`
	RoundTrip       time.Duration `json:"round_trip"`
	SameNetwork     bool          `json:"same_network"`
}

// VoucherRecord is what the store knows about one DID's standing.
type VoucherRecord struct {
	// VouchTimes are the confirmed vouches this DID gave, newest last.
	VouchTimes []time.Time
	// Strikes counts people this DID vouched for who were later proven fake.
	Strikes int
	// SuspendedUntil: no vouching before this time.
	SuspendedUntil time.Time
	// Revoked marks a DID that was itself proven a duplicate or a cheater.
	// It can neither vouch nor be vouched for again.
	Revoked bool
}

// Errors CommitVouch returns.
var (
	ErrVoucherSuspended = errors.New("social-vouching: voucher is suspended")
	ErrVoucherRevoked   = errors.New("social-vouching: voucher was revoked")
	ErrQuotaExhausted   = errors.New("social-vouching: voucher has no vouches left this period")
	ErrAlreadyVouched   = errors.New("social-vouching: voucher already vouched for this candidate")
	ErrCandidateRevoked = errors.New("social-vouching: candidate was revoked")
	ErrOfferNotFound    = errors.New("social-vouching: offer not found")
)

// InPersonStore holds offers, confirmed vouches and voucher standing.
//
// Implementations MUST be safe for concurrent use, and CommitVouch and
// Penalize MUST be atomic: two confirms racing for a voucher's last vouch
// may not both succeed.
type InPersonStore interface {
	PutOffer(ctx context.Context, o Offer) error
	GetOffer(ctx context.Context, code string) (Offer, error)
	// UpdateOffer applies fn to the stored offer atomically and saves the
	// result unless fn returns an error (which UpdateOffer then returns).
	UpdateOffer(ctx context.Context, code string, fn func(*Offer) error) (Offer, error)

	Voucher(ctx context.Context, did string) (VoucherRecord, error)

	// CommitVouch records v if the voucher is not revoked or suspended at
	// v.At, has given fewer than maxPerPeriod vouches in (v.At-period, v.At],
	// has not already vouched for the candidate, and the candidate is not
	// revoked.
	CommitVouch(ctx context.Context, v InPersonVouch, maxPerPeriod int, period time.Duration) error

	// VouchesFor returns the confirmed vouches for candidateDID.
	VouchesFor(ctx context.Context, candidateDID string) ([]InPersonVouch, error)

	// Penalize marks candidateDID revoked and gives each DID in vouchers a
	// strike, suspending it until now + suspendFor * strikes. It returns the
	// strike count each voucher now has. Penalizing an already revoked
	// candidate again is a no-op that returns (nil, nil), so a repeated
	// report cannot stack strikes.
	Penalize(ctx context.Context, candidateDID string, vouchers []string, now time.Time, suspendFor time.Duration) (map[string]int, error)
}

// InMemoryInPersonStore is a mutex-protected InPersonStore. Like every
// InMemory* store in this repo it forgets everything on restart: quotas,
// strikes and suspensions included. Dev, tests and single-process use only.
type InMemoryInPersonStore struct {
	mu       sync.Mutex
	offers   map[string]Offer
	vouches  map[string]map[string]InPersonVouch // candidate -> voucher -> vouch
	vouchers map[string]VoucherRecord
}

var _ InPersonStore = (*InMemoryInPersonStore)(nil)

func NewInMemoryInPersonStore() *InMemoryInPersonStore {
	return &InMemoryInPersonStore{
		offers:   map[string]Offer{},
		vouches:  map[string]map[string]InPersonVouch{},
		vouchers: map[string]VoucherRecord{},
	}
}

func (s *InMemoryInPersonStore) PutOffer(_ context.Context, o Offer) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.gcOffers(o.CreatedAt)
	if _, exists := s.offers[o.Code]; exists {
		return errors.New("social-vouching: offer code collision")
	}
	s.offers[o.Code] = o
	return nil
}

// gcOffers drops offers whose confirm (or accept) deadline passed over an
// hour ago, so the map does not grow without bound.
func (s *InMemoryInPersonStore) gcOffers(now time.Time) {
	for code, o := range s.offers {
		end := o.ExpiresAt
		if o.ReturnExpiry.After(end) {
			end = o.ReturnExpiry
		}
		if now.Sub(end) > time.Hour {
			delete(s.offers, code)
		}
	}
}

func (s *InMemoryInPersonStore) GetOffer(_ context.Context, code string) (Offer, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	o, ok := s.offers[code]
	if !ok {
		return Offer{}, ErrOfferNotFound
	}
	return o, nil
}

func (s *InMemoryInPersonStore) UpdateOffer(_ context.Context, code string, fn func(*Offer) error) (Offer, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	o, ok := s.offers[code]
	if !ok {
		return Offer{}, ErrOfferNotFound
	}
	if err := fn(&o); err != nil {
		return Offer{}, err
	}
	s.offers[code] = o
	return o, nil
}

func (s *InMemoryInPersonStore) Voucher(_ context.Context, did string) (VoucherRecord, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	r := s.vouchers[did]
	r.VouchTimes = append([]time.Time(nil), r.VouchTimes...)
	return r, nil
}

func (s *InMemoryInPersonStore) CommitVouch(_ context.Context, v InPersonVouch, maxPerPeriod int, period time.Duration) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.vouchers[v.CandidateDID].Revoked {
		return ErrCandidateRevoked
	}
	r := s.vouchers[v.VoucherDID]
	switch {
	case r.Revoked:
		return ErrVoucherRevoked
	case v.At.Before(r.SuspendedUntil):
		return ErrVoucherSuspended
	}
	if _, dup := s.vouches[v.CandidateDID][v.VoucherDID]; dup {
		return ErrAlreadyVouched
	}
	// Keep only the vouches inside the current period.
	kept := r.VouchTimes[:0:0]
	for _, t := range r.VouchTimes {
		if v.At.Sub(t) < period {
			kept = append(kept, t)
		}
	}
	if len(kept) >= maxPerPeriod {
		return ErrQuotaExhausted
	}
	r.VouchTimes = append(kept, v.At)
	s.vouchers[v.VoucherDID] = r
	byVoucher := s.vouches[v.CandidateDID]
	if byVoucher == nil {
		byVoucher = map[string]InPersonVouch{}
		s.vouches[v.CandidateDID] = byVoucher
	}
	byVoucher[v.VoucherDID] = v
	return nil
}

func (s *InMemoryInPersonStore) VouchesFor(_ context.Context, candidateDID string) ([]InPersonVouch, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	out := make([]InPersonVouch, 0, len(s.vouches[candidateDID]))
	for _, v := range s.vouches[candidateDID] {
		out = append(out, v)
	}
	return out, nil
}

func (s *InMemoryInPersonStore) Penalize(_ context.Context, candidateDID string, vouchers []string, now time.Time, suspendFor time.Duration) (map[string]int, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	c := s.vouchers[candidateDID]
	if c.Revoked {
		return nil, nil
	}
	c.Revoked = true
	s.vouchers[candidateDID] = c
	strikes := make(map[string]int, len(vouchers))
	for _, did := range vouchers {
		if did == candidateDID {
			continue
		}
		r := s.vouchers[did]
		r.Strikes++
		until := now.Add(suspendFor * time.Duration(r.Strikes))
		if until.After(r.SuspendedUntil) {
			r.SuspendedUntil = until
		}
		s.vouchers[did] = r
		strikes[did] = r.Strikes
	}
	return strikes, nil
}
