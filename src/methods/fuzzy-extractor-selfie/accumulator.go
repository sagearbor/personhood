package fuzzyextractorselfie

import (
	"context"
	"sync"
	"time"
)

// EnrollmentRecord is what the accumulator retains per successful
// enrollment: the public helper data (XOR-masked, not the raw biometric) and
// the derived Commitment. Never the raw template.
type EnrollmentRecord struct {
	Helper     []byte
	Commitment Commitment
	EnrolledAt time.Time
}

// Accumulator is the server-side "no central biometric DB" membership set:
// it lets CompleteCeremony check whether a newly presented template belongs
// to someone who already enrolled, without ever storing (or needing) a raw
// biometric database. It only ever stores helper data + one-way commitments.
//
// v0.1 implementation note: FindDuplicate is an O(n) scan attempting Rep
// against every stored record. This is the accepted simple approach for a
// fuzzy-extractor accumulator at small-to-medium scale; a production version
// at large scale should bucket records with a locality-sensitive hash (LSH)
// over the template space so only a shortlist of plausible candidates is
// scanned per enrollment, rather than the whole population.
//
// Implementations MUST be safe for concurrent use.
type Accumulator interface {
	// FindDuplicate scans stored records for one whose helper data, combined
	// with template via Rep, reproduces that record's Commitment — i.e. the
	// presented template belongs to someone already enrolled. Returns the
	// matching record and true if found; a zero record and false otherwise.
	FindDuplicate(ctx context.Context, template []byte) (EnrollmentRecord, bool, error)

	// Add appends a new enrollment record. Callers MUST have already called
	// FindDuplicate and confirmed no match before calling Add, to avoid
	// enrolling the same person twice under a race.
	Add(ctx context.Context, rec EnrollmentRecord) error

	// Count returns the number of enrolled records (for health/tests).
	Count(ctx context.Context) (int, error)
}

// InMemoryAccumulator is a mutex-protected Accumulator suitable for dev,
// tests, and single-process deployments. Production should swap in a shared
// backend so the membership set is visible to every issuer replica — the
// same caveat every other InMemory* store in this repo carries.
type InMemoryAccumulator struct {
	mu      sync.Mutex
	records []EnrollmentRecord
}

var _ Accumulator = (*InMemoryAccumulator)(nil)

// NewInMemoryAccumulator returns an empty InMemoryAccumulator.
func NewInMemoryAccumulator() *InMemoryAccumulator {
	return &InMemoryAccumulator{}
}

// FindDuplicate implements Accumulator.
func (a *InMemoryAccumulator) FindDuplicate(_ context.Context, template []byte) (EnrollmentRecord, bool, error) {
	a.mu.Lock()
	defer a.mu.Unlock()
	for _, rec := range a.records {
		commitment, ok, err := Rep(template, rec.Helper)
		if err != nil {
			return EnrollmentRecord{}, false, err
		}
		if ok && commitment == rec.Commitment {
			return rec, true, nil
		}
	}
	return EnrollmentRecord{}, false, nil
}

// Add implements Accumulator.
func (a *InMemoryAccumulator) Add(_ context.Context, rec EnrollmentRecord) error {
	a.mu.Lock()
	defer a.mu.Unlock()
	a.records = append(a.records, rec)
	return nil
}

// Count implements Accumulator.
func (a *InMemoryAccumulator) Count(_ context.Context) (int, error) {
	a.mu.Lock()
	defer a.mu.Unlock()
	return len(a.records), nil
}
