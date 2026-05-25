package registry

import (
	"context"
	"errors"
	"fmt"
	"sync"
	"testing"
	"time"

	"github.com/sagearbor/personhood/pkg/types"
)

// fakeMethod is a tiny in-test implementation of Method that returns whatever
// metadata it was constructed with. It is intentionally trivial; tests in
// other packages should NOT import this.
type fakeMethod struct {
	md          types.MethodMetadata
	available   bool
	reason      string
	healthErr   error
	challenge   types.ChallengeData
	beginErr    error
	result      types.MethodResult
	completeErr error
}

func (f *fakeMethod) Metadata() types.MethodMetadata { return f.md }

func (f *fakeMethod) IsAvailableForUser(types.UserContext) (bool, string) {
	return f.available, f.reason
}

func (f *fakeMethod) BeginCeremony(context.Context, types.CeremonyContext) (types.ChallengeData, error) {
	return f.challenge, f.beginErr
}

func (f *fakeMethod) CompleteCeremony(context.Context, types.CeremonyContext, types.ResponseData) (types.MethodResult, error) {
	return f.result, f.completeErr
}

func (f *fakeMethod) HealthCheck(context.Context) error { return f.healthErr }

// newAnchor returns a fakeMethod with valid anchor metadata.
func newAnchor(id string, strength int) *fakeMethod {
	return &fakeMethod{md: types.MethodMetadata{
		ID:                id,
		Type:              types.MethodTypeAnchor,
		Strength:          strength,
		UXFriction:        types.FrictionHigh,
		FreshnessLifetime: 24 * time.Hour,
		Version:           "0.1.0",
	}}
}

// newSupp returns a fakeMethod with valid supplementary metadata.
func newSupp(id string, strength int) *fakeMethod {
	return &fakeMethod{md: types.MethodMetadata{
		ID:                id,
		Type:              types.MethodTypeSupplementary,
		Strength:          strength,
		UXFriction:        types.FrictionLow,
		FreshnessLifetime: 24 * time.Hour,
		Version:           "0.1.0",
	}}
}

func TestRegister_ValidMethod_GetReturnsIt(t *testing.T) {
	r := New()
	m := newAnchor("phone-liveness", 80)
	if err := r.Register(m); err != nil {
		t.Fatalf("Register returned unexpected error: %v", err)
	}

	got, ok := r.Get("phone-liveness")
	if !ok {
		t.Fatalf("Get(%q): not found after Register", "phone-liveness")
	}
	if got.Metadata().ID != "phone-liveness" {
		t.Errorf("Get returned method with ID %q, want %q", got.Metadata().ID, "phone-liveness")
	}
}

func TestRegister_NilMethod_ReturnsErr(t *testing.T) {
	r := New()
	if err := r.Register(nil); !errors.Is(err, ErrNilMethod) {
		t.Errorf("Register(nil) = %v, want ErrNilMethod", err)
	}
}

func TestRegister_DuplicateID_ReturnsErr(t *testing.T) {
	r := New()
	if err := r.Register(newAnchor("email-magic-link", 60)); err != nil {
		t.Fatalf("first Register failed: %v", err)
	}
	err := r.Register(newAnchor("email-magic-link", 70))
	if !errors.Is(err, ErrDuplicateMethodID) {
		t.Errorf("duplicate Register = %v, want ErrDuplicateMethodID", err)
	}
}

func TestRegister_InvalidMetadata_TableDriven(t *testing.T) {
	cases := []struct {
		name string
		m    Method
	}{
		{
			name: "anchor with strength below 50",
			m: &fakeMethod{md: types.MethodMetadata{
				ID: "weak-anchor", Type: types.MethodTypeAnchor, Strength: 40,
				UXFriction: types.FrictionLow, Version: "0.1.0",
			}},
		},
		{
			name: "supplementary with strength >= 50",
			m: &fakeMethod{md: types.MethodMetadata{
				ID: "strong-supp", Type: types.MethodTypeSupplementary, Strength: 60,
				UXFriction: types.FrictionLow, Version: "0.1.0",
			}},
		},
		{
			name: "strength out of range",
			m: &fakeMethod{md: types.MethodMetadata{
				ID: "huge", Type: types.MethodTypeAnchor, Strength: 200,
				UXFriction: types.FrictionLow, Version: "0.1.0",
			}},
		},
		{
			name: "empty id",
			m: &fakeMethod{md: types.MethodMetadata{
				ID: "", Type: types.MethodTypeAnchor, Strength: 80,
				UXFriction: types.FrictionLow, Version: "0.1.0",
			}},
		},
		{
			name: "empty version",
			m: &fakeMethod{md: types.MethodMetadata{
				ID: "no-version", Type: types.MethodTypeAnchor, Strength: 80,
				UXFriction: types.FrictionLow, Version: "",
			}},
		},
		{
			name: "unknown type",
			m: &fakeMethod{md: types.MethodMetadata{
				ID: "weird", Type: types.MethodType("mystery"), Strength: 50,
				UXFriction: types.FrictionLow, Version: "0.1.0",
			}},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			r := New()
			err := r.Register(tc.m)
			if err == nil {
				t.Fatalf("Register(%s): expected validation error, got nil", tc.name)
			}
			// Confirm it did NOT get added.
			if _, ok := r.Get(tc.m.Metadata().ID); ok {
				t.Errorf("invalid method was inserted despite validation failure")
			}
		})
	}
}

func TestGet_Unknown_ReturnsFalse(t *testing.T) {
	r := New()
	if _, ok := r.Get("does-not-exist"); ok {
		t.Errorf("Get(unknown) returned ok=true, want false")
	}
}

func TestList_ReturnsSortedSnapshot(t *testing.T) {
	r := New()
	// Register in deliberately unsorted order.
	for _, id := range []string{"zeta", "alpha", "mu", "beta"} {
		if err := r.Register(newAnchor(id, 80)); err != nil {
			t.Fatalf("Register(%q) failed: %v", id, err)
		}
	}

	got := r.List()
	wantIDs := []string{"alpha", "beta", "mu", "zeta"}
	if len(got) != len(wantIDs) {
		t.Fatalf("List length = %d, want %d", len(got), len(wantIDs))
	}
	for i, want := range wantIDs {
		if got[i].Metadata().ID != want {
			t.Errorf("List()[%d].ID = %q, want %q", i, got[i].Metadata().ID, want)
		}
	}

	// Snapshot independence: mutating returned slice must not affect future calls.
	got[0] = nil
	again := r.List()
	if again[0] == nil {
		t.Errorf("List returned aliased internal storage; snapshot was mutated externally")
	}
}

func TestListByType_FiltersCorrectly(t *testing.T) {
	r := New()
	for _, m := range []*fakeMethod{
		newAnchor("phone-liveness", 80),
		newAnchor("bank-link", 90),
		newSupp("email", 20),
		newSupp("sms", 30),
		newSupp("captcha", 10),
	} {
		if err := r.Register(m); err != nil {
			t.Fatalf("Register(%q) failed: %v", m.md.ID, err)
		}
	}

	anchors := r.ListByType(types.MethodTypeAnchor)
	if len(anchors) != 2 {
		t.Fatalf("ListByType(anchor) length = %d, want 2", len(anchors))
	}
	if anchors[0].Metadata().ID != "bank-link" || anchors[1].Metadata().ID != "phone-liveness" {
		t.Errorf("ListByType(anchor) order wrong: got [%q, %q]",
			anchors[0].Metadata().ID, anchors[1].Metadata().ID)
	}

	supps := r.ListByType(types.MethodTypeSupplementary)
	if len(supps) != 3 {
		t.Fatalf("ListByType(supplementary) length = %d, want 3", len(supps))
	}
	wantSuppIDs := []string{"captcha", "email", "sms"}
	for i, want := range wantSuppIDs {
		if supps[i].Metadata().ID != want {
			t.Errorf("supplementary[%d] = %q, want %q", i, supps[i].Metadata().ID, want)
		}
	}

	// Unknown type yields empty slice (not nil panic).
	unknown := r.ListByType(types.MethodType("nope"))
	if len(unknown) != 0 {
		t.Errorf("ListByType(unknown) length = %d, want 0", len(unknown))
	}
}

func TestRegister_ConcurrentSafe(t *testing.T) {
	r := New()
	const goroutines = 32
	const perGoroutine = 8

	var wg sync.WaitGroup
	wg.Add(goroutines)
	errs := make(chan error, goroutines*perGoroutine)

	for g := 0; g < goroutines; g++ {
		go func(g int) {
			defer wg.Done()
			for i := 0; i < perGoroutine; i++ {
				id := fmt.Sprintf("m-%d-%d", g, i)
				if err := r.Register(newAnchor(id, 80)); err != nil {
					errs <- err
				}
				// Concurrent reads during writes.
				_ = r.List()
				_, _ = r.Get(id)
			}
		}(g)
	}

	wg.Wait()
	close(errs)

	for err := range errs {
		t.Errorf("concurrent Register returned error: %v", err)
	}

	if got := len(r.List()); got != goroutines*perGoroutine {
		t.Errorf("after concurrent Register, List length = %d, want %d",
			got, goroutines*perGoroutine)
	}
}

func TestRegister_ConcurrentDuplicates_AtMostOneSucceeds(t *testing.T) {
	r := New()
	const goroutines = 16

	var wg sync.WaitGroup
	wg.Add(goroutines)
	successes := make(chan struct{}, goroutines)

	for g := 0; g < goroutines; g++ {
		go func() {
			defer wg.Done()
			if err := r.Register(newAnchor("contended", 80)); err == nil {
				successes <- struct{}{}
			}
		}()
	}
	wg.Wait()
	close(successes)

	count := 0
	for range successes {
		count++
	}
	if count != 1 {
		t.Errorf("contended Register succeeded %d times, want exactly 1", count)
	}
}

func TestDefaultRegistry_RegisterAndGet(t *testing.T) {
	// Use a unique ID so this test doesn't interact with anything that might
	// also register into Default during the test binary's lifetime.
	id := fmt.Sprintf("test-default-%d", time.Now().UnixNano())
	m := newAnchor(id, 70)

	if err := Register(m); err != nil {
		t.Fatalf("package-level Register failed: %v", err)
	}

	got, ok := Get(id)
	if !ok {
		t.Fatalf("package-level Get(%q): not found", id)
	}
	if got.Metadata().ID != id {
		t.Errorf("Get returned ID %q, want %q", got.Metadata().ID, id)
	}

	// It should also appear in List and ListByType.
	found := false
	for _, x := range List() {
		if x.Metadata().ID == id {
			found = true
			break
		}
	}
	if !found {
		t.Errorf("package-level List did not include %q", id)
	}

	foundTyped := false
	for _, x := range ListByType(types.MethodTypeAnchor) {
		if x.Metadata().ID == id {
			foundTyped = true
			break
		}
	}
	if !foundTyped {
		t.Errorf("package-level ListByType(anchor) did not include %q", id)
	}
}
