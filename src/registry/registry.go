package registry

import (
	"errors"
	"fmt"
	"sort"
	"sync"

	"github.com/sagearbor/personhood/pkg/types"
)

// ErrDuplicateMethodID is returned by Register when a Method is registered
// under an ID that is already present in the Registry.
var ErrDuplicateMethodID = errors.New("registry: method id already registered")

// ErrNilMethod is returned by Register when the provided Method is nil.
var ErrNilMethod = errors.New("registry: cannot register nil method")

// Registry is a thread-safe in-process catalog of Method plugins, keyed by
// MethodMetadata.ID.
//
// All public methods on *Registry are safe for concurrent use by multiple
// goroutines. Reads (Get, List, ListByType) take a shared lock; Register takes
// an exclusive lock.
type Registry struct {
	mu      sync.RWMutex
	methods map[string]Method
}

// New constructs an empty Registry.
func New() *Registry {
	return &Registry{
		methods: make(map[string]Method),
	}
}

// Register adds m to the registry. It returns:
//   - ErrNilMethod if m is nil,
//   - the underlying validation error if m.Metadata().Validate() fails,
//   - ErrDuplicateMethodID wrapped with the offending ID if a method with the
//     same ID is already registered,
//   - nil on success.
//
// On any error, the registry is left unchanged.
func (r *Registry) Register(m Method) error {
	if m == nil {
		return ErrNilMethod
	}
	md := m.Metadata()
	if err := md.Validate(); err != nil {
		return fmt.Errorf("registry: invalid method metadata: %w", err)
	}

	r.mu.Lock()
	defer r.mu.Unlock()
	if _, exists := r.methods[md.ID]; exists {
		return fmt.Errorf("%w: %q", ErrDuplicateMethodID, md.ID)
	}
	r.methods[md.ID] = m
	return nil
}

// Get returns the Method registered under id, and a boolean reporting whether
// it was found.
func (r *Registry) Get(id string) (Method, bool) {
	r.mu.RLock()
	defer r.mu.RUnlock()
	m, ok := r.methods[id]
	return m, ok
}

// List returns a snapshot of all registered methods, sorted by ID. The
// returned slice is safe for the caller to retain and modify; the registry's
// internal storage is not aliased.
func (r *Registry) List() []Method {
	r.mu.RLock()
	defer r.mu.RUnlock()

	out := make([]Method, 0, len(r.methods))
	for _, m := range r.methods {
		out = append(out, m)
	}
	sort.Slice(out, func(i, j int) bool {
		return out[i].Metadata().ID < out[j].Metadata().ID
	})
	return out
}

// ListByType returns a snapshot of all registered methods whose
// MethodMetadata.Type equals t, sorted by ID.
func (r *Registry) ListByType(t types.MethodType) []Method {
	r.mu.RLock()
	defer r.mu.RUnlock()

	out := make([]Method, 0, len(r.methods))
	for _, m := range r.methods {
		if m.Metadata().Type == t {
			out = append(out, m)
		}
	}
	sort.Slice(out, func(i, j int) bool {
		return out[i].Metadata().ID < out[j].Metadata().ID
	})
	return out
}
