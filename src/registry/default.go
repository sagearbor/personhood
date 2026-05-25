package registry

import "github.com/sagearbor/personhood/pkg/types"

// Default is the package-level Registry that method packages should register
// themselves into from their init() functions.
//
// Trade-off: using a global registry is convenient for production wire-up
// (each method package's init() can self-register without the issuer having to
// know the list ahead of time), but it makes test isolation harder because
// state leaks across tests. Tests that need a clean slate should construct a
// fresh registry with New() and inject it via dependency injection rather than
// touching Default.
var Default = New()

// Register adds m to the Default registry. See (*Registry).Register.
func Register(m Method) error { return Default.Register(m) }

// Get looks up id in the Default registry. See (*Registry).Get.
func Get(id string) (Method, bool) { return Default.Get(id) }

// List returns a sorted snapshot of all methods in the Default registry.
// See (*Registry).List.
func List() []Method { return Default.List() }

// ListByType returns a sorted snapshot of methods of the given type from the
// Default registry. See (*Registry).ListByType.
func ListByType(t types.MethodType) []Method { return Default.ListByType(t) }
