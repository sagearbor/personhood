// Package registry defines the in-process catalog of verification method
// plugins (the Method Registry) for the Personhood framework.
//
// A Method is a self-describing plugin that knows how to:
//   - publish its own MethodMetadata,
//   - decide whether it is applicable for a given UserContext,
//   - drive a challenge/response ceremony,
//   - report its own health.
//
// Each running issuer process holds a Registry instance (typically the
// package-level Default) into which every available method registers itself
// at startup. The issuer server and the verifier SDK then query the registry
// to discover the catalog and dispatch ceremonies.
package registry

import (
	"context"

	"github.com/sagearbor/personhood/pkg/types"
)

// Method is the plugin contract every verification method implements.
//
// Implementations MUST be safe for concurrent use: a single Method instance is
// shared across all in-flight ceremonies on the issuer.
type Method interface {
	// Metadata returns the method's static description. The returned value
	// MUST be stable for the lifetime of the process; callers may cache it.
	Metadata() types.MethodMetadata

	// IsAvailableForUser reports whether this method can run for the given
	// user environment. If it returns false, reason is a short human-readable
	// string explaining why (e.g. "no biometric capability detected"). The
	// reason should be safe to surface to end users.
	IsAvailableForUser(ctx types.UserContext) (available bool, reason string)

	// BeginCeremony starts a new ceremony for the given CeremonyContext and
	// returns the challenge the issuer should deliver to the client.
	//
	// The Go context.Context governs cancellation and deadlines for any I/O
	// the method performs (e.g. calling a liveness vendor).
	BeginCeremony(ctx context.Context, cc types.CeremonyContext) (types.ChallengeData, error)

	// CompleteCeremony validates the client's response and returns a
	// MethodResult. A non-nil error indicates an internal/transport failure;
	// a logical verification failure should be returned as a MethodResult with
	// Success=false and a populated ErrorReason.
	CompleteCeremony(ctx context.Context, cc types.CeremonyContext, resp types.ResponseData) (types.MethodResult, error)

	// HealthCheck probes any external dependencies the method relies on
	// (vendor APIs, message gateways, etc.) and returns nil if the method is
	// ready to serve traffic. The issuer's /healthz endpoint aggregates these.
	HealthCheck(ctx context.Context) error
}
