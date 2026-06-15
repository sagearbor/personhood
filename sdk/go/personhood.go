// Package personhood is the Go SDK for integrators — services that want to
// accept Personhood W3C Verifiable Credentials.
//
// It is a thin, dependency-light wrapper that composes the three pieces an
// integrator needs into one call:
//
//  1. issuer-signature verification (src/credential)
//  2. revocation status (W3C Status List 2021, src/credential)
//  3. policy evaluation + nullifier derivation (src/policy)
//
// Typical use:
//
//	v := personhood.NewVerifier(
//		personhood.TrustedIssuers(map[types.DID]ed25519.PublicKey{
//			"did:web:issuer.example": issuerPub,
//		}),
//	)
//	res, err := v.Verify(ctx, cred, policy)
//	if err != nil {
//		// transport / internal error (e.g. status-list fetch failed)
//	}
//	if !res.OK {
//		// res.Code, res.Human, res.Details tell the user what to fix
//	}
//	nullifier := res.Nullifier // non-empty iff policy.NullifierRequired
//
// The SDK deliberately does NOT handle end-user enrollment UI — that lives in
// the issuer server (src/server) and the end-user app (app/web).
package personhood

import (
	"context"
	"crypto/ed25519"
	"errors"
	"net/http"
	"time"

	"github.com/sagearbor/personhood/pkg/types"
	"github.com/sagearbor/personhood/src/credential"
	"github.com/sagearbor/personhood/src/policy"
)

// Result is the outcome of verifying a credential against a policy. It mirrors
// types.EvaluationResult but flattens the derived nullifier into a plain string
// for caller convenience.
type Result struct {
	// OK is true iff the credential passed signature verification, is not
	// revoked, and satisfies the policy. Equivalent to Code == types.EvalOK.
	OK bool

	// Code is the stable machine-readable outcome code. On a non-OK result it
	// tells the integrator (and, via Human, the end user) what failed.
	Code types.EvaluationCode

	// Human is an end-user-safe explanation of the outcome.
	Human string

	// Details carries structured supporting information specific to the
	// outcome (e.g. {"have_points": 5, "need_points": 10}). May be nil.
	Details map[string]any

	// Nullifier is the hex-encoded per-context nullifier derived from the
	// credential's NullifierBinding and the policy's NullifierContextTag. It is
	// non-empty iff policy.NullifierRequired is true and the result is OK.
	//
	// Integrators that want unlinkable, one-action-per-human semantics (e.g.
	// OpenLine Suffrage votes, Commons UBI claims) record this value in a
	// per-context spent-nullifier set.
	Nullifier string
}

// Verifier verifies presented credentials against integrator policies. It is
// safe for concurrent use; construct one with NewVerifier and reuse it.
type Verifier struct {
	resolver   credential.DIDResolver
	httpClient *http.Client
	now        func() time.Time
	skipRevoke bool
}

// Option customizes a Verifier.
type Option func(*Verifier)

// WithHTTPClient sets the HTTP client used for Status List 2021 revocation
// fetches (and any future I/O). Defaults to http.DefaultClient. Pass a client
// with a sane timeout in production.
func WithHTTPClient(hc *http.Client) Option {
	return func(v *Verifier) {
		if hc != nil {
			v.httpClient = hc
		}
	}
}

// WithClock overrides the time source used for expiry and freshness checks.
// Defaults to time.Now. Useful for deterministic tests and for pinning
// verification time.
func WithClock(now func() time.Time) Option {
	return func(v *Verifier) {
		if now != nil {
			v.now = now
		}
	}
}

// WithoutRevocationCheck disables the Status List 2021 fetch. Use this only
// when revocation is handled out of band, or in offline/air-gapped verifiers
// that cannot reach the issuer's status list. When disabled, a credential that
// has in fact been revoked will still pass — handle that risk explicitly.
func WithoutRevocationCheck() Option {
	return func(v *Verifier) { v.skipRevoke = true }
}

// NewVerifier constructs a Verifier. The resolver supplies the Ed25519 public
// key for each trusted issuer DID; use TrustedIssuers for the common
// allow-list case, or pass any credential.DIDResolver (e.g. a did:web
// resolver) for dynamic resolution.
func NewVerifier(resolver credential.DIDResolver, opts ...Option) *Verifier {
	v := &Verifier{
		resolver:   resolver,
		httpClient: http.DefaultClient,
		now:        time.Now,
	}
	for _, opt := range opts {
		opt(v)
	}
	return v
}

// TrustedIssuers builds a DIDResolver from an explicit allow-list mapping each
// trusted issuer DID to its Ed25519 public key. A credential whose Issuer is
// not in the map fails verification with types.EvalUnknownIssuer.
func TrustedIssuers(keys map[types.DID]ed25519.PublicKey) credential.DIDResolver {
	return credential.MapResolver(keys)
}

// ErrResolverRequired is returned by Verify when the Verifier was constructed
// without a DID resolver.
var ErrResolverRequired = errors.New("personhood: a DID resolver (trusted issuers) is required")

// Verify runs the full integrator check against cred:
//
//  1. issuer signature + structural validity
//  2. revocation (unless disabled via WithoutRevocationCheck)
//  3. policy evaluation + nullifier derivation
//
// The returned error is non-nil only for transport/internal failures the
// caller cannot attribute to the credential itself — most importantly a
// revocation-list fetch that failed. A credential that is simply invalid,
// revoked, or non-compliant yields (Result{OK:false, ...}, nil); inspect
// Result.Code. This split lets callers distinguish "the user needs to fix
// something" (nil error, !OK) from "we couldn't complete the check" (error).
func (v *Verifier) Verify(ctx context.Context, cred types.PersonhoodCredential, pol types.Policy) (Result, error) {
	if v == nil || v.resolver == nil {
		return Result{}, ErrResolverRequired
	}

	// 1. Signature + structure. Map credential errors to evaluation codes so
	// the caller sees one consistent code space.
	cv := &credential.Verifier{Resolver: v.resolver, HTTPClient: v.httpClient}
	if err := cv.Verify(ctx, cred); err != nil {
		switch {
		case errors.Is(err, credential.ErrIssuerUnknown):
			return deny(types.EvalUnknownIssuer,
				"This credential was issued by a party this service does not trust.",
				map[string]any{"reason": err.Error()}), nil
		case errors.Is(err, credential.ErrSignatureInvalid),
			errors.Is(err, credential.ErrStructuralInvalid),
			errors.Is(err, credential.ErrProofMissing),
			errors.Is(err, credential.ErrProofUnsupported),
			errors.Is(err, credential.ErrProofMalformed):
			return deny(types.EvalSignatureInvalid,
				"This credential could not be verified. Please re-verify.",
				map[string]any{"reason": err.Error()}), nil
		default:
			// Unexpected (e.g. a future resolver returning a non-sentinel
			// transport error). Surface as an error, not a silent deny.
			return Result{}, err
		}
	}

	// 2. Revocation.
	if !v.skipRevoke {
		revoked, err := credential.IsRevoked(ctx, v.httpClient, cred)
		if err != nil {
			return Result{}, err
		}
		if revoked {
			return deny(types.EvalRevoked,
				"This credential has been revoked. Please re-verify.", nil), nil
		}
	}

	// 3. Policy evaluation (pure; no I/O) + nullifier derivation.
	er := policy.Evaluate(cred, pol, v.now())
	res := Result{
		OK:      er.OK,
		Code:    er.Code,
		Human:   er.Human,
		Details: er.Details,
	}
	if er.DerivedNullifier != nil {
		res.Nullifier = *er.DerivedNullifier
	}
	return res, nil
}

// deny builds a non-OK Result.
func deny(code types.EvaluationCode, human string, details map[string]any) Result {
	return Result{OK: false, Code: code, Human: human, Details: details}
}
