// Package types defines the canonical, cross-module type definitions for the
// Personhood proof-of-personhood framework (v0.1).
//
// Every other module (registry, credential, policy, methods, server, SDKs)
// depends on this package. It is stdlib-only by design so that downstream
// modules can choose their own serialization / transport stacks without
// inheriting heavyweight dependencies.
//
// Types are grouped into five sections:
//  1. Method metadata — describes a verification method plugin
//  2. Credential       — the W3C Verifiable Credential users hold
//  3. Policy           — integrator-declared verification requirements
//  4. Evaluation       — the result of evaluating a credential against a policy
//  5. Ceremony         — runtime types passed to a method plugin during a verification ceremony
package types

import "time"

// -----------------------------------------------------------------------------
// 1. Method metadata
// -----------------------------------------------------------------------------

// MethodType classifies a verification method as either an anchor (a strong,
// hard-to-Sybil signal) or a supplementary signal (a weak signal that on its
// own is not sufficient for high-stakes actions, but contributes to a points
// total).
type MethodType string

const (
	// MethodTypeAnchor identifies a strong verification method. Anchor methods
	// must have a Strength of at least 50. Examples: phone-camera-liveness,
	// bank-account-link.
	MethodTypeAnchor MethodType = "anchor"

	// MethodTypeSupplementary identifies a weak verification method that
	// contributes points but cannot satisfy an anchor requirement on its own.
	// Supplementary methods must have a Strength below 50. Examples: email,
	// SMS.
	MethodTypeSupplementary MethodType = "supplementary"
)

// FrictionLevel is a coarse measure of how much effort or UX friction a method
// imposes on the end user. Integrators may use this to choose between
// equivalent methods or to display warnings.
type FrictionLevel string

const (
	// FrictionLow indicates the method can be completed in seconds with no
	// special hardware (e.g. clicking a magic link in email).
	FrictionLow FrictionLevel = "low"

	// FrictionMed indicates the method requires a moderate effort such as
	// receiving an SMS or installing an app.
	FrictionMed FrictionLevel = "med"

	// FrictionHigh indicates the method requires significant effort such as
	// performing a liveness ceremony on camera or linking a bank account.
	FrictionHigh FrictionLevel = "high"
)

// MethodMetadata describes a single verification method plugin registered with
// the Personhood method registry. The registry, credential issuer, and policy
// evaluator all consume this metadata to make decisions about a credential.
type MethodMetadata struct {
	// ID is the stable, machine-readable identifier of the method
	// (e.g. "phone-liveness", "email", "sms"). It must be unique within an
	// issuer's registry.
	ID string `json:"id" yaml:"id"`

	// Type marks the method as either an anchor or supplementary.
	Type MethodType `json:"type" yaml:"type"`

	// Strength is the integer score (0-100) the method contributes towards a
	// policy's anchor or supplementary point requirement. Validators enforce
	// that anchor methods have Strength >= 50 and supplementary methods have
	// Strength < 50.
	Strength int `json:"strength" yaml:"strength"`

	// CostUSD is the per-verification cost paid by the issuer (e.g. SMS fees,
	// liveness vendor fees). Zero means free.
	CostUSD float64 `json:"cost_usd" yaml:"cost_usd"`

	// UXFriction estimates how much effort the method requires of the end
	// user.
	UXFriction FrictionLevel `json:"ux_friction" yaml:"ux_friction"`

	// PlatformRequirements lists platform capabilities the user's client must
	// have for this method to work (e.g. "ios>=14", "android>=10",
	// "biometric", "webauthn"). Empty means no special requirements.
	PlatformRequirements []string `json:"platform_requirements,omitempty" yaml:"platform_requirements,omitempty"`

	// FreshnessLifetime is the maximum duration after issuance during which a
	// verification of this method is considered fresh. Policies may also
	// override this with their own MaxAnchorMethodAgeSeconds.
	FreshnessLifetime time.Duration `json:"freshness_lifetime" yaml:"freshness_lifetime"`

	// Version is the semver of the method plugin implementation. Issuers
	// freeze the version onto each VerifiedMethod entry at issuance time.
	Version string `json:"version" yaml:"version"`
}

// -----------------------------------------------------------------------------
// 2. Credential (W3C VC)
// -----------------------------------------------------------------------------

// DID is a typed string alias for a Decentralized Identifier
// (e.g. "did:web:personhood.example", "did:key:z6Mk...").
type DID string

// VerifiedMethod describes a single completed method verification recorded on
// a credential. Issuers freeze the relevant metadata (notably Strength) at
// issuance time so that later changes to a method's metadata do not retroactively
// alter the meaning of an already-issued credential.
type VerifiedMethod struct {
	// MethodID is the method plugin identifier (matches MethodMetadata.ID).
	MethodID string `json:"method_id"`

	// Strength is the method's strength as of issuance. Frozen here so the
	// credential is self-describing without consulting the live registry.
	Strength int `json:"strength"`

	// VerifiedAt is the wall-clock time at which the method ceremony completed
	// successfully.
	VerifiedAt time.Time `json:"verified_at"`

	// FreshnessLifetime is the per-method freshness window, captured at
	// issuance from the method's metadata. The policy evaluator combines this
	// with VerifiedAt to decide whether the method is still fresh.
	FreshnessLifetime time.Duration `json:"freshness_lifetime"`

	// AttestationDigest is the SHA-256 digest (hex-encoded) of the underlying
	// attestation evidence (e.g. liveness vendor report, signed email-magic-link
	// proof). The raw evidence is NEVER stored or transmitted in the
	// credential; only the digest, so the issuer can audit later if needed.
	AttestationDigest string `json:"attestation_digest"`
}

// NullifierBinding describes a Pedersen commitment to the user's secret plus
// an issuer-specific salt. Holders prove knowledge of the secret in zero
// knowledge when claiming OpenLine Suffrage votes or Commons UBI, producing a
// per-context nullifier that prevents double-spending while preserving
// unlinkability across contexts.
//
// Optional on a generic credential; required for OpenLine Suffrage/Commons
// integrations.
type NullifierBinding struct {
	// Commitment is the hex-encoded Pedersen commitment value.
	Commitment string `json:"commitment"`

	// Curve names the elliptic curve used (e.g. "bn254").
	Curve string `json:"curve"`

	// Scheme identifies the commitment scheme and version
	// (e.g. "pedersen-v1").
	Scheme string `json:"scheme"`
}

// CredentialSubject is the W3C VC subject block: the holder-bound facts the
// credential asserts.
type CredentialSubject struct {
	// ID is the holder's DID. The credential is bound to this DID; presenting
	// the credential requires proving control of the corresponding key.
	ID DID `json:"id"`

	// VerifiedMethods lists every method ceremony the issuer recorded for this
	// holder. Must be non-empty.
	VerifiedMethods []VerifiedMethod `json:"verifiedMethods"`

	// AnchorMethodID identifies which of the VerifiedMethods is the anchor for
	// this credential. Nil means the credential has no anchor (only
	// supplementary methods); such credentials cannot satisfy policies with
	// AnchorRequired=true.
	AnchorMethodID *string `json:"anchorMethodId,omitempty"`

	// NullifierBinding is an optional Pedersen commitment enabling
	// privacy-preserving nullifier derivation. Required for OpenLine
	// integrations; ignored by integrators that do not need nullifiers.
	NullifierBinding *NullifierBinding `json:"nullifierBinding,omitempty"`
}

// CredentialStatus implements W3C Status List 2021 references for revocation.
// A verifier may dereference StatusListCredential and check the bit at
// StatusListIndex to determine whether the credential has been revoked.
type CredentialStatus struct {
	// ID is the URL that uniquely identifies this status entry.
	ID string `json:"id"`

	// Type is always "StatusList2021Entry" for this version.
	Type string `json:"type"`

	// StatusPurpose is the purpose of the status check, currently always
	// "revocation".
	StatusPurpose string `json:"statusPurpose"`

	// StatusListIndex is the zero-based bit index within the referenced status
	// list credential.
	StatusListIndex int `json:"statusListIndex"`

	// StatusListCredential is the URL of the JSON-LD status list credential
	// the verifier should fetch and inspect.
	StatusListCredential string `json:"statusListCredential"`
}

// Proof is the W3C VC cryptographic proof block. v0.1 uses
// Ed25519Signature2020.
type Proof struct {
	// Type identifies the proof suite, e.g. "Ed25519Signature2020".
	Type string `json:"type"`

	// Created is the wall-clock time the signature was produced.
	Created time.Time `json:"created"`

	// ProofPurpose declares what the signature attests to; for issued
	// credentials this is always "assertionMethod".
	ProofPurpose string `json:"proofPurpose"`

	// VerificationMethod is the absolute URL (typically issuer DID + key
	// fragment) of the public key used to verify the signature.
	VerificationMethod string `json:"verificationMethod"`

	// ProofValue is the multibase-encoded Ed25519 signature over the
	// canonicalized credential.
	ProofValue string `json:"proofValue"`
}

// PersonhoodCredential is the user-facing W3C Verifiable Credential issued by
// the Personhood framework. It is JSON-LD: when serialized, the field order
// and casing match the W3C VC data model.
type PersonhoodCredential struct {
	// Context is the JSON-LD @context array. The first entry is always
	// "https://www.w3.org/2018/credentials/v1" and the second is always
	// "https://personhood.protocol/credentials/v1".
	Context []string `json:"@context"`

	// ID is an absolute URL uniquely identifying this credential.
	ID string `json:"id"`

	// Type is the JSON-LD type array, typically
	// ["VerifiableCredential", "PersonhoodCredential"].
	Type []string `json:"type"`

	// Issuer is the DID of the issuer that signed this credential.
	Issuer DID `json:"issuer"`

	// IssuanceDate is when the issuer produced the credential.
	IssuanceDate time.Time `json:"issuanceDate"`

	// ExpirationDate is when the credential ceases to be valid. Must be after
	// IssuanceDate.
	ExpirationDate time.Time `json:"expirationDate"`

	// CredentialSubject contains the holder-bound assertions.
	CredentialSubject CredentialSubject `json:"credentialSubject"`

	// CredentialStatus is an optional reference enabling revocation checks.
	CredentialStatus *CredentialStatus `json:"credentialStatus,omitempty"`

	// Proof is the issuer's cryptographic signature. Set after signing; may be
	// nil on an unsigned credential under construction.
	Proof *Proof `json:"proof,omitempty"`
}

// -----------------------------------------------------------------------------
// 3. Policy
// -----------------------------------------------------------------------------

// Policy is an integrator-declared set of verification requirements that a
// PersonhoodCredential must satisfy for the policy's Action to be permitted.
// Policies are typically authored in YAML and unmarshalled into this struct.
type Policy struct {
	// Version is the policy DSL version this document conforms to
	// (currently "1.0").
	Version string `json:"version" yaml:"version"`

	// PolicyID is a stable identifier chosen by the integrator
	// (e.g. "ubi.claim.daily"). Used for audit logging.
	PolicyID string `json:"policy_id" yaml:"policy_id"`

	// Action is the integrator action this policy governs
	// (e.g. "vote.cast", "ubi.claim").
	Action string `json:"action" yaml:"action"`

	// AnchorRequired declares whether the credential must include at least one
	// anchor method.
	AnchorRequired bool `json:"anchor_required" yaml:"anchor_required"`

	// MinSupplementaryPoints is the minimum sum of supplementary method
	// Strengths required. Zero means no supplementary requirement.
	MinSupplementaryPoints int `json:"min_supplementary_points" yaml:"min_supplementary_points"`

	// AllowedMethods restricts which method IDs may count toward the
	// requirements. Nil or empty means all methods are allowed.
	AllowedMethods []string `json:"allowed_methods,omitempty" yaml:"allowed_methods,omitempty"`

	// BlockedMethods lists method IDs that must NOT count toward the
	// requirements (overrides AllowedMethods).
	BlockedMethods []string `json:"blocked_methods,omitempty" yaml:"blocked_methods,omitempty"`

	// MinStrengthPerMethod, if set, requires each named method to meet a
	// specified minimum strength (useful for tightening requirements above the
	// method's default).
	MinStrengthPerMethod map[string]int `json:"min_strength_per_method,omitempty" yaml:"min_strength_per_method,omitempty"`

	// MaxCredentialAgeSeconds is the maximum age (in seconds since
	// IssuanceDate) the credential may be. Zero means no limit.
	MaxCredentialAgeSeconds int `json:"max_credential_age_seconds" yaml:"max_credential_age_seconds"`

	// MaxAnchorMethodAgeSeconds is the maximum age (in seconds since
	// VerifiedAt) the anchor method verification may be. Zero means use the
	// method's own FreshnessLifetime.
	MaxAnchorMethodAgeSeconds int `json:"max_anchor_method_age_seconds" yaml:"max_anchor_method_age_seconds"`

	// RequireFreshAnchorProof requires the holder to perform a fresh
	// challenge-response proof (e.g. re-prove control of the anchor device) at
	// presentation time rather than relying on the recorded VerifiedAt
	// timestamp.
	RequireFreshAnchorProof bool `json:"require_fresh_anchor_proof" yaml:"require_fresh_anchor_proof"`

	// NullifierRequired requires the credential to include a NullifierBinding
	// and the holder to present a derived nullifier scoped by
	// NullifierContextTag.
	NullifierRequired bool `json:"nullifier_required" yaml:"nullifier_required"`

	// NullifierContextTag is the per-context tag bound to the derived
	// nullifier (e.g. "vote:2026-05-24:proposal-42"). Required when
	// NullifierRequired is true.
	NullifierContextTag string `json:"nullifier_context_tag,omitempty" yaml:"nullifier_context_tag,omitempty"`
}

// -----------------------------------------------------------------------------
// 4. Evaluation
// -----------------------------------------------------------------------------

// EvaluationCode is a stable, machine-readable code identifying the outcome of
// evaluating a credential against a policy.
type EvaluationCode string

const (
	// EvalOK indicates the credential satisfies the policy.
	EvalOK EvaluationCode = "ok"

	// EvalAnchorMissing indicates the policy required an anchor method but the
	// credential has none.
	EvalAnchorMissing EvaluationCode = "anchor_missing"

	// EvalInsufficientSupplementary indicates the sum of supplementary
	// strengths is below MinSupplementaryPoints.
	EvalInsufficientSupplementary EvaluationCode = "insufficient_supplementary"

	// EvalVCExpired indicates the credential is past its ExpirationDate or
	// MaxCredentialAgeSeconds.
	EvalVCExpired EvaluationCode = "vc_expired"

	// EvalAnchorMethodExpired indicates the anchor method's freshness window
	// has elapsed.
	EvalAnchorMethodExpired EvaluationCode = "anchor_method_expired"

	// EvalMethodBlocked indicates the credential relies on a method that is on
	// the policy's BlockedMethods list.
	EvalMethodBlocked EvaluationCode = "method_blocked"

	// EvalMethodNotAllowed indicates the credential relies on a method that is
	// not on the policy's AllowedMethods list (when set).
	EvalMethodNotAllowed EvaluationCode = "method_not_allowed"

	// EvalMethodStrengthInsufficient indicates a method's recorded strength is
	// below the policy's MinStrengthPerMethod entry for that method.
	EvalMethodStrengthInsufficient EvaluationCode = "method_strength_insufficient"

	// EvalFreshAnchorRequired indicates the policy required a fresh
	// challenge-response anchor proof and the presentation did not include
	// one.
	EvalFreshAnchorRequired EvaluationCode = "fresh_anchor_required"

	// EvalNullifierMissing indicates the policy required a nullifier and the
	// credential lacked a NullifierBinding or the presentation lacked a
	// derived nullifier.
	EvalNullifierMissing EvaluationCode = "nullifier_missing"

	// EvalSignatureInvalid indicates the credential's cryptographic signature
	// failed verification.
	EvalSignatureInvalid EvaluationCode = "signature_invalid"

	// EvalRevoked indicates the credential's status list entry shows it has
	// been revoked.
	EvalRevoked EvaluationCode = "revoked"

	// EvalUnknownIssuer indicates the credential's Issuer DID is not trusted
	// by this verifier.
	EvalUnknownIssuer EvaluationCode = "unknown_issuer"
)

// EvaluationResult is what the policy evaluator returns after checking a
// credential against a policy.
type EvaluationResult struct {
	// OK is true when the credential satisfies the policy. Equivalent to
	// Code == EvalOK.
	OK bool `json:"ok"`

	// Code identifies the outcome category.
	Code EvaluationCode `json:"code"`

	// Human is a human-readable explanation safe to surface to end users
	// (e.g. "Please complete a fresh face scan to vote.").
	Human string `json:"human"`

	// Details carries structured supporting information specific to the
	// outcome (e.g. {"have_points": 5, "need_points": 10}). May be nil.
	Details map[string]any `json:"details,omitempty"`

	// DerivedNullifier is the hex-encoded nullifier derived from the
	// credential's NullifierBinding and the policy's NullifierContextTag.
	// Present iff NullifierRequired is true and verification succeeded.
	DerivedNullifier *string `json:"derived_nullifier,omitempty"`
}

// -----------------------------------------------------------------------------
// 5. Ceremony (for method plugins)
// -----------------------------------------------------------------------------

// UserContext describes the end-user's client environment, passed into a
// method ceremony so the method can choose an appropriate flow (e.g. WebAuthn
// vs SMS).
type UserContext struct {
	// UserAgent is the raw User-Agent string from the client.
	UserAgent string `json:"user_agent"`

	// Platform is a normalized platform identifier such as "ios", "android",
	// or "web".
	Platform string `json:"platform"`

	// HasBiometric reports whether the client advertises a biometric
	// capability (FaceID, TouchID, Android BiometricPrompt, WebAuthn UV).
	HasBiometric bool `json:"has_biometric"`

	// CountryCode is the user's country in ISO 3166-1 alpha-2 form
	// (e.g. "US", "DE", "JP"). May be empty if undetermined.
	CountryCode string `json:"country_code"`
}

// CeremonyContext is the per-ceremony state the framework passes to a method
// plugin so it can correlate its challenge/response cycle with the issuer's
// session tracking.
type CeremonyContext struct {
	// SessionID is the issuer's session identifier for this ceremony.
	SessionID string `json:"session_id"`

	// UserID is the issuer-internal user identifier the ceremony attaches to.
	UserID string `json:"user_id"`

	// MethodID is the method plugin running the ceremony.
	MethodID string `json:"method_id"`

	// IssuerDID is the DID of the issuer running the ceremony.
	IssuerDID DID `json:"issuer_did"`

	// StartedAt is when the ceremony began.
	StartedAt time.Time `json:"started_at"`
}

// ChallengeData is the method-specific challenge the issuer sends to the
// client. The client must echo it back (typically signed or transformed) in a
// ResponseData.
type ChallengeData struct {
	// Type names the challenge sub-protocol
	// (e.g. "magic-link", "otp", "webauthn").
	Type string `json:"type"`

	// Payload carries the method-specific challenge fields.
	Payload map[string]any `json:"payload"`
}

// ResponseData is the client's response to a ChallengeData.
type ResponseData struct {
	// Type names the response sub-protocol (must match the corresponding
	// ChallengeData.Type).
	Type string `json:"type"`

	// Payload carries the method-specific response fields.
	Payload map[string]any `json:"payload"`
}

// MethodResult is what a method plugin returns to the credential builder once
// its ceremony completes (or fails).
type MethodResult struct {
	// Success is true if the ceremony completed and produced valid evidence.
	Success bool `json:"success"`

	// MethodID is the method plugin identifier (matches MethodMetadata.ID).
	MethodID string `json:"method_id"`

	// VerifiedAt is when the ceremony completed. Zero value if Success is
	// false.
	VerifiedAt time.Time `json:"verified_at"`

	// AttestationDigest is the SHA-256 digest (hex-encoded) of the underlying
	// attestation evidence. Empty if Success is false.
	AttestationDigest string `json:"attestation_digest"`

	// ErrorReason is a short machine-readable reason for failure. Set when
	// Success is false; empty otherwise.
	ErrorReason string `json:"error_reason,omitempty"`
}
