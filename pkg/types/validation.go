package types

import (
	"errors"
	"fmt"
)

// PolicyDSLVersion is the only Policy.Version this build currently accepts.
const PolicyDSLVersion = "1.0"

// W3C VC and Personhood JSON-LD context URLs that every PersonhoodCredential
// must declare.
const (
	W3CVCContext        = "https://www.w3.org/2018/credentials/v1"
	PersonhoodVCContext = "https://personhood.protocol/credentials/v1"
)

// Validate checks that a MethodMetadata is internally consistent:
//   - Strength is in [0, 100]
//   - Anchor methods have Strength >= 50
//   - Supplementary methods have Strength < 50
//   - ID, Type, and Version are non-empty
//
// Validate does NOT check semantic correctness of CostUSD or platform strings;
// those are issuer-policy concerns.
func (m MethodMetadata) Validate() error {
	if m.ID == "" {
		return errors.New("method metadata: id is required")
	}
	if m.Version == "" {
		return errors.New("method metadata: version is required")
	}
	if m.Strength < 0 || m.Strength > 100 {
		return fmt.Errorf("method metadata %q: strength %d out of range [0,100]", m.ID, m.Strength)
	}
	switch m.Type {
	case MethodTypeAnchor:
		if m.Strength < 50 {
			return fmt.Errorf("method metadata %q: anchor method must have strength >= 50, got %d", m.ID, m.Strength)
		}
	case MethodTypeSupplementary:
		if m.Strength >= 50 {
			return fmt.Errorf("method metadata %q: supplementary method must have strength < 50, got %d", m.ID, m.Strength)
		}
	default:
		return fmt.Errorf("method metadata %q: unknown type %q", m.ID, m.Type)
	}
	return nil
}

// Validate performs basic sanity checks on a Policy document:
//   - Version equals the supported PolicyDSLVersion
//   - PolicyID is non-empty
//   - Action is non-empty
//   - MinSupplementaryPoints >= 0
//   - MaxCredentialAgeSeconds >= 0
//   - MaxAnchorMethodAgeSeconds >= 0
//   - NullifierRequired implies a non-empty NullifierContextTag
//
// Validate does NOT verify that the named methods exist in any registry;
// that's the policy evaluator's job at runtime.
func (p Policy) Validate() error {
	if p.Version != PolicyDSLVersion {
		return fmt.Errorf("policy: unsupported version %q (want %q)", p.Version, PolicyDSLVersion)
	}
	if p.PolicyID == "" {
		return errors.New("policy: policy_id is required")
	}
	if p.Action == "" {
		return errors.New("policy: action is required")
	}
	if p.MinSupplementaryPoints < 0 {
		return fmt.Errorf("policy %q: min_supplementary_points must be >= 0, got %d", p.PolicyID, p.MinSupplementaryPoints)
	}
	if p.MaxCredentialAgeSeconds < 0 {
		return fmt.Errorf("policy %q: max_credential_age_seconds must be >= 0, got %d", p.PolicyID, p.MaxCredentialAgeSeconds)
	}
	if p.MaxAnchorMethodAgeSeconds < 0 {
		return fmt.Errorf("policy %q: max_anchor_method_age_seconds must be >= 0, got %d", p.PolicyID, p.MaxAnchorMethodAgeSeconds)
	}
	if p.NullifierRequired && p.NullifierContextTag == "" {
		return fmt.Errorf("policy %q: nullifier_context_tag is required when nullifier_required is true", p.PolicyID)
	}
	return nil
}

// RequiresNullifier reports whether this policy requires a derived nullifier
// at presentation time.
func (p Policy) RequiresNullifier() bool {
	return p.NullifierRequired
}

// Validate performs structural checks on a PersonhoodCredential:
//   - Both required JSON-LD @context entries are present (W3C VC first, then
//     Personhood)
//   - Issuer is non-empty
//   - IssuanceDate is strictly before ExpirationDate
//   - CredentialSubject.VerifiedMethods is non-empty
//   - If CredentialSubject.AnchorMethodID is set, it matches one of the
//     VerifiedMethods entries
//
// Validate does NOT verify the cryptographic Proof; that is the verifier's
// job.
func (vc PersonhoodCredential) Validate() error {
	if !containsString(vc.Context, W3CVCContext) {
		return fmt.Errorf("credential: missing required @context %q", W3CVCContext)
	}
	if !containsString(vc.Context, PersonhoodVCContext) {
		return fmt.Errorf("credential: missing required @context %q", PersonhoodVCContext)
	}
	if len(vc.Context) < 2 || vc.Context[0] != W3CVCContext {
		return fmt.Errorf("credential: @context[0] must be %q", W3CVCContext)
	}
	if vc.Issuer == "" {
		return errors.New("credential: issuer is required")
	}
	if vc.IssuanceDate.IsZero() {
		return errors.New("credential: issuanceDate is required")
	}
	if vc.ExpirationDate.IsZero() {
		return errors.New("credential: expirationDate is required")
	}
	if !vc.IssuanceDate.Before(vc.ExpirationDate) {
		return fmt.Errorf("credential: issuanceDate (%s) must be before expirationDate (%s)",
			vc.IssuanceDate.Format("2006-01-02T15:04:05Z07:00"),
			vc.ExpirationDate.Format("2006-01-02T15:04:05Z07:00"))
	}
	if len(vc.CredentialSubject.VerifiedMethods) == 0 {
		return errors.New("credential: credentialSubject.verifiedMethods must be non-empty")
	}
	if vc.CredentialSubject.AnchorMethodID != nil {
		anchor := *vc.CredentialSubject.AnchorMethodID
		found := false
		for _, vm := range vc.CredentialSubject.VerifiedMethods {
			if vm.MethodID == anchor {
				found = true
				break
			}
		}
		if !found {
			return fmt.Errorf("credential: anchorMethodId %q not present in verifiedMethods", anchor)
		}
	}
	return nil
}

// containsString reports whether a slice contains a given string.
func containsString(haystack []string, needle string) bool {
	for _, s := range haystack {
		if s == needle {
			return true
		}
	}
	return false
}
