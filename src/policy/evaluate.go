package policy

import (
	"fmt"
	"time"

	"github.com/sagearbor/personhood/pkg/types"
)

// supplementaryStrengthCeiling is the threshold below which a method's
// Strength is treated as supplementary for the purposes of point-summing.
// Anchor methods (Strength >= 50) never count toward supplementary points.
const supplementaryStrengthCeiling = 50

// Evaluate checks the credential against the policy and returns a structured
// result. The current time `now` is passed in (rather than calling time.Now())
// so tests can be deterministic and integrators can pin verification time.
//
// Checks are performed in a deliberate order so that the most user-actionable
// failure (e.g. "anchor missing") surfaces before less actionable ones.
// Evaluate performs NO I/O: no DID resolution, no signature verification, no
// status-list fetch. The caller is responsible for having already verified
// signatures and revocation status before calling Evaluate.
func Evaluate(cred types.PersonhoodCredential, policy types.Policy, now time.Time) types.EvaluationResult {
	// 1. Structural validity. The structure check is a stand-in for signature
	// verification; the real signature check lives in src/credential and is
	// expected to run *before* Evaluate. We surface a structural failure as
	// EvalSignatureInvalid because, from the integrator's POV, both are "this
	// credential is not a presentable VC."
	if err := cred.Validate(); err != nil {
		return result(false, types.EvalSignatureInvalid,
			"This credential is not a valid Personhood credential.",
			map[string]any{"reason": err.Error()}, nil)
	}

	// 2. Credential-age check (max_credential_age_seconds).
	if policy.MaxCredentialAgeSeconds > 0 {
		age := now.Sub(cred.IssuanceDate)
		if age > time.Duration(policy.MaxCredentialAgeSeconds)*time.Second {
			return result(false, types.EvalVCExpired,
				"Your verification is too old for this action. Please re-verify.",
				map[string]any{
					"age_seconds":     int(age.Seconds()),
					"max_age_seconds": policy.MaxCredentialAgeSeconds,
				}, nil)
		}
	}

	// 3. Hard expiration check.
	if now.After(cred.ExpirationDate) {
		return result(false, types.EvalVCExpired,
			"Your verification has expired. Please re-verify.",
			map[string]any{
				"expiration_date": cred.ExpirationDate.Format(time.RFC3339),
			}, nil)
	}

	// 4. Anchor presence (anchor_required).
	if policy.AnchorRequired && cred.CredentialSubject.AnchorMethodID == nil {
		return result(false, types.EvalAnchorMissing,
			"This action requires a stronger verification method (an anchor). Please add one.",
			nil, nil)
	}

	// 5. If an anchor is present, check anchor method freshness.
	if cred.CredentialSubject.AnchorMethodID != nil {
		anchorID := *cred.CredentialSubject.AnchorMethodID
		var anchorMethod *types.VerifiedMethod
		for i := range cred.CredentialSubject.VerifiedMethods {
			if cred.CredentialSubject.VerifiedMethods[i].MethodID == anchorID {
				anchorMethod = &cred.CredentialSubject.VerifiedMethods[i]
				break
			}
		}
		// cred.Validate() already guarantees the anchor is in VerifiedMethods,
		// but be defensive — a future change in Validate must not silently
		// turn this into a nil-deref.
		if anchorMethod == nil {
			return result(false, types.EvalAnchorMissing,
				"The credential's anchor method is not present in verifiedMethods.",
				map[string]any{"anchor_method_id": anchorID}, nil)
		}

		// Pick the freshness window: explicit policy override wins; else use
		// the per-method FreshnessLifetime that was frozen at issuance time.
		var window time.Duration
		if policy.MaxAnchorMethodAgeSeconds > 0 {
			window = time.Duration(policy.MaxAnchorMethodAgeSeconds) * time.Second
		} else {
			window = anchorMethod.FreshnessLifetime
		}
		// A zero window means "freshness not enforced" — skip the check.
		if window > 0 && now.Sub(anchorMethod.VerifiedAt) > window {
			return result(false, types.EvalAnchorMethodExpired,
				"Your anchor verification is too old. Please re-verify the anchor method.",
				map[string]any{
					"anchor_method_id": anchorID,
					"verified_at":      anchorMethod.VerifiedAt.Format(time.RFC3339),
					"window_seconds":   int(window.Seconds()),
				}, nil)
		}
	}

	// 6. Per-method allow/block/strength checks.
	allowedSet := stringSet(policy.AllowedMethods)
	blockedSet := stringSet(policy.BlockedMethods)
	for _, vm := range cred.CredentialSubject.VerifiedMethods {
		// Blocked overrides allowed: a method on both lists is blocked.
		if _, blocked := blockedSet[vm.MethodID]; blocked {
			return result(false, types.EvalMethodBlocked,
				"Your credential relies on a verification method that is not accepted for this action.",
				map[string]any{"method_id": vm.MethodID}, nil)
		}
		if len(allowedSet) > 0 {
			if _, ok := allowedSet[vm.MethodID]; !ok {
				return result(false, types.EvalMethodNotAllowed,
					"Your credential includes a verification method that is not accepted for this action.",
					map[string]any{"method_id": vm.MethodID}, nil)
			}
		}
		if policy.MinStrengthPerMethod != nil {
			if minStrength, ok := policy.MinStrengthPerMethod[vm.MethodID]; ok {
				if vm.Strength < minStrength {
					return result(false, types.EvalMethodStrengthInsufficient,
						"One of your verification methods is below the required strength for this action.",
						map[string]any{
							"method_id":      vm.MethodID,
							"have_strength":  vm.Strength,
							"need_strength":  minStrength,
						}, nil)
				}
			}
		}
	}

	// 7. Supplementary points: sum Strength for non-anchor methods (Strength
	// < 50) that are still fresh per their own FreshnessLifetime.
	suppPoints := 0
	for _, vm := range cred.CredentialSubject.VerifiedMethods {
		if vm.Strength >= supplementaryStrengthCeiling {
			continue
		}
		// Drop expired-by-own-lifetime supplementary methods.
		if vm.FreshnessLifetime > 0 && now.Sub(vm.VerifiedAt) > vm.FreshnessLifetime {
			continue
		}
		suppPoints += vm.Strength
	}
	if suppPoints < policy.MinSupplementaryPoints {
		return result(false, types.EvalInsufficientSupplementary,
			"Please complete additional verification methods before continuing.",
			map[string]any{
				"have_points": suppPoints,
				"need_points": policy.MinSupplementaryPoints,
			}, nil)
	}

	// 8. Nullifier binding presence (nullifier_required).
	if policy.NullifierRequired && cred.CredentialSubject.NullifierBinding == nil {
		return result(false, types.EvalNullifierMissing,
			"Your credential is missing the privacy binding needed for this action.",
			nil, nil)
	}

	// 9. Fresh-anchor-proof signaling. For v0.1, we return EvalOK but include
	// a Details flag so the caller knows to demand a fresh proof at
	// presentation time. Real handling lives in the presentation flow.
	details := map[string]any{
		"supplementary_points": suppPoints,
	}
	if policy.RequireFreshAnchorProof {
		details["fresh_anchor_required"] = true
	}

	// 10. Compute derived nullifier when required.
	var derivedPtr *string
	if policy.NullifierRequired {
		// At this point NullifierBinding is non-nil and NullifierContextTag is
		// non-empty (Policy.Validate enforces the latter when
		// NullifierRequired is true).
		derived, err := DeriveNullifier(*cred.CredentialSubject.NullifierBinding, policy.NullifierContextTag)
		if err != nil {
			return result(false, types.EvalNullifierMissing,
				"Your credential's privacy binding is malformed.",
				map[string]any{"reason": err.Error()}, nil)
		}
		derivedPtr = &derived
		details["derived_nullifier_present"] = true
	}

	human := "Verified."
	if policy.RequireFreshAnchorProof {
		human = "Verified — a fresh anchor proof is still required at presentation time."
	}
	return result(true, types.EvalOK, human, details, derivedPtr)
}

// result is a small helper that builds an EvaluationResult and keeps
// `OK == (code == EvalOK)` invariant in one place.
func result(ok bool, code types.EvaluationCode, human string, details map[string]any, derived *string) types.EvaluationResult {
	if ok && code != types.EvalOK {
		// Programmer error: defend against future edits that set ok=true with
		// a non-OK code. Surface it as a signature-invalid result rather than
		// silently lying.
		return types.EvaluationResult{
			OK:    false,
			Code:  types.EvalSignatureInvalid,
			Human: fmt.Sprintf("internal: inconsistent evaluation (ok=true, code=%s)", code),
		}
	}
	return types.EvaluationResult{
		OK:               ok,
		Code:             code,
		Human:            human,
		Details:          details,
		DerivedNullifier: derived,
	}
}

// stringSet builds a set-like map for O(1) membership checks. Returns nil if
// the slice is empty so callers can use `len(set) > 0` for the
// "policy did not declare this list" branch.
func stringSet(xs []string) map[string]struct{} {
	if len(xs) == 0 {
		return nil
	}
	out := make(map[string]struct{}, len(xs))
	for _, x := range xs {
		out[x] = struct{}{}
	}
	return out
}
