package policy

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"

	"github.com/sagearbor/personhood/pkg/types"
)

// DeriveNullifier produces a deterministic per-context nullifier from the
// holder's NullifierBinding commitment and the policy's context tag.
//
// v0.1 implementation: SHA-256(commitment || ":" || context_tag), hex-encoded.
// This is a placeholder; the production OpenLine ZK circuit derives a Pedersen
// commitment in BN254 that integrators verify via a SNARK. The stub here is
// non-malleable and stable, suitable for non-ZK integrators in v0.1.
//
// Returns an error if the binding's Commitment is empty, the binding is
// otherwise unpopulated (Scheme or Curve missing), or if contextTag is empty.
// The error semantics make accidental "all-zero" nullifier reuse impossible.
func DeriveNullifier(binding types.NullifierBinding, contextTag string) (string, error) {
	if binding.Commitment == "" {
		return "", fmt.Errorf("nullifier: binding commitment is empty")
	}
	if binding.Scheme == "" {
		return "", fmt.Errorf("nullifier: binding scheme is empty")
	}
	if binding.Curve == "" {
		return "", fmt.Errorf("nullifier: binding curve is empty")
	}
	if contextTag == "" {
		return "", fmt.Errorf("nullifier: context tag is empty")
	}

	h := sha256.New()
	h.Write([]byte(binding.Commitment))
	h.Write([]byte(":"))
	h.Write([]byte(contextTag))
	return hex.EncodeToString(h.Sum(nil)), nil
}
