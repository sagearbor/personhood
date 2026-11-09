package credential

import (
	"context"
	"errors"

	"github.com/sagearbor/personhood/pkg/types"
)

// Post-quantum companion signatures (experimental; see docs/POST_QUANTUM.md).
//
// The algorithm lives in the separate src/credential/pq module so that
// importers of this package (OpenLine among them) take on no new dependency.
// An Issuer with PQ set adds Proof.PQProof: a signature over the same
// canonical, proof-less signing input the Ed25519 signature covers. Nesting
// it inside Proof keeps it out of that signing input, so verifiers that
// predate it are unaffected. A Verifier with PQ set checks it when present,
// and with RequirePQ refuses credentials that lack it. RequirePQ is what
// defeats an attacker who can forge Ed25519: such an attacker can strip the
// PQ proof and re-sign.

// PQSigner produces the PQ proof for a credential's signing input.
type PQSigner interface {
	SignPQ(signingInput []byte) (*types.PQProof, error)
}

// PQVerifier checks a PQ proof against a credential's signing input under
// the issuer's PQ key. It returns an error wrapping ErrPQSignatureInvalid,
// ErrProofUnsupported, ErrProofMalformed or ErrIssuerUnknown on failure.
type PQVerifier interface {
	VerifyPQ(ctx context.Context, issuer types.DID, proof *types.PQProof, signingInput []byte) error
}

// SigningInput returns the bytes both proofs sign: the RFC 8785 (JCS)
// canonical credential without "proof". Exposed for PQVerifier
// implementations and their tests.
func SigningInput(cred types.PersonhoodCredential) ([]byte, error) {
	return canonicalizeWithoutProof(cred)
}

var (
	// ErrPQProofMissing means the verifier requires a PQ proof (RequirePQ)
	// and the credential has none.
	ErrPQProofMissing = errors.New("credential: post-quantum proof missing")
	// ErrPQSignatureInvalid means the post-quantum signature did not verify.
	ErrPQSignatureInvalid = errors.New("credential: post-quantum signature invalid")
)
