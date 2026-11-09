// Package pq provides the ML-DSA-65 (FIPS 204) post-quantum companion
// signature for Personhood credentials: a credential.PQSigner for issuers
// and a credential.PQVerifier for verifiers. Experimental; see
// docs/POST_QUANTUM.md.
//
// It is its own Go module so that importers of src/credential do not pull
// in cloudflare/circl unless they opt in.
package pq

import (
	"context"
	"encoding/base64"
	"fmt"

	"github.com/cloudflare/circl/sign/mldsa/mldsa65"
	"github.com/sagearbor/personhood/pkg/types"
	"github.com/sagearbor/personhood/src/credential"
)

const (
	// ProofType is the PQProof.Type value.
	ProofType = "DataIntegrityProof"
	// Cryptosuite is the PQProof.Cryptosuite value: ML-DSA-65 over the
	// RFC 8785 (JCS) canonical credential without "proof". Personhood's own
	// name, not a registered cryptosuite.
	Cryptosuite = "mldsa65-jcs-personhood-v1"
	// SeedSize is the length of the seed ISSUER_MLDSA_SK holds.
	SeedSize = mldsa65.SeedSize
)

// signingContext is the FIPS 204 context string. It domain-separates
// credential signatures from anything else the same key might ever sign.
var signingContext = []byte("personhood-credential-v1")

// KeyFromSeed derives an ML-DSA-65 key pair from a 32-byte seed.
func KeyFromSeed(seed []byte) (*mldsa65.PublicKey, *mldsa65.PrivateKey, error) {
	if len(seed) != mldsa65.SeedSize {
		return nil, nil, fmt.Errorf("ML-DSA-65 seed must be %d bytes, got %d", mldsa65.SeedSize, len(seed))
	}
	var s [mldsa65.SeedSize]byte
	copy(s[:], seed)
	pub, priv := mldsa65.NewKeyFromSeed(&s)
	return pub, priv, nil
}

// Signer is a credential.PQSigner.
type Signer struct {
	Key *mldsa65.PrivateKey
	// VerificationMethod is the absolute URL of the public key in the
	// issuer's DID document (e.g. "did:web:host#key-pq-1").
	VerificationMethod string
}

// SignPQ signs signingInput. Signing is hedged (randomized), as FIPS 204
// recommends.
func (s Signer) SignPQ(signingInput []byte) (*types.PQProof, error) {
	sig := make([]byte, mldsa65.SignatureSize)
	if err := mldsa65.SignTo(s.Key, signingInput, signingContext, true, sig); err != nil {
		return nil, err
	}
	return &types.PQProof{
		Type:               ProofType,
		Cryptosuite:        Cryptosuite,
		VerificationMethod: s.VerificationMethod,
		ProofValue:         base64.RawURLEncoding.EncodeToString(sig),
	}, nil
}

// Resolver maps an issuer DID to its ML-DSA-65 public key.
type Resolver interface {
	ResolvePQ(ctx context.Context, did types.DID) (*mldsa65.PublicKey, error)
}

// MapResolver is an in-memory Resolver (pinned keys, tests).
type MapResolver map[types.DID]*mldsa65.PublicKey

// ResolvePQ returns the key for did, or an error if it is not present.
func (m MapResolver) ResolvePQ(_ context.Context, did types.DID) (*mldsa65.PublicKey, error) {
	pub, ok := m[did]
	if !ok || pub == nil {
		return nil, fmt.Errorf("pq.MapResolver: no key for DID %q", did)
	}
	return pub, nil
}

// Verifier is a credential.PQVerifier.
type Verifier struct {
	Resolver Resolver
}

// VerifyPQ checks proof against signingInput under the issuer's key.
func (v Verifier) VerifyPQ(ctx context.Context, issuer types.DID, proof *types.PQProof, signingInput []byte) error {
	if proof.Type != ProofType || proof.Cryptosuite != Cryptosuite {
		return fmt.Errorf("%w: unsupported pq proof %q/%q", credential.ErrProofUnsupported, proof.Type, proof.Cryptosuite)
	}
	sig, err := base64.RawURLEncoding.DecodeString(proof.ProofValue)
	if err != nil || len(sig) != mldsa65.SignatureSize {
		return fmt.Errorf("%w: pq proofValue is not a base64url %d-byte ML-DSA-65 signature", credential.ErrProofMalformed, mldsa65.SignatureSize)
	}
	if v.Resolver == nil {
		return fmt.Errorf("%w: no pq resolver", credential.ErrIssuerUnknown)
	}
	pub, err := v.Resolver.ResolvePQ(ctx, issuer)
	if err != nil {
		return fmt.Errorf("%w: %v", credential.ErrIssuerUnknown, err)
	}
	if !mldsa65.Verify(pub, signingInput, signingContext, sig) {
		return credential.ErrPQSignatureInvalid
	}
	return nil
}
