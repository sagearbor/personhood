// Package credential implements the W3C Verifiable Credential issuer and
// verifier for PersonhoodCredential. v0.1 of the format uses Ed25519
// signatures over a canonicalized JSON serialization (RFC 8785 / JCS) of the
// credential with its Proof field stripped.
//
// v0.1 simplifications (will revisit in v0.2):
//
//   - ProofValue is encoded as base64url (no padding) rather than the
//     multibase-base58-btc "z..." form mandated by the Ed25519Signature2020
//     spec. Migration to multibase is planned for v0.2 once we settle on a
//     dependency-free multibase implementation.
//   - DID resolution is limited to an in-memory MapResolver plus a stub
//     did:web resolver. Full did:web resolution (HTTPS fetch of
//     /.well-known/did.json + verificationMethod extraction) is also planned
//     for v0.2.
//   - JSON-LD context expansion / RDF canonicalization (URDNA2015) is NOT
//     performed. We canonicalize the JSON form directly via JCS, which is
//     deterministic and adequate for closed-world Personhood credentials
//     because both issuer and verifier agree on the field set up front.
package credential

import (
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"time"

	jcs "github.com/cyberphone/json-canonicalization/go/src/webpki.org/jsoncanonicalizer"
	"github.com/sagearbor/personhood/pkg/types"
)

// ProofTypeEd25519Signature2020 is the W3C-registered proof type string used
// by Personhood v0.1 credentials.
const ProofTypeEd25519Signature2020 = "Ed25519Signature2020"

// ProofPurposeAssertionMethod is the only proof purpose v0.1 supports for
// issued credentials.
const ProofPurposeAssertionMethod = "assertionMethod"

// CredentialTypeVerifiable and CredentialTypePersonhood are the JSON-LD type
// strings every PersonhoodCredential carries.
const (
	CredentialTypeVerifiable = "VerifiableCredential"
	CredentialTypePersonhood = "PersonhoodCredential"
)

// StatusList2021EntryType is the credentialStatus.type string for W3C Status
// List 2021 entries.
const StatusList2021EntryType = "StatusList2021Entry"

// Issuer signs PersonhoodCredentials with an Ed25519 key.
//
// One Issuer instance is bound to exactly one (DID, key) pair. The DID and
// VerificationMethod fields are copied verbatim into every credential's
// Issuer field and Proof.VerificationMethod field respectively, so callers
// must ensure the public half of PrivateKey is the one published under that
// VerificationMethod.
type Issuer struct {
	// IssuerDID is the issuer's DID (e.g. "did:web:personhood.example").
	IssuerDID types.DID

	// VerificationMethod is the absolute URL of the verification method
	// referencing the public key half of PrivateKey
	// (e.g. "did:web:personhood.example#key-1").
	VerificationMethod string

	// PrivateKey is the Ed25519 private key used to sign credentials.
	PrivateKey ed25519.PrivateKey

	// StatusListCredentialURL, if non-empty, is the default Status List 2021
	// credential URL embedded in CredentialStatus.StatusListCredential when
	// Issue is called with a non-nil statusListIndex.
	StatusListCredentialURL string
}

// NewIssuer constructs an Issuer. keyFragment is appended to did with "#" to
// form the VerificationMethod URL (e.g. NewIssuer("did:web:x", "key-1", ...)
// produces VerificationMethod "did:web:x#key-1"). statusListURL may be empty
// if the issuer does not publish a revocation list.
func NewIssuer(did types.DID, keyFragment string, priv ed25519.PrivateKey, statusListURL string) *Issuer {
	vm := string(did)
	if keyFragment != "" {
		vm = fmt.Sprintf("%s#%s", did, keyFragment)
	}
	return &Issuer{
		IssuerDID:               did,
		VerificationMethod:      vm,
		PrivateKey:              priv,
		StatusListCredentialURL: statusListURL,
	}
}

// Issue assembles, signs, and returns a PersonhoodCredential.
//
// The returned credential is fully populated:
//   - Context, Type, Issuer, IssuanceDate, ExpirationDate set
//   - CredentialSubject populated from the supplied holder, methods,
//     anchorMethodID, and nullifierBinding
//   - CredentialStatus populated iff statusListIndex is non-nil AND the
//     issuer has a non-empty StatusListCredentialURL
//   - Proof attached with an Ed25519 signature over the canonicalized
//     credential
//
// Issue runs cred.Validate() before signing; a structurally-invalid credential
// is rejected with the underlying validation error.
func (i *Issuer) Issue(
	holder types.DID,
	methods []types.VerifiedMethod,
	anchorMethodID *string,
	nullifierBinding *types.NullifierBinding,
	issuedAt time.Time,
	expiresAt time.Time,
	statusListIndex *int,
) (types.PersonhoodCredential, error) {
	if i == nil {
		return types.PersonhoodCredential{}, errors.New("issuer: nil receiver")
	}
	if len(i.PrivateKey) != ed25519.PrivateKeySize {
		return types.PersonhoodCredential{}, fmt.Errorf("issuer: private key must be %d bytes, got %d", ed25519.PrivateKeySize, len(i.PrivateKey))
	}
	if i.IssuerDID == "" {
		return types.PersonhoodCredential{}, errors.New("issuer: IssuerDID is required")
	}
	if i.VerificationMethod == "" {
		return types.PersonhoodCredential{}, errors.New("issuer: VerificationMethod is required")
	}
	if holder == "" {
		return types.PersonhoodCredential{}, errors.New("issuer: holder DID is required")
	}
	if len(methods) == 0 {
		return types.PersonhoodCredential{}, errors.New("issuer: at least one verified method is required")
	}

	// Build credential without proof.
	cred := types.PersonhoodCredential{
		Context: []string{
			types.W3CVCContext,
			types.PersonhoodVCContext,
		},
		ID:             credentialID(i.IssuerDID, holder, issuedAt),
		Type:           []string{CredentialTypeVerifiable, CredentialTypePersonhood},
		Issuer:         i.IssuerDID,
		IssuanceDate:   issuedAt.UTC(),
		ExpirationDate: expiresAt.UTC(),
		CredentialSubject: types.CredentialSubject{
			ID:               holder,
			VerifiedMethods:  methods,
			AnchorMethodID:   anchorMethodID,
			NullifierBinding: nullifierBinding,
		},
	}

	if statusListIndex != nil && i.StatusListCredentialURL != "" {
		cred.CredentialStatus = &types.CredentialStatus{
			ID:                   fmt.Sprintf("%s#%d", i.StatusListCredentialURL, *statusListIndex),
			Type:                 StatusList2021EntryType,
			StatusPurpose:        "revocation",
			StatusListIndex:      *statusListIndex,
			StatusListCredential: i.StatusListCredentialURL,
		}
	}

	if err := cred.Validate(); err != nil {
		return types.PersonhoodCredential{}, fmt.Errorf("issuer: credential failed validation: %w", err)
	}

	// Canonicalize the (proof-less) credential and sign.
	signingInput, err := canonicalizeWithoutProof(cred)
	if err != nil {
		return types.PersonhoodCredential{}, fmt.Errorf("issuer: canonicalize: %w", err)
	}
	sig := ed25519.Sign(i.PrivateKey, signingInput)

	cred.Proof = &types.Proof{
		Type:               ProofTypeEd25519Signature2020,
		Created:            issuedAt.UTC(),
		ProofPurpose:       ProofPurposeAssertionMethod,
		VerificationMethod: i.VerificationMethod,
		// v0.1: base64url (no padding). v0.2 will migrate to multibase-base58-btc ("z..." prefix).
		ProofValue: base64.RawURLEncoding.EncodeToString(sig),
	}
	return cred, nil
}

// credentialID returns a stable, deterministic ID URL for a credential.
// The format is opaque to verifiers; they treat it as an identifier only.
func credentialID(issuer, holder types.DID, issuedAt time.Time) string {
	// Use RFC3339Nano for sub-second uniqueness across rapid issuance.
	return fmt.Sprintf("urn:personhood:credential:%s:%s:%d",
		issuer, holder, issuedAt.UTC().UnixNano())
}

// canonicalizeWithoutProof returns the RFC 8785 (JCS) canonical JSON encoding
// of cred with its Proof field omitted. Both issuer (when signing) and
// verifier (when checking the signature) must produce byte-identical output
// from this function.
//
// Implementation: we round-trip the credential through encoding/json into a
// generic map, drop the "proof" key, then run JCS over the result. This is
// faster than constructing a parallel struct type for every credential
// variant and guarantees JCS sees exactly the fields json.Marshal would have
// emitted (e.g. omitempty pointer fields stay absent).
func canonicalizeWithoutProof(cred types.PersonhoodCredential) ([]byte, error) {
	raw, err := json.Marshal(cred)
	if err != nil {
		return nil, fmt.Errorf("marshal credential: %w", err)
	}
	var asMap map[string]any
	if err := json.Unmarshal(raw, &asMap); err != nil {
		return nil, fmt.Errorf("re-unmarshal credential: %w", err)
	}
	delete(asMap, "proof")
	stripped, err := json.Marshal(asMap)
	if err != nil {
		return nil, fmt.Errorf("re-marshal stripped credential: %w", err)
	}
	canonical, err := jcs.Transform(stripped)
	if err != nil {
		return nil, fmt.Errorf("jcs transform: %w", err)
	}
	return canonical, nil
}
