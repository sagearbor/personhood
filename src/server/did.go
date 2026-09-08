package server

import (
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"net/url"
	"strings"

	"github.com/sagearbor/personhood/pkg/types"
)

// IssuerDIDFromPublicURL derives the issuer's did:web identifier from the
// server's PublicURL config. The host portion of the URL becomes the DID's
// host segment per the did:web spec (https://w3c-ccg.github.io/did-method-web/).
//
// Path-form did:web (e.g. did:web:host:user:alice) is not supported in v0.1.
// Localhost (or any host the resolver cannot fetch over HTTPS) yields a DID
// that is only usable with an in-memory MapResolver — fine for dev and tests.
func IssuerDIDFromPublicURL(publicURL string) (types.DID, error) {
	u, err := url.Parse(publicURL)
	if err != nil {
		return "", fmt.Errorf("IssuerDIDFromPublicURL: parse %q: %w", publicURL, err)
	}
	host := u.Host
	if host == "" {
		return "", fmt.Errorf("IssuerDIDFromPublicURL: %q has no host", publicURL)
	}
	// The did:web spec percent-encodes the colon-port separator as %3A.
	host = strings.ReplaceAll(host, ":", "%3A")
	return types.DID(fmt.Sprintf("did:web:%s", host)), nil
}

// IssuerVerificationMethod returns the absolute verification method URL the
// server publishes its key under in /.well-known/did.json.
//
// keyFragment is appended to the issuer DID with "#". Use "key-1" for v0.1.
func IssuerVerificationMethod(issuerDID types.DID, keyFragment string) string {
	if keyFragment == "" {
		keyFragment = "key-1"
	}
	return fmt.Sprintf("%s#%s", issuerDID, keyFragment)
}

// ed25519MulticodecPrefix is the two-byte unsigned-varint encoding of the
// multicodec code 0xed ("ed25519-pub"), per the did:key spec
// (https://w3c-ccg.github.io/did-method-key/#ed25519-x25519). This is the
// prefix that goes in front of the raw 32-byte Ed25519 public key before
// base58btc-encoding.
var ed25519MulticodecPrefix = []byte{0xed, 0x01}

// DIDKeyFromEd25519 encodes an Ed25519 public key as a did:key identifier:
// "did:key:z" + base58btc(multicodec-prefix || raw public key).
//
// did:key is self-certifying — the DID itself is a full encoding of the
// public key, so no registry or resolver fetch is needed to recover it (see
// Ed25519FromDIDKey). This is the real holder identifier the v0.2 web app
// produces once it generates its own Ed25519 keypair; v0.1's placeholder
// did:personhood:holder:<sha256> (still used when no client key is supplied,
// e.g. the round-1 email-only flow) remains available as a fallback.
func DIDKeyFromEd25519(pub ed25519.PublicKey) (types.DID, error) {
	if len(pub) != ed25519.PublicKeySize {
		return "", fmt.Errorf("DIDKeyFromEd25519: public key must be %d bytes, got %d", ed25519.PublicKeySize, len(pub))
	}
	data := make([]byte, 0, len(ed25519MulticodecPrefix)+len(pub))
	data = append(data, ed25519MulticodecPrefix...)
	data = append(data, pub...)
	return types.DID(fmt.Sprintf("did:key:z%s", base58Encode(data))), nil
}

// Ed25519FromDIDKey decodes a did:key identifier produced by
// DIDKeyFromEd25519 back into the raw Ed25519 public key. It rejects any DID
// that is not a "did:key:z..." Ed25519 identifier.
func Ed25519FromDIDKey(did types.DID) (ed25519.PublicKey, error) {
	const prefix = "did:key:z"
	s := string(did)
	if !strings.HasPrefix(s, prefix) {
		return nil, fmt.Errorf("Ed25519FromDIDKey: %q is not a did:key:z... identifier", did)
	}
	data, err := base58Decode(strings.TrimPrefix(s, prefix))
	if err != nil {
		return nil, fmt.Errorf("Ed25519FromDIDKey: %w", err)
	}
	if len(data) != len(ed25519MulticodecPrefix)+ed25519.PublicKeySize {
		return nil, fmt.Errorf("Ed25519FromDIDKey: decoded length %d does not match ed25519-pub multicodec + key", len(data))
	}
	if data[0] != ed25519MulticodecPrefix[0] || data[1] != ed25519MulticodecPrefix[1] {
		return nil, fmt.Errorf("Ed25519FromDIDKey: unexpected multicodec prefix %x, want %x", data[:2], ed25519MulticodecPrefix)
	}
	return ed25519.PublicKey(data[2:]), nil
}

// HolderDIDForSession returns the holder DID the issued credential will be
// bound to.
//
// If `holderPublicKey` is a valid 32-byte Ed25519 public key (the web app
// generates one and sends it in POST /enrollment/start), the holder DID is a
// real, self-certifying did:key derived from it via DIDKeyFromEd25519 — the
// same key always maps to the same DID, independent of the session.
//
// Otherwise this falls back to the v0.1 placeholder
// did:personhood:holder:<sha256(sessionID)>, used when a client does not (or
// cannot yet) supply a holder key — e.g. the round-1 email-only flow.
// Credentials issued against a placeholder DID carry no NullifierBinding
// (see NullifierBindingForHolder), so policies with nullifier_required fail
// closed rather than silently accepting an unbound credential.
func HolderDIDForSession(sessionID string, holderPublicKey ed25519.PublicKey) types.DID {
	if len(holderPublicKey) == ed25519.PublicKeySize {
		did, err := DIDKeyFromEd25519(holderPublicKey)
		if err == nil {
			return did
		}
		// Unreachable given the length check above, but fall through to the
		// placeholder rather than panicking on a malformed key.
	}
	h := sha256.New()
	h.Write([]byte(sessionID))
	digest := h.Sum(nil)
	return types.DID(fmt.Sprintf("did:personhood:holder:%s", hex.EncodeToString(digest)))
}

// NullifierBindingForHolder derives a v0.1 stub NullifierBinding from a
// holder's Ed25519 public key, or nil if no valid key was supplied.
//
// docs/03-credential-format.md specifies the production scheme as a Pedersen
// commitment over BN254 to a holder-held secret scalar, verified in
// zero-knowledge (OpenLine's Circom/Poseidon stack). Generating and handing
// back such a secret is out of scope here; consistent with the existing
// src/policy/nullifier.go "SHA-256 stub for v0.1" (see its doc comment), this
// produces a deterministic, non-malleable stand-in commitment:
//
//	commitment = SHA-256("personhood-nullifier-binding-v1" || holderPubKey)
//
// Because the commitment is a pure function of the holder's public key, the
// same holder consistently derives the same commitment (and therefore the
// same per-context nullifier via policy.DeriveNullifier) across separate
// credential issuances — the anti-double-claim property NullifierBinding
// exists for. Curve/Scheme are set to the values the eventual real Pedersen
// implementation will use ("bn254"/"pedersen-v1") so integrators do not need
// to change their field-matching logic when v0.2 lands.
func NullifierBindingForHolder(holderPublicKey ed25519.PublicKey) *types.NullifierBinding {
	if len(holderPublicKey) != ed25519.PublicKeySize {
		return nil
	}
	h := sha256.New()
	h.Write([]byte("personhood-nullifier-binding-v1"))
	h.Write(holderPublicKey)
	return &types.NullifierBinding{
		Commitment: hex.EncodeToString(h.Sum(nil)),
		Curve:      "bn254",
		Scheme:     "pedersen-v1",
	}
}

// NullifierBindingForBiometricCommitment derives a NullifierBinding from the
// fuzzy-extractor-selfie anchor's AttestationDigest (a hex-encoded
// fuzzyextractorselfie.Commitment — see that package's doc comment), or nil
// if commitmentHex is empty.
//
// This exists alongside NullifierBindingForHolder (device-keypair-derived)
// because a device keypair is not what STATUS.md checklist #10a's airdrop-
// test anchor needs to bind a nullifier to: a holder can generate an
// unlimited number of fresh Ed25519 keypairs, each yielding a distinct
// NullifierBindingForHolder commitment, so a device-key-only nullifier
// cannot by itself stop one person from claiming an OpenLine UBI payout
// (or vote) more than once. fuzzy-extractor-selfie's AttestationDigest, by
// contrast, is derived from the person's BIOMETRIC (see
// fuzzy-extractor-selfie/extractor.go): the accumulator (Sybil check)
// already guarantees that digest is stable across separate sessions for the
// same person and unique across distinct people, independent of which
// device key they used. Binding the nullifier to it instead closes the
// device-keypair-regeneration loophole for holders anchored this way.
//
// handleIssueCredential (see handlers.go) prefers this over
// NullifierBindingForHolder whenever the session's verified methods include
// a successful fuzzy-extractor-selfie result — see
// biometricCommitmentFromVerifiedMethods.
//
// Same v0.1 stub-crypto caveat as NullifierBindingForHolder: a real Pedersen
// commitment over BN254 belongs here eventually; SHA-256 over a domain tag
// plus the commitment hex is a deterministic, non-malleable stand-in that
// needs no new dependency.
func NullifierBindingForBiometricCommitment(commitmentHex string) *types.NullifierBinding {
	if commitmentHex == "" {
		return nil
	}
	h := sha256.New()
	h.Write([]byte("personhood-nullifier-binding-biometric-v1"))
	h.Write([]byte(commitmentHex))
	return &types.NullifierBinding{
		Commitment: hex.EncodeToString(h.Sum(nil)),
		Curve:      "bn254",
		Scheme:     "pedersen-v1",
	}
}

// biometricCommitmentFromVerifiedMethods scans verifiedMethods for a
// successful fuzzy-extractor-selfie result and returns its AttestationDigest
// (empty string if none is present). Takes methodID as a parameter (rather
// than importing the fuzzy-extractor-selfie package's MethodID constant
// directly) to keep did.go independent of any specific method package;
// server.go's BuildDependencies / handlers.go's handleIssueCredential pass
// fuzzyextractorselfie.MethodID.
func biometricCommitmentFromVerifiedMethods(verifiedMethods []types.VerifiedMethod, methodID string) string {
	for _, vm := range verifiedMethods {
		if vm.MethodID == methodID && vm.AttestationDigest != "" {
			return vm.AttestationDigest
		}
	}
	return ""
}

// IssuerDIDDocument is the minimal subset of a W3C DID document the issuer
// publishes at /.well-known/did.json. v0.1 advertises a single Ed25519 key
// as a JWK; multibase-base58btc encoding is deferred to v0.2 (see notes in
// src/credential/issue.go).
type IssuerDIDDocument struct {
	Context            []string                  `json:"@context"`
	ID                 types.DID                 `json:"id"`
	VerificationMethod []IssuerVerificationEntry `json:"verificationMethod"`
	AssertionMethod    []string                  `json:"assertionMethod"`
}

// IssuerVerificationEntry is one entry in the DID document's
// verificationMethod array.
type IssuerVerificationEntry struct {
	ID           string                 `json:"id"`
	Type         string                 `json:"type"`
	Controller   types.DID              `json:"controller"`
	PublicKeyJwk map[string]interface{} `json:"publicKeyJwk,omitempty"`
}

// BuildDIDDocument constructs the issuer's DID document.
//
// The verification method publishes the public key as an Ed25519 OKP JWK
// (RFC 8037), which the v0.1 stub did:web resolver in src/credential cannot
// yet ingest. Integrators verifying in v0.1 should use MapResolver. v0.2 will
// land full did:web semantics including JWK + multibase support.
func BuildDIDDocument(issuerDID types.DID, keyFragment string, pub ed25519.PublicKey) (IssuerDIDDocument, error) {
	if len(pub) != ed25519.PublicKeySize {
		return IssuerDIDDocument{}, errors.New("BuildDIDDocument: public key must be 32 bytes")
	}
	vmID := IssuerVerificationMethod(issuerDID, keyFragment)
	return IssuerDIDDocument{
		Context: []string{
			"https://www.w3.org/ns/did/v1",
			"https://w3id.org/security/suites/jws-2020/v1",
		},
		ID: issuerDID,
		VerificationMethod: []IssuerVerificationEntry{{
			ID:         vmID,
			Type:       "JsonWebKey2020",
			Controller: issuerDID,
			PublicKeyJwk: map[string]interface{}{
				"kty": "OKP",
				"crv": "Ed25519",
				"x":   base64.RawURLEncoding.EncodeToString(pub),
			},
		}},
		AssertionMethod: []string{vmID},
	}, nil
}
