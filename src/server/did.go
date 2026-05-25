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

// HolderDIDForSession returns a placeholder did:personhood holder DID derived
// from the session ID. The v0.1 reference server does NOT manage per-holder
// key pairs; the credential is bound to this opaque identifier so it can be
// uniquely addressed, but presentation flows are out of scope until v0.2.
//
// If `holderPublicKey` is non-nil (32 bytes), its SHA-256 is mixed in so two
// sessions using the same client-side key derive the same DID. This is the
// hook the web app will use once it generates a WebCrypto Ed25519 keypair.
func HolderDIDForSession(sessionID string, holderPublicKey ed25519.PublicKey) types.DID {
	h := sha256.New()
	h.Write([]byte(sessionID))
	if len(holderPublicKey) == ed25519.PublicKeySize {
		h.Write([]byte{0})
		h.Write(holderPublicKey)
	}
	digest := h.Sum(nil)
	return types.DID(fmt.Sprintf("did:personhood:holder:%s", hex.EncodeToString(digest)))
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
