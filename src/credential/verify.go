package credential

import (
	"context"
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strings"

	"github.com/sagearbor/personhood/pkg/types"
)

// DIDResolver maps an issuer DID to the Ed25519 public key the issuer uses to
// sign credentials. Implementations are responsible for selecting the correct
// verification method when a DID document advertises multiple keys.
type DIDResolver interface {
	Resolve(ctx context.Context, did types.DID) (ed25519.PublicKey, error)
}

// Verifier validates a PersonhoodCredential's structure and Ed25519 signature.
//
// It deliberately does NOT check:
//   - Revocation status (use IsRevoked from status.go).
//   - Policy compliance (that's src/policy).
//   - Expiration vs wall-clock now (Validate ensures issuance < expiration,
//     but a verifier that wants "is this credential valid right now" should
//     compare ExpirationDate to time.Now() itself).
type Verifier struct {
	// Resolver is consulted to obtain the issuer's public key. Must be
	// non-nil.
	Resolver DIDResolver

	// HTTPClient is unused by the core verifier but is exposed so callers
	// that pass a WebResolver share a client (timeouts, transport, etc).
	HTTPClient *http.Client
}

// NewVerifier constructs a Verifier using the supplied DID resolver. Pass a
// MapResolver in tests; pass a WebResolver (once implemented) or any custom
// resolver in production.
func NewVerifier(resolver DIDResolver) *Verifier {
	return &Verifier{
		Resolver:   resolver,
		HTTPClient: http.DefaultClient,
	}
}

// Verify returns nil iff cred is structurally valid AND its Ed25519 signature
// verifies under the public key returned by the resolver for cred.Issuer.
//
// On failure the returned error wraps one of the sentinel errors below so
// callers can distinguish categories with errors.Is.
func (v *Verifier) Verify(ctx context.Context, cred types.PersonhoodCredential) error {
	if v == nil || v.Resolver == nil {
		return errors.New("verifier: resolver is required")
	}
	if err := cred.Validate(); err != nil {
		return fmt.Errorf("%w: %v", ErrStructuralInvalid, err)
	}
	if cred.Proof == nil {
		return fmt.Errorf("%w: credential has no proof", ErrProofMissing)
	}
	if cred.Proof.Type != ProofTypeEd25519Signature2020 {
		return fmt.Errorf("%w: unsupported proof type %q", ErrProofUnsupported, cred.Proof.Type)
	}
	if cred.Proof.ProofPurpose != ProofPurposeAssertionMethod {
		return fmt.Errorf("%w: unsupported proof purpose %q", ErrProofUnsupported, cred.Proof.ProofPurpose)
	}
	if cred.Proof.ProofValue == "" {
		return fmt.Errorf("%w: empty proofValue", ErrProofMissing)
	}

	pub, err := v.Resolver.Resolve(ctx, cred.Issuer)
	if err != nil {
		return fmt.Errorf("%w: %v", ErrIssuerUnknown, err)
	}
	if len(pub) != ed25519.PublicKeySize {
		return fmt.Errorf("%w: resolver returned %d byte key, want %d", ErrIssuerUnknown, len(pub), ed25519.PublicKeySize)
	}

	signingInput, err := canonicalizeWithoutProof(cred)
	if err != nil {
		return fmt.Errorf("verifier: canonicalize: %w", err)
	}

	sig, err := decodeProofValue(cred.Proof.ProofValue)
	if err != nil {
		return fmt.Errorf("%w: %v", ErrProofMalformed, err)
	}

	if !ed25519.Verify(pub, signingInput, sig) {
		return ErrSignatureInvalid
	}
	return nil
}

// Sentinel errors returned (wrapped) by Verifier.Verify.
var (
	// ErrStructuralInvalid means the credential failed types.PersonhoodCredential.Validate.
	ErrStructuralInvalid = errors.New("credential: structurally invalid")
	// ErrProofMissing means the credential carries no proof or an empty proofValue.
	ErrProofMissing = errors.New("credential: proof missing")
	// ErrProofUnsupported means the proof type or purpose is not supported by v0.1.
	ErrProofUnsupported = errors.New("credential: proof unsupported")
	// ErrProofMalformed means the proofValue could not be decoded.
	ErrProofMalformed = errors.New("credential: proof malformed")
	// ErrIssuerUnknown means the resolver could not return a public key for the issuer DID.
	ErrIssuerUnknown = errors.New("credential: issuer unknown")
	// ErrSignatureInvalid means the Ed25519 signature did not verify under the issuer's key.
	ErrSignatureInvalid = errors.New("credential: signature invalid")
)

// decodeProofValue decodes a v0.1 base64url-encoded proofValue. For forward
// compatibility we also accept a multibase-base58-btc value (prefix "z"),
// though Issue currently never emits one. v0.2 will flip the default to
// multibase.
func decodeProofValue(s string) ([]byte, error) {
	if s == "" {
		return nil, errors.New("empty proofValue")
	}
	if strings.HasPrefix(s, "z") {
		// Reserved for v0.2 multibase-base58-btc. We deliberately do NOT
		// pull in a base58 dependency in v0.1; reject with a clear message.
		return nil, errors.New("multibase-base58-btc proofValues not yet supported (v0.2)")
	}
	// Try unpadded base64url (what Issue emits).
	if b, err := base64.RawURLEncoding.DecodeString(s); err == nil {
		return b, nil
	}
	// Fall back to padded base64url, for tolerance.
	if b, err := base64.URLEncoding.DecodeString(s); err == nil {
		return b, nil
	}
	return nil, errors.New("proofValue is not valid base64url")
}

// ---------------------------------------------------------------------------
// In-memory resolver (for tests and trusted-issuer allow lists)
// ---------------------------------------------------------------------------

// MapResolver is an in-memory DIDResolver. Construct with a literal:
//
//	MapResolver{"did:web:example": pub}
//
// Lookup is exact; an unmapped DID returns an error.
type MapResolver map[types.DID]ed25519.PublicKey

// Resolve returns the public key for did, or an error if did is not present.
func (m MapResolver) Resolve(_ context.Context, did types.DID) (ed25519.PublicKey, error) {
	if m == nil {
		return nil, errors.New("MapResolver: nil map")
	}
	pub, ok := m[did]
	if !ok {
		return nil, fmt.Errorf("MapResolver: no key for DID %q", did)
	}
	return pub, nil
}

// ---------------------------------------------------------------------------
// did:web resolver (stub)
// ---------------------------------------------------------------------------

// WebResolver implements DIDResolver for did:web identifiers per the
// https://w3c-ccg.github.io/did-method-web/ spec.
//
// v0.1 status: stub. We perform the HTTPS fetch and JSON parse but the
// verificationMethod / publicKeyMultibase extraction logic is intentionally
// minimal: it expects exactly one Ed25519VerificationKey2020 entry whose
// publicKeyMultibase begins with "z" followed by raw base58btc (NOT yet
// decoded — see TODO below). Use MapResolver in tests until v0.2 lands a
// real did:web client.
type WebResolver struct {
	HTTPClient *http.Client
}

// didDocument is a minimal subset of a W3C DID document, sufficient for v0.1
// did:web stub resolution.
type didDocument struct {
	ID                 string                 `json:"id"`
	VerificationMethod []didVerificationEntry `json:"verificationMethod"`
}

type didVerificationEntry struct {
	ID                 string `json:"id"`
	Type               string `json:"type"`
	Controller         string `json:"controller"`
	PublicKeyMultibase string `json:"publicKeyMultibase,omitempty"`
	// publicKeyJwk and publicKeyBase58 also exist in the wild but are not
	// handled by the v0.1 stub.
}

// Resolve fetches a did:web DID document and returns the first
// Ed25519VerificationKey2020 public key it finds.
//
// TODO(v0.2): full did:web semantics — path-form DIDs, key selection by
// fragment, JWK + Base58 fallbacks, full multibase-base58-btc decoding.
func (w *WebResolver) Resolve(ctx context.Context, did types.DID) (ed25519.PublicKey, error) {
	const prefix = "did:web:"
	s := string(did)
	if !strings.HasPrefix(s, prefix) {
		return nil, fmt.Errorf("WebResolver: not a did:web DID: %q", did)
	}
	host := strings.TrimPrefix(s, prefix)
	// Strip any fragment / key selector — we just fetch the document.
	if idx := strings.Index(host, "#"); idx >= 0 {
		host = host[:idx]
	}
	// did:web supports path-form ("did:web:example.com:user:alice") but the
	// v0.1 stub only handles the root form. Reject anything more elaborate
	// with a clear error so users know to upgrade.
	if strings.ContainsAny(host, ":") {
		return nil, errors.New("WebResolver: path-form did:web not supported in v0.1")
	}
	url := fmt.Sprintf("https://%s/.well-known/did.json", host)

	client := w.HTTPClient
	if client == nil {
		client = http.DefaultClient
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return nil, fmt.Errorf("WebResolver: build request: %w", err)
	}
	req.Header.Set("Accept", "application/json,application/did+json")
	resp, err := client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("WebResolver: fetch %s: %w", url, err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("WebResolver: %s returned status %d", url, resp.StatusCode)
	}
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("WebResolver: read body: %w", err)
	}
	var doc didDocument
	if err := json.Unmarshal(body, &doc); err != nil {
		return nil, fmt.Errorf("WebResolver: parse did document: %w", err)
	}
	for _, vm := range doc.VerificationMethod {
		if vm.Type != "Ed25519VerificationKey2020" {
			continue
		}
		// v0.2 will properly decode multibase-base58-btc here. For now we
		// fail loudly so callers know to swap in MapResolver until then.
		return nil, errors.New("WebResolver: multibase key decoding not implemented (v0.2); use MapResolver for now")
	}
	return nil, fmt.Errorf("WebResolver: no Ed25519VerificationKey2020 in did document at %s", url)
}
