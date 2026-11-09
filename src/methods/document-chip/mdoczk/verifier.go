// Package mdoczk verifies a zero-knowledge proof of an ISO/IEC 18013-5
// mobile document (a mobile driving licence in Apple, Google or Samsung
// Wallet, or another government mdoc), made on the phone with personhood's
// own Noir circuit (tools/zk-circuits/mdoc, Apache-2.0). One UltraHonk
// proof shows that
//
//  1. an IACA (a government issuing authority's root) in the issuer's
//     published registry signed a document signer certificate;
//  2. that document signer signed the Mobile Security Object (MSO);
//  3. the MSO's docType is the public doc type, and it is valid at the
//     public `now`;
//  4. the MSO lists the digest of an IssuerSignedItem "document_number" in
//     the public namespace;
//  5. the MSO's device key (in the phone's secure hardware) signed
//     DeviceAuthentication over this session's transcript, whose SHA-256 is
//     a public input: a copied licence cannot answer a fresh nonce;
//  6. nullifier = Poseidon2(scope, jurisdiction, document number) for the
//     public scope.
//
// Nothing personal is public: not the name, number, birth date, photo,
// jurisdiction or keys. The mobile-id-zk method (../mobileid.go) wraps it.
// See docs/mobile-id.md.
package mdoczk

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"math/big"
	"strings"
	"time"

	"github.com/sagearbor/personhood/src/methods/document-chip/zkproof"
)

// Document types and their namespace for document_number.
const (
	DocTypeMDL   = "org.iso.18013.5.1.mDL"
	NameSpaceMDL = "org.iso.18013.5.1"
)

// CompanySignedDocTypes are signed by the wallet's company (Apple's Digital
// ID and Google's ID pass, both made from a passport), not by a government.
// They are refused (the passport itself is the stronger way in).
var CompanySignedDocTypes = []string{"org.iso.23220.photoid.1", "com.google.wallet.idcard.1"}

// DefaultDocTypes are accepted unless configured otherwise: docType ->
// namespace that holds document_number.
var DefaultDocTypes = map[string]string{DocTypeMDL: NameSpaceMDL}

// ScopeLabel is hashed into the service scope (changing it re-keys every
// licence).
const ScopeLabel = "personhood:mobile-id-zk:v1"

// ServiceScope is Poseidon2(pack_be(ScopeLabel)).
func ServiceScope() [zkproof.FieldSize]byte {
	return zkproof.FieldBytes(zkproof.Poseidon2Hash(zkproof.PackBEBytesIntoFields([]byte(ScopeLabel))))
}

// PublicInputs is the number of public fields: registry root, now, doc
// type, namespace, transcript hash (2), scope, nullifier.
const PublicInputs = 8

// CircuitPrefix starts every accepted circuit name (mdoc_p256_msg_<bytes>).
const CircuitPrefix = "mdoc_p256_msg_"

// Proof is what the phone sends.
type Proof struct {
	Circuit      string
	Proof        []byte
	PublicInputs []byte
}

// Result is what a verified proof establishes.
type Result struct {
	Nullifier    [zkproof.FieldSize]byte
	RegistryRoot [zkproof.FieldSize]byte
	DocType      string
	Now          time.Time
}

// Identifier is the uniqueness identifier the issuer keys with
// IDENTIFIER_HMAC_KEY: "mdoc:ZK:<64 hex>".
func (r Result) Identifier() string { return "mdoc:ZK:" + hex.EncodeToString(r.Nullifier[:]) }

// Errors; each maps to a refusal reason with a next step (docs/mobile-id.md).
var (
	ErrMalformed       = errors.New("mdoczk: malformed proof")
	ErrUnknownCircuit  = errors.New("mdoczk: circuit not in the trusted set")
	ErrProofInvalid    = errors.New("mdoczk: proof does not verify")
	ErrRegistryUnknown = errors.New("mdoczk: IACA registry root not published by this issuer")
	ErrScope           = errors.New("mdoczk: proof is for another scope")
	ErrStaleDate       = errors.New("mdoczk: proof's now is not now")
	ErrTranscript      = errors.New("mdoczk: proof is for another session")
	ErrDocType         = errors.New("mdoczk: document type not accepted")
	ErrCompanySigned   = errors.New("mdoczk: credential signed by a company, not a government")
)

// Verifier checks proofs.
type Verifier struct {
	BB    string
	VKs   map[string][]byte
	Roots map[[zkproof.FieldSize]byte]bool
	Scope [zkproof.FieldSize]byte
	// DocTypes maps accepted docType -> namespace (DefaultDocTypes if nil).
	DocTypes map[string]string
	// MaxDateSkew bounds |now - clock|. Default 36h.
	MaxDateSkew time.Duration
	Now         func() time.Time
}

func unpackText(f [zkproof.FieldSize]byte) (string, bool) {
	b := bytes.TrimLeft(f[:], "\x00")
	if len(b) == 0 || len(b) > 31 {
		return "", false
	}
	for _, c := range b {
		if c < 0x20 || c > 0x7e {
			return "", false
		}
	}
	return string(b), true
}

// PackText is the circuit's big-endian packing of a short ASCII string.
func PackText(s string) [zkproof.FieldSize]byte {
	return zkproof.FieldBytes(new(big.Int).SetBytes([]byte(s)))
}

// Verify checks one proof against this session's transcript hash.
func (v *Verifier) Verify(ctx context.Context, p Proof, transcriptHash [32]byte) (Result, error) {
	var res Result
	if len(p.Proof) != zkproof.ProofSize || len(p.PublicInputs) != PublicInputs*zkproof.FieldSize {
		return res, fmt.Errorf("%w: proof %d bytes, public inputs %d bytes", ErrMalformed, len(p.Proof), len(p.PublicInputs))
	}
	if !strings.HasPrefix(p.Circuit, CircuitPrefix) {
		return res, ErrUnknownCircuit
	}
	vk, ok := v.VKs[p.Circuit]
	if !ok {
		return res, ErrUnknownCircuit
	}
	f := make([][zkproof.FieldSize]byte, PublicInputs)
	for i := range f {
		copy(f[i][:], p.PublicInputs[i*zkproof.FieldSize:])
	}
	root, nowF, docF, nsF, thHi, thLo, scope, nul := f[0], f[1], f[2], f[3], f[4], f[5], f[6], f[7]

	if !v.Roots[root] {
		return res, ErrRegistryUnknown
	}
	if scope != v.Scope {
		return res, ErrScope
	}
	docType, ok1 := unpackText(docF)
	ns, ok2 := unpackText(nsF)
	if !ok1 || !ok2 {
		return res, ErrMalformed
	}
	for _, c := range CompanySignedDocTypes {
		if docType == c {
			return res, ErrCompanySigned
		}
	}
	types := v.DocTypes
	if types == nil {
		types = DefaultDocTypes
	}
	if want, ok := types[docType]; !ok || want != ns {
		return res, fmt.Errorf("%w: %q / %q", ErrDocType, docType, ns)
	}
	var wantHi, wantLo [zkproof.FieldSize]byte
	copy(wantHi[16:], transcriptHash[:16])
	copy(wantLo[16:], transcriptHash[16:])
	if thHi != wantHi || thLo != wantLo {
		return res, ErrTranscript
	}
	nowS, ok := unpackText(nowF)
	if !ok {
		return res, ErrMalformed
	}
	now, err := time.Parse("2006-01-02T15:04:05Z", nowS)
	if err != nil || len(nowS) != 20 {
		return res, ErrMalformed
	}
	clock := time.Now
	if v.Now != nil {
		clock = v.Now
	}
	skew := v.MaxDateSkew
	if skew == 0 {
		skew = 36 * time.Hour
	}
	if d := now.Sub(clock()); d > skew || d < -skew {
		return res, ErrStaleDate
	}
	if err := zkproof.BBVerify(ctx, v.BB, vk, zkproof.SubProof{Circuit: p.Circuit, Proof: p.Proof, PublicInputs: p.PublicInputs}); err != nil {
		if errors.Is(err, zkproof.ErrProofInvalid) {
			return res, ErrProofInvalid
		}
		return res, err
	}
	return Result{Nullifier: nul, RegistryRoot: root, DocType: docType, Now: now}, nil
}

// TranscriptHash is SHA-256 of a session transcript.
func TranscriptHash(sessionTranscript []byte) [32]byte { return sha256.Sum256(sessionTranscript) }

// ExpectedNullifier recomputes a nullifier from the cleartext values (tests
// and fixtures only; the issuer never sees them): Poseidon2(scope,
// pack(jurisdiction), pack(document number), len).
func ExpectedNullifier(scope [zkproof.FieldSize]byte, jurisdiction, documentNumber string) *big.Int {
	return zkproof.Poseidon2Hash([]*big.Int{
		new(big.Int).SetBytes(scope[:]),
		new(big.Int).SetBytes([]byte(jurisdiction)),
		new(big.Int).SetBytes([]byte(documentNumber)),
		big.NewInt(int64(len(documentNumber))),
	})
}
