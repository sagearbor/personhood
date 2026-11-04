package credential

// Equivocation proofs: two conflicting signatures by one holder key.
//
// Some integrators need a holder to sign a thing at most once. OpenLine's
// instant payments are the first case: a payer signs "spend coin X" once, and
// two different spends of the same coin are a double spend. When a holder
// signs two different payloads for the same slot, the two signatures
// together are a self-contained proof of cheating that anyone can check
// offline, with no trusted party. An issuer that receives such a proof
// revokes the holder's credential and bans its nullifier seed (see
// src/server/holderrevoke.go).
//
// A holder signs a SLOT STATEMENT, the UTF-8 text:
//
//	personhood-slot/v1
//	<context>
//	<slot>
//	<payload digest, 64 lower-case hex digits>
//
// joined by "\n" with no trailing newline.
//
//   - context names the integrator and the kind of slot, e.g.
//     "openline/<chain-id>/spend". Two integrators never share a context.
//   - slot names the thing that may be signed once, e.g. "<account>:<seq>"
//     or a coin id.
//   - the payload digest is SHA-256 of whatever was actually signed for the
//     slot (the payment body).
//
// context and slot are 1..256 bytes of printable ASCII (0x20..0x7e), so the
// newline-joined text is unambiguous.
//
// An EquivocationProof is valid when both statements carry the same context
// and slot, different payload digests, and both signatures verify under the
// same holder public key. Nothing else is needed, so a proof can be gossiped
// between phones and submitted by anyone.
//
// A wallet must only sign a slot statement as part of a spend it built
// itself. Signing one for a third party would let that party frame the
// holder with a second, conflicting statement.

import (
	"bytes"
	"crypto/ed25519"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"strings"
)

// SlotStatementScheme is the only EquivocationProof.Scheme this build accepts.
const SlotStatementScheme = "personhood-slot/v1"

// maxSlotFieldBytes bounds context and slot.
const maxSlotFieldBytes = 256

// ErrEquivocationInvalid is wrapped by every EquivocationProof.Verify failure.
var ErrEquivocationInvalid = errors.New("equivocation proof invalid")

// SlotStatement is one signed statement inside an EquivocationProof.
type SlotStatement struct {
	// PayloadDigestHex is hex(SHA-256(payload)), 64 lower-case hex digits.
	PayloadDigestHex string `json:"payload_digest_hex"`
	// SignatureB64 is the holder's Ed25519 signature over
	// SlotStatementMessage(context, slot, payload digest), standard base64.
	SignatureB64 string `json:"signature_b64"`
}

// EquivocationProof is the wire form of a double-signing proof.
type EquivocationProof struct {
	Scheme             string           `json:"scheme"`
	HolderPublicKeyB64 string           `json:"holder_public_key_b64"`
	Context            string           `json:"context"`
	Slot               string           `json:"slot"`
	Statements         [2]SlotStatement `json:"statements"`
}

// SlotStatementMessage returns the exact text a holder signs for one slot.
func SlotStatementMessage(context, slot string, payloadDigest []byte) (string, error) {
	if err := checkSlotField("context", context); err != nil {
		return "", err
	}
	if err := checkSlotField("slot", slot); err != nil {
		return "", err
	}
	if len(payloadDigest) != 32 {
		return "", fmt.Errorf("%w: payload digest must be 32 bytes, got %d", ErrEquivocationInvalid, len(payloadDigest))
	}
	return SlotStatementScheme + "\n" + context + "\n" + slot + "\n" + hex.EncodeToString(payloadDigest), nil
}

// SignSlotStatement signs one slot statement with priv. Integrators (and
// tests) use it to produce the statements an EquivocationProof carries.
func SignSlotStatement(priv ed25519.PrivateKey, context, slot string, payloadDigest []byte) (SlotStatement, error) {
	msg, err := SlotStatementMessage(context, slot, payloadDigest)
	if err != nil {
		return SlotStatement{}, err
	}
	return SlotStatement{
		PayloadDigestHex: hex.EncodeToString(payloadDigest),
		SignatureB64:     base64.StdEncoding.EncodeToString(ed25519.Sign(priv, []byte(msg))),
	}, nil
}

// Verify checks the proof and returns the holder public key it convicts.
// Every failure wraps ErrEquivocationInvalid.
func (p EquivocationProof) Verify() (ed25519.PublicKey, error) {
	if p.Scheme != SlotStatementScheme {
		return nil, fmt.Errorf("%w: unsupported scheme %q (want %q)", ErrEquivocationInvalid, p.Scheme, SlotStatementScheme)
	}
	pub, err := decodeB64(p.HolderPublicKeyB64)
	if err != nil || len(pub) != ed25519.PublicKeySize {
		return nil, fmt.Errorf("%w: holder_public_key_b64 must be a base64 32-byte Ed25519 key", ErrEquivocationInvalid)
	}
	var digests [2][]byte
	for i, st := range p.Statements {
		d, err := hex.DecodeString(st.PayloadDigestHex)
		if err != nil || len(d) != 32 || st.PayloadDigestHex != strings.ToLower(st.PayloadDigestHex) {
			return nil, fmt.Errorf("%w: statements[%d].payload_digest_hex must be 64 lower-case hex digits", ErrEquivocationInvalid, i)
		}
		digests[i] = d
	}
	if bytes.Equal(digests[0], digests[1]) {
		return nil, fmt.Errorf("%w: the two statements sign the same payload; that is not a conflict", ErrEquivocationInvalid)
	}
	for i, st := range p.Statements {
		msg, err := SlotStatementMessage(p.Context, p.Slot, digests[i])
		if err != nil {
			return nil, err
		}
		sig, err := decodeB64(st.SignatureB64)
		if err != nil || len(sig) != ed25519.SignatureSize {
			return nil, fmt.Errorf("%w: statements[%d].signature_b64 must be a base64 64-byte signature", ErrEquivocationInvalid, i)
		}
		if !ed25519.Verify(ed25519.PublicKey(pub), []byte(msg), sig) {
			return nil, fmt.Errorf("%w: statements[%d] signature does not verify under the holder key", ErrEquivocationInvalid, i)
		}
	}
	return ed25519.PublicKey(pub), nil
}

func checkSlotField(name, v string) error {
	if len(v) == 0 || len(v) > maxSlotFieldBytes {
		return fmt.Errorf("%w: %s must be 1..%d bytes", ErrEquivocationInvalid, name, maxSlotFieldBytes)
	}
	for i := 0; i < len(v); i++ {
		if v[i] < 0x20 || v[i] > 0x7e {
			return fmt.Errorf("%w: %s must be printable ASCII", ErrEquivocationInvalid, name)
		}
	}
	return nil
}

// decodeB64 accepts standard or URL-safe base64, padded or not.
func decodeB64(s string) ([]byte, error) {
	s = strings.TrimSpace(s)
	for _, enc := range []*base64.Encoding{base64.StdEncoding, base64.RawStdEncoding, base64.URLEncoding, base64.RawURLEncoding} {
		if b, err := enc.DecodeString(s); err == nil {
			return b, nil
		}
	}
	return nil, errors.New("not base64")
}
