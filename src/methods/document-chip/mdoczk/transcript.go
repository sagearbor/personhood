package mdoczk

import (
	"bytes"
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"fmt"
	"strings"
)

// The session transcript binds the mdoc's device signature to one issuer
// session. The phone asks its wallet (Android Credential Manager, ISO/IEC
// 18013-7 Annex C, protocol "org-iso-mdoc") for the licence with
//
//	EncryptionInfo     = ["dcapi", {"nonce": bstr, "recipientPublicKey": COSE_Key}]
//	Base64EncryptionInfo = base64url(no padding) of the CBOR of EncryptionInfo
//
// and the wallet signs, with the licence's device key (held in the phone's
// secure hardware),
//
//	SessionTranscript  = [null, null, ["dcapi", SHA-256(CBOR [Base64EncryptionInfo, origin])]]
//
// inside DeviceAuthentication. The nonce is the issuer's (Nonce): the phone
// cannot get a device signature over it without the licence's device key,
// which is the mdoc equivalent of a passport chip's Active Authentication
// (copy protection). recipientPublicKey is the phone's own one-time HPKE key
// (the wallet encrypts its answer to it), so the answer is decrypted on the
// phone and never reaches the issuer.

// NonceLabel domain-separates the nonce.
const NonceLabel = "personhood/mobile-id/v1"

// Nonce is the 32-byte nonce the phone must put in EncryptionInfo:
// SHA-256(NonceLabel 0x00 challenge SHA-256(holder)). It binds the session
// challenge and the holder (DID) the credential will be issued to, so a
// proof cannot be completed into another session or for another key.
func Nonce(challenge [32]byte, holder string) [32]byte {
	hh := sha256.Sum256([]byte(holder))
	h := sha256.New()
	h.Write([]byte(NonceLabel))
	h.Write([]byte{0})
	h.Write(challenge[:])
	h.Write(hh[:])
	var out [32]byte
	copy(out[:], h.Sum(nil))
	return out
}

// Errors from the transcript checks.
var (
	ErrEncryptionInfo = errors.New("mdoczk: encryption_info is not this session's")
	ErrOrigin         = errors.New("mdoczk: origin is missing or not allowed")
)

// EncryptionInfo is the CBOR of ["dcapi", {"nonce": nonce,
// "recipientPublicKey": key}], as the phone builds it.
func EncryptionInfo(nonce [32]byte, recipientKey Map) []byte {
	return Encode([]any{"dcapi", Map{{"nonce", nonce[:]}, {"recipientPublicKey", recipientKey}}})
}

// CheckEncryptionInfo decodes Base64EncryptionInfo and checks it carries
// this session's nonce and a recipient key.
func CheckEncryptionInfo(b64 string, nonce [32]byte) error {
	if len(b64) == 0 || len(b64) > 1024 {
		return ErrEncryptionInfo
	}
	raw, err := base64.RawURLEncoding.DecodeString(b64)
	if err != nil {
		return ErrEncryptionInfo
	}
	v, err := Decode(raw)
	if err != nil {
		return ErrEncryptionInfo
	}
	arr, ok := v.([]any)
	if !ok || len(arr) != 2 || arr[0] != "dcapi" {
		return ErrEncryptionInfo
	}
	m, ok := arr[1].(Map)
	if !ok {
		return ErrEncryptionInfo
	}
	n, _ := m.Get("nonce")
	nb, ok := n.([]byte)
	if !ok || !bytes.Equal(nb, nonce[:]) {
		return ErrEncryptionInfo
	}
	if k, _ := m.Get("recipientPublicKey"); k == nil {
		return ErrEncryptionInfo
	} else if _, ok := k.(Map); !ok {
		return ErrEncryptionInfo
	}
	return nil
}

// SessionTranscript is the CBOR of the Annex C (dcapi) session transcript.
func SessionTranscript(b64EncryptionInfo, origin string) []byte {
	info := sha256.Sum256(Encode([]any{b64EncryptionInfo, origin}))
	return Encode([]any{Null, Null, []any{"dcapi", info[:]}})
}

// CheckOrigin accepts a non-empty origin of at most 512 bytes; when allowed
// is non-empty, the origin must be one of them (e.g. the app's
// "android:apk-key-hash:<base64url SHA-256 of its signing certificate>").
func CheckOrigin(origin string, allowed []string) error {
	if origin == "" || len(origin) > 512 || strings.ContainsAny(origin, "\x00\n\r") {
		return ErrOrigin
	}
	if len(allowed) == 0 {
		return nil
	}
	for _, a := range allowed {
		if a == origin {
			return nil
		}
	}
	return fmt.Errorf("%w: %q", ErrOrigin, origin)
}

// OpenID4VPHandover is the session transcript of OpenID4VP 1.0 over the
// Digital Credentials API (response_mode dc_api.jwt; the form Google Wallet
// documents for relying parties):
//
//	[null, null, ["OpenID4VPDCAPIHandover", SHA-256(CBOR [origin, nonce, jwk_thumbprint])]]
//
// nonce is the request's nonce string (here base64url of Nonce), and
// jwkThumbprint the RFC 7638 SHA-256 thumbprint of the phone's response
// encryption key (nil encodes as null for an unencrypted response).
func OpenID4VPSessionTranscript(origin, nonce string, jwkThumbprint []byte) []byte {
	var tp any = Null
	if jwkThumbprint != nil {
		tp = jwkThumbprint
	}
	h := sha256.Sum256(Encode([]any{origin, nonce, tp}))
	return Encode([]any{Null, Null, []any{"OpenID4VPDCAPIHandover", h[:]}})
}

// NonceString is the nonce as OpenID4VP carries it: base64url, no padding.
func NonceString(n [32]byte) string { return base64.RawURLEncoding.EncodeToString(n[:]) }
