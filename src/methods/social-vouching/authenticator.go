package socialvouching

import (
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/hex"
	"errors"
)

// VoucherAuthenticator validates that a vouch submission genuinely comes
// from the claimed VoucherID, before the Method consults GraphStore for
// that voucher's trust score. A nil error means the proof checks out; any
// non-nil error means the vouch must be rejected.
//
// Implementations MUST be safe for concurrent use.
type VoucherAuthenticator interface {
	Authenticate(ctx context.Context, voucherID, candidateID, proof string) error
}

// ErrVouchProofMismatch is returned by HMACDevAuthenticator when the
// supplied proof does not match the recomputed value.
var ErrVouchProofMismatch = errors.New("social-vouching: vouch proof mismatch")

// HMACDevAuthenticator is the v0.1 stand-in VoucherAuthenticator: it
// recomputes HMAC-SHA256(secret, voucherID + "." + candidateID) and
// constant-time compares it (hex) to the supplied proof. This makes the
// whole method testable end-to-end without any real voucher identity
// infrastructure — mirroring app-attest-device's HMACDevVerifier.
//
// PRODUCTION NOTE: this is NOT a real cross-person identity proof (anyone
// who has the shared secret can "vouch" as anyone). v0.2 should authenticate
// each voucher via their OWN previously-issued Personhood credential: the
// voucher signs the vouch statement (candidateID + timestamp) with their
// holder Ed25519 key (see src/server/did.go), and the server verifies that
// signature against the DID on a credential it itself issued. That is a
// materially larger feature (looking up "does this DID hold a credential
// that itself passed this same ceremony, transitively, back to a seed") and
// is out of scope for this session; the VoucherAuthenticator interface is
// the seam it drops into without changing anything else in this method.
type HMACDevAuthenticator struct {
	secret []byte
}

var _ VoucherAuthenticator = (*HMACDevAuthenticator)(nil)

// NewHMACDevAuthenticator constructs an HMACDevAuthenticator. An empty
// secret is a programmer error and panics.
func NewHMACDevAuthenticator(secret string) *HMACDevAuthenticator {
	if secret == "" {
		panic("social-vouching.NewHMACDevAuthenticator: secret must not be empty")
	}
	return &HMACDevAuthenticator{secret: []byte(secret)}
}

// Authenticate implements VoucherAuthenticator.
func (a *HMACDevAuthenticator) Authenticate(_ context.Context, voucherID, candidateID, proof string) error {
	want := vouchProof(a.secret, voucherID, candidateID)
	if subtle.ConstantTimeCompare([]byte(want), []byte(proof)) != 1 {
		return ErrVouchProofMismatch
	}
	return nil
}

// SignVouchForTesting produces the proof a genuine voucher would send for
// the HMACDevAuthenticator, so tests (and the eventual client) can exercise
// the happy path. Mirrors SignDeviceTokenForTesting in app-attest-device.
func SignVouchForTesting(secret, voucherID, candidateID string) string {
	return vouchProof([]byte(secret), voucherID, candidateID)
}

func vouchProof(secret []byte, voucherID, candidateID string) string {
	mac := hmac.New(sha256.New, secret)
	mac.Write([]byte(voucherID + "." + candidateID))
	return hex.EncodeToString(mac.Sum(nil))
}
