package appattestdevice

import (
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/hex"
	"errors"
)

// Platform identifies the device attestation ecosystem the token came from.
type Platform string

const (
	// PlatformIOS is Apple App Attest (DCAppAttestService).
	PlatformIOS Platform = "ios"

	// PlatformAndroid is Google Play Integrity.
	PlatformAndroid Platform = "android"
)

// AttestationInput is the device-supplied material a Verifier checks. The Nonce
// is the server challenge the device must have signed; binding to it is what
// prevents replay of a captured token across ceremonies.
type AttestationInput struct {
	// Platform is "ios" (Apple App Attest) or "android" (Play Integrity).
	Platform Platform

	// Nonce is the server challenge the device signed.
	Nonce string

	// Token is the base64 attestation object (iOS) or the integrity token
	// (Android).
	Token string

	// KeyID is the iOS App Attest key id. Optional for Android.
	KeyID string
}

// Verifier validates that an AttestationInput came from a genuine,
// non-emulated device and is bound to the issued Nonce. A nil error means
// genuine device + nonce matches; any non-nil error means the attestation must
// be rejected.
//
// Implementations MUST be safe for concurrent use.
type Verifier interface {
	Verify(ctx context.Context, in AttestationInput) error
}

// ErrAttestationMismatch is returned by HMACDevVerifier when the supplied token
// does not match the recomputed value.
var ErrAttestationMismatch = errors.New("app-attest-device: attestation token mismatch")

// HMACDevVerifier is the v0.1 stand-in Verifier. It recomputes
// HMAC-SHA256(secret, platform + "." + nonce + "." + keyID) and constant-time
// compares it (hex) to the supplied Token. This makes the whole method testable
// end-to-end without Apple or Google infrastructure.
//
// PRODUCTION NOTE: this is NOT real device attestation. v0.2 must swap in a
// real verifier:
//   - iOS: parse the CBOR attestation object, validate the certificate chain to
//     the Apple App Attest root, confirm the embedded nonce hash, and pin the
//     app's appID + key id.
//   - Android: decode the Play Integrity JWS/JWT against Google's public keys
//     and assert MEETS_DEVICE_INTEGRITY (rejecting emulators) plus the request
//     nonce.
// The Verifier interface is the seam those drop into; nothing else in the
// method needs to change.
type HMACDevVerifier struct {
	secret []byte
}

var _ Verifier = (*HMACDevVerifier)(nil)

// NewHMACDevVerifier constructs an HMACDevVerifier. An empty secret is a
// programmer error and panics.
func NewHMACDevVerifier(secret string) *HMACDevVerifier {
	if secret == "" {
		panic("app-attest-device.NewHMACDevVerifier: secret must not be empty")
	}
	return &HMACDevVerifier{secret: []byte(secret)}
}

// Verify implements Verifier.
func (v *HMACDevVerifier) Verify(_ context.Context, in AttestationInput) error {
	want := hmacDeviceToken(v.secret, in.Platform, in.Nonce, in.KeyID)
	if subtle.ConstantTimeCompare([]byte(want), []byte(in.Token)) != 1 {
		return ErrAttestationMismatch
	}
	return nil
}

// SignDeviceTokenForTesting produces the token a genuine device would send for
// the HMACDevVerifier, so tests (and the eventual client mock) can exercise the
// happy path. It mirrors SignWebhookForTesting in plaid-bank-link. Production
// clients never use this; real devices produce real attestation objects.
func SignDeviceTokenForTesting(secret string, platform Platform, nonce, keyID string) string {
	return hmacDeviceToken([]byte(secret), platform, nonce, keyID)
}

// hmacDeviceToken is the shared computation for the dev verifier and the test
// signer: hex(HMAC-SHA256(secret, platform + "." + nonce + "." + keyID)).
func hmacDeviceToken(secret []byte, platform Platform, nonce, keyID string) string {
	mac := hmac.New(sha256.New, secret)
	mac.Write([]byte(string(platform) + "." + nonce + "." + keyID))
	return hex.EncodeToString(mac.Sum(nil))
}
