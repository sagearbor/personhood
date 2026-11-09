package appattestdevice

import (
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/hex"
	"errors"
	"fmt"
)

// Platform identifies the device attestation ecosystem the token came from.
type Platform string

const (
	// PlatformIOS is Apple App Attest (DCAppAttestService).
	PlatformIOS Platform = "ios"

	// PlatformAndroid is an Android phone. With AndroidKeyVerifier the token
	// is an Android Key Attestation certificate chain (see androidkey.go).
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

	// Token is the base64 attestation object (iOS) or, for Android Key
	// Attestation, the certificate chain: base64 DER certificates, leaf
	// first, joined with ",".
	Token string

	// KeyID is the iOS App Attest key id. Optional for Android.
	KeyID string
}

// Verifier validates that an AttestationInput came from a genuine,
// non-emulated device and is bound to the issued Nonce. A nil error means
// genuine device + nonce matches; any non-nil error means the attestation must
// be rejected. A *VerifyError carries a machine-readable reason.
//
// Implementations MUST be safe for concurrent use.
type Verifier interface {
	Verify(ctx context.Context, in AttestationInput) (Evidence, error)
}

// Evidence is what a successful verification learned beyond "yes".
type Evidence struct {
	// SecurityLevel is "tee" or "strongbox" for Android Key Attestation;
	// empty for verifiers that do not know.
	SecurityLevel string

	// DeviceHint is a value that is likely the same for the same phone over
	// a short period, and is set only where that is honest (see
	// androidkey.go: Remote Key Provisioning attestation keys). It is a
	// rate-limit hint, never an identity: different values do not prove
	// different phones, and it rotates.
	DeviceHint string
}

// VerifyError is a rejected attestation with a short machine-readable
// reason (e.g. "attestation_not_hardware"), which becomes the
// MethodResult.ErrorReason.
type VerifyError struct {
	Reason string
	Err    error
}

func (e *VerifyError) Error() string {
	if e.Err == nil {
		return "app-attest-device: " + e.Reason
	}
	return "app-attest-device: " + e.Reason + ": " + e.Err.Error()
}

func (e *VerifyError) Unwrap() error { return e.Err }

func reject(reason string, format string, args ...any) error {
	return &VerifyError{Reason: reason, Err: fmt.Errorf(format, args...)}
}

// PlatformRouter sends each attestation to the Verifier for its platform.
// A platform with no entry is rejected as "platform_unsupported".
type PlatformRouter map[Platform]Verifier

var _ Verifier = PlatformRouter(nil)

// Verify implements Verifier.
func (r PlatformRouter) Verify(ctx context.Context, in AttestationInput) (Evidence, error) {
	v, ok := r[in.Platform]
	if !ok || v == nil {
		return Evidence{}, &VerifyError{Reason: "platform_unsupported"}
	}
	return v.Verify(ctx, in)
}

// ErrAttestationMismatch is returned by HMACDevVerifier when the supplied token
// does not match the recomputed value.
var ErrAttestationMismatch = errors.New("app-attest-device: attestation token mismatch")

// HMACDevVerifier is the v0.1 stand-in Verifier. It recomputes
// HMAC-SHA256(secret, platform + "." + nonce + "." + keyID) and constant-time
// compares it (hex) to the supplied Token. This makes the whole method testable
// end-to-end without Apple or Google infrastructure.
//
// PRODUCTION NOTE: this is NOT real device attestation. Android has a real
// verifier (AndroidKeyVerifier, androidkey.go). iOS still needs one: parse
// the CBOR attestation object, validate the certificate chain to the Apple
// App Attest root, confirm the embedded nonce hash, and pin the app's appID +
// key id.
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
func (v *HMACDevVerifier) Verify(_ context.Context, in AttestationInput) (Evidence, error) {
	want := hmacDeviceToken(v.secret, in.Platform, in.Nonce, in.KeyID)
	if subtle.ConstantTimeCompare([]byte(want), []byte(in.Token)) != 1 {
		return Evidence{}, ErrAttestationMismatch
	}
	return Evidence{}, nil
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
