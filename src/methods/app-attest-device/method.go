// Package appattestdevice implements the Personhood "app-attest-device"
// supplementary verification method: standalone Apple App Attest (iOS) /
// Google Play Integrity (Android) device attestation.
//
// On its own this is a near-free "floor" signal: it proves the request comes
// from a genuine, non-emulated device running the real app, which kills
// emulator and VM farms cheaply. It is SUPPLEMENTARY — it never substitutes for
// an anchor — because a single attacker with a fleet of real, jailbroken-or-not
// phones can still pass it. Per docs/06-methods-catalog.md the strength is 18
// (well below the 50-point anchor threshold).
//
// Wire model (challenge/response with a server-issued nonce, mirroring sms):
//   1. BeginCeremony generates a random nonce, stores it against the SessionID,
//      and returns it in ChallengeData so the device can sign it.
//   2. The client performs platform attestation over the nonce (App Attest on
//      iOS, Play Integrity on Android) and POSTs the token back.
//   3. CompleteCeremony looks up the stored nonce, hands the token + nonce to a
//      pluggable Verifier, and on success records an attestation digest.
//
// The default Verifier (HMACDevVerifier) is a v0.1 stand-in so the method is
// fully testable without Apple/Google; production wires in real App Attest /
// Play Integrity verifiers behind the same Verifier interface. See verifier.go.
package appattestdevice

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/sagearbor/personhood/pkg/types"
)

// methodPlugin mirrors registry.Method (which lives in a sibling module) so
// this module stays independently compilable. The assertion below enforces the
// contract at build time.
type methodPlugin interface {
	Metadata() types.MethodMetadata
	IsAvailableForUser(ctx types.UserContext) (available bool, reason string)
	BeginCeremony(ctx context.Context, cc types.CeremonyContext) (types.ChallengeData, error)
	CompleteCeremony(ctx context.Context, cc types.CeremonyContext, resp types.ResponseData) (types.MethodResult, error)
	HealthCheck(ctx context.Context) error
}

var _ methodPlugin = (*Method)(nil)

const (
	// MethodID is the stable plugin identifier.
	MethodID = "app-attest-device"

	// MethodVersion tracks the plugin implementation version.
	MethodVersion = "0.1.0"

	// MethodStrength is the on-credential supplementary point value. 18 is below
	// the 50-point anchor threshold per docs/06-methods-catalog.md: real-device
	// attestation is a meaningful floor but a determined attacker can farm real
	// phones, so it stays supplementary.
	MethodStrength = 18

	// MethodCostUSD is the per-verification cost. Apple App Attest and Google
	// Play Integrity are free at the volumes Personhood targets.
	MethodCostUSD = 0.00

	// MethodFreshnessLifetime is the on-credential freshness window. Device
	// possession is fairly stable, so a 30-day window keeps the floor signal
	// current without re-attesting too often.
	MethodFreshnessLifetime = 30 * 24 * time.Hour
)

// Method implements the Personhood app-attest-device supplementary method. Safe
// for concurrent use: all per-ceremony state lives in the injected
// ChallengeStore.
type Method struct {
	verifier Verifier
	store    ChallengeStore
	// newNonce generates the per-ceremony challenge nonce. Injectable for
	// deterministic tests; defaults to 32 random bytes hex-encoded.
	newNonce func() (string, error)
}

// Config bundles NewMethod's dependencies. Both fields are required.
type Config struct {
	Verifier Verifier
	Store    ChallengeStore
}

// NewMethod constructs a Method. A nil Verifier or Store is a programmer error
// and panics.
func NewMethod(cfg Config) *Method {
	if cfg.Verifier == nil {
		panic("app-attest-device.NewMethod: Verifier must not be nil")
	}
	if cfg.Store == nil {
		panic("app-attest-device.NewMethod: Store must not be nil")
	}
	return &Method{
		verifier: cfg.Verifier,
		store:    cfg.Store,
		newNonce: defaultNonce,
	}
}

// Metadata implements registry.Method.
func (m *Method) Metadata() types.MethodMetadata {
	return types.MethodMetadata{
		ID:                MethodID,
		Type:              types.MethodTypeSupplementary,
		Strength:          MethodStrength,
		CostUSD:           MethodCostUSD,
		UXFriction:        types.FrictionLow,
		FreshnessLifetime: MethodFreshnessLifetime,
		Version:           MethodVersion,
	}
}

// IsAvailableForUser implements registry.Method. App Attest / Play Integrity
// require a mobile platform; web and kiosk clients have no equivalent.
func (m *Method) IsAvailableForUser(ctx types.UserContext) (bool, string) {
	switch strings.ToLower(strings.TrimSpace(ctx.Platform)) {
	case "web", "kiosk":
		return false, "Device attestation requires the iOS or Android app."
	default:
		return true, ""
	}
}

// BeginCeremony implements registry.Method. It mints a random challenge nonce,
// binds it to the session, and returns it for the device to sign.
func (m *Method) BeginCeremony(ctx context.Context, cc types.CeremonyContext) (types.ChallengeData, error) {
	if cc.SessionID == "" {
		return types.ChallengeData{}, errors.New("app-attest-device: CeremonyContext.SessionID is required")
	}
	nonce, err := m.newNonce()
	if err != nil {
		return types.ChallengeData{}, fmt.Errorf("app-attest-device: generate nonce: %w", err)
	}
	if err := m.store.PutChallenge(ctx, cc.SessionID, nonce); err != nil {
		return types.ChallengeData{}, fmt.Errorf("app-attest-device: store challenge: %w", err)
	}
	return types.ChallengeData{
		Type: "app-attest-challenge",
		Payload: map[string]any{
			"nonce":             nonce,
			"complete_endpoint": "/v1/methods/" + MethodID + "/complete",
		},
	}, nil
}

// CompleteCeremony implements registry.Method. It reads the platform, token,
// and key_id from the response, looks up the stored nonce, and delegates to the
// Verifier. Verifier errors are attributable to the device, so they surface as
// Success:false (not a Go error); a non-nil error is reserved for internal
// store failures.
func (m *Method) CompleteCeremony(ctx context.Context, cc types.CeremonyContext, resp types.ResponseData) (types.MethodResult, error) {
	if cc.SessionID == "" {
		return types.MethodResult{Success: false, MethodID: MethodID, ErrorReason: "missing_session_id"}, nil
	}

	platform, _ := stringField(resp.Payload, "platform")
	token, _ := stringField(resp.Payload, "token")
	keyID, _ := stringField(resp.Payload, "key_id")

	nonce, err := m.store.GetChallenge(ctx, cc.SessionID)
	if err != nil {
		if errors.Is(err, ErrNoChallenge) {
			return types.MethodResult{Success: false, MethodID: MethodID, ErrorReason: "no_challenge_issued"}, nil
		}
		return types.MethodResult{}, fmt.Errorf("app-attest-device: store: %w", err)
	}

	if token == "" {
		return types.MethodResult{Success: false, MethodID: MethodID, ErrorReason: "missing_attestation_token"}, nil
	}

	in := AttestationInput{
		Platform: Platform(platform),
		Nonce:    nonce,
		Token:    token,
		KeyID:    keyID,
	}
	if err := m.verifier.Verify(ctx, in); err != nil {
		return types.MethodResult{Success: false, MethodID: MethodID, ErrorReason: "attestation_invalid"}, nil
	}

	return types.MethodResult{
		Success:           true,
		MethodID:          MethodID,
		VerifiedAt:        time.Now().UTC(),
		AttestationDigest: attestationDigest(cc.SessionID, platform, keyID, nonce),
	}, nil
}

// HealthCheck implements registry.Method. No external dependency to probe; the
// in-memory store and HMAC verifier are local. v0.1 is a no-op success.
func (m *Method) HealthCheck(_ context.Context) error { return nil }

// defaultNonce returns 32 cryptographically-random bytes, hex-encoded.
func defaultNonce() (string, error) {
	b := make([]byte, 32)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return hex.EncodeToString(b), nil
}

// attestationDigest mirrors the other methods: SHA-256 over a
// session_id || platform || key_id || nonce tuple. The raw token never lands on
// the credential.
func attestationDigest(sessionID, platform, keyID, nonce string) string {
	h := sha256.New()
	h.Write([]byte(sessionID))
	h.Write([]byte{0})
	h.Write([]byte(platform))
	h.Write([]byte{0})
	h.Write([]byte(keyID))
	h.Write([]byte{0})
	h.Write([]byte(nonce))
	return hex.EncodeToString(h.Sum(nil))
}

// stringField returns a trimmed, non-empty string field from a payload map,
// with a boolean for "found and non-empty."
func stringField(m map[string]any, key string) (string, bool) {
	v, ok := m[key]
	if !ok {
		return "", false
	}
	s, ok := v.(string)
	if !ok {
		return "", false
	}
	s = strings.TrimSpace(s)
	return s, s != ""
}
