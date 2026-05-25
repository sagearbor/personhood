// Package sms implements the Personhood "sms" supplementary verification
// method: a 6-digit OTP delivered over SMS.
//
// The method is intentionally simple. Tunables (TTL, max attempts, strength)
// are exported as constants. The OTP store and the delivery transport are
// both injectable so tests can run without a real carrier and so production
// can swap an in-memory store for Redis.
//
// On-credential strength: 12 points. SMS is weak against SIM-swap and SS7
// attacks; it MUST never satisfy a policy that requires an anchor, and the
// policy DSL enforces this independently.
package sms

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"math/big"
	"strings"
	"time"

	"github.com/sagearbor/personhood/pkg/types"
)

// methodPlugin is a local mirror of registry.Method. The registry package is
// developed in a sibling PR (feat/registry); to keep this module compilable
// without that dependency we redeclare the contract here. Once feat/registry
// merges, this interface should be replaced with a direct import of
// registry.Method and the *Method type below asserted against it via a
// blank-identifier var.
type methodPlugin interface {
	Metadata() types.MethodMetadata
	IsAvailableForUser(ctx types.UserContext) (available bool, reason string)
	BeginCeremony(ctx context.Context, cc types.CeremonyContext) (types.ChallengeData, error)
	CompleteCeremony(ctx context.Context, cc types.CeremonyContext, resp types.ResponseData) (types.MethodResult, error)
	HealthCheck(ctx context.Context) error
}

// ensure *Method satisfies the contract at compile time.
var _ methodPlugin = (*Method)(nil)

const (
	// OTPTTL is the lifetime of an OTP between BeginCeremony and
	// CompleteCeremony. Tight on purpose — an OTP that lives too long is a
	// re-issuance / SS7-window risk.
	OTPTTL = 5 * time.Minute

	// freshnessLifetime is the on-credential freshness window the method
	// advertises.
	freshnessLifetime = 90 * 24 * time.Hour

	// methodID is the stable method identifier.
	methodID = "sms"

	// methodVersion tracks the plugin implementation version.
	methodVersion = "0.1.0"

	// methodStrength is the supplementary point value (must be < 50).
	methodStrength = 12
)

// Method implements the Personhood "sms" supplementary method.
//
// It is safe for concurrent use: all per-ceremony state lives in the injected
// OTPStore.
type Method struct {
	sender Sender
	store  OTPStore
}

// NewMethod constructs a Method. Both arguments are required; nil sender or
// store is a programmer error and panics.
func NewMethod(sender Sender, store OTPStore) *Method {
	if sender == nil {
		panic("sms.NewMethod: sender must not be nil")
	}
	if store == nil {
		panic("sms.NewMethod: store must not be nil")
	}
	return &Method{sender: sender, store: store}
}

// Metadata implements registry.Method.
func (m *Method) Metadata() types.MethodMetadata {
	return types.MethodMetadata{
		ID:                methodID,
		Type:              types.MethodTypeSupplementary,
		Strength:          methodStrength,
		CostUSD:           0.0075, // illustrative US Twilio price; varies internationally
		UXFriction:        types.FrictionMed,
		FreshnessLifetime: freshnessLifetime,
		Version:           methodVersion,
	}
}

// IsAvailableForUser implements registry.Method. SMS is unavailable on
// kiosk-style platforms with no out-of-band channel to the user; everything
// else gets it.
func (m *Method) IsAvailableForUser(ctx types.UserContext) (bool, string) {
	if ctx.Platform == "kiosk" {
		return false, "SMS not available on kiosk platforms"
	}
	return true, ""
}

// BeginCeremony implements registry.Method. The phone number is passed via
// CeremonyContext.UserID, the same convention email/email.go uses for email
// addresses. This is a v0.1 shortcut — a future revision of CeremonyContext
// should grow a dedicated MethodInput map.
//
// Validation:
//  1. UserID non-empty
//  2. number does NOT look like a known VOIP / fictional range (LooksLikeVOIP)
//  3. fresh 6-digit OTP generated via crypto/rand
//  4. OTP stored under key sessionID|phoneNumber with OTPTTL
//  5. Sender invoked; on failure the just-stored entry is invalidated
//
// On any pre-store failure the store is untouched; on Send failure the entry
// is best-effort invalidated to keep the user able to retry immediately.
func (m *Method) BeginCeremony(ctx context.Context, cc types.CeremonyContext) (types.ChallengeData, error) {
	phoneNumber := strings.TrimSpace(cc.UserID)
	if phoneNumber == "" {
		return types.ChallengeData{}, errors.New("sms: CeremonyContext.UserID must carry the target phone number")
	}
	if LooksLikeVOIP(phoneNumber) {
		return types.ChallengeData{}, errors.New("too_many_voip_signals")
	}

	otp, err := generateOTP()
	if err != nil {
		return types.ChallengeData{}, fmt.Errorf("sms: generate otp: %w", err)
	}

	key := storeKey(cc.SessionID, phoneNumber)
	expiresAt := time.Now().Add(OTPTTL)
	if err := m.store.Put(ctx, key, otp, expiresAt); err != nil {
		return types.ChallengeData{}, fmt.Errorf("sms: store put: %w", err)
	}

	body := fmt.Sprintf("Your Personhood verification code: %s", otp)
	if err := m.sender.Send(ctx, phoneNumber, body); err != nil {
		_ = m.store.Invalidate(ctx, key)
		return types.ChallengeData{}, fmt.Errorf("sms: send: %w", err)
	}

	return types.ChallengeData{
		Type: "otp",
		Payload: map[string]any{
			"phone_number_last4": lastFour(phoneNumber),
			"expires_in_seconds": int(OTPTTL.Seconds()),
			"max_attempts":       MaxAttempts,
		},
	}, nil
}

// CompleteCeremony implements registry.Method. It expects ResponseData.Type
// "otp" and Payload {"phone_number": "...", "code": "123456"}.
//
// Constant-time compare lives inside InMemoryStore.Verify; this function only
// dispatches and translates the result.
//
// Logical failures (wrong code, expired, locked out) return a MethodResult
// with Success=false and a populated ErrorReason; non-nil error is reserved
// for internal store failures.
func (m *Method) CompleteCeremony(ctx context.Context, cc types.CeremonyContext, resp types.ResponseData) (types.MethodResult, error) {
	if resp.Type != "otp" {
		return types.MethodResult{
			Success:     false,
			MethodID:    methodID,
			ErrorReason: fmt.Sprintf("unexpected response type %q (expected \"otp\")", resp.Type),
		}, nil
	}

	phoneNumber, ok := stringField(resp.Payload, "phone_number")
	if !ok {
		return types.MethodResult{
			Success:     false,
			MethodID:    methodID,
			ErrorReason: "missing or empty phone_number in response payload",
		}, nil
	}
	code, ok := stringField(resp.Payload, "code")
	if !ok {
		return types.MethodResult{
			Success:     false,
			MethodID:    methodID,
			ErrorReason: "missing or empty code in response payload",
		}, nil
	}

	key := storeKey(cc.SessionID, phoneNumber)
	valid, attemptsRemaining, err := m.store.Verify(ctx, key, code)
	if err != nil {
		return types.MethodResult{}, fmt.Errorf("sms: store verify: %w", err)
	}
	if valid {
		digest := attestationDigest(cc.SessionID, phoneNumber, code)
		return types.MethodResult{
			Success:           true,
			MethodID:          methodID,
			VerifiedAt:        time.Now().UTC(),
			AttestationDigest: digest,
		}, nil
	}
	if attemptsRemaining == 0 {
		return types.MethodResult{
			Success:     false,
			MethodID:    methodID,
			ErrorReason: "too_many_attempts",
		}, nil
	}
	return types.MethodResult{
		Success:     false,
		MethodID:    methodID,
		ErrorReason: fmt.Sprintf("wrong_code (%d attempts remaining)", attemptsRemaining),
	}, nil
}

// HealthCheck implements registry.Method. The in-memory store has no external
// dependency to probe; Sender is opaque. v0.1 is a no-op success.
func (m *Method) HealthCheck(_ context.Context) error {
	return nil
}

// generateOTP returns a uniformly-random 6-digit zero-padded OTP using
// crypto/rand. Range is [000000, 999999]; the leading-zero space is included
// so an attacker can't shortcut by ignoring 6-digit strings starting with '0'.
func generateOTP() (string, error) {
	n, err := rand.Int(rand.Reader, big.NewInt(1_000_000))
	if err != nil {
		return "", err
	}
	return fmt.Sprintf("%06d", n.Int64()), nil
}

// storeKey composes the per-ceremony OTPStore key from sessionID and the
// (trimmed) phone number. Including the phone number prevents one session
// from cross-verifying another's OTP after a re-Begin under the same session.
func storeKey(sessionID, phoneNumber string) string {
	return sessionID + "|" + strings.TrimSpace(phoneNumber)
}

// lastFour returns the trailing 4 decimal digits of a phone number, used in
// the challenge payload so the client can echo back which number it sent the
// code to without us revealing the full number.
func lastFour(phoneNumber string) string {
	digits := strings.Map(func(r rune) rune {
		if r >= '0' && r <= '9' {
			return r
		}
		return -1
	}, phoneNumber)
	if len(digits) <= 4 {
		return digits
	}
	return digits[len(digits)-4:]
}

// attestationDigest is the SHA-256 over the canonical
// session_id || phone_number || code triple. Lands on the issued credential;
// the raw phone number and code never do.
func attestationDigest(sessionID, phoneNumber, code string) string {
	h := sha256.New()
	h.Write([]byte(sessionID))
	h.Write([]byte{0})
	h.Write([]byte(strings.TrimSpace(phoneNumber)))
	h.Write([]byte{0})
	h.Write([]byte(code))
	sum := h.Sum(nil)
	return hex.EncodeToString(sum)
}

// stringField returns a non-empty string field from a payload map, with a
// boolean for "found and non-empty."
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
