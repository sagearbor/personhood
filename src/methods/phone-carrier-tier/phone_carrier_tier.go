// Package phonecarriertier implements the Personhood "phone-carrier-tier"
// supplementary verification method: the same 6-digit SMS OTP ceremony as the
// plain "sms" method, upgraded with carrier intelligence (line type + porting
// history via Twilio Lookup).
//
// Per docs/06-methods-catalog.md this is the strength-28 upgrade for the
// strength-12 "sms" method. Same UX and near-same cost (~$0.05 incl. the Lookup
// call): plain SMS only proves a device can receive a code — trivially Sybil'd
// with cheap VOIP numbers — whereas requiring a real mobile line that has not
// been recently ported raises the bar substantially.
//
// Strength rationale: the strength-28 rating assumes a real CarrierProvider
// (TwilioLookupProvider) is wired. Built with the dev-default NeutralProvider
// it only applies the offline LooksLikeVOIP pre-check and is effectively
// plain-SMS strength; the server wiring logs a warning. This mirrors the repo
// convention for ip-asn-reputation and app-attest-device.
package phonecarriertier

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

// methodPlugin mirrors registry.Method so this module stays independently
// compilable. The assertion below enforces the contract at build time.
type methodPlugin interface {
	Metadata() types.MethodMetadata
	IsAvailableForUser(ctx types.UserContext) (available bool, reason string)
	BeginCeremony(ctx context.Context, cc types.CeremonyContext) (types.ChallengeData, error)
	CompleteCeremony(ctx context.Context, cc types.CeremonyContext, resp types.ResponseData) (types.MethodResult, error)
	HealthCheck(ctx context.Context) error
}

var _ methodPlugin = (*Method)(nil)

const (
	// OTPTTL is the lifetime of an OTP between Begin and Complete.
	OTPTTL = 5 * time.Minute

	// freshnessLifetime is the on-credential freshness window the method
	// advertises.
	freshnessLifetime = 90 * 24 * time.Hour

	// MethodID is the stable method identifier.
	MethodID = "phone-carrier-tier"

	// MethodVersion tracks the plugin implementation version.
	MethodVersion = "0.1.0"

	// MethodStrength is the supplementary point value (must be < 50). 28 per the
	// methods catalog; earned when a real CarrierProvider is wired.
	MethodStrength = 28

	// MethodCostUSD is the illustrative per-verification cost (~$0.05: SMS +
	// Lookup).
	MethodCostUSD = 0.05
)

// Method implements the Personhood "phone-carrier-tier" supplementary method.
// Safe for concurrent use: per-ceremony state lives in the injected OTPStore.
type Method struct {
	sender   Sender
	store    OTPStore
	provider CarrierProvider
}

// Config bundles NewMethod's dependencies.
type Config struct {
	// Sender delivers the OTP SMS. Required.
	Sender Sender

	// Store persists outstanding OTPs. Required.
	Store OTPStore

	// Provider supplies carrier intelligence. If nil, NeutralProvider{} is used
	// (dev default; offline pre-check only).
	Provider CarrierProvider
}

// NewMethod constructs a Method. Sender and Store are required; a nil value is
// a programmer error and panics. A nil Provider defaults to NeutralProvider.
func NewMethod(cfg Config) *Method {
	if cfg.Sender == nil {
		panic("phone-carrier-tier.NewMethod: Sender must not be nil")
	}
	if cfg.Store == nil {
		panic("phone-carrier-tier.NewMethod: Store must not be nil")
	}
	provider := cfg.Provider
	if provider == nil {
		provider = NeutralProvider{}
	}
	return &Method{sender: cfg.Sender, store: cfg.Store, provider: provider}
}

// Metadata implements registry.Method.
func (m *Method) Metadata() types.MethodMetadata {
	return types.MethodMetadata{
		ID:                MethodID,
		Type:              types.MethodTypeSupplementary,
		Strength:          MethodStrength,
		CostUSD:           MethodCostUSD,
		UXFriction:        types.FrictionMed,
		FreshnessLifetime: freshnessLifetime,
		Version:           MethodVersion,
	}
}

// ProviderName reports the active CarrierProvider's name. The server wiring
// uses it to warn when the dev-default NeutralProvider is in use.
func (m *Method) ProviderName() string { return m.provider.Name() }

// IsAvailableForUser implements registry.Method. SMS is unavailable on
// kiosk-style platforms with no out-of-band channel to the user.
func (m *Method) IsAvailableForUser(ctx types.UserContext) (bool, string) {
	if ctx.Platform == "kiosk" {
		return false, "SMS not available on kiosk platforms"
	}
	return true, ""
}

// BeginCeremony implements registry.Method. The phone number is carried in
// CeremonyContext.UserID (the same v0.1 convention as the sms and email
// methods).
//
// Steps:
//  1. UserID non-empty
//  2. offline LooksLikeVOIP pre-check rejects fictional/known-VOIP numbers
//  3. carrier lookup runs; a VOIP line OR a recently-ported line is rejected
//  4. a fresh 6-digit OTP is stored together with the captured CarrierSignal
//  5. the Sender is invoked; on failure the entry is invalidated
func (m *Method) BeginCeremony(ctx context.Context, cc types.CeremonyContext) (types.ChallengeData, error) {
	phoneNumber := strings.TrimSpace(cc.UserID)
	if phoneNumber == "" {
		return types.ChallengeData{}, errors.New("phone-carrier-tier: CeremonyContext.UserID must carry the target phone number")
	}
	if LooksLikeVOIP(phoneNumber) {
		return types.ChallengeData{}, errors.New("too_many_voip_signals")
	}

	signal, err := m.provider.Lookup(ctx, phoneNumber)
	if err != nil {
		return types.ChallengeData{}, fmt.Errorf("phone-carrier-tier: carrier lookup: %w", err)
	}
	if signal.LineType == LineTypeVOIP {
		return types.ChallengeData{}, errors.New("voip_line_not_accepted")
	}
	if signal.Ported {
		return types.ChallengeData{}, errors.New("recently_ported_line")
	}

	otp, err := generateOTP()
	if err != nil {
		return types.ChallengeData{}, fmt.Errorf("phone-carrier-tier: generate otp: %w", err)
	}

	key := storeKey(cc.SessionID, phoneNumber)
	expiresAt := time.Now().Add(OTPTTL)
	if err := m.store.Put(ctx, key, otp, expiresAt); err != nil {
		return types.ChallengeData{}, fmt.Errorf("phone-carrier-tier: store put: %w", err)
	}

	body := fmt.Sprintf("Your Personhood verification code: %s", otp)
	if err := m.sender.Send(ctx, phoneNumber, body); err != nil {
		_ = m.store.Invalidate(ctx, key)
		return types.ChallengeData{}, fmt.Errorf("phone-carrier-tier: send: %w", err)
	}

	return types.ChallengeData{
		Type: "otp",
		Payload: map[string]any{
			"phone_number_last4": lastFour(phoneNumber),
			"expires_in_seconds": int(OTPTTL.Seconds()),
			"max_attempts":       MaxAttempts,
			"line_type":          string(signal.LineType),
			"carrier":            signal.Carrier,
			"carrier_provider":   signal.Provider,
		},
	}, nil
}

// CompleteCeremony implements registry.Method. It expects ResponseData.Type
// "otp" and Payload {"phone_number": "...", "code": "123456"}.
func (m *Method) CompleteCeremony(ctx context.Context, cc types.CeremonyContext, resp types.ResponseData) (types.MethodResult, error) {
	if resp.Type != "otp" {
		return types.MethodResult{
			Success:     false,
			MethodID:    MethodID,
			ErrorReason: fmt.Sprintf("unexpected response type %q (expected \"otp\")", resp.Type),
		}, nil
	}

	phoneNumber, ok := stringField(resp.Payload, "phone_number")
	if !ok {
		return types.MethodResult{Success: false, MethodID: MethodID, ErrorReason: "missing or empty phone_number in response payload"}, nil
	}
	code, ok := stringField(resp.Payload, "code")
	if !ok {
		return types.MethodResult{Success: false, MethodID: MethodID, ErrorReason: "missing or empty code in response payload"}, nil
	}

	key := storeKey(cc.SessionID, phoneNumber)
	valid, attemptsRemaining, err := m.store.Verify(ctx, key, code)
	if err != nil {
		return types.MethodResult{}, fmt.Errorf("phone-carrier-tier: store verify: %w", err)
	}
	if valid {
		digest := attestationDigest(cc.SessionID, phoneNumber, code)
		return types.MethodResult{
			Success:           true,
			MethodID:          MethodID,
			VerifiedAt:        time.Now().UTC(),
			AttestationDigest: digest,
		}, nil
	}
	if attemptsRemaining == 0 {
		return types.MethodResult{Success: false, MethodID: MethodID, ErrorReason: "too_many_attempts"}, nil
	}
	return types.MethodResult{
		Success:     false,
		MethodID:    MethodID,
		ErrorReason: fmt.Sprintf("wrong_code (%d attempts remaining)", attemptsRemaining),
	}, nil
}

// HealthCheck implements registry.Method. v0.1 is a no-op success.
func (m *Method) HealthCheck(_ context.Context) error { return nil }

// generateOTP returns a uniformly-random 6-digit zero-padded OTP.
func generateOTP() (string, error) {
	n, err := rand.Int(rand.Reader, big.NewInt(1_000_000))
	if err != nil {
		return "", err
	}
	return fmt.Sprintf("%06d", n.Int64()), nil
}

// storeKey composes the per-ceremony OTPStore key from sessionID and the phone
// number, preventing cross-verification across a re-Begin under the same
// session.
func storeKey(sessionID, phoneNumber string) string {
	return sessionID + "|" + strings.TrimSpace(phoneNumber)
}

// lastFour returns the trailing 4 decimal digits of a phone number.
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
// session_id || phone_number || code triple. Lands on the credential; the raw
// phone number and code never do.
func attestationDigest(sessionID, phoneNumber, code string) string {
	h := sha256.New()
	h.Write([]byte(sessionID))
	h.Write([]byte{0})
	h.Write([]byte(strings.TrimSpace(phoneNumber)))
	h.Write([]byte{0})
	h.Write([]byte(code))
	return hex.EncodeToString(h.Sum(nil))
}

// stringField returns a non-empty trimmed string field from a payload map.
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
