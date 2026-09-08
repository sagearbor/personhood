// Package emailtier implements the Personhood "email-tier" supplementary
// verification method: the same magic-link inbox-control ceremony as the plain
// "email" method, upgraded with an enrichment signal (domain reputation +
// HaveIBeenPwned breach-presence).
//
// Per docs/06-methods-catalog.md this is the strength-22 upgrade for the
// strength-8 "email" method. Same UX and near-same cost (~$0.005 for the HIBP
// lookup), much better signal: inbox control alone is trivially Sybil'd with
// throwaway addresses, whereas domain reputation + breach-presence raise the
// bar to "a long-lived mailbox a real person actually uses".
//
// Strength rationale: the strength-22 rating assumes a real EnrichmentProvider
// (HIBPProvider) is wired. Built with the dev-default NeutralProvider it
// performs no external lookups and is effectively plain-email strength; the
// server wiring logs a warning in that case. This mirrors the repo convention
// for ip-asn-reputation and app-attest-device, which ship a safe default
// provider and advertise the catalog strength.
package emailtier

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"net/url"
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
	// TokenTTL is the lifetime of a magic-link token between Begin and Complete.
	TokenTTL = 15 * time.Minute

	// tokenBytes is the entropy of the magic-link token.
	tokenBytes = 32

	// freshnessLifetime is the on-credential freshness window the method
	// advertises.
	freshnessLifetime = 90 * 24 * time.Hour

	// MethodID is the stable method identifier.
	MethodID = "email-tier"

	// MethodVersion tracks the plugin implementation version.
	MethodVersion = "0.1.0"

	// MethodStrength is the supplementary point value (must be < 50). 22 per the
	// methods catalog; earned when a real EnrichmentProvider is wired.
	MethodStrength = 22

	// MethodCostUSD is the illustrative per-verification cost (~$0.005 HIBP).
	MethodCostUSD = 0.005

	magicLinkQueryParam   = "token"
	magicLinkSessionParam = "session"
)

// Method implements the Personhood "email-tier" supplementary method. Safe for
// concurrent use: all per-ceremony state lives in the injected TokenStore.
type Method struct {
	sender   Sender
	store    TokenStore
	provider EnrichmentProvider
	baseURL  string
}

// Config bundles NewMethod's dependencies.
type Config struct {
	// Sender delivers the magic-link email. Required.
	Sender Sender

	// BaseURL is the absolute URL the magic link points at. Required.
	BaseURL string

	// Store persists outstanding tokens. Required.
	Store TokenStore

	// Provider scores the address. If nil, NeutralProvider{} is used (dev
	// default; no external lookups).
	Provider EnrichmentProvider
}

// NewMethod constructs a Method. Sender, BaseURL, and Store are required; a nil
// or empty value is a programmer error and panics. A nil Provider defaults to
// NeutralProvider.
func NewMethod(cfg Config) *Method {
	if cfg.Sender == nil {
		panic("email-tier.NewMethod: Sender must not be nil")
	}
	if cfg.Store == nil {
		panic("email-tier.NewMethod: Store must not be nil")
	}
	if strings.TrimSpace(cfg.BaseURL) == "" {
		panic("email-tier.NewMethod: BaseURL must not be empty")
	}
	provider := cfg.Provider
	if provider == nil {
		provider = NeutralProvider{}
	}
	return &Method{
		sender:   cfg.Sender,
		store:    cfg.Store,
		provider: provider,
		baseURL:  cfg.BaseURL,
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
		FreshnessLifetime: freshnessLifetime,
		Version:           MethodVersion,
	}
}

// ProviderName reports the name of the active EnrichmentProvider. The server
// wiring uses this to warn when the dev-default NeutralProvider is in use.
func (m *Method) ProviderName() string { return m.provider.Name() }

// IsAvailableForUser implements registry.Method. Email is universally
// available; every user can supply an address.
func (m *Method) IsAvailableForUser(_ types.UserContext) (bool, string) {
	return true, ""
}

// BeginCeremony implements registry.Method. The target email address is
// carried in CeremonyContext.UserID (the same v0.1 convention as the email and
// sms methods).
//
// Steps:
//  1. UserID is non-empty and parses as an email
//  2. enrichment runs; a disposable domain (static list OR provider flag)
//     rejects the address
//  3. a fresh 32-byte token is stored together with the captured Signal
//  4. the Sender is invoked with the magic-link URL
func (m *Method) BeginCeremony(ctx context.Context, cc types.CeremonyContext) (types.ChallengeData, error) {
	emailAddr := strings.TrimSpace(cc.UserID)
	if emailAddr == "" {
		return types.ChallengeData{}, errors.New("email-tier: CeremonyContext.UserID must carry the target email address")
	}
	if !looksLikeEmail(emailAddr) {
		return types.ChallengeData{}, fmt.Errorf("email-tier: %q is not a valid email address", emailAddr)
	}

	signal, err := m.provider.Enrich(ctx, emailAddr)
	if err != nil {
		return types.ChallengeData{}, fmt.Errorf("email-tier: enrich: %w", err)
	}
	if signal.DomainDisposable {
		return types.ChallengeData{}, errors.New("Disposable email addresses are not accepted.")
	}

	token, err := generateToken()
	if err != nil {
		return types.ChallengeData{}, fmt.Errorf("email-tier: generate token: %w", err)
	}

	expiresAt := time.Now().Add(TokenTTL)
	if err := m.store.Put(ctx, cc.SessionID, token, emailAddr, signal, expiresAt); err != nil {
		return types.ChallengeData{}, fmt.Errorf("email-tier: store put: %w", err)
	}

	linkURL, err := m.buildMagicLink(cc.SessionID, token)
	if err != nil {
		_ = m.store.Delete(ctx, cc.SessionID)
		return types.ChallengeData{}, fmt.Errorf("email-tier: build magic link: %w", err)
	}

	if err := m.sender.Send(ctx, emailAddr, "Confirm your email", linkURL); err != nil {
		_ = m.store.Delete(ctx, cc.SessionID)
		return types.ChallengeData{}, fmt.Errorf("email-tier: send: %w", err)
	}

	return types.ChallengeData{
		Type: "magic-link",
		Payload: map[string]any{
			"magic_link_url":      linkURL,
			"email_address":       emailAddr,
			"expires_in_seconds":  int(TokenTTL.Seconds()),
			"domain_reputation":   signal.DomainReputation,
			"breach_presence":     signal.BreachPresence,
			"enrichment_provider": signal.Provider,
		},
	}, nil
}

// CompleteCeremony implements registry.Method. It expects ResponseData.Type
// "magic-link-click" and Payload {"token": "..."}.
func (m *Method) CompleteCeremony(ctx context.Context, cc types.CeremonyContext, resp types.ResponseData) (types.MethodResult, error) {
	if resp.Type != "magic-link-click" {
		return types.MethodResult{
			Success:     false,
			MethodID:    MethodID,
			ErrorReason: fmt.Sprintf("unexpected response type %q (expected \"magic-link-click\")", resp.Type),
		}, nil
	}

	tokenRaw, ok := resp.Payload["token"]
	if !ok {
		return types.MethodResult{Success: false, MethodID: MethodID, ErrorReason: "missing token in response payload"}, nil
	}
	token, ok := tokenRaw.(string)
	if !ok || token == "" {
		return types.MethodResult{Success: false, MethodID: MethodID, ErrorReason: "token must be a non-empty string"}, nil
	}

	emailAddr, signal, found, err := m.store.Lookup(ctx, cc.SessionID, token)
	if err != nil {
		return types.MethodResult{}, fmt.Errorf("email-tier: store lookup: %w", err)
	}
	if !found {
		return types.MethodResult{Success: false, MethodID: MethodID, ErrorReason: "invalid_or_expired_token"}, nil
	}

	// Single-use: clear on success. Best-effort.
	_ = m.store.Delete(ctx, cc.SessionID)

	digest := attestationDigest(cc.SessionID, token, emailAddr, signal)
	return types.MethodResult{
		Success:           true,
		MethodID:          MethodID,
		VerifiedAt:        time.Now().UTC(),
		AttestationDigest: digest,
	}, nil
}

// HealthCheck implements registry.Method. v0.1 is a no-op success: the
// in-memory store has no dependency to probe and the provider is opaque.
func (m *Method) HealthCheck(_ context.Context) error { return nil }

// buildMagicLink composes the clickable URL, URL-escaping the session and token
// and preserving any existing query string on baseURL.
func (m *Method) buildMagicLink(sessionID, token string) (string, error) {
	u, err := url.Parse(m.baseURL)
	if err != nil {
		return "", err
	}
	q := u.Query()
	q.Set(magicLinkSessionParam, sessionID)
	q.Set(magicLinkQueryParam, token)
	u.RawQuery = q.Encode()
	return u.String(), nil
}

// generateToken returns a 32-byte base64url (no padding) random string.
func generateToken() (string, error) {
	buf := make([]byte, tokenBytes)
	if _, err := rand.Read(buf); err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(buf), nil
}

// looksLikeEmail is a minimal sanity check; strict RFC 5322 validation is left
// to a higher layer.
func looksLikeEmail(s string) bool {
	at := strings.LastIndex(s, "@")
	return at > 0 && at < len(s)-1 && !strings.ContainsAny(s, " \t\r\n")
}

// attestationDigest is the SHA-256 over the canonical
// session_id || token || email || reputation || breach triple+. It binds the
// captured enrichment Signal into the credential's attestation digest so an
// auditor can later confirm which tier signals were present, without the raw
// address ever landing on the credential.
func attestationDigest(sessionID, token, emailAddr string, signal Signal) string {
	h := sha256.New()
	h.Write([]byte(sessionID))
	h.Write([]byte{0})
	h.Write([]byte(token))
	h.Write([]byte{0})
	h.Write([]byte(strings.ToLower(strings.TrimSpace(emailAddr))))
	h.Write([]byte{0})
	h.Write([]byte(fmt.Sprintf("rep=%d;breach=%t;n=%d;p=%s", signal.DomainReputation, signal.BreachPresence, signal.BreachCount, signal.Provider)))
	return hex.EncodeToString(h.Sum(nil))
}
