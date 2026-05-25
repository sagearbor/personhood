package email

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

// methodPlugin is a local mirror of registry.Method (defined in
// github.com/sagearbor/personhood/src/registry). The registry package is being
// developed in a sibling PR (feat/registry); to keep this module compilable
// without that dependency we redeclare the contract here. Once feat/registry
// merges this interface should be replaced with a direct import of
// registry.Method and the *Method type below should be asserted against it via
// a blank-identifier var.
type methodPlugin interface {
	Metadata() types.MethodMetadata
	IsAvailableForUser(ctx types.UserContext) (available bool, reason string)
	BeginCeremony(ctx context.Context, cc types.CeremonyContext) (types.ChallengeData, error)
	CompleteCeremony(ctx context.Context, cc types.CeremonyContext, resp types.ResponseData) (types.MethodResult, error)
	HealthCheck(ctx context.Context) error
}

// ensure *Method satisfies the contract at compile time.
var _ methodPlugin = (*Method)(nil)

// Method-level tunables. Exposed as exported constants so tests and downstream
// consumers can reason about expected TTLs without reading source comments.
const (
	// TokenTTL is the lifetime of a magic-link token between BeginCeremony
	// and CompleteCeremony.
	TokenTTL = 15 * time.Minute

	// tokenBytes is the entropy of the magic-link token.
	tokenBytes = 32

	// freshnessLifetime is the on-credential freshness window the method
	// advertises.
	freshnessLifetime = 90 * 24 * time.Hour

	// methodID is the stable method identifier.
	methodID = "email"

	// methodVersion tracks the plugin implementation version.
	methodVersion = "0.1.0"

	// methodStrength is the supplementary point value (must be < 50).
	methodStrength = 8

	// magicLinkQueryParam is the URL query parameter carrying the token.
	magicLinkQueryParam = "token"

	// magicLinkSessionParam is the URL query parameter carrying the
	// SessionID; included so the click handler can correlate without
	// out-of-band state.
	magicLinkSessionParam = "session"
)

// Method implements the Personhood "email" supplementary method.
//
// It is safe for concurrent use: all per-ceremony state is stored in the
// injected TokenStore.
type Method struct {
	sender  Sender
	store   TokenStore
	baseURL string // e.g. "https://issuer.example.com/methods/email/verify"
}

// NewMethod constructs a Method. baseURL is the absolute URL the magic link
// should point at; the method appends ?token=... &session=... query
// parameters. sender delivers the email; store persists outstanding tokens.
//
// All three arguments are required; NewMethod panics on a nil sender or
// store, or on an empty baseURL — these are programmer errors rather than
// runtime conditions.
func NewMethod(sender Sender, baseURL string, store TokenStore) *Method {
	if sender == nil {
		panic("email.NewMethod: sender must not be nil")
	}
	if store == nil {
		panic("email.NewMethod: store must not be nil")
	}
	if strings.TrimSpace(baseURL) == "" {
		panic("email.NewMethod: baseURL must not be empty")
	}
	return &Method{
		sender:  sender,
		store:   store,
		baseURL: baseURL,
	}
}

// Metadata implements registry.Method.
func (m *Method) Metadata() types.MethodMetadata {
	return types.MethodMetadata{
		ID:                   methodID,
		Type:                 types.MethodTypeSupplementary,
		Strength:             methodStrength,
		CostUSD:              0,
		UXFriction:           types.FrictionLow,
		PlatformRequirements: nil,
		FreshnessLifetime:    freshnessLifetime,
		Version:              methodVersion,
	}
}

// IsAvailableForUser implements registry.Method. Email is universally
// available; every user can supply an address.
func (m *Method) IsAvailableForUser(_ types.UserContext) (bool, string) {
	return true, ""
}

// BeginCeremony implements registry.Method. It expects the email address to
// be supplied via cc by way of a higher-layer hand-off; v0.1's CeremonyContext
// has no dedicated field for this, so the issuer is expected to thread the
// address through UserID-prefixed context state or by extending
// CeremonyContext in a later revision. To keep the v0.1 surface usable, the
// caller is required to set CeremonyContext.UserID to the target email
// address. This is documented here and in INTERFACE.md.
//
// Validation steps, in order:
//  1. UserID is non-empty and parses as an email
//  2. domain is not on the disposable blocklist
//  3. a fresh 32-byte token is generated and stored with TokenTTL
//  4. the configured Sender is invoked with the constructed magic-link URL
//
// On any pre-send failure the store is left untouched and a non-nil error is
// returned. On Send failure the just-stored entry is best-effort deleted so a
// retry is not blocked by stale state.
func (m *Method) BeginCeremony(ctx context.Context, cc types.CeremonyContext) (types.ChallengeData, error) {
	emailAddr := strings.TrimSpace(cc.UserID)
	if emailAddr == "" {
		return types.ChallengeData{}, errors.New("email: CeremonyContext.UserID must carry the target email address")
	}
	if !looksLikeEmail(emailAddr) {
		return types.ChallengeData{}, fmt.Errorf("email: %q is not a valid email address", emailAddr)
	}
	if IsDisposable(emailAddr) {
		return types.ChallengeData{}, errors.New("Disposable email addresses are not accepted.")
	}

	token, err := generateToken()
	if err != nil {
		return types.ChallengeData{}, fmt.Errorf("email: generate token: %w", err)
	}

	expiresAt := time.Now().Add(TokenTTL)
	if err := m.store.Put(ctx, cc.SessionID, token, emailAddr, expiresAt); err != nil {
		return types.ChallengeData{}, fmt.Errorf("email: store put: %w", err)
	}

	linkURL, err := m.buildMagicLink(cc.SessionID, token)
	if err != nil {
		// roll back the stored token; ignore secondary error
		_ = m.store.Delete(ctx, cc.SessionID)
		return types.ChallengeData{}, fmt.Errorf("email: build magic link: %w", err)
	}

	if err := m.sender.Send(ctx, emailAddr, "Confirm your email", linkURL); err != nil {
		_ = m.store.Delete(ctx, cc.SessionID)
		return types.ChallengeData{}, fmt.Errorf("email: send: %w", err)
	}

	return types.ChallengeData{
		Type: "magic-link",
		Payload: map[string]any{
			"magic_link_url":     linkURL,
			"email_address":      emailAddr,
			"expires_in_seconds": int(TokenTTL.Seconds()),
		},
	}, nil
}

// CompleteCeremony implements registry.Method. It expects ResponseData.Type
// "magic-link-click" and Payload {"token": "..."}.
//
// A logical verification failure (wrong token, expired, missing) is returned
// as a MethodResult with Success=false and a populated ErrorReason; a non-nil
// error is reserved for internal/transport problems.
func (m *Method) CompleteCeremony(ctx context.Context, cc types.CeremonyContext, resp types.ResponseData) (types.MethodResult, error) {
	if resp.Type != "magic-link-click" {
		return types.MethodResult{
			Success:     false,
			MethodID:    methodID,
			ErrorReason: fmt.Sprintf("unexpected response type %q (expected \"magic-link-click\")", resp.Type),
		}, nil
	}

	tokenRaw, ok := resp.Payload["token"]
	if !ok {
		return types.MethodResult{
			Success:     false,
			MethodID:    methodID,
			ErrorReason: "missing token in response payload",
		}, nil
	}
	token, ok := tokenRaw.(string)
	if !ok || token == "" {
		return types.MethodResult{
			Success:     false,
			MethodID:    methodID,
			ErrorReason: "token must be a non-empty string",
		}, nil
	}

	emailAddr, found, err := m.store.Lookup(ctx, cc.SessionID, token)
	if err != nil {
		return types.MethodResult{}, fmt.Errorf("email: store lookup: %w", err)
	}
	if !found {
		return types.MethodResult{
			Success:     false,
			MethodID:    methodID,
			ErrorReason: "invalid_or_expired_token",
		}, nil
	}

	// Single-use: clear the entry on success. Best-effort; a delete failure
	// must not turn a successful verification into a failure, but log via
	// returning the result anyway.
	_ = m.store.Delete(ctx, cc.SessionID)

	digest := attestationDigest(cc.SessionID, token, emailAddr)
	return types.MethodResult{
		Success:           true,
		MethodID:          methodID,
		VerifiedAt:        time.Now().UTC(),
		AttestationDigest: digest,
	}, nil
}

// HealthCheck implements registry.Method. The in-memory store has no external
// dependency to probe; the injected Sender is opaque (cannot generically be
// pinged), so a future revision may grow a Sender.HealthCheck hook. For v0.1
// this is a no-op success.
func (m *Method) HealthCheck(_ context.Context) error {
	return nil
}

// buildMagicLink composes the URL the user clicks. It URL-escapes both the
// session and token values and preserves any existing query string on
// baseURL.
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

// looksLikeEmail is a minimal sanity check; it rejects only addresses with
// no '@' or empty local / domain parts. Strict RFC 5322 validation is left
// to a higher-layer DSL — for the supplementary method this is sufficient.
func looksLikeEmail(s string) bool {
	at := strings.LastIndex(s, "@")
	return at > 0 && at < len(s)-1 && !strings.ContainsAny(s, " \t\r\n")
}

// attestationDigest returns the hex-encoded SHA-256 over the canonical
// session_id || token || email triple. The digest is what lands on the
// issued credential; the raw token and email are never persisted on chain.
func attestationDigest(sessionID, token, emailAddr string) string {
	h := sha256.New()
	h.Write([]byte(sessionID))
	h.Write([]byte{0})
	h.Write([]byte(token))
	h.Write([]byte{0})
	h.Write([]byte(strings.ToLower(emailAddr)))
	sum := h.Sum(nil)
	return hex.EncodeToString(sum)
}
