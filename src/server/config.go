// Package server provides the Personhood reference REST issuer.
//
// It wires together the method registry (src/registry), credential signer
// (src/credential), policy evaluator (src/policy), and the supplementary
// method plugins (src/methods/email, src/methods/sms) into HTTP endpoints
// exposed under the routes documented in README.md.
//
// One Server value owns the issuer-private signing key, the in-memory session
// store, and the method registry it was constructed with. It is safe to share
// across goroutines; net/http calls into Server's handlers concurrently.
//
// The v0.1 reference deployment is single-process and in-memory: sessions and
// method-store state vanish on restart. Production deployments should swap
// SessionStore + the per-method stores for Redis-backed implementations.
package server

import (
	"crypto/ed25519"
	"encoding/base64"
	"errors"
	"fmt"
	"net/url"
	"os"
	"strings"
	"time"
)

// Config holds all runtime tunables the server needs to start.
//
// The zero value is NOT valid — call LoadConfigFromEnv (or construct one
// directly and call Validate) before passing to NewServer.
type Config struct {
	// Addr is the address net/http.ListenAndServe binds to. Example ":8080".
	Addr string

	// PublicURL is the absolute URL the server is reachable at from a browser.
	// Used to (a) construct magic-link URLs the email method emails out,
	// (b) build the issuer DID (did:web:<host-of-PublicURL>),
	// (c) build absolute URLs in DID document + status list responses.
	//
	// In local dev this is typically "http://localhost:8080"; in prod it is
	// the deploy URL such as "https://personhood.fly.dev".
	PublicURL string

	// IssuerPrivateKey is the Ed25519 private key the issuer signs credentials
	// with. Must be exactly ed25519.PrivateKeySize (64) bytes.
	IssuerPrivateKey ed25519.PrivateKey

	// CORSAllowedOrigins is the comma-split allowlist of browser origins the
	// web app may call from. Empty means "no CORS allowlist" (server only
	// answers same-origin requests, which is the strict default).
	CORSAllowedOrigins []string

	// SessionTTL is how long a single enrollment session is valid before its
	// state is garbage-collected.
	SessionTTL time.Duration
}

// LoadConfigFromEnv reads the canonical environment variables documented in
// env.example and returns a populated Config. Missing required variables
// return an error; missing optional variables fall back to sensible defaults.
//
// Required:
//   - ISSUER_ED25519_SK_B64 (base64-encoded 32-byte seed or 64-byte private
//     key; both forms are accepted)
//
// Optional with defaults:
//   - SERVER_ADDR           default ":8080"
//   - SERVER_PUBLIC_URL     default "http://localhost:8080"
//   - CORS_ALLOWED_ORIGINS  default "http://localhost:3000"
//   - SESSION_TTL_MINUTES   default 60
func LoadConfigFromEnv() (Config, error) {
	cfg := Config{
		Addr:               firstNonEmpty(os.Getenv("SERVER_ADDR"), ":8080"),
		PublicURL:          firstNonEmpty(os.Getenv("SERVER_PUBLIC_URL"), "http://localhost:8080"),
		CORSAllowedOrigins: splitCSV(firstNonEmpty(os.Getenv("CORS_ALLOWED_ORIGINS"), "http://localhost:3000")),
		SessionTTL:         60 * time.Minute,
	}

	if m := os.Getenv("SESSION_TTL_MINUTES"); m != "" {
		mins, err := time.ParseDuration(m + "m")
		if err != nil {
			return Config{}, fmt.Errorf("SESSION_TTL_MINUTES: %w", err)
		}
		cfg.SessionTTL = mins
	}

	skB64 := os.Getenv("ISSUER_ED25519_SK_B64")
	if skB64 == "" {
		return Config{}, errors.New("ISSUER_ED25519_SK_B64 is required (generate with `go run ./src/server/cmd/gen-key`)")
	}
	priv, err := DecodeIssuerKey(skB64)
	if err != nil {
		return Config{}, fmt.Errorf("ISSUER_ED25519_SK_B64: %w", err)
	}
	cfg.IssuerPrivateKey = priv

	if err := cfg.Validate(); err != nil {
		return Config{}, err
	}
	return cfg, nil
}

// Validate reports a non-nil error if cfg is missing required fields or has
// inconsistent values. NewServer calls Validate itself; callers may call it
// earlier to fail fast in init paths.
func (c *Config) Validate() error {
	if c.Addr == "" {
		return errors.New("server: Config.Addr is required")
	}
	if c.PublicURL == "" {
		return errors.New("server: Config.PublicURL is required")
	}
	if _, err := url.Parse(c.PublicURL); err != nil {
		return fmt.Errorf("server: Config.PublicURL is not a URL: %w", err)
	}
	if len(c.IssuerPrivateKey) != ed25519.PrivateKeySize {
		return fmt.Errorf("server: Config.IssuerPrivateKey must be %d bytes, got %d", ed25519.PrivateKeySize, len(c.IssuerPrivateKey))
	}
	if c.SessionTTL <= 0 {
		return errors.New("server: Config.SessionTTL must be positive")
	}
	return nil
}

// DecodeIssuerKey decodes a base64-encoded Ed25519 private key.
//
// It accepts both 32-byte seeds (the form gen-key writes) and 64-byte full
// private keys (the form ed25519.NewKeyFromSeed expands a seed into). Either
// padded or unpadded base64 is tolerated.
func DecodeIssuerKey(b64 string) (ed25519.PrivateKey, error) {
	raw, err := decodeB64Tolerant(b64)
	if err != nil {
		return nil, fmt.Errorf("decode base64: %w", err)
	}
	switch len(raw) {
	case ed25519.SeedSize:
		return ed25519.NewKeyFromSeed(raw), nil
	case ed25519.PrivateKeySize:
		return ed25519.PrivateKey(raw), nil
	default:
		return nil, fmt.Errorf("expected %d (seed) or %d (full) bytes, got %d",
			ed25519.SeedSize, ed25519.PrivateKeySize, len(raw))
	}
}

// EncodeSeed returns the base64url (no padding) form of the 32-byte seed
// underlying priv. Useful for printing a freshly generated key to stdout.
func EncodeSeed(priv ed25519.PrivateKey) string {
	return base64.RawURLEncoding.EncodeToString(priv.Seed())
}

func decodeB64Tolerant(s string) ([]byte, error) {
	s = strings.TrimSpace(s)
	for _, enc := range []*base64.Encoding{
		base64.RawURLEncoding, base64.URLEncoding,
		base64.RawStdEncoding, base64.StdEncoding,
	} {
		if b, err := enc.DecodeString(s); err == nil {
			return b, nil
		}
	}
	return nil, errors.New("not valid base64 (tried url/std, padded/unpadded)")
}

func firstNonEmpty(xs ...string) string {
	for _, s := range xs {
		if strings.TrimSpace(s) != "" {
			return s
		}
	}
	return ""
}

func splitCSV(s string) []string {
	if strings.TrimSpace(s) == "" {
		return nil
	}
	parts := strings.Split(s, ",")
	out := make([]string, 0, len(parts))
	for _, p := range parts {
		if p = strings.TrimSpace(p); p != "" {
			out = append(out, p)
		}
	}
	return out
}
