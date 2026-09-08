package emailtier

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"
)

// Signal is the enrichment outcome for a single email address. It is the
// "tier" in email-tier: the magic-link ceremony only proves inbox control;
// the Signal is what distinguishes a long-lived human mailbox from a
// freshly-minted bot address.
type Signal struct {
	// DomainReputation is a coarse score in [0,100]; higher is more reputable.
	// 50 means "unknown / neutral". Computed by a deterministic local
	// classifier (see DomainReputation); no external call is required.
	DomainReputation int `json:"domain_reputation"`

	// DomainDisposable reports whether the domain is a known disposable /
	// throwaway provider. A true value causes the method to reject the address.
	DomainDisposable bool `json:"domain_disposable"`

	// BreachPresence reports whether the address appears in known historical
	// data breaches (HaveIBeenPwned). Counter-intuitively this is a *positive*
	// personhood signal: a throwaway address minted moments ago is absent from
	// years-old breach corpora, whereas a real long-lived human address very
	// often appears in at least one. The neutral provider leaves this false.
	BreachPresence bool `json:"breach_presence"`

	// BreachCount is the number of distinct breaches the address appears in
	// (0 when none, or when the provider cannot determine it).
	BreachCount int `json:"breach_count"`

	// Provider names the EnrichmentProvider that produced this Signal.
	Provider string `json:"provider"`
}

// EnrichmentProvider scores an email address beyond mere inbox control.
//
// Implementations MUST be safe for concurrent use and MUST respect the
// context deadline. A non-nil error indicates a transport/internal failure;
// providers should NOT return an error merely because they have no signal for
// an address (return a neutral Signal instead).
type EnrichmentProvider interface {
	Enrich(ctx context.Context, email string) (Signal, error)
	Name() string
}

// NeutralProvider is the dev / test default. It performs no external lookups:
// it applies only the deterministic local DomainReputation classifier and
// reports no breach data. A method built with NeutralProvider behaves like the
// plain "email" method — production deployments are expected to wire the
// HIBPProvider (or another real provider) so the strength-22 rating is earned.
//
// This mirrors the repo convention used by ip-asn-reputation (default "clean"
// provider) and app-attest-device (dev HMAC verifier): ship a safe default,
// wire the real provider via env.
type NeutralProvider struct{}

// Enrich implements EnrichmentProvider.
func (NeutralProvider) Enrich(_ context.Context, email string) (Signal, error) {
	domain := domainOf(email)
	return Signal{
		DomainReputation: DomainReputation(domain),
		DomainDisposable: IsDisposable(email),
		Provider:         "neutral",
	}, nil
}

// Name implements EnrichmentProvider.
func (NeutralProvider) Name() string { return "neutral" }

// HIBPBaseURL is the HaveIBeenPwned API v3 root.
const HIBPBaseURL = "https://haveibeenpwned.com/api/v3"

// HIBPProvider queries HaveIBeenPwned's breachedaccount endpoint for
// breach-presence and combines it with the local DomainReputation classifier.
//
// HIBP requires an API key (hibp-api-key header) and a descriptive
// user-agent. A 404 from HIBP means "no breaches" (a weaker personhood signal),
// not an error.
type HIBPProvider struct {
	// APIKey is the HIBP subscription key. Required.
	APIKey string

	// UserAgent is sent on every request; HIBP rejects requests without one.
	// Defaults to "personhood-email-tier" when empty.
	UserAgent string

	// BaseURL overrides HIBPBaseURL (used by tests). Defaults to HIBPBaseURL.
	BaseURL string

	// HTTPClient is the underlying client. If nil a 10s-timeout client is used.
	HTTPClient *http.Client
}

// NewHIBPProvider constructs an HIBPProvider. apiKey is required.
func NewHIBPProvider(apiKey string, httpClient *http.Client) (*HIBPProvider, error) {
	if strings.TrimSpace(apiKey) == "" {
		return nil, fmt.Errorf("email-tier: HIBP API key is required")
	}
	p := &HIBPProvider{
		APIKey:     apiKey,
		UserAgent:  "personhood-email-tier",
		BaseURL:    HIBPBaseURL,
		HTTPClient: httpClient,
	}
	if p.HTTPClient == nil {
		p.HTTPClient = &http.Client{Timeout: 10 * time.Second}
	}
	return p, nil
}

// Name implements EnrichmentProvider.
func (p *HIBPProvider) Name() string { return "haveibeenpwned" }

// Enrich implements EnrichmentProvider. It returns the local domain reputation
// plus HIBP breach presence. A 404 (no breaches) yields BreachPresence=false
// with a nil error; any other non-2xx is a transport error.
func (p *HIBPProvider) Enrich(ctx context.Context, email string) (Signal, error) {
	sig := Signal{
		DomainReputation: DomainReputation(domainOf(email)),
		DomainDisposable: IsDisposable(email),
		Provider:         p.Name(),
	}

	endpoint := strings.TrimRight(p.BaseURL, "/") + "/breachedaccount/" + url.PathEscape(strings.ToLower(strings.TrimSpace(email))) + "?truncateResponse=true"
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, endpoint, nil)
	if err != nil {
		return sig, fmt.Errorf("email-tier: build HIBP request: %w", err)
	}
	req.Header.Set("hibp-api-key", p.APIKey)
	req.Header.Set("user-agent", p.UserAgent)
	req.Header.Set("Accept", "application/json")

	resp, err := p.HTTPClient.Do(req)
	if err != nil {
		return sig, fmt.Errorf("email-tier: HIBP request: %w", err)
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<20))

	switch resp.StatusCode {
	case http.StatusNotFound:
		// No breaches on record — valid, weaker signal.
		return sig, nil
	case http.StatusOK:
		var breaches []struct {
			Name string `json:"Name"`
		}
		if err := json.Unmarshal(body, &breaches); err != nil {
			return sig, fmt.Errorf("email-tier: decode HIBP response: %w", err)
		}
		sig.BreachPresence = len(breaches) > 0
		sig.BreachCount = len(breaches)
		return sig, nil
	default:
		return sig, fmt.Errorf("email-tier: HIBP returned %d: %s", resp.StatusCode, excerpt(body))
	}
}

// majorMailboxProviders are large consumer mailbox providers. Membership is a
// mild positive signal (a real, generally rate-limited mailbox) but not a
// strong one — bots use Gmail too — so they score moderately, not maximally.
var majorMailboxProviders = map[string]int{
	"gmail.com":      60,
	"googlemail.com": 60,
	"outlook.com":    60,
	"hotmail.com":    58,
	"live.com":       58,
	"yahoo.com":      55,
	"ymail.com":      55,
	"icloud.com":     62,
	"me.com":         62,
	"proton.me":      60,
	"protonmail.com": 60,
	"aol.com":        50,
	"gmx.com":        52,
	"zoho.com":       55,
}

// DomainReputation is a deterministic, offline reputation classifier in
// [0,100]. It deliberately makes no network calls so it is cheap, testable,
// and privacy-preserving. Production deployments wanting a richer score can
// implement their own EnrichmentProvider; this is the floor.
//
// Scoring:
//   - disposable domain                 -> 0
//   - known major mailbox provider      -> 50–62 (see table)
//   - corporate-looking custom domain   -> 55 (not free-mail, not disposable)
//   - everything else / unknown         -> 50 (neutral)
func DomainReputation(domain string) int {
	domain = strings.ToLower(strings.TrimSpace(domain))
	if domain == "" {
		return 50
	}
	if _, ok := disposableDomains[domain]; ok {
		return 0
	}
	if score, ok := majorMailboxProviders[domain]; ok {
		return score
	}
	// A custom domain (not free-mail, not disposable) tends to indicate a real
	// organization or an individual who controls their own domain — a mild
	// positive over an anonymous free mailbox.
	return 55
}

// domainOf returns the lowercased domain part of an email address, or "" if
// the address is malformed.
func domainOf(email string) string {
	email = strings.ToLower(strings.TrimSpace(email))
	at := strings.LastIndex(email, "@")
	if at <= 0 || at == len(email)-1 {
		return ""
	}
	return email[at+1:]
}

func excerpt(b []byte) string {
	const max = 200
	if len(b) <= max {
		return string(b)
	}
	return string(b[:max]) + "...(truncated)"
}
