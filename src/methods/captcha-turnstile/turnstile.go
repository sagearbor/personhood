package captchaturnstile

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"
)

// DefaultBaseURL is the Cloudflare Turnstile API root. The siteverify endpoint
// lives at BaseURL + "/siteverify".
const DefaultBaseURL = "https://challenges.cloudflare.com/turnstile/v0"

// TurnstileClient calls Cloudflare's Turnstile /siteverify endpoint to validate
// a token produced by the client-side widget. All calls respect the context
// deadline.
type TurnstileClient struct {
	// HTTPClient is the underlying client. If nil, a 15s-timeout client is used.
	HTTPClient *http.Client

	// SecretKey is the Turnstile server-side secret (never sent to the client).
	SecretKey string

	// SiteKey is the public Turnstile site key embedded in the client widget.
	SiteKey string

	// BaseURL is the Turnstile API root (DefaultBaseURL, or an httptest server
	// in tests).
	BaseURL string
}

// NewTurnstileClient constructs a TurnstileClient. siteKey and secretKey are
// required. BaseURL defaults to DefaultBaseURL and httpClient defaults to a
// 15s-timeout client.
func NewTurnstileClient(siteKey, secretKey string, httpClient *http.Client) (*TurnstileClient, error) {
	if strings.TrimSpace(siteKey) == "" {
		return nil, errors.New("turnstile: SiteKey is required")
	}
	if strings.TrimSpace(secretKey) == "" {
		return nil, errors.New("turnstile: SecretKey is required")
	}
	c := &TurnstileClient{
		HTTPClient: httpClient,
		SecretKey:  secretKey,
		SiteKey:    siteKey,
		BaseURL:    DefaultBaseURL,
	}
	if c.HTTPClient == nil {
		c.HTTPClient = &http.Client{Timeout: 15 * time.Second}
	}
	return c, nil
}

// SiteVerifyResult is the subset of Cloudflare's siteverify response we use.
type SiteVerifyResult struct {
	// Success reports whether the token was valid.
	Success bool `json:"success"`

	// ErrorCodes carries Cloudflare's machine-readable failure codes.
	ErrorCodes []string `json:"error-codes"`

	// ChallengeTS is the RFC3339 timestamp of the challenge, verbatim.
	ChallengeTS string `json:"challenge_ts"`

	// Hostname is the hostname the challenge was solved on.
	Hostname string `json:"hostname"`
}

// SiteVerify POSTs the token to BaseURL + "/siteverify" as
// application/x-www-form-urlencoded and parses the JSON response. remoteIP is
// optional (pass "" to omit). An HTTP/transport error or non-2xx status is
// returned as an error so the caller can treat it as an unattributable failure.
func (c *TurnstileClient) SiteVerify(ctx context.Context, token, remoteIP string) (SiteVerifyResult, error) {
	form := url.Values{}
	form.Set("secret", c.SecretKey)
	form.Set("response", token)
	if remoteIP != "" {
		form.Set("remoteip", remoteIP)
	}

	httpReq, err := http.NewRequestWithContext(ctx, http.MethodPost, c.BaseURL+"/siteverify", strings.NewReader(form.Encode()))
	if err != nil {
		return SiteVerifyResult{}, fmt.Errorf("turnstile: build request: %w", err)
	}
	httpReq.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	httpReq.Header.Set("Accept", "application/json")

	resp, err := c.HTTPClient.Do(httpReq)
	if err != nil {
		return SiteVerifyResult{}, fmt.Errorf("turnstile: siteverify: %w", err)
	}
	defer resp.Body.Close()
	rawBody, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<20))

	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return SiteVerifyResult{}, fmt.Errorf("turnstile: siteverify returned %d: %s", resp.StatusCode, excerpt(rawBody))
	}

	var out SiteVerifyResult
	if err := json.Unmarshal(rawBody, &out); err != nil {
		return SiteVerifyResult{}, fmt.Errorf("turnstile: decode siteverify: %w (body: %s)", err, excerpt(rawBody))
	}
	return out, nil
}

func excerpt(b []byte) string {
	const max = 200
	if len(b) <= max {
		return string(b)
	}
	return string(b[:max]) + "...(truncated)"
}
