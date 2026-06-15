package plaidbanklink

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"
)

// PlaidBaseURLSandbox / Development / Production are the Plaid API roots. The
// caller picks one explicitly; there is no implicit default environment.
const (
	PlaidBaseURLSandbox    = "https://sandbox.plaid.com"
	PlaidBaseURLProduction = "https://production.plaid.com"
)

// PlaidClient calls the Plaid /link/token/create endpoint to start a Hosted
// Link session. All methods respect the context deadline.
type PlaidClient struct {
	// HTTPClient is the underlying client. If nil, a 15s-timeout client is used.
	HTTPClient *http.Client

	// ClientID and Secret are the Plaid API credentials.
	ClientID string
	Secret   string

	// BaseURL is the Plaid environment root (PlaidBaseURLSandbox / Production,
	// or an httptest server in tests).
	BaseURL string

	// TemplateID, if set, selects a Plaid IDV / Link template. Optional.
	TemplateID string

	// Products are the Plaid products to request (default ["auth", "identity"]).
	Products []string

	// WebhookURL is the absolute URL Plaid POSTs session webhooks to.
	WebhookURL string
}

// NewPlaidClient constructs a PlaidClient. clientID, secret, and baseURL are
// required.
func NewPlaidClient(clientID, secret, baseURL string, httpClient *http.Client) (*PlaidClient, error) {
	if strings.TrimSpace(clientID) == "" {
		return nil, errors.New("plaid: ClientID is required")
	}
	if strings.TrimSpace(secret) == "" {
		return nil, errors.New("plaid: Secret is required")
	}
	if strings.TrimSpace(baseURL) == "" {
		return nil, errors.New("plaid: BaseURL is required")
	}
	c := &PlaidClient{
		ClientID:   clientID,
		Secret:     secret,
		BaseURL:    strings.TrimRight(baseURL, "/"),
		HTTPClient: httpClient,
		Products:   []string{"auth", "identity"},
	}
	if c.HTTPClient == nil {
		c.HTTPClient = &http.Client{Timeout: 15 * time.Second}
	}
	return c, nil
}

// CreatedLinkSession is the subset of Plaid's link/token/create response we use.
type CreatedLinkSession struct {
	// LinkToken is the Plaid link token (e.g. "link-sandbox-..."). It is the
	// stable handle we bind to the session and that the webhook echoes.
	LinkToken string

	// HostedLinkURL is the URL the end-user opens to complete bank linking on
	// Plaid's domain (Hosted Link).
	HostedLinkURL string

	// Expiration is the RFC3339 expiry of the link token, verbatim from Plaid.
	Expiration string
}

// CreateLinkSession creates a Plaid Hosted Link session bound to clientUserID
// (the Personhood session id). The returned LinkToken must be recorded in
// ResultStore so the webhook handler can resolve events back to this session.
func (c *PlaidClient) CreateLinkSession(ctx context.Context, clientUserID string) (CreatedLinkSession, error) {
	type user struct {
		ClientUserID string `json:"client_user_id"`
	}
	// hosted_link being present (even empty) opts the token into Hosted Link,
	// which makes Plaid return a hosted_link_url.
	type hostedLink struct {
		CompletionRedirectURI string `json:"completion_redirect_uri,omitempty"`
	}
	reqBody := map[string]any{
		"client_id":     c.ClientID,
		"secret":        c.Secret,
		"client_name":   "Personhood",
		"language":      "en",
		"country_codes": []string{"US"},
		"user":          user{ClientUserID: clientUserID},
		"products":      c.Products,
		"hosted_link":   hostedLink{},
	}
	if c.TemplateID != "" {
		reqBody["template_id"] = c.TemplateID
	}
	if c.WebhookURL != "" {
		reqBody["webhook"] = c.WebhookURL
	}

	body, err := json.Marshal(reqBody)
	if err != nil {
		return CreatedLinkSession{}, fmt.Errorf("plaid: marshal link-token-create: %w", err)
	}
	httpReq, err := http.NewRequestWithContext(ctx, http.MethodPost, c.BaseURL+"/link/token/create", bytes.NewReader(body))
	if err != nil {
		return CreatedLinkSession{}, fmt.Errorf("plaid: build request: %w", err)
	}
	httpReq.Header.Set("Content-Type", "application/json")
	httpReq.Header.Set("Accept", "application/json")

	resp, err := c.HTTPClient.Do(httpReq)
	if err != nil {
		return CreatedLinkSession{}, fmt.Errorf("plaid: link-token-create: %w", err)
	}
	defer resp.Body.Close()
	rawBody, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<20))

	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return CreatedLinkSession{}, fmt.Errorf("plaid: link-token-create returned %d: %s", resp.StatusCode, excerpt(rawBody))
	}

	var wr struct {
		LinkToken     string `json:"link_token"`
		HostedLinkURL string `json:"hosted_link_url"`
		Expiration    string `json:"expiration"`
	}
	if err := json.Unmarshal(rawBody, &wr); err != nil {
		return CreatedLinkSession{}, fmt.Errorf("plaid: decode link-token-create: %w (body: %s)", err, excerpt(rawBody))
	}
	if wr.LinkToken == "" {
		return CreatedLinkSession{}, fmt.Errorf("plaid: link-token-create returned empty link_token (body: %s)", excerpt(rawBody))
	}
	if wr.HostedLinkURL == "" {
		return CreatedLinkSession{}, fmt.Errorf("plaid: link-token-create returned no hosted_link_url; is Hosted Link enabled? (body: %s)", excerpt(rawBody))
	}
	return CreatedLinkSession{
		LinkToken:     wr.LinkToken,
		HostedLinkURL: wr.HostedLinkURL,
		Expiration:    wr.Expiration,
	}, nil
}

func excerpt(b []byte) string {
	const max = 200
	if len(b) <= max {
		return string(b)
	}
	return string(b[:max]) + "...(truncated)"
}
