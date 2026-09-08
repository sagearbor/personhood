package paidbillingcard

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

// StripeBaseURL is the Stripe API root.
const StripeBaseURL = "https://api.stripe.com"

// StripeClient creates SetupIntents on Stripe. A SetupIntent saves a card
// without charging it (a $0 "pre-auth"); requiring 3-D Secure (SCA) on the
// confirmation makes the card meaningfully expensive to mint at scale.
//
// All methods respect the context deadline.
type StripeClient struct {
	// SecretKey is the Stripe secret API key (sk_test_... / sk_live_...). Required.
	SecretKey string

	// BaseURL is the Stripe API root (StripeBaseURL, or an httptest server in
	// tests).
	BaseURL string

	// HTTPClient is the underlying client. If nil a 15s-timeout client is used.
	HTTPClient *http.Client

	// RequestThreeDSecure controls the request_three_d_secure hint on the
	// SetupIntent. "any" (default) forces 3DS/SCA whenever the card supports it;
	// "automatic" lets Stripe decide. Forcing it is what makes this a strong
	// supplementary signal.
	RequestThreeDSecure string
}

// NewStripeClient constructs a StripeClient. secretKey and baseURL are required.
func NewStripeClient(secretKey, baseURL string, httpClient *http.Client) (*StripeClient, error) {
	if strings.TrimSpace(secretKey) == "" {
		return nil, errors.New("paid-billing-card: Stripe SecretKey is required")
	}
	if strings.TrimSpace(baseURL) == "" {
		return nil, errors.New("paid-billing-card: Stripe BaseURL is required")
	}
	c := &StripeClient{
		SecretKey:           secretKey,
		BaseURL:             strings.TrimRight(baseURL, "/"),
		HTTPClient:          httpClient,
		RequestThreeDSecure: "any",
	}
	if c.HTTPClient == nil {
		c.HTTPClient = &http.Client{Timeout: 15 * time.Second}
	}
	return c, nil
}

// CreatedSetupIntent is the subset of Stripe's setup_intents response we use.
type CreatedSetupIntent struct {
	// ID is the SetupIntent id ("seti_..."). It is the stable handle we bind to
	// the session and that the webhook echoes.
	ID string

	// ClientSecret is handed to the client so Stripe.js / the mobile SDK can
	// confirm the card (and run the 3DS challenge) without the secret key.
	ClientSecret string

	// Status is the verbatim initial status (e.g. "requires_payment_method").
	Status string
}

// CreateSetupIntent creates a $0 SetupIntent bound to clientReferenceID (the
// Personhood session id, recorded in metadata so the webhook can resolve back
// to the session). usage=off_session + request_three_d_secure enforce the SCA
// challenge.
func (c *StripeClient) CreateSetupIntent(ctx context.Context, clientReferenceID string) (CreatedSetupIntent, error) {
	form := url.Values{}
	form.Set("usage", "off_session")
	form.Set("payment_method_types[]", "card")
	form.Set("payment_method_options[card][request_three_d_secure]", c.RequestThreeDSecure)
	// metadata.session_id is how the webhook maps the event back to our session.
	form.Set("metadata[session_id]", clientReferenceID)

	httpReq, err := http.NewRequestWithContext(ctx, http.MethodPost, c.BaseURL+"/v1/setup_intents", strings.NewReader(form.Encode()))
	if err != nil {
		return CreatedSetupIntent{}, fmt.Errorf("paid-billing-card: build request: %w", err)
	}
	httpReq.Header.Set("Authorization", "Bearer "+c.SecretKey)
	httpReq.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	httpReq.Header.Set("Accept", "application/json")

	resp, err := c.HTTPClient.Do(httpReq)
	if err != nil {
		return CreatedSetupIntent{}, fmt.Errorf("paid-billing-card: setup_intents create: %w", err)
	}
	defer resp.Body.Close()
	rawBody, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<20))

	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return CreatedSetupIntent{}, fmt.Errorf("paid-billing-card: setup_intents create returned %d: %s", resp.StatusCode, excerpt(rawBody))
	}

	var sr struct {
		ID           string `json:"id"`
		ClientSecret string `json:"client_secret"`
		Status       string `json:"status"`
	}
	if err := json.Unmarshal(rawBody, &sr); err != nil {
		return CreatedSetupIntent{}, fmt.Errorf("paid-billing-card: decode setup_intents: %w (body: %s)", err, excerpt(rawBody))
	}
	if sr.ID == "" || sr.ClientSecret == "" {
		return CreatedSetupIntent{}, fmt.Errorf("paid-billing-card: setup_intents returned empty id/client_secret (body: %s)", excerpt(rawBody))
	}
	return CreatedSetupIntent{ID: sr.ID, ClientSecret: sr.ClientSecret, Status: sr.Status}, nil
}

func excerpt(b []byte) string {
	const max = 200
	if len(b) <= max {
		return string(b)
	}
	return string(b[:max]) + "...(truncated)"
}
