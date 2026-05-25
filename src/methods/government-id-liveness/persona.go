package governmentidliveness

import (
	"bytes"
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

// PersonaBaseURL is the default Persona REST API root.
// Sandbox and production share the same URL; the API key prefix
// (persona_sandbox_ vs persona_production_) selects the environment.
const PersonaBaseURL = "https://withpersona.com/api/v1"

// PersonaHostedFlowOrigin is where Persona hosts the verifier UI. The full
// URL appended with ?inquiry-id=inq_… is what the end-user opens.
const PersonaHostedFlowOrigin = "https://inquiry.withpersona.com/verify"

// PersonaClient calls the Persona Inquiries API.
//
// All methods accept a context.Context and respect its deadline. Errors from
// Persona's API surface as wrapped HTTP errors with the body excerpted.
type PersonaClient struct {
	// HTTPClient is the underlying client. If nil, http.DefaultClient is used.
	HTTPClient *http.Client

	// APIKey is the bearer token used in Authorization headers.
	APIKey string

	// BaseURL overrides the default PersonaBaseURL. Useful in tests with a
	// httptest.Server pointing at a fake Persona.
	BaseURL string

	// TemplateID is the Persona inquiry template ID to instantiate.
	TemplateID string

	// EnvironmentID, if set, scopes inquiries to a particular Persona
	// environment (helpful when one account holds multiple sandboxes).
	EnvironmentID string
}

// NewPersonaClient constructs a PersonaClient pointed at the production API.
// All four arguments except environmentID are required; pass "" if you don't
// need EnvironmentID scoping.
func NewPersonaClient(apiKey, templateID, environmentID string, httpClient *http.Client) (*PersonaClient, error) {
	if strings.TrimSpace(apiKey) == "" {
		return nil, errors.New("persona: APIKey is required")
	}
	if strings.TrimSpace(templateID) == "" {
		return nil, errors.New("persona: TemplateID is required")
	}
	c := &PersonaClient{
		APIKey:        apiKey,
		TemplateID:    templateID,
		EnvironmentID: environmentID,
		BaseURL:       PersonaBaseURL,
		HTTPClient:    httpClient,
	}
	if c.HTTPClient == nil {
		c.HTTPClient = &http.Client{Timeout: 15 * time.Second}
	}
	return c, nil
}

// CreatedInquiry is the subset of Persona's create-inquiry response we use.
type CreatedInquiry struct {
	// ID is the Persona inquiry identifier (e.g. "inq_…").
	ID string

	// Status is Persona's initial status, typically "created".
	Status string

	// SessionToken, when non-empty, is the short-lived token the client uses
	// to load the hosted flow. v0.1 does not use it (we pass inquiry-id
	// directly) but it is preserved in the struct so callers that prefer
	// session-token-based hosted flows can opt in.
	SessionToken string
}

// HostedFlowURL composes the URL the end-user opens to complete the inquiry.
// It defaults to inquiry-id-only; pass returnURL non-empty if the inquiry
// template is configured to redirect back to your app after completion.
func (i CreatedInquiry) HostedFlowURL(returnURL string) string {
	q := url.Values{}
	q.Set("inquiry-id", i.ID)
	if returnURL != "" {
		q.Set("redirect-uri", returnURL)
	}
	return fmt.Sprintf("%s?%s", PersonaHostedFlowOrigin, q.Encode())
}

// CreateInquiry instantiates a new Persona inquiry against the configured
// template, binding it to the supplied reference-id (the Personhood session
// id). The returned CreatedInquiry contains the Persona inquiry-id the
// caller must record in ResultStore so the webhook handler can resolve
// incoming events back to this session.
func (c *PersonaClient) CreateInquiry(ctx context.Context, referenceID string) (CreatedInquiry, error) {
	type attributes struct {
		InquiryTemplateID string `json:"inquiry-template-id"`
		ReferenceID       string `json:"reference-id,omitempty"`
		EnvironmentID     string `json:"environment-id,omitempty"`
	}
	type wireRequest struct {
		Data struct {
			Attributes attributes `json:"attributes"`
		} `json:"data"`
	}
	req := wireRequest{}
	req.Data.Attributes = attributes{
		InquiryTemplateID: c.TemplateID,
		ReferenceID:       referenceID,
		EnvironmentID:     c.EnvironmentID,
	}
	body, err := json.Marshal(req)
	if err != nil {
		return CreatedInquiry{}, fmt.Errorf("persona: marshal create-inquiry: %w", err)
	}

	httpReq, err := http.NewRequestWithContext(ctx, http.MethodPost, c.BaseURL+"/inquiries", bytes.NewReader(body))
	if err != nil {
		return CreatedInquiry{}, fmt.Errorf("persona: build request: %w", err)
	}
	httpReq.Header.Set("Authorization", "Bearer "+c.APIKey)
	httpReq.Header.Set("Content-Type", "application/json")
	httpReq.Header.Set("Accept", "application/json")
	httpReq.Header.Set("Persona-Version", "2023-01-05")

	resp, err := c.HTTPClient.Do(httpReq)
	if err != nil {
		return CreatedInquiry{}, fmt.Errorf("persona: create-inquiry: %w", err)
	}
	defer resp.Body.Close()
	rawBody, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<20))

	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return CreatedInquiry{}, fmt.Errorf("persona: create-inquiry returned %d: %s", resp.StatusCode, excerpt(rawBody))
	}

	type wireResponse struct {
		Data struct {
			ID         string `json:"id"`
			Attributes struct {
				Status       string `json:"status"`
				SessionToken string `json:"session-token"`
			} `json:"attributes"`
		} `json:"data"`
	}
	var wr wireResponse
	if err := json.Unmarshal(rawBody, &wr); err != nil {
		return CreatedInquiry{}, fmt.Errorf("persona: decode create-inquiry response: %w (body: %s)", err, excerpt(rawBody))
	}
	if wr.Data.ID == "" {
		return CreatedInquiry{}, fmt.Errorf("persona: create-inquiry returned empty inquiry id (body: %s)", excerpt(rawBody))
	}
	return CreatedInquiry{
		ID:           wr.Data.ID,
		Status:       wr.Data.Attributes.Status,
		SessionToken: wr.Data.Attributes.SessionToken,
	}, nil
}

// FetchInquiryStatus retrieves the current state of an inquiry from Persona.
// Used as a fallback when the webhook is delayed; not the primary path.
func (c *PersonaClient) FetchInquiryStatus(ctx context.Context, inquiryID string) (string, error) {
	httpReq, err := http.NewRequestWithContext(ctx, http.MethodGet, c.BaseURL+"/inquiries/"+url.PathEscape(inquiryID), nil)
	if err != nil {
		return "", err
	}
	httpReq.Header.Set("Authorization", "Bearer "+c.APIKey)
	httpReq.Header.Set("Accept", "application/json")
	httpReq.Header.Set("Persona-Version", "2023-01-05")

	resp, err := c.HTTPClient.Do(httpReq)
	if err != nil {
		return "", fmt.Errorf("persona: fetch inquiry: %w", err)
	}
	defer resp.Body.Close()
	rawBody, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<20))

	if resp.StatusCode == http.StatusNotFound {
		return "", fmt.Errorf("persona: inquiry %s not found", inquiryID)
	}
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return "", fmt.Errorf("persona: fetch-inquiry returned %d: %s", resp.StatusCode, excerpt(rawBody))
	}
	type wireResponse struct {
		Data struct {
			Attributes struct {
				Status string `json:"status"`
			} `json:"attributes"`
		} `json:"data"`
	}
	var wr wireResponse
	if err := json.Unmarshal(rawBody, &wr); err != nil {
		return "", fmt.Errorf("persona: decode fetch-inquiry: %w", err)
	}
	return wr.Data.Attributes.Status, nil
}

func excerpt(b []byte) string {
	const max = 200
	if len(b) <= max {
		return string(b)
	}
	return string(b[:max]) + "...(truncated)"
}
