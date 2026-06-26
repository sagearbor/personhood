package phonecarriertier

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

// LineType classifies a phone line. Mobile lines are the strongest personhood
// signal (a real, carrier-issued SIM); VOIP lines are cheap and disposable and
// are rejected.
type LineType string

const (
	LineTypeMobile   LineType = "mobile"
	LineTypeLandline LineType = "landline"
	LineTypeVOIP     LineType = "voip"
	LineTypeUnknown  LineType = "unknown"
)

// CarrierSignal is the enrichment outcome for a phone number — the "tier" in
// phone-carrier-tier. Plain SMS only proves possession of a device that can
// receive a code; the CarrierSignal distinguishes a real mobile SIM from a
// throwaway VOIP number or a recently-ported (SIM-swap-risk) line.
type CarrierSignal struct {
	// LineType is the carrier-reported line classification.
	LineType LineType `json:"line_type"`

	// Carrier is the carrier/network name if known (e.g. "AT&T Wireless").
	Carrier string `json:"carrier,omitempty"`

	// Ported reports whether the number was recently ported between carriers.
	// Recent porting is a SIM-swap-attack signal and causes rejection when the
	// provider can determine it. The neutral provider leaves this false.
	Ported bool `json:"ported"`

	// Provider names the CarrierProvider that produced this signal.
	Provider string `json:"provider"`
}

// CarrierProvider looks up carrier intelligence for a phone number.
//
// Implementations MUST be safe for concurrent use and respect the context
// deadline. A non-nil error indicates a transport/internal failure; providers
// should NOT error merely because they lack data (return an unknown/neutral
// CarrierSignal instead).
type CarrierProvider interface {
	Lookup(ctx context.Context, e164 string) (CarrierSignal, error)
	Name() string
}

// NeutralProvider is the dev / test default. It performs no external lookup and
// reports an unknown line type with no porting signal — so a number only fails
// the cheap local LooksLikeVOIP heuristic, not real carrier intelligence. A
// method built with NeutralProvider is effectively plain-SMS strength;
// production wires TwilioLookupProvider so the strength-28 rating is earned.
//
// This mirrors the repo convention used by ip-asn-reputation and
// app-attest-device: ship a safe default, wire the real provider via env.
type NeutralProvider struct{}

// Lookup implements CarrierProvider.
func (NeutralProvider) Lookup(_ context.Context, _ string) (CarrierSignal, error) {
	return CarrierSignal{LineType: LineTypeUnknown, Provider: "neutral"}, nil
}

// Name implements CarrierProvider.
func (NeutralProvider) Name() string { return "neutral" }

// TwilioLookupBaseURL is the Twilio Lookup v2 API root.
const TwilioLookupBaseURL = "https://lookups.twilio.com/v2/PhoneNumbers"

// TwilioLookupProvider queries Twilio Lookup v2 line_type_intelligence (and,
// when enabled, the sim_swap package) for real carrier classification.
//
// Auth is HTTP Basic with the Twilio Account SID + Auth Token. A number Twilio
// cannot classify yields LineTypeUnknown with a nil error.
type TwilioLookupProvider struct {
	// AccountSID and AuthToken are the Twilio API credentials. Required.
	AccountSID string
	AuthToken  string

	// IncludeSimSwap requests the sim_swap package (extra cost; not on every
	// account). When false, only line_type_intelligence is requested.
	IncludeSimSwap bool

	// BaseURL overrides TwilioLookupBaseURL (used by tests).
	BaseURL string

	// HTTPClient is the underlying client. If nil a 10s-timeout client is used.
	HTTPClient *http.Client
}

// NewTwilioLookupProvider constructs a TwilioLookupProvider. accountSID and
// authToken are required.
func NewTwilioLookupProvider(accountSID, authToken string, httpClient *http.Client) (*TwilioLookupProvider, error) {
	if strings.TrimSpace(accountSID) == "" || strings.TrimSpace(authToken) == "" {
		return nil, fmt.Errorf("phone-carrier-tier: Twilio AccountSID and AuthToken are required")
	}
	p := &TwilioLookupProvider{
		AccountSID: accountSID,
		AuthToken:  authToken,
		BaseURL:    TwilioLookupBaseURL,
		HTTPClient: httpClient,
	}
	if p.HTTPClient == nil {
		p.HTTPClient = &http.Client{Timeout: 10 * time.Second}
	}
	return p, nil
}

// Name implements CarrierProvider.
func (p *TwilioLookupProvider) Name() string { return "twilio-lookup" }

// twilioLookupResponse is the subset of the Lookup v2 response we read.
type twilioLookupResponse struct {
	LineTypeIntelligence *struct {
		Type        string `json:"type"`
		CarrierName string `json:"carrier_name"`
	} `json:"line_type_intelligence"`
	SimSwap *struct {
		LastSimSwap *struct {
			SwappedInPeriod bool `json:"swapped_in_period"`
		} `json:"last_sim_swap"`
	} `json:"sim_swap"`
}

// Lookup implements CarrierProvider.
func (p *TwilioLookupProvider) Lookup(ctx context.Context, e164 string) (CarrierSignal, error) {
	sig := CarrierSignal{LineType: LineTypeUnknown, Provider: p.Name()}

	fields := "line_type_intelligence"
	if p.IncludeSimSwap {
		fields += ",sim_swap"
	}
	endpoint := strings.TrimRight(p.BaseURL, "/") + "/" + url.PathEscape(e164) + "?Fields=" + url.QueryEscape(fields)
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, endpoint, nil)
	if err != nil {
		return sig, fmt.Errorf("phone-carrier-tier: build Twilio request: %w", err)
	}
	req.SetBasicAuth(p.AccountSID, p.AuthToken)
	req.Header.Set("Accept", "application/json")

	resp, err := p.HTTPClient.Do(req)
	if err != nil {
		return sig, fmt.Errorf("phone-carrier-tier: Twilio lookup: %w", err)
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<20))

	if resp.StatusCode == http.StatusNotFound {
		// Twilio could not find the number — treat as unknown, not an error.
		return sig, nil
	}
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return sig, fmt.Errorf("phone-carrier-tier: Twilio lookup returned %d: %s", resp.StatusCode, excerpt(body))
	}

	var lr twilioLookupResponse
	if err := json.Unmarshal(body, &lr); err != nil {
		return sig, fmt.Errorf("phone-carrier-tier: decode Twilio response: %w", err)
	}
	if lr.LineTypeIntelligence != nil {
		sig.LineType = mapTwilioLineType(lr.LineTypeIntelligence.Type)
		sig.Carrier = lr.LineTypeIntelligence.CarrierName
	}
	if lr.SimSwap != nil && lr.SimSwap.LastSimSwap != nil {
		sig.Ported = lr.SimSwap.LastSimSwap.SwappedInPeriod
	}
	return sig, nil
}

// mapTwilioLineType maps Twilio's line_type_intelligence.type to our LineType.
// Twilio reports: mobile, landline, fixedVoip, nonFixedVoip, personal,
// tollFree, premium, sharedCost, uan, voicemail, unknown.
func mapTwilioLineType(t string) LineType {
	switch strings.ToLower(strings.TrimSpace(t)) {
	case "mobile":
		return LineTypeMobile
	case "landline", "fixedline":
		return LineTypeLandline
	case "fixedvoip", "nonfixedvoip", "voip":
		return LineTypeVOIP
	default:
		return LineTypeUnknown
	}
}

func excerpt(b []byte) string {
	const max = 200
	if len(b) <= max {
		return string(b)
	}
	return string(b[:max]) + "...(truncated)"
}
