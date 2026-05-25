//go:build twilio

// Build-tag-gated Twilio sender. Only compiled into binaries built with
// `go build -tags twilio`. Without the tag, twilio_sender_disabled.go
// provides a stub and the default Sender is LogSender (sender.go). See
// docs/02-methods.md for the env-var matrix.

package sms

import (
	"context"
	"errors"
	"fmt"
	"io"
	"log"
	"net/http"
	"net/url"
	"os"
	"strings"
	"time"
)

// TwilioAPIRoot is the v2010 Programmable Messaging endpoint root. The full
// per-message URL is TwilioAPIRoot + "/Accounts/{AccountSid}/Messages.json".
const TwilioAPIRoot = "https://api.twilio.com/2010-04-01"

// TwilioSender delivers SMS OTPs through Twilio Programmable Messaging.
//
// Safe for concurrent use. Uses plain net/http (Basic Auth + form-encoded
// POST) to avoid depending on twilio-go.
type TwilioSender struct {
	AccountSID string
	AuthToken  string
	FromNumber string // E.164, e.g. "+15551234567"

	// HTTPClient is the underlying client; if nil, a client with a 15s
	// timeout is used.
	HTTPClient *http.Client

	// Endpoint overrides the default Twilio Messages URL. Tests point this
	// at an httptest server.
	Endpoint string
}

// NewTwilioSender constructs a TwilioSender. All three string arguments are
// required.
func NewTwilioSender(accountSID, authToken, fromNumber string) (*TwilioSender, error) {
	if strings.TrimSpace(accountSID) == "" {
		return nil, errors.New("sms: Twilio AccountSID is required")
	}
	if strings.TrimSpace(authToken) == "" {
		return nil, errors.New("sms: Twilio AuthToken is required")
	}
	if strings.TrimSpace(fromNumber) == "" {
		return nil, errors.New("sms: Twilio From number is required")
	}
	return &TwilioSender{
		AccountSID: accountSID,
		AuthToken:  authToken,
		FromNumber: fromNumber,
		HTTPClient: &http.Client{Timeout: 15 * time.Second},
	}, nil
}

// Send implements Sender by POSTing a form-encoded request to Twilio's
// Messages resource for the configured AccountSID.
func (s *TwilioSender) Send(ctx context.Context, toPhone string, body string) error {
	if s == nil {
		return errors.New("sms: nil TwilioSender")
	}
	if strings.TrimSpace(toPhone) == "" {
		return errors.New("sms/twilio: empty toPhone")
	}

	endpoint := s.Endpoint
	if endpoint == "" {
		endpoint = fmt.Sprintf("%s/Accounts/%s/Messages.json", TwilioAPIRoot, url.PathEscape(s.AccountSID))
	}

	form := url.Values{}
	form.Set("To", toPhone)
	form.Set("From", s.FromNumber)
	form.Set("Body", body)

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, endpoint, strings.NewReader(form.Encode()))
	if err != nil {
		return fmt.Errorf("sms/twilio: build request: %w", err)
	}
	req.SetBasicAuth(s.AccountSID, s.AuthToken)
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("Accept", "application/json")

	client := s.HTTPClient
	if client == nil {
		client = http.DefaultClient
	}
	resp, err := client.Do(req)
	if err != nil {
		return fmt.Errorf("sms/twilio: post: %w", err)
	}
	defer resp.Body.Close()
	respBody, _ := io.ReadAll(io.LimitReader(resp.Body, 4096))

	// Twilio returns 201 Created for accepted messages.
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return fmt.Errorf("sms/twilio: status %d: %s", resp.StatusCode, string(respBody))
	}
	return nil
}

// TwilioSenderEnabled reports whether the binary was built with the twilio
// build tag. Always true in this build-tagged file; the disabled twin
// returns false.
func TwilioSenderEnabled() bool { return true }

// realSenderFromEnv is consumed by NewSenderFromEnv (factory.go). In the
// twilio build it inspects TWILIO_ACCOUNT_SID + TWILIO_AUTH_TOKEN +
// TWILIO_FROM and returns a configured TwilioSender, or nil if any are
// missing.
func realSenderFromEnv() Sender {
	sid := os.Getenv("TWILIO_ACCOUNT_SID")
	tok := os.Getenv("TWILIO_AUTH_TOKEN")
	from := os.Getenv("TWILIO_FROM")
	if sid == "" || tok == "" || from == "" {
		return nil
	}
	s, err := NewTwilioSender(sid, tok, from)
	if err != nil {
		log.Printf("sms/twilio: %v; falling back to LogSender", err)
		return nil
	}
	return s
}
