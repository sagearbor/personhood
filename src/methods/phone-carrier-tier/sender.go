package phonecarriertier

import (
	"context"
	"errors"
	"log"
	"strings"
)

// Sender abstracts SMS delivery. Real implementations wrap Twilio, MessageBird,
// Plivo, etc. Kept identical to the sms module's Sender so phone-carrier-tier
// stays an independently-compilable module (the repo deliberately decouples
// method modules rather than sharing internal packages).
type Sender interface {
	// Send delivers body to toPhone (E.164 format). A non-nil error means the
	// message was NOT accepted; the caller treats the ceremony as failed.
	Send(ctx context.Context, toPhone string, body string) error
}

// LogSender writes the SMS body to its logger instead of contacting a carrier.
// Useful for dev, tests, and demos. The OTP is logged in clear text — do NOT
// use in any environment where logs are accessible to non-operators.
type LogSender struct {
	Logger *log.Logger
}

// Send implements Sender. It errors only for an empty destination.
func (s *LogSender) Send(_ context.Context, toPhone string, body string) error {
	if strings.TrimSpace(toPhone) == "" {
		return errors.New("phone-carrier-tier.LogSender: empty phone number")
	}
	logger := s.Logger
	if logger == nil {
		logger = log.Default()
	}
	logger.Printf("phone-carrier-tier: would send to %s: %s", toPhone, body)
	return nil
}
