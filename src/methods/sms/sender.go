package sms

import (
	"context"
	"errors"
	"log"
	"strings"
)

// Sender abstracts SMS delivery. Real implementations wrap Twilio, MessageBird,
// Plivo, etc. The interface is intentionally tiny so a test or dev deployment
// can ship a LogSender and an integration test can ship a fake recording
// sender.
type Sender interface {
	// Send delivers body to toPhone (E.164 format). A non-nil error indicates
	// the message was NOT accepted by the carrier; the caller should treat the
	// ceremony as failed and invalidate any stored OTP.
	Send(ctx context.Context, toPhone string, body string) error
}

// LogSender writes the SMS body to its logger instead of contacting a carrier.
// Useful for dev, tests, and demos.
//
// The OTP is logged in clear text — this is intentional for dev mode. Do NOT
// use LogSender in any environment where the logs are accessible to anyone
// other than the operator.
type LogSender struct {
	// Logger receives one line per call. If nil, the package-level log.Default()
	// is used.
	Logger *log.Logger
}

// Send implements Sender. It returns an error only for an obviously invalid
// destination (empty phone number).
func (s *LogSender) Send(_ context.Context, toPhone string, body string) error {
	if strings.TrimSpace(toPhone) == "" {
		return errors.New("sms.LogSender: empty phone number")
	}
	logger := s.Logger
	if logger == nil {
		logger = log.Default()
	}
	logger.Printf("sms: would send to %s: %s", toPhone, body)
	return nil
}
