package emailtier

import (
	"context"
	"log"
)

// Sender delivers a magic-link email to the user. Implementations integrate
// with whatever transactional email vendor the issuer prefers and MUST be safe
// for concurrent use. This mirrors the email module's Sender so email-tier
// stays an independently-compilable module (the repo deliberately decouples
// method modules rather than sharing internal packages).
type Sender interface {
	Send(ctx context.Context, to string, subject string, magicLinkURL string) error
}

// LogSender is a development / test Sender that writes the magic link to a
// logger instead of sending mail. If Logger is nil, log.Default() is used.
type LogSender struct {
	Logger *log.Logger
}

// Send implements Sender by logging the magic link.
func (s *LogSender) Send(_ context.Context, to string, subject string, magicLinkURL string) error {
	logger := s.Logger
	if logger == nil {
		logger = log.Default()
	}
	logger.Printf("[email-tier/LogSender] to=%s subject=%q link=%s", to, subject, magicLinkURL)
	return nil
}
