package email

import (
	"context"
	"log"
)

// Sender is the abstraction the Email method uses to deliver a magic-link
// email to the user. Implementations integrate with whatever transactional
// email vendor (SES, SendGrid, Postmark, an SMTP relay, etc.) the issuer
// prefers.
//
// Implementations MUST be safe for concurrent use. The provided ctx governs
// any deadlines / cancellation for the underlying delivery RPC.
type Sender interface {
	// Send delivers a single message to the given address. subject is a short
	// human-readable subject line; magicLinkURL is the full URL the user must
	// click to complete the ceremony. The implementation is expected to wrap
	// magicLinkURL in an HTML body of its choosing — this interface does not
	// dictate templating.
	Send(ctx context.Context, to string, subject string, magicLinkURL string) error
}

// LogSender is a development / test Sender that writes the magic link to a
// logger instead of actually sending an email. It is intentionally trivial so
// developers can copy the link out of stdout during local testing.
//
// If Logger is nil, log.Default() is used.
type LogSender struct {
	Logger *log.Logger
}

// Send implements Sender by logging the magic link.
func (s *LogSender) Send(_ context.Context, to string, subject string, magicLinkURL string) error {
	logger := s.Logger
	if logger == nil {
		logger = log.Default()
	}
	logger.Printf("[email/LogSender] to=%s subject=%q link=%s", to, subject, magicLinkURL)
	return nil
}
