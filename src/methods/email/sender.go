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

// SenderKindLog / SenderKindSMTP / SenderKindSendGrid are the stable string
// identifiers a Sender reports through Kind. They are part of the issuer's
// public wire contract: the reference server surfaces the selected kind on
// GET /v1/config so a client can tell whether real mail is being delivered or
// magic links are only being written to the server log.
const (
	SenderKindLog      = "log"
	SenderKindSMTP     = "smtp"
	SenderKindSendGrid = "sendgrid"
	SenderKindUnknown  = "unknown"
)

// KindedSender is the optional interface a Sender may implement to report
// which delivery backend it is. Every Sender in this package implements it;
// third-party and test Senders need not.
type KindedSender interface {
	// Kind returns one of the SenderKind* constants.
	Kind() string
}

// SenderKind reports which delivery backend s is, via the optional
// KindedSender interface. A nil Sender, or one that does not implement Kind,
// reports SenderKindUnknown.
//
// It reads no credentials: the answer comes from the constructed Sender
// itself, so it stays correct under every build-tag / env-var combination
// NewSenderFromEnv can resolve.
func SenderKind(s Sender) string {
	if k, ok := s.(KindedSender); ok {
		return k.Kind()
	}
	return SenderKindUnknown
}

// Kind implements KindedSender.
func (s *LogSender) Kind() string { return SenderKindLog }
