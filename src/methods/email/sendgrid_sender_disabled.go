//go:build !sendgrid

// Build tag complement of sendgrid_sender.go: this file is compiled into
// binaries built WITHOUT `-tags sendgrid`. It provides a stub that callers
// can use to detect SendGrid support at runtime without crashing the build.

package email

import (
	"context"
	"errors"
)

// errSendGridNotBuilt is returned by NewSendGridSender / Send when the
// binary was not built with the sendgrid build tag.
var errSendGridNotBuilt = errors.New("email: SendGrid support not compiled in (rebuild with `-tags sendgrid`)")

// SendGridSender is a stub that satisfies the Sender interface but always
// fails. Provided so callers can write a single function signature for
// both build modes.
type SendGridSender struct{}

// NewSendGridSender returns an error explaining that SendGrid was not
// compiled in.
func NewSendGridSender(_, _, _ string) (*SendGridSender, error) {
	return nil, errSendGridNotBuilt
}

// Send implements Sender by always returning errSendGridNotBuilt.
func (s *SendGridSender) Send(_ context.Context, _ string, _ string, _ string) error {
	return errSendGridNotBuilt
}

// SendGridSenderEnabled reports whether the binary was built with the
// sendgrid build tag. Always false in this disabled twin.
func SendGridSenderEnabled() bool { return false }

// realSenderFromEnv is consumed by NewSenderFromEnv (factory.go). In the
// default (non-sendgrid) build it returns nil so the factory falls back to
// LogSender.
func realSenderFromEnv() Sender { return nil }
