//go:build !twilio

// Build-tag complement of twilio_sender.go: compiled into binaries built
// WITHOUT `-tags twilio`. Provides a stub so callers can write a single
// function signature for both modes.

package sms

import (
	"context"
	"errors"
)

var errTwilioNotBuilt = errors.New("sms: Twilio support not compiled in (rebuild with `-tags twilio`)")

// TwilioSender is a stub that satisfies the Sender interface but always
// fails.
type TwilioSender struct{}

// NewTwilioSender returns an error explaining that Twilio was not compiled in.
func NewTwilioSender(_, _, _ string) (*TwilioSender, error) {
	return nil, errTwilioNotBuilt
}

// Send implements Sender by always returning errTwilioNotBuilt.
func (s *TwilioSender) Send(_ context.Context, _ string, _ string) error {
	return errTwilioNotBuilt
}

// TwilioSenderEnabled reports whether the binary was built with the twilio
// build tag. Always false in this disabled twin.
func TwilioSenderEnabled() bool { return false }

// realSenderFromEnv is consumed by NewSenderFromEnv (factory.go). In the
// default build it returns nil so the factory falls back to LogSender.
func realSenderFromEnv() Sender { return nil }
