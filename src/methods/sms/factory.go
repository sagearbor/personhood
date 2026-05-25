package sms

import (
	"log"
	"os"
)

// NewSenderFromEnv constructs the appropriate Sender given the binary's
// build tags and environment variables.
//
// Decision order:
//  1. If the binary was built with `-tags twilio` AND TWILIO_ACCOUNT_SID +
//     TWILIO_AUTH_TOKEN + TWILIO_FROM are all set, return a TwilioSender.
//  2. Otherwise return a LogSender.
//
// If Twilio env vars are set but the build tag is missing — or vice versa
// — NewSenderFromEnv logs a warning and falls back to LogSender.
func NewSenderFromEnv() Sender {
	if s := realSenderFromEnv(); s != nil {
		return s
	}
	if os.Getenv("TWILIO_ACCOUNT_SID") != "" && !TwilioSenderEnabled() {
		log.Println("sms: TWILIO_ACCOUNT_SID is set but binary was not built with `-tags twilio`; falling back to LogSender")
	}
	return &LogSender{}
}
