package email

import (
	"log"
	"os"
)

// NewSenderFromEnv constructs the appropriate Sender given the binary's
// build tags and environment variables.
//
// Decision order:
//  1. If the binary was built with `-tags sendgrid` AND
//     SENDGRID_API_KEY + SENDGRID_FROM are both set, return a SendGridSender.
//  2. Otherwise return a LogSender so dev / test deployments keep working.
//
// If SENDGRID_API_KEY is set but the sendgrid tag is missing — or vice versa
// — NewSenderFromEnv logs a warning and falls back to LogSender, so the
// failure is obvious rather than silent.
func NewSenderFromEnv() Sender {
	if s := realSenderFromEnv(); s != nil {
		return s
	}
	if os.Getenv("SENDGRID_API_KEY") != "" && !SendGridSenderEnabled() {
		log.Println("email: SENDGRID_API_KEY is set but binary was not built with `-tags sendgrid`; falling back to LogSender")
	}
	return &LogSender{}
}
