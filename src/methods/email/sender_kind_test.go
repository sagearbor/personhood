package email

import (
	"context"
	"testing"
)

// unkindedSender is a Sender that does not implement KindedSender — the shape
// a test fake or a third-party integration would have.
type unkindedSender struct{}

func (unkindedSender) Send(context.Context, string, string, string) error { return nil }

func TestSenderKind(t *testing.T) {
	tests := []struct {
		name string
		in   Sender
		want string
	}{
		{"log", &LogSender{}, SenderKindLog},
		{"smtp", &SMTPSender{Host: "smtp.example.com", From: "a@example.com"}, SenderKindSMTP},
		{"sendgrid", &SendGridSender{}, SenderKindSendGrid},
		{"third-party", unkindedSender{}, SenderKindUnknown},
		{"nil", nil, SenderKindUnknown},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			if got := SenderKind(tc.in); got != tc.want {
				t.Errorf("SenderKind(%T) = %q, want %q", tc.in, got, tc.want)
			}
		})
	}
}

// NewSenderFromEnv with no vendor env vars set must fall back to LogSender,
// and SenderKind must say so. This is the state a fresh preview deployment is
// in, and the state GET /v1/config on the issuer reports as "log".
func TestSenderKind_DefaultFactoryIsLog(t *testing.T) {
	t.Setenv("SENDGRID_API_KEY", "")
	t.Setenv("SENDGRID_FROM", "")
	t.Setenv("SMTP_HOST", "")
	t.Setenv("SMTP_FROM", "")

	if got := SenderKind(NewSenderFromEnv()); got != SenderKindLog {
		t.Errorf("SenderKind(NewSenderFromEnv()) = %q, want %q", got, SenderKindLog)
	}
}

// With SMTP_HOST + SMTP_FROM set the factory picks SMTPSender in every build
// mode (no build tag involved), so the reported kind must be "smtp" whether
// or not the binary was built with -tags sendgrid.
func TestSenderKind_SMTPFactory(t *testing.T) {
	t.Setenv("SENDGRID_API_KEY", "")
	t.Setenv("SMTP_HOST", "smtp.example.com")
	t.Setenv("SMTP_FROM", "noreply@example.com")

	if got := SenderKind(NewSenderFromEnv()); got != SenderKindSMTP {
		t.Errorf("SenderKind(NewSenderFromEnv()) = %q, want %q", got, SenderKindSMTP)
	}
}
