package email

// No build tag: unlike SendGridSender (behind `-tags sendgrid`), SMTPSender
// uses only the stdlib net/smtp and is always compiled in. This gives every
// build — including the default one shipped to Fly.io — a way to deliver
// real mail via any SMTP relay (a Gmail app password, Fastmail, Postmark
// SMTP, an internal relay, etc.) without a SendGrid account.

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"net"
	"net/smtp"
	"os"
	"strings"
	"time"
)

// SMTPSender delivers magic-link emails through a generic SMTP relay using
// the stdlib net/smtp package.
//
// Port 465 is treated as implicit TLS (SMTPS); any other port (587, 25, ...)
// dials in plaintext and upgrades via STARTTLS if the server advertises it,
// which is what Gmail, Fastmail, Postmark SMTP, and most relays expect on
// 587. If User is non-empty and the server advertises AUTH, PLAIN auth is
// attempted.
//
// Safe for concurrent use: it holds no mutable state and opens a fresh
// connection per Send call.
type SMTPSender struct {
	Host     string
	Port     string // defaults to "587" if empty
	User     string // optional; skip AUTH if empty
	Pass     string
	From     string
	FromName string // optional

	// DialTimeout bounds the initial TCP/TLS connect. Defaults to 15s.
	DialTimeout time.Duration
}

// NewSMTPSender constructs an SMTPSender. host and from are required; user,
// pass, and port may be empty (port defaults to 587).
func NewSMTPSender(host, port, user, pass, from string) (*SMTPSender, error) {
	if strings.TrimSpace(host) == "" {
		return nil, errors.New("email: SMTP host is required")
	}
	if strings.TrimSpace(from) == "" {
		return nil, errors.New("email: SMTP From address is required")
	}
	if strings.TrimSpace(port) == "" {
		port = "587"
	}
	return &SMTPSender{
		Host: host,
		Port: port,
		User: user,
		Pass: pass,
		From: from,
	}, nil
}

// Send implements Sender by connecting to the configured SMTP relay and
// delivering a single MIME message (text/plain + text/html alternative,
// matching SendGridSender's body) to to.
func (s *SMTPSender) Send(ctx context.Context, to string, subject string, magicLinkURL string) error {
	if s == nil {
		return errors.New("email: nil SMTPSender")
	}
	if strings.TrimSpace(to) == "" {
		return errors.New("email/smtp: recipient address is required")
	}

	timeout := s.DialTimeout
	if timeout <= 0 {
		timeout = 15 * time.Second
	}
	dialCtx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()

	addr := net.JoinHostPort(s.Host, s.Port)

	var conn net.Conn
	var err error
	if s.Port == "465" {
		// Implicit TLS (SMTPS). tls.Dialer honors the context for the
		// underlying TCP dial.
		conn, err = (&tls.Dialer{Config: &tls.Config{ServerName: s.Host}}).DialContext(dialCtx, "tcp", addr)
	} else {
		conn, err = (&net.Dialer{}).DialContext(dialCtx, "tcp", addr)
	}
	if err != nil {
		return fmt.Errorf("email/smtp: dial %s: %w", addr, err)
	}
	defer conn.Close()

	client, err := smtp.NewClient(conn, s.Host)
	if err != nil {
		return fmt.Errorf("email/smtp: new client: %w", err)
	}
	defer client.Close()

	if s.Port != "465" {
		if ok, _ := client.Extension("STARTTLS"); ok {
			if err := client.StartTLS(&tls.Config{ServerName: s.Host}); err != nil {
				return fmt.Errorf("email/smtp: starttls: %w", err)
			}
		}
	}

	if s.User != "" {
		if ok, _ := client.Extension("AUTH"); ok {
			auth := smtp.PlainAuth("", s.User, s.Pass, s.Host)
			if err := client.Auth(auth); err != nil {
				return fmt.Errorf("email/smtp: auth: %w", err)
			}
		}
	}

	if err := client.Mail(s.From); err != nil {
		return fmt.Errorf("email/smtp: mail from: %w", err)
	}
	if err := client.Rcpt(to); err != nil {
		return fmt.Errorf("email/smtp: rcpt to: %w", err)
	}
	w, err := client.Data()
	if err != nil {
		return fmt.Errorf("email/smtp: data: %w", err)
	}
	if _, err := w.Write(smtpMessage(s.From, s.FromName, to, subject, magicLinkURL)); err != nil {
		_ = w.Close()
		return fmt.Errorf("email/smtp: write body: %w", err)
	}
	if err := w.Close(); err != nil {
		return fmt.Errorf("email/smtp: close data: %w", err)
	}
	return client.Quit()
}

// smtpMessage builds a minimal multipart/alternative MIME message with a
// plain-text and an HTML part carrying magicLinkURL. Bodies mirror
// SendGridSender's copy so the two delivery paths read identically.
func smtpMessage(from, fromName, to, subject, magicLinkURL string) []byte {
	fromHeader := from
	if fromName != "" {
		fromHeader = fmt.Sprintf("%s <%s>", fromName, from)
	}

	plain := fmt.Sprintf(
		"Tap the link to confirm your email for Personhood enrollment:\r\n\r\n%s\r\n\r\n"+
			"This link expires in 15 minutes. If you did not request it, you can ignore this email.",
		magicLinkURL,
	)
	htmlBody := fmt.Sprintf(
		`<!doctype html><html><body style="font-family:system-ui,sans-serif;line-height:1.5;color:#0f1115">`+
			`<p>Tap the button below to confirm your email for Personhood enrollment.</p>`+
			`<p><a href=%q style="display:inline-block;padding:10px 16px;border-radius:8px;background:#0f1115;color:#fff;text-decoration:none">Confirm email</a></p>`+
			`<p style="color:#6b7280;font-size:14px">Or open this link directly: <a href=%q>%s</a></p>`+
			`<p style="color:#6b7280;font-size:14px">This link expires in 15 minutes. If you did not request it, you can ignore this email.</p>`+
			`</body></html>`,
		magicLinkURL, magicLinkURL, magicLinkURL,
	)

	const boundary = "personhood-smtp-boundary"
	var b strings.Builder
	fmt.Fprintf(&b, "From: %s\r\n", fromHeader)
	fmt.Fprintf(&b, "To: %s\r\n", to)
	fmt.Fprintf(&b, "Subject: %s\r\n", subject)
	b.WriteString("MIME-Version: 1.0\r\n")
	fmt.Fprintf(&b, "Content-Type: multipart/alternative; boundary=%q\r\n", boundary)
	b.WriteString("\r\n")
	fmt.Fprintf(&b, "--%s\r\n", boundary)
	b.WriteString("Content-Type: text/plain; charset=UTF-8\r\n\r\n")
	b.WriteString(plain)
	b.WriteString("\r\n\r\n")
	fmt.Fprintf(&b, "--%s\r\n", boundary)
	b.WriteString("Content-Type: text/html; charset=UTF-8\r\n\r\n")
	b.WriteString(htmlBody)
	b.WriteString("\r\n\r\n")
	fmt.Fprintf(&b, "--%s--\r\n", boundary)
	return []byte(b.String())
}

// Kind implements KindedSender.
func (s *SMTPSender) Kind() string { return SenderKindSMTP }

// smtpSenderFromEnv inspects SMTP_HOST/SMTP_PORT/SMTP_USER/SMTP_PASS/
// SMTP_FROM and returns a configured SMTPSender, or nil if SMTP_HOST or
// SMTP_FROM is unset. Consumed by NewSenderFromEnv (factory.go) as the
// fallback tier below SendGrid: no build tag required.
func smtpSenderFromEnv() Sender {
	host := os.Getenv("SMTP_HOST")
	from := os.Getenv("SMTP_FROM")
	if host == "" || from == "" {
		return nil
	}
	s, err := NewSMTPSender(host, os.Getenv("SMTP_PORT"), os.Getenv("SMTP_USER"), os.Getenv("SMTP_PASS"), from)
	if err != nil {
		return nil
	}
	return s
}
