# src/methods/email

**Supplementary method** (target strength 5–10).

Email verification via magic link (preferred over OTP — better UX, similar security). Checks against a maintained disposable-email block-list before issuing the challenge.

## Delivery

`NewSenderFromEnv()` (`factory.go`) picks a `Sender` in this order:

1. **SendGrid** (`sendgrid_sender.go`) — only compiled in with `go build -tags sendgrid`, and only used when `SENDGRID_API_KEY` + `SENDGRID_FROM` are set.
2. **Generic SMTP** (`smtp_sender.go`) — `SMTPSender`, stdlib `net/smtp`, **no build tag** (always compiled in). Used when `SMTP_HOST` + `SMTP_FROM` are set (`SMTP_PORT` defaults to `587`/STARTTLS; use `465` for implicit TLS; `SMTP_USER`/`SMTP_PASS` are optional — omit for an open relay). This is what lets a Gmail app password or a Fastmail account send real mail without a SendGrid account. See `RUNBOOK.md` §3b-alt for setup. Covered by a fake-SMTP-server test in `smtp_sender_test.go` (`TestSMTPSender_*`) — no network access required.
3. **LogSender** (`sender.go`) — the dev/test default; writes the magic link to stdout.

## Strength rationale

Email is weak. A bot farm can mint unlimited Gmail/Outlook addresses for free. This method exists to demonstrate the framework and to give integrators a "frictionless" low-stakes option (e.g. forum signup). It must NEVER satisfy a high-stakes policy on its own; the policy DSL's `anchor_required` flag enforces this.

## Future enhancement

Per-domain strength weighting (work-email domain → higher strength than free-mail) is a v0.2 candidate.
