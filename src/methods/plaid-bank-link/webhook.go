package plaidbanklink

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strconv"
	"strings"
	"time"
)

// WebhookMaxBodyBytes caps the webhook body we accept (1 MiB is generous).
const WebhookMaxBodyBytes = 1 << 20

// WebhookReplayWindow is the longest accepted age of the signature timestamp.
const WebhookReplayWindow = 5 * time.Minute

// ErrWebhookBadSignature is returned when the Plaid-Signature header is
// missing, malformed, expired, or fails the HMAC comparison.
var ErrWebhookBadSignature = errors.New("plaid-bank-link: webhook signature invalid")

// VerifyWebhookSignature checks a Plaid-Signature header against the raw
// webhook body using the configured shared secret.
//
// NOTE (v0.2): production Plaid signs webhooks with a JWT in the
// Plaid-Verification header, verified against Plaid's JWKS. v0.1 uses the same
// HMAC scheme as the government-id-liveness method for a consistent, testable
// shape:
//
//	Plaid-Signature: t=<unix seconds>,v1=<hex hmac>[,v1=<hex hmac>...]
//
// Returns nil if at least one v1 matches HMAC-SHA256(secret, "<t>.<body>") and
// the timestamp is within the replay window. now is injected for tests.
func VerifyWebhookSignature(secret, header string, body []byte, now time.Time) error {
	if secret == "" {
		return errors.New("plaid-bank-link: webhook secret is required")
	}
	if header == "" {
		return fmt.Errorf("%w: missing header", ErrWebhookBadSignature)
	}

	var timestamp int64
	var sigs []string
	for _, part := range strings.Split(header, ",") {
		part = strings.TrimSpace(part)
		k, v, ok := strings.Cut(part, "=")
		if !ok {
			return fmt.Errorf("%w: malformed header part %q", ErrWebhookBadSignature, part)
		}
		switch strings.ToLower(strings.TrimSpace(k)) {
		case "t":
			ts, err := strconv.ParseInt(strings.TrimSpace(v), 10, 64)
			if err != nil {
				return fmt.Errorf("%w: bad timestamp %q", ErrWebhookBadSignature, v)
			}
			timestamp = ts
		case "v1":
			sigs = append(sigs, strings.TrimSpace(v))
		}
	}
	if timestamp == 0 || len(sigs) == 0 {
		return fmt.Errorf("%w: missing t or v1", ErrWebhookBadSignature)
	}
	age := now.Sub(time.Unix(timestamp, 0))
	if age < -WebhookReplayWindow || age > WebhookReplayWindow {
		return fmt.Errorf("%w: timestamp out of replay window (age %s)", ErrWebhookBadSignature, age)
	}

	signedPayload := strconv.FormatInt(timestamp, 10) + "." + string(body)
	mac := hmac.New(sha256.New, []byte(secret))
	mac.Write([]byte(signedPayload))
	expected := mac.Sum(nil)

	for _, sig := range sigs {
		decoded, err := hex.DecodeString(sig)
		if err != nil {
			continue
		}
		if hmac.Equal(decoded, expected) {
			return nil
		}
	}
	return ErrWebhookBadSignature
}

// webhookEvent is the subset of Plaid's LINK webhook payload we care about.
type webhookEvent struct {
	WebhookType   string `json:"webhook_type"`
	WebhookCode   string `json:"webhook_code"`
	LinkToken     string `json:"link_token"`
	LinkSessionID string `json:"link_session_id"`
	Status        string `json:"status"`
}

// ParsedWebhook is the narrowed form of a Plaid webhook ready for ResultStore.
type ParsedWebhook struct {
	EventName     string
	LinkToken     string
	LinkSessionID string
	Status        Status
	RawStatus     string
}

// ParseWebhookBody decodes a Plaid LINK webhook and maps the raw status onto
// the narrowed Status enum.
func ParseWebhookBody(body []byte) (ParsedWebhook, error) {
	var ev webhookEvent
	if err := json.Unmarshal(body, &ev); err != nil {
		return ParsedWebhook{}, fmt.Errorf("plaid-bank-link: parse webhook: %w", err)
	}
	if ev.LinkToken == "" && ev.LinkSessionID == "" {
		return ParsedWebhook{}, errors.New("plaid-bank-link: webhook missing link_token and link_session_id")
	}
	raw := strings.ToUpper(strings.TrimSpace(ev.Status))
	return ParsedWebhook{
		EventName:     ev.WebhookCode,
		LinkToken:     ev.LinkToken,
		LinkSessionID: ev.LinkSessionID,
		Status:        mapStatus(ev.WebhookCode, raw),
		RawStatus:     raw,
	}, nil
}

// mapStatus turns a Plaid webhook_code + status into the narrowed Status enum.
func mapStatus(webhookCode, rawUpper string) Status {
	if strings.EqualFold(webhookCode, "SESSION_EXPIRED") {
		return StatusExpired
	}
	switch rawUpper {
	case "SUCCESS", "COMPLETED":
		return StatusApproved
	case "EXITED", "FAILED", "ABANDONED":
		return StatusDeclined
	case "REQUIRES_REVIEW", "PENDING":
		return StatusNeedsReview
	case "EXPIRED":
		return StatusExpired
	default:
		return Status(strings.ToLower(rawUpper))
	}
}

// NewWebhookHandler returns an http.Handler that validates the signature,
// parses the body, resolves the session via the link token, and persists the
// result. nowFunc is injected for tests; pass time.Now in production.
func NewWebhookHandler(secret string, store ResultStore, nowFunc func() time.Time) http.Handler {
	if nowFunc == nil {
		nowFunc = time.Now
	}
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, err := io.ReadAll(http.MaxBytesReader(w, r.Body, WebhookMaxBodyBytes))
		if err != nil {
			http.Error(w, "webhook: body too large or unreadable", http.StatusBadRequest)
			return
		}
		if err := VerifyWebhookSignature(secret, r.Header.Get("Plaid-Signature"), body, nowFunc()); err != nil {
			http.Error(w, "webhook: "+err.Error(), http.StatusUnauthorized)
			return
		}
		parsed, err := ParseWebhookBody(body)
		if err != nil {
			http.Error(w, "webhook: "+err.Error(), http.StatusBadRequest)
			return
		}
		// We only act on session-completion events; other LINK events (e.g.
		// item add notifications) are acknowledged without storing a result.
		if parsed.Status == "" {
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write([]byte(`{"received":true,"ignored":true}`))
			return
		}

		ctx := r.Context()
		sessionID, _ := store.LookupSessionByLinkToken(ctx, parsed.LinkToken)
		if sessionID == "" {
			http.Error(w, "webhook: link token not associated with a session", http.StatusNotFound)
			return
		}

		result := Result{
			LinkSessionID: parsed.LinkSessionID,
			Status:        parsed.Status,
			RawStatus:     parsed.RawStatus,
			CompletedAt:   nowFunc().UTC(),
			EventName:     parsed.EventName,
		}
		if err := store.PutResult(ctx, sessionID, result); err != nil {
			http.Error(w, "webhook: "+err.Error(), http.StatusInternalServerError)
			return
		}
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`{"received":true}`))
	})
}

// SignWebhookForTesting returns the Plaid-Signature header value the handler
// accepts for body+timestamp under secret. Production does not need this.
func SignWebhookForTesting(secret string, body []byte, timestamp time.Time) string {
	mac := hmac.New(sha256.New, []byte(secret))
	signedPayload := strconv.FormatInt(timestamp.Unix(), 10) + "." + string(body)
	mac.Write([]byte(signedPayload))
	return fmt.Sprintf("t=%d,v1=%s", timestamp.Unix(), hex.EncodeToString(mac.Sum(nil)))
}
