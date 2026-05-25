package governmentidliveness

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

// WebhookMaxBodyBytes is the upper bound on a Persona webhook body we will
// accept. Persona payloads are typically a few kilobytes; 1 MiB is a generous
// limit that protects against accidental memory blow-ups.
const WebhookMaxBodyBytes = 1 << 20

// WebhookReplayWindow is the longest age (in seconds) of the timestamp
// included in the signature header that the verifier will accept. Persona's
// recommended default is 5 minutes.
const WebhookReplayWindow = 5 * time.Minute

// ErrWebhookBadSignature is returned by VerifyWebhookSignature when the
// Persona-Signature header is missing, malformed, expired, or fails the HMAC
// comparison.
var ErrWebhookBadSignature = errors.New("government-id-liveness: webhook signature invalid")

// VerifyWebhookSignature checks a Persona-Signature header against the raw
// webhook body, using the configured shared secret.
//
// Persona's signature header has the shape:
//
//	Persona-Signature: t=<unix seconds>,v1=<hex hmac>[,v1=<hex hmac>...]
//
// Multiple v1 values appear during secret rotations. The function returns
// nil if at least one v1 value matches HMAC-SHA256(secret, "<t>.<body>") AND
// the timestamp is within the replay window. now is injected so tests can
// pin the clock; pass time.Now() in production.
func VerifyWebhookSignature(secret string, header string, body []byte, now time.Time) error {
	if secret == "" {
		return errors.New("government-id-liveness: webhook secret is required")
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

// webhookEvent is the subset of Persona's webhook payload we care about.
type webhookEvent struct {
	Data struct {
		Attributes struct {
			Name    string `json:"name"`
			Payload struct {
				Data struct {
					ID         string `json:"id"`
					Type       string `json:"type"`
					Attributes struct {
						Status      string `json:"status"`
						ReferenceID string `json:"reference-id"`
					} `json:"attributes"`
				} `json:"data"`
			} `json:"payload"`
		} `json:"attributes"`
	} `json:"data"`
}

// ParsedWebhook is the narrowed form of a Persona webhook ready to be
// written into ResultStore.
type ParsedWebhook struct {
	EventName   string
	InquiryID   string
	ReferenceID string
	Status      Status
	RawStatus   string
}

// ParseWebhookBody decodes a Persona webhook JSON body and maps the raw
// Persona status onto the narrowed Status enum.
func ParseWebhookBody(body []byte) (ParsedWebhook, error) {
	var ev webhookEvent
	if err := json.Unmarshal(body, &ev); err != nil {
		return ParsedWebhook{}, fmt.Errorf("government-id-liveness: parse webhook: %w", err)
	}
	if ev.Data.Attributes.Payload.Data.ID == "" {
		return ParsedWebhook{}, errors.New("government-id-liveness: webhook missing inquiry id")
	}
	raw := strings.ToLower(strings.TrimSpace(ev.Data.Attributes.Payload.Data.Attributes.Status))
	mapped := mapStatus(ev.Data.Attributes.Name, raw)
	return ParsedWebhook{
		EventName:   ev.Data.Attributes.Name,
		InquiryID:   ev.Data.Attributes.Payload.Data.ID,
		ReferenceID: ev.Data.Attributes.Payload.Data.Attributes.ReferenceID,
		Status:      mapped,
		RawStatus:   raw,
	}, nil
}

// mapStatus turns Persona's raw status string into the narrowed Status enum.
func mapStatus(eventName, raw string) Status {
	if eventName == "inquiry.expired" {
		return StatusExpired
	}
	switch raw {
	case "approved", "completed":
		return StatusApproved
	case "declined", "failed":
		return StatusDeclined
	case "needs_review", "needs-review", "pending":
		return StatusNeedsReview
	default:
		return Status(raw)
	}
}

// NewWebhookHandler returns an http.Handler that:
//   - reads the request body (capped by WebhookMaxBodyBytes),
//   - validates Persona-Signature against secret,
//   - parses the body,
//   - resolves the session via store.LookupSessionByInquiry,
//   - persists the Result via store.PutResult,
//   - returns 200 on success or an appropriate 4xx/5xx on failure.
//
// nowFunc is injected so tests can freeze time. Pass time.Now in production.
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
		sigHeader := r.Header.Get("Persona-Signature")
		if err := VerifyWebhookSignature(secret, sigHeader, body, nowFunc()); err != nil {
			http.Error(w, "webhook: "+err.Error(), http.StatusUnauthorized)
			return
		}
		parsed, err := ParseWebhookBody(body)
		if err != nil {
			http.Error(w, "webhook: "+err.Error(), http.StatusBadRequest)
			return
		}

		ctx := r.Context()
		sessionID := parsed.ReferenceID
		if sessionID == "" {
			// Fall back to inquiry -> session lookup if the event omitted reference-id.
			sessionID, _ = store.LookupSessionByInquiry(ctx, parsed.InquiryID)
		}
		if sessionID == "" {
			http.Error(w, "webhook: inquiry not associated with a session", http.StatusNotFound)
			return
		}

		result := Result{
			InquiryID:   parsed.InquiryID,
			Status:      parsed.Status,
			RawStatus:   parsed.RawStatus,
			CompletedAt: nowFunc().UTC(),
			EventName:   parsed.EventName,
		}
		if err := store.PutResult(ctx, sessionID, result); err != nil {
			http.Error(w, "webhook: "+err.Error(), http.StatusInternalServerError)
			return
		}
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`{"received":true}`))
	})
}

// SignWebhookForTesting returns the Persona-Signature header value the
// webhook handler will accept for body+timestamp under secret. Exposed so
// tests can produce valid signatures without copying the HMAC code.
//
// Production code does NOT need this — Persona itself emits the signature.
func SignWebhookForTesting(secret string, body []byte, timestamp time.Time) string {
	mac := hmac.New(sha256.New, []byte(secret))
	signedPayload := strconv.FormatInt(timestamp.Unix(), 10) + "." + string(body)
	mac.Write([]byte(signedPayload))
	return fmt.Sprintf("t=%d,v1=%s", timestamp.Unix(), hex.EncodeToString(mac.Sum(nil)))
}

