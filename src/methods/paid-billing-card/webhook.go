package paidbillingcard

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

// WebhookMaxBodyBytes caps the webhook body we accept.
const WebhookMaxBodyBytes = 1 << 20

// WebhookReplayWindow is the longest accepted age of the signature timestamp.
const WebhookReplayWindow = 5 * time.Minute

// ErrWebhookBadSignature is returned when the Stripe-Signature header is
// missing, malformed, expired, or fails the HMAC comparison.
var ErrWebhookBadSignature = errors.New("paid-billing-card: webhook signature invalid")

// VerifyWebhookSignature checks a Stripe-Signature header against the raw body.
// This implements Stripe's genuine scheme:
//
//	Stripe-Signature: t=<unix seconds>,v1=<hex hmac>[,v1=<hex hmac>...]
//
// where each v1 is HMAC-SHA256(secret, "<t>.<body>"). Returns nil if at least
// one v1 matches and the timestamp is within the replay window. now is injected
// for tests.
func VerifyWebhookSignature(secret, header string, body []byte, now time.Time) error {
	if secret == "" {
		return errors.New("paid-billing-card: webhook secret is required")
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

	mac := hmac.New(sha256.New, []byte(secret))
	mac.Write([]byte(strconv.FormatInt(timestamp, 10) + "." + string(body)))
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

// stripeEvent is the subset of a Stripe webhook event we care about. The
// payment_method field is decoded with json.RawMessage so we can accept either
// the unexpanded id string or an expanded object carrying the card fingerprint.
type stripeEvent struct {
	Type string `json:"type"`
	Data struct {
		Object struct {
			ID            string          `json:"id"`
			Status        string          `json:"status"`
			PaymentMethod json.RawMessage `json:"payment_method"`
			Metadata      struct {
				SessionID string `json:"session_id"`
			} `json:"metadata"`
		} `json:"object"`
	} `json:"data"`
}

// ParsedWebhook is the narrowed form of a Stripe webhook ready for ResultStore.
type ParsedWebhook struct {
	EventType       string
	SetupIntentID   string
	SessionID       string // from metadata, when present
	CardFingerprint string
	Status          Status
	RawStatus       string
}

// ParseWebhookBody decodes a Stripe setup_intent.* webhook and maps the event
// type onto the narrowed Status enum.
func ParseWebhookBody(body []byte) (ParsedWebhook, error) {
	var ev stripeEvent
	if err := json.Unmarshal(body, &ev); err != nil {
		return ParsedWebhook{}, fmt.Errorf("paid-billing-card: parse webhook: %w", err)
	}
	if ev.Data.Object.ID == "" {
		return ParsedWebhook{}, errors.New("paid-billing-card: webhook missing data.object.id")
	}
	return ParsedWebhook{
		EventType:       ev.Type,
		SetupIntentID:   ev.Data.Object.ID,
		SessionID:       ev.Data.Object.Metadata.SessionID,
		CardFingerprint: fingerprintFrom(ev.Data.Object.PaymentMethod),
		Status:          mapEventType(ev.Type),
		RawStatus:       ev.Type,
	}, nil
}

// mapEventType turns a Stripe setup_intent.* event type into a Status. Events
// we do not act on (e.g. setup_intent.created) map to "" and are acknowledged
// without storing a result.
func mapEventType(eventType string) Status {
	switch eventType {
	case "setup_intent.succeeded":
		return StatusApproved
	case "setup_intent.setup_failed":
		return StatusDeclined
	case "setup_intent.canceled":
		return StatusCanceled
	default:
		return ""
	}
}

// fingerprintFrom extracts a stable card fingerprint from the payment_method
// field. Stripe sends it unexpanded (a "pm_..." id string) by default; when the
// integrator configures the webhook/event to expand payment_method, this reads
// the nested card.fingerprint. Falls back to the raw id string so dedup still
// has *something* to key on. Empty if neither is present.
func fingerprintFrom(raw json.RawMessage) string {
	if len(raw) == 0 {
		return ""
	}
	// Try the expanded object form first.
	var expanded struct {
		Card struct {
			Fingerprint string `json:"fingerprint"`
		} `json:"card"`
	}
	if err := json.Unmarshal(raw, &expanded); err == nil && expanded.Card.Fingerprint != "" {
		return expanded.Card.Fingerprint
	}
	// Fall back to the unexpanded id string.
	var id string
	if err := json.Unmarshal(raw, &id); err == nil {
		return id
	}
	return ""
}

// NewWebhookHandler returns an http.Handler that validates the signature,
// parses the event, resolves the session (by SetupIntent id, falling back to
// metadata.session_id), and persists the result. nowFunc is injected for tests;
// pass nil for time.Now.
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
		if err := VerifyWebhookSignature(secret, r.Header.Get("Stripe-Signature"), body, nowFunc()); err != nil {
			http.Error(w, "webhook: "+err.Error(), http.StatusUnauthorized)
			return
		}
		parsed, err := ParseWebhookBody(body)
		if err != nil {
			http.Error(w, "webhook: "+err.Error(), http.StatusBadRequest)
			return
		}
		// Only act on terminal setup_intent events; ignore the rest.
		if parsed.Status == "" {
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write([]byte(`{"received":true,"ignored":true}`))
			return
		}

		ctx := r.Context()
		sessionID, _ := store.LookupSessionBySetupIntent(ctx, parsed.SetupIntentID)
		if sessionID == "" {
			// Fall back to the session id Stripe echoes in metadata.
			sessionID = parsed.SessionID
		}
		if sessionID == "" {
			http.Error(w, "webhook: setup intent not associated with a session", http.StatusNotFound)
			return
		}

		result := Result{
			SetupIntentID:   parsed.SetupIntentID,
			CardFingerprint: parsed.CardFingerprint,
			Status:          parsed.Status,
			RawStatus:       parsed.RawStatus,
			CompletedAt:     nowFunc().UTC(),
		}
		if err := store.PutResult(ctx, sessionID, result); err != nil {
			http.Error(w, "webhook: "+err.Error(), http.StatusInternalServerError)
			return
		}
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`{"received":true}`))
	})
}

// SignWebhookForTesting returns the Stripe-Signature header value the handler
// accepts for body+timestamp under secret. Production does not need this.
func SignWebhookForTesting(secret string, body []byte, timestamp time.Time) string {
	mac := hmac.New(sha256.New, []byte(secret))
	mac.Write([]byte(strconv.FormatInt(timestamp.Unix(), 10) + "." + string(body)))
	return fmt.Sprintf("t=%d,v1=%s", timestamp.Unix(), hex.EncodeToString(mac.Sum(nil)))
}
