package appattestdevice

import (
	"context"
	"crypto/x509"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strings"
	"sync"
	"time"
)

// GoogleStatusListURL is Google's attestation certificate revocation list.
// It lists the serial numbers (lowercase hex) of attestation keys and
// intermediates Google has revoked, usually because a device's keys leaked.
const GoogleStatusListURL = "https://android.googleapis.com/attestation/status"

// RevocationMode says what happens when the status list cannot be had.
type RevocationMode string

const (
	// RevocationOff never fetches the list.
	RevocationOff RevocationMode = "off"
	// RevocationFailOpen accepts attestations while no list has ever been
	// fetched (Google unreachable, a censored network, a cold start
	// offline). A cached list, even a stale one, is always used.
	RevocationFailOpen RevocationMode = "fail-open"
	// RevocationFailClosed rejects attestations until a list has been
	// fetched at least once.
	RevocationFailClosed RevocationMode = "fail-closed"
)

// ParseRevocationMode accepts "", "off", "fail-open", "fail-closed"
// (case-insensitive). "" means fail-open.
func ParseRevocationMode(s string) (RevocationMode, error) {
	switch m := RevocationMode(strings.ToLower(strings.TrimSpace(s))); m {
	case "":
		return RevocationFailOpen, nil
	case RevocationOff, RevocationFailOpen, RevocationFailClosed:
		return m, nil
	default:
		return "", fmt.Errorf("revocation mode %q: want off, fail-open or fail-closed", s)
	}
}

// StatusListConfig configures a StatusList.
type StatusListConfig struct {
	// URL of the status list JSON. Empty means GoogleStatusListURL. A
	// mirror works: the list is plain JSON and not signed, so trust in it
	// is trust in whoever serves it over HTTPS.
	URL string
	// Mode is fail-open or fail-closed (RevocationOff: don't build one).
	Mode RevocationMode
	// MaxAge is how long a fetched list is used before refetching. Zero
	// means 1 hour.
	MaxAge time.Duration
	// RetryAfter is the minimum gap between failed fetch attempts, so an
	// outage doesn't add a timeout to every verification. Zero means 1
	// minute.
	RetryAfter time.Duration
	// Client is the HTTP client. Nil means one with a 10s timeout.
	Client *http.Client
	// Now overrides the clock (tests).
	Now func() time.Time
}

// StatusList fetches and caches the attestation status list. Safe for
// concurrent use; at most one fetch runs at a time.
type StatusList struct {
	cfg StatusListConfig

	mu          sync.Mutex
	revoked     map[string]string // serial hex -> status/reason
	fetchedAt   time.Time
	lastAttempt time.Time
	lastErr     error
}

// NewStatusList builds a StatusList. It does not fetch until first used.
func NewStatusList(cfg StatusListConfig) *StatusList {
	if cfg.URL == "" {
		cfg.URL = GoogleStatusListURL
	}
	if cfg.Mode == "" {
		cfg.Mode = RevocationFailOpen
	}
	if cfg.MaxAge <= 0 {
		cfg.MaxAge = time.Hour
	}
	if cfg.RetryAfter <= 0 {
		cfg.RetryAfter = time.Minute
	}
	if cfg.Client == nil {
		cfg.Client = &http.Client{Timeout: 10 * time.Second}
	}
	if cfg.Now == nil {
		cfg.Now = time.Now
	}
	return &StatusList{cfg: cfg}
}

// maxStatusListBytes caps the download; the real list is about 200 KB.
const maxStatusListBytes = 16 << 20

type statusListJSON struct {
	Entries map[string]struct {
		Status string `json:"status"`
		Reason string `json:"reason"`
	} `json:"entries"`
}

// Check rejects the chain if any certificate's serial is on the list. With
// no list ever fetched, fail-open accepts and fail-closed rejects with
// "attestation_revocation_unavailable".
func (s *StatusList) Check(ctx context.Context, chain []*x509.Certificate) error {
	revoked, err := s.list(ctx)
	if revoked == nil {
		if s.cfg.Mode == RevocationFailClosed {
			return &VerifyError{Reason: "attestation_revocation_unavailable", Err: err}
		}
		return nil
	}
	for i, c := range chain {
		serial := strings.ToLower(c.SerialNumber.Text(16))
		if why, ok := revoked[serial]; ok {
			return reject("attestation_revoked", "certificate %d (serial %s) is %s", i, serial, why)
		}
	}
	return nil
}

// list returns the cached entries, refreshing them when stale. A failed
// refresh keeps the previous list. nil means no list has ever been fetched.
func (s *StatusList) list(ctx context.Context) (map[string]string, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	now := s.cfg.Now()
	fresh := s.revoked != nil && now.Sub(s.fetchedAt) < s.cfg.MaxAge
	if fresh || now.Sub(s.lastAttempt) < s.cfg.RetryAfter {
		return s.revoked, s.lastErr
	}
	s.lastAttempt = now
	m, err := s.fetch(ctx)
	if err != nil {
		s.lastErr = err
		return s.revoked, err
	}
	s.revoked, s.fetchedAt, s.lastErr = m, now, nil
	return m, nil
}

func (s *StatusList) fetch(ctx context.Context) (map[string]string, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, s.cfg.URL, nil)
	if err != nil {
		return nil, err
	}
	resp, err := s.cfg.Client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("fetch status list: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("fetch status list: HTTP %d", resp.StatusCode)
	}
	body, err := io.ReadAll(io.LimitReader(resp.Body, maxStatusListBytes+1))
	if err != nil {
		return nil, fmt.Errorf("read status list: %w", err)
	}
	if len(body) > maxStatusListBytes {
		return nil, errors.New("status list too large")
	}
	var parsed statusListJSON
	if err := json.Unmarshal(body, &parsed); err != nil {
		return nil, fmt.Errorf("parse status list: %w", err)
	}
	if parsed.Entries == nil {
		return nil, errors.New("status list has no entries object")
	}
	m := make(map[string]string, len(parsed.Entries))
	for serial, e := range parsed.Entries {
		// Every listed serial is out, whatever the status says (REVOKED or
		// SUSPENDED); the reason is kept for the error message.
		m[strings.TrimLeft(strings.ToLower(strings.TrimSpace(serial)), "0")] = strings.TrimSpace(e.Status + " " + e.Reason)
	}
	return m, nil
}
