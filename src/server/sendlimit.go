package server

import (
	"crypto/sha256"
	"encoding/hex"
	"strings"
	"sync"
	"time"
)

// identifierSendLimiter caps how many verification messages one email
// address or phone number receives per hour, whoever asks. The per-IP
// limiter stops one client sending many messages; this stops many clients
// (or one rotating its IP) flooding one inbox, which is the harassment and
// phishing vector once real delivery is on.
//
// It keys on a hash of the normalized identifier, never the identifier
// itself, and lives in memory (the issuer runs as one instance; a restart
// forgets the counts, which only errs toward sending).
type identifierSendLimiter struct {
	perHour int

	mu    sync.Mutex
	sends map[string][]time.Time
}

func newIdentifierSendLimiter(perHour int) *identifierSendLimiter {
	return &identifierSendLimiter{perHour: perHour, sends: make(map[string][]time.Time)}
}

// allow records a send to key at now if fewer than perHour happened in the
// last hour, and otherwise reports how long until the oldest one ages out.
func (l *identifierSendLimiter) allow(key string, now time.Time) (bool, time.Duration) {
	l.mu.Lock()
	defer l.mu.Unlock()
	cutoff := now.Add(-time.Hour)
	recent := l.sends[key][:0]
	for _, t := range l.sends[key] {
		if t.After(cutoff) {
			recent = append(recent, t)
		}
	}
	if len(recent) >= l.perHour {
		l.sends[key] = recent
		return false, recent[0].Sub(cutoff)
	}
	if len(l.sends) >= maxBuckets {
		l.sweepLocked(cutoff)
		if len(l.sends) >= maxBuckets {
			return false, time.Minute
		}
	}
	l.sends[key] = append(recent, now)
	return true, 0
}

func (l *identifierSendLimiter) sweepLocked(cutoff time.Time) {
	for k, ts := range l.sends {
		if len(ts) == 0 || !ts[len(ts)-1].After(cutoff) {
			delete(l.sends, k)
		}
	}
}

// identifierSendKey is the limiter key for a /begin to raw under kind
// ("email" or "phone"): the same keyed HMAC identifier.go uses when
// IDENTIFIER_HMAC_KEY is set, else a plain SHA-256. Input that doesn't
// normalize is keyed as typed (lowercased), so it is still counted.
func (s *Server) identifierSendKey(kind, raw string) string {
	normalized, err := normalizeIdentifier(kind, raw)
	if err != nil {
		normalized = strings.ToLower(strings.TrimSpace(raw))
	}
	if s.identifierKeys != nil {
		return s.identifierKeys.Key(kind, normalized)
	}
	sum := sha256.Sum256([]byte(kind + ":" + normalized))
	return hex.EncodeToString(sum[:])
}
