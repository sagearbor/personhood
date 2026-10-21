package server

import (
	"math"
	"net"
	"net/http"
	"strconv"
	"strings"
	"sync"
	"time"
)

// RateLimitConfig bounds how often one client may call the issuer. Each
// request is classified by route into one of three buckets, each a token
// bucket per client IP:
//
//   - Start: POST /enrollment/start. Every accepted call allocates a session
//     (a Firestore write on the live deployment), so it is the tightest.
//   - Begin: POST /v1/methods/{id}/begin. Once real email/SMS delivery is on,
//     each call sends a message to a third party — the costly, abusable one.
//   - Default: everything else, sized for the web app polling
//     GET /v1/sessions/{id} every couple of seconds.
//
// GET /health and /healthz are never limited, so probes keep working while a
// client is being throttled.
//
// The zero value disables limiting. LoadConfigFromEnv turns it on with
// DefaultRateLimitConfig unless RATE_LIMIT=off.
type RateLimitConfig struct {
	Enabled bool

	// PerMinute is the sustained refill rate; Burst is the bucket size.
	StartPerMinute, StartBurst     float64
	BeginPerMinute, BeginBurst     float64
	DefaultPerMinute, DefaultBurst float64

	// TrustedProxyHops is how many proxies in front of the server append to
	// X-Forwarded-For. 0 means use the TCP peer address and ignore the
	// header entirely (a client can write anything into it). Cloud Run's
	// frontend appends exactly one entry — the real client IP — after any
	// value the client sent, so Cloud Run deployments set 1 and the limiter
	// keys on the rightmost entry, which the client cannot forge.
	// Env: TRUSTED_PROXY_HOPS.
	TrustedProxyHops int
}

// DefaultRateLimitConfig is generous for a human on a phone and tight for a
// script. A human enrolls once, sends a handful of codes, and polls; a script
// trying to mint sessions or spam inboxes hits 429 within seconds.
func DefaultRateLimitConfig() RateLimitConfig {
	return RateLimitConfig{
		Enabled:          true,
		StartPerMinute:   6,
		StartBurst:       6,
		BeginPerMinute:   6,
		BeginBurst:       4,
		DefaultPerMinute: 120,
		DefaultBurst:     60,
	}
}

type rateClass int

const (
	classDefault rateClass = iota
	classStart
	classBegin
)

type bucket struct {
	tokens float64
	last   time.Time
}

type rateLimiter struct {
	cfg RateLimitConfig
	now func() time.Time

	mu        sync.Mutex
	buckets   map[string]*bucket
	lastSweep time.Time
}

func newRateLimiter(cfg RateLimitConfig, now func() time.Time) *rateLimiter {
	if now == nil {
		now = time.Now
	}
	return &rateLimiter{cfg: cfg, now: now, buckets: make(map[string]*bucket)}
}

func (l *rateLimiter) params(c rateClass) (perMinute, burst float64) {
	switch c {
	case classStart:
		return l.cfg.StartPerMinute, l.cfg.StartBurst
	case classBegin:
		return l.cfg.BeginPerMinute, l.cfg.BeginBurst
	default:
		return l.cfg.DefaultPerMinute, l.cfg.DefaultBurst
	}
}

// allow takes one token from (client, class)'s bucket. When the bucket is
// empty it returns false and how long until a token is available.
func (l *rateLimiter) allow(client string, c rateClass) (bool, time.Duration) {
	perMinute, burst := l.params(c)
	if perMinute <= 0 || burst <= 0 {
		return true, 0
	}
	perSec := perMinute / 60
	now := l.now()
	key := strconv.Itoa(int(c)) + "|" + client

	l.mu.Lock()
	defer l.mu.Unlock()
	l.sweepLocked(now)

	b, ok := l.buckets[key]
	if !ok {
		b = &bucket{tokens: burst, last: now}
		l.buckets[key] = b
	}
	b.tokens = math.Min(burst, b.tokens+now.Sub(b.last).Seconds()*perSec)
	b.last = now
	if b.tokens >= 1 {
		b.tokens--
		return true, 0
	}
	wait := time.Duration((1 - b.tokens) / perSec * float64(time.Second))
	return false, wait
}

// sweepLocked drops buckets idle long enough to have refilled completely, so
// the map's size tracks recently active clients rather than every IP ever
// seen. Runs at most once a minute.
func (l *rateLimiter) sweepLocked(now time.Time) {
	if now.Sub(l.lastSweep) < time.Minute {
		return
	}
	l.lastSweep = now
	for k, b := range l.buckets {
		if now.Sub(b.last) > 10*time.Minute {
			delete(l.buckets, k)
		}
	}
}

func classify(r *http.Request) (rateClass, bool) {
	p := r.URL.Path
	if p == "/health" || p == "/healthz" || r.Method == http.MethodOptions {
		return 0, false
	}
	if r.Method == http.MethodPost {
		if p == "/enrollment/start" {
			return classStart, true
		}
		if strings.HasPrefix(p, "/v1/methods/") && strings.HasSuffix(p, "/begin") {
			return classBegin, true
		}
	}
	return classDefault, true
}

// clientIP picks the address the limiter keys on; see
// RateLimitConfig.TrustedProxyHops.
func clientIP(r *http.Request, trustedHops int) string {
	if trustedHops > 0 {
		var hops []string
		for _, h := range r.Header.Values("X-Forwarded-For") {
			for _, part := range strings.Split(h, ",") {
				if part = strings.TrimSpace(part); part != "" {
					hops = append(hops, part)
				}
			}
		}
		if len(hops) >= trustedHops {
			return hops[len(hops)-trustedHops]
		}
	}
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		return r.RemoteAddr
	}
	return host
}

func (l *rateLimiter) middleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		c, limited := classify(r)
		if !limited {
			next.ServeHTTP(w, r)
			return
		}
		ok, wait := l.allow(clientIP(r, l.cfg.TrustedProxyHops), c)
		if !ok {
			secs := int(math.Ceil(wait.Seconds()))
			if secs < 1 {
				secs = 1
			}
			w.Header().Set("Retry-After", strconv.Itoa(secs))
			writeError(w, http.StatusTooManyRequests, "rate_limited",
				"too many requests; retry after "+strconv.Itoa(secs)+"s")
			return
		}
		next.ServeHTTP(w, r)
	})
}

// maxBodyBytes caps every request body. The largest legitimate body is a
// method /complete payload or a third-party webhook — a few KB. Without a
// cap, one client can make the issuer buffer an arbitrarily large JSON
// document.
const maxBodyBytes = 256 << 10

func limitBody(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Body != nil {
			r.Body = http.MaxBytesReader(w, r.Body, maxBodyBytes)
		}
		next.ServeHTTP(w, r)
	})
}
