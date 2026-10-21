package server

import (
	"io"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"testing"
	"time"
)

func TestRateLimiter_BucketRefills(t *testing.T) {
	now := time.Unix(1_700_000_000, 0)
	l := newRateLimiter(RateLimitConfig{Enabled: true, StartPerMinute: 6, StartBurst: 2}, func() time.Time { return now })

	for i := 0; i < 2; i++ {
		if ok, _ := l.allow("1.2.3.4", classStart); !ok {
			t.Fatalf("request %d within burst was refused", i)
		}
	}
	ok, wait := l.allow("1.2.3.4", classStart)
	if ok {
		t.Fatal("request beyond burst was allowed")
	}
	if wait != 10*time.Second {
		t.Fatalf("wait = %v, want 10s at 6/min", wait)
	}
	if ok, _ := l.allow("5.6.7.8", classStart); !ok {
		t.Fatal("a different client shares the first client's bucket")
	}

	now = now.Add(10 * time.Second)
	if ok, _ := l.allow("1.2.3.4", classStart); !ok {
		t.Fatal("bucket did not refill after the advertised wait")
	}
}

func TestRateLimiter_ClassesAreIndependent(t *testing.T) {
	l := newRateLimiter(RateLimitConfig{Enabled: true, StartPerMinute: 1, StartBurst: 1, DefaultPerMinute: 60, DefaultBurst: 5}, nil)
	l.allow("ip", classStart)
	if ok, _ := l.allow("ip", classStart); ok {
		t.Fatal("start bucket should be empty")
	}
	if ok, _ := l.allow("ip", classDefault); !ok {
		t.Fatal("exhausting the start bucket throttled default routes too")
	}
}

func TestClientIP(t *testing.T) {
	cases := []struct {
		name string
		xff  []string
		hops int
		want string
	}{
		{"no proxy ignores header", []string{"6.6.6.6"}, 0, "10.0.0.1"},
		{"one hop takes rightmost", []string{"6.6.6.6, 9.9.9.9"}, 1, "9.9.9.9"},
		{"one hop across header lines", []string{"6.6.6.6", "9.9.9.9"}, 1, "9.9.9.9"},
		{"missing header falls back to peer", nil, 1, "10.0.0.1"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			r := httptest.NewRequest(http.MethodGet, "/", nil)
			r.RemoteAddr = "10.0.0.1:5555"
			for _, v := range tc.xff {
				r.Header.Add("X-Forwarded-For", v)
			}
			if got := clientIP(r, tc.hops); got != tc.want {
				t.Fatalf("clientIP = %q, want %q", got, tc.want)
			}
		})
	}
}

func TestRouter_RateLimitsEnrollmentStart(t *testing.T) {
	base, _, _, _, cleanup := newTestServerWith(t, func(c *Config) {
		c.RateLimit = RateLimitConfig{Enabled: true, StartPerMinute: 1, StartBurst: 2, DefaultPerMinute: 600, DefaultBurst: 100}
	})
	defer cleanup()

	for i := 0; i < 2; i++ {
		if status, body := postRaw(t, base+"/enrollment/start", []byte(`{}`)); status != http.StatusOK {
			t.Fatalf("start %d: status %d body %v", i, status, body)
		}
	}
	resp, err := http.Post(base+"/enrollment/start", "application/json", strings.NewReader(`{}`))
	if err != nil {
		t.Fatal(err)
	}
	raw, _ := io.ReadAll(resp.Body)
	resp.Body.Close()
	if resp.StatusCode != http.StatusTooManyRequests {
		t.Fatalf("third start: status %d, want 429", resp.StatusCode)
	}
	if resp.Header.Get("Retry-After") == "" {
		t.Fatal("429 without Retry-After")
	}
	if !strings.Contains(string(raw), `"rate_limited"`) {
		t.Fatalf("429 body lacks rate_limited code: %s", raw)
	}

	// Probes are never throttled.
	hr, err := http.Get(base + "/health")
	if err != nil {
		t.Fatal(err)
	}
	hr.Body.Close()
	if hr.StatusCode != http.StatusOK {
		t.Fatalf("/health while throttled: %d", hr.StatusCode)
	}
}

func TestRouter_RejectsOversizedBody(t *testing.T) {
	base, _, _, _, cleanup := newTestServer(t)
	defer cleanup()
	body := `{"holder_public_key_b64":"` + strings.Repeat("A", maxBodyBytes) + `"}`
	status, _ := postRaw(t, base+"/enrollment/start", []byte(body))
	if status != http.StatusBadRequest {
		t.Fatalf("oversized body: status %d, want 400", status)
	}
}

func TestLimiterKey_GroupsIPv6By64(t *testing.T) {
	a := limiterKey("2001:db8:1:2:aaaa::1")
	b := limiterKey("2001:db8:1:2:ffff:ffff:ffff:ffff")
	c := limiterKey("2001:db8:1:3::1")
	if a != b || a == c {
		t.Errorf("keys: %q %q %q; want the first two equal and the third different", a, b, c)
	}
	if got := limiterKey("203.0.113.7"); got != "203.0.113.7" {
		t.Errorf("IPv4 key = %q", got)
	}
	if got := limiterKey("::ffff:203.0.113.7"); got != "::ffff:203.0.113.7" {
		t.Errorf("IPv4-mapped key = %q, want it untouched", got)
	}
}

func TestRateLimiter_CapsBucketCount(t *testing.T) {
	l := newRateLimiter(DefaultRateLimitConfig(), time.Now)
	for i := 0; i < maxBuckets; i++ {
		l.buckets[strconv.Itoa(i)] = &bucket{tokens: 1, last: time.Now()}
	}
	if ok, _ := l.allow("198.51.100.1", classDefault); ok {
		t.Error("a new client was admitted with the bucket map full")
	}
}
