package server

import (
	"bytes"
	"encoding/json"
	"net/http"
	"testing"
	"time"
)

func TestIdentifierSendLimiter_WindowAndRetryAfter(t *testing.T) {
	l := newIdentifierSendLimiter(2)
	t0 := time.Date(2026, 10, 29, 0, 0, 0, 0, time.UTC)
	for i := 0; i < 2; i++ {
		if ok, _ := l.allow("k", t0.Add(time.Duration(i)*time.Minute)); !ok {
			t.Fatalf("send %d refused, want allowed", i)
		}
	}
	ok, wait := l.allow("k", t0.Add(10*time.Minute))
	if ok || wait != 50*time.Minute {
		t.Fatalf("third send: ok=%v wait=%v, want refused with 50m", ok, wait)
	}
	if ok, _ := l.allow("other", t0.Add(10*time.Minute)); !ok {
		t.Error("another identifier should have its own budget")
	}
	if ok, _ := l.allow("k", t0.Add(61*time.Minute)); !ok {
		t.Error("send after the first one aged out should be allowed")
	}
}

func TestIdentifierSendKey_NormalizesAndHidesAddress(t *testing.T) {
	s := &Server{}
	a := s.identifierSendKey("email", "Some.One+tag@gmail.com")
	b := s.identifierSendKey("email", " someone@googlemail.com ")
	if a != b {
		t.Errorf("spellings of one inbox got different keys: %q vs %q", a, b)
	}
	if bytes.Contains([]byte(a), []byte("someone")) {
		t.Error("key leaks the address")
	}
}

// TestIntegration_BeginLimitedPerIdentifier: different sessions (as if from
// different clients) can't send a third message to one address within the
// hour.
func TestIntegration_BeginLimitedPerIdentifier(t *testing.T) {
	base, _, _, _, cleanup := newTestServerWith(t, func(c *Config) { c.RateLimit.IdentifierSendsPerHour = 2 })
	defer cleanup()
	begin := func(addr string) (int, string, string) {
		var start startEnrollmentResponse
		mustPOST(t, base+"/enrollment/start", mustJSON(t, map[string]any{"platform": "web"}), &start)
		resp, err := http.Post(base+"/v1/methods/email/begin", "application/json", bytes.NewReader(mustJSON(t, map[string]any{
			"session_id": start.SessionID,
			"user_input": addr,
		})))
		if err != nil {
			t.Fatal(err)
		}
		defer resp.Body.Close()
		var out struct {
			Error struct {
				Code string `json:"code"`
			} `json:"error"`
		}
		_ = json.NewDecoder(resp.Body).Decode(&out)
		return resp.StatusCode, out.Error.Code, resp.Header.Get("Retry-After")
	}
	for i := 0; i < 2; i++ {
		if code, ec, _ := begin("victim@example.com"); code != http.StatusOK {
			t.Fatalf("send %d: %d %s", i, code, ec)
		}
	}
	code, ec, retry := begin("VICTIM@example.com")
	if code != http.StatusTooManyRequests || ec != "identifier_rate_limited" || retry == "" {
		t.Errorf("third send: %d %q Retry-After=%q, want 429 identifier_rate_limited with Retry-After", code, ec, retry)
	}
	if code, ec, _ := begin("someone-else@example.com"); code != http.StatusOK {
		t.Errorf("other address: %d %s, want 200", code, ec)
	}
}
