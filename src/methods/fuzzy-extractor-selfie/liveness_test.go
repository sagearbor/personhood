package fuzzyextractorselfie

import (
	"context"
	"encoding/base64"
	"sync"
	"testing"
	"time"

	"github.com/sagearbor/personhood/pkg/types"
)

// fakeClock is a settable clock for ceremony timing.
type fakeClock struct {
	mu sync.Mutex
	t  time.Time
}

func (c *fakeClock) Now() time.Time { c.mu.Lock(); defer c.mu.Unlock(); return c.t }
func (c *fakeClock) Add(d time.Duration) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.t = c.t.Add(d)
}

func newLivenessMethod(t *testing.T) (*Method, *fakeClock) {
	t.Helper()
	clk := &fakeClock{t: time.Date(2026, 11, 3, 12, 0, 0, 0, time.UTC)}
	m := NewMethod(Config{
		Accumulator: NewInMemoryAccumulator(),
		Liveness:    &LivenessConfig{Key: make([]byte, 32), Now: clk.Now},
		Strength:    50,
	})
	return m, clk
}

// begin returns the issued challenge kinds and token.
func begin(t *testing.T, m *Method, session string) ([]string, string) {
	t.Helper()
	ch, err := m.BeginCeremony(context.Background(), types.CeremonyContext{SessionID: session})
	if err != nil {
		t.Fatalf("BeginCeremony: %v", err)
	}
	kinds, _ := ch.Payload["challenges"].([]string)
	token, _ := ch.Payload["challenge_token"].(string)
	if len(kinds) != ChallengeCount || token == "" {
		t.Fatalf("begin payload missing challenges/token: %+v", ch.Payload)
	}
	return kinds, token
}

// answers builds the liveness evidence the web client sends, as the
// decoded-JSON shape (map / []any) CompleteCeremony receives.
func answers(kinds []string, ms int) map[string]any {
	chs := make([]any, len(kinds))
	for i, k := range kinds {
		chs[i] = map[string]any{"kind": k, "ms": float64(ms)}
	}
	return map[string]any{"challenges": chs, "frames": float64(6)}
}

func complete(t *testing.T, m *Method, session string, payload map[string]any) types.MethodResult {
	t.Helper()
	res, err := m.CompleteCeremony(context.Background(), types.CeremonyContext{SessionID: session}, types.ResponseData{Payload: payload})
	if err != nil {
		t.Fatalf("CompleteCeremony: %v", err)
	}
	return res
}

func goodPayload(template []byte, kinds []string, token string) map[string]any {
	return map[string]any{
		"template_b64":     base64.StdEncoding.EncodeToString(template),
		"template_version": DefaultTemplateVersion,
		"challenge_token":  token,
		"liveness":         answers(kinds, 1200),
	}
}

func TestLiveness_BeginIssuesDistinctRandomChallenges(t *testing.T) {
	t.Parallel()
	m, _ := newLivenessMethod(t)
	orders := map[string]bool{}
	for i := 0; i < 200; i++ {
		kinds, _ := begin(t, m, "sess")
		seen := map[string]bool{}
		for _, k := range kinds {
			if seen[k] {
				t.Fatalf("repeated challenge in %v", kinds)
			}
			seen[k] = true
		}
		orders[kinds[0]+kinds[1]+kinds[2]] = true
	}
	// 24 possible orders; 200 draws should hit most of them.
	if len(orders) < 15 {
		t.Fatalf("only %d distinct orders in 200 draws; order is not random", len(orders))
	}
	if md := m.Metadata(); md.Strength != 50 || md.Type != types.MethodTypeAnchor {
		t.Fatalf("metadata = %+v, want anchor strength 50", md)
	}
}

func TestLiveness_HappyPathThenDuplicateRefused(t *testing.T) {
	t.Parallel()
	m, clk := newLivenessMethod(t)
	face := RandomTemplateForTesting()

	kinds, token := begin(t, m, "s1")
	clk.Add(8 * time.Second)
	res := complete(t, m, "s1", goodPayload(face, kinds, token))
	if !res.Success || res.AttestationDigest == "" {
		t.Fatalf("first enrollment failed: %+v", res)
	}

	// Same face again, a little noisy, in a new session: refused.
	kinds, token = begin(t, m, "s2")
	clk.Add(8 * time.Second)
	res = complete(t, m, "s2", goodPayload(NoisyTemplateForTesting(face, 20), kinds, token))
	if res.Success || res.ErrorReason != "duplicate_person_detected" {
		t.Fatalf("re-enrollment of the same face: %+v, want duplicate_person_detected", res)
	}

	// A different face enrolls.
	kinds, token = begin(t, m, "s3")
	clk.Add(8 * time.Second)
	if res = complete(t, m, "s3", goodPayload(RandomTemplateForTesting(), kinds, token)); !res.Success {
		t.Fatalf("different face refused: %+v", res)
	}
}

func TestLiveness_Rejections(t *testing.T) {
	t.Parallel()
	face := RandomTemplateForTesting()
	cases := []struct {
		name   string
		mutate func(p map[string]any, kinds []string)
		wait   time.Duration
		want   string
	}{
		{"no token", func(p map[string]any, _ []string) { delete(p, "challenge_token") }, 8 * time.Second, "missing_challenge_token"},
		{"tampered token", func(p map[string]any, _ []string) {
			tok := []byte(p["challenge_token"].(string))
			if tok[0] == 'A' {
				tok[0] = 'B'
			} else {
				tok[0] = 'A'
			}
			p["challenge_token"] = string(tok)
		}, 8 * time.Second, "invalid_challenge_token"},
		{"wrong template version", func(p map[string]any, _ []string) { p["template_version"] = "ahash-v0" }, 8 * time.Second, "unsupported_template_version"},
		{"no liveness", func(p map[string]any, _ []string) { delete(p, "liveness") }, 8 * time.Second, "missing_liveness"},
		{"wrong order", func(p map[string]any, k []string) {
			p["liveness"] = answers([]string{k[1], k[0], k[2]}, 1200)
		}, 8 * time.Second, "liveness_challenge_mismatch"},
		{"too few", func(p map[string]any, k []string) { p["liveness"] = answers(k[:2], 1200) }, 8 * time.Second, "liveness_challenge_mismatch"},
		{"inhumanly quick answer", func(p map[string]any, k []string) { p["liveness"] = answers(k, 40) }, 8 * time.Second, "liveness_timing_implausible"},
		{"answers longer than the ceremony", func(p map[string]any, k []string) { p["liveness"] = answers(k, 3000) }, 5 * time.Second, "liveness_timing_implausible"},
		{"ceremony too fast", nil, time.Second, "liveness_too_fast"},
		{"ceremony expired", nil, 11 * time.Minute, "challenge_expired"},
	}
	for _, tc := range cases {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			m, clk := newLivenessMethod(t)
			kinds, token := begin(t, m, "sess")
			clk.Add(tc.wait)
			p := goodPayload(face, kinds, token)
			if tc.mutate != nil {
				tc.mutate(p, kinds)
			}
			res := complete(t, m, "sess", p)
			if res.Success || res.ErrorReason != tc.want {
				t.Fatalf("got %+v, want error %q", res, tc.want)
			}
			if n, _ := m.accumulator.Count(context.Background()); n != 0 {
				t.Fatalf("a rejected ceremony enrolled a template (count %d)", n)
			}
		})
	}
}

func TestLiveness_TokenBoundToSession(t *testing.T) {
	t.Parallel()
	m, clk := newLivenessMethod(t)
	kinds, token := begin(t, m, "session-a")
	clk.Add(8 * time.Second)
	res := complete(t, m, "session-b", goodPayload(RandomTemplateForTesting(), kinds, token))
	if res.ErrorReason != "invalid_challenge_token" {
		t.Fatalf("token from another session: %+v, want invalid_challenge_token", res)
	}
}

func TestLiveness_ConcurrentSameFaceEnrollsOnce(t *testing.T) {
	t.Parallel()
	m, clk := newLivenessMethod(t)
	face := RandomTemplateForTesting()
	const n = 8
	payloads := make([]map[string]any, n)
	for i := range payloads {
		kinds, token := begin(t, m, "sess-"+string(rune('a'+i)))
		payloads[i] = goodPayload(NoisyTemplateForTesting(face, 10), kinds, token)
	}
	clk.Add(8 * time.Second)
	var wg sync.WaitGroup
	var mu sync.Mutex
	ok := 0
	for i := range payloads {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			res, err := m.CompleteCeremony(context.Background(), types.CeremonyContext{SessionID: "sess-" + string(rune('a'+i))}, types.ResponseData{Payload: payloads[i]})
			if err != nil {
				t.Error(err)
				return
			}
			if res.Success {
				mu.Lock()
				ok++
				mu.Unlock()
			}
		}(i)
	}
	wg.Wait()
	if ok != 1 {
		t.Fatalf("%d of %d concurrent enrollments of one face succeeded, want 1", ok, n)
	}
}

func TestLiveness_ShortKeyPanics(t *testing.T) {
	t.Parallel()
	defer func() {
		if recover() == nil {
			t.Fatal("NewMethod with a 16-byte liveness key did not panic")
		}
	}()
	NewMethod(Config{Accumulator: NewInMemoryAccumulator(), Liveness: &LivenessConfig{Key: make([]byte, 16)}})
}
