package email

import (
	"context"
	"fmt"
	"io"
	"log"
	"net/url"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/sagearbor/personhood/pkg/types"
)

// captureSender records the last sent message instead of actually sending. It
// also exposes the captured magic-link URL for tests to extract the token.
type captureSender struct {
	mu          sync.Mutex
	lastTo      string
	lastSubject string
	lastLink    string
	sendErr     error
	calls       int
}

func (c *captureSender) Send(_ context.Context, to, subject, link string) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.calls++
	if c.sendErr != nil {
		return c.sendErr
	}
	c.lastTo = to
	c.lastSubject = subject
	c.lastLink = link
	return nil
}

func (c *captureSender) tokenFromLink(t *testing.T) string {
	t.Helper()
	c.mu.Lock()
	link := c.lastLink
	c.mu.Unlock()
	if link == "" {
		t.Fatalf("no magic-link URL captured")
	}
	u, err := url.Parse(link)
	if err != nil {
		t.Fatalf("parse captured link: %v", err)
	}
	tok := u.Query().Get(magicLinkQueryParam)
	if tok == "" {
		t.Fatalf("magic-link URL missing token query param: %s", link)
	}
	return tok
}

func newTestMethod(t *testing.T) (*Method, *captureSender, *InMemoryStore) {
	t.Helper()
	sender := &captureSender{}
	store := NewInMemoryStore()
	m := NewMethod(sender, "https://issuer.example.com/methods/email/verify", store)
	return m, sender, store
}

func ceremonyCtx(sessionID, emailAddr string) types.CeremonyContext {
	return types.CeremonyContext{
		SessionID: sessionID,
		UserID:    emailAddr,
		MethodID:  "email",
		IssuerDID: "did:web:issuer.example.com",
		StartedAt: time.Now(),
	}
}

func TestMetadata(t *testing.T) {
	m, _, _ := newTestMethod(t)
	md := m.Metadata()
	if md.ID != "email" {
		t.Errorf("ID = %q, want %q", md.ID, "email")
	}
	if md.Type != types.MethodTypeSupplementary {
		t.Errorf("Type = %q, want supplementary", md.Type)
	}
	if md.Strength != 8 {
		t.Errorf("Strength = %d, want 8", md.Strength)
	}
	if md.CostUSD != 0 {
		t.Errorf("CostUSD = %v, want 0", md.CostUSD)
	}
	if md.UXFriction != types.FrictionLow {
		t.Errorf("UXFriction = %q, want low", md.UXFriction)
	}
	if md.FreshnessLifetime != 90*24*time.Hour {
		t.Errorf("FreshnessLifetime = %v, want 90 days", md.FreshnessLifetime)
	}
	if md.Version != "0.1.0" {
		t.Errorf("Version = %q, want 0.1.0", md.Version)
	}
	if len(md.PlatformRequirements) != 0 {
		t.Errorf("PlatformRequirements = %v, want empty", md.PlatformRequirements)
	}
}

func TestIsAvailableForUser_AlwaysTrue(t *testing.T) {
	m, _, _ := newTestMethod(t)
	ok, reason := m.IsAvailableForUser(types.UserContext{Platform: "ios"})
	if !ok || reason != "" {
		t.Errorf("expected (true, \"\"), got (%v, %q)", ok, reason)
	}
}

func TestBeginCompleteRoundtrip(t *testing.T) {
	m, sender, _ := newTestMethod(t)
	cc := ceremonyCtx("sess-1", "alice@example.com")
	ctx := context.Background()

	ch, err := m.BeginCeremony(ctx, cc)
	if err != nil {
		t.Fatalf("BeginCeremony: %v", err)
	}
	if ch.Type != "magic-link" {
		t.Errorf("ChallengeData.Type = %q, want \"magic-link\"", ch.Type)
	}
	if got := ch.Payload["email_address"]; got != "alice@example.com" {
		t.Errorf("payload email_address = %v, want alice@example.com", got)
	}
	if _, ok := ch.Payload["magic_link_url"].(string); !ok {
		t.Errorf("payload magic_link_url not a string: %v", ch.Payload["magic_link_url"])
	}
	if sender.lastTo != "alice@example.com" {
		t.Errorf("sender.to = %q, want alice@example.com", sender.lastTo)
	}

	token := sender.tokenFromLink(t)
	resp := types.ResponseData{
		Type:    "magic-link-click",
		Payload: map[string]any{"token": token},
	}
	res, err := m.CompleteCeremony(ctx, cc, resp)
	if err != nil {
		t.Fatalf("CompleteCeremony: %v", err)
	}
	if !res.Success {
		t.Fatalf("expected Success=true, got %+v", res)
	}
	if res.MethodID != "email" {
		t.Errorf("MethodID = %q, want email", res.MethodID)
	}
	if res.AttestationDigest == "" {
		t.Errorf("AttestationDigest empty")
	}
	if res.VerifiedAt.IsZero() {
		t.Errorf("VerifiedAt zero")
	}
}

func TestBeginCeremony_RejectsDisposableEmail(t *testing.T) {
	m, sender, store := newTestMethod(t)
	cc := ceremonyCtx("sess-disp", "bob@mailinator.com")
	_, err := m.BeginCeremony(context.Background(), cc)
	if err == nil {
		t.Fatalf("expected error for disposable email, got nil")
	}
	if !strings.Contains(err.Error(), "Disposable") {
		t.Errorf("error %q should mention Disposable", err)
	}
	if sender.calls != 0 {
		t.Errorf("Sender.Send must not be called for disposable email, got %d calls", sender.calls)
	}
	if _, ok := store.entries.Load("sess-disp"); ok {
		t.Errorf("store should not contain entry for rejected session")
	}
}

func TestBeginCeremony_RejectsMissingEmail(t *testing.T) {
	m, _, _ := newTestMethod(t)
	cc := ceremonyCtx("sess-empty", "")
	if _, err := m.BeginCeremony(context.Background(), cc); err == nil {
		t.Fatalf("expected error for empty UserID, got nil")
	}
}

func TestBeginCeremony_RejectsMalformedEmail(t *testing.T) {
	m, _, _ := newTestMethod(t)
	for _, bad := range []string{"no-at-sign", "trailing@", "@no-local"} {
		cc := ceremonyCtx("sess-bad", bad)
		if _, err := m.BeginCeremony(context.Background(), cc); err == nil {
			t.Errorf("expected error for malformed email %q, got nil", bad)
		}
	}
}

func TestCompleteCeremony_WrongToken(t *testing.T) {
	m, sender, _ := newTestMethod(t)
	cc := ceremonyCtx("sess-wrong", "carol@example.com")
	if _, err := m.BeginCeremony(context.Background(), cc); err != nil {
		t.Fatalf("BeginCeremony: %v", err)
	}
	_ = sender.tokenFromLink(t) // capture real token but discard

	resp := types.ResponseData{
		Type:    "magic-link-click",
		Payload: map[string]any{"token": "totally-wrong-token"},
	}
	res, err := m.CompleteCeremony(context.Background(), cc, resp)
	if err != nil {
		t.Fatalf("CompleteCeremony: %v", err)
	}
	if res.Success {
		t.Fatalf("expected Success=false, got %+v", res)
	}
	if res.ErrorReason != "invalid_or_expired_token" {
		t.Errorf("ErrorReason = %q, want invalid_or_expired_token", res.ErrorReason)
	}
}

func TestCompleteCeremony_AfterExpiry(t *testing.T) {
	sender := &captureSender{}
	store := NewInMemoryStore()
	m := NewMethod(sender, "https://issuer.example.com/methods/email/verify", store)
	cc := ceremonyCtx("sess-expire", "dave@example.com")
	ctx := context.Background()

	if _, err := m.BeginCeremony(ctx, cc); err != nil {
		t.Fatalf("BeginCeremony: %v", err)
	}
	token := sender.tokenFromLink(t)

	// Force-expire the entry by rewriting it with a past expiry.
	if err := store.Put(ctx, cc.SessionID, token, "dave@example.com", time.Now().Add(-time.Second)); err != nil {
		t.Fatalf("Put: %v", err)
	}

	resp := types.ResponseData{Type: "magic-link-click", Payload: map[string]any{"token": token}}
	res, err := m.CompleteCeremony(ctx, cc, resp)
	if err != nil {
		t.Fatalf("CompleteCeremony: %v", err)
	}
	if res.Success {
		t.Fatalf("expected Success=false after expiry, got %+v", res)
	}
	if res.ErrorReason != "invalid_or_expired_token" {
		t.Errorf("ErrorReason = %q, want invalid_or_expired_token", res.ErrorReason)
	}
}

func TestCompleteCeremony_BadResponseShape(t *testing.T) {
	m, _, _ := newTestMethod(t)
	cc := ceremonyCtx("sess-shape", "eve@example.com")
	ctx := context.Background()
	_, _ = m.BeginCeremony(ctx, cc)

	cases := []struct {
		name   string
		resp   types.ResponseData
		reason string
	}{
		{
			name:   "wrong type",
			resp:   types.ResponseData{Type: "otp", Payload: map[string]any{"token": "x"}},
			reason: "unexpected response type",
		},
		{
			name:   "missing token",
			resp:   types.ResponseData{Type: "magic-link-click", Payload: map[string]any{}},
			reason: "missing token",
		},
		{
			name:   "token wrong type",
			resp:   types.ResponseData{Type: "magic-link-click", Payload: map[string]any{"token": 42}},
			reason: "non-empty string",
		},
	}
	for _, tc := range cases {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			res, err := m.CompleteCeremony(ctx, cc, tc.resp)
			if err != nil {
				t.Fatalf("CompleteCeremony: %v", err)
			}
			if res.Success {
				t.Fatalf("expected Success=false, got %+v", res)
			}
			if !strings.Contains(res.ErrorReason, tc.reason) {
				t.Errorf("ErrorReason = %q, want substring %q", res.ErrorReason, tc.reason)
			}
		})
	}
}

func TestCompleteCeremony_SingleUse(t *testing.T) {
	m, sender, _ := newTestMethod(t)
	cc := ceremonyCtx("sess-single", "frank@example.com")
	ctx := context.Background()
	if _, err := m.BeginCeremony(ctx, cc); err != nil {
		t.Fatalf("BeginCeremony: %v", err)
	}
	token := sender.tokenFromLink(t)
	resp := types.ResponseData{Type: "magic-link-click", Payload: map[string]any{"token": token}}

	res1, _ := m.CompleteCeremony(ctx, cc, resp)
	if !res1.Success {
		t.Fatalf("first Complete should succeed, got %+v", res1)
	}
	res2, _ := m.CompleteCeremony(ctx, cc, resp)
	if res2.Success {
		t.Fatalf("second Complete must fail (token consumed), got %+v", res2)
	}
}

func TestConcurrentCeremoniesIsolated(t *testing.T) {
	m, sender, _ := newTestMethod(t)
	ctx := context.Background()

	const N = 25
	type pair struct {
		cc    types.CeremonyContext
		token string
	}

	// Begin N ceremonies in parallel.
	pairs := make([]pair, N)
	var wg sync.WaitGroup
	wg.Add(N)
	// Serialize Begin so we can deterministically grab each token from
	// sender.lastLink without races; the actual concurrency under test is
	// Complete.
	for i := 0; i < N; i++ {
		cc := ceremonyCtx(fmt.Sprintf("sess-%d", i), fmt.Sprintf("user%d@example.com", i))
		if _, err := m.BeginCeremony(ctx, cc); err != nil {
			t.Fatalf("BeginCeremony[%d]: %v", i, err)
		}
		pairs[i] = pair{cc: cc, token: sender.tokenFromLink(t)}
	}

	results := make([]bool, N)
	for i := 0; i < N; i++ {
		i := i
		go func() {
			defer wg.Done()
			resp := types.ResponseData{Type: "magic-link-click", Payload: map[string]any{"token": pairs[i].token}}
			res, err := m.CompleteCeremony(ctx, pairs[i].cc, resp)
			if err != nil {
				t.Errorf("Complete[%d] err: %v", i, err)
				return
			}
			results[i] = res.Success
		}()
	}
	wg.Wait()
	for i, ok := range results {
		if !ok {
			t.Errorf("ceremony %d failed unexpectedly", i)
		}
	}

	// Cross-contamination check: token from session 0 against session 1.
	if N >= 2 {
		resp := types.ResponseData{Type: "magic-link-click", Payload: map[string]any{"token": pairs[0].token}}
		// session 1 was already consumed above; reopen.
		cc1b := ceremonyCtx(pairs[1].cc.SessionID, pairs[1].cc.UserID)
		if _, err := m.BeginCeremony(ctx, cc1b); err != nil {
			t.Fatalf("re-Begin sess-1: %v", err)
		}
		res, _ := m.CompleteCeremony(ctx, cc1b, resp)
		if res.Success {
			t.Errorf("token from sess-0 must not unlock sess-1")
		}
	}
}

func TestInMemoryStore_Roundtrip(t *testing.T) {
	s := NewInMemoryStore()
	ctx := context.Background()
	exp := time.Now().Add(5 * time.Minute)
	if err := s.Put(ctx, "sess", "tok", "x@y.com", exp); err != nil {
		t.Fatalf("Put: %v", err)
	}
	email, found, err := s.Lookup(ctx, "sess", "tok")
	if err != nil || !found || email != "x@y.com" {
		t.Errorf("Lookup = (%q, %v, %v), want (x@y.com, true, nil)", email, found, err)
	}
	// Wrong token
	_, found, _ = s.Lookup(ctx, "sess", "other")
	if found {
		t.Errorf("Lookup with wrong token should miss")
	}
	// Wrong session
	_, found, _ = s.Lookup(ctx, "other", "tok")
	if found {
		t.Errorf("Lookup with wrong session should miss")
	}
	// Delete
	if err := s.Delete(ctx, "sess"); err != nil {
		t.Fatalf("Delete: %v", err)
	}
	_, found, _ = s.Lookup(ctx, "sess", "tok")
	if found {
		t.Errorf("Lookup after Delete should miss")
	}
	// Delete is idempotent
	if err := s.Delete(ctx, "sess"); err != nil {
		t.Fatalf("Delete idempotent: %v", err)
	}
}

func TestInMemoryStore_Expiry(t *testing.T) {
	s := NewInMemoryStore()
	ctx := context.Background()
	_ = s.Put(ctx, "sess", "tok", "x@y.com", time.Now().Add(-time.Hour))
	_, found, err := s.Lookup(ctx, "sess", "tok")
	if err != nil {
		t.Fatalf("Lookup: %v", err)
	}
	if found {
		t.Errorf("expired entry should not be found")
	}
}

func TestIsDisposable(t *testing.T) {
	cases := []struct {
		email string
		want  bool
	}{
		{"alice@mailinator.com", true},
		{"alice@MailInAtor.COM", true},
		{"alice@gmail.com", false},
		{"alice@personhood.org", false},
		{"", false},
		{"no-at-sign", false},
		{"alice@", false},
		{"@only.com", false},
	}
	for _, c := range cases {
		if got := IsDisposable(c.email); got != c.want {
			t.Errorf("IsDisposable(%q) = %v, want %v", c.email, got, c.want)
		}
	}
}

func TestNewMethod_PanicsOnNilOrEmpty(t *testing.T) {
	cases := []struct {
		name string
		fn   func()
	}{
		{"nil sender", func() { NewMethod(nil, "https://x", NewInMemoryStore()) }},
		{"nil store", func() { NewMethod(&LogSender{}, "https://x", nil) }},
		{"empty url", func() { NewMethod(&LogSender{}, "  ", NewInMemoryStore()) }},
	}
	for _, c := range cases {
		c := c
		t.Run(c.name, func(t *testing.T) {
			defer func() {
				if r := recover(); r == nil {
					t.Errorf("expected panic, got none")
				}
			}()
			c.fn()
		})
	}
}

func TestSendFailure_RollsBackStore(t *testing.T) {
	sender := &captureSender{sendErr: fmt.Errorf("smtp blew up")}
	store := NewInMemoryStore()
	m := NewMethod(sender, "https://issuer.example.com/verify", store)
	cc := ceremonyCtx("sess-rollback", "grace@example.com")
	if _, err := m.BeginCeremony(context.Background(), cc); err == nil {
		t.Fatalf("expected Send error to propagate")
	}
	if _, ok := store.entries.Load("sess-rollback"); ok {
		t.Errorf("store entry should have been rolled back on send failure")
	}
}

func TestLogSender_NilLoggerOK(t *testing.T) {
	// Use a discard logger to keep test output clean while still exercising
	// the non-nil path.
	ls := &LogSender{Logger: log.New(io.Discard, "", 0)}
	if err := ls.Send(context.Background(), "x@y", "subj", "http://link"); err != nil {
		t.Fatalf("LogSender.Send: %v", err)
	}
	// Now exercise the nil-logger default path.
	ls2 := &LogSender{}
	prevOut := log.Default().Writer()
	log.Default().SetOutput(io.Discard)
	defer log.Default().SetOutput(prevOut)
	if err := ls2.Send(context.Background(), "x@y", "subj", "http://link"); err != nil {
		t.Fatalf("LogSender.Send (nil logger): %v", err)
	}
}
