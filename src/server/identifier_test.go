package server

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"errors"
	"io"
	"net/http"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/sagearbor/personhood/pkg/types"
)

func TestNormalizeEmail(t *testing.T) {
	cases := []struct{ in, want string }{
		{"alice@example.com", "alice@example.com"},
		{"  Alice@Example.COM ", "alice@example.com"},
		{"alice+votes@example.com", "alice@example.com"},
		{"alice+a+b@example.com", "alice@example.com"},
		{"a.lice@example.com", "a.lice@example.com"}, // dots matter outside gmail
		{"A.Li.Ce+x@Gmail.com", "alice@gmail.com"},
		{"alice@googlemail.com", "alice@gmail.com"},
		{"alice@example.com.", "alice@example.com"},
		{"we@ird@example.com", "we@ird@example.com"},
	}
	for _, c := range cases {
		got, err := NormalizeEmail(c.in)
		if err != nil || got != c.want {
			t.Errorf("NormalizeEmail(%q) = %q, %v; want %q", c.in, got, err, c.want)
		}
	}
	for _, bad := range []string{"", "alice", "@example.com", "alice@", "+tag@example.com", "a b@example.com", "...@gmail.com"} {
		if got, err := NormalizeEmail(bad); !errors.Is(err, ErrIdentifierFormat) {
			t.Errorf("NormalizeEmail(%q) = %q, %v; want ErrIdentifierFormat", bad, got, err)
		}
	}
}

func TestNormalizePhoneE164(t *testing.T) {
	cases := []struct{ in, want string }{
		{"+15551234567", "+15551234567"},
		{"+1 (555) 123-4567", "+15551234567"},
		{"+1.555.123.4567", "+15551234567"},
		{"0044 20 7946 0958", "+442079460958"},
	}
	for _, c := range cases {
		got, err := NormalizePhoneE164(c.in)
		if err != nil || got != c.want {
			t.Errorf("NormalizePhoneE164(%q) = %q, %v; want %q", c.in, got, err, c.want)
		}
	}
	for _, bad := range []string{"", "5551234567", "(555) 123-4567", "+0123456789", "+12345", "+1234567890123456", "+1555abc4567"} {
		if got, err := NormalizePhoneE164(bad); !errors.Is(err, ErrIdentifierFormat) {
			t.Errorf("NormalizePhoneE164(%q) = %q, %v; want ErrIdentifierFormat", bad, got, err)
		}
	}
}

func testKey(t *testing.T) []byte {
	t.Helper()
	k := make([]byte, 32)
	if _, err := rand.Read(k); err != nil {
		t.Fatal(err)
	}
	return k
}

func TestIdentifierKeyer(t *testing.T) {
	if _, err := newIdentifierKeyer(make([]byte, 31)); err == nil {
		t.Fatal("a 31-byte key must be refused")
	}
	k1, _ := newIdentifierKeyer(testKey(t))
	k2, _ := newIdentifierKeyer(testKey(t))
	a := k1.Key(identifierKindEmail, "alice@example.com")
	if a != k1.Key(identifierKindEmail, "alice@example.com") {
		t.Fatal("key must be deterministic")
	}
	if len(a) != 64 || !validIdentifierKey(a) {
		t.Fatalf("key should be 64 hex chars, got %q", a)
	}
	if a == k1.Key(identifierKindPhone, "alice@example.com") {
		t.Error("kinds must be domain-separated")
	}
	if a == k2.Key(identifierKindEmail, "alice@example.com") {
		t.Error("different server keys must give different hashes")
	}
	if strings.Contains(a, "alice") {
		t.Error("key leaks the identifier")
	}
}

func TestResolveIdentifierSeed(t *testing.T) {
	ctx := context.Background()
	st := NewInMemoryIdentifierStore()
	email := map[string]string{identifierKindEmail: strings.Repeat("a", 64)}

	s1, err := resolveIdentifierSeed(ctx, st, email)
	if err != nil || len(s1) != 64 {
		t.Fatalf("first resolve: %q, %v", s1, err)
	}
	s2, _ := resolveIdentifierSeed(ctx, st, email)
	if s1 != s2 {
		t.Fatal("same identifier must get the same seed back")
	}
	other, _ := resolveIdentifierSeed(ctx, st, map[string]string{identifierKindEmail: strings.Repeat("b", 64)})
	if other == s1 {
		t.Fatal("different identifiers must get different seeds")
	}

	// A known email plus a new phone: the phone is linked to the email's
	// seed, so the phone alone later resolves to it too.
	phone := strings.Repeat("c", 64)
	linked, _ := resolveIdentifierSeed(ctx, st, map[string]string{identifierKindEmail: strings.Repeat("a", 64), identifierKindPhone: phone})
	if linked != s1 {
		t.Fatal("new phone with a known email should reuse the email's seed")
	}
	if got, _ := resolveIdentifierSeed(ctx, st, map[string]string{identifierKindPhone: phone}); got != s1 {
		t.Fatal("phone should now resolve to the linked seed")
	}

	if _, err := resolveIdentifierSeed(ctx, st, nil); err == nil {
		t.Fatal("no keys must be an error")
	}
}

func TestResolveIdentifierSeed_ConcurrentSameIdentifier(t *testing.T) {
	ctx := context.Background()
	st := NewInMemoryIdentifierStore()
	keys := map[string]string{identifierKindEmail: strings.Repeat("d", 64)}
	const n = 16
	seeds := make([]string, n)
	var wg sync.WaitGroup
	for i := 0; i < n; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			s, err := resolveIdentifierSeed(ctx, st, keys)
			if err != nil {
				t.Error(err)
			}
			seeds[i] = s
		}(i)
	}
	wg.Wait()
	for _, s := range seeds {
		if s != seeds[0] {
			t.Fatalf("racing enrollments of one inbox got different seeds: %v", seeds)
		}
	}
}

// ---- end to end through the HTTP server ----

func holderKeyB64(t *testing.T) string {
	t.Helper()
	pub, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	return base64.StdEncoding.EncodeToString(pub)
}

// enrollEmail runs start -> email begin -> magic link -> issue with a fresh
// holder key and returns the credential.
func enrollEmail(t *testing.T, base string, sender *recordingEmailSender, email string) types.PersonhoodCredential {
	t.Helper()
	var start startEnrollmentResponse
	mustPOST(t, base+"/enrollment/start", mustJSON(t, map[string]any{"holder_public_key_b64": holderKeyB64(t)}), &start)
	mustPOST(t, base+"/v1/methods/email/begin", mustJSON(t, map[string]any{"session_id": start.SessionID, "user_input": email}), nil)
	_, link, _ := sender.lastSent()
	if code := mustGET(t, link, nil); code != http.StatusOK {
		t.Fatalf("magic link -> %d", code)
	}
	var sess map[string]any
	mustGET(t, base+"/v1/sessions/"+start.SessionID, &sess)
	if _, leaked := sess["identifier_keys"]; leaked {
		t.Fatalf("session view leaks identifier keys: %v", sess)
	}
	var issued issueCredentialResponse
	mustPOST(t, base+"/v1/credentials/issue", mustJSON(t, map[string]any{"session_id": start.SessionID}), &issued)
	return issued.Credential
}

func commitmentOf(t *testing.T, c types.PersonhoodCredential) string {
	t.Helper()
	if c.CredentialSubject.NullifierBinding == nil || c.CredentialSubject.NullifierBinding.Commitment == "" {
		t.Fatalf("credential has no nullifierBinding: %+v", c.CredentialSubject)
	}
	return c.CredentialSubject.NullifierBinding.Commitment
}

func TestIdentifierDedup_SameInboxSameBinding(t *testing.T) {
	key := testKey(t)
	base, _, sender, _, cleanup := newTestServerWith(t, func(c *Config) { c.IdentifierHMACKey = key })
	defer cleanup()

	var cfg serverConfigResponse
	mustGET(t, base+"/v1/config", &cfg)
	if !cfg.IdentifierDedup {
		t.Fatal("/v1/config should report identifier_dedup=true")
	}

	first := enrollEmail(t, base, sender, "alice@gmail.com")
	again := enrollEmail(t, base, sender, "A.Lice+second@googlemail.com")
	if first.CredentialSubject.ID == again.CredentialSubject.ID {
		t.Fatal("test setup: the two enrollments should use different holder keys")
	}
	if commitmentOf(t, first) != commitmentOf(t, again) {
		t.Fatal("re-enrolling the same inbox (any spelling, any device key) must give the same nullifierBinding")
	}
	stranger := enrollEmail(t, base, sender, "bob@gmail.com")
	if commitmentOf(t, stranger) == commitmentOf(t, first) {
		t.Fatal("a different inbox must get a different nullifierBinding")
	}
}

func TestIdentifierDedup_OffKeepsHolderBinding(t *testing.T) {
	base, _, sender, _, cleanup := newTestServer(t)
	defer cleanup()
	var cfg serverConfigResponse
	mustGET(t, base+"/v1/config", &cfg)
	if cfg.IdentifierDedup {
		t.Fatal("identifier_dedup should be false without a key")
	}
	a := enrollEmail(t, base, sender, "alice@example.com")
	b := enrollEmail(t, base, sender, "alice@example.com")
	if commitmentOf(t, a) == commitmentOf(t, b) {
		t.Fatal("without a key the binding follows the device key (the old behaviour)")
	}
}

func postStatus(t *testing.T, url string, body []byte) (int, string) {
	t.Helper()
	resp, err := http.Post(url, "application/json", bytes.NewReader(body))
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	b, _ := io.ReadAll(resp.Body)
	return resp.StatusCode, string(b)
}

func TestIdentifierDedup_PhoneMustBeE164(t *testing.T) {
	key := testKey(t)
	base, _, _, smsSender, cleanup := newTestServerWith(t, func(c *Config) { c.IdentifierHMACKey = key })
	defer cleanup()

	var start startEnrollmentResponse
	mustPOST(t, base+"/enrollment/start", mustJSON(t, map[string]any{}), &start)
	code, body := postStatus(t, base+"/v1/methods/sms/begin", mustJSON(t, map[string]any{"session_id": start.SessionID, "user_input": "555 123 4567"}))
	if code != http.StatusBadRequest || !strings.Contains(body, "invalid_identifier") {
		t.Fatalf("national-format phone should be refused with invalid_identifier, got %d %s", code, body)
	}

	// The same phone spelled two ways is one identifier.
	commit := func(spelling string) string {
		var st startEnrollmentResponse
		mustPOST(t, base+"/enrollment/start", mustJSON(t, map[string]any{}), &st)
		mustPOST(t, base+"/v1/methods/sms/begin", mustJSON(t, map[string]any{"session_id": st.SessionID, "user_input": spelling}), nil)
		mustPOST(t, base+"/v1/methods/sms/complete", mustJSON(t, map[string]any{
			"session_id": st.SessionID,
			"response":   types.ResponseData{Type: "otp", Payload: map[string]any{"phone_number": spelling, "code": smsSender.lastOTP()}},
		}), nil)
		var issued issueCredentialResponse
		mustPOST(t, base+"/v1/credentials/issue", mustJSON(t, map[string]any{"session_id": st.SessionID}), &issued)
		return commitmentOf(t, issued.Credential)
	}
	if commit("+1 555 123 4567") != commit("+15551234567") {
		t.Fatal("two spellings of one phone must share a binding")
	}
}

func TestIdentifierDedup_SessionVerifiedBeforeKeyingMustReverify(t *testing.T) {
	key := testKey(t)
	base, srv, _, _, cleanup := newTestServerWith(t, func(c *Config) { c.IdentifierHMACKey = key })
	defer cleanup()

	// Simulate a session whose email was verified by a build that did not
	// key identifiers: the method is recorded but no identifier key.
	var start startEnrollmentResponse
	mustPOST(t, base+"/enrollment/start", mustJSON(t, map[string]any{}), &start)
	meta := types.MethodMetadata{ID: "email", Type: types.MethodTypeSupplementary, Strength: 8}
	if err := srv.sessions.RecordMethodResult(start.SessionID, types.MethodResult{Success: true, MethodID: "email", AttestationDigest: "x"}, meta); err != nil {
		t.Fatal(err)
	}
	code, body := postStatus(t, base+"/v1/credentials/issue", mustJSON(t, map[string]any{"session_id": start.SessionID}))
	if code != http.StatusConflict || !strings.Contains(body, "reverify_required") {
		t.Fatalf("want 409 reverify_required, got %d %s", code, body)
	}
}

func TestLoadConfig_IdentifierKey(t *testing.T) {
	t.Setenv("ISSUER_ED25519_SK_B64", base64.StdEncoding.EncodeToString(make([]byte, 32)))
	t.Setenv(IdentifierKeyEnv, base64.StdEncoding.EncodeToString(make([]byte, 16)))
	if _, err := LoadConfigFromEnv(); err == nil {
		t.Fatal("a 16-byte identifier key must be refused")
	}
	t.Setenv(IdentifierKeyEnv, base64.StdEncoding.EncodeToString(testKey(t)))
	cfg, err := LoadConfigFromEnv()
	if err != nil || len(cfg.IdentifierHMACKey) != 32 {
		t.Fatalf("valid key: %v (len %d)", err, len(cfg.IdentifierHMACKey))
	}
}

func TestInMemorySessionStore_IdentifierKeys(t *testing.T) {
	st := NewInMemorySessionStore(time.Hour)
	view, _ := st.Create(nil, time.Now())
	if err := st.SetIdentifierKey(view.ID, identifierKindEmail, "k1"); err != nil {
		t.Fatal(err)
	}
	if err := st.SetIdentifierKey(view.ID, identifierKindEmail, "k2"); err != nil {
		t.Fatal(err)
	}
	got, _ := st.Get(view.ID)
	if got.IdentifierKeys[identifierKindEmail] != "k2" {
		t.Fatalf("a later key of the same kind should replace the earlier one: %+v", got.IdentifierKeys)
	}
	got.IdentifierKeys[identifierKindEmail] = "mutated"
	if again, _ := st.Get(view.ID); again.IdentifierKeys[identifierKindEmail] != "k2" {
		t.Fatal("views must be copies")
	}
	_ = st.MarkIssued(view.ID, "cred")
	if err := st.SetIdentifierKey(view.ID, identifierKindPhone, "k3"); !errors.Is(err, ErrSessionAlreadyIssued) {
		t.Fatalf("after issue: err=%v, want ErrSessionAlreadyIssued", err)
	}
}

func TestIntegration_FirestoreIdentifierStore(t *testing.T) {
	client := firestoreTestClient(t)
	st := NewFirestoreIdentifierStore(client)
	ctx := context.Background()
	k, _ := newIdentifierKeyer(testKey(t))
	key := k.Key(identifierKindEmail, "it-"+uniqueSuffix()+"@example.com")

	if _, found, err := st.Lookup(ctx, key); err != nil || found {
		t.Fatalf("fresh key: found=%v err=%v", found, err)
	}
	got, err := st.GetOrCreate(ctx, key, "seed-one")
	if err != nil || got != "seed-one" {
		t.Fatalf("create: %q %v", got, err)
	}
	got, err = st.GetOrCreate(ctx, key, "seed-two")
	if err != nil || got != "seed-one" {
		t.Fatalf("second create must return the first seed: %q %v", got, err)
	}
	if _, err := st.GetOrCreate(ctx, "not-a-key", "x"); err == nil {
		t.Fatal("malformed key must be refused before reaching Firestore")
	}

	// The Firestore session store persists identifier keys.
	sessions := NewFirestoreSessionStore(client, time.Hour)
	view, err := sessions.Create(nil, time.Now())
	if err != nil {
		t.Fatal(err)
	}
	if err := sessions.SetIdentifierKey(view.ID, identifierKindEmail, key); err != nil {
		t.Fatal(err)
	}
	after, _ := sessions.Get(view.ID)
	if after.IdentifierKeys[identifierKindEmail] != key {
		t.Fatalf("identifier key not persisted: %+v", after.IdentifierKeys)
	}
}
