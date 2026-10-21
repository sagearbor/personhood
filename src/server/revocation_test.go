package server

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/sagearbor/personhood/pkg/types"
	"github.com/sagearbor/personhood/src/credential"
)

const testAdminToken = "test-admin-token"

// issueEmailCredential runs start → email begin → click → issue against base
// and returns the credential.
func issueEmailCredential(t *testing.T, base string, emailSender *recordingEmailSender) types.PersonhoodCredential {
	t.Helper()
	var start startEnrollmentResponse
	mustPOST(t, base+"/enrollment/start", mustJSON(t, map[string]any{"platform": "web"}), &start)
	var begin beginMethodResponse
	mustPOST(t, base+"/v1/methods/email/begin", mustJSON(t, map[string]any{
		"session_id": start.SessionID,
		"user_input": "revoke@example.com",
	}), &begin)
	_, link, _ := emailSender.lastSent()
	resp, err := http.Get(link)
	if err != nil {
		t.Fatalf("click magic link: %v", err)
	}
	resp.Body.Close()
	var issued issueCredentialResponse
	mustPOST(t, base+"/v1/credentials/issue", mustJSON(t, map[string]any{"session_id": start.SessionID}), &issued)
	return issued.Credential
}

func postAdminRevoke(t *testing.T, base, token, credentialID string) (int, adminRevokeResponse) {
	t.Helper()
	req, err := http.NewRequest(http.MethodPost, base+"/v1/admin/revoke",
		bytes.NewReader(mustJSON(t, map[string]any{"credential_id": credentialID})))
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Set("Content-Type", "application/json")
	if token != "" {
		req.Header.Set("Authorization", "Bearer "+token)
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("admin revoke: %v", err)
	}
	defer resp.Body.Close()
	var out adminRevokeResponse
	_ = json.NewDecoder(resp.Body).Decode(&out)
	return resp.StatusCode, out
}

func TestIntegration_RevokeFlipsStatusListBit(t *testing.T) {
	base, _, emailSender, _, cleanup := newTestServerWith(t, func(c *Config) { c.AdminToken = testAdminToken })
	defer cleanup()

	cred := issueEmailCredential(t, base, emailSender)
	if cred.CredentialStatus == nil {
		t.Fatal("issued credential has no credentialStatus")
	}
	if cred.CredentialStatus.StatusListCredential != base+"/v1/status-list/default" {
		t.Errorf("statusListCredential = %q", cred.CredentialStatus.StatusListCredential)
	}

	ctx := context.Background()
	if revoked, err := credential.IsRevoked(ctx, http.DefaultClient, cred); err != nil || revoked {
		t.Fatalf("before revoke: revoked=%v err=%v, want false", revoked, err)
	}

	if code, _ := postAdminRevoke(t, base, "", cred.ID); code != http.StatusUnauthorized {
		t.Errorf("no token: got %d, want 401", code)
	}
	if code, _ := postAdminRevoke(t, base, "wrong", cred.ID); code != http.StatusUnauthorized {
		t.Errorf("wrong token: got %d, want 401", code)
	}

	code, out := postAdminRevoke(t, base, testAdminToken, cred.ID)
	if code != http.StatusOK || out.AlreadyRevoked || out.StatusListIndex != cred.CredentialStatus.StatusListIndex {
		t.Fatalf("revoke: code=%d out=%+v, want 200 at index %d", code, out, cred.CredentialStatus.StatusListIndex)
	}
	if revoked, err := credential.IsRevoked(ctx, http.DefaultClient, cred); err != nil || !revoked {
		t.Fatalf("after revoke: revoked=%v err=%v, want true", revoked, err)
	}

	if code, out := postAdminRevoke(t, base, testAdminToken, cred.ID); code != http.StatusOK || !out.AlreadyRevoked {
		t.Errorf("second revoke: code=%d out=%+v, want 200 already_revoked", code, out)
	}
	if code, _ := postAdminRevoke(t, base, testAdminToken, "urn:personhood:credential:unknown"); code != http.StatusNotFound {
		t.Errorf("unknown credential: got %d, want 404", code)
	}
}

func TestIntegration_RevokeOnlyTouchesItsOwnCredential(t *testing.T) {
	base, _, emailSender, _, cleanup := newTestServerWith(t, func(c *Config) { c.AdminToken = testAdminToken })
	defer cleanup()

	a := issueEmailCredential(t, base, emailSender)
	b := issueEmailCredential(t, base, emailSender)
	if a.CredentialStatus.StatusListIndex == b.CredentialStatus.StatusListIndex {
		t.Fatalf("two credentials share status slot %d", a.CredentialStatus.StatusListIndex)
	}
	if code, _ := postAdminRevoke(t, base, testAdminToken, a.ID); code != http.StatusOK {
		t.Fatalf("revoke a: %d", code)
	}
	if revoked, err := credential.IsRevoked(context.Background(), http.DefaultClient, b); err != nil || revoked {
		t.Errorf("b after revoking a: revoked=%v err=%v, want false", revoked, err)
	}
}

func TestIntegration_AdminRouteOffWithoutToken(t *testing.T) {
	base, _, _, _, cleanup := newTestServer(t)
	defer cleanup()
	if code, _ := postAdminRevoke(t, base, "anything", "x"); code != http.StatusNotFound {
		t.Errorf("admin route without AdminToken: got %d, want 404", code)
	}
}

func TestIntegration_UnknownStatusListIs404(t *testing.T) {
	base, _, _, _, cleanup := newTestServer(t)
	defer cleanup()
	resp, err := http.Get(base + "/v1/status-list/other")
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusNotFound {
		t.Errorf("got %d, want 404", resp.StatusCode)
	}
}

func TestClassify_VerifierReadsAreNeverLimited(t *testing.T) {
	for _, p := range []string{"/.well-known/did.json", "/v1/status-list/default"} {
		if _, limited := classify(httptest.NewRequest(http.MethodGet, p, nil)); limited {
			t.Errorf("GET %s is rate limited; verifiers fail closed on 429", p)
		}
	}
	if c, limited := classify(httptest.NewRequest(http.MethodPost, "/v1/admin/revoke", nil)); !limited || c != classStart {
		t.Errorf("POST /v1/admin/revoke: class=%v limited=%v, want the start bucket", c, limited)
	}
}

func TestInMemoryRevocationStore_AllocatesDistinctSlots(t *testing.T) {
	s := NewInMemoryRevocationStore()
	seen := map[int]bool{}
	for i := 0; i < 500; i++ {
		idx, err := s.Allocate(context.Background())
		if err != nil {
			t.Fatal(err)
		}
		if idx < 0 || idx >= statusListSize || seen[idx] {
			t.Fatalf("slot %d out of range or reused", idx)
		}
		seen[idx] = true
	}
}

func TestIntegration_FirestoreRevocationStore(t *testing.T) {
	s := NewFirestoreRevocationStore(firestoreTestClient(t))
	ctx := context.Background()
	idx, err := s.Allocate(ctx)
	if err != nil {
		t.Fatal(err)
	}
	credID := "urn:personhood:credential:test:" + t.Name() + ":" + uniqueSuffix()
	if err := s.Bind(ctx, idx, credID); err != nil {
		t.Fatal(err)
	}
	got, already, err := s.Revoke(ctx, credID)
	if err != nil || already || got != idx {
		t.Fatalf("Revoke: idx=%d already=%v err=%v, want %d", got, already, err, idx)
	}
	if _, already, _ := s.Revoke(ctx, credID); !already {
		t.Error("second Revoke: want already_revoked")
	}
	revoked, err := s.Revoked(ctx)
	if err != nil {
		t.Fatal(err)
	}
	found := false
	for _, r := range revoked {
		found = found || r == idx
	}
	if !found {
		t.Errorf("Revoked() = %v, missing %d", revoked, idx)
	}
	if _, _, err := s.Revoke(ctx, "urn:never-issued"); err != ErrCredentialNotFound {
		t.Errorf("unknown credential: err=%v, want ErrCredentialNotFound", err)
	}
}

func uniqueSuffix() string { return time.Now().UTC().Format("150405.000000000") }
