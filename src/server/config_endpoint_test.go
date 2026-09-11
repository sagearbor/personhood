package server

import (
	"bytes"
	"encoding/json"
	"io"
	"net/http"
	"testing"

	emailmethod "github.com/sagearbor/personhood/src/methods/email"
)

// These tests cover the two knobs that make a public-URL preview deployment
// survivable: the ENROLLMENT_INVITE_CODE gate on /enrollment/start, and the
// GET /v1/config endpoint a client reads to discover which gates are on.

// postRaw issues a POST and returns the status code plus the decoded body, so
// a test can assert on non-200 responses (mustPOST fatals on those).
func postRaw(t *testing.T, url string, body []byte) (int, map[string]any) {
	t.Helper()
	req, err := http.NewRequest(http.MethodPost, url, bytes.NewReader(body))
	if err != nil {
		t.Fatalf("new request: %v", err)
	}
	req.Header.Set("Content-Type", "application/json")
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("do %s: %v", url, err)
	}
	defer resp.Body.Close()
	raw, _ := io.ReadAll(resp.Body)
	var decoded map[string]any
	if len(raw) > 0 {
		if err := json.Unmarshal(raw, &decoded); err != nil {
			t.Fatalf("decode %s: %v\n%s", url, err, raw)
		}
	}
	return resp.StatusCode, decoded
}

// errorCode digs the machine-readable code out of writeError's envelope.
func errorCode(t *testing.T, body map[string]any) string {
	t.Helper()
	errObj, ok := body["error"].(map[string]any)
	if !ok {
		t.Fatalf("response has no error object: %v", body)
	}
	code, _ := errObj["code"].(string)
	return code
}

func TestEnrollmentStart_NoInviteCodeConfigured_AcceptsBareRequest(t *testing.T) {
	base, _, _, _, cleanup := newTestServer(t)
	defer cleanup()

	status, body := postRaw(t, base+"/enrollment/start", mustJSON(t, map[string]any{"platform": "test"}))
	if status != http.StatusOK {
		t.Fatalf("start without invite code -> %d (%v); an unconfigured gate must not block", status, body)
	}
	if body["session_id"] == "" || body["session_id"] == nil {
		t.Fatalf("expected a session_id: %v", body)
	}
}

func TestEnrollmentStart_InviteCodeRequired_MissingIsForbidden(t *testing.T) {
	base, _, _, _, cleanup := newTestServerWith(t, func(c *Config) { c.EnrollmentInviteCode = "sekrit-friends-2026" })
	defer cleanup()

	status, body := postRaw(t, base+"/enrollment/start", mustJSON(t, map[string]any{"platform": "test"}))
	if status != http.StatusForbidden {
		t.Fatalf("start with no invite_code -> %d, want 403 (%v)", status, body)
	}
	if got := errorCode(t, body); got != "invite_code_required" {
		t.Errorf("error code = %q, want invite_code_required", got)
	}
	// A whitespace-only code is "missing", not "wrong".
	status, body = postRaw(t, base+"/enrollment/start", mustJSON(t, map[string]any{"invite_code": "   "}))
	if status != http.StatusForbidden || errorCode(t, body) != "invite_code_required" {
		t.Errorf("blank invite_code -> %d %v, want 403 invite_code_required", status, body)
	}
}

func TestEnrollmentStart_InviteCodeRequired_WrongIsForbidden(t *testing.T) {
	base, _, _, _, cleanup := newTestServerWith(t, func(c *Config) { c.EnrollmentInviteCode = "sekrit-friends-2026" })
	defer cleanup()

	for _, wrong := range []string{"nope", "sekrit-friends-2025", "sekrit-friends-2026x", "SEKRIT-FRIENDS-2026"} {
		status, body := postRaw(t, base+"/enrollment/start", mustJSON(t, map[string]any{"invite_code": wrong}))
		if status != http.StatusForbidden {
			t.Fatalf("invite_code=%q -> %d, want 403 (%v)", wrong, status, body)
		}
		if got := errorCode(t, body); got != "invite_code_invalid" {
			t.Errorf("invite_code=%q: error code = %q, want invite_code_invalid", wrong, got)
		}
		// The response must never echo the configured code back.
		if bytes.Contains(mustJSON(t, body), []byte("sekrit-friends-2026")) {
			t.Errorf("403 body leaked the configured invite code: %v", body)
		}
	}
}

func TestEnrollmentStart_InviteCodeRequired_CorrectSucceeds(t *testing.T) {
	base, _, _, _, cleanup := newTestServerWith(t, func(c *Config) { c.EnrollmentInviteCode = "sekrit-friends-2026" })
	defer cleanup()

	// Surrounding whitespace is trimmed — users paste codes out of messages.
	for _, ok := range []string{"sekrit-friends-2026", "  sekrit-friends-2026\n"} {
		status, body := postRaw(t, base+"/enrollment/start", mustJSON(t, map[string]any{"invite_code": ok, "platform": "test"}))
		if status != http.StatusOK {
			t.Fatalf("invite_code=%q -> %d, want 200 (%v)", ok, status, body)
		}
		if sid, _ := body["session_id"].(string); sid == "" {
			t.Errorf("invite_code=%q: expected a session_id: %v", ok, body)
		}
	}
}

func TestConfigEndpoint_ReflectsConfig(t *testing.T) {
	tests := []struct {
		name         string
		mutate       func(*Config)
		senderKind   string
		wantInvite   bool
		wantExposed  bool
		wantDelivery string
	}{
		{
			name:         "defaults",
			mutate:       func(*Config) {},
			wantDelivery: emailmethod.SenderKindUnknown,
		},
		{
			name:         "preview deployment",
			mutate:       func(c *Config) { c.EnrollmentInviteCode = "sekrit"; c.ExposeChallengeSecrets = true },
			senderKind:   emailmethod.SenderKindLog,
			wantInvite:   true,
			wantExposed:  true,
			wantDelivery: emailmethod.SenderKindLog,
		},
		{
			name:         "real mail via smtp",
			mutate:       func(c *Config) {},
			senderKind:   emailmethod.SenderKindSMTP,
			wantDelivery: emailmethod.SenderKindSMTP,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			base, _, _, _, cleanup := newTestServerWithDeps(t, tc.mutate, func(d *Dependencies) {
				d.EmailSenderKind = tc.senderKind
			})
			defer cleanup()

			var got serverConfigResponse
			if code := mustGET(t, base+"/v1/config", &got); code != http.StatusOK {
				t.Fatalf("GET /v1/config -> %d", code)
			}
			if got.InviteCodeRequired != tc.wantInvite {
				t.Errorf("invite_code_required = %v, want %v", got.InviteCodeRequired, tc.wantInvite)
			}
			if got.ChallengeSecretsExposed != tc.wantExposed {
				t.Errorf("challenge_secrets_exposed = %v, want %v", got.ChallengeSecretsExposed, tc.wantExposed)
			}
			if got.EmailDelivery != tc.wantDelivery {
				t.Errorf("email_delivery = %q, want %q", got.EmailDelivery, tc.wantDelivery)
			}
		})
	}
}

func TestConfigEndpoint_NeverLeaksTheInviteCode(t *testing.T) {
	base, _, _, _, cleanup := newTestServerWith(t, func(c *Config) { c.EnrollmentInviteCode = "sekrit-friends-2026" })
	defer cleanup()

	resp, err := http.Get(base + "/v1/config")
	if err != nil {
		t.Fatalf("GET /v1/config: %v", err)
	}
	defer resp.Body.Close()
	raw, _ := io.ReadAll(resp.Body)
	if bytes.Contains(raw, []byte("sekrit-friends-2026")) {
		t.Fatalf("/v1/config must advertise that a gate exists, not the code: %s", raw)
	}
}

func TestLoadConfigFromEnv_EnrollmentInviteCode(t *testing.T) {
	t.Setenv("ISSUER_ED25519_SK_B64", "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA")

	t.Setenv("ENROLLMENT_INVITE_CODE", "")
	cfg, err := LoadConfigFromEnv()
	if err != nil {
		t.Fatalf("LoadConfigFromEnv: %v", err)
	}
	if cfg.EnrollmentInviteCode != "" {
		t.Errorf("unset ENROLLMENT_INVITE_CODE should leave the gate off, got %q", cfg.EnrollmentInviteCode)
	}

	t.Setenv("ENROLLMENT_INVITE_CODE", "  padded-code  ")
	cfg, err = LoadConfigFromEnv()
	if err != nil {
		t.Fatalf("LoadConfigFromEnv: %v", err)
	}
	if cfg.EnrollmentInviteCode != "padded-code" {
		t.Errorf("EnrollmentInviteCode = %q, want %q (trimmed)", cfg.EnrollmentInviteCode, "padded-code")
	}
}
