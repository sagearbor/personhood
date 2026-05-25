//go:build twilio

package sms

import (
	"context"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestTwilioSender_Send_Success(t *testing.T) {
	var capturedForm string
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			t.Errorf("unexpected method %q", r.Method)
		}
		if r.Header.Get("Content-Type") != "application/x-www-form-urlencoded" {
			t.Errorf("Content-Type wrong: %q", r.Header.Get("Content-Type"))
		}
		// Basic auth assertion: SetBasicAuth uses RFC 7617.
		gotUser, gotPass, ok := r.BasicAuth()
		if !ok || gotUser != "AC_test" || gotPass != "token_test" {
			t.Errorf("basic auth mismatch: ok=%v user=%q pass=%q", ok, gotUser, gotPass)
		}
		body, _ := io.ReadAll(r.Body)
		capturedForm = string(body)
		w.WriteHeader(http.StatusCreated)
		_, _ = w.Write([]byte(`{"sid":"SM123","status":"queued"}`))
	}))
	defer server.Close()

	sender := &TwilioSender{
		AccountSID: "AC_test",
		AuthToken:  "token_test",
		FromNumber: "+15559876543",
		Endpoint:   server.URL,
		HTTPClient: http.DefaultClient,
	}
	err := sender.Send(context.Background(), "+15551234567", "Your Personhood code: 654321")
	if err != nil {
		t.Fatalf("send: %v", err)
	}
	if !strings.Contains(capturedForm, "To=%2B15551234567") {
		t.Errorf("body missing To param: %s", capturedForm)
	}
	if !strings.Contains(capturedForm, "From=%2B15559876543") {
		t.Errorf("body missing From param: %s", capturedForm)
	}
	if !strings.Contains(capturedForm, "Body=Your+Personhood+code%3A+654321") {
		t.Errorf("body param malformed: %s", capturedForm)
	}
}

func TestTwilioSender_Send_NonSuccess(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusForbidden)
		_, _ = w.Write([]byte(`{"code":21408,"message":"Permission to send to this number denied"}`))
	}))
	defer server.Close()
	sender := &TwilioSender{
		AccountSID: "AC", AuthToken: "tok", FromNumber: "+1555",
		Endpoint:   server.URL,
		HTTPClient: http.DefaultClient,
	}
	err := sender.Send(context.Background(), "+15551234567", "hi")
	if err == nil {
		t.Fatal("expected error on 403")
	}
	if !strings.Contains(err.Error(), "403") {
		t.Errorf("error should mention status code: %v", err)
	}
}

func TestNewTwilioSender_ValidatesRequired(t *testing.T) {
	for _, tc := range []struct {
		name, sid, tok, from string
	}{
		{"empty sid", "", "tok", "+1"},
		{"empty token", "AC", "", "+1"},
		{"empty from", "AC", "tok", ""},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if _, err := NewTwilioSender(tc.sid, tc.tok, tc.from); err == nil {
				t.Errorf("expected error on %s", tc.name)
			}
		})
	}
}

func TestTwilioSenderEnabled_True(t *testing.T) {
	if !TwilioSenderEnabled() {
		t.Error("TwilioSenderEnabled must be true in a twilio build")
	}
}
