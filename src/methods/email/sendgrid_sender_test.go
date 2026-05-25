//go:build sendgrid

package email

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestSendGridSender_Send_Success(t *testing.T) {
	var captured sendGridRequest
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/v3/mail/send" {
			t.Errorf("unexpected path: %q", r.URL.Path)
		}
		if r.Header.Get("Authorization") != "Bearer sg-key" {
			t.Errorf("Authorization header wrong: %q", r.Header.Get("Authorization"))
		}
		if r.Header.Get("Content-Type") != "application/json" {
			t.Errorf("Content-Type wrong: %q", r.Header.Get("Content-Type"))
		}
		body, _ := io.ReadAll(r.Body)
		if err := json.Unmarshal(body, &captured); err != nil {
			t.Fatalf("decode body: %v", err)
		}
		w.WriteHeader(http.StatusAccepted)
	}))
	defer server.Close()

	sender := &SendGridSender{
		APIKey:      "sg-key",
		FromAddress: "noreply@example.com",
		FromName:    "Personhood",
		Endpoint:    server.URL + "/v3/mail/send",
		HTTPClient:  http.DefaultClient,
	}
	err := sender.Send(context.Background(), "alice@example.com", "Confirm your email", "https://issuer.example/v1/methods/email/verify?session=s&token=t")
	if err != nil {
		t.Fatalf("send: %v", err)
	}

	if len(captured.Personalizations) != 1 || len(captured.Personalizations[0].To) != 1 {
		t.Fatalf("unexpected personalizations: %+v", captured.Personalizations)
	}
	if captured.Personalizations[0].To[0].Email != "alice@example.com" {
		t.Errorf("recipient mismatch: %q", captured.Personalizations[0].To[0].Email)
	}
	if captured.From.Email != "noreply@example.com" {
		t.Errorf("from mismatch: %q", captured.From.Email)
	}
	if captured.From.Name != "Personhood" {
		t.Errorf("from name mismatch: %q", captured.From.Name)
	}
	if captured.Subject != "Confirm your email" {
		t.Errorf("subject mismatch: %q", captured.Subject)
	}
	if len(captured.Content) != 2 {
		t.Fatalf("expected text/plain + text/html parts, got %d", len(captured.Content))
	}
	// The link must appear verbatim in BOTH content parts.
	for _, c := range captured.Content {
		if !strings.Contains(c.Value, "session=s&token=t") {
			t.Errorf("%s content missing the link: %s", c.Type, c.Value)
		}
	}
}

func TestSendGridSender_Send_NonSuccessStatus(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusUnauthorized)
		_, _ = w.Write([]byte(`{"errors":[{"message":"bad api key"}]}`))
	}))
	defer server.Close()

	sender := &SendGridSender{
		APIKey:      "bad",
		FromAddress: "x@y.com",
		Endpoint:    server.URL,
		HTTPClient:  http.DefaultClient,
	}
	err := sender.Send(context.Background(), "alice@example.com", "subj", "https://issuer.example/verify?token=t")
	if err == nil {
		t.Fatal("expected error on 401")
	}
	if !strings.Contains(err.Error(), "401") {
		t.Errorf("error should mention status code: %v", err)
	}
}

func TestNewSendGridSender_ValidatesRequired(t *testing.T) {
	if _, err := NewSendGridSender("", "from@x.com", ""); err == nil {
		t.Error("expected error on empty API key")
	}
	if _, err := NewSendGridSender("k", "", ""); err == nil {
		t.Error("expected error on empty From address")
	}
}

func TestSendGridSenderEnabled_True(t *testing.T) {
	if !SendGridSenderEnabled() {
		t.Error("SendGridSenderEnabled must be true in a sendgrid build")
	}
}
