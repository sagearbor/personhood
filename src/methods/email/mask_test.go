package email

import (
	"bytes"
	"context"
	"log"
	"strings"
	"testing"
)

func TestMaskEmail(t *testing.T) {
	for in, want := range map[string]string{
		"alice@example.com": "a***@example.com",
		" bob@x.org ":       "b***@x.org",
		"no-at-sign":        "***",
		"@example.com":      "***",
	} {
		if got := MaskEmail(in); got != want {
			t.Errorf("MaskEmail(%q) = %q, want %q", in, got, want)
		}
	}
}

func TestLogSender_DoesNotLogTheAddress(t *testing.T) {
	var buf bytes.Buffer
	s := &LogSender{Logger: log.New(&buf, "", 0)}
	if err := s.Send(context.Background(), "alice@example.com", "subj", "https://x/verify?token=t"); err != nil {
		t.Fatal(err)
	}
	out := buf.String()
	if strings.Contains(out, "alice@") {
		t.Fatalf("log line leaks the address: %s", out)
	}
	if !strings.Contains(out, "link=https://x/verify?token=t") {
		t.Fatalf("log line lost the link dev flows scrape: %s", out)
	}
}
