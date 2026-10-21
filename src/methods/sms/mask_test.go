package sms

import (
	"bytes"
	"context"
	"log"
	"strings"
	"testing"
)

func TestMaskPhone(t *testing.T) {
	for in, want := range map[string]string{
		"+1 (555) 555-0123": "***23",
		"+15555550199":      "***99",
		"7":                 "***",
	} {
		if got := MaskPhone(in); got != want {
			t.Errorf("MaskPhone(%q) = %q, want %q", in, got, want)
		}
	}
}

func TestLogSender_DoesNotLogTheNumber(t *testing.T) {
	var buf bytes.Buffer
	s := &LogSender{Logger: log.New(&buf, "", 0)}
	if err := s.Send(context.Background(), "+15555550123", "code 123456"); err != nil {
		t.Fatal(err)
	}
	if strings.Contains(buf.String(), "5550123") {
		t.Fatalf("log line leaks the number: %s", buf.String())
	}
}
