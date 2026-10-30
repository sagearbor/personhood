package email

import (
	"strings"
	"testing"
	"time"
)

func TestMagicLinkBodies_SayWhoAskedAndWhen(t *testing.T) {
	at := time.Date(2026, 10, 29, 23, 58, 0, 0, time.UTC)
	plain, htmlBody := magicLinkBodies("https://issuer.example/v1/methods/email/callback?t=a&s=b", at)
	for name, body := range map[string]string{"plain": plain, "html": htmlBody} {
		for _, want := range []string{"Someone asked issuer.example", "2026-10-29 23:58 UTC", "nothing is verified unless the link is opened"} {
			if !strings.Contains(body, want) {
				t.Errorf("%s body missing %q", name, want)
			}
		}
	}
	if !strings.Contains(htmlBody, "t=a&amp;s=b") {
		t.Error("html body should escape the link")
	}
}
