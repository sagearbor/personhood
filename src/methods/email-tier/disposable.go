package emailtier

import "strings"

// disposableDomains is the v0.1 blocklist of well-known disposable / throwaway
// email providers. Lowercase, no leading "@". Kept in sync with the email
// module's list; production deployments should swap in a maintained feed by
// composing an alternative EnrichmentProvider.
var disposableDomains = map[string]struct{}{
	"10minutemail.com":  {},
	"20minutemail.com":  {},
	"33mail.com":        {},
	"airmail.cc":        {},
	"anonbox.net":       {},
	"burnermail.io":     {},
	"deadaddress.com":   {},
	"discard.email":     {},
	"dispostable.com":   {},
	"emailondeck.com":   {},
	"fakeinbox.com":     {},
	"fakemail.net":      {},
	"getairmail.com":    {},
	"getnada.com":       {},
	"guerrillamail.com": {},
	"guerrillamail.net": {},
	"guerrillamail.org": {},
	"harakirimail.com":  {},
	"inboxbear.com":     {},
	"inboxkitten.com":   {},
	"mailcatch.com":     {},
	"maildrop.cc":       {},
	"mailinator.com":    {},
	"mailnesia.com":     {},
	"mintemail.com":     {},
	"mohmal.com":        {},
	"mytemp.email":      {},
	"sharklasers.com":   {},
	"spamgourmet.com":   {},
	"tempmail.com":      {},
	"tempmail.io":       {},
	"tempmail.net":      {},
	"tempr.email":       {},
	"throwawaymail.com": {},
	"trashmail.com":     {},
	"trashmail.de":      {},
	"yopmail.com":       {},
}

// IsDisposable reports whether the given email address belongs to a known
// disposable / throwaway provider. Malformed addresses return false.
func IsDisposable(email string) bool {
	email = strings.ToLower(strings.TrimSpace(email))
	at := strings.LastIndex(email, "@")
	if at <= 0 || at == len(email)-1 {
		return false
	}
	_, ok := disposableDomains[email[at+1:]]
	return ok
}
