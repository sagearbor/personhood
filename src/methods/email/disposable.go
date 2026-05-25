// Package email implements the Personhood "email" supplementary verification
// method: a magic-link email ceremony.
//
// This file declares a small hard-coded blocklist of well-known disposable /
// throwaway email domains. It is intentionally tiny and static for v0.1 so the
// module remains stdlib-only; production deployments are expected to swap in a
// maintained blocklist (e.g. disposable-email-domains/disposable-email-domains
// or a commercial feed) by composing an alternative IsDisposable function
// upstream of the method.
package email

import "strings"

// disposableDomains is the v0.1 blocklist. Lowercase, no leading "@".
//
// Source: hand-picked from publicly known disposable-mail providers. Order is
// alphabetical purely for readability.
var disposableDomains = map[string]struct{}{
	"10minutemail.com":     {},
	"20minutemail.com":     {},
	"33mail.com":           {},
	"airmail.cc":           {},
	"anonbox.net":          {},
	"burnermail.io":        {},
	"deadaddress.com":      {},
	"discard.email":        {},
	"dispostable.com":      {},
	"emailondeck.com":      {},
	"fakeinbox.com":        {},
	"fakemail.net":         {},
	"getairmail.com":       {},
	"getnada.com":          {},
	"guerrillamail.com":    {},
	"guerrillamail.net":    {},
	"guerrillamail.org":    {},
	"harakirimail.com":     {},
	"inboxbear.com":        {},
	"inboxkitten.com":      {},
	"mailcatch.com":        {},
	"maildrop.cc":          {},
	"mailinator.com":       {},
	"mailnesia.com":        {},
	"mintemail.com":        {},
	"mohmal.com":           {},
	"mytemp.email":         {},
	"sharklasers.com":      {},
	"spamgourmet.com":      {},
	"tempmail.com":         {},
	"tempmail.io":          {},
	"tempmail.net":         {},
	"tempr.email":          {},
	"throwawaymail.com":    {},
	"trashmail.com":        {},
	"trashmail.de":         {},
	"yopmail.com":          {},
}

// IsDisposable reports whether the given email address belongs to a
// hard-coded list of well-known disposable / throwaway email providers.
//
// It lowercases the input, splits on the final '@', and checks the domain
// (without subdomain stripping) against the static blocklist. Malformed
// addresses (no '@', or empty local/domain part) return false — domain
// validity is the caller's responsibility; this function only answers the
// disposable-or-not question.
func IsDisposable(email string) bool {
	email = strings.ToLower(strings.TrimSpace(email))
	at := strings.LastIndex(email, "@")
	if at <= 0 || at == len(email)-1 {
		return false
	}
	domain := email[at+1:]
	_, ok := disposableDomains[domain]
	return ok
}
