package phonecarriertier

import (
	"regexp"
	"strings"
)

// This file is a cheap, offline VOIP/fictional-number pre-check that runs
// before any carrier lookup. It mirrors the sms module's heuristic so a number
// in the fictional +1-NPA-555 band or a known-unassigned NANP prefix is
// rejected without spending a Twilio Lookup call. Real classification is the
// CarrierProvider's job.

var fictional555 = regexp.MustCompile(`^\+1\d{3}555\d{4}$`)

var knownVOIPPrefixes = []string{
	"+1500", "+1521", "+1533", "+1544", "+1566", "+1577", "+1588", "+1622", "+1700",
}

var stripNonDigitsRe = regexp.MustCompile(`[\s\-\(\)\.]`)

// LooksLikeVOIP is the offline pre-check. It returns true for the fictional
// +1-NPA-555-XXXX band and a hard-coded list of unassigned/VOIP-test NANP
// prefixes. Numbers that do not parse as E.164 return false (no decision).
func LooksLikeVOIP(phoneNumber string) bool {
	cleaned := stripNonDigitsRe.ReplaceAllString(strings.TrimSpace(phoneNumber), "")
	if cleaned == "" || !strings.HasPrefix(cleaned, "+") {
		return false
	}
	if fictional555.MatchString(cleaned) {
		return true
	}
	for _, p := range knownVOIPPrefixes {
		if strings.HasPrefix(cleaned, p) {
			return true
		}
	}
	return false
}
