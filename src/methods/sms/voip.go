// Package sms implements the Personhood "sms" supplementary verification
// method: a 6-digit OTP delivered over SMS.
//
// This file contains a placeholder VOIP-detection heuristic. Real production
// deployments MUST replace LooksLikeVOIP with a call to a carrier-lookup
// vendor (Twilio Lookup, Telesign, Plivo, etc.) — the heuristic here is
// merely a stopgap so the v0.1 reference issuer can demonstrate the rejection
// path end-to-end without external dependencies.
package sms

import (
	"regexp"
	"strings"
)

// usVoipExchanges is a short, deliberately-conservative list of US +1
// area-code/exchange prefixes that are commonly used by SIP/VOIP providers or
// are reserved for fictional / testing use (and therefore should not be
// accepted as real personhood signals). Each entry is a 6-digit prefix
// matching the area code + exchange portion of an E.164 +1 number.
//
// Examples:
//   - "555" exchanges in any area code are reserved for fictional use
//     (the +1NPA-555-XXXX bands historically used by Hollywood).
//
// We pattern-match the country-code and exchange separately rather than
// trying to enumerate every VOIP-friendly carrier — that is the vendor's job.
var fictional555 = regexp.MustCompile(`^\+1\d{3}555\d{4}$`)

// knownVOIPPrefixes is an illustrative (NOT exhaustive) list of E.164
// prefixes that historically belong to VOIP-heavy ranges. Production must
// replace this.
var knownVOIPPrefixes = []string{
	"+1500", // CSC / shared-cost, sometimes used for VOIP test ranges
	"+1521", // expansion area code reserved by NANP, not yet in service
	"+1533", // ditto
	"+1544", // ditto
	"+1566", // ditto
	"+1577", // ditto
	"+1588", // ditto
	"+1622", // ditto
	"+1700", // NANP unassigned / carrier-internal
}

var stripNonDigitsRe = regexp.MustCompile(`[\s\-\(\)\.]`)

// LooksLikeVOIP is a heuristic placeholder for v0.1. Real implementations
// query Twilio Lookup, Telesign, or an equivalent carrier database to
// determine whether a number is mobile, landline, or VOIP.
//
// The current heuristic:
//   - Normalizes the input to remove common formatting characters.
//   - Returns true for the +1 NPA-555-XXXX fictional band.
//   - Returns true for a hard-coded list of NANP prefixes that are known to
//     be unassigned or used for carrier-internal / VOIP test traffic.
//   - Returns false otherwise.
//
// Numbers that fail to parse as a vaguely-E.164-looking string return false
// (no decision); upstream validation is responsible for rejecting malformed
// numbers.
func LooksLikeVOIP(phoneNumber string) bool {
	cleaned := stripNonDigitsRe.ReplaceAllString(strings.TrimSpace(phoneNumber), "")
	if cleaned == "" {
		return false
	}
	// Require a leading '+' to be sure we're dealing with E.164.
	if !strings.HasPrefix(cleaned, "+") {
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
