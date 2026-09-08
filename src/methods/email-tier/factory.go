package emailtier

import (
	"log"
	"os"
)

// NewProviderFromEnv returns the appropriate EnrichmentProvider for the current
// environment:
//
//   - if HIBP_API_KEY is set, an HIBPProvider (real breach-presence lookups);
//   - otherwise the NeutralProvider (dev default; no external calls).
//
// When the neutral provider is selected, a warning is logged so it is obvious
// that the strength-22 rating is not being earned by real enrichment.
func NewProviderFromEnv() EnrichmentProvider {
	if key := os.Getenv("HIBP_API_KEY"); key != "" {
		p, err := NewHIBPProvider(key, nil)
		if err == nil {
			if ua := os.Getenv("HIBP_USER_AGENT"); ua != "" {
				p.UserAgent = ua
			}
			return p
		}
		log.Printf("email-tier: HIBP_API_KEY set but provider init failed (%v); falling back to NeutralProvider", err)
	}
	log.Println("email-tier: no HIBP_API_KEY; using NeutralProvider (strength-22 rating assumes a real enrichment provider in production)")
	return NeutralProvider{}
}
