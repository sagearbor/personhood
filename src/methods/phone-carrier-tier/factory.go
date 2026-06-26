package phonecarriertier

import (
	"log"
	"os"
)

// NewProviderFromEnv returns the appropriate CarrierProvider for the current
// environment:
//
//   - if TWILIO_ACCOUNT_SID + TWILIO_AUTH_TOKEN are set, a TwilioLookupProvider
//     (real line-type intelligence; sim_swap requested when
//     TWILIO_LOOKUP_SIM_SWAP=1);
//   - otherwise the NeutralProvider (dev default; offline pre-check only).
//
// When the neutral provider is selected, a warning is logged so it is obvious
// the strength-28 rating is not being earned by real carrier intelligence.
func NewProviderFromEnv() CarrierProvider {
	sid := os.Getenv("TWILIO_ACCOUNT_SID")
	token := os.Getenv("TWILIO_AUTH_TOKEN")
	if sid != "" && token != "" {
		p, err := NewTwilioLookupProvider(sid, token, nil)
		if err == nil {
			p.IncludeSimSwap = os.Getenv("TWILIO_LOOKUP_SIM_SWAP") == "1"
			return p
		}
		log.Printf("phone-carrier-tier: Twilio creds set but provider init failed (%v); falling back to NeutralProvider", err)
	}
	log.Println("phone-carrier-tier: no Twilio Lookup creds; using NeutralProvider (strength-28 rating assumes a real carrier provider in production)")
	return NeutralProvider{}
}
