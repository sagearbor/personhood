# src/methods/sms

**Supplementary method** (target strength 10–15).

6-digit OTP via SMS (Twilio / MessageBird / etc.). Carrier lookup to detect and reject VOIP / virtual numbers.

## Strength rationale

Slightly stronger than email because phone numbers have a small monetary cost and rate-limit; but SS7 attacks and SIM swaps make SMS genuinely weak against targeted attackers. Fine for casual sybil resistance; never sufficient as an anchor.

## Cost

Twilio SMS: ~$0.0075 per message in the US; varies internationally.
