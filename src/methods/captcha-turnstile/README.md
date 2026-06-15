# captcha-turnstile

**Supplementary** verification method wrapping [Cloudflare Turnstile](https://developers.cloudflare.com/turnstile/).
The "captcha-turnstile" tier per `docs/06-methods-catalog.md`.

| Property | Value |
|---|---|
| Type | supplementary |
| Strength | 4 |
| Cost | $0.00 |
| Friction | low |
| Freshness | 24 hours |
| Airdrop test | ✅ (any browser) |

It is a universal, near-zero-cost floor that catches naive scripted signups. It
is **not** an anchor and on its own proves almost nothing: see v0.1 limitations.

## Flow

1. **BeginCeremony** → returns `ChallengeData` (type `turnstile`) with the
   public `site_key` and a `verify_action`. The client embeds the Turnstile
   widget with that site key.
2. The user solves the (usually invisible) challenge; the widget yields a token.
3. **CompleteCeremony** reads `token` (and optional `ip`) from `ResponseData`,
   POSTs it to Cloudflare's `/siteverify` endpoint with the secret key, and:
   - `success: true` → `MethodResult{Success: true}` + attestation digest.
   - `success: false` → `MethodResult{Success: false, ErrorReason: "turnstile_failed:<codes>"}`.
   - missing token → `MethodResult{Success: false, ErrorReason: "missing_turnstile_token"}`.
   - HTTP/transport error → non-nil error (unattributable failure).

Verification is synchronous and stateless; there is no webhook.

## Configuration

```go
tc, _ := captchaturnstile.NewTurnstileClient(siteKey, secretKey, nil)
m := captchaturnstile.NewMethod(captchaturnstile.Config{TurnstileClient: tc})
```

Env vars (suggested): `TURNSTILE_SITE_KEY` (public), `TURNSTILE_SECRET_KEY`
(server-side secret).

## v0.1 limitations

- **Commercial solvers defeat CAPTCHA.** Solving services run ~$0.50 per 1000
  tokens, so a funded bot farm passes Turnstile at negligible cost. Treat this
  method strictly as a floor that filters out the unfunded, naive bots — never
  as evidence of personhood. Always pair it with an anchor method.
- **Token is single-use and short-lived**, which is why the freshness window is
  only 24 hours; it proves a fresh challenge was solved at signup, not ongoing
  control.
