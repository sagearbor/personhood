# paid-billing-card (supplementary, strength 35)

The **strongest single supplementary** method per
[`docs/06-methods-catalog.md`](../../../docs/06-methods-catalog.md) — a $0
[Stripe SetupIntent](https://stripe.com/docs/payments/setup-intents) with
3-D Secure / SCA. The "Twitter Blue / OpenAI tier-1" pattern: a real card that
passes an SCA challenge is expensive to mint at scale.

| | |
|---|---|
| **Type** | supplementary (NOT an anchor) |
| **Strength** | 35 |
| **Cost** | ~$0.30 / verification |
| **UX friction** | med |
| **Freshness** | 180 days |
| **Airdrop-test** | ❌ requires a payment card |

It is **supplementary, not an anchor** (35 < 50): a card never satisfies
`anchor_required` on its own. Integrators serving the unbanked should not
*require* it.

## Why it's strong

- **Cost to mint** — a working card that clears an SCA/3DS challenge is far
  harder to mass-produce than an email or SMS number.
- **Cross-identity dedup** — Stripe returns a stable **card fingerprint**; the
  same physical card reused across identities produces the same fingerprint,
  which lands (hashed) in the credential's `attestation_digest`.

## Wire model (mirrors `plaid-bank-link` / `government-id-liveness`)

1. `BeginCeremony` creates a `$0` SetupIntent (`usage=off_session`,
   `request_three_d_secure=any`) bound to the session via
   `metadata.session_id`, and returns `client_secret` + `publishable_key`.
2. The client confirms the card with Stripe.js / the mobile SDK, running the
   3DS challenge.
3. Stripe POSTs a `setup_intent.succeeded` / `.setup_failed` webhook. The
   `WebhookHandler` verifies the genuine `Stripe-Signature` HMAC
   (`t=…,v1=HMAC-SHA256(secret,"t.body")`) and stores the result.
4. The client polls `CompleteCeremony`, which succeeds iff the SetupIntent
   succeeded.

## Card fingerprint expansion

Stripe sends `payment_method` **unexpanded** (a `pm_…` id) by default. The
webhook handler reads `data.object.payment_method.card.fingerprint` when the
event is configured with expansion, and falls back to the `pm_…` id otherwise.
For stable cross-identity dedup, configure the webhook/event to expand
`payment_method` (or retrieve it server-side) so the real card fingerprint is
available.

## Environment variables

| Var | Required | Purpose |
|---|---|---|
| `STRIPE_SECRET_KEY` | to enable | Stripe secret key (`sk_test_…`/`sk_live_…`); gates registration |
| `STRIPE_WEBHOOK_SECRET` | to enable | webhook signing secret (`whsec_…`) |
| `STRIPE_PUBLISHABLE_KEY` | recommended | `pk_…` passed to the client to confirm the card |
| `STRIPE_BASE_URL` | optional | overrides the API root (default `https://api.stripe.com`) |

Registers (with its webhook route) only when `STRIPE_SECRET_KEY` +
`STRIPE_WEBHOOK_SECRET` are both set.
