# plaid-bank-link

**Anchor** verification method wrapping Plaid's [Hosted Link](https://plaid.com/docs/link/hosted-link/)
flow (bank-account OAuth + identity). "Anchor #3" per `docs/06-methods-catalog.md`.

| Property | Value |
|---|---|
| Type | anchor |
| Strength | 88 |
| Cost | ~$1.50 / link |
| Friction | med |
| Freshness | 180 days |
| Airdrop test | ❌ (requires a bank account) |

Because it requires a bank, policies targeting unbanked users (e.g. OpenLine's
airdrop-test flows) should not require this method; it complements, not
replaces, document- or biometric-based anchors.

## Flow

1. **BeginCeremony** → `PlaidClient.CreateLinkSession` calls
   `POST /link/token/create` with `hosted_link` enabled, binds the returned
   `link_token` to the session, and returns `{ link_token, hosted_link_url }`
   in `ChallengeData` (type `plaid-hosted-link`).
2. The client opens `hosted_link_url`; the user authenticates with their bank
   on Plaid's domain.
3. Plaid POSTs a `LINK` / `SESSION_FINISHED` webhook to the issuer.
   `WebhookHandler` validates the signature, resolves the session via the
   `link_token`, and stores the `Result`.
4. The client polls **CompleteCeremony**, which returns success iff Plaid
   reported `SUCCESS`.

## Status mapping

| Plaid | Personhood `Status` | CompleteCeremony |
|---|---|---|
| `SUCCESS` / `COMPLETED` | `approved` | success + attestation digest |
| `EXITED` / `FAILED` / `ABANDONED` | `declined` | `plaid_declined` |
| `REQUIRES_REVIEW` / `PENDING` | `needs_review` | `plaid_needs_review` |
| `SESSION_EXPIRED` / `EXPIRED` | `expired` | `plaid_session_expired` |

## Configuration

```go
pc, _ := plaidbanklink.NewPlaidClient(clientID, secret, plaidbanklink.PlaidBaseURLSandbox, nil)
pc.WebhookURL = "https://issuer.example/v1/methods/plaid-bank-link/webhook"
m := plaidbanklink.NewMethod(plaidbanklink.Config{
    PlaidClient: pc,
    Store:       plaidbanklink.NewInMemoryStore(),
})
```

Env vars (suggested, mirroring the Persona method): `PLAID_CLIENT_ID`,
`PLAID_SECRET`, `PLAID_ENV` (`sandbox`/`production`), `PLAID_WEBHOOK_SECRET`,
optional `PLAID_TEMPLATE_ID`.

## v0.1 limitations

- **Webhook signature**: v0.1 uses the same HMAC `Plaid-Signature: t=…,v1=…`
  scheme as `government-id-liveness` for a consistent, testable shape.
  Production Plaid signs webhooks with a JWT in the `Plaid-Verification` header,
  verified against Plaid's JWKS — wire that up in v0.2.
- **In-memory store**: swap for a shared backend (Redis/Postgres) to scale the
  webhook + API handlers horizontally.
- **Public-token exchange**: v0.1 treats `SUCCESS` as sufficient for the
  anchor. A future version may exchange the public token and assert bank
  identity-name match before marking the method approved.
