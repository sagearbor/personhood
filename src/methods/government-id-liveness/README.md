# src/methods/government-id-liveness

Personhood anchor verification method: government ID document capture
(driver's licence, passport, national ID) + selfie liveness check, wrapping
[Persona](https://withpersona.com/)'s hosted Inquiries flow.

| Metadata | Value |
|---|---|
| ID | `government-id-liveness` |
| Type | **anchor** |
| Strength | **90** |
| Cost / verification | ~$2 USD (Persona contract; sandbox is free) |
| UX friction | high — user uploads document + completes liveness |
| Freshness lifetime | 180 days |
| Platforms | mobile + desktop browsers with a camera |

## Flow

1. **Server: `BeginCeremony`** — server creates a Persona Inquiry via
   `POST /api/v1/inquiries` with `reference-id = sessionID`. The store binds
   `inquiry-id → session-id` so the webhook can resolve back to the right
   session. Server returns:

   ```json
   {
     "type": "persona-hosted-flow",
     "payload": {
       "inquiry_id": "inq_…",
       "hosted_flow_url": "https://inquiry.withpersona.com/verify?inquiry-id=inq_…&redirect-uri=…",
       "return_url": "<app return URL>",
       "poll_endpoint": "/v1/methods/government-id-liveness/complete"
     }
   }
   ```

2. **Client** — the web app navigates the user to `hosted_flow_url`. Persona
   handles the entire document-capture + selfie-liveness UI on its own domain.

3. **Persona → Server: webhook** — once the inquiry reaches a terminal state
   (`approved` / `declined` / `needs_review`), Persona POSTs an
   `inquiry.completed` (or `inquiry.expired`) event to the server's webhook
   endpoint. The webhook handler validates the `Persona-Signature` HMAC,
   parses the body, and writes a `Result` to the store keyed by sessionID.

4. **Client: poll `CompleteCeremony`** — the web app polls
   `POST /v1/methods/government-id-liveness/complete` every few seconds. The
   server returns a non-zero `MethodResult` once the webhook has recorded an
   approved status; until then the result is `{success:false,
   error_reason:"pending_persona_webhook"}`.

## Configuration

```bash
PERSONA_API_KEY=persona_sandbox_xxx       # or persona_production_xxx
PERSONA_TEMPLATE_ID=itmpl_xxx
PERSONA_WEBHOOK_SECRET=whsec_xxx          # set when creating the webhook in Persona's dashboard
PERSONA_ENVIRONMENT_ID=env_xxx            # optional; only if you have multiple sandbox envs
```

Create the API key at <https://withpersona.com/dashboard/api-keys> and the
inquiry template at <https://withpersona.com/dashboard/inquiry-templates>.
Register the webhook endpoint at
<https://withpersona.com/dashboard/webhooks> pointing at
`https://<your-server>/v1/methods/government-id-liveness/webhook`. Persona
will reveal the webhook secret immediately after creation; copy it into
`.env.local`.

## Webhook signature

Persona emits `Persona-Signature: t=<unix>,v1=<hex>[,v1=…]` headers. The HMAC
is computed as:

```
HMAC-SHA256(secret, "<unix-timestamp>.<raw body>")
```

Multiple `v1=` values appear during secret rotations. `VerifyWebhookSignature`
accepts any match within `WebhookReplayWindow` (5 minutes by default).

## Tests

```bash
go test -race ./src/methods/government-id-liveness/
```

Coverage: Persona Inquiry creation (against a `httptest` fake), webhook
signature verification (good / bad secret / out-of-window), webhook body
parsing + status mapping, full webhook → CompleteCeremony round-trip,
pending-state behaviour.

## Future work

- **Server-side polling fallback**: if the webhook is delayed, the server can
  call `PersonaClient.FetchInquiryStatus` from `CompleteCeremony`. v0.1 ships
  this method but does not invoke it.
- **Replay-attack defence beyond timestamp window**: keep a bounded LRU of
  recently-processed `inquiry-id + event timestamp` pairs.
- **Persona JS Inquiry SDK** (in-app inline flow) — wrap as an alternative
  challenge type to the redirect-based hosted flow.
- **Human review queue**: when status is `needs_review`, surface to an
  operator UI rather than failing the ceremony.
