# src/server

Reference REST API for the Personhood issuer. Wires together
[`src/registry`](../registry), [`src/credential`](../credential),
[`src/policy`](../policy), and the v0.1 method plugins
([`src/methods/email`](../methods/email),
[`src/methods/sms`](../methods/sms)) into HTTP endpoints a web/mobile client
can drive an enrollment ceremony over.

The server is **stateless across restarts** in v0.1: sessions and per-method
state live in memory. Production deployments should swap in Redis-backed
implementations of `SessionStore`, `email.TokenStore`, and `sms.OTPStore`.

## Run locally

```bash
# 1. Generate an issuer signing key (writes ISSUER_ED25519_SK_B64=... to stdout)
go run ./src/server/cmd/gen-key

# 2. Put that line in `.env.local` (gitignored) alongside any other vars from
#    `env.example`, then source and start the server:
export ISSUER_ED25519_SK_B64=...  # from step 1
export SERVER_ADDR=":8080"
export SERVER_PUBLIC_URL="http://localhost:8080"
export CORS_ALLOWED_ORIGINS="http://localhost:3000"
go run ./src/server/cmd/server
```

By default the server registers the `email` and `sms` methods, both with the
`LogSender`: every ceremony's magic link / OTP is printed to stdout instead of
being sent. PR #3 swaps in real `SendGridSender` / `TwilioSender` behind
build tags. PR #2 registers the `government-id-liveness` Persona anchor.

## Endpoints (v0.1)

All requests/responses are JSON unless noted.

| Method | Path | Purpose |
|---|---|---|
| GET  | `/healthz` | Liveness probe; returns `{"status":"ok"}`. |
| GET  | `/.well-known/did.json` | Issuer DID document (Ed25519 public key as a JWK). |
| GET  | `/v1/methods` | List the registered methods (id, type, strength, friction, version). |
| POST | `/enrollment/start` | Create a session. Returns `{session_id, holder_did, issuer_did, expires_at, available_methods}`. |
| POST | `/v1/methods/{methodId}/begin` | Body: `{session_id, user_input}`. Returns the method's `ChallengeData`. |
| POST | `/v1/methods/{methodId}/complete` | Body: `{session_id, response}`. Records the result on the session and returns `{result, session}`. |
| GET  | `/v1/methods/email/verify?session=...&token=...` | Magic-link landing for the email method; calls `CompleteCeremony` internally and renders an HTML success/failure page. |
| POST | `/v1/credentials/issue` (and `/credentials/issue` alias) | Body: `{session_id}`. Issues the W3C VC for the session's accumulated `VerifiedMethods`. Single-use per session. |
| GET  | `/v1/status-list/{listId}` | Public W3C Status List 2021 credential (v0.1 publishes an empty list). |

### Request flow

1. `POST /enrollment/start` — get a `session_id`.
2. `POST /v1/methods/email/begin` with `user_input: "alice@example.com"` — the server emails a magic link (or LogSender prints it to stdout).
3. User clicks the link, lands on `GET /v1/methods/email/verify?session=...&token=...`, sees a success page; the server has recorded the email `VerifiedMethod` on the session.
4. `POST /v1/methods/sms/begin` with `user_input: "+15551234567"` — SMS OTP is delivered (or logged).
5. `POST /v1/methods/sms/complete` with `response: {type: "otp", payload: {phone_number, code}}` — server records the SMS `VerifiedMethod`.
6. `POST /v1/credentials/issue` with the `session_id` — server returns the signed `PersonhoodCredential` JSON.

## Configuration

See `env.example` at the repo root for the canonical env-var list. The server
itself only reads:

| Variable | Required | Default | Purpose |
|---|---|---|---|
| `ISSUER_ED25519_SK_B64` | yes | — | Base64url-encoded Ed25519 private key (seed OR full). |
| `SERVER_ADDR` | no | `:8080` | net/http bind address. |
| `SERVER_PUBLIC_URL` | no | `http://localhost:8080` | Used to construct magic-link URLs, the issuer DID, and the status list URL. |
| `CORS_ALLOWED_ORIGINS` | no | `http://localhost:3000` | Comma-separated browser origin allowlist. |
| `SESSION_TTL_MINUTES` | no | `60` | How long a session can sit between `start` and `issue`. |

## v0.1 quirks worth knowing

- **Holder DID format**: this server emits `did:personhood:holder:<sha256-hex>`
  rather than `did:key:...`. Reason: avoids a base58 dependency until v0.2;
  see `did.go` for the derivation. A real flow accepts the holder's own
  public key via `holder_public_key_b64` in `/enrollment/start`.
- **Issuer DID is `did:web:<host>`**, derived from `SERVER_PUBLIC_URL`. The
  DID document at `/.well-known/did.json` advertises the public key as a JWK.
  Full did:web resolution (consumed by `credential.WebResolver`) is also v0.2;
  in v0.1 use `credential.MapResolver` for tests/integration.
- **CeremonyContext.UserID hand-off**: the v0.1 `email` and `sms` methods
  receive the user's email address / phone number through
  `CeremonyContext.UserID`. The server threads `user_input` from the request
  body straight into that field. A future revision will grow a dedicated
  `MethodInput` map.
- **Status list is unsigned**: `/v1/status-list/{listId}` returns a placeholder
  Status List 2021 credential with no revocations and no signature. v0.2 signs
  it the same way credentials are signed.

## Tests

```bash
go test ./src/server/...
go test -race ./src/server/...
```

Integration tests in `server_test.go` exercise the full ceremony flow:
`/enrollment/start` → email begin/complete → SMS begin/complete →
`/credentials/issue` → verify the returned VC via `credential.NewVerifier`.

## Layout

```
src/server/
├── go.mod
├── README.md            — this file
├── config.go            — Config + LoadConfigFromEnv
├── session.go           — SessionStore, in-memory
├── did.go               — issuer / holder DID + DID document
├── server.go            — Server type + DefaultMethods()
├── handlers.go          — HTTP handler methods
├── router.go            — chi route wiring + CORS / recover middleware
├── server_test.go       — httptest integration tests
└── cmd/
    ├── server/main.go   — entrypoint (`go run ./src/server/cmd/server`)
    └── gen-key/main.go  — Ed25519 seed generator
```
