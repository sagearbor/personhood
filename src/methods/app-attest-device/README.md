# app-attest-device

**Supplementary** verification method: standalone Apple App Attest (iOS) /
Google Play Integrity (Android) device attestation. A near-free "floor" that
proves the request comes from a genuine, non-emulated device running the real
app — killing emulator and VM farms cheaply.

| Property | Value |
|---|---|
| Type | supplementary |
| Strength | 18 |
| Cost | $0.00 |
| Friction | low |
| Freshness | 30 days |
| Platforms | iOS / Android app (not web/kiosk) |

It is **supplementary**, never an anchor: a determined attacker can still farm a
fleet of real phones, so it must never satisfy a policy's anchor requirement.
Strength 18 (< 50) per `docs/06-methods-catalog.md`.

## Flow (challenge nonce → device attestation → verify)

1. **BeginCeremony** mints a random 32-byte challenge `nonce`, binds it to the
   `SessionID` via the `ChallengeStore`, and returns it in `ChallengeData`
   (type `app-attest-challenge`) along with the `complete_endpoint`.
2. The client performs platform attestation over that nonce — Apple App Attest
   on iOS, Google Play Integrity on Android — and POSTs `{ platform, token,
   key_id }` back.
3. **CompleteCeremony** looks up the stored nonce, builds an `AttestationInput`,
   and hands it to the pluggable `Verifier`. On success it records a SHA-256
   attestation digest over `session_id || platform || key_id || nonce`. The raw
   token never lands on the credential.

| CompleteCeremony outcome | Result |
|---|---|
| verifier returns nil | `Success: true` + attestation digest |
| no nonce stored for session | `no_challenge_issued` |
| empty token | `missing_attestation_token` |
| verifier rejects the token | `attestation_invalid` |

Verifier errors are attributable to the device, so they surface as
`Success: false`, not as a Go error.

## Configuration

```go
m := appattestdevice.NewMethod(appattestdevice.Config{
    Verifier: appattestdevice.NewHMACDevVerifier(os.Getenv("APP_ATTEST_SECRET")),
    Store:    appattestdevice.NewInMemoryStore(),
})
```

Suggested env var: `APP_ATTEST_SECRET` (the shared secret for the dev verifier).

## v0.1 vs v0.2

- **Verifier (v0.1 stand-in)**: the default `HMACDevVerifier` recomputes
  `HMAC-SHA256(secret, platform + "." + nonce + "." + key_id)` and constant-time
  compares it (hex) to the supplied token. This makes the method fully testable
  without Apple/Google infrastructure — `SignDeviceTokenForTesting` produces a
  matching token (mirroring `SignWebhookForTesting` in `plaid-bank-link`). It is
  **not** real attestation.
- **v0.2** swaps in real verifiers behind the same `Verifier` interface — no
  other change to the method is needed:
  - **iOS** (`AppAttestVerifier`): parse the CBOR attestation object, validate
    the certificate chain to the Apple App Attest root, confirm the embedded
    nonce hash, and pin the app's appID + key id.
  - **Android** (`PlayIntegrityVerifier`): decode the Play Integrity JWS/JWT
    against Google's public keys and assert `MEETS_DEVICE_INTEGRITY` (rejecting
    emulators) plus the request nonce.
- **In-memory store**: swap `InMemoryStore` for a shared backend (Redis/Postgres)
  so the challenge nonce is visible to every issuer replica.
