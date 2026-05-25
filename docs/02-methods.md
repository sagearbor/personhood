# 02 — Methods: Plugin Interface + v0.1 Specs

> Status: design spec for v0.1. Companion docs: [01-architecture.md](./01-architecture.md), [03-credential-format.md](./03-credential-format.md), [04-policy-dsl.md](./04-policy-dsl.md).

This document defines the verification-method plugin interface, the three v0.1 methods that ship with the reference implementation, the rationale behind the strength scores, the future methods catalog, and the math (with two worked examples) for stacking supplementary methods on top of an anchor.

## Method taxonomy

Every method declares the following metadata at registration time. The fields are immutable once the process starts so that the credential builder and policy evaluator can reason about them without coordination:

| Field | Type | Meaning |
|---|---|---|
| `id` | string | Globally unique identifier (e.g. `"phone-liveness"`). Becomes the `verifiedMethods[].method` value in the issued credential. |
| `type` | `anchor` \| `supplementary` | Anchor methods can satisfy the anchor requirement of a policy alone; supplementary methods can never substitute for an anchor regardless of how many you stack. |
| `strength` | `0–100` | Integer score representing the per-method evidence of unique humanity. Anchors must be `>= 50`; supplementary must be `< 50`. Calibration in the rationale section below. |
| `cost` | decimal USD | Per-verification cost to the issuer (used by the wallet to choose cheaper paths when policies allow alternatives, and by the issuer to bill / rate-limit). |
| `ux_friction` | `low` \| `med` \| `high` | Hint for the wallet to choose a default ordering during enrollment. |
| `platform_requirements` | `[]string` | Capabilities required of the host device (e.g. `["mobile", "biometric_capable_device"]`, `["any"]`). |
| `freshness_lifetime` | `time.Duration` | Maximum age at which the **per-method** result is still considered fresh. Independent of the credential's own expiry. A policy may require an anchor result < 24h old even when the credential as a whole is < 1y old. |

The taxonomy is deliberately small. Anything else a method needs to communicate (e.g. liveness vendor, OS version, attestation chain) lives in the `verifiedMethods[].evidence` blob of the issued credential, not in the method's static metadata.

## Plugin interface

### Go (canonical)

```go
package methods

import (
    "context"
    "time"

    "github.com/sagearbor/personhood/pkg/types"
)

// Method is implemented by every verification method plugin.
//
// Methods are registered with the global registry (see src/registry) and
// invoked by the issuer server during enrollment ceremonies. Methods MUST be
// safe for concurrent use; the server may run many ceremonies in parallel.
type Method interface {
    // ── Metadata (immutable for the lifetime of the process) ──
    ID() string
    Type() types.MethodType            // types.MethodTypeAnchor | types.MethodTypeSupplementary
    Strength() int                     // 0–100
    Cost() types.USD                   // decimal USD per verification
    UXFriction() types.FrictionLevel   // low | med | high
    PlatformRequirements() []string
    FreshnessLifetime() time.Duration
    Version() string                   // semver of this plugin

    // ── Availability check ──
    // Called before BeginCeremony to confirm this method is usable for the
    // current user context (platform, region, locale). Returns false +
    // human-readable reason so the wallet can explain why a method is hidden.
    IsAvailableForUser(ctx context.Context, uc types.UserContext) (bool, string)

    // ── Ceremony lifecycle ──
    // BeginCeremony returns a method-specific challenge that the wallet
    // presents to the user. The server retains any per-ceremony state keyed
    // by CeremonyContext.EnrollmentID + Method.ID().
    BeginCeremony(ctx context.Context, cc types.CeremonyContext) (types.ChallengeData, error)

    // CompleteCeremony validates the user's response. On success the returned
    // MethodResult is stored by the issuer and used by the credential builder.
    CompleteCeremony(ctx context.Context, cc types.CeremonyContext, response types.ResponseData) (types.MethodResult, error)

    // ── Operational ──
    // HealthCheck is called periodically by the registry; methods that
    // depend on external vendors should ping them. A persistently unhealthy
    // method is removed from /methods until it recovers.
    HealthCheck(ctx context.Context) error
}
```

`types.MethodResult` carries: the method ID, completion timestamp, the per-method `evidence` blob (vendor name + attestation excerpt + opaque vendor receipt id), and the method's claimed `strength` at completion time (frozen so a later strength recalibration of the running process can't retroactively change what a credential says).

### TypeScript

```typescript
// sdk/typescript/src/methods.ts

export type MethodType = 'anchor' | 'supplementary';
export type FrictionLevel = 'low' | 'med' | 'high';

export interface MethodMetadata {
  id: string;
  type: MethodType;
  strength: number;            // 0–100
  cost: string;                // decimal string in USD ("0.04")
  ux_friction: FrictionLevel;
  platform_requirements: string[];
  freshness_lifetime_seconds: number;
  version: string;
}

export interface ChallengeData {
  challengeId: string;
  payload: Record<string, unknown>;   // method-specific (e.g. magic link URL, OTP request id, liveness vendor session token)
  expiresAt: string;                  // ISO-8601
}

export interface ResponseData {
  challengeId: string;
  payload: Record<string, unknown>;   // method-specific
}

export interface MethodResult {
  methodId: string;
  completedAt: string;                // ISO-8601
  strength: number;                   // frozen at completion
  evidence: Record<string, unknown>;
}

export interface Method {
  metadata(): MethodMetadata;
  isAvailableForUser(uc: UserContext): Promise<{ available: boolean; reason?: string }>;
  beginCeremony(cc: CeremonyContext): Promise<ChallengeData>;
  completeCeremony(cc: CeremonyContext, response: ResponseData): Promise<MethodResult>;
  healthCheck(): Promise<void>;
}
```

The TS interface mirrors the Go interface so that future TS-implemented methods (browser-side fuzzy-extractor helpers, in-browser WebAuthn-bound methods) can register on the client side and be cross-validated by the server.

## v0.1 method specs

### Phone-camera liveness + device attestation (ANCHOR, target strength 70–85)

**ID:** `phone-liveness`
**Type:** `anchor`
**Strength:** `75` (mid of the 70–85 range; calibrated against the rationale section below)
**Cost:** `$0.04–$0.20` per verification, vendor-dependent
**UX friction:** `med` (~30 seconds; user must face the camera, blink, turn head)
**Platform requirements:** `["mobile", "biometric_capable_device", "attestation_capable_os"]`
**Freshness lifetime:** `90 days` (per-method), the credential as a whole is also bounded by its own `expirationDate`

**Candidate SDKs (v0.1 evaluation order):**

| Vendor | Strength | Cost | Notes |
|---|---|---|---|
| **Apple FaceID + App Attest** (native iOS) | 80 | $0 | Best UX, best attestation, iOS-only, no remote audit trail |
| **Android BiometricPrompt + Play Integrity** (native Android) | 75 | $0 | Strong attestation, biometric class varies by device |
| **FaceTec ZoOm** (hosted SDK) | 85 | $0.06 | NIST PAD Level 1+2 certified, vendor-neutral, cross-platform, audit trail |
| **iProov** (hosted SDK) | 85 | $0.12 | Flashmark active liveness, server-side analysis |
| **Sumsub** (hosted SDK) | 75 | $0.20 | KYC-flavored; over-collects data for v0.1 |

**Recommendation:** native-first with a hosted fallback. On iOS, use FaceID + App Attest; on Android, BiometricPrompt + Play Integrity. When the user is on the web wallet or on a platform without strong native attestation, fall back to FaceTec (lowest cost of the certified hosted SDKs, best vendor-neutrality). The plugin abstracts the choice — the integrator sees `phone-liveness` either way, with the vendor name disclosed in `verifiedMethods[].evidence.vendor` for integrators that care.

**User flow:**
1. Wallet calls `POST /methods/phone-liveness/begin`. Server returns a vendor-specific challenge — e.g. a FaceTec session token, or for native iOS, a nonce that will be wrapped by App Attest.
2. Wallet opens the camera, runs the liveness ceremony (blink + head turn + flashmark, ~20 seconds).
3. Wallet collects the device attestation: App Attest assertion on iOS, Play Integrity verdict on Android. Wallet bundles this with the liveness response.
4. Wallet calls `POST /methods/phone-liveness/complete` with `{ challengeId, livenessVendorReceipt, deviceAttestation }`.
5. Server-side validation (below) runs; on success, a `MethodResult` is stored.

**Server-side validation:**
- Verify the device attestation against Apple's / Google's roots. Reject if the device is rooted/jailbroken, the OS is unrecognized, or the attestation is stale (> 5 minutes old).
- Submit the liveness receipt to the vendor's verification endpoint. Reject anything below the vendor's pass threshold (FaceTec: ZoOm score >= 0.95 with PAD verdict "live").
- Cross-check: the `holder_did` in the `CeremonyContext` must match the device that produced the attestation (the holder key is generated *in* the device's secure enclave during enrollment, so the public key in the attestation chain matches the holder DID).
- Rate-limit by source IP + device id to make farming expensive.

**Anti-fraud measures:**
- **Replay defense:** the liveness challenge embeds a server-issued nonce that the vendor SDK incorporates into the recorded frames; replaying a captured liveness session at a later time fails the vendor's check.
- **Presentation attack defense:** the chosen vendor must be NIST PAD Level 1 minimum (FaceTec Level 2 preferred).
- **Sybil farming defense:** device attestation prevents emulators/rooted devices; the per-method cost (even at $0.06) raises the per-account marginal cost well above naive bot economics.
- **Hardware sybil farming:** still possible with racks of real phones and human accomplices, but this is the realistic upper bound and well-understood by integrators choosing this method.

**Known weaknesses:**
- 3D-printed silicone masks defeat low-end PAD; mitigated by choosing a Level 2+ vendor and by future ZK-bound multi-anchor policies.
- Apple App Attest has had key-extraction PoCs on jailbroken devices; mitigated by rejecting jailbroken devices in attestation validation.
- A user-assisted attack (the real human holds the phone for an attacker) is undetectable cryptographically; integrators who care should require periodic re-anchor and combine with behavioural signals.

---

### Email magic link (SUPPLEMENTARY, target strength 5–10)

**ID:** `email`
**Type:** `supplementary`
**Strength:** `8`
**Cost:** `$0.001` (SES-equivalent)
**UX friction:** `low`
**Platform requirements:** `["any"]`
**Freshness lifetime:** `30 days`

**Flow:**
1. Wallet calls `POST /methods/email/begin` with the user's claimed email address.
2. Server validates the address: syntactically valid, MX records resolve, the domain is **not** on the disposable-email blocklist (e.g. `disposable-email-domains` + a maintained allowlist of corporate-but-burner-looking domains).
3. Server generates a random 32-byte token, stores `{ token: challengeId, email, expiresAt }`, and emails a one-click magic link `https://wallet.personhood.example/verify-email?token=<base64url>`.
4. User clicks the link in their inbox; wallet receives the token, calls `POST /methods/email/complete`.
5. Server marks the email verified, returns a `MethodResult{methodId: "email", evidence: {email_hash: sha256(email)}}`. The plaintext email is **not** stored in the credential — only the hash.

**Anti-fraud:**
- Disposable-email blocklist (refreshed weekly).
- Per-IP and per-email-domain rate limits.
- Magic-link single-use, 10-minute expiry.
- Click confirmation includes a per-token nonce in the URL fragment, validated client-side, to defend against email-scanning security tools that pre-fetch links (which would otherwise mark links as used before the user clicks).

**Why strength = 8:** owning an email address proves almost nothing about uniqueness — Gmail signup is free, free-tier corporate emails are easy, and bot farms can mint thousands of addresses per dollar. The signal is "this human can receive an inbox message right now" which is mildly useful as a recency check. We treat it as the floor of supplementary strength.

---

### SMS OTP (SUPPLEMENTARY, target strength 10–15)

**ID:** `sms`
**Type:** `supplementary`
**Strength:** `12`
**Cost:** `$0.04` (Twilio US-equivalent)
**UX friction:** `low`
**Platform requirements:** `["any"]`
**Freshness lifetime:** `30 days`

**Flow:**
1. Wallet calls `POST /methods/sms/begin` with the user's phone number (E.164).
2. Server validates: parses with `libphonenumber`, runs a Twilio Lookup to retrieve the line type, and **rejects VOIP / non-mobile lines** (`carrier.type != "mobile"`). Also rejects numbers on a maintained blocklist of known SMS-farming carriers.
3. Server sends a 6-digit OTP via Twilio.
4. User types the OTP into the wallet; wallet calls `POST /methods/sms/complete`.
5. Server validates the OTP (single-use, 10-minute expiry, max 3 attempts), returns a `MethodResult` with `evidence: { phone_hash: sha256(e164), carrier: "Verizon Wireless", line_type: "mobile" }`.

**Anti-fraud:**
- VOIP rejection (kills the cheapest farming path).
- Carrier blocklist (kills the second-cheapest path).
- Per-IP and per-number rate limits; exponential backoff after failures.
- One credential per number ever (issuer keeps a hash-of-number → was-used set; collisions across users are flagged for manual review).

**SS7 caveat:** SMS is vulnerable to SS7 interception and SIM-swap. We accept this — SMS is supplementary, never an anchor, and a SS7-positioned attacker still cannot satisfy a policy that demands an anchor. We document the caveat in the integrator-facing docs so policies for high-stakes actions can choose `blocked_methods: [sms]` if they want zero SS7 exposure.

**Why strength = 12:** owning a mobile number is a stronger signal than owning an email — it costs ~$0.04 to send the SMS, costs the bot farm ~$2–$10/month to lease the number, and the carrier-type check rules out the cheapest farming. Still trivially defeated at the cost of a real prepaid SIM card, so it remains supplementary.

## Strength rationale

Strength scores are calibrated on a 0–100 scale anchored against publicly-known proof-of-personhood signals so integrators have an intuitive frame:

| Signal | Strength | Rationale |
|---|---|---|
| WorldCoin iris orb scan | 100 | Best-in-class biometric, in-person, $30k device cost, near-impossible to forge at scale |
| Government ID + liveness (Persona/Onfido) | 90 | Strong, but ID forgery industry exists; depends on issuing country |
| Plaid bank account link | 90 | Strong proof of bank-verified identity; cheap to defeat only if attacker has stolen banking credentials |
| FaceTec liveness (PAD Level 2) + device attestation | 85 | The phone-liveness ceiling in v0.1 |
| Native FaceID + App Attest | 80 | Slightly below FaceTec because there's no remote audit trail |
| Native BiometricPrompt + Play Integrity | 75 | Mid of 70–85, varies by Android device class |
| Personhood `phone-liveness` (mixed) | 75 | The default we ship |
| **Anchor threshold** | 50 | Anything below this cannot be an anchor |
| In-person notary attestation | 40 | High-friction, low-throughput; useful as supp only |
| Web-of-trust attestation by N verified humans | 25–40 | Scales with N and the verifier reputation; out of scope for v0.1 |
| SMS OTP (mobile, non-VOIP) | 12 | Carrier check + per-OTP cost makes farming non-trivial |
| Email magic link | 8 | Floor of useful supplementary; trivially farmed but proves recency |
| Naive CAPTCHA pass | 3 | Defeated by every modern CAPTCHA-solver service |

The scores are deliberately conservative on the anchor side (we'd rather understate strength and let integrators stack supplementary checks than overstate strength and have a credential give false confidence). The anchor floor of 50 is the protocol invariant; the actual numbers above 50 are calibration we expect to tune with empirical fraud data once the framework has live integrators.

## Future methods catalog (v0.2+)

- **Fuzzy extractor + on-device biometric commitment** — anchor, strength target 70. Inherits from OpenLine's existing Rust prototype (`src/suffrage/fuzzy-extractor/`). The "airdrop-test compliant" anchor with no central biometric database. Requires productionization of the helper-data scheme and the accompanying ZK circuits.
- **Plaid bank account link** — anchor, strength 90. Integrate Plaid Identity Verification; the user proves control of a bank account whose holder identity the bank has already verified. Highest-strength anchor available cheaply; failure mode is users without bank accounts.
- **Persona / Onfido KYC** — anchor, strength 90. Government-ID + selfie liveness. Best for jurisdictions where ID is widespread; fails the airdrop test for the unbanked / undocumented.
- **Iris orb** — anchor, strength 100. Requires WorldCoin-style hardware partnership; unlikely in v0.2 but listed for completeness.
- **Web of trust attestation** — supplementary, strength 25–40 scaling with attestor reputation. Existing Personhood-verified humans co-sign that a new human is real; needs careful Sybil-resistance design.
- **Government ID document scan (without liveness)** — supplementary, strength 30. ID alone without a liveness check is weaker than ID+liveness but still useful as a recency / cross-context signal.
- **WebAuthn passkey on a known device** — supplementary, strength 15. Proves device continuity, not personhood; mildly useful for "still the same human" checks.
- **In-person enrollment by partner organization** — anchor, strength 70. NGO with a tablet does the liveness + photo capture in-person; useful for the airdrop-test cohort.

Each future method will land as a PR adding `src/methods/<name>/` and updating this document with its strength rationale and known weaknesses.

## Stacking math

A policy declares some combination of: an anchor requirement (`anchor_required: true|false`), a supplementary points threshold (`min_supplementary_points: N`), and freshness windows. The evaluator (defined in [04-policy-dsl.md](./04-policy-dsl.md)) decides pass/fail as follows:

1. Filter `verifiedMethods` to those whose `completedAt` is within the policy's allowed freshness window (per-method age <= `max_anchor_method_age_seconds` for anchors; <= `max_credential_age_seconds` for supplementary, etc.).
2. If `anchor_required` is true, assert at least one method with `type == anchor` survives the filter.
3. Sum `strength` of all surviving supplementary methods; assert `sum >= min_supplementary_points`.
4. Apply any `blocked_methods` / `allowed_methods` filters.
5. If policy requests a nullifier, derive it from the credential's `nullifierBinding` + the policy's `nullifier_context_tag`.

### Example 1: passing UBI claim

```
Policy (OpenLine Commons UBI claim):
  anchor_required: true
  min_supplementary_points: 0
  max_anchor_method_age_seconds: 86400   # 24h
  nullifier_required: true
  nullifier_context_tag: "openline/commons/ubi-claim/cycle-42"

Credential:
  verifiedMethods:
    - method: phone-liveness    type: anchor          strength: 75   completedAt: 6h ago
    - method: email             type: supplementary   strength: 8    completedAt: 5d ago
    - method: sms               type: supplementary   strength: 12   completedAt: 5d ago

Evaluation:
  - filter by freshness: phone-liveness (6h < 24h) PASS; email + sms not constrained by anchor freshness, retained
  - anchor_required: phone-liveness survives → PASS
  - min_supplementary_points: 0 → trivially PASS
  - nullifier derived from binding + tag → returned to integrator
  Result: PASS, derived_nullifier = 0xabc…
```

### Example 2: failing high-trust account recovery

```
Policy (third-party financial app, account recovery):
  anchor_required: true
  min_supplementary_points: 20
  max_anchor_method_age_seconds: 86400      # 24h fresh anchor
  max_credential_age_seconds: 2592000       # 30d max VC age

Credential:
  verifiedMethods:
    - method: phone-liveness    type: anchor          strength: 75   completedAt: 40h ago
    - method: email             type: supplementary   strength: 8    completedAt: 6d ago
    - method: sms               type: supplementary   strength: 12   completedAt: 6d ago

Evaluation:
  - VC age: 6d < 30d → PASS overall age
  - filter by anchor freshness: phone-liveness completedAt 40h ago > 24h → DROP from anchor candidates
  - anchor_required: no surviving anchor → FAIL
  Result: FAIL, code = "EVAL_ANCHOR_EXPIRED",
          remediation = "re-verify with phone-liveness within the last 24 hours"
```

Note that the supplementary points would have totalled 20 (8 + 12) — *just* enough to satisfy `min_supplementary_points`. But because the anchor was stale, the credential fails outright. This is the framework's central design choice: **stacking supplementary signals never substitutes for a fresh anchor when the policy demands one**. An attacker who has farmed thousands of emails and burner SIMs cannot satisfy a policy that requires a fresh anchor, period.

## Delivery configuration — environment variables

Every method that talks to a third-party API is configured via env vars. The reference server reads them at startup and routes them into the appropriate `Sender` / `Client` / webhook handler. See `.example.env` at the repo root for the canonical template (copy to `.env.local` and fill in).

### Email — SendGrid (`src/methods/email`)

Built behind the `sendgrid` build tag. Default build uses `LogSender` (writes the magic link to stdout — useful for dev and unit tests).

| Variable | Required when `sendgrid` tag | Notes |
|---|---|---|
| `SENDGRID_API_KEY` | yes | Get from <https://app.sendgrid.com/settings/api_keys>. Scope: `mail.send`. |
| `SENDGRID_FROM` | yes | A verified Single Sender or any address on an authenticated domain. |
| `SENDGRID_FROM_NAME` | optional | Display name shown to recipients. Defaults to empty. |

Compile with `go build -tags sendgrid ./src/server/cmd/server`. If `SENDGRID_API_KEY` is set but the binary was not built with the tag, the email package logs a warning and falls back to `LogSender` rather than failing silently.

### SMS — Twilio (`src/methods/sms`)

Built behind the `twilio` build tag. Default build uses `LogSender`.

| Variable | Required when `twilio` tag | Notes |
|---|---|---|
| `TWILIO_ACCOUNT_SID` | yes | From the Twilio console home page. |
| `TWILIO_AUTH_TOKEN` | yes | From the Twilio console home page. |
| `TWILIO_FROM` | yes | E.164 phone number you own (e.g. `+15551234567`). Trial accounts must verify the destination at <https://console.twilio.com/us1/develop/phone-numbers/manage/verified>. |

Compile with `go build -tags twilio ./src/server/cmd/server`. To enable both vendors at once: `go build -tags 'sendgrid twilio'`.

### Government ID + liveness — Persona (`src/methods/government-id-liveness`)

No build tag; the module is always compiled. Registration is gated on env vars: the server registers the method only when *all three* of `PERSONA_API_KEY`, `PERSONA_TEMPLATE_ID`, and `PERSONA_WEBHOOK_SECRET` are set.

| Variable | Required | Notes |
|---|---|---|
| `PERSONA_API_KEY` | yes | `persona_sandbox_…` (free) or `persona_production_…`. |
| `PERSONA_TEMPLATE_ID` | yes | Inquiry template id, starts with `itmpl_`. |
| `PERSONA_WEBHOOK_SECRET` | yes | Shown when creating the webhook in Persona's dashboard. Cannot be re-fetched later. |
| `PERSONA_ENVIRONMENT_ID` | optional | Scopes to a particular sandbox env. |
| `PERSONA_RETURN_URL` | optional | URL the user is redirected to after completing the hosted flow. Defaults to Persona's "all done" screen. |

### Server itself

| Variable | Required | Default | Notes |
|---|---|---|---|
| `ISSUER_ED25519_SK_B64` | yes | — | Generate with `go run ./src/server/cmd/gen-key`. |
| `SERVER_ADDR` | no | `:8080` | Bind address. |
| `SERVER_PUBLIC_URL` | no | `http://localhost:8080` | Used for magic-link URLs, did:web issuer DID, status list URL. |
| `CORS_ALLOWED_ORIGINS` | no | `http://localhost:3000` | Comma-separated browser origin allowlist. |
| `SESSION_TTL_MINUTES` | no | `60` | Enrollment session lifetime. |

### Build matrix

| Command | Email sender | SMS sender |
|---|---|---|
| `go build ./src/server/cmd/server` | `LogSender` | `LogSender` |
| `go build -tags sendgrid ./...` | `SendGridSender` (if env set) | `LogSender` |
| `go build -tags twilio ./...` | `LogSender` | `TwilioSender` (if env set) |
| `go build -tags 'sendgrid twilio' ./...` | `SendGridSender` | `TwilioSender` |

`Dockerfile` (PR #5) builds with `-tags 'sendgrid twilio'` so production has both.

## Cross-references

- The full credential schema and how `verifiedMethods[]` is serialized: [03-credential-format.md](./03-credential-format.md).
- The full policy schema, evaluator pseudocode, and worked policy examples: [04-policy-dsl.md](./04-policy-dsl.md).
- The OpenLine Suffrage + Commons policies that consume these methods in production: [05-openline-refactor.md](./05-openline-refactor.md).
