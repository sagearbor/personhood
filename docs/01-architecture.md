# 01 — Personhood Architecture

> Status: design spec for v0.1. Companion docs: [02-methods.md](./02-methods.md), [03-credential-format.md](./03-credential-format.md), [04-policy-dsl.md](./04-policy-dsl.md), [05-openline-refactor.md](./05-openline-refactor.md).

## Elevator pitch

Personhood is a pluggable, open-source framework that lets any application answer the question *"is this a unique human?"* without locking the integrator into a single biometric vendor, identity provider, or trust assumption. End users complete one or more verification methods (in v0.1: a phone-camera liveness check plus optional email and SMS) and receive a portable W3C Verifiable Credential that they own and re-present to any consuming service. Integrators declare a **policy** — "require one anchor method plus N supplementary points, no older than 90 days" — and a small SDK evaluates a presented credential against that policy. The architectural commitment that distinguishes Personhood from naive weighted-sum stacks is that **every valid credential must include at least one anchor method**; supplementary signals add recency and cross-context binding but never substitute for a high-entropy anchor. The reference implementation is intentionally small, vendor-neutral at the seams, and designed to grow new anchor methods (fuzzy extractor, government-ID + liveness, iris/orb, bank-account-link) without breaking integrators.

## System diagram

```
                       ┌──────────────────────────────────┐
                       │      End-User Wallet App         │
                       │  (web + mobile, hybrid in v0.1)  │
                       │  - holds VC + holder key         │
                       │  - drives ceremonies             │
                       │  - presents VC to integrators    │
                       └─────────────┬────────────────────┘
                                     │  enrollment ceremonies
                                     ▼
┌─────────────────────────────────────────────────────────────────────────┐
│                       Personhood Core (issuer server)                    │
│                                                                          │
│  ┌──────────────┐    ┌──────────────────┐    ┌───────────────────────┐  │
│  │   Method     │───▶│   Credential     │───▶│  W3C VC Issuer        │  │
│  │   Registry   │    │   Builder        │    │  (Ed25519 + URDNA15)  │  │
│  └──────┬───────┘    └──────────────────┘    └───────────────────────┘  │
│         │                                                                │
│  ┌──────▼─────────┐  ┌──────────────┐  ┌──────────────────────────┐    │
│  │ phone-liveness │  │    email     │  │           sms             │    │
│  │   (ANCHOR)     │  │ (supp 5pt)   │  │       (supp 10pt)         │    │
│  └────────────────┘  └──────────────┘  └──────────────────────────┘    │
└─────────────────────────────────────────────────────────────────────────┘
                                     │  issues credential
                                     ▼
                       ┌──────────────────────────────────┐
                       │  User-held W3C VC (in wallet)    │
                       │  signed with did:web:issuer.pers │
                       │  bound to did:key:holder         │
                       └─────────────┬────────────────────┘
                                     │  Verifiable Presentation
                                     ▼
┌─────────────────────────────────────────────────────────────────────────┐
│  Integrator (e.g. OpenLine Suffrage, OpenLine Commons, third-party app) │
│                                                                          │
│  ┌──────────────┐    ┌────────────────────┐    ┌────────────────────┐   │
│  │ Verifier SDK │───▶│  Policy Evaluator  │───▶│  EvaluationResult  │   │
│  │  (Go / TS)   │    │  (deterministic)   │    │  (pass | fail+code)│   │
│  └──────┬───────┘    └────────────────────┘    └────────────────────┘   │
│         │                                                                │
│         │   policy declared in YAML / JSON                               │
│         ▼                                                                │
│  ┌────────────────────────────────────────────────────────────────┐     │
│  │  policy: anchor_required + 15 supp pts + max_age 90d           │     │
│  └────────────────────────────────────────────────────────────────┘     │
└─────────────────────────────────────────────────────────────────────────┘
```

## Components

### Method Registry (`src/registry/`)
The registry is a runtime catalog of verification methods that have been compiled into the issuer binary. Each method package registers itself in its `init()` function (or via explicit wire-up in the server `main`). The registry is queried by the credential builder during enrollment ("which methods is this user starting?"), by the server REST API ("list available methods for this platform"), and by health checks ("can phone-liveness still talk to its vendor?"). Invariants are enforced at registration time: method IDs must be globally unique within the process; anchor methods must declare `Strength >= 50` and supplementary methods must declare `Strength < 50`; metadata fields (strength, cost, friction) are immutable for the lifetime of the process so that the credential builder can rely on them without coordination. See [02-methods.md](./02-methods.md) for the full `Method` interface.

### Method Plugins (`src/methods/<name>/`)
Each verification method is a standalone Go module that implements the `Method` interface. v0.1 ships three: `phone-liveness` (anchor, strength 70–85), `email` (supplementary, strength 5–10), and `sms` (supplementary, strength 10–15). Methods are intentionally small surfaces — they expose lifecycle hooks (`BeginCeremony`, `CompleteCeremony`) and metadata, but never touch credential signing, policy evaluation, or storage. A new method (fuzzy extractor in v0.2, Plaid KYC, etc.) lands as a new Go module in `src/methods/`, wired into `go.work`, and registered. The core does not change.

### Credential Builder + W3C VC Issuer (`src/credential/`)
The credential builder collects the `MethodResult`s from completed ceremonies in a single enrollment session, validates them (anchor present? freshness windows respected?), and assembles a `PersonhoodCredential` payload. The VC issuer canonicalizes the JSON-LD using URDNA2015, signs with the issuer's Ed25519 key (DID: `did:web:issuer.personhood.example`), and emits the signed VC bound to the holder's `did:key`. The issuer is also the entity that derives the optional `nullifierBinding` Pedersen-BN254 commitment that downstream ZK-aware integrators (e.g. OpenLine Suffrage) use to compute per-context nullifiers without revealing the holder's identity secret. See [03-credential-format.md](./03-credential-format.md).

### Policy Evaluator (`src/policy/`)
A pure, deterministic function: `Evaluate(vc PersonhoodCredential, policy Policy, now time.Time) EvaluationResult`. The evaluator parses the integrator's declared policy, walks the credential's `verifiedMethods` array, checks the anchor requirement, sums supplementary points, validates freshness, optionally checks the nullifier binding, and returns a structured pass-or-fail result with a machine-readable error code. The evaluator never makes network calls, never reads disk — it is trivially unit-testable and the same code ships in the Go SDK, the TypeScript SDK, and the reference server's verification endpoint. See [04-policy-dsl.md](./04-policy-dsl.md).

### Verifier SDK (`sdk/go/`, `sdk/typescript/`)
Two thin wrappers around (a) VC signature verification, (b) issuer-DID resolution (cached), (c) revocation list lookup, and (d) the policy evaluator. Integrators import the SDK, load their policy YAML, and call `personhood.Verify(presentedVP, policy)`. The Go SDK is the canonical implementation; the TypeScript SDK has feature parity for the verification path and additionally exposes browser helpers for triggering the wallet's presentation flow over a redirect or postMessage.

### End-User Wallet (`app/web/` v0.1, `app/mobile/` v0.2)
The reference Next.js wallet is where end users actually run the enrollment ceremonies. It drives the user through method selection, calls the issuer's REST endpoints to begin and complete each ceremony, stores the resulting VC locally (IndexedDB, encrypted at rest with a WebAuthn-protected key), and exposes a "present credential to <integrator URL>" flow. v0.1 web works on any modern browser; v0.2 adds a React Native mobile wallet that can hold the key in the secure enclave / Android Keystore and that is the recommended host for the phone-liveness anchor method. The wallet is reference-quality, not the only possible wallet — third parties can build their own as long as they implement the holder side of the presentation protocol.

## Data flows

### 1. Enrollment
1. User opens the wallet, picks "verify with Personhood".
2. Wallet generates a fresh holder keypair (Ed25519 in secure enclave on mobile; WebAuthn-protected key on web), derives `did:key:<base58(pub)>`.
3. Wallet POSTs `/enrollment/begin` with the holder DID and the user's target integrator policy (optional — used only to suggest which methods to complete).
4. Server returns an `enrollment_id` and the list of available methods with their metadata.
5. For each method the user selects, wallet calls `/methods/<id>/begin` → method-specific challenge → user completes the challenge in-app → wallet POSTs `/methods/<id>/complete` with the response. Server validates and stores a `MethodResult` against the `enrollment_id`.
6. Wallet calls `/enrollment/issue` to request issuance.

### 2. Issuance
1. Issuer loads all `MethodResult`s for the `enrollment_id`.
2. Issuer asserts the credential meets the **minimum issuance bar**: at least one anchor method completed successfully. (Issuance refuses if not — supplementary-only credentials are not issuable. This is enforced at the issuance layer, not just at the policy layer, to prevent low-quality credentials from existing at all.)
3. Issuer builds the JSON-LD `PersonhoodCredential`, including the holder DID as `credentialSubject.id`, each verified method as a `verifiedMethods` entry, and (if the user opted in) a `nullifierBinding` Pedersen commitment.
4. Issuer canonicalizes (URDNA2015), signs with Ed25519Signature2020 using `did:web:issuer.personhood.example#key-1`.
5. Issuer registers the new VC's status-list index in its Status List 2021 credential (default: not revoked).
6. Issuer returns the signed VC.
7. Wallet persists the VC in encrypted local storage and shows the user "you are verified — here are the things you can now do".

### 3. Presentation
1. Integrator (e.g. OpenLine Commons) opens its action flow ("claim this cycle's UBI").
2. Integrator generates a random `challenge` (≥128 bits, single-use, bound to the action) and a `domain` (the integrator's origin).
3. Integrator redirects (or postMessages) the user to the wallet with `(challenge, domain, requested_policy_id)`.
4. Wallet picks the highest-quality VC that satisfies the requested policy (if multiple are held), builds a W3C Verifiable Presentation that embeds the VC, signs the VP with the holder's private key over `(challenge || domain)`, and returns it to the integrator.

### 4. Verification
1. Integrator passes the VP to its verifier SDK along with the loaded policy.
2. SDK verifies the holder's signature over the VP, then the issuer's signature over the embedded VC. Issuer DID is resolved via `did:web` (cached). The Status List 2021 entry is fetched and checked for revocation.
3. SDK calls `policy.Evaluate(vc, policy, time.Now())`.
4. Evaluator returns `EvaluationResult{Passed: true/false, Code: "...", DerivedNullifier: 0x...}`.
5. If passed and the policy requested a nullifier, the SDK exposes `DerivedNullifier` to the integrator, which checks its own nullifier store to prevent replay (e.g. one UBI claim per cycle).
6. Integrator either authorises the action or returns a structured error to its UI with a code the wallet can interpret ("anchor expired — re-verify").

## Trust model

Trust in Personhood is intentionally layered and transitive:

- **End users trust the issuer** to honestly verify each method and not issue credentials to non-humans. The issuer is *not* trusted with the user's biometric — the phone-camera liveness method ships its verification result (plus device attestation) to the issuer, but the raw biometric stays on-device under TEE control.
- **End users trust their wallet** (it holds the holder key and the VC). On mobile this trust is anchored in the secure enclave; on web it is anchored in WebAuthn.
- **Integrators trust the issuer's DID and its method roster.** An integrator picks a set of trusted issuers (in v0.1, typically just the reference `did:web:issuer.personhood.example`); larger deployments will accept multiple issuers with explicit per-issuer trust scores.
- **Issuers transitively trust upstream attestors:** Apple App Attest and Google Play Integrity for device legitimacy, the chosen liveness vendor (FaceTec, iProov, Sumsub, or native) for the liveness pass/fail signal, Twilio (or equivalent) for SMS deliverability, and the user's email provider for inbox control.
- **Everyone trusts standard cryptographic assumptions:** Ed25519 signatures, SHA-256, BN254 pairing for the optional ZK extension hooks.

Personhood does *not* try to remove transitive trust on platform attestation — that would require an anchor method like the fuzzy extractor that doesn't depend on Apple or Google, which is exactly the v0.2 research track. v0.1 ships with credible transitive trust on widely-deployed platform features.

## Threat model

**Defended:**
- **Sybil via stacked weak signals.** Naive "email + SMS + CAPTCHA = human" schemes are bot-farm-cheap; Personhood's anchor requirement raises the per-account marginal cost from cents to dollars (rented phone + biometric forge attempt).
- **Replay across actions.** Verifiable Presentations are bound to a per-action `challenge` and `domain`; a VP captured during one UBI claim cannot be replayed against another integrator or another cycle.
- **MITM on enrollment.** All issuer endpoints are HTTPS; method-specific ceremonies use challenge-response patterns (magic links, OTP codes); device attestation prevents a remote attacker from completing a liveness check on behalf of a real phone.
- **VC tampering.** JSON-LD URDNA2015 canonicalization + Ed25519 signatures detect any field modification.

**Not defended (out of scope for v0.1):**
- **Nation-state biometric forgery.** A well-funded adversary that can 3D-print silicone masks bypassing FaceTec at scale, or steal an Apple device attestation key, can mint Personhood credentials at the cost of the targeted operation. Mitigation: choose stronger anchor methods (in-person verification, government ID + liveness) for integrator policies that care about this threat.
- **Compromised TEE.** If the user's secure enclave is compromised (jailbroken device + custom firmware), an attacker can extract the holder key and present the VC themselves. Defenders should layer in revocation and behavioral signals at the integrator level.
- **Social engineering.** A user tricked into completing a liveness check on behalf of an attacker, or who hands over their phone, is outside the cryptographic threat model.
- **Issuer compromise.** A compromised issuer signing key allows arbitrary credential minting. Defenders rotate the issuer key periodically, use HSM-backed signing, and publish key revocation via the issuer DID document.

## API surface

REST (issuer):
- `GET  /methods` — list registered methods + metadata
- `POST /enrollment/begin` → `{ enrollment_id, holder_did, available_methods }`
- `POST /methods/{methodId}/begin` → method-specific `ChallengeData`
- `POST /methods/{methodId}/complete` → method-specific `MethodResult`
- `POST /enrollment/issue` → signed `PersonhoodCredential`
- `GET  /credentials/status/{statusListId}` → W3C Status List 2021 credential
- `GET  /.well-known/did.json` — issuer DID document

Go SDK (integrator):
```go
package personhood

func ParsePolicy(yamlOrJson []byte) (Policy, error)
func VerifyPresentation(vp []byte, opts VerifyOpts) (VerifiedCredential, error)
func Evaluate(vc VerifiedCredential, p Policy, now time.Time) EvaluationResult
// Convenience wrapper:
func Verify(vp []byte, p Policy) (EvaluationResult, error)
```

TypeScript SDK (integrator):
```ts
parsePolicy(text: string): Policy
verifyPresentation(vp: unknown, opts?: VerifyOpts): Promise<VerifiedCredential>
evaluate(vc: VerifiedCredential, p: Policy, now?: Date): EvaluationResult
verify(vp: unknown, p: Policy): Promise<EvaluationResult>
// Browser-only helpers:
requestPresentation(walletUrl: string, policyId: string, challenge: string): Promise<unknown>
```

## Storage model

| Layer | What it stores | Lifetime |
|---|---|---|
| **End-user device** (wallet) | Holder Ed25519 keypair (secure enclave / WebAuthn-protected), issued VCs (IndexedDB, encrypted), method-specific local state (e.g. fuzzy-extractor helper data in v0.2) | Until user resets the wallet |
| **Issuer server** | `MethodResult` rows per enrollment (only as long as needed to issue the VC, then deletable); issued-credential index for the Status List 2021 entry; issuer signing key (HSM in production); audit log of issuances | MethodResults purgeable post-issuance; issuance index permanent until revocation expiry |
| **Integrator** | Loaded policy (in code or config); a nullifier store keyed by `(policy_id, derived_nullifier)` for replay prevention if the policy requests nullifiers; **never** the user's VC | Per integrator's retention policy; nullifier store grows with action volume |

The credential itself is held *only* by the user. The issuer can verify it and revoke it, but does not hand it to integrators. Integrators see the VC only at the moment of presentation and need not persist it.

## Failure modes & graceful degradation

- **Method vendor outage** (e.g. FaceTec API down): the registry's `HealthCheck` marks the method unhealthy, the issuer omits it from `/methods` for the duration, and the wallet shows the user a "phone liveness temporarily unavailable" notice. If no anchor methods are healthy, the issuer refuses new enrollments rather than issuing unanchored credentials.
- **Issuer downtime**: existing credentials remain valid (signature + revocation status can be checked from cached issuer DID document), only new issuances and revocation-list refreshes are blocked. Integrators may configure a Status List 2021 cache TTL.
- **VC expiry mid-action**: integrator returns a structured `EVAL_VC_EXPIRED` error and the wallet prompts the user to re-verify before retrying.
- **Holder key loss**: there is no protocol-level recovery in v0.1 — the user re-enrolls from scratch and acquires a new VC bound to a new holder DID. Integrators that need account continuity must handle this at the application layer.
- **Revocation propagation lag**: integrators with strict requirements should set a short Status List 2021 cache TTL (e.g. 1 hour); the trade-off is more network calls per verification.

## Open questions

Deferred to later design rounds:

1. **Multiple issuers / trust federation.** v0.1 assumes a single trusted issuer DID per integrator. How do we let integrators accept multiple issuers with weighted trust scores, and how do anchor methods get rated across issuers?
2. **Selective disclosure.** Should the VC use BBS+ from day one to allow holders to present "anchor was completed" without revealing *which* anchor? v0.1 ships full disclosure; BBS+ is targeted for v0.2.
3. **Quorum-based issuance.** Should issuance require k-of-n issuers signing the same `MethodResult` set, to harden against single-issuer compromise? Probably yes for high-stakes anchor methods in v0.3.
4. **Cross-device portability.** When a user gets a new phone, can they migrate the VC + holder key safely? E2EE backup-to-cloud is one option; protocol-level recovery via re-enrollment is the v0.1 default.
5. **Pricing for issuer-hosted SaaS.** Is the issuer free, freemium, or pay-per-issuance? Affects how the registry meters expensive methods like Plaid.
6. **AI agent / Steward integration.** OpenLine Steward agents may want to present "I act on behalf of a verified human" — should we extend the VC to support delegation, and how does that interact with policies that demand a fresh anchor?
7. **On-chain anchoring.** Should issuers periodically commit a Merkle root of issued credentials to a blockchain for tamper evidence? Useful for high-stakes deployments; not required for v0.1.
8. **Method-level revocation.** Today the VC is revoked as a whole. Do we need to revoke individual methods (e.g. "your SMS was hijacked, drop just that signal") while keeping the anchor valid?
9. **Holder key rotation.** Can a holder rotate their key while keeping the same VC bound (key-binding via a holder-issued counter-signature)? Useful for long-lived credentials.
10. **Privacy of the issuer–holder link.** The issuer knows which `did:key` it issued each VC to; a strong privacy story would prevent the issuer from correlating user actions across integrators. BBS+ + blinded issuance is the eventual answer; v0.1 does not provide it.
