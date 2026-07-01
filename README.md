# Personhood

**Pluggable proof-of-personhood: let any app verify "this is a unique human" using portable W3C Verifiable Credentials and a declarative policy — without a single biometric vendor, a central identity database, or a naive "email + SMS = human" score.**

Personhood issues credentials built from composable verification *methods*, and lets each integrator declare a *policy* (e.g. "require one strong anchor method plus a floor of supplementary signals, and re-verify the anchor every 90 days") instead of hand-rolling fraud heuristics. Credentials are user-held and portable: a person verifies once and can present the same credential to any service that trusts the issuer.

> ### ⚠️ Status — early / in development
>
> **This is a v0.1 research prototype. It is NOT production-ready and has NOT been security-audited.** The core library runs end to end (issue → sign → verify → policy-evaluate) with tests across every module, and there is a runnable reference server and web app. But several parts are deliberate stubs, the interfaces and policy DSL will still change, and the privacy/anti-Sybil guarantees below are **design intent, not proven properties**. Expect breaking changes through v0.x. Do not rely on it to gate anything real yet.
>
> Known stubs today (see [`STATUS.md`](STATUS.md) for the live list):
> - The nullifier is a **SHA-256 stand-in**, not the real Pedersen-commitment / zero-knowledge scheme.
> - The App Attest anchor ships a **dev HMAC verifier**; real Apple/Google attestation validation is v0.2.
> - Holder DIDs are a **hash placeholder** (`did:personhood:holder:<sha256>`), and the revocation status list is **published unsigned**.
> - All server/method stores are **in-memory** (no horizontal scaling yet).

## Why this matters

"Prove you're a real, unique person" is becoming load-bearing infrastructure — for one-person-one-vote governance, Sybil-resistant airdrops and UBI, and keeping bot farms out of public discourse. The two dominant answers today are both unsatisfying:

1. **A single closed vendor** with a proprietary biometric database — you must trust one company with everyone's face, and you're locked into its availability, pricing, and jurisdiction.
2. **A naive weighted-sum stack** — "email + SMS + CAPTCHA + an IP check ≥ threshold ⇒ human." A modern Sybil farm passes all of those for well under a dollar per account; stacking more cheap signals only raises the attacker's cost *marginally*, never *categorically*.

Personhood aims for a third path: **proof-of-personhood without mass surveillance or vendor lock-in.** Verification methods are pluggable modules; integrators pick their own trust bar; users hold portable credentials; and — critically — the design refuses to let a pile of weak signals substitute for genuine uniqueness evidence.

## Design — anchors, supplementary signals, and why it isn't a weighted sum

Every verification method declares metadata ([`pkg/types.MethodMetadata`](pkg/types/types.go)) including a `type` and an integer `strength` (0–100). The `type` is the heart of the design:

- **Anchor** methods (`strength >= 50`) carry the *one-human* guarantee — evidence that is hard to forge at scale. Shipped anchors: **government-ID + selfie liveness** (via Persona, strength 90) and **bank-account link** (via Plaid, strength 88). A phone-attestation anchor is scaffolded.
- **Supplementary** methods (`strength < 50`) add *recency* and *cross-context binding* but are individually cheap to farm. Shipped supplementary methods: **email magic-link**, **SMS OTP**, **device attestation** (18), **IP/ASN reputation** (10), and **CAPTCHA / Cloudflare Turnstile** (4).

The split is a **hard structural invariant, not a tunable weight.** The type/strength boundary is enforced at registration time — [`MethodMetadata.Validate`](pkg/types/validation.go) rejects any anchor with `strength < 50` or any supplementary with `strength >= 50`, so no method can straddle the line and no misconfiguration can quietly promote a weak signal into an anchor.

Because of that invariant, the policy evaluator ([`src/policy/evaluate.go`](src/policy/evaluate.go)) treats an anchor requirement and a supplementary floor as **two independent conditions that are AND-ed together**, never a single additive score:

- `anchor_required: true` is a **presence check** — the credential must contain at least one method flagged as an anchor. No quantity of supplementary points can satisfy it.
- `min_supplementary_points` sums `strength` **only across supplementary methods** (those below the ceiling), and only those still within their freshness window. **Anchor strength never counts toward the supplementary total**, and supplementary points never count toward the anchor requirement.

That is exactly what a naive weighted sum gets wrong. Under a single-threshold score, enough sub-dollar signals (email + SMS + CAPTCHA + …) eventually clear the same bar an anchor would — so a bot farm just buys more cheap signals. Here the anchor is a **categorical gate**: you cannot buy your way past it with volume, because supplementary points and anchor presence live in separate, non-fungible buckets. Stacking supplementary signals only ever tunes *recency and binding*, never *uniqueness*.

The default recommended policy, [`docs/policies/default-floor.yaml`](docs/policies/default-floor.yaml), encodes this: `anchor_required: true` **plus** a 32-point supplementary floor (device-attest 18 + IP/ASN 10 + Turnstile 4, ~$0.001 total) that kills emulator farms and datacenter signups **without ever substituting for the anchor**. A comment site might accept anchor-only; a financial action might demand anchor + supplementary floor + a fresh-anchor re-proof.

Two more properties fall out of the same model:

- **Frozen strengths + independent freshness.** Each method's `strength` and `freshness_lifetime` are frozen onto the credential at issuance ([`VerifiedMethod`](pkg/types/types.go)), so recalibrating a live method never retroactively changes what an old credential means, and a policy can demand a *fresh anchor* (e.g. re-verified within 24h) even when the credential as a whole is still valid for a year.
- **Unlinkable one-action-per-human.** A credential can carry an optional `nullifierBinding`; a policy with `nullifier_required` derives a per-context nullifier (scoped by a context tag like `vote:2026:proposal-42`) so a holder can prove "I haven't already voted/claimed here" without linking their actions across contexts. *(v0.1 derives this with a SHA-256 stand-in — the real Pedersen/ZK scheme is future work.)*

## How it works

The system is a small set of independent Go modules (a `go.work` workspace) plus reference apps:

| Layer | Path | Role |
|---|---|---|
| Canonical types | [`pkg/types`](pkg/types/) | Credential, Policy, MethodMetadata, EvaluationResult — stdlib-only, shared by everything. |
| Method registry | [`src/registry`](src/registry/) | Thread-safe plugin catalog. Each method implements one `Method` interface (metadata, availability, begin/complete ceremony, health). Anchor/supplementary strength invariant enforced at `Register`. |
| Credential | [`src/credential`](src/credential/) | W3C VC issue/verify. Ed25519 over RFC 8785 (JCS) canonical JSON; W3C Status List 2021 revocation. |
| Policy engine | [`src/policy`](src/policy/) | Pure (no-I/O) evaluator; parses YAML/JSON policies; returns the full outcome-code space; derives nullifiers. |
| Methods | [`src/methods/*`](src/methods/) | One Go module per method: `government-id-liveness`, `plaid-bank-link`, `email`, `sms`, `app-attest-device`, `ip-asn-reputation`, `captcha-turnstile`, plus a `phone-liveness` stub. |
| Issuer server | [`src/server`](src/server/) | Chi-based REST API that drives enrollment ceremonies and signs credentials. |
| Integrator SDKs | [`sdk/go`](sdk/go/), [`sdk/typescript`](sdk/typescript/) | Drop-in verifiers; cross-language interop proven against a shared fixture. |
| End-user app | [`app/web`](app/web/) | Next.js PWA for the enrollment ceremony (email → SMS → ID/selfie → credential). |

**Enrollment (issuer side):** a client calls `POST /enrollment/start`, runs each method's begin/complete ceremony, then `POST /v1/credentials/issue` to receive a signed `PersonhoodCredential`. See [`src/server/README.md`](src/server/README.md) for the full endpoint list and request flow.

**Verification (integrator side)** is one call — signature + revocation + policy in a single `Result`:

```go
import (
    "crypto/ed25519"
    personhood "github.com/sagearbor/personhood/sdk/go"
    "github.com/sagearbor/personhood/pkg/types"
)

// 1. Declare which issuers you trust (DID -> Ed25519 public key).
v := personhood.NewVerifier(personhood.TrustedIssuers(map[types.DID]ed25519.PublicKey{
    "did:web:issuer.example": issuerPub,
}))

// 2. Verify a presented credential against your policy.
res, err := v.Verify(ctx, cred, policy)
if err != nil {
    // transport/internal failure (e.g. revocation-list fetch) — fail closed.
}
if !res.OK {
    // res.Code / res.Human / res.Details say what the user must fix.
}
nullifier := res.Nullifier // non-empty iff policy.nullifier_required
```

`Verify` returns an **error** only for failures you can't attribute to the credential (so you can fail closed); an invalid, revoked, or non-compliant credential comes back as `Result{OK:false, Code: ...}` with an end-user-safe `Human` message. The TypeScript SDK mirrors this surface with zero runtime dependencies.

## Quickstart

Requires Go 1.22+ (workspace via `go.work`). Node 18+ only if you want the web app.

```bash
git clone https://github.com/sagearbor/personhood.git
cd personhood

# Run the module test suites (each module is its own go.mod).
go test ./...                       # from within pkg/types, src/policy, sdk/go, etc.
go test -race ./src/server/...      # server integration tests (full ceremony flow)

# Run the reference issuer locally.
go run ./src/server/cmd/gen-key                    # prints an Ed25519 issuer key
export ISSUER_ED25519_SK_B64=...                   # paste the value from gen-key
export SERVER_PUBLIC_URL="http://localhost:8080"
go run ./src/server/cmd/server                     # serves on :8080

# In the default build, email magic-links and SMS OTPs are printed to stdout
# (LogSender). Real delivery is behind build tags: -tags sendgrid / -tags twilio.

# (optional) Run the end-user PWA against the local server.
cd app/web && npm install && npm run dev           # http://localhost:3000
```

A longer clean-machine-to-verified-on-phone walkthrough (vendor signups, deploy config, on-phone enrollment) lives in [`RUNBOOK.md`](RUNBOOK.md).

## What's in v0.1

- Anchors: **government-ID + selfie liveness** (Persona), **bank-account link** (Plaid); phone-attestation anchor scaffolded.
- Supplementary: **email magic-link**, **SMS OTP**, **device attestation**, **IP/ASN reputation**, **CAPTCHA (Turnstile)**.
- **W3C Verifiable Credentials** — JSON-LD, Ed25519 over RFC 8785 (JCS), Status List 2021 revocation.
- **Declarative policy DSL** (YAML/JSON) with an anchor gate, supplementary floor, per-method allow/block/strength, credential + anchor freshness, and optional nullifier binding.
- **Go + TypeScript integrator SDKs** (interop-tested), a **reference REST issuer**, and a **reference Next.js PWA**.

We are explicitly **not** building: reputation/social-graph trust scoring, on-chain identity registries, or a proprietary biometric database. Those can be layered on top by consumers.

## Contributing

Issues, design feedback, and PRs welcome — see [CONTRIBUTING.md](CONTRIBUTING.md) for branch naming, PR process, and style. Report security issues privately per [SECURITY.md](SECURITY.md) (and note the audit status above). The live task list and per-module state are in [STATUS.md](STATUS.md).

## Related projects

- **[OpenLine](https://github.com/sagearbor/openline)** — the sibling civic-tech protocol (anonymous payments + one-person-one-vote governance + UBI) that motivated this library. Personhood was extracted from OpenLine's suffrage work so *any* project needing Sybil-resistant, privacy-preserving personhood can use it — the nullifier machinery exists precisely so a person can vote once or claim UBI once without their actions being linkable across contexts.

## License

Apache 2.0. See [LICENSE](LICENSE).
