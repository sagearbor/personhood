# Personhood

**Personhood is an open-source, pluggable proof-of-personhood framework that lets any application verify "this is a unique human" without locking into a single identity provider, biometric vendor, or trust assumption.** It issues W3C Verifiable Credentials produced by composable verification methods, and lets integrators declare *policies* (e.g. "require one anchor method plus two supplementary signals") rather than hand-rolling fraud heuristics. The credentials are portable — users own them and can present them to any service that trusts the issuer.

## Why?

Most "proof-of-personhood" schemes in production today are either (a) a single vendor with a closed-source biometric DB, or (b) a naive weighted-sum stack ("email + SMS + CAPTCHA = human"). Both lose to bot farms. A modern sybil farm can pass email + SMS + a hosted IP at <$1/account; the stacking just increases their cost-per-account marginally, not categorically.

Personhood takes a different stance: **at least one method in any valid credential must be a high-entropy anchor** (something cryptographically hard to fake at scale — phone-camera liveness with device attestation in v0.1; later: in-person verification, government ID + liveness, well-known institution attestation). Supplementary methods (email, SMS, social-graph signals) add *recency* and *cross-context binding*, but never substitute for an anchor. Integrators choose their own policy — a comment site can accept anchor-only, a financial app can demand anchor + 2 supplementary + a recency check.

## What's in v0.1?

- **Three verification methods:**
  - **Phone-camera liveness + device attestation** (anchor) — Apple FaceID + App Attest / Android BiometricPrompt + Play Integrity
  - **Email magic link** (supplementary)
  - **SMS one-time code** (supplementary)
- **W3C Verifiable Credential issuance** — credentials are JSON-LD, signed with the issuer's Ed25519 key
- **Policy DSL** — declarative JSON policies that an integrator's verifier evaluates against a presented credential
- **Reference Go SDK** for verifiers, and a TypeScript SDK shell
- **Reference Next.js web app** for the end-user enrollment ceremony
- **Reference REST API server** that hosts the enrollment ceremonies and signs credentials

## Status

**Early development. Not production-ready.** This is the initial scaffold; implementation lands in subsequent PRs. The interfaces and policy DSL are still being shaped — expect breaking changes through v0.x.

We are explicitly *not* targeting:
- Government-ID-only verification (out of scope for v0.1, may add as an anchor method later)
- Reputation scoring or social-graph trust (different problem)
- On-chain identity registries (consumers can build this on top)

## Quick start

Coming soon. Once the reference server runs locally, the quick start will be a single `docker compose up` plus a snippet for the Go and TS SDKs showing `personhood.Verify(vc, policy)`.

## Architecture

Personhood is split into a registry of pluggable methods, a credential issuer/verifier, a policy evaluator, and a reference server that exposes enrollment over HTTP. Each method is its own Go module behind a small interface, so adding a new method (e.g. in-person verification, government ID + liveness) is a matter of writing a new module and registering it — no changes to the core. See [ARCHITECTURE.md](ARCHITECTURE.md).

## How to contribute

We welcome issues, design feedback, and PRs. See [CONTRIBUTING.md](CONTRIBUTING.md) for branch naming, PR process, and code style. Security disclosures go through [SECURITY.md](SECURITY.md).

## License

Apache 2.0. See [LICENSE](LICENSE).

## Related projects

- **[OpenLine](https://github.com/sagearbor/openline)** — the protocol that originally needed this library. OpenLine is a payments + voting + UBI protocol where every governance vote is one-person-one-vote, so it needs strong proof-of-personhood. Personhood was extracted from OpenLine's `src/suffrage/` work so it could be used by any project, not just OpenLine.
