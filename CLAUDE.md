# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project Overview

Personhood is an open-source, pluggable proof-of-personhood framework. It issues W3C Verifiable Credentials produced by composable verification methods and evaluates them against integrator-declared policies.

The project was extracted from [OpenLine](https://github.com/sagearbor/openline) (at `/Users/sophie.arborbot/PROJECTS/github_repos/openline/`), which originally needed proof-of-personhood for its one-person-one-vote governance.

## Current Status (2026-05-25)

**Backend primitives are complete.** Six merged PRs cover the full Go-side core:

| Module | Status | Lines | Tests |
|---|---|---|---|
| `pkg/types` | ✅ implemented | 1,287 | 24 |
| `src/registry` | ✅ implemented (thread-safe, race-clean) | 538 | 10 |
| `src/credential` | ✅ implemented (Ed25519 + RFC 8785 JCS + Status List 2021) | 1,412 | 33 |
| `src/policy` | ✅ implemented (YAML/JSON DSL + evaluator + nullifier stub) | ~1,200 | ~20 |
| `src/methods/email` | ✅ implemented (magic-link, disposable blocklist) | ~700 | ~10 |
| `src/methods/sms` | ✅ implemented (6-digit OTP, lockout, VOIP heuristic) | ~700 | ~14 |
| `docs/` | ✅ 5 design specs (~14k words) | 1,436 | — |

**Stubs still needing implementation:**

| Module | Why it's blocking | Approx effort |
|---|---|---|
| `src/server` | No REST API yet — ceremonies have no HTTP wiring | ~½ day (200–400 LOC) |
| `app/web` | No end-user app — phone testing impossible without it | ~1 day (500–800 LOC, Next.js) |
| `src/methods/phone-liveness` | The anchor — no high-stakes use until built | ~3–5 days (FaceID + App Attest + native bridges) |
| `sdk/go`, `sdk/typescript` | Integrator-facing thin wrappers; can be built after server | ~1 day each |
| `app/mobile` | React Native installable; deferred to v0.2 | ~1–2 weeks |
| Real `Sender` implementations | Currently `LogSender` only. Need Twilio + SendGrid wrappers | ~1 hour + free-tier signups |

**Suggested next prompts** (paste into a fresh CC session in this repo):

- *"Build the `src/server/` reference REST issuer. Wire together `pkg/types`, `src/registry`, `src/credential`, `src/policy`, and the email + SMS methods into the endpoints sketched in `src/server/README.md`. Use net/http + chi router. Add httptest integration tests. Open a PR."*
- *"Build `app/web/` as a Next.js 14 App Router enrollment app that calls a local Personhood server at http://localhost:8080. Use the `frontend-design` skill for distinctive styling. Three screens: email entry → SMS entry → credential issued with JSON viewer. Open a PR."*
- *"Wire real email + SMS delivery: write a `SendGridSender` in `src/methods/email/` and a `TwilioSender` in `src/methods/sms/`, each behind a build tag. Document required env vars."*

The full v0.1 design plan lives at `/Users/sophie.arborbot/.claude/plans/eventual-swinging-stearns.md`. The most recent session wrapup is at `tmp/wrapups/` (gitignored).

## Architecture

Four logical layers, each its own Go module (or set of modules):

1. **Methods** (`src/methods/*`) — pluggable verification methods. v0.1 ships three:
   - **`phone-liveness`** (anchor, **stub**) — Apple FaceID + App Attest / Android BiometricPrompt + Play Integrity. This is the only **anchor** method in v0.1; every valid credential must include at least one anchor method.
   - **`email`** (supplementary, ✅ implemented) — magic-link verification.
   - **`sms`** (supplementary, ✅ implemented) — one-time code verification.
2. **Registry** (`src/registry`) — methods register themselves at startup; the issuer queries this to discover what's available.
3. **Credential** (`src/credential`) — W3C Verifiable Credential issuer + verifier. Signs with Ed25519.
4. **Policy** (`src/policy`) — declarative JSON DSL that integrators use to express verification requirements (e.g. "anchor required + 2 supplementary points + verified within last 90 days"). The evaluator checks a presented credential against a policy and returns pass/fail with reasons.

The reference **server** (`src/server`) exposes enrollment ceremonies and credential issuance over REST. The reference **web app** (`app/web`) is a Next.js end-user app that drives a user through the enrollment ceremony. **SDKs** (`sdk/go`, `sdk/typescript`) are for *integrators* — services that want to accept Personhood credentials.

## Core Design Constraint: Anchor + Supplementary

Personhood explicitly rejects naive weighted-sum stacking (email + SMS + CAPTCHA = "human"). Bot farms defeat that. Instead: **every valid credential must include at least one anchor method** — a method that is cryptographically hard to fake at scale. Supplementary methods add recency and cross-context binding but never substitute for an anchor. In v0.1 the only anchor is phone-camera liveness + device attestation; later anchors may include in-person verification, government ID + liveness, or institutional attestation.

## Repository Structure

```
README.md                            — Project overview
CLAUDE.md                            — This file
ARCHITECTURE.md                      — Pointer to docs/01-architecture.md
CONTRIBUTING.md                      — Contribution guide
SECURITY.md                          — Vulnerability disclosure
LICENSE                              — Apache 2.0
go.work                              — Go workspace tying all modules together
pkg/types/                           — Shared Go types: PersonhoodCredential, MethodMetadata, Policy, EvaluationResult, NullifierBinding
pkg/proto/                           — JSON-LD context, credential JSON schema, Policy DSL JSON schema
src/registry/                        — Method plugin registry (see src/registry/INTERFACE.md)
src/credential/                      — W3C VC issuer + verifier (Ed25519)
src/policy/                          — Policy DSL parser + evaluator
src/methods/INTERFACE.md             — Method plugin contract
src/methods/phone-liveness/          — Anchor: phone-camera liveness + device attestation
src/methods/email/                   — Supplementary: email magic link
src/methods/sms/                     — Supplementary: SMS OTP
src/server/                          — Reference REST API issuer
sdk/go/                              — Go SDK for integrators
sdk/typescript/                      — TypeScript SDK for integrators
app/web/                             — Next.js end-user enrollment app (v0.1)
app/mobile/                          — React Native end-user app (v0.2, deferred)
docs/                                — Design specifications
tests/                               — End-to-end tests
```

All Go modules use the `github.com/sagearbor/personhood/` module path prefix. All Go modules target Go `1.22.0`. The npm scope for TS packages is `@personhood/` (to be reserved).

## Working in This Repo

- When adding or changing cross-module types, update `pkg/types/types.go` first, then `pkg/proto/` JSON schemas, then propagate to module-local code.
- New verification methods are added as new Go modules under `src/methods/<name>/`, registered in `go.work`, and exposed through the `Method` interface described in `src/methods/INTERFACE.md`.
- Don't add a method without an explicit declaration of whether it is an **anchor** or **supplementary** method. The registry's `MethodMetadata.Type` field is load-bearing for policy evaluation.
- The full v0.1 design plan lives at `/Users/sophie.arborbot/.claude/plans/eventual-swinging-stearns.md` — read it before making non-trivial design changes.
