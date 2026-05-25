# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project Overview

Personhood is an open-source, pluggable proof-of-personhood framework. It issues W3C Verifiable Credentials produced by composable verification methods and evaluates them against integrator-declared policies. This repo is in early development — the v0.1 scaffold is in place; implementation lands in subsequent PRs.

The project is being extracted from [OpenLine](https://github.com/sagearbor/openline) (at `/Users/sophie.arborbot/PROJECTS/github_repos/openline/`), which originally needed proof-of-personhood for its one-person-one-vote governance.

## Architecture

Four logical layers, each its own Go module (or set of modules):

1. **Methods** (`src/methods/*`) — pluggable verification methods. v0.1 ships three:
   - **`phone-liveness`** (anchor) — Apple FaceID + App Attest / Android BiometricPrompt + Play Integrity. This is the only **anchor** method in v0.1; every valid credential must include at least one anchor method.
   - **`email`** (supplementary) — magic-link verification.
   - **`sms`** (supplementary) — one-time code verification.
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
