# STATUS.md — Current State & Dev Checklist

> This file is the single source of truth for **what's done, what's stub, and what to work on next.** It changes often. Architecture and conventions live in `CLAUDE.md` (evergreen); the methods catalog lives in `docs/06-methods-catalog.md`. The last session wrapup with PR-by-PR detail is at `tmp/wrapups/` (gitignored).
>
> **For a new CC session in this repo:** read `CLAUDE.md`, then this file, then pick a task from the checklist below.

---

## Current state — last updated 2026-05-25 (post-deployment-sprint)

`main` is **about to merge a 7-PR stack** that takes Personhood from a backend-only library to an end-to-end deployable system you can install on an Android phone today. PRs #7–#12 (see `gh pr list`) are stacked on top of one another and not yet merged — reviewers should walk the stack in order. All tests pass with `-race` in every build configuration.

```bash
cd /Users/sophie.arborbot/PROJECTS/github_repos/personhood
gh pr list                # 7 open: feat/server -> feat/government-id-liveness -> feat/real-delivery
                          # -> feat/web-pwa -> feat/deploy-config -> feat/runbook -> feat/status-update
go test ./...             # all modules green in default + sendgrid + twilio builds
cd app/web && npm run build  # 100 kB First Load JS
```

### What's implemented

| Module | Path | What works |
|---|---|---|
| Canonical types | `pkg/types/` | `PersonhoodCredential`, `Policy`, `MethodMetadata`, `EvaluationResult`, `NullifierBinding` + validation. JSON-LD context + JSON schemas in `pkg/proto/`. |
| Method registry | `src/registry/` | Thread-safe `Method` plugin registry; enforces anchor strength ≥50 / supplementary <50 at registration. |
| W3C VC issuer + verifier | `src/credential/` | Ed25519 over RFC 8785 (JCS) canonical JSON. `MapResolver` for DIDs in tests; `did:web` stub. W3C Status List 2021 fetcher. |
| Policy DSL | `src/policy/` | YAML + JSON parser; evaluator returns all 11 `EvaluationCode` outcomes. Refuses naive supplementary stacking when `anchor_required: true`. Pedersen-binding → nullifier (SHA-256 stub for v0.1). |
| Email method | `src/methods/email/` | Magic-link, 32-byte token, 15-min TTL, disposable-domain blocklist. `LogSender` default; **SendGridSender** behind `-tags sendgrid` (PR #9). |
| SMS method | `src/methods/sms/` | 6-digit OTP, 5-min TTL, 3-attempt lockout, constant-time compare, fictional-555/VOIP heuristic. `LogSender` default; **TwilioSender** behind `-tags twilio` (PR #9). |
| **Government-ID + selfie anchor** | `src/methods/government-id-liveness/` | **Persona** hosted-flow wrapper (PR #8). Strength 90, anchor. HMAC-validated webhook handler, in-memory result store, status mapping (approved/declined/needs_review/expired). |
| **REST issuer** | `src/server/` | **Chi-based HTTP server (PR #7)**. `/enrollment/start`, `/v1/methods/{id}/begin` and `/complete`, `/v1/methods/email/verify` (magic-link landing), `/v1/credentials/issue`, `/v1/status-list/{id}`, `/.well-known/did.json`, `/healthz`. CORS allowlist + recover + request-log middleware. In-memory `SessionStore`. `BuildDependencies()` auto-registers gov-id when PERSONA_* env present. cmd/gen-key utility for issuer seed. 8 httptest integration tests pass with `-race`. |
| **End-user PWA** | `app/web/` | **Next.js 14 App Router PWA (PR #10)**. Four screens (email → SMS → ID/selfie → credential). PWA manifest + service worker + apple-touch-icon → Add-to-Home-Screen installs a real app icon on Android + iOS. IndexedDB-backed credential vault with optional WebAuthn biometric gating. "Trusted terminal" aesthetic: JetBrains Mono + Plus Jakarta Sans, electric-lime accent on near-black. 100 kB First Load JS. |
| **Deploy infrastructure** | `Dockerfile`, `fly.toml`, `.dockerignore`, `app/web/vercel.json`, `.github/workflows/build.yml` | **PR #11**. Multi-stage Dockerfile (golang:1.22 → distroless/static-debian12:nonroot, built with sendgrid+twilio tags). Fly.io app config with /healthz, force_https, auto_stop_machines. vercel.json with security headers + camera permissions policy scoped to Persona. CI runs all 4 build configurations + production binary + Next build + Docker image. |
| **RUNBOOK** | `RUNBOOK.md` | **PR #12**. Clean-machine → verified-on-phone in 45-75 minutes wall clock, ~20 minutes hands-on. Twelve sections covering prereqs, vendor signups (Persona / SendGrid / Twilio / Fly / Vercel), local dev, real-delivery local test, server deploy, web deploy, Persona webhook registration, Add-to-Home-Screen install, on-phone enrollment, troubleshooting (10-row table), cost expectations. |
| Design docs | `docs/` | 5 specs covering architecture, methods, credential format, policy DSL, OpenLine refactor. ~14k words. `docs/02-methods.md` now includes a delivery env-var matrix per vendor + a build-tag matrix. |
| Methods catalog | `docs/06-methods-catalog.md` | 3-agent brainstorm of ~40 additional methods with comparison table and prioritized roadmap. |

### What's stub

| Module | Path | What's needed | Effort |
|---|---|---|---|
| **Anchor method (App Attest)** | `src/methods/phone-liveness/` | Apple App Attest + Google Play Integrity server-side validators; client-side ceremony driver. Was the original v0.1 anchor; superseded for the demo by `government-id-liveness`. Useful for a future native shell that can attest in-app. | ~3–5 days |
| **Integrator SDKs** | `sdk/go/`, `sdk/typescript/` | Thin wrappers around `src/credential` + `src/policy` for external apps to verify presented credentials. | ~1 day each |
| **Mobile app (Capacitor wrap)** | `app/mobile/` | Sprint 3 — see below. Wrap `app/web` in Capacitor; ship to Play Store internal track. | ~3–5 days incl. store paperwork |
| **Signed status list** | `src/credential/` + `src/server/` | The `/v1/status-list/{id}` endpoint currently returns an unsigned placeholder. v0.2 will sign it like a normal credential. | ~½ day |
| **did:key holder DIDs** | `src/server/did.go` | Currently emits `did:personhood:holder:<sha256>` to avoid a base58 dep. v0.2 web app generates a WebCrypto Ed25519 keypair and provides the public key in `/enrollment/start`. | ~1 day |
| **Redis-backed stores** | `src/server/session.go`, `src/methods/{email,sms,government-id-liveness}/store.go` | All four stores are in-memory; horizontal scaling needs a shared backend. | ~½ day |

---

## Dev checklist — what to work on next (ordered)

Tackle in order. Each item is sized to be one PR. Copy any of the **bold prompts** into a fresh CC session in this repo.

### Sprint 1 — get to "open URL on phone and complete a ceremony"

- [x] **1. Build the REST issuer (`src/server/`).** ✅ PR #7 (`feat/server`)
  > Chi router, 8 endpoints, 8 httptest integration tests covering full enrollment → issuance with signature verification through `credential.MapResolver`. `cmd/gen-key` utility. CORS + recover + request-log middleware.

- [x] **2. Build the end-user web app (`app/web/`).** ✅ PR #10 (`feat/web-pwa`)
  > Next.js 14 App Router PWA, 4 screens (email → SMS → ID/selfie → credential), PWA manifest + SW + apple-touch-icon, IndexedDB-backed credential vault with optional WebAuthn biometric gate. "Trusted terminal" aesthetic. 100 kB First Load JS.

- [x] **3. Wire real email + SMS delivery.** ✅ PR #9 (`feat/real-delivery`)
  > `SendGridSender` (`-tags sendgrid`) + `TwilioSender` (`-tags twilio`) with disabled twins so the default build still uses `LogSender`. `email.NewSenderFromEnv()` + `sms.NewSenderFromEnv()` dispatch on build tag AND env vars. Build-matrix tests across 4 configurations.

- [x] **4. Deploy server + web for phone testing.** ✅ PR #11 (`feat/deploy-config`) + PR #12 (`feat/runbook`)
  > `Dockerfile` (multi-stage, distroless/nonroot), `fly.toml`, `app/web/vercel.json`, CI workflow. `RUNBOOK.md` walks clean-machine → verified-on-phone in ~20 minutes hands-on.

**Sprint 1 outcome:** you can open `https://<your-app>.vercel.app` on your Android phone, Add to Home Screen, complete email + SMS + government-ID-selfie, and see your signed W3C credential. The credential satisfies `anchor_required: true` policies because the gov-id anchor is fully wired.

### Sprint 2 — add real anchors (per `docs/06-methods-catalog.md` v0.2 plan)

- [x] **5. Add `government-id-liveness` anchor.** ✅ PR #8 (`feat/government-id-liveness`)
  > `src/methods/government-id-liveness/` wraps Persona's hosted Inquiries API. Strength 90, anchor. HMAC-validated webhook, in-memory result store, status mapping (approved/declined/needs_review/expired), 11 tests covering signature verification + status mapping + full flow.

- [ ] **6. Add `plaid-bank-link` anchor.**
  > *Add `src/methods/plaid-bank-link/` wrapping Plaid Identity Verification. Strength 88. Same shape as PR #5. Open a PR.*

- [ ] **7. Add `app-attest-device` + `ip-asn-reputation` + `captcha-turnstile` as a mandatory floor.**
  > *Build `src/methods/app-attest-device/`, `src/methods/ip-asn-reputation/`, `src/methods/captcha-turnstile/`. These are near-free supplementary signals (~$0.001 total) that the server should require on every ceremony. Update the default policy and server middleware. Open a PR.*

- [ ] **8. Upgrade existing `email` → `email-tier` and `sms` → `phone-carrier-tier`.**
  > *Per `docs/06-methods-catalog.md`, replace the strength-8 plain email with the strength-22 tiered variant (domain rep + breach-presence via HaveIBeenPwned). Replace strength-12 plain SMS with strength-28 tiered variant (line tenure + porting history via Twilio Lookup or Telesign). Open one PR per method.*

- [ ] **9. Add `paid-billing-card` supplementary (strongest single supplementary).**
  > *Build `src/methods/paid-billing-card/` wrapping Stripe SetupIntent with $0 pre-auth + 3DS/SCA. Strength 35. Open a PR.*

### Sprint 3 — mobile: Capacitor wrap → Play Store internal test

Once the PWA is live on a real domain (Sprint 1 outcome above), Sprint 3 ships it through the Play Store. The web app does the heavy lifting; Capacitor is just a native shell that loads it and adds the device APIs PWAs can't reach (FCM push, App Attest / Play Integrity).

- [ ] **3a. Scaffold Capacitor under `app/mobile/`.**
  > *Initialise a Capacitor 6 project that loads `https://<your-web>.vercel.app` (the live PWA). Configure for both Android and iOS. Wire `capacitor.config.ts` with `server.url` so OTA updates of the web app reach the wrapped app without a store roll. Open a PR.*

- [ ] **3b. Wire Google Play Integrity + Apple App Attest as a second anchor.**
  > *Inside the Capacitor wrapper, call Play Integrity on launch and post the attestation token to `src/methods/phone-liveness/` (the existing stub). On iOS, do the same with App Attest. This re-enables the original v0.1 anchor — useful for issuers that want one-Sybil-defeating signal without ID upload. Open a PR.*

- [ ] **3c. Build Android release + upload to Play Console internal track.**
  > *Generate a signed AAB with `npx cap build android --release`. Create the Play Console app, fill in the privacy questionnaire (we collect: email, phone, ID document via Persona; we do NOT collect: location, contacts, biometrics on-device, persistent identifier). Submit to internal track for invite-only testing. Document the keystore password storage convention in `app/mobile/RELEASE.md`. Open a PR.*

- [ ] **3d. (optional) iOS TestFlight build.**
  > *Same as 3c but iOS. Requires a paid Apple Developer account ($99/year). Lower priority for the initial demo; the Android Play Console internal track is invite-only and free.*

**Sprint 3 outcome:** the Personhood app installs from the Play Store onto your phone via the Internal Test program. You can hand a friend an invite link and they get a real app, not a PWA shortcut. Same backend, same UX, same credential format — but the wrapped shell gives you per-device App Attest / Play Integrity attestation as a strong-anchor signal that does not require uploading a government ID.

### Sprint 4 — airdrop-test compatibility (OpenLine UBI integration)

For OpenLine's one-person-one-vote and UBI claim use cases, anchors must work for users with no docs, no bank, no fixed address. Pick at least one (numbering preserved from the original Sprint 3 below; these are independent of the new mobile sprint above):

- [ ] **10a. Promote OpenLine's `fuzzy-extractor` prototype to a Personhood anchor.**
  > *The Rust crate at `openline/src/suffrage/fuzzy-extractor/` is the airdrop-test-compliant anchor (no central biometric DB, on-device key derivation). Wrap it as `src/methods/fuzzy-extractor-selfie/`, add server-side accumulator membership check, integrate with the credential `nullifierBinding`. Open a PR.*

- [ ] **10b. Add `social-vouching-graph` anchor (BrightID model).**
  > *Build `src/methods/social-vouching/`. Members vouch for new members in connection ceremonies; SybilRank-style graph analysis scores the candidate. Open a PR.*

- [ ] **10c. Add `proof-of-address-document-ocr` supplementary (the Android dev console pattern).**
  > *Build `src/methods/document-address-match/`. User uploads utility bill / bank statement / lease showing claimed address. OCR + template tampering detection. Optional human-review queue. Open a PR.*

### Backlog — v0.4+ specialty methods

See `docs/06-methods-catalog.md` for the full ~40-method catalog with recommendations:
- `background-check` for gig-economy
- `live-video-review` for highest-trust regulated finance
- `eidas-national-eid` for EU/Nordic deployments
- `sim-possession-carrier-attestation` where carrier APIs exist
- `stamp-stacking-aggregator` for Gitcoin Passport interop
- `encointer-pseudonym-ceremony` for community-driven rollout

---

## OpenLine integration — when Personhood is ready to be consumed

Once Sprint 1 ships, OpenLine (sibling repo at `/Users/sophie.arborbot/PROJECTS/github_repos/openline/`) can start refactoring `src/suffrage/` and `src/commons/` to verify Personhood credentials. The detailed plan is at `docs/05-openline-refactor.md` — broadly:

1. OpenLine adds Go dependency on `github.com/sagearbor/personhood/sdk/go` (need SDK first — see backlog).
2. Suffrage vote-eligibility check refactors to: `personhood.Verify(vc, vote_policy)`.
3. Commons UBI claim refactors to: `personhood.Verify(vc, ubi_policy)` + nullifier check.
4. Move `openline/src/suffrage/accumulator/` → `personhood/` (identity-set-membership infra).
5. Voting-specific Circom circuits stay in OpenLine.

---

## When this file goes stale

If you finish a checklist item, **check the box and update the "What's implemented" / "What's stub" tables.** If you start a new sprint, add the new items below. If the recommendations in `docs/06-methods-catalog.md` change, update the dev-checklist roadmap to match. The wrapup HTML in `tmp/wrapups/` is a session snapshot — useful history but not the canonical state. STATUS.md is the canonical state.
