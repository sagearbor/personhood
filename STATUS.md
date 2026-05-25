# STATUS.md — Current State & Dev Checklist

> This file is the single source of truth for **what's done, what's stub, and what to work on next.** It changes often. Architecture and conventions live in `CLAUDE.md` (evergreen); the methods catalog lives in `docs/06-methods-catalog.md`. The last session wrapup with PR-by-PR detail is at `tmp/wrapups/` (gitignored).
>
> **For a new CC session in this repo:** read `CLAUDE.md`, then this file, then pick a task from the checklist below.

---

## Current state — last updated 2026-05-25

`main` has the full v0.1 backend in 6 merged PRs. All tests pass with `-race`. Repo is clean and pushable.

```bash
cd /Users/sophie.arborbot/PROJECTS/github_repos/personhood
git status                # clean main
go test ./...             # all modules green
gh repo view --web        # https://github.com/sagearbor/personhood
```

### What's implemented

| Module | Path | What works |
|---|---|---|
| Canonical types | `pkg/types/` | `PersonhoodCredential`, `Policy`, `MethodMetadata`, `EvaluationResult`, `NullifierBinding` + validation. JSON-LD context + JSON schemas in `pkg/proto/`. |
| Method registry | `src/registry/` | Thread-safe `Method` plugin registry; enforces anchor strength ≥50 / supplementary <50 at registration. |
| W3C VC issuer + verifier | `src/credential/` | Ed25519 over RFC 8785 (JCS) canonical JSON. `MapResolver` for DIDs in tests; `did:web` stub. W3C Status List 2021 fetcher. |
| Policy DSL | `src/policy/` | YAML + JSON parser; evaluator returns all 11 `EvaluationCode` outcomes. Refuses naive supplementary stacking when `anchor_required: true`. Pedersen-binding → nullifier (SHA-256 stub for v0.1). |
| Email method | `src/methods/email/` | Magic-link, 32-byte token, 15-min TTL, disposable-domain blocklist. `LogSender` for dev. |
| SMS method | `src/methods/sms/` | 6-digit OTP, 5-min TTL, 3-attempt lockout, constant-time compare, fictional-555/VOIP heuristic. `LogSender` for dev. |
| Design docs | `docs/` | 5 specs covering architecture, methods, credential format, policy DSL, OpenLine refactor. ~14k words. |
| Methods catalog | `docs/06-methods-catalog.md` | 3-agent brainstorm of ~40 additional methods with comparison table and prioritized roadmap. |

### What's stub

| Module | Path | What's needed | Effort |
|---|---|---|---|
| **REST issuer** | `src/server/` | Wire `pkg/types` + `src/registry` + `src/credential` + `src/policy` + the methods into HTTP endpoints (see `src/server/README.md` for sketch). httptest integration tests. | ~½ day, 200–400 LOC |
| **End-user web app** | `app/web/` | Next.js 14 App Router enrollment flow → email → SMS → credential viewer. Stores VC in IndexedDB. | ~1 day, 500–800 LOC |
| **Anchor method** | `src/methods/phone-liveness/` | Apple App Attest + Google Play Integrity server-side validators; stubbed client-side ceremony driver. | ~3–5 days |
| **Real delivery** | `src/methods/{email,sms}/` | `SendGridSender` + `TwilioSender` behind build tags. Currently only `LogSender`. | ~1 hour + free-tier signups |
| **Integrator SDKs** | `sdk/go/`, `sdk/typescript/` | Thin wrappers around `src/credential` + `src/policy` for external apps. | ~1 day each |
| **Mobile app** | `app/mobile/` | React Native shell. v0.2+, optional. | ~1–2 weeks incl. App/Play Store |

---

## Dev checklist — what to work on next (ordered)

Tackle in order. Each item is sized to be one PR. Copy any of the **bold prompts** into a fresh CC session in this repo.

### Sprint 1 — get to "open URL on phone and complete a ceremony"

- [ ] **1. Build the REST issuer (`src/server/`).**
  > *Build the `src/server/` reference REST issuer. Wire `pkg/types`, `src/registry`, `src/credential`, `src/policy`, `src/methods/email`, and `src/methods/sms` into the endpoints sketched in `src/server/README.md` (`POST /enrollment/start`, `POST /methods/{id}/begin`, `POST /methods/{id}/complete`, `POST /credentials/issue`, `GET /status-list/{listId}`, `GET /.well-known/did.json`). Use `net/http` + the `chi` router. Add httptest integration tests covering the full enrollment → issuance flow. Open a PR.*

- [ ] **2. Build the end-user web app (`app/web/`).**
  > *Build `app/web/` as a Next.js 14 App Router enrollment app that calls a Personhood server at `http://localhost:8080`. Use the `frontend-design` skill for distinctive styling. Three screens: email entry → SMS entry → issued-credential viewer with JSON pretty-print and "save to browser" (IndexedDB). Open a PR.*

- [ ] **3. Wire real email + SMS delivery.**
  > *In `src/methods/email/`, add a `SendGridSender` (env: `SENDGRID_API_KEY`, `SENDGRID_FROM`). In `src/methods/sms/`, add a `TwilioSender` (env: `TWILIO_ACCOUNT_SID`, `TWILIO_AUTH_TOKEN`, `TWILIO_FROM`). Each behind a build tag so the default `LogSender` keeps working in tests. Update `docs/02-methods.md` with the env-var matrix. Open a PR.*

- [ ] **4. Deploy server + web for phone testing.**
  - Server → Fly.io / Railway / Vercel Functions
  - Web → Vercel
  - Test from a phone browser

**After Sprint 1, you can open a URL on your phone, complete email + SMS, and see your W3C credential.** No anchor yet, so no real anti-Sybil claim is possible, but the full pipeline works.

### Sprint 2 — add real anchors (per `docs/06-methods-catalog.md` v0.2 plan)

- [ ] **5. Add `government-id-liveness` anchor.**
  > *Add `src/methods/government-id-liveness/` as the second anchor method. Wrap Persona's API (or Onfido as alternative). Strength 90. Register in `src/registry`. Update web app to offer this as an anchor option. Open a PR.*

- [ ] **6. Add `plaid-bank-link` anchor.**
  > *Add `src/methods/plaid-bank-link/` wrapping Plaid Identity Verification. Strength 88. Same shape as PR #5. Open a PR.*

- [ ] **7. Add `app-attest-device` + `ip-asn-reputation` + `captcha-turnstile` as a mandatory floor.**
  > *Build `src/methods/app-attest-device/`, `src/methods/ip-asn-reputation/`, `src/methods/captcha-turnstile/`. These are near-free supplementary signals (~$0.001 total) that the server should require on every ceremony. Update the default policy and server middleware. Open a PR.*

- [ ] **8. Upgrade existing `email` → `email-tier` and `sms` → `phone-carrier-tier`.**
  > *Per `docs/06-methods-catalog.md`, replace the strength-8 plain email with the strength-22 tiered variant (domain rep + breach-presence via HaveIBeenPwned). Replace strength-12 plain SMS with strength-28 tiered variant (line tenure + porting history via Twilio Lookup or Telesign). Open one PR per method.*

- [ ] **9. Add `paid-billing-card` supplementary (strongest single supplementary).**
  > *Build `src/methods/paid-billing-card/` wrapping Stripe SetupIntent with $0 pre-auth + 3DS/SCA. Strength 35. Open a PR.*

### Sprint 3 — airdrop-test compatibility (OpenLine UBI integration)

For OpenLine's one-person-one-vote and UBI claim use cases, anchors must work for users with no docs, no bank, no fixed address. Pick at least one:

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
