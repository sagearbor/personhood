# STATUS.md — Current State & Dev Checklist

> This file is the single source of truth for **what's done, what's stub, and what to work on next.** It changes often. Architecture and conventions live in `CLAUDE.md` (evergreen); the methods catalog lives in `docs/06-methods-catalog.md`. The last session wrapup with PR-by-PR detail is at `tmp/wrapups/` (gitignored).
>
> **For a new CC session in this repo:** read `CLAUDE.md`, then this file, then pick a task from the checklist below.

---

## Round-6 session summary (2026-09-11, overnight)

**The first real deploy is live.** Personhood now runs on Google Cloud
instead of nothing:

- Web app: <https://personhood-web.web.app> (Firebase Hosting, static Next.js export)
- Issuer: <https://personhood-issuer-664594784582.us-central1.run.app> (Cloud Run, source build)

Shipped in three PRs: #41 (Cloud Run source-build compatibility — removed
Dockerfile cache mounts, since Cloud Build's legacy docker builder doesn't
support BuildKit), #42 (`.gcloudignore` for the source-build upload context,
plus a `GET /health` alias for `/healthz` — Cloud Run's frontend intercepts
`GET /healthz` on `*.run.app` and 404s before the container ever sees it),
and #43 (invite-code gate + `GET /v1/config`, on-screen magic link in test
mode, static export + Firebase Hosting config). The issuer signing key lives
only in Secret Manager (`personhood-issuer-key`) — never in a file, never in
git. `max-instances=1` is load-bearing, not a cost knob: sessions and
challenge tokens are in-memory with no Redis wired up for this deployment, so
two concurrent instances would silently drop each other's sessions.

**Test mode is on**, same shape as round-1's Fly path but with two additions
this session: an `ENROLLMENT_INVITE_CODE` gate (there's no mail credential
configured, so `DEV_EXPOSE_CHALLENGE_SECRETS=1` shows the magic link on
screen instead of emailing it — without an invite gate that would let anyone
enroll any email address as themselves) and `GET /v1/config` so the web app
can discover both facts before showing the enrollment UI. This is
appropriate for 5 trusted friends and nothing more; turning it off (real
SMTP + drop `DEV_EXPOSE_CHALLENGE_SECRETS`) is Sprint 1 follow-up 4b below.

Full deploy commands, the `/healthz` gotcha, the key-backup and
invite-code-rotation instructions, and the exact "turn test mode off" steps
are now in `RUNBOOK.md`'s "§6-alt / §7-alt — Google Cloud" section (the
Fly/Vercel path stays documented as a working alternative, just not what's
running). `scripts/deploy-cloudrun.sh` and `scripts/deploy-web-firebase.sh`
wrap the deploy commands idempotently for next time; `scripts/e2e-remote.sh`
re-proves the round-1 path against a live remote issuer (enroll by email →
issue → `verify-credential` accepts `round1-email.yaml`, rejects
`default-floor.yaml` with `anchor_missing`) and passed against the live
deployment this session. `FRIENDS.md`'s two placeholder URLs are filled in.

Everything below this paragraph documents earlier sessions, including the
now-stale "Nothing is deployed yet" note under Round-3.

## Current state — last updated 2026-09-10 (overnight round-5 session)

Since the round-4 session below: two gentle, self-contained follow-ups from
that session's `next_steps` shipped. (1) `fuzzy-extractor-selfie` finally
has client-side wiring in `app/web` — a new "Selfie anchor" enrollment step
(`components/steps/SelfieStep.tsx`) captures a selfie via the browser camera
(or accepts an uploaded image, both for browsers without camera access and
for automated testing), derives a deterministic feature vector client-side
(`lib/selfieTemplate.ts` — a 16x16 grayscale average-hash, explicitly
documented as a placeholder for a real on-device face-embedding model, not
one itself), and calls the method's begin/complete endpoints; gated by
`session.available_methods` advertising `fuzzy-extractor-selfie`, which is
itself driven by the server's `FUZZY_EXTRACTOR_ENABLED` flag (the same
pattern `IdStep` already used for Persona — no separate `NEXT_PUBLIC_*` flag
needed). Proven with 9 vitest unit tests on the feature derivation plus a
real headless-browser run (claude-in-chrome) against a locally built server
+ `next dev`, including the Sybil-dedup "DUPLICATE DETECTED" path. (2)
`social-vouching-graph`'s candidate identity key is now the session's
stable holder `did:key` (PR #35) instead of the bare enrollment `SessionID`
— `pkg/types.CeremonyContext` gained a `HolderDID` field, and the method's
new `candidateKey(cc)` helper prefers it (falling back to `SessionID` when
absent, e.g. the round-1 email-only flow). This means a graduate can now
vouch for someone else in a later, separate session, and a re-enrolling
candidate doesn't lose accumulated vouches — see that method's README
section "Candidate identity: holder `did:key`, not the enrollment
`SessionID`" for the full reasoning. `docker build .` also reverified
locally this session (colima + `docker-buildx` — a prior session's dev-
machine gap, now fixed). See PRs #38 and #39 for detail. Everything below
this paragraph documents earlier sessions.

## Round-4 session summary (2026-09-08, overnight)

Since the round-3 session below: STATUS.md checklist #10a and #10b (Sprint
4's airdrop-test anchors) are done — `src/methods/fuzzy-extractor-selfie/`
(anchor, strength 70) and `src/methods/social-vouching/` (supplementary,
strength 35 — see that section for why it's supplementary despite the
checklist item calling it "the ... anchor"). Both are self-hosted (no
vendor account, gated behind opt-in env vars) and both pass the airdrop
test. `fuzzy-extractor-selfie`'s biometric commitment now also drives
`nullifierBinding` (via `src/server/did.go`'s new
`NullifierBindingForBiometricCommitment`) in preference to the holder's
device keypair, closing the "regenerate a keypair, get a new nullifier"
loophole for OpenLine's UBI-claim / vote-eligibility policies. See the two
new "What's implemented" rows (plus the airdrop-anchor-example policy row)
for detail. Everything below this paragraph documents earlier sessions.

## Round-3 session summary (2026-09-08, overnight)

Since the round-1/round-2 sessions below: issued credentials now carry a real
`did:key` holder DID and a `nullifierBinding` when the web app supplies a
holder public key (#35), and `SessionStore` / `email.TokenStore` /
`sms.OTPStore` / `government-id-liveness.ResultStore` all gained Redis-backed
implementations selected via `REDIS_URL`, with in-memory remaining the
default. See the two new "What's implemented" rows above the "What's stub"
table for detail — both were this session's scope, carried over from the
round-2 wrapup's `next_steps`. Everything below this paragraph documents the
earlier round-1 session. `main` is green in CI again (it had been red since 2026-06-15: the Dockerfile
missed newly added go.work modules — fixed in #28, and the image now builds
with `GOWORK=off` so go.work changes cannot break it). The **round-1 path is
real**: a friend with only an email address enrolls, the web app notices the
magic-link click by polling `/v1/sessions/{id}`, the issuer signs an
email-only credential, and `tools/verify-credential` accepts it against
`docs/policies/round1-email.yaml`. That flow was driven through a real
browser and is pinned by `tests/TestE2E_EmailOnlyEnrollment` (real server
binary on a loopback port) plus `scripts/e2e-email.sh` in CI. The magic link
is no longer returned to the client that asked for it (#29). A verifier bug
that rejected ~1.5% of genuine credentials (base64url signatures beginning
with `z`) is fixed (#31). All open method PRs (#23 email-tier, #24
phone-carrier-tier, #25 paid-billing-card) and the README rewrite (#27) are
merged; the Capacitor scaffold (#26) is closed until the PWA has a live URL.

**Deployed as of the round-6 session (2026-09-11)** — see that summary at the
top of this file. Live URLs: web <https://personhood-web.web.app>, issuer
<https://personhood-issuer-664594784582.us-central1.run.app> (Google Cloud
Run + Firebase Hosting, not Fly/Vercel — `RUNBOOK.md`'s "§6-alt / §7-alt"
section has the exact commands; §2b below still describes the Fly/Vercel
path as a working alternative). `FRIENDS.md`'s two URLs are filled in.

```bash
bash scripts/test-all.sh      # every go.work module with -race (incl. tests/, tools/)
bash scripts/e2e-email.sh     # real server: enroll by email → issue → verify
cd app/web && npm run build   # 101 kB First Load JS
```

OpenLine consumes this via `openline/src/suffrage/personhood-verifier`
(sibling checkout, `replace` directives). Its vote/claim policies require an
anchor verified within 24h, so round-1 credentials are rejected there with
`anchor_missing` **by design**; for round 1 OpenLine must evaluate
`docs/policies/round1-email.yaml` and pin the issuer key from
`/.well-known/did.json`.

### What's implemented

| Module | Path | What works |
|---|---|---|
| Canonical types | `pkg/types/` | `PersonhoodCredential`, `Policy`, `MethodMetadata`, `EvaluationResult`, `NullifierBinding` + validation. JSON-LD context + JSON schemas in `pkg/proto/`. |
| Method registry | `src/registry/` | Thread-safe `Method` plugin registry; enforces anchor strength ≥50 / supplementary <50 at registration. |
| W3C VC issuer + verifier | `src/credential/` | Ed25519 over RFC 8785 (JCS) canonical JSON. `MapResolver` for DIDs in tests; `did:web` stub. W3C Status List 2021 fetcher. |
| Policy DSL | `src/policy/` | YAML + JSON parser; evaluator returns all 11 `EvaluationCode` outcomes. Refuses naive supplementary stacking when `anchor_required: true`. Pedersen-binding → nullifier (SHA-256 stub for v0.1). |
| Email method | `src/methods/email/` | Magic-link, 32-byte token, 15-min TTL, disposable-domain blocklist. `LogSender` default; **SendGridSender** behind `-tags sendgrid` (PR #9). |
| SMS method | `src/methods/sms/` | 6-digit OTP, 5-min TTL, 3-attempt lockout, constant-time compare, fictional-555/VOIP heuristic. `LogSender` default; **TwilioSender** behind `-tags twilio` (PR #9). |
| **Phone-carrier-tier method** | `src/methods/phone-carrier-tier/` | Strength-28 upgrade for `sms` (checklist #8). Same OTP ceremony + pluggable `CarrierProvider`: Twilio Lookup v2 line-type intelligence (rejects VOIP) + optional sim_swap (rejects recently-ported). `NeutralProvider` dev default (offline VOIP pre-check only); `TwilioLookupProvider` behind Twilio creds. Registered additively alongside `sms` when `TWILIO_ACCOUNT_SID`+`TWILIO_AUTH_TOKEN` set. 12 tests with `-race`. |
| **Email-tier method** | `src/methods/email-tier/` | Strength-22 upgrade for `email` (checklist #8). Same magic-link ceremony + pluggable `EnrichmentProvider`: offline `DomainReputation` classifier + HaveIBeenPwned breach-presence. `NeutralProvider` dev default; `HIBPProvider` behind `HIBP_API_KEY`. Signal folded into the attestation digest. Registered additively alongside `email` when `HIBP_API_KEY` set. 13 tests with `-race`. |
| **Government-ID + selfie anchor** | `src/methods/government-id-liveness/` | **Persona** hosted-flow wrapper (PR #8). Strength 90, anchor. HMAC-validated webhook handler, in-memory result store, status mapping (approved/declined/needs_review/expired). |
| **Bank-link anchor** | `src/methods/plaid-bank-link/` | **Plaid** Hosted Link wrapper (checklist #6). Strength 88, anchor, ~$1.50, med friction. Client (`/link/token/create` + `hosted_link_url`), in-memory store keyed by link token, HMAC-validated `LINK`/`SESSION_FINISHED` webhook, status mapping. Auto-registers in the server when `PLAID_*` env present. 14 tests with `-race`. Not airdrop-test compatible (requires a bank). |
| **Floor: device attestation** | `src/methods/app-attest-device/` | Supplementary (strength 18, free). Apple App Attest / Google Play Integrity standalone. Server-issued challenge nonce + pluggable `Verifier` (v0.1 HMAC dev verifier; real Apple/Google = v0.2). Registers when `APP_ATTEST_SECRET` set. |
| **Floor: IP/ASN reputation** | `src/methods/ip-asn-reputation/` | Supplementary (strength 10, ~$0.001). Flags datacenter/proxy/tor IPs (VPN allowed by default) via a pluggable `ReputationProvider` (default static/clean; wire MaxMind/IPQualityScore for prod). Always-on in the server. |
| **Floor: CAPTCHA** | `src/methods/captcha-turnstile/` | Supplementary (strength 4, free). Cloudflare Turnstile `siteverify`. Registers when `TURNSTILE_SITE_KEY`+`TURNSTILE_SECRET_KEY` set. |
| **Paid-billing-card method** | `src/methods/paid-billing-card/` | Strongest single supplementary (strength 35, ~$0.30, checklist #9). $0 **Stripe** SetupIntent with forced 3DS/SCA. Client (`/v1/setup_intents`), in-memory store keyed by SetupIntent id, genuine `Stripe-Signature` HMAC webhook (`setup_intent.succeeded`/`.setup_failed`/`.canceled`), card-fingerprint dedup folded into the attestation. Auto-registers with its webhook route when `STRIPE_SECRET_KEY`+`STRIPE_WEBHOOK_SECRET` set. 14 tests with `-race`. Not airdrop-test compatible. |
| **Default policies** | `docs/policies/` | `default-floor.yaml` — anchor + 32 floor supplementary points; the recommended baseline integrators apply via the SDK. `round1-email.yaml` — the deliberately weak email-only policy for the first friends cohort (no anchor registered yet); OpenLine's anchor policies reject round-1 credentials with `anchor_missing` by design. |
| **End-to-end tests** | `tests/`, `scripts/e2e-email.sh` | `TestE2E_EmailOnlyEnrollment` builds the real server + `verify-credential` binaries, starts the server on a loopback port with LogSender, enrolls via email (link scraped from the log, never from the client response), polls the session, issues, and verifies against `round1-email.yaml` (pass), `default-floor.yaml` (`anchor_missing`), and a tampered copy (`signature_invalid`). The bash script is the same flow for humans and runs in CI. |
| **Verifier CLI** | `tools/verify-credential/` | `go run ./tools/verify-credential -cred c.json -policy p.yaml -issuer-url https://issuer` — signature + Status List + policy via the Go SDK; trusts the issuer by fetching its `/.well-known/did.json` (or `-issuer-did`/`-issuer-pub` to pin). Exit 0/1/2 = ok/rejected/error. |
| **REST issuer** | `src/server/` | **Chi-based HTTP server (PR #7)**. `/enrollment/start`, `/v1/sessions/{id}` (poll progress), `/v1/methods/{id}/begin` (secret challenge fields such as the email `magic_link_url` are redacted unless `DEV_EXPOSE_CHALLENGE_SECRETS=1`) and `/complete`, `/v1/methods/email/verify` (magic-link landing), `/v1/credentials/issue`, `/v1/status-list/{id}`, `/.well-known/did.json`, `/healthz`. CORS allowlist + recover + request-log middleware. In-memory `SessionStore`. `BuildDependencies()` auto-registers gov-id when PERSONA_* env present and plaid-bank-link when PLAID_* env present. cmd/gen-key utility for issuer seed. 8 httptest integration tests pass with `-race`. |
| **End-user PWA** | `app/web/` | **Next.js 14 App Router PWA (PR #10)**. Four screens (email → SMS → ID/selfie → credential). Email step polls `/v1/sessions/{id}` until the magic link is clicked (any tab/device); SMS and ID steps are skippable so an email-only server still issues. PWA manifest + service worker + apple-touch-icon → Add-to-Home-Screen installs a real app icon on Android + iOS. IndexedDB-backed credential vault with optional WebAuthn biometric gating. "Trusted terminal" aesthetic: JetBrains Mono + Plus Jakarta Sans, electric-lime accent on near-black. 100 kB First Load JS. |
| **Deploy infrastructure** | `Dockerfile`, `fly.toml`, `.dockerignore`, `app/web/vercel.json`, `.github/workflows/build.yml` | **PR #11**. Multi-stage Dockerfile (golang:1.22 → distroless/static-debian12:nonroot, built with sendgrid+twilio tags). Fly.io app config with /healthz, force_https, auto_stop_machines. vercel.json with security headers + camera permissions policy scoped to Persona. CI runs all 4 build configurations + production binary + Next build + Docker image. |
| **RUNBOOK** | `RUNBOOK.md` | **PR #12**. Clean-machine → verified-on-phone in 45-75 minutes wall clock, ~20 minutes hands-on. Twelve sections covering prereqs, vendor signups (Persona / SendGrid / Twilio / Fly / Vercel), local dev, real-delivery local test, server deploy, web deploy, Persona webhook registration, Add-to-Home-Screen install, on-phone enrollment, troubleshooting (10-row table), cost expectations. |
| **Integrator SDK (Go)** | `sdk/go/` | Drop-in verifier for services accepting Personhood credentials. `personhood.NewVerifier(TrustedIssuers{...})` + `Verify(ctx, cred, policy)` composes issuer-signature verification, Status List 2021 revocation, and policy evaluation + nullifier derivation into one `Result{OK, Code, Human, Details, Nullifier}`. Options for HTTP client, clock, and revocation-skip. `ParsePolicyYAML/JSON` + `ParseCredential` helpers. 9 tests (OK, unknown-issuer, tampered-sig, anchor-missing, revoked via httptest, bit-clear, resolver-required, parse) green with `-race`; standalone `go.sum` for external (OpenLine) consumption. |
| **Integrator SDK (TypeScript)** | `sdk/typescript/` | `@personhood/sdk` — `new Verifier(trustedIssuers).verify(vcJson, policy)`, same surface as the Go SDK, ESM with **zero runtime deps** (WebCrypto + `DecompressionStream` + `fetch`). Hand-rolled RFC 8785 JCS canonicalizer that preserves large integers, Ed25519 verify, Status List 2021, full policy evaluator port, SHA-256 nullifier. **Cross-language interop proven**: a fixture issued by the Go reference issuer (`tools/gen-ts-fixture`) verifies and reproduces the exact nullifier. 13 vitest tests green; `tsc` typecheck + build clean. |
| Design docs | `docs/` | 5 specs covering architecture, methods, credential format, policy DSL, OpenLine refactor. ~14k words. `docs/02-methods.md` now includes a delivery env-var matrix per vendor + a build-tag matrix. |
| Methods catalog | `docs/06-methods-catalog.md` | 3-agent brainstorm of ~40 additional methods with comparison table and prioritized roadmap. |
| **Holder did:key + nullifierBinding** | `app/web/lib/holderkey.ts`, `src/server/did.go`, `src/server/base58.go` | The web app generates a real Ed25519 keypair via WebCrypto on first boot (persisted in IndexedDB) and sends the public key on `POST /enrollment/start`; the server encodes it as a real `did:key:z...` (hand-rolled base58btc, no new dep) instead of the old opaque placeholder, and populates `credentialSubject.nullifierBinding` (stub Pedersen-shaped commitment, `bn254`/`pedersen-v1`) at `/v1/credentials/issue`. Sessions without a client key still get the v0.1 placeholder DID and no `nullifierBinding`, so `nullifier_required` policies fail closed. `tools/verify-credential` and `sdk/go` needed no changes — their nullifier derivation was already generic. Unblocks OpenLine's per-action nullifiers. `docs/policies/nullifier-example.yaml` fixture. Proven with a real Chrome browser run (WebCrypto keygen → issued credential → verified by the actual `verify-credential` binary) plus `tests/e2e_nullifier_test.go` (bound session → `nullifier_required` passes with a derived nullifier; unbound session → `nullifier_missing`). |
| **Redis-backed stores** | `pkg/redisclient/`, `src/server/session_redis.go`, `src/methods/{email,sms,government-id-liveness}/store_redis.go` | Hand-rolled, dependency-free RESP2 client (`pkg/redisclient` — matches every other vendor integration in this repo being a plain net client, not an SDK). `SessionStore`, `email.TokenStore`, `sms.OTPStore`, and `government-id-liveness.ResultStore` each gained a Redis-backed implementation selected via `REDIS_URL` (`NewSessionStoreFromEnv` / `*.NewTokenStoreFromEnv` / `*.NewOTPStoreFromEnv` / `*.NewResultStoreFromEnv`); in-memory remains the default when `REDIS_URL` is unset, so round-1-scale deployments are unaffected. `SessionStore` is now an interface (`InMemorySessionStore` + `RedisSessionStore`); all `SessionStore` methods return `SessionView` (a plain value) rather than a mutable pointer, so both backends share one call-site contract. Verified against a real local Redis (not just mocked): unit + integration tests for all four stores, plus a full curl-driven enrollment→issuance run against the actual server binary with `REDIS_URL` set, confirming real `personhood:session:*` / `personhood:email-token:*` keys in Redis. |
| **Fuzzy-extractor-selfie anchor** | `src/methods/fuzzy-extractor-selfie/`, `app/web/components/steps/SelfieStep.tsx` | **Airdrop-test anchor (checklist #10a).** Strength 70, anchor, $0.00, no vendor. From-scratch pure-Go fuzzy-extractor (Juels-Wattenberg fuzzy commitment over a repetition code — see the package's extractor.go doc comment) rather than an FFI wrap of the OpenLine Rust prototype (see the decision note in that doc comment). Server-side `Accumulator` does a Sybil-dedup membership scan (fuzzy-extractor `Rep` against every stored helper-data record — no raw biometric ever stored). `src/server/did.go`'s `NullifierBindingForBiometricCommitment` binds the issued credential's `nullifierBinding` to this method's biometric commitment (not the regenerable holder device keypair) whenever it's the anchor — closing the "mint a new keypair, get a new nullifier" loophole for OpenLine's UBI-claim / vote use cases. Registers when `FUZZY_EXTRACTOR_ENABLED=1` (no vendor credential to gate on otherwise). 20 unit tests + 6 server-integration tests + a real-server e2e test, all `-race` green. **Client wiring (round-5, PR #39):** a camera-or-upload enrollment step in `app/web` derives a deterministic feature vector on-device (`lib/selfieTemplate.ts` — a documented placeholder for a real face-embedding model) and drives begin/complete against the real server; 9 vitest unit tests + a real headless-browser run incl. the duplicate-detection path. |
| **Social-vouching-graph supplementary** | `src/methods/social-vouching/` | **Airdrop-test web of trust (checklist #10b).** Strength 35, **supplementary** (docs/06-methods-catalog.md scores it 35, below the registry's hard-enforced 50-point anchor floor — see that method's README for why it ships supplementary despite the checklist item's "anchor" wording). BrightID-style: an existing member vouches for a candidate via `POST /v1/methods/social-vouching-graph/vouch` (the same "extra method-owned HTTP route" mechanism every vendor webhook already uses); a simplified SybilRank-style weighted-vouch-with-decay score gates admission, and a newly-admitted member is enrolled at a decayed trust score so they can vouch for others afterwards (a chained-vouching test proves trust actually propagates, not just a fixed-seed allowlist). Registers when `SOCIAL_VOUCHING_ENABLED=1` + `SOCIAL_VOUCHING_SECRET` + operator-configured `SOCIAL_VOUCHING_SEED_IDS`. 27 unit tests + 4 server-integration tests, all `-race` green. |
| **Airdrop-anchor example policy** | `docs/policies/airdrop-anchor-example.yaml` | `anchor_required: true` + `nullifier_required: true`, `allowed_methods: [fuzzy-extractor-selfie, social-vouching-graph]`. Proven three ways against a real running server in `tests/e2e_airdrop_anchors_test.go`: fuzzy-extractor-selfie alone passes with a real nullifier; social-vouching-graph alone correctly fails `anchor_missing`; both together on one credential compose and pass. |
| **Google Cloud deploy (Cloud Run + Firebase Hosting)** | `scripts/deploy-cloudrun.sh`, `scripts/deploy-web-firebase.sh`, `scripts/e2e-remote.sh`, `.gcloudignore` | **Round-6 (PRs #41/#42/#43).** The live round-1 deployment: issuer on Cloud Run (source build, `--max-instances 1` since sessions are in-memory with no Redis wired up here), web app as a static Next.js export on Firebase Hosting. Issuer key lives only in Secret Manager, never in git. `scripts/deploy-cloudrun.sh` / `scripts/deploy-web-firebase.sh` are idempotent, parameterized wrappers around the exact `gcloud`/`firebase` commands run tonight (never overwrite an existing signing-key secret); `scripts/e2e-remote.sh` re-proves enroll → issue → verify against a live remote issuer. See `RUNBOOK.md`'s "§6-alt / §7-alt" section for the full command reference, the `/healthz`-vs-`/health` Cloud Run gotcha, and how to turn test mode off. |
| **`/v1/config` + invite gate** | `src/server/handlers.go`, `src/server/config.go` | New public `GET /v1/config` endpoint reports `{invite_code_required, challenge_secrets_exposed, email_delivery}` so a client can decide whether to prompt for an invite code and whether to warn that magic links are shown on screen rather than emailed — never leaks the code itself. `ENROLLMENT_INVITE_CODE` (env), when set, requires a matching `invite_code` field on `POST /enrollment/start` (constant-time compare; `403 invite_code_required` / `403 invite_code_invalid` otherwise). This is what makes `DEV_EXPOSE_CHALLENGE_SECRETS=1` safe enough for a small trusted cohort in production — see `config_endpoint_test.go`. |

### What's stub

| Module | Path | What's needed | Effort |
|---|---|---|---|
| **Anchor method (App Attest)** | `src/methods/phone-liveness/` | Apple App Attest + Google Play Integrity server-side validators; client-side ceremony driver. Was the original v0.1 anchor; superseded for the demo by `government-id-liveness`. Useful for a future native shell that can attest in-app. | ~3–5 days |
| **Mobile app (Capacitor wrap)** | `app/mobile/` | Sprint 3 — see below. Wrap `app/web` in Capacitor; ship to Play Store internal track. | ~3–5 days incl. store paperwork |
| **Signed status list** | `src/credential/` + `src/server/` | The `/v1/status-list/{id}` endpoint currently returns an unsigned placeholder. v0.2 will sign it like a normal credential. | ~½ day |

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

- [ ] **4b. Turn test mode off: SMTP creds, remove DEV_EXPOSE_CHALLENGE_SECRETS.**
  > *The live round-6 deployment runs with `DEV_EXPOSE_CHALLENGE_SECRETS=1` (magic link shown on screen, no real mail credential configured). Set `SMTP_HOST`/`SMTP_PORT`/`SMTP_USER`/`SMTP_PASS`/`SMTP_FROM` (a Gmail app password works — RUNBOOK.md §3b-alt) on the Cloud Run service and remove `DEV_EXPOSE_CHALLENGE_SECRETS`; see RUNBOOK.md's "§6-alt / §7-alt" section for the exact `gcloud run services update` command. Confirm via `GET /v1/config` that `challenge_secrets_exposed` flips to `false`.*

**Sprint 1 outcome:** you can open `https://<your-app>.vercel.app` on your Android phone, Add to Home Screen, complete email + SMS + government-ID-selfie, and see your signed W3C credential. The credential satisfies `anchor_required: true` policies because the gov-id anchor is fully wired.

### Sprint 2 — add real anchors (per `docs/06-methods-catalog.md` v0.2 plan)

- [x] **5. Add `government-id-liveness` anchor.** ✅ PR #8 (`feat/government-id-liveness`)
  > `src/methods/government-id-liveness/` wraps Persona's hosted Inquiries API. Strength 90, anchor. HMAC-validated webhook, in-memory result store, status mapping (approved/declined/needs_review/expired), 11 tests covering signature verification + status mapping + full flow.

- [x] **6. Add `plaid-bank-link` anchor.** ✅ (`feat/plaid-bank-link`)
  > `src/methods/plaid-bank-link/` wraps Plaid Hosted Link (bank-account OAuth + identity). Strength 88, anchor, ~$1.50, med friction, 180-day freshness. Same shape as PR #5: client + in-memory store + HMAC-validated webhook + status mapping (SUCCESS→approved / EXITED→declined / REQUIRES_REVIEW→needs_review / expired). Auto-registers in the server when `PLAID_CLIENT_ID`+`PLAID_SECRET`+`PLAID_WEBHOOK_SECRET` are set. 14 tests green with `-race`. Note: not airdrop-test compatible (requires a bank).

- [x] **7. Add `app-attest-device` + `ip-asn-reputation` + `captcha-turnstile` as a mandatory floor.** ✅ (`feat/floor-methods`)
  > Built all three supplementary methods (`app-attest-device` 18, `ip-asn-reputation` 10, `captcha-turnstile` 4 = 32 floor points, ~$0.001 total). All auto-register in the server: ip-asn always-on (default clean provider), captcha when `TURNSTILE_*` set, app-attest when `APP_ATTEST_SECRET` set. Shipped `docs/policies/default-floor.yaml` (anchor_required + min_supplementary_points: 32) as the recommended default integrators apply via the SDK. NOTE: enforcement is integrator-side (policy DSL), consistent with the architecture — the server registers/runs the floor methods rather than hard-gating issuance (which has no policy layer today).

- [x] **8. Upgrade existing `email` → `email-tier` and `sms` → `phone-carrier-tier`.** ✅ PR #23 + PR #24
  > Both built additively (plain `email`/`sms` stay registered; the tiered variants register when their vendor env is present). **email-tier** (strength 22): domain reputation + HaveIBeenPwned breach-presence, `HIBPProvider` behind `HIBP_API_KEY`. **phone-carrier-tier** (strength 28): Twilio Lookup v2 line-type + optional SIM-swap, behind Twilio creds. `app/web` now picks the tiered variant whenever the server advertises it and falls back to plain `email`/`sms` otherwise (`app/web/lib/tiering.ts`; `EmailStep`/`SmsStep` no longer hardcode a method id) — this is the "retire plain email/sms" swap, done. Fixed alongside it: `GET /v1/methods/email/verify` used to hardcode the plain `email` method, so an email-tier magic link (token stored in email-tier's own store) would always fail with `invalid_or_expired_token`; the handler now reads an optional `method=` query param (defaulted to `email` for old links) and `BuildDependencies` sets it on email-tier's base URL. Regression test: `src/server/emailtier_routing_test.go`.

- [x] **9. Add `paid-billing-card` supplementary (strongest single supplementary).** ✅ PR #25
  > *`src/methods/paid-billing-card/` wraps Stripe SetupIntent ($0 pre-auth + forced 3DS/SCA). Strength 35, supplementary, ~$0.30. Same shape as plaid-bank-link: Stripe client + in-memory store + genuine Stripe-Signature HMAC webhook (setup_intent.succeeded/setup_failed/canceled) + card-fingerprint dedup folded into the attestation digest. Auto-registers with its webhook route when STRIPE_SECRET_KEY + STRIPE_WEBHOOK_SECRET set. 14 tests with `-race`.*

### Sprint 3 — mobile: Capacitor wrap → Play Store internal test

Once the PWA is live on a real domain (Sprint 1 outcome above), Sprint 3 ships it through the Play Store. The web app does the heavy lifting; Capacitor is just a native shell that loads it and adds the device APIs PWAs can't reach (FCM push, App Attest / Play Integrity).

- [ ] **3a. Scaffold Capacitor under `app/mobile/`.** (PR #26 closed 2026-09-08: unverifiable until the PWA has a live URL; branch `feat/mobile-capacitor-scaffold` kept — reopen after Sprint 1 deploy.)
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

- [x] **10a. Promote OpenLine's `fuzzy-extractor` prototype to a Personhood anchor.** ✅ (`feat/airdrop-test-anchors`)
  > *`src/methods/fuzzy-extractor-selfie/` — strength 70 anchor, $0.00, no vendor. Implements the fuzzy-extractor concept from scratch in pure Go (a Juels-Wattenberg fuzzy commitment over a repetition code — see the package doc comment) rather than FFI-binding the OpenLine Rust prototype: cgo-bridging a separate repo's crate into this repo's dependency-free-Go-client convention was judged disproportionate to one method, and this session's working rules scoped work to the personhood repo only (see the wrapup's decision record). Server-side `Accumulator` does the Sybil-dedup membership check STATUS.md asked for (scans stored helper data via the fuzzy-extractor `Rep` operation — no raw biometric ever stored). `src/server/did.go`'s new `NullifierBindingForBiometricCommitment` binds the credential's `nullifierBinding` to the biometric commitment (not the holder's regenerable device keypair) whenever this anchor is present — closing the "just make a new keypair" loophole for OpenLine's UBI-claim / vote use cases. Gated behind opt-in `FUZZY_EXTRACTOR_ENABLED=1` (no vendor credential to gate on otherwise). 20 unit tests + 6 server-integration tests + a 3-subtest real-server e2e test, all green with `-race`.*
  > *Round-5 follow-up ✅ (PR #39): client-side wiring in `app/web` — see the round-5 "Current state" summary above for detail.*

- [x] **10b. Add `social-vouching-graph` supplementary (BrightID model).** ✅ (`feat/airdrop-test-anchors`)
  > *`src/methods/social-vouching/` — members vouch for new members via an out-of-band `POST /v1/methods/social-vouching-graph/vouch` route (the same "extra HTTP route via MethodRoutes" mechanism every vendor webhook already uses); a simplified SybilRank-style weighted-vouch-with-decay score (distinct-voucher count + cumulative trust-weighted score, both configurable) decides whether a candidate passes, and passing enrolls them into the graph at a decayed trust score so they can vouch for others afterwards (proven with a chained-vouching test, not just fixed-seed admission). **Shipped as SUPPLEMENTARY (strength 35), not an anchor**, despite this checklist item's wording: `docs/06-methods-catalog.md` Table 2 scores `social-vouching-graph` at 35, below the registry's hard-enforced 50-point anchor floor (`pkg/types/validation.go`) — registering it as an anchor would fail at server startup, not just be a documentation mismatch. See the method's README for the full reasoning. Gated behind opt-in `SOCIAL_VOUCHING_ENABLED=1` + a required `SOCIAL_VOUCHING_SECRET` + operator-configured `SOCIAL_VOUCHING_SEED_IDS`. 27 unit tests + 4 server-integration tests, all green with `-race`.*
  > *Round-5 follow-up ✅ (PR #38): candidate identity keyed by holder `did:key` instead of `SessionID` — see the round-5 "Current state" summary above for detail.*

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

1. OpenLine adds Go dependency on `github.com/sagearbor/personhood/sdk/go` (✅ Go SDK now shipped — see "What's implemented").
2. Suffrage vote-eligibility check refactors to: `personhood.Verify(vc, vote_policy)`.
3. Commons UBI claim refactors to: `personhood.Verify(vc, ubi_policy)` + nullifier check.
4. Move `openline/src/suffrage/accumulator/` → `personhood/` (identity-set-membership infra).
5. Voting-specific Circom circuits stay in OpenLine.

---

## When this file goes stale

If you finish a checklist item, **check the box and update the "What's implemented" / "What's stub" tables.** If you start a new sprint, add the new items below. If the recommendations in `docs/06-methods-catalog.md` change, update the dev-checklist roadmap to match. The wrapup HTML in `tmp/wrapups/` is a session snapshot — useful history but not the canonical state. STATUS.md is the canonical state.
