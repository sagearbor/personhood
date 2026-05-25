# Methods Catalog — Brainstorm Snapshot (2026-05-25)

Three independent agents brainstormed verification methods that could be added to Personhood beyond the v0.1 set (`phone-liveness` anchor + `email` + `sms` supplementary). Each agent worked from a different perspective so the lists wouldn't all converge on the same WorldCoin-and-Plaid answer:

- **Agent A — KYC / regulated industry.** Reference vendors: Persona, Onfido, Veriff, Sumsub, Jumio, Stripe Identity, Plaid, ID.me, Login.gov, eIDAS, Boku/Telesign, Notarize, LexisNexis.
- **Agent B — Decentralized identity / anti-Sybil research.** Reference projects: WorldCoin, BrightID, Proof of Humanity, Idena, Gitcoin Passport, Sismo/Privado ID, Encointer, fuzzy extractors, web of trust.
- **Agent C — Platform anti-fraud / trust-and-safety practitioner.** Reference platforms: Apple/Google dev consoles, Tinder/Bumble photo verification, Twitter Blue, Cash App/Venmo KYC, Uber/Lyft driver onboarding, Airbnb, Cloudflare, Persona Account Aging.

The full per-agent outputs are in the openline sibling repo at `tmp/personhood-methods-brainstorm/agent-{A,B,C}-*.md`. This catalog is the deduplicated synthesis.

**How to use this file:**
- Anchor methods are the gap in v0.1 (only `phone-liveness` exists today). Look at Table 1 to pick what to add next.
- Supplementary methods compose with anchors. Look at Table 2 to pick "near-free floors" and upgrade paths for the existing email/SMS.
- The `Rec` column is my recommendation for v0.2/v0.3+ priority. Override freely with project context I don't have.

Legend for `Rec`:

| Symbol | Meaning |
|---|---|
| 🌟 | Ship next — high value, clear path, no blocking unknowns |
| ✅ | Add when capacity allows — good, standard, integratable |
| 🤔 | Conditional — depends on use case (jurisdiction, density, partnership) |
| ⏸ | Defer to v0.3+ — research-grade, degrading, or low ROI today |
| ❌ | Recommend against — NIST-deprecated or fundamentally broken in 2026 |

Legend for `Airdrop`: ✅ passes the airdrop test (works with no ID/bank/address); ⚠️ partial; ❌ requires documents/banking/jurisdiction.

---

## Table 1 — Anchor candidates (strength ≥ 50)

Sorted by the highest score any agent gave. Anchors satisfy `anchor_required: true` policies. Personhood needs more than one to be useful in real deployments.

| Method ID | A | B | C | Cost | Friction | Airdrop | Rec | One-line summary |
|---|---:|---:|---:|---:|---|:---:|:---:|---|
| `iris-orb` | — | 98 | — | $0.50 | high | ❌ | ✅ | WorldCoin hardware. Gold standard. Needs partnership; bespoke hardware. |
| `eidas-national-eid` | 95 | — | — | $1.50 | low | ❌ | 🤔 | BankID / MitID / Personalausweis. Top-tier in ~30 countries; nothing elsewhere. |
| `background-check` | — | — | 92 | $25 | high | ❌ | 🤔 | Checkr/Onfido full background. Only for gig-platform integrators where cost is justified. |
| `government-id-liveness` | 90 | — | 90 | $1.00 | med | ❌ | 🌟 | Passport/license + selfie liveness via Persona/Onfido. **Ship next as anchor #2.** |
| `plaid-bank-link` | 90 | — | 88 | $1.50 | med | ❌ | 🌟 | Bank OAuth via Plaid. **Ship next as anchor #3.** Fast integration, well-understood. |
| `in-person-partner-location` | 85 | — | — | $5.00 | high | ✅ | 🤔 | UPS/post office/NGO field agent enrollment. The airdrop-test answer; ops-heavy. |
| `government-credential-federation` | 85 | — | — | $1.00 | med | ❌ | ✅ | ID.me / Login.gov SSO. Cheap to integrate where supported (US-centric). |
| `live-video-review` | 80 | — | 82 | $8.00 | high | ⚠️ | 🤔 | Human reviewer on Zoom-style call. Defeats deepfakes; expensive; queue waits. |
| `video-notary` | 75 | — | — | $25 | high | ❌ | ⏸ | RON. Legal weight, but expensive and US-state-specific. |
| `fuzzy-extractor-selfie` | — | 70 | — | $0.00 | med | ✅ | ✅ | On-device, no central DB. **Already prototyped in OpenLine.** Productionize and promote here as the airdrop-test anchor. |
| `idena-ceremony` | — | 65 | — | $0.05 | high | ✅ | ⏸ | Synchronous flip puzzles. Degrading vs GPT-4V/Gemini multimodal. |
| `encointer-pseudonym-ceremony` | — | 60 | — | $0.00 | high | ✅ | 🤔 | Local synchronized meetup. Truly decentralized; needs density to bootstrap. |
| `sim-possession-carrier-attestation` | 55 | — | — | $0.05 | low | ⚠️ | ✅ | Carrier HLR lookup (Boku/Telesign), bypasses SS7. Cheap, low friction; uneven coverage. |
| `selfie-video-community-challenge` | — | 55 | — | $0.30 | high | ✅ | ⏸ | Proof-of-Humanity-style. Deepfake erosion is real and accelerating. |

## Table 2 — Supplementary methods (strength < 50)

Sorted by the highest score any agent gave. Supplementaries never satisfy `anchor_required: true` alone — they compose with anchors to raise total trust or add freshness/binding.

| Method ID | A | B | C | Cost | Friction | Airdrop | Rec | One-line summary |
|---|---:|---:|---:|---:|---|:---:|:---:|---|
| `stamp-stacking-aggregator` | — | 40 | — | $0.10 | med | ⚠️ | ✅ | Gitcoin Passport style: aggregate many OAuth/onchain stamps. Composable; airdrop-fails for non-Web2-active. |
| `in-person-meetup-attestation` | — | 40 | — | $0.50 | high | ✅ | 🤔 | Geo-tagged group selfie with verified peers. Strong but coordination-heavy. |
| `paid-billing-card` | — | — | 35 | $0.30 | med | ❌ | 🌟 | Real card pre-auth (Twitter Blue / OpenAI tier-1 pattern). **Strongest single supplementary; ship next.** |
| `credit-header-triangulation` | 35 | — | — | $0.75 | low | ❌ | ⏸ | LexisNexis-style depth check. Synthetic-ID detector; thin-file exclusion. |
| `social-vouching-graph` | — | 35 | — | $0.00 | high | ✅ | ✅ | BrightID web-of-trust. Airdrop-compatible; cold-start hard; great for v0.3 community drive. |
| `zk-credential-aggregation` | — | 35 | — | $0.02 | med | ⚠️ | 🤔 | Sismo/Privado ID ZK stamp predicates. Privacy-preserving; same source-weakness as stamp-stacking. |
| `tax-id-ssn-match` | 30 | — | — | $0.50 | low | ❌ | ❌ | Post-Equifax-breach this is mostly broken. Skip. |
| `property-mortgage-records-match` | 30 | — | — | $0.50 | low | ❌ | ⏸ | LexisNexis property records. Excludes renters; controversial source. |
| `tee-device-attestation` / `app-attest-device` | — | 30 | 18 | $0.00 | low | ⚠️ | 🌟 | Apple App Attest / Google Play Integrity standalone. **Ship as a near-free mandatory floor.** Already used inside `phone-liveness`; expose as its own method too. |
| `voice-biometric` | — | 30 | — | $0.05 | low | ✅ | ⏸ | Accessibility-friendly. Modern TTS (ElevenLabs/XTTS) erodes liveness. |
| `proof-of-address-document-ocr` / `document-address-match` | 25 | — | 30 | $0.40 | high | ⚠️ | ✅ | **The Android dev console pattern** — utility bill / bank statement / lease showing claimed address. Multi-doc alternative path. |
| `phone-carrier-tier` | — | — | 28 | $0.05 | low | ⚠️ | 🌟 | **Upgrade for existing `sms`** — adds line tenure + porting history, same UX/cost. |
| `passkey-attestation` | — | 25 | — | $0.00 | low | ⚠️ | ✅ | WebAuthn/FIDO with hardware attestation. Free, universal device support. |
| `postal-mail-postcard-code` | 25 | — | — | $1.50 | high | ⚠️ | 🤔 | Physical postcard with code (Google My Business pattern). Establishes address; 3-10 day delay kills UX. |
| `onchain-reputation-aggregator` | — | 25 | — | $0.05 | low | ❌ | 🤔 | Axiom/Herodotus ZK proofs over chain history. Web3-native only; airdrop-farmers gamed it. |
| `social-account-age` | — | — | 25 | $0.10 | med | ❌ | 🤔 | LinkedIn/GitHub/StackOverflow tenure. Demographically narrow; aged-account markets exist. |
| `email-tier` | — | — | 22 | $0.005 | low | ✅ | 🌟 | **Upgrade for existing `email`** — domain rep + breach-presence signal. Same UX, much better signal. |
| `account-age-proof` / `oauth-account-age` | — | 20 | 18 | $0.00 | low | ⚠️ | ✅ | Apple/Google/GitHub account-age via OAuth. Free, low friction; aged accounts purchaseable. |
| `knowledge-based-authentication` | 20 | — | — | $1.25 | med | ❌ | ❌ | NIST-deprecated post-Equifax. Skip. |
| `proof-of-stake-of-time` | — | 20 | — | $0.00* | med | ❌ | ⏸ | Token lock / VDF. Wealth-biased; airdrop-fails. |
| `behavioral-biometrics` | — | 15 | 20 | $0.05 | low | ⚠️ | 🤔 | BioCatch/Sift keystroke + mouse. Privacy-invasive; accessibility-hostile. |
| `edu-employer-email-federation` | 18 | — | — | $0.01 | low | ❌ | ✅ | `.edu` + verified employer domains. Cheap upgrade to `email` for institutional cohort. |
| `geographic-consistency` | — | — | 15 | $0.02 | low | ⚠️ | ✅ | IP + GPS + cell + shipping cross-check. Strongest as a *negative* signal (inconsistency = fraud). |
| `device-fingerprint-tenure` | — | — | 15 | $0.01 | low | ⚠️ | 🤔 | FingerprintJS/Iovation. Useful only for re-verification; intentionally broken by privacy browsers. |
| `ip-asn-reputation` | — | — | 10 | $0.001 | low | ⚠️ | 🌟 | **Ship as a near-free mandatory floor.** Catches >90% of naive bot signups; defeatable but cheap. |
| `captcha-turnstile` | — | 5 | 4 | $0.00 | low | ✅ | ✅ | Cloudflare Turnstile etc. Universal floor; commercial solvers ($0.50/1000) defeat it. |

---

## Where the agents agreed and disagreed

**Three-of-three (or two-of-three) consensus** — broad consensus signal that these are real:

- `government-id-liveness` / `selfie-id-doc-liveness` (A 90, C 90)
- `plaid-bank-link` (A 90, C 88)
- `live-video-review` (A 80, C 82)
- `proof-of-address-document-ocr` / `document-address-match` (A 25, C 30) — **the user's Android dev console example**
- `tee-device-attestation` / `app-attest-device` (B 30, C 18) — different angles on the same primitive
- `captcha-with-paid-fallback` / `captcha-turnstile` (B 5, C 4)
- `account-age-proof` / `oauth-account-age` (B 20, C 18)
- `behavioral-biometrics` (B 15, C 20)

**Unique to one perspective** — likely missing from a single-source brainstorm:

- KYC-only: `eidas-national-eid`, `government-credential-federation`, `tax-id-ssn-match`, `credit-header-triangulation`, `KBA`, `postal-postcard`, `video-notary`, `property-records`, `in-person-partner`, `edu-employer-email`, `sim-possession-carrier-attestation`
- Decentralized-only: `iris-orb`, `fuzzy-extractor-selfie`, `social-vouching-graph`, `idena-ceremony`, `encointer-pseudonym-ceremony`, `selfie-video-community-challenge`, `stamp-stacking-aggregator`, `zk-credential-aggregation`, `in-person-meetup-attestation`, `passkey-attestation`, `voice-biometric`, `onchain-reputation-aggregator`, `proof-of-stake-of-time`
- Practitioner-only: `paid-billing-card`, `ip-asn-reputation`, `email-tier`, `phone-carrier-tier`, `social-account-age`, `background-check`, `geographic-consistency`, `device-fingerprint-tenure`

The KYC perspective gave the most regulated-acceptable anchors. The decentralized perspective gave the most airdrop-test-compatible options. The practitioner perspective surfaced the *cheap-near-free signals* the other two missed (IP/ASN, app-attest standalone, tiered upgrades for existing methods).

---

## Recommended next-phase roadmap

Grouped by what to ship in which version, based on the 🌟 / ✅ ratings above:

### v0.2 — "Make the existing demo bulletproof and add 2 real anchors"

These should ship together. Total ~2-3 weeks of work.

1. **`government-id-liveness` anchor** (Persona or Onfido vendor wrap). Regulated-industry default.
2. **`plaid-bank-link` anchor** (Plaid Identity Verification API). Fintech default.
3. **`app-attest-device` mandatory floor** (Apple App Attest + Google Play Integrity). Free, kills emulator farms.
4. **`ip-asn-reputation` mandatory floor** (MaxMind or IPQualityScore). Free-ish, kills datacenter signups.
5. **`captcha-turnstile` mandatory floor** (Cloudflare Turnstile). Free, kills naive scripts.
6. **Replace `email` → `email-tier`** (domain rep + breach presence). Same UX, better signal.
7. **Replace `sms` → `phone-carrier-tier`** (line tenure + porting history). Same UX, better signal.
8. **`paid-billing-card` supplementary** (Stripe SetupIntent). Strongest single supplementary.

### v0.3 — "Add airdrop-test-compatible options"

For OpenLine's UBI use case, anchors must work for the undocumented. Pick 1-2:

9. **Productionize `fuzzy-extractor-selfie`** from the OpenLine prototype. Promote here as the airdrop-test anchor.
10. **`social-vouching-graph`** (BrightID model). Cold-start hard but truly airdrop-compatible.
11. **`proof-of-address-document-ocr`** (utility bill / bank statement). The Android dev console pattern for documented-but-unbanked.
12. **`document-address-match`** as a v0.2 → v0.3 upgrade with manual review queue.

### v0.4+ — "Specialty methods for specialty integrators"

13. **`background-check` anchor** (Checkr) for gig-economy integrators.
14. **`live-video-review` anchor** for highest-trust regulated finance.
15. **`eidas-national-eid` anchor** for EU/Nordic deployments.
16. **`sim-possession-carrier-attestation`** (Boku/Telesign) as a low-friction anchor where carriers cooperate.
17. **`stamp-stacking-aggregator`** for Web3 integrators (Gitcoin Passport interop).
18. **`encointer-pseudonym-ceremony`** as a community-run anchor where density allows.

### Skip / monitor only

- `knowledge-based-authentication` — NIST-deprecated, skip.
- `tax-id-ssn-match` — post-Equifax, privacy-toxic, mostly broken.
- `idena-ceremony` — degrading vs GPT-4V multimodal AI; revisit if AI-resistance assumption holds.
- `selfie-video-community-challenge` — deepfake erosion accelerating.
- `voice-biometric-liveness` — ElevenLabs / XTTS defeat liveness; revisit when synthesis-detection catches up.
- `property-mortgage-records-match` — LexisNexis aggregation controversial; thin coverage outside US/UK.

---

## How to extend this catalog

This is a snapshot of one brainstorm session (2026-05-25). To add a new method or update existing recommendations:

1. Add a row to Table 1 (anchor) or Table 2 (supplementary).
2. Cite which agent/source proposed it, or add yourself as a new column.
3. Update the "Recommended next-phase roadmap" section if it shifts priorities.
4. Don't delete deprecated methods — mark them ❌ with reason so the institutional memory stays.

The single source of truth for current implementation status (which of these are built vs stub) lives in `STATUS.md` at the repo root, not in this file.
