# email-tier (supplementary, strength 22)

The strength-22 upgrade for the plain [`email`](../email/) method, per
[`docs/06-methods-catalog.md`](../../../docs/06-methods-catalog.md). Same UX
(a magic-link inbox-control ceremony), much better Sybil signal.

| | |
|---|---|
| **Type** | supplementary |
| **Strength** | 22 |
| **Cost** | ~$0.005 / verification (HIBP lookup) |
| **UX friction** | low |
| **Freshness** | 90 days |
| **Anchor?** | no — supplementary only, never satisfies `anchor_required` |

## Why "tier"?

Inbox control alone (the plain `email` method) is trivially Sybil'd: a bot farm
mints throwaway addresses by the thousand. `email-tier` keeps the inbox-control
proof and layers an enrichment **Signal** on top:

- **Domain reputation** — a deterministic, offline classifier
  (`DomainReputation`). Disposable domains score 0 (and are rejected); known
  major mailbox providers score 50–62; custom domains score 55. No network call.
- **Breach presence** — whether the address appears in known historical data
  breaches via [HaveIBeenPwned](https://haveibeenpwned.com/). Counter-intuitively
  a **positive** personhood signal: a throwaway address minted moments ago is
  absent from years-old breach corpora, whereas a real long-lived human address
  usually appears in at least one.

The captured Signal is folded into the credential's `attestation_digest`, so an
auditor can later confirm which tier signals were present — the raw address
never lands on the credential.

## Providers (the repo's dev-default convention)

Like [`ip-asn-reputation`](../ip-asn-reputation/) and
[`app-attest-device`](../app-attest-device/), the method ships a safe dev
default and wires the real provider via env:

| Provider | When | Behaviour |
|---|---|---|
| `NeutralProvider` | default (no `HIBP_API_KEY`) | local domain reputation only, no breach lookup |
| `HIBPProvider` | `HIBP_API_KEY` set | real breach-presence via HIBP API v3 |

**The strength-22 rating assumes a real provider is wired.** Built with the
neutral provider the method is effectively plain-email strength; the server
wiring logs a warning, and `BuildDependencies` only registers `email-tier` when
`HIBP_API_KEY` is present.

## Environment variables

| Var | Required | Purpose |
|---|---|---|
| `HIBP_API_KEY` | to enable | HaveIBeenPwned subscription key; also gates server registration |
| `HIBP_USER_AGENT` | optional | overrides the default `personhood-email-tier` UA (HIBP rejects requests without a UA) |

Email delivery reuses the `email` module's env-aware sender (`SendGridSender`
behind `-tags sendgrid`, `LogSender` otherwise) via a thin adapter in the
server.

## Wire model

1. `BeginCeremony` — validate the address (carried in `CeremonyContext.UserID`),
   run enrichment (reject disposable), store a 32-byte token + the Signal, send
   the magic link.
2. The user clicks the link; the client posts the token back.
3. `CompleteCeremony` — look up the token (single-use), succeed, and emit the
   enrichment-bound `attestation_digest`.

## Status

Additive and non-breaking: registered alongside `email`, not replacing it. The
intended end-state (per checklist #8) is to retire plain `email` once the web
app threads the enrichment fields through its email screen.
