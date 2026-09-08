# phone-carrier-tier (supplementary, strength 28)

The strength-28 upgrade for the plain [`sms`](../sms/) method, per
[`docs/06-methods-catalog.md`](../../../docs/06-methods-catalog.md). Same UX
(a 6-digit OTP over SMS), much better Sybil signal.

| | |
|---|---|
| **Type** | supplementary |
| **Strength** | 28 |
| **Cost** | ~$0.05 / verification (SMS + Lookup) |
| **UX friction** | med |
| **Freshness** | 90 days |
| **Anchor?** | no — supplementary only, never satisfies `anchor_required` |

## Why "tier"?

Plain SMS only proves a device can receive a code — trivially Sybil'd with
cheap VOIP numbers bought by the hundred. `phone-carrier-tier` keeps the OTP
possession proof and adds **carrier intelligence**:

- **Line type** — `mobile` / `landline` / `voip` / `unknown` via Twilio Lookup
  v2 `line_type_intelligence`. A carrier-reported **VOIP** line is rejected.
- **Porting / SIM-swap** — when the `sim_swap` package is enabled, a number
  that was **recently ported** is rejected (a SIM-swap-attack signal).

A cheap offline `LooksLikeVOIP` pre-check rejects the fictional +1-NPA-555 band
and known-unassigned NANP prefixes *before* spending a Lookup call.

## Providers (the repo's dev-default convention)

Like [`ip-asn-reputation`](../ip-asn-reputation/) and
[`app-attest-device`](../app-attest-device/): ships a safe dev default and
wires the real provider via env.

| Provider | When | Behaviour |
|---|---|---|
| `NeutralProvider` | default | offline pre-check only; reports `unknown` line type |
| `TwilioLookupProvider` | Twilio creds set | real line-type intelligence (+ optional sim_swap) |

**The strength-28 rating assumes a real provider is wired.** Built with the
neutral provider the method is effectively plain-SMS strength; the server
wiring logs a warning, and `BuildDependencies` only registers
`phone-carrier-tier` when `TWILIO_ACCOUNT_SID` + `TWILIO_AUTH_TOKEN` are set.

## Environment variables

| Var | Required | Purpose |
|---|---|---|
| `TWILIO_ACCOUNT_SID` | to enable | Twilio Account SID (also used by the `sms` sender); gates registration |
| `TWILIO_AUTH_TOKEN` | to enable | Twilio Auth Token |
| `TWILIO_LOOKUP_SIM_SWAP` | optional | set to `1` to request the `sim_swap` package (extra cost; not on every account) |

OTP delivery reuses the `sms` module's env-aware sender (`TwilioSender` behind
`-tags twilio`, `LogSender` otherwise) via a thin adapter in the server.

## Wire model

1. `BeginCeremony` — read the number (`CeremonyContext.UserID`), offline VOIP
   pre-check, carrier lookup (reject VOIP / recently-ported), store a 6-digit
   OTP, send it.
2. The user enters the code; the client posts `{phone_number, code}`.
3. `CompleteCeremony` — constant-time verify (3-attempt lockout), succeed.

## Status

Additive and non-breaking: registered alongside `sms`, not replacing it. The
intended end-state (per checklist #8) is to retire plain `sms` once the web app
threads the carrier fields through its SMS screen.
