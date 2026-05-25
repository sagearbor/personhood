# Security Policy

## Reporting a vulnerability

If you believe you have found a security vulnerability in Personhood, please report it privately. **Do not open a public GitHub issue for a vulnerability.** Two channels:

1. **Email** `security@personhood.example` *(placeholder — to be replaced before the first public release)*
2. **Or** open a GitHub issue with the title prefixed by `[security]` *only* if it does not disclose exploit details. Use this to request a private channel.

We will acknowledge your report within 5 business days and aim to provide a remediation plan within 30 days.

## Supported versions

Only the `main` branch is currently supported. There are no tagged releases yet. Once v0.1 ships, this section will be updated with a support matrix.

## Scope

In scope:

- Cryptographic primitives used in credential signing and verification
- W3C Verifiable Credential format implementation and JSON-LD context handling
- Policy DSL parsing and evaluation
- Reference server REST endpoints (authentication, authorization, input handling, secrets management)
- Method plugin interface (registry boundary)

Out of scope:

- End-user device security (compromised phones, jailbroken/rooted devices, malicious keyboards)
- Third-party SDK vulnerabilities (Apple App Attest, Google Play Integrity, etc.) — report those upstream
- Integrator applications that consume Personhood credentials but are not in this repo
- Denial-of-service against rate-limited endpoints, unless an amplification factor is involved
