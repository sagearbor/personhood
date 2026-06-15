# sdk/typescript — `@personhood/sdk`

TypeScript SDK for **integrators** verifying Personhood W3C Verifiable
Credentials against integrator policies. Same surface as the Go SDK
(`../go/`), and byte-for-byte interoperable with Go-issued credentials
(JCS canonicalization + Ed25519 + SHA-256 nullifier).

Runs in Node.js 20+ and modern browsers. ESM, **zero runtime dependencies**
(uses WebCrypto, `DecompressionStream`, and `fetch`).

```ts
import { Verifier, base64ToBytes, type Policy } from "@personhood/sdk";

// 1. Declare trusted issuers: DID -> 32-byte raw Ed25519 public key.
const v = new Verifier({
  "did:web:issuer.example": base64ToBytes(issuerPublicKeyB64),
});

// 2. Verify a presented credential (pass the raw JSON string when you can).
const res = await v.verify(presentedVcJson, policy);
if (!res.ok) {
  // res.code, res.human, res.details
}
const nullifier = res.nullifier; // present iff policy.nullifier_required
```

## What it handles

- **Issuer signature + structure** → `EvaluationCode.SignatureInvalid` /
  `UnknownIssuer`.
- **Revocation** via W3C Status List 2021 → `Revoked`. Disable with
  `{ skipRevocationCheck: true }`.
- **Expiry / freshness / anchor / supplementary / nullifier** policy checks —
  identical outcomes and codes to the Go evaluator.
- **Nullifier derivation** — `res.nullifier` when `policy.nullifier_required`.

## Error vs. non-OK result

`verify` **throws** only for unattributable transport/internal failures (e.g. a
revocation-list fetch that failed) so you can fail closed. An invalid, revoked,
or non-compliant credential resolves to `{ ok: false, ... }` — inspect
`res.code`.

## Options

```ts
new Verifier(trustedIssuers, {
  now: () => new Date(),     // pin verification time
  fetch: customFetch,        // for the revocation fetch
  skipRevocationCheck: false // offline / out-of-band revocation
});
```

## Passing the credential

Prefer the **raw JSON string**: it is canonicalized for signature verification
and avoids any number-precision loss. A parsed object also works for the value
range Personhood credentials use.

## Develop

```bash
npm install
npm run typecheck   # tsc --noEmit
npm test            # vitest run (incl. cross-language interop fixture)
npm run build       # tsc -> dist/
```

The interop test verifies a credential issued by the Go reference issuer; the
fixture is regenerated with `personhood/tools/gen-ts-fixture`.
