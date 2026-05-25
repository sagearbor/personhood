# sdk/typescript — @personhood/sdk

TypeScript SDK for integrators. Drop-in verifier:

```ts
import { verify } from "@personhood/sdk";

const result = await verify(presentedVC, policy);
if (!result.ok) {
  // result.code, result.human, result.details
}
const nullifier = result.nullifier; // present iff policy.nullifier_required
```

Works in Node.js 20+ and modern browsers. Bundled as ESM. Treats the W3C VC, policy DSL, and nullifier derivation identically to the Go SDK at `../go/`.
