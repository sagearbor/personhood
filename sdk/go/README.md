# sdk/go — `github.com/sagearbor/personhood/sdk/go`

Go SDK for **integrators** — services that want to accept Personhood
credentials. It composes signature verification, revocation, and policy
evaluation into one call.

```go
import (
    "crypto/ed25519"
    personhood "github.com/sagearbor/personhood/sdk/go"
    "github.com/sagearbor/personhood/pkg/types"
)

// 1. Declare which issuers you trust (DID -> Ed25519 public key).
v := personhood.NewVerifier(
    personhood.TrustedIssuers(map[types.DID]ed25519.PublicKey{
        "did:web:issuer.example": issuerPub,
    }),
)

// 2. Verify a presented credential against your policy.
res, err := v.Verify(ctx, cred, policy)
if err != nil {
    // transport / internal error — e.g. the revocation list fetch failed.
    // The credential's validity is unknown; fail closed.
}
if !res.OK {
    // res.Code, res.Human, res.Details say what the user needs to fix.
}
nullifier := res.Nullifier // non-empty iff policy.nullifier_required
```

## What it handles

- **Issuer signature + structure** (`src/credential`) — mapped to
  `EvalSignatureInvalid` / `EvalUnknownIssuer`.
- **Revocation** via W3C Status List 2021 (`EvalRevoked`). Disable with
  `personhood.WithoutRevocationCheck()` for offline verifiers.
- **Expiry / freshness / anchor / supplementary / nullifier** policy checks
  (`src/policy`), returning the full `types.EvaluationCode` space.
- **Nullifier derivation** — when the policy sets `nullifier_required`, the
  per-context nullifier is returned in `res.Nullifier`. Record it in a
  per-context spent-set for one-action-per-human semantics.

## What it does NOT handle

End-user enrollment UI — that's the issuer server (`src/server`) and the
end-user app (`app/web`).

## Error vs. non-OK result

`Verify` returns a non-nil **error** only for failures you cannot attribute to
the credential (a status-list fetch that failed, a misconfigured verifier).
A credential that is invalid, revoked, or non-compliant returns
`(Result{OK:false, ...}, nil)` — inspect `Result.Code`. This lets you cleanly
distinguish "the user must fix something" from "we couldn't complete the
check" (fail closed on the latter).

## Options

| Option | Purpose |
|---|---|
| `TrustedIssuers(map[DID]ed25519.PublicKey)` | Build the issuer allow-list resolver (the common case). Any `credential.DIDResolver` also works. |
| `WithHTTPClient(*http.Client)` | Client for the Status List 2021 fetch; set a timeout in production. |
| `WithClock(func() time.Time)` | Pin verification time (tests, deterministic replay). |
| `WithoutRevocationCheck()` | Skip the revocation fetch (offline / out-of-band revocation). |

## Helpers

`ParsePolicyYAML`, `ParsePolicyJSON`, and `ParseCredential` are re-exported so
integrators depend only on this module.

## Consuming from a sibling repo (e.g. OpenLine)

The Personhood modules are not yet tag-published. A sibling repo depends on the
SDK with a local `replace` pointing at the checkout:

```
require github.com/sagearbor/personhood/sdk/go v0.0.0
replace github.com/sagearbor/personhood/sdk/go => ../personhood/sdk/go
```

(plus matching `replace` lines for `pkg/types`, `src/credential`, `src/policy`,
which the SDK's own `go.mod` already wires relative to its location).
