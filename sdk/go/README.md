# sdk/go

Go SDK for integrators. Drop-in verifier:

```go
import "github.com/sagearbor/personhood/sdk/go"

result, err := personhood.Verify(presentedVC, policy)
if err != nil { /* transport / parse error */ }
if !result.OK {
    // result.Code, result.Human, result.Details
}
nullifier := result.Nullifier // present iff policy.nullifier_required
```

Handles: VC signature validation, expiry check, revocation status list fetch, policy evaluation, nullifier derivation.

Does NOT handle: end-user enrollment UI (that's the issuer server + the end-user app).
