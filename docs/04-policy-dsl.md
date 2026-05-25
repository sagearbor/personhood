# 04 — Policy DSL: Schema, Evaluator, Examples

> Status: design spec for v0.1. Companion docs: [01-architecture.md](./01-architecture.md), [02-methods.md](./02-methods.md), [03-credential-format.md](./03-credential-format.md).

## Design rationale

A Personhood policy is a small declarative document that an integrator publishes alongside the action it gates. It is the *only* way integrators express verification requirements — there is no per-call procedural API where integrators write fraud heuristics in code. Pushing all verification logic into a declarative DSL has three concrete payoffs: (a) policies are auditable in isolation, including by non-engineers; (b) the same policy can be evaluated by a wallet (to preview "do I qualify?") and by an integrator backend (to actually decide), so the user gets no surprises; (c) the evaluator is a pure function and trivially unit-testable.

The policy is defined as **JSON Schema**, but the canonical source the integrator edits is **YAML**. YAML is friendlier for the structural shape of these documents (lots of optional fields, short field names, occasional inline comments), and the parser converts YAML → JSON before validation. **Either encoding is accepted by the parser and the SDKs.** When this doc shows YAML, the same policy expressed as JSON is equivalent (every YAML example here was test-converted with a YAML→JSON round-trip).

## Policy schema

```json
{
  "$schema": "https://json-schema.org/draft/2020-12/schema",
  "$id": "https://personhood.protocol/policies/v1/schema.json",
  "title": "Personhood Policy v1",
  "type": "object",
  "required": ["version", "policy_id", "action"],
  "properties": {
    "version": {
      "const": "1.0",
      "description": "Policy DSL version. Bump on breaking schema changes."
    },
    "policy_id": {
      "type": "string",
      "pattern": "^[a-z0-9][a-z0-9._/-]{2,127}$",
      "description": "Stable, integrator-controlled identifier (e.g. 'openline/commons/ubi-claim/v1'). Acts as the namespace for nullifier derivation and audit logs."
    },
    "action": {
      "type": "string",
      "description": "Human-readable label for the gated action (e.g. 'Claim UBI', 'Cast vote', 'Recover account')."
    },
    "anchor_required": {
      "type": "boolean",
      "default": false,
      "description": "If true, the credential MUST contain at least one method with type=anchor that survives all freshness filters."
    },
    "min_supplementary_points": {
      "type": "integer",
      "minimum": 0,
      "default": 0,
      "description": "Sum of strength scores across supplementary methods (those with methodType=supplementary in the credential) must be >= this value."
    },
    "allowed_methods": {
      "type": "array",
      "items": { "type": "string" },
      "description": "If set, only methods in this list count toward anchor satisfaction or supplementary points. Use to exclude vendor-specific methods you don't trust."
    },
    "blocked_methods": {
      "type": "array",
      "items": { "type": "string" },
      "description": "Methods in this list are ignored during evaluation. Mutually exclusive with allowed_methods; if both are set, allowed_methods wins and blocked_methods is logged as a warning."
    },
    "min_strength_per_method": {
      "type": "integer",
      "minimum": 0,
      "maximum": 100,
      "description": "Any verifiedMethod whose frozen strength is below this is ignored. Useful to require Level-2-PAD anchors only."
    },
    "max_credential_age_seconds": {
      "type": "integer",
      "minimum": 0,
      "description": "Reject credentials whose issuanceDate is older than this. Independent of the credential's own expirationDate."
    },
    "max_anchor_method_age_seconds": {
      "type": "integer",
      "minimum": 0,
      "description": "Per-method freshness for anchors: the chosen anchor's completedAt must be within this window."
    },
    "require_fresh_anchor_proof": {
      "type": "boolean",
      "default": false,
      "description": "If true, the integrator additionally demands a live presentation step that re-confirms the anchor at presentation time (out-of-band signal; the evaluator records the requirement and the SDK surfaces it to the integrator UI)."
    },
    "nullifier_required": {
      "type": "boolean",
      "default": false,
      "description": "If true, the credential MUST carry credentialSubject.nullifierBinding and the evaluator returns the derived nullifier for this policy's context tag."
    },
    "nullifier_context_tag": {
      "type": "string",
      "description": "Domain-separation tag mixed into the nullifier derivation. MUST be unique per logical action (e.g. one tag per election, not one tag per vote). Required if nullifier_required is true."
    }
  },
  "additionalProperties": false
}
```

## Five example policies

### 1. Low-stakes signup (no anchor)

```yaml
version: "1.0"
policy_id: "example/forum/signup/v1"
action: "Sign up for the forum"
anchor_required: false
min_supplementary_points: 5
```

Anyone with a verified email (strength 8) clears this — no anchor required, no SMS even. Suitable for a community forum where the cost of bad actors is low and the marginal user is more important than airtight Sybil resistance. The framework explicitly tolerates this — supplementary-only policies are legal — but they are *not* the recommended default for anything financial, governance-related, or rate-limited.

### 2. Frictionless payment send (empty policy)

```yaml
version: "1.0"
policy_id: "example/payments/send/v1"
action: "Send a payment from a verified account"
```

The minimum legal policy. No anchor required, zero supplementary points, no freshness window. Use this when the integrator only needs proof that a valid Personhood credential exists (e.g. the credential was presented during account creation; this action wants to confirm the same credential still exists and is unrevoked). The verifier still checks signature validity and Status List 2021 revocation — the policy doesn't add any application-level requirement.

### 3. UBI claim (anchor, 24h max, nullifier with tag)

```yaml
version: "1.0"
policy_id: "openline/commons/ubi-claim/v1"
action: "Claim UBI dividend for the current cycle"
anchor_required: true
max_anchor_method_age_seconds: 86400      # 24h
min_supplementary_points: 0
nullifier_required: true
nullifier_context_tag: "openline/commons/ubi-claim/cycle-${CYCLE_ID}"
```

OpenLine Commons UBI: anchor must be within 24 hours (each cycle requires a fresh personhood proof — prevents an attacker who compromises a credential from auto-claiming forever), no supplementary requirement (the anchor is enough), and a per-cycle nullifier prevents double-claiming. The `${CYCLE_ID}` substitution is performed by the integrator before passing the policy to the evaluator; the policy artifact stored in the repo has the literal template, and the integrator's verification layer substitutes the current cycle ID at evaluation time.

### 4. Vote casting (anchor, fresh-anchor-required, nullifier with tag)

```yaml
version: "1.0"
policy_id: "openline/suffrage/vote/v1"
action: "Cast a vote"
anchor_required: true
max_anchor_method_age_seconds: 86400      # 24h
require_fresh_anchor_proof: true
min_supplementary_points: 0
nullifier_required: true
nullifier_context_tag: "openline/suffrage/vote/${ELECTION_ID}"
```

Stricter than UBI: in addition to the 24-hour anchor freshness window, `require_fresh_anchor_proof: true` tells the integrator's flow to demand a *live* anchor re-confirmation at the moment of voting (the wallet runs a phone-liveness ceremony again and produces a fresh signed assertion that the SDK passes to the integrator alongside the VP). This raises the bar against credential theft for the highest-stakes action in OpenLine. The nullifier tag is per-election; the same VC can vote in different elections without collision but cannot vote twice in the same election.

### 5. High-trust account recovery (anchor + 20 supp pts, 30-day max VC age)

```yaml
version: "1.0"
policy_id: "example/bank/account-recovery/v1"
action: "Recover access to a high-value account"
anchor_required: true
max_anchor_method_age_seconds: 86400        # 24h fresh anchor
max_credential_age_seconds: 2592000         # 30 days
min_supplementary_points: 20
allowed_methods: ["phone-liveness", "sms"]  # exclude email; we don't trust it for recovery
min_strength_per_method: 10
```

A bank-like integrator gating account recovery. Demands a fresh anchor *and* significant supplementary signal (≥ 20 points from non-email methods), *and* the credential as a whole has to be < 30 days old (you can't recover with a year-old VC that's been sitting in some abandoned wallet). `min_strength_per_method: 10` drops the email signal (strength 8) even if it would otherwise count, hardening against weak signals slipping in.

## Policy evaluator algorithm

### Pseudocode

```
function Evaluate(vc PersonhoodCredential, policy Policy, now Time) -> EvaluationResult:

    # 1. Structural sanity
    if vc.expirationDate < now:                return Fail("EVAL_VC_EXPIRED")
    if vc.credentialStatus.revoked == true:    return Fail("EVAL_VC_REVOKED")
    if not vc.credentialSubject.anchorPresent: return Fail("EVAL_NO_ANCHOR_PRESENT")

    # 2. Credential-age check
    if policy.max_credential_age_seconds is set:
        age = now - vc.issuanceDate
        if age > policy.max_credential_age_seconds:
            return Fail("EVAL_VC_TOO_OLD")

    # 3. Filter verified methods
    methods = vc.credentialSubject.verifiedMethods

    if policy.allowed_methods is set:
        methods = [m for m in methods if m.method in policy.allowed_methods]

    if policy.blocked_methods is set and policy.allowed_methods is not set:
        methods = [m for m in methods if m.method not in policy.blocked_methods]

    if policy.min_strength_per_method is set:
        methods = [m for m in methods if m.strength >= policy.min_strength_per_method]

    # 4. Anchor check (with per-anchor freshness window)
    anchor_candidates = [m for m in methods if m.methodType == "anchor"]
    if policy.max_anchor_method_age_seconds is set:
        anchor_candidates = [m for m in anchor_candidates
                             if (now - m.completedAt) <= policy.max_anchor_method_age_seconds]

    if policy.anchor_required and len(anchor_candidates) == 0:
        if any anchor existed before filtering by freshness:
            return Fail("EVAL_ANCHOR_EXPIRED")
        else:
            return Fail("EVAL_ANCHOR_MISSING")

    # 5. Supplementary points sum
    supp_methods = [m for m in methods if m.methodType == "supplementary"]
    supp_points = sum(m.strength for m in supp_methods)

    if supp_points < policy.min_supplementary_points:
        return Fail("EVAL_INSUFFICIENT_SUPPLEMENTARY",
                    {required: policy.min_supplementary_points, present: supp_points})

    # 6. Nullifier derivation
    derived_nullifier = nil
    if policy.nullifier_required:
        if vc.credentialSubject.nullifierBinding is missing:
            return Fail("EVAL_NULLIFIER_BINDING_MISSING")
        if policy.nullifier_context_tag is empty:
            return Fail("EVAL_POLICY_INVALID_NULLIFIER_TAG")
        # NOTE: Personhood SDK does NOT compute the nullifier itself.
        # It returns the binding + tag and the integrator's ZK layer computes
        # the nullifier inside its proof system (Circom + Poseidon for OpenLine).
        derived_nullifier_request = {
            commitment: vc.credentialSubject.nullifierBinding.commitment,
            context_tag: policy.nullifier_context_tag,
        }

    # 7. Fresh-anchor-proof requirement (signaled to integrator)
    fresh_anchor_proof_required = policy.require_fresh_anchor_proof

    return Pass(
        anchor_used: anchor_candidates[0].method if any else nil,
        supplementary_points: supp_points,
        derived_nullifier_request: derived_nullifier_request,
        fresh_anchor_proof_required: fresh_anchor_proof_required,
    )
```

The algorithm is intentionally linear and side-effect-free. There are no network calls, no disk reads, no clocks except the `now` parameter the caller passes in (so tests can pin time).

### Go implementation (signature only — full impl lands in `src/policy/`)

```go
package policy

import (
    "time"

    "github.com/sagearbor/personhood/pkg/types"
)

// EvaluationCode is the machine-readable outcome of a policy evaluation.
type EvaluationCode string

const (
    CodePass                       EvaluationCode = "EVAL_PASS"
    CodeVCExpired                  EvaluationCode = "EVAL_VC_EXPIRED"
    CodeVCRevoked                  EvaluationCode = "EVAL_VC_REVOKED"
    CodeVCTooOld                   EvaluationCode = "EVAL_VC_TOO_OLD"
    CodeNoAnchorPresent            EvaluationCode = "EVAL_NO_ANCHOR_PRESENT"
    CodeAnchorMissing              EvaluationCode = "EVAL_ANCHOR_MISSING"
    CodeAnchorExpired              EvaluationCode = "EVAL_ANCHOR_EXPIRED"
    CodeInsufficientSupplementary  EvaluationCode = "EVAL_INSUFFICIENT_SUPPLEMENTARY"
    CodeNullifierBindingMissing    EvaluationCode = "EVAL_NULLIFIER_BINDING_MISSING"
    CodePolicyInvalidNullifierTag  EvaluationCode = "EVAL_POLICY_INVALID_NULLIFIER_TAG"
)

// EvaluationResult is the structured outcome of policy evaluation.
type EvaluationResult struct {
    Passed                    bool
    Code                      EvaluationCode
    Detail                    map[string]any
    AnchorUsed                string
    SupplementaryPoints       int
    DerivedNullifierRequest   *NullifierRequest
    FreshAnchorProofRequired  bool
}

type NullifierRequest struct {
    Commitment   []byte
    ContextTag   string
}

// Evaluate is the pure, deterministic policy evaluator.
//
// It performs NO I/O; it does not resolve DIDs, fetch revocation status, or
// compute Pedersen commitments. The caller is responsible for having already
// verified signatures and revocation status before calling Evaluate.
func Evaluate(vc types.PersonhoodCredential, p types.Policy, now time.Time) EvaluationResult
```

### TypeScript implementation (signature only — full impl lands in `sdk/typescript/src/policy.ts`)

```typescript
import type {
  PersonhoodCredential,
  Policy,
  NullifierRequest,
} from './types';

export type EvaluationCode =
  | 'EVAL_PASS'
  | 'EVAL_VC_EXPIRED'
  | 'EVAL_VC_REVOKED'
  | 'EVAL_VC_TOO_OLD'
  | 'EVAL_NO_ANCHOR_PRESENT'
  | 'EVAL_ANCHOR_MISSING'
  | 'EVAL_ANCHOR_EXPIRED'
  | 'EVAL_INSUFFICIENT_SUPPLEMENTARY'
  | 'EVAL_NULLIFIER_BINDING_MISSING'
  | 'EVAL_POLICY_INVALID_NULLIFIER_TAG';

export interface EvaluationResult {
  passed: boolean;
  code: EvaluationCode;
  detail?: Record<string, unknown>;
  anchorUsed?: string;
  supplementaryPoints: number;
  derivedNullifierRequest?: NullifierRequest;
  freshAnchorProofRequired: boolean;
}

/**
 * Pure, deterministic policy evaluator.
 *
 * Performs no I/O. The caller is responsible for verifying signatures and
 * revocation status before calling evaluate().
 */
export function evaluate(
  vc: PersonhoodCredential,
  policy: Policy,
  now: Date = new Date(),
): EvaluationResult;
```

Both implementations share the same code shape so the Go SDK and TS SDK evolve in lock-step. A property-based test suite (in `tests/`) feeds the same inputs to both and asserts identical outputs.

## Error model

Every failed evaluation returns a structured `EvaluationResult` carrying a stable `code` (the `EvaluationCode` enum above) and an optional `detail` map with diagnostic data. Integrators are expected to translate codes into user-facing messages and remediation flows. Recommended UX:

| Code | What the user sees | What the integrator does |
|---|---|---|
| `EVAL_PASS` | "Verified" | Authorize the action |
| `EVAL_VC_EXPIRED` | "Your verification has expired. Please re-verify." | Redirect to wallet for fresh enrollment |
| `EVAL_VC_REVOKED` | "Your verification was revoked. Contact support." | Block, audit-log |
| `EVAL_VC_TOO_OLD` | "Please re-verify for this action (we require recent verification)." | Redirect to wallet |
| `EVAL_ANCHOR_MISSING` | "This action requires a phone-camera verification." | Redirect to wallet for anchor method |
| `EVAL_ANCHOR_EXPIRED` | "Please re-do your phone-camera check (it was over 24h ago)." | Redirect to wallet for fresh anchor |
| `EVAL_INSUFFICIENT_SUPPLEMENTARY` | "Add an SMS verification to continue." | Show which supp methods are missing using `detail.required` / `detail.present` |
| `EVAL_NULLIFIER_BINDING_MISSING` | "Your credential needs the privacy extension for this action." | Redirect to wallet to re-issue with `include_nullifier_binding: true` |
| `EVAL_POLICY_INVALID_NULLIFIER_TAG` | (n/a — integrator misconfiguration) | Fix the policy; do not surface to user |

The detail map is intentionally untyped so methods can extend it without changing the SDK; the contract is that the `code` is stable and machine-readable.

## Policy versioning

The `version` field on every policy is `"1.0"` for the v0.1 release. Schema changes follow these rules:

- **Minor bumps (1.0 → 1.1):** strictly additive (new optional fields). Existing policies remain valid; existing evaluators ignore unknown fields with a warning.
- **Major bumps (1.0 → 2.0):** reserved for breaking changes. The evaluator refuses to evaluate a policy whose major version it doesn't understand.

Integrators publish a **new `policy_id`** when they materially change the meaning of a policy (e.g. tightening from "no anchor" to "anchor required"). The old `policy_id` is allowed to continue evaluating against old VPs that were captured under the old rules; the new `policy_id` applies to new requests. This makes audit logs unambiguous: "user X's claim was evaluated against `openline/commons/ubi-claim/v1`" is a complete statement of what rule was applied.

We do NOT support versionless mutation of policies — silently editing a `policy_id`'s contents in place is an anti-pattern that breaks audit trails.

## Anti-patterns to warn against

The DSL is permissive in shape but the docs are opinionated about which combinations to avoid:

- **Stacking-without-anchor.** Setting `anchor_required: false` and instead piling on `min_supplementary_points: 100` is exactly the design the framework rejects. The user-visible failure mode (legitimate users frustrated by friction) is the same as the all-supplementary path, but bot farms can satisfy 100 supp points cheaply by stacking burner emails, SMS, and (future) social attestation farms. The SDK emits a lint warning when it sees this combination: "Policy `<id>` requests `min_supplementary_points >= 50` without an anchor — supplementary points are not Sybil-resistant on their own; consider `anchor_required: true`."
- **Reusing `nullifier_context_tag` across actions.** Each tag should namespace one logical action class. Using `nullifier_context_tag: "openline/suffrage/vote"` (without an election ID) across multiple elections would prevent a user from voting in more than one election ever, because the nullifier would collide. Always include the per-instance discriminant in the tag.
- **Globbing methods with broad `allowed_methods`.** If you list every method as allowed, you've added complexity without restricting anything. Use `allowed_methods` only when you actually want to exclude methods; otherwise omit it.
- **Setting `max_anchor_method_age_seconds` shorter than the typical UX delay.** A 5-minute window for the anchor will cause UX failures for users on slow networks. Recommended minimums: 1 hour for high-stakes flows where you'll just retry, 24 hours for routine flows.
- **Setting `max_credential_age_seconds` longer than `expirationDate`.** Redundant. If you want VC-age enforcement, use a window strictly shorter than the VC's lifetime.
- **Using v0.1 with the expectation of selective disclosure.** v0.1 evaluation requires reading the full credential. Until BBS+ ships in v0.2, the whole `verifiedMethods` array is visible to the integrator. Policies that promise the user "we only see that you're verified, not how" are misleading in v0.1.

## Future extensions

- **Dynamic policies.** Today policies are static documents. v0.2 may allow integrators to express conditional clauses ("if user is in jurisdiction X, additionally require Y"). Initial design: a small `when` expression language with explicit allowed predicates (geo, time-of-day, account-tier). Keep the evaluator pure by passing the context as input.
- **Negotiation between integrator and wallet.** The wallet currently picks the best VC it has and tries to satisfy the policy. A negotiation protocol — "here are the policies I support; which method do you want me to add?" — would let users complete *just* the missing methods on demand rather than re-enrolling from scratch.
- **Federated trust scores per issuer.** Today `allowed_methods` is the only way to scope trust. A future schema field `trusted_issuers: [{did, weight}]` would let integrators accept multiple issuers with weighted contributions to the supplementary point total.
- **Risk-based policies.** Allowing a policy to declare a risk score function (e.g. "ratio of anchor strength to supp strength must exceed X") for use cases where a single fixed threshold is too crude. Likely v0.3+, after we have live integrator feedback on what the static thresholds get wrong.
- **Multi-credential policies.** A policy that demands the holder presents two unrelated VCs (e.g. a Personhood VC *and* a separately-issued employment VC). Cleanly composable with W3C VPs, just needs policy schema support for multiple credential slots.

## Cross-references

- The credential fields the evaluator reads (`anchorPresent`, `verifiedMethods[]`, `nullifierBinding`): [03-credential-format.md](./03-credential-format.md).
- The method strength scores that drive `min_supplementary_points`: [02-methods.md](./02-methods.md).
- The OpenLine policies actually in production: [05-openline-refactor.md](./05-openline-refactor.md).
- The verifier SDK and integrator API that hosts the evaluator: [01-architecture.md](./01-architecture.md).
