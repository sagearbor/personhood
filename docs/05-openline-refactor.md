# 05 — OpenLine Refactor: Consuming Personhood

> Status: design spec for the OpenLine Phase 2 migration. Companion docs: [01-architecture.md](./01-architecture.md), [02-methods.md](./02-methods.md), [03-credential-format.md](./03-credential-format.md), [04-policy-dsl.md](./04-policy-dsl.md).

This document describes how the sibling [OpenLine](https://github.com/sagearbor/openline) project — currently a monolithic protocol with payments (Flurry), voting/identity (Suffrage), UBI (Commons), and AI agents (Steward) — will refactor its Suffrage and Commons modules to consume the Personhood library instead of carrying its own identity stack. The file paths in this doc refer to the OpenLine repo at `/Users/sophie.arborbot/PROJECTS/github_repos/openline/`.

## Current state summary

OpenLine today has its own complete proof-of-personhood layer under `src/suffrage/`:

- **`src/suffrage/fuzzy-extractor/`** (Rust, ~6 source files in `src/`) — Boyen-Dodis-Pointcheval fuzzy extractor that turns noisy multi-modal biometric vectors (face + fingerprint + voice) into stable on-device keys, then hashes the key to a 32-byte `BiometricCommitment`. No raw biometric ever leaves the device. The pipeline is described in `src/suffrage/fuzzy-extractor/README.md:7-15`.
- **`src/suffrage/accumulator/`** (Rust, ~4 source files in `src/`) — RSA accumulator that maps biometric commitments to primes and accumulates them into a single constant-size value. Supports membership and non-membership proofs for "this human is registered" / "this human is not yet registered". Proofs are constant-size ~2 KB regardless of population. See `src/suffrage/accumulator/README.md:11-15`.
- **`src/suffrage/zk-circuits/`** (Circom 2.x + snarkjs Groth16) — two main circuits and three library circuits:
  - `circuits/VoteProof.circom` (22,463 constraints) — proves the voter holds a registered `identity_secret`, has correctly derived `Poseidon(1, identity_secret, election_id)` as the per-election nullifier, has cast a vote in range, and is not revoked.
  - `circuits/ClaimProof.circom` (11,005 constraints) — proves the claimant holds a registered `biometric_commitment` and has derived `Poseidon(2, biometric_commitment, cycle_id)` as the per-cycle nullifier.
  - `circuits/lib/MerkleProof.circom`, `circuits/lib/Nullifier.circom`, `circuits/lib/RangeCheck.circom` — supporting primitives. The Nullifier circuit uses domain tag `1` for votes, `2` for claims (`README.md:29-32`).
- **`src/suffrage/contracts/`** (Solidity, Foundry) — `IdentityRevocation.sol` (418 lines) tracks ZK identity commitments on-chain, enforces a 90-day liveness interval with a 30-day grace period (`IdentityRevocation.sol:40-43`), supports voluntary revocation, governance-Sybil-revocation by 66% supermajority, and suspension pending investigation.
- **`src/commons/src/`** (Solidity, Foundry) — `CommonsPool.sol` (334 lines) receives Flurry levy payments, splits them between dividend and validator pools, and exposes a `claim(cycleId, biometricCommitment, proof, nullifier, recipient)` function (`CommonsPool.sol:221-278`). `ClaimVerifier.sol` (59 lines) is the **mock** ZK verifier that today simply checks the first 32 bytes of the proof are non-zero (`ClaimVerifier.sol:50-58`). The `_verifyProof` comment explicitly says "Replace with real Groth16 verifier" (line 49).

The boundary between identity primitives and voting/UBI logic is muddy: `CommonsPool.claim()` directly references `biometricCommitment` as a `bytes32` and computes the nullifier itself with `keccak256("commons-claim", commitment, cycleId)` (`CommonsPool.sol:262-264`). The ZK verifier is decoupled but mocked. The `pkg/types/types.go` shared layer already defines `BiometricCommitment` (`types.go:114`) and `Nullifier` with domain tags `NullifierDomainVote = 1` and `NullifierDomainClaim = 2` (`types.go:124-128`).

The work to consume Personhood is therefore (a) replace the identity-issuance side (today vague handwave to "off-chain fuzzy-extractor + on-chain enrollment") with "user holds a Personhood VC" and (b) replace the on-chain `bytes32 biometricCommitment` parameter with "verifier-passed `(commitment, nullifier, proof)` tuple computed from the Personhood `nullifierBinding`".

## Integration boundary

**Personhood's responsibility:** issue a `PersonhoodCredential` (W3C VC) containing `verifiedMethods[]` (at minimum one anchor — `phone-liveness` in v0.1) and an optional `nullifierBinding` (Pedersen-BN254 commitment + the holder's secret scalar `s`). See [03-credential-format.md](./03-credential-format.md) for the full schema.

**OpenLine's responsibility:** integrate the Personhood Go SDK + the Personhood policy DSL. On the read path:
1. Receive a W3C Verifiable Presentation from a user.
2. Verify the issuer's signature, the holder's signature, and the Status List 2021 entry (Personhood SDK does this).
3. Evaluate the credential against an OpenLine-published policy (Personhood SDK does this).
4. Take the policy's `DerivedNullifierRequest` (the binding commitment + the policy's `nullifier_context_tag`) and pass both into OpenLine's existing Circom + Poseidon proving / verifying pipeline to (a) derive the per-action nullifier and (b) build / verify the ZK predicate that the holder owns the secret bound to the commitment.
5. Check the derived nullifier against OpenLine's per-action nullifier store (votes for this election; claims for this cycle).
6. Authorise the action if everything passes.

The key architectural decision is that **Personhood does not compute nullifiers inside its own SDK**. It returns the commitment + tag, and the integrator's ZK system (Circom + snarkjs in OpenLine's case) does the Poseidon derivation inside the constraint system, so the same proof simultaneously asserts knowledge of the secret and binds the nullifier. This keeps Personhood ZK-agnostic and lets OpenLine continue to use its existing Groth16 toolchain.

## File-level migration map

The table below covers every file/directory under `src/suffrage/` and `src/commons/`. "Phase 2" = the OpenLine refactor PR series that integrates Personhood. "Phase 3+" = future cleanup once Personhood v0.2 ships the fuzzy extractor as a hosted anchor method.

| File / Directory | Current Status | Phase 2 Action | Phase 3+ Action | Justification |
|---|---|---|---|---|
| `src/suffrage/fuzzy-extractor/` | Rust prototype, on-device biometric → key | **STAY in OpenLine** | Promote to Personhood as the v0.2 "airdrop-test compliant" anchor method | Production-ready fuzzy extractor is research-track; do not block OpenLine on it. Keep code where it lives; move when Personhood v0.2 lands. |
| `src/suffrage/accumulator/` | Rust RSA accumulator | **STAY in OpenLine** (still used by VoteProof / ClaimProof Merkle paths conceptually replaced by accumulator) | Move to Personhood as part of `pkg/accumulator/`, used by issuer for set-membership of issued credentials | RSA accumulator is fundamentally an identity-set-membership primitive — it belongs with the issuer in the long run, not with the integrator. Phase 2 still uses it for the in-place voting circuits; Phase 3 deprecates this OpenLine copy. |
| `src/suffrage/zk-circuits/circuits/VoteProof.circom` | Circom voting circuit | **STAY** (updates: replace Merkle membership against the OpenLine-local registration tree with a check that the input commitment matches the one in a Personhood `nullifierBinding`; replace the domain-1 Poseidon nullifier with `Poseidon(s, Poseidon(utf8(election_id)))` derivation matching Personhood's spec) | Keep — voting is OpenLine-specific | Voting is OpenLine's concern. The circuit's job changes slightly (input shape) but it remains here. |
| `src/suffrage/zk-circuits/circuits/ClaimProof.circom` | Circom UBI claim circuit | **STAY** (same kind of update: bind to a Personhood commitment instead of an OpenLine Merkle root) | Keep — UBI is OpenLine-specific | Same reasoning. |
| `src/suffrage/zk-circuits/circuits/lib/MerkleProof.circom` | Poseidon Merkle path | **STAY** but DEPRECATE for identity use (only voting-internal uses remain) | Remove if no remaining users | The "user is in the registration tree" check moves to Personhood credential verification; voting may still use Merkle elsewhere. |
| `src/suffrage/zk-circuits/circuits/lib/Nullifier.circom` | Domain-separated Poseidon nullifier | **STAY** but update domain-tag semantics: the tag is now derived from the Personhood `nullifier_context_tag` string rather than the hard-coded `1` / `2` literals | Keep | Reusable; small change. |
| `src/suffrage/zk-circuits/circuits/lib/RangeCheck.circom` | Vote-choice range | **STAY** | Keep | Voting-specific. |
| `src/suffrage/contracts/src/IdentityRevocation.sol` | Identity lifecycle + governance Sybil revocation | **DEPRECATE** (Personhood Status List 2021 replaces the per-credential revocation; OpenLine governance Sybil revocation becomes a Personhood-issuer revocation flow rather than an on-chain operation) | Delete | Personhood owns the credential lifecycle. The Sybil-revocation supermajority logic, if still wanted, moves to a governance contract that calls the Personhood admin revoke API. |
| `src/suffrage/contracts/test/IdentityRevocation.t.sol` | Tests for the above | **DEPRECATE** alongside the contract | Delete | Same as above. |
| `src/suffrage/Cargo.toml`, `Cargo.lock` | Workspace metadata | **STAY** (workspace still has fuzzy-extractor + accumulator) | Reduce or remove if both crates move | Keep until both Rust crates move. |
| `src/commons/src/CommonsPool.sol` | UBI dividend pool | **MODIFY**: replace the `bytes32 biometricCommitment` parameter on `claim()` with a `(bytes32 commitment, bytes calldata zkProof, bytes32 nullifier)` tuple sourced from the Personhood-integrated off-chain verifier. The contract trusts the off-chain integrator to have evaluated the policy before submitting. | Keep, possibly migrate to a per-cycle Merkle-root commitment scheme | Core economic logic stays. The verification surface narrows. |
| `src/commons/src/ClaimVerifier.sol` | Mock ZK proof verifier | **REPLACE** with the real Groth16 verifier generated from the updated `ClaimProof.circom` (the existing `_verifyProof` is documented as a mock at line 49) | Refine for gas; possibly batch-verify | This is the explicit "replace with real Groth16 verifier" comment getting honoured. |
| `src/commons/src/GovernanceParams.sol` | Cycle length, split BPS, etc. | **NO CHANGE** | Keep | Independent of identity. |
| `src/commons/src/StaggeredDistribution.sol` | Per-commitment claim-day staggering | **MODIFY**: input is now the Personhood `commitment` (from `nullifierBinding`) instead of the OpenLine `biometricCommitment`. Same `bytes32`, different provenance. | Keep | Logic unchanged; type stays `bytes32`. |
| `src/commons/src/interfaces/IOLN.sol` | Token interface | **NO CHANGE** | Keep | Unrelated. |
| `src/commons/test/CommonsPool.t.sol` | CommonsPool tests | **UPDATE**: test inputs now come from a mocked Personhood SDK + Circom prover rather than test-supplied raw commitments | Keep | Tests follow the contract changes. |
| `src/commons/test/SecurityCommonsPool.t.sol` | Security tests | **UPDATE** alongside CommonsPool | Keep | Same. |
| `src/commons/test/StaggeredDistribution.t.sol` | Distribution tests | **NO CHANGE** | Keep | Pure-math tests. |

## Code changes in Suffrage (vote eligibility)

The current vote-eligibility check is conceptual (no single function ties enrollment + ZK proof + revocation together; the prototype assumes the voter has somehow already enrolled and submitted a `VoteProof`). After Phase 2, the off-chain voter flow looks like this:

```
BEFORE (today, conceptual):
  voter calls some "submit vote" endpoint with:
    (commitment, election_id, vote_choice, zk_vote_proof)
  endpoint:
    1. verifies zk_vote_proof against VoteProof.vkey
    2. checks the nullifier from the proof's public outputs is not yet spent
    3. checks commitment is in the IdentityRevocation registration tree
       AND in the active-not-revoked set
    4. records the nullifier as spent and the vote_choice
```

```
AFTER (Phase 2):
  voter presents a Verifiable Presentation containing a PersonhoodCredential
  that includes nullifierBinding.
  voter also presents a Circom ZK proof produced client-side, taking
  (s, election_id) as private inputs and (commitment, election_id, nullifier, vote_choice)
  as public inputs.
  the off-chain Suffrage verifier:
    1. policy := load("openline/suffrage/vote/v1")
    2. evalResult := personhood.Evaluate(vp, policy)
        - personhood SDK verifies the issuer signature, holder signature,
          and Status List 2021 entry
        - the policy demands an anchor within 24h + nullifier with tag
          "openline/suffrage/vote/${ELECTION_ID}"
    3. if evalResult.Code != EVAL_PASS: reject
    4. verifies the VoteProof against the snarkjs verifier, asserting:
        a. zk_vote_proof public input `commitment` equals vp.credentialSubject.nullifierBinding.commitment
        b. zk_vote_proof public input `nullifier` equals
            Poseidon(s, Poseidon(utf8(evalResult.derivedNullifierRequest.contextTag)))
            (this equality is enforced INSIDE the Circom circuit)
        c. vote_choice in range
    5. checks the nullifier is not in the per-election spent-nullifier set
    6. records the nullifier as spent and the vote_choice
```

The `IdentityRevocation` contract drops out entirely: revocation is now a Personhood concern, expressed via the credential's Status List 2021 entry. Sybil revocation by OpenLine governance, if still desired, becomes "OpenLine governance contract issues a signed instruction that the Personhood-issuer-of-record honours by flipping the revocation bit", which is a governance integration on the Personhood side, not a Suffrage on-chain primitive.

## Code changes in Commons (UBI claim)

```
BEFORE (CommonsPool.sol:221-278):
  function claim(
      uint256 cycleId,
      bytes32 biometricCommitment,
      bytes calldata proof,
      bytes32 nullifier,
      address payable recipient
  ) external nonReentrant whenNotPaused {
      // staggered eligibility check on biometricCommitment
      // expected nullifier: keccak256("commons-claim", biometricCommitment, cycleId)
      // ClaimVerifier.verifyAndSpend(proof, nullifier);   ← mock verifier
      // pay out perCapita
  }
```

```
AFTER (Phase 2):
  off-chain Commons verifier (Go service):
    1. policy := load("openline/commons/ubi-claim/v1")  // see below for YAML
    2. evalResult := personhood.Evaluate(vp, policy)
    3. if evalResult.Code != EVAL_PASS: reject with code
    4. ctxTag := evalResult.derivedNullifierRequest.contextTag
       (this is "openline/commons/ubi-claim/cycle-${CYCLE_ID}",
        the integrator substitutes ${CYCLE_ID} before evaluation)
    5. expectedCommitment := evalResult.derivedNullifierRequest.commitment
    6. verify Circom ClaimProof such that:
        a. public input `commitment` == expectedCommitment
        b. public input `nullifier` == Poseidon(s, Poseidon(utf8(ctxTag)))
           (enforced inside the circuit; service does not learn s)
    7. service calls CommonsPool.claim(cycleId, expectedCommitment, zkProof, nullifier, recipient)

  CommonsPool.sol:
    function claim(
        uint256 cycleId,
        bytes32 commitment,
        bytes calldata zkProof,
        bytes32 nullifier,
        address payable recipient
    ) external nonReentrant whenNotPaused {
        // staggered eligibility check on `commitment` (was biometricCommitment)
        // NO LONGER: expectedNullifier = keccak256("commons-claim", commitment, cycleId)
        //   because the nullifier is now Poseidon-derived and committed inside the ZK proof
        // verifier.verify(zkProof, [commitment, cycleId, nullifier])  ← REAL Groth16 verifier
        // require !spentNullifiers[nullifier]; spentNullifiers[nullifier] = true;
        // pay out perCapita to recipient
    }
```

The two material changes in the contract are:

1. `biometricCommitment` parameter is renamed `commitment` (semantic shift — the commitment is now a Personhood Pedersen-BN254 commitment, not an OpenLine-internal biometric hash; the type stays `bytes32`).
2. The `keccak256("commons-claim", ...)` nullifier formula is removed. The nullifier is now derived inside the Circom ClaimProof from the holder's secret `s` and the context tag, and the contract trusts the Groth16 verifier to assert that derivation. This collapses the "expected-nullifier" check into the proof verification, simplifying the contract.

The mock `ClaimVerifier` is replaced with a real Groth16 verifier (snarkjs-generated Solidity from the updated `ClaimProof.circom`).

## Suffrage policy YAML (concrete, ships with OpenLine after Phase 2)

```yaml
# File: openline/src/suffrage/policies/vote_casting.yaml
version: "1.0"
policy_id: "openline/suffrage/vote/v1"
action: "Cast a vote in an OpenLine election"
anchor_required: true
max_anchor_method_age_seconds: 86400        # 24h
require_fresh_anchor_proof: true
min_supplementary_points: 0
nullifier_required: true
# ${ELECTION_ID} is substituted by the Suffrage backend before evaluation.
# It MUST be unique per election (e.g. the election's on-chain content hash).
nullifier_context_tag: "openline/suffrage/vote/${ELECTION_ID}"
```

This policy is the operational expression of OpenLine's existing "one human, one vote per election" invariant. The anchor requirement is the one-human guarantee; the nullifier tag instantiates the per-election scope; `require_fresh_anchor_proof: true` is the same intuition that drove OpenLine's original 90-day liveness interval, sharpened to "at the moment of voting".

## Commons policy YAML (concrete, ships with OpenLine after Phase 2)

```yaml
# File: openline/src/commons/policies/ubi_claim.yaml
version: "1.0"
policy_id: "openline/commons/ubi-claim/v1"
action: "Claim UBI dividend for the current cycle"
anchor_required: true
max_anchor_method_age_seconds: 86400        # 24h
min_supplementary_points: 0
nullifier_required: true
# ${CYCLE_ID} is substituted by the Commons backend at evaluation time.
# Maps to the on-chain currentCycleId in CommonsPool.sol:54.
nullifier_context_tag: "openline/commons/ubi-claim/cycle-${CYCLE_ID}"
```

The 24-hour anchor freshness here is the airdrop-test analogue of the 90-day liveness interval in the legacy `IdentityRevocation.sol:40`: instead of forcing the user to re-prove liveness on a fixed cron, we force a fresh anchor at the moment of claim. The anti-replay property OpenLine cares about (one claim per cycle per human) is provided by the per-cycle `nullifier_context_tag`.

## Migration sequence (PR-by-PR)

The plan is to land Phase 2 across five PRs so each step is reviewable and revertible:

1. **PR1 — `personhood-integration-prep`.** Add `github.com/sagearbor/personhood/sdk/go` as a Go dependency at the repo root. Add Personhood verifier SDK wiring in a new `src/suffrage/personhood-verifier/` package, exposed behind a feature flag `OPENLINE_PERSONHOOD_ENABLED=false` (default off). No existing code paths change. Land the policy YAML files. CI: unit tests for the verifier wrapper against a mocked issuer.
2. **PR2 — `suffrage-flip-to-personhood`.** Set the feature flag to true in `staging`, point the Suffrage vote-eligibility check at the new Personhood-backed path, and remove the now-dead pre-Personhood vote-eligibility code. The on-chain VoteProof is unchanged in this PR; only the off-chain enrollment side is rewired. `IdentityRevocation.sol` still exists but is no longer required by the happy path.
3. **PR3 — `commons-flip-to-personhood`.** Same flip for Commons UBI claim. Update `CommonsPool.sol` to rename `biometricCommitment` → `commitment`, remove the `keccak256("commons-claim", ...)` formula, and integrate the new real Groth16 `ClaimVerifier` (generated from updated `ClaimProof.circom`). Includes a Foundry script to deploy the new verifier and re-point `CommonsPool` at it. Migration of existing testnet pools requires a one-time admin call to update the verifier address.
4. **PR4 — `remove-legacy-identity-stack`.** Delete `src/suffrage/contracts/src/IdentityRevocation.sol` and its tests. Remove the in-OpenLine biometric registration tree code paths (where they exist as scaffolding). Move the `BiometricCommitment` type out of `pkg/types/types.go` (it's no longer a cross-OpenLine-module type — Commons just sees `bytes32 commitment`). Update `pkg/proto/openline.proto` accordingly. Drop the `OPENLINE_PERSONHOOD_ENABLED` feature flag.
5. **PR5 — `zk-circuit-split`.** Update the Circom circuits in `src/suffrage/zk-circuits/` so VoteProof and ClaimProof bind to a Personhood Pedersen-BN254 commitment (input shape change) and derive nullifiers using the Personhood-spec'd Poseidon derivation. Update the test vectors in `src/suffrage/zk-circuits/test/`. Regenerate the Groth16 verifier contract. This is the highest-risk PR (constraint counts change, trusted-setup re-run required) and is intentionally last so the off-chain flow has already been validated in staging.

Between PR2 and PR3 we run for ~1 week to catch UX issues. Between PR4 and PR5 we run for ~2 weeks (the Circom changes are non-trivial). The feature flag in PR1 ensures any of PR2–PR4 can be reverted to the legacy path with a single environment variable until they're deleted.

## Documentation updates needed in OpenLine

After Phase 2, the following OpenLine documentation needs updating:

- **`CLAUDE.md`** — the project overview already mentions "On-device fuzzy extractors + TEE, no central biometric database". Reframe: identity is now sourced from a Personhood VC; OpenLine continues to operate on Poseidon commitments but does not issue them. Add a "Personhood Dependency" subsection with the link to this repo.
- **`MODULES.md`** — the module inventory table currently lists `Suffrage/Fuzzy Extractor`, `Suffrage/Accumulator`, `Suffrage/ZK Circuits` as in-OpenLine modules with their language tags. After Phase 2, the inventory adds a row for "Personhood SDK (Go)" as a cross-module dependency. The Cross-Module Data Flow ASCII diagram (`MODULES.md:62-80`) updates so the "Suffrage/ZK Circuits → Suffrage/Fuzzy Extractor → Suffrage/Accumulator" chain becomes "Suffrage policy → Personhood SDK → Personhood Issuer".
- **`docs/WHITEPAPER.md`** — the Identity section needs the largest rewrite: instead of describing OpenLine's bespoke on-device fuzzy extractor as the identity primitive, describe identity as "a Personhood credential the user holds, satisfying the per-action Personhood policy". The whitepaper's commitment to "no central biometric database" continues to hold in Phase 2 (the v0.1 anchor is phone-camera liveness with vendor-side ephemeral processing; the v0.2 fuzzy-extractor anchor restores on-device-only). The 90-day liveness interval section retires in favour of per-action anchor freshness windows.
- **`README.md`** — short note in "Module summary": "Suffrage and Commons consume the [Personhood](https://github.com/sagearbor/personhood) framework for proof-of-personhood; OpenLine focuses on the protocol surface (committee consensus, levy economics, governance)".
- **`SECURITY.md`** — add a section on the trust transitivity OpenLine now inherits from Personhood (issuer compromise, vendor compromise) and the corresponding mitigations (multi-issuer support when Personhood ships it; integrator-side per-issuer trust scoring).

## Backwards compatibility

**None.** OpenLine is pre-v1 and has no production deployments; testnet deployments will be redeployed after the migration. We do not maintain compatibility for existing in-testnet `IdentityRevocation` enrollments or `CommonsPool` claims — those are wiped at the migration boundary. This is documented in the OpenLine v1.0 release notes when it ships post-Phase-2.

If a later real production deployment needs migration, the migration path is: deploy a new CommonsPool with the new verifier, take a snapshot of existing-claimant balances, airdrop them in the new pool, archive the old pool. Out of scope for this design; flagged here for posterity.

## Risks

- **Personhood issuer downtime.** OpenLine actions are blocked when the issuer is unavailable (no new VCs can be minted; existing VCs still verify against cached issuer DID document). Mitigation: pin issuer DID document with a long TTL in the OpenLine verifier; document the dependency in OpenLine's status page; move toward multi-issuer support in Personhood v0.2 so OpenLine can fail over.
- **VC expiry mid-action.** If a user's VC expires between starting a vote and submitting the proof, the action fails with `EVAL_VC_EXPIRED`. Mitigation: the wallet pre-checks expiry before starting the action; the integrator UI surfaces the error code and offers a single-click re-enrollment flow.
- **Performance.** ZK proving (Circom Groth16) on mobile is already the long pole; adding Personhood SDK verification adds tens of milliseconds for signature checks and a single Status List 2021 fetch (cached). The wall-clock impact is negligible relative to the existing proving cost. CI benchmarks the combined flow as part of PR2 / PR3 acceptance.
- **ZK redesign scope.** PR5 (the Circom circuit changes) is the biggest risk in the migration. The input shape of the circuit changes (no more Merkle path against an OpenLine-internal tree; instead a Pedersen commitment opened against a Personhood-issued public commitment), and the constraint count may change materially. A trusted-setup re-run is required. Mitigation: PR5 is last in the sequence, so the off-chain flow is already validated in staging; the off-chain rollout (PR2 + PR3) does not depend on PR5 completing.
- **Trust transitivity.** OpenLine implicitly trusts the Personhood issuer's choice of anchor vendor (FaceTec, Apple, Google) and the issuer's operational security. A compromised issuer can mint arbitrary VCs, which OpenLine would accept. Mitigation (long-term): Personhood v0.3 quorum issuance; OpenLine governance may pin a trusted-issuers list with weights.
- **Operational learning curve.** The OpenLine team has not previously operated against a separate identity issuer. Mitigation: PR1 ships with a runbook (`docs/runbooks/personhood-integration.md`) covering issuer key rotation, revocation propagation, and incident response when the issuer is unavailable.

## Cross-references

- The W3C VC schema and `nullifierBinding` semantics OpenLine integrates against: [03-credential-format.md](./03-credential-format.md).
- The policy DSL OpenLine writes its policies in: [04-policy-dsl.md](./04-policy-dsl.md).
- The Personhood method roster Suffrage and Commons depend on (v0.1 anchor = `phone-liveness`): [02-methods.md](./02-methods.md).
- The system-level architecture and trust model: [01-architecture.md](./01-architecture.md).
