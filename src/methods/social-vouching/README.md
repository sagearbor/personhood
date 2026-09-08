# social-vouching-graph

**Supplementary** verification method (STATUS.md checklist #10b): a
BrightID-style web of trust where already-vouched members vouch for new
members, and a simplified SybilRank-style score decides whether the
candidate has accumulated enough vouches to pass.

| Property | Value |
|---|---|
| Type | supplementary |
| Strength | 35 |
| Cost | $0.00 |
| Friction | high |
| Freshness | 90 days |
| Airdrop test | ✅ passes (no ID/bank/address required) |

## Why supplementary, not an anchor

STATUS.md's checklist #10b calls this "the `social-vouching-graph`
anchor," but `docs/06-methods-catalog.md` Table 2 (supplementary methods)
scores it 35 — below the registry's hard-enforced anchor floor of 50
(`pkg/types/validation.go`'s `MethodMetadata.Validate()` rejects an anchor
method with strength < 50; registering this as an anchor would fail at
server startup, not just be a documentation inconsistency). This
implementation follows the catalog's number: cold-start web-of-trust
vouching alone cannot defeat a well-resourced attacker who bootstraps
their own vouching ring (the catalog's own "cold-start hard" note), so it
composes with an anchor (e.g. `fuzzy-extractor-selfie`) rather than
substituting for one — consistent with this repo's core "anchor +
supplementary, never naive stacking" design constraint (see `CLAUDE.md`).

## Flow (candidate code → out-of-band vouches → threshold check)

1. **BeginCeremony** returns a `candidate_code` (v0.1: the ceremony's own
   `SessionID` — see the scope note below), the out-of-band `vouch_endpoint`
   an existing member POSTs a vouch to, and the configured thresholds.
2. The candidate shares `candidate_code` with an existing vouched member
   (in person, over a call, however the two humans coordinate — this is the
   "high friction" the catalog flags).
3. The voucher's client POSTs `{candidate_id, voucher_id, proof}` to
   `POST /v1/methods/social-vouching-graph/vouch`. The server authenticates
   the voucher (`VoucherAuthenticator`), looks up their current trust score,
   and records the vouch (one per distinct voucher; a repeat vouch from the
   same voucher overwrites rather than double-counting).
4. The candidate's client polls **CompleteCeremony** (ignores its own
   `ResponseData` — the vouches already arrived out-of-band in step 3). Once
   the candidate has both enough *distinct* vouchers (`RequiredVouches`,
   default 3) AND enough cumulative weighted score (`RequiredScore`, default
   1.5 — sum of each voucher's own trust score), the ceremony succeeds: the
   candidate is enrolled into the graph with a decayed trust score
   (`avg(voucher weights) * DecayFactor`, default 0.75) so they can vouch for
   others afterwards — this is what makes it a real, propagating graph and
   not just a fixed-seed allowlist (see
   `TestMethod_CompleteCeremony_ChainedVouchingThroughGraduate`).

| CompleteCeremony outcome | Result |
|---|---|
| enough distinct vouches + enough score | `Success: true` + digest over the vouch set |
| not enough yet | `insufficient_vouches:have=X/N,score=S/T` (poll again later) |

| VouchHandler outcome | HTTP status |
|---|---|
| recorded | 200 |
| bad/missing fields | 400 |
| voucher proof doesn't authenticate | 401 |
| voucher isn't a known graph member | 403 |
| self-vouch | 400 |

## Seeding the graph (`graph.go`)

Every web of trust needs a bootstrap set: `NewInMemoryGraphStore(seeds)`
takes a `map[string]float64` of seed member id → trust score (typically
1.0). Without at least `RequiredVouches` seed members (or a chain of
already-graduated members reachable from them), nobody can ever pass.
`InMemoryGraphStore` is an in-process map, matching every other
`InMemory*` store in this repo — it does not survive a restart or share
state across replicas.

## Voucher authentication (`authenticator.go`) — the fake provider

Unlike `government-id-liveness`/`plaid-bank-link`, there is no vendor to
call here; the "fake provider" pattern the brief for this session asked for
maps onto authenticating a VOUCHER's identity instead. `HMACDevAuthenticator`
mirrors `app-attest-device`'s `HMACDevVerifier`: it recomputes
`HMAC-SHA256(secret, voucherID + "." + candidateID)` and constant-time
compares it to the supplied proof — fully testable without any real
cross-person identity infrastructure. `SignVouchForTesting` produces a
matching proof for tests (mirroring `SignDeviceTokenForTesting`).

**Not a real identity proof**: anyone holding the shared secret can "vouch"
as anyone. Production (v0.2) should have each voucher sign the vouch
statement with their OWN previously-issued Personhood credential's holder
Ed25519 key (see `src/server/did.go`), verified by the server against a DID
it itself issued — i.e. only someone who already holds a valid Personhood
credential can vouch, and their vouch weight derives from how they
themselves reached the graph. That's a materially larger feature (looking
up "does this DID hold a credential that itself passed this ceremony,
transitively, back to a seed") intentionally left as v0.2 work; the
`VoucherAuthenticator` interface is the seam it drops into without changing
anything else in this method.

## Configuration

```go
m := socialvouching.NewMethod(socialvouching.Config{
    Store:         socialvouching.NewInMemoryGraphStore(map[string]float64{
        "operator-seed-1": 1.0,
    }),
    Authenticator: socialvouching.NewHMACDevAuthenticator(os.Getenv("SOCIAL_VOUCHING_SECRET")),
    // RequiredVouches, RequiredScore, DecayFactor all default sensibly if left zero.
})
```

Env vars: `SOCIAL_VOUCHING_ENABLED=1` gates registration in
`BuildDependencies`; `SOCIAL_VOUCHING_SECRET` is the dev-authenticator's
shared secret; `SOCIAL_VOUCHING_SEED_IDS` is a comma-separated bootstrap
seed list (each seeded at trust 1.0) — see `src/server/server.go` and
`RUNBOOK.md`.

## v0.1 scope notes

- **Candidate identity key is the enrollment `SessionID`**, not a stable
  long-term DID. This is internally consistent for the lifetime of one
  server process (every vouch and the eventual `Enroll` call key off the
  same `SessionID`), matching every other `InMemory*` store's process
  lifetime limitation, but means a candidate who wants to vouch for someone
  else in a LATER, separate enrollment session needs their original
  `SessionID` threaded through — not their holder DID. Wiring
  `CeremonyContext` (or a server-side lookup) to carry the holder DID once
  established would let a future session key the graph by DID instead;
  flagged as a follow-up, not done here (see this session's wrapup).
- **No real graph analysis (SybilRank's random walks) — a simplified
  weighted-sum-with-decay approximation.** True SybilRank runs bounded
  random walks from trusted seeds and ranks nodes by landing probability;
  this v0.1 does one multiplicative decay step per admission instead. Good
  enough to demonstrate real trust propagation (see the chained-vouching
  test) without the complexity of maintaining a full random-walk index over
  an in-memory graph that doesn't persist between requests anyway.
