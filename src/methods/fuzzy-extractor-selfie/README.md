# fuzzy-extractor-selfie

**Anchor** verification method (STATUS.md checklist #10a): the
airdrop-test-compatible anchor for users with no government ID, no bank
account, and no fixed address. Unlike `government-id-liveness` (Persona) or
`plaid-bank-link` (Plaid), this method wraps **no third-party vendor** — the
whole implementation is self-contained Go, so there is nothing to sign up
for and no vendor credential to configure.

| Property | Value |
|---|---|
| Type | anchor |
| Strength | 70 |
| Cost | $0.00 |
| Friction | med |
| Freshness | 180 days |
| Airdrop test | ✅ passes (no ID/bank/address required) |
| Platforms | any (needs a camera, on the client) |

## Two modes

- `SELFIE_ANCHOR=1` (the phone-ready mode): the web app runs a real
  on-device face model (MediaPipe Face Landmarker + dlib's face-recognition
  ResNet via face-api) and a randomized active-liveness ceremony; the issuer
  checks a signed challenge token and the ceremony timing (`liveness.go`),
  keeps the accumulator in Firestore or Redis, and advertises strength 50.
  What it proves, measured error rates and the threat model:
  [docs/selfie-anchor.md](../../../docs/selfie-anchor.md). Short version:
  useful against casual double enrollment in a small cohort, not a
  Sybil-resistant anchor, because a browser cannot prove its camera is real.
- `FUZZY_EXTRACTOR_ENABLED=1` (the original dev mode, described below):
  template only, no liveness, in-memory accumulator, strength 70.

The two flags are exclusive.

## Flow (selfie → on-device template → fuzzy-extractor dedup)

1. **BeginCeremony** returns instructions only — unlike the nonce-based
   ceremonies elsewhere in this repo, there's no server-side state to bind
   ahead of time; the whole ceremony input arrives in one shot.
2. The client captures a selfie, runs on-device liveness + face-embedding
   extraction (an ML model; out of scope for this Go module — see
   "What this module does NOT do" below), binarizes the embedding to a
   fixed `TemplateBytes`-length (32-byte / 256-bit) template, and POSTs it
   base64-encoded as `template_b64`.
3. **CompleteCeremony** decodes the template and asks the `Accumulator`
   whether it duplicates an already-enrolled person — a linear scan
   attempting the fuzzy-extractor `Rep` operation against every previously
   stored helper-data record (see `accumulator.go`). A duplicate means this
   biometric already has a Personhood identity: reject as Sybil
   (`duplicate_person_detected`). Otherwise this is a new person: `Gen`
   derives fresh helper data + a `Commitment`, both are stored, and the hex
   `Commitment` becomes the method's `AttestationDigest`.

| CompleteCeremony outcome | Result |
|---|---|
| new person | `Success: true` + `AttestationDigest` = hex commitment |
| already-enrolled biometric (even with noise) | `duplicate_person_detected` |
| no template in the request | `missing_template` |
| template isn't valid base64 | `invalid_template_encoding` |
| wrong decoded length | `invalid_template_length:want=32,got=N` |

## The fuzzy extractor (`extractor.go`)

A fuzzy extractor solves a specific problem: two selfies of the same
person never produce a bit-identical template (lighting, angle, sensor
noise), yet the server needs a STABLE, non-reversible identity commitment
that only a genuine re-reading of the same person reproduces — without ever
storing a raw biometric.

This is a from-scratch, pure-Go implementation of a **Juels-Wattenberg
fuzzy commitment scheme**: `Gen(template)` XOR-masks the template against a
random repetition-code codeword to produce public "helper data" plus a
`SHA-256`-derived `Commitment`; `Rep(template', helper)` recovers the same
`Commitment` if `template'` is close enough (within a Hamming-distance
budget) to the original, and reports no match otherwise. See the doc
comment at the top of `extractor.go` for the full construction and its
known v0.1 simplifications (a repetition code instead of a proper
BCH/Reed-Solomon secure sketch).

**Why not FFI-wrap the OpenLine Rust prototype?** STATUS.md's checklist
pointed at `openline/src/suffrage/fuzzy-extractor/` as the reference
implementation. This module does not bind to it: cgo/FFI-bridging a
separate repo's Rust crate into this repo's plain-net-client Go modules
would be a large, repo-wide dependency-shape change disproportionate to one
method, and per this session's working rules, work was scoped to the
`personhood` repo only. The construction implemented here is the same
well-known primitive (fuzzy commitment / secure sketch), independently
implemented in Go to match this repo's "no new dependency, dependency-free
vendor-style client" convention.

## Server-side accumulator (`accumulator.go`)

`Accumulator` is the "no central biometric DB" membership set. It stores
only public helper data (XOR-masked, not the raw biometric) and one-way
`Commitment` hashes — never a raw template. `InMemoryAccumulator` is an
`O(n)`-scan implementation suitable for dev/tests/single-process
deployments (matching every other `InMemory*` store in this repo); a
production deployment at scale should bucket records with a
locality-sensitive hash (LSH) over the template space so only a shortlist
of plausible candidates is scanned per enrollment.

## nullifierBinding integration

`src/server/did.go`'s `NullifierBindingForBiometricCommitment` derives the
issued credential's `nullifierBinding` from this method's
`AttestationDigest` when it is the credential's anchor, in preference to
the holder's device keypair (`NullifierBindingForHolder`). That ties the
per-context nullifier to the **person** (their biometric commitment) rather
than to whichever device key they happened to generate for a given
enrollment session — the anti-Sybil property OpenLine's UBI-claim / vote
use cases need from an airdrop-test anchor: generating a new holder keypair
alone cannot mint a second nullifier for the same person. See
`src/server/handlers.go`'s `handleIssueCredential`.

## What this module does NOT do

- **No on-device ML here.** Face detection, liveness checks, and embedding
  extraction happen in the client app (`app/web/lib/face`), not in this
  module. This module accepts an already-binarized template and
  is agnostic to how it was produced — tests use
  `RandomTemplateForTesting()` / `NoisyTemplateForTesting()` as stand-ins,
  mirroring `SignDeviceTokenForTesting` in `app-attest-device` and
  `SignWebhookForTesting` in `plaid-bank-link`.
- **Liveness is client-side.** With `SELFIE_ANCHOR=1` the server issues
  the challenge order and checks the token and timings, but every
  measurement is made by the client; a scripted client or a virtual camera
  is not stopped (docs/selfie-anchor.md).
- **Durable accumulators live in the server.** `src/server/accumulator_store.go`
  has Firestore and Redis implementations used under `SELFIE_ANCHOR=1`.
  Enrollment is serialized per process; several issuer replicas sharing one
  store could race (the reference deployment runs one instance).

## Configuration

```go
m := fuzzyextractorselfie.NewMethod(fuzzyextractorselfie.Config{
    Accumulator: fuzzyextractorselfie.NewInMemoryAccumulator(),
})
```

No environment variables or vendor credentials are required — see
`src/server/server.go`'s `BuildDependencies` for how it's registered
(gated behind `FUZZY_EXTRACTOR_ENABLED=1`, an explicit opt-in rather than
always-on, consistent with every other anchor/supplementary method that
isn't the round-1 email/SMS baseline).
