# Post-quantum signatures (experimental)

Status: built, tested, **off by default, not deployed**. The issuer can sign
every credential twice, with Ed25519 (as today) and with ML-DSA-65
(FIPS 204, August 2024). Turning it on needs one secret and a redeploy; see
"Switching it on" below.

## The threat

Personhood credentials are signed with Ed25519. A large enough quantum
computer running Shor's algorithm recovers an Ed25519 private key from its
public key, and the issuer's public key is published at
`/.well-known/did.json`. Whoever holds a recovered key can mint credentials
for people who do not exist, which is exactly the Sybil attack the whole
project exists to stop.

No such computer exists today, and estimates of when one might range from
about a decade to never.

**Harvest-now-forge-later matters less here than for encryption.** Recorded
*encrypted* traffic can be decrypted years later, so encryption has to move
first. A signature is different: a forged credential is only useful while
verifiers still accept the broken algorithm. If verifiers move to requiring
the PQ signature before a quantum computer arrives, old Ed25519 signatures
stop mattering. So the work is to have the second signature in place, and a
tested switch, well before it is needed; it does not have to be live now.

## What the change does

- `pkg/types.Proof` gains an optional `pqProof` object:
  `{type: "DataIntegrityProof", cryptosuite: "mldsa65-jcs-personhood-v1",
  verificationMethod, proofValue}`. The shape follows W3C Data Integrity;
  the cryptosuite name is Personhood's own, not a registered one.
- Both signatures cover the same bytes: the RFC 8785 (JCS) canonical
  credential without `proof`. ML-DSA uses the FIPS 204 context string
  `personhood-credential-v1` and hedged (randomized) signing.
- `pqProof` sits **inside** `proof`, which is stripped from the signing
  input. A verifier that has never heard of it (today's OpenLine node and
  wallet, the TypeScript SDK) verifies the Ed25519 proof exactly as before.
  A tested case drops `pqProof` on the wire and verifies what remains.
- The DID document lists the ML-DSA key **after** the Ed25519 key, as a JWK
  with `kty: "AKP"`, `alg: "ML-DSA-65"` (IETF draft-ietf-cose-dilithium), id
  `#key-pq-1`. Verifiers that read the first entry keep finding Ed25519.
- `/v1/config` reports `pq_proof`.
- The algorithm lives in its own Go module, `src/credential/pq`
  (cloudflare/circl v1.6.3, which implements final FIPS 204 and ships the
  NIST ACVP test vectors). `src/credential` gains only two small interfaces
  (`PQSigner`, `PQVerifier`), so modules that build against it, OpenLine
  included, take on no new dependency.

### Verifier modes

| `Verifier` setting | Ed25519-only credential | hybrid credential |
|---|---|---|
| no `PQ` (today) | checks Ed25519 | checks Ed25519, ignores `pqProof` |
| `PQ` set | checks Ed25519 | checks both |
| `PQ` + `RequirePQ` | **rejected** (`ErrPQProofMissing`) | checks both |

Only `RequirePQ` gives post-quantum security. Someone who can forge Ed25519
can also strip `pqProof` and re-sign the rest, so a verifier that still
accepts Ed25519-only credentials is no safer than before.

## Cost

| | Ed25519 | ML-DSA-65 |
|---|---|---|
| public key | 32 B | 1,952 B |
| signature | 64 B | 3,309 B |
| sample credential JSON | 835 B | 5,400 B (hybrid) |

A credential grows about 6.5 times. That matters for QR codes (a hybrid
credential no longer fits in one) and for anything stored per person on a
chain; it does not matter for HTTPS.

Speed: in the one measurement made so far, ML-DSA-65 signing cost about
ten Ed25519 signatures and verification was in the same range as Ed25519.
That run was on a laptop with a load average near 200 (absolute times were
inflated about fifty-fold), so only the ratios mean anything; re-run on an
idle machine before quoting absolute numbers. Either way the issuer signs a
handful of credentials per minute, so signing cost is not a constraint. The
benchmarks are in `src/credential/pq/mldsa_test.go`
(`go test -bench . ./...` in that module).

## Migration plan

1. **Now (this change):** code and tests merged, switch off.
2. **Issue hybrid credentials:** create the secret, redeploy (see below).
   Nothing breaks; credentials get bigger. Every credential issued from then
   on can later be checked under `RequirePQ`.
3. **Verifiers learn PQ:** OpenLine's node adds `pq.Verifier` with the
   issuer's ML-DSA key pinned next to the Ed25519 one; the TypeScript
   wallet needs an ML-DSA verifier (for example `@noble/post-quantum`).
4. **Re-issue:** credentials expire after a year, so a year after step 2
   every live credential is hybrid. Earlier, users can simply re-enroll.
5. **Require PQ:** verifiers turn on `RequirePQ`. From then on, a broken
   Ed25519 key alone mints nothing.

Steps 3 to 5 are OpenLine changes and an owner timing decision. Holder
keys (the `did:key` the wallet signs presentations with) and OpenLine's own
transaction signatures are Ed25519 too and need the same treatment; this
change covers only the issuer's credential signature.

## Switching it on

```bash
openssl rand -base64 32 | tr -d '\n' | gcloud secrets create personhood-issuer-mldsa-key --data-file=- --project arborfam-hub
# then redeploy with scripts/deploy-cloudrun.sh: it attaches the secret
# when it exists, and /v1/config should report pq_proof: true
```

The seed is the private key: never log it, never rotate it casually
(rotating means re-issuing or publishing both keys for a while).

## What this does not protect against

- **A practical P = NP algorithm.** ML-DSA rests on lattice problems that
  are believed hard even for quantum computers. A constructive, efficient
  proof that P = NP would break it along with essentially all other
  public-key cryptography and make secure hash functions invertible in
  practice. Nothing deployable survives that except information-theoretic
  schemes such as one-time pads. Most researchers expect P ≠ NP, and a proof
  either way need not yield a fast algorithm.
- **A stolen issuer key.** Post-quantum math does nothing if the seed leaks.
- **Unsigned proof metadata.** As with the Ed25519 proof today, the
  `pqProof` fields themselves are not covered by any signature. A verifier
  resolves the key by the issuer DID, not by the `verificationMethod`
  string, so this does not let anyone substitute a key.
