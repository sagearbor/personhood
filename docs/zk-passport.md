# Zero-knowledge passport (`document-chip-zk`)

Status: **design + phase-1 spike**. Nothing here is wired into the issuer.
The existing `document-chip` method (docs/document-chip-anchor.md) is
unchanged. The new method id is `document-chip-zk`, off by default.

## The problem, in one table

| | `document-chip` (today) | `document-chip-zk` (this design) |
|---|---|---|
| What the phone sends | DG1 (name, document number, birth date, MRZ), EF.SOD, DSC, AA signature | Four zero-knowledge proofs (4 × 14.6 KB) plus 14 public numbers |
| What the issuer learns | Everything in DG1, then drops it | That *some* passport chained to a CSCA in our list is valid today, and one opaque per-passport number |
| Country | Learned (from the CSCA) | Not learned |
| Photo (DG2) | Stays on the phone | Stays on the phone |
| Same passport twice | Same identifier, same identity | Same identifier, same identity |
| Clone resistance (AA) | Yes, when the chip has DG15 | Not in phase 2 (see "Active Authentication") |

The goal is the right-hand column: the name, document number, birth date and
photo never leave the phone, and the issuer still issues one identity per
passport.

## Prior art (surveyed 2026-11-04)

| | Self (selfxyz) | **zkPassport** | Rarimo | Google longfellow-zk |
|---|---|---|---|---|
| License | Circuits MIT; **app and Go SDK BUSL-1.1** until 2029; TEE prover server unlicensed | **Apache-2.0** (circuits, noir_rsa, noir-ecdsa, noir-bignum, noir_rs, sdk). `zkpassport-packages` (the `@zkpassport/utils` input builder) and `noir_bigcurve` carry **no license file** | MIT | Apache-2.0 |
| Proof system | Circom + Groth16 (per-circuit trusted setup, PSE ceremony) | Noir + UltraHonk (Barretenberg), universal setup, no ceremony | Circom/Groth16; a Noir port on old toolchains | Ligero + sumcheck: hash-based, transparent |
| Algorithms | RSA, RSA-PSS, ECDSA (secondary source) | RSA PKCS#1 v1.5 and PSS 1024–4096 (CSCA up to 6144); ECDSA NIST P-192…P-521, brainpool 192r1…512r1; SHA-1/224/256/384/512, every combination (checked in the repo) | RSA/PSS 2048–4096, P-256, brainpool 256/384/512, P-521 | ECDSA/SHA-256 only. **No RSA, no ICAO passport support** |
| CSCA → DSC | Merkle tree of ~500 CSCAs, root set by one owner key on chain; DSC tree on chain | `certificate_registry_root` = Poseidon2 Merkle tree of CSCAs (plus revocation and master-list roots, bound but not checked in-circuit) | On-chain SMT filled from the ICAO master list | n/a |
| Nullifier | Hash of signed attributes: anyone who has read the chip can compute it | Poseidon2(DG1, eContent, SOD signature), scoped; optional OPRF salt verified in-circuit | Hash of signed attributes + user secret | n/a |
| Active Authentication | No | No | **Yes**: circuit commits to DG15 key, contract checks the AA signature | n/a |
| Where proving runs | **Registration proofs run in a vendor TEE that sees the passport data** | On the phone (noir_rs); cloud prover only for public-data DSC proofs and the final recursion | On the phone (2.7–2.9 GB peak); "light" mode delegates the signature check to Rarimo | Phone (~1.2 s for an mdoc) |
| Audit | zkSecurity, 2025 (three reports) | **None published** | Halborn, 2024 | Lean proofs for ECDSA circuits |
| Activity | Active | Very active (last push 2026-11-03, v0.21.1) | Slow (last tag 2025-02) | Active |

Sources: github.com/zkpassport/circuits (read directly for this doc),
docs.zkpassport.id/faq, github.com/selfxyz/self, docs.self.xyz,
reports.zksecurity.xyz, github.com/rarimo/passport-zk-circuits(-noir),
github.com/google/longfellow-zk. Self's algorithm range and zkPassport's
registry-admin details come from a secondary write-up and were not checked.

### Choice: zkPassport's circuits

- Apache-2.0, proves on the phone, no trusted-setup ceremony to trust, and
  the widest algorithm coverage (the passports of the world are a long tail
  of RSA and ECDSA variants). Vocdoni already reuses these circuits, which
  shows they can be reused outside zkPassport.
- Self is out: its prover for the heavy step is a vendor-run TEE that sees
  the passport, and its app/SDK are BUSL. Rarimo's AA design is worth
  copying, but its memory use (>2.5 GB) fails the $50-phone test and its
  toolchain is stale. longfellow-zk has no RSA, so it cannot read most
  passports.
- Two risks we accept knowingly: **no published audit** of zkPassport's
  circuits, and `@zkpassport/utils` (the TypeScript that turns a passport
  into circuit inputs) has **no license file**. The circuits themselves are
  Apache-2.0. Before shipping: ask zkPassport to add a license to
  `zkpassport-packages` (or write our own input builder; it is about 1,500
  lines of mostly ASN.1 slicing), and fund or find an audit of the subset of
  circuits we enable.
- We use **our own certificate registry root**, not zkPassport's on-chain
  registry, so trust stays with this issuer's operator (and later with
  OpenLine governance), not with a third party's admin key.

## How the proof is built

zkPassport splits the proof into four sub-proofs. Each one outputs a salted
commitment that the next one takes as its first public input. The salts are
random and stay on the phone, so the commitments reveal nothing, but a proof
of one passport cannot be chained to a proof of another.

```
  dsc ──comm──▶ id ──comm──▶ integrity ──comm──▶ expiry
   │                                               │
   └ registry root (public)        current date, scope, nullifier (public)
```

| Sub-proof | Proves | Public inputs |
|---|---|---|
| `dsc` (sig_check_dsc_…) | A CSCA in the published registry (Merkle path) signed this DSC | registry root, commitment out |
| `id` (sig_check_id_data_…) | That DSC signed EF.SOD's signed attributes | commitment in, out |
| `integrity` (data_check_integrity_…) | The signed attributes hash eContent; eContent lists the hash of DG1 (and DG2) | commitment in, out |
| `expiry` (compare_expiry) | DG1's expiry date is on or after `current_date`; outputs the scoped nullifier | commitment in, current date, scope, subscope, parameter commitment, nullifier type, nullifier, OPRF key hash |

The circuits also tie the country together: the CSCA's registry leaf carries
a country, and the `id` circuit rebuilds the incoming commitment with the
issuing state read from DG1, so a DSC from one state's CSCA cannot sign a
passport claiming another state. That is the same "a state mints only in its
own namespace" property `document-chip` has today.

There is no outer recursive proof. zkPassport adds one (about 84 s and 11 GB
on a server) to get a single proof for Ethereum. The issuer can simply check
four proofs: it takes about 40 ms.

Which circuit variant the phone uses depends on the passport's algorithms
(about 280 DSC and 280 ID-data variants, 25 integrity variants). zkPassport's
`circuit-matcher` picks the variant; the issuer accepts only verification
keys from its own pinned list.

### What the proof states, exactly

1. A CSCA in registry root *R* signed a DSC (any DSC; the DSC itself stays
   private). *R* is one of the roots this issuer has published.
2. That DSC signed this document's EF.SOD.
3. EF.SOD's hashes cover a DG1 whose issuing state is the CSCA's state.
4. DG1's expiry date is on or after `current_date`, which the issuer checks
   is today (±36 h for time zones).
5. `nullifier = Poseidon2(private_nullifier, scope, subscope)`, where
   `private_nullifier = Poseidon2(DG1 ‖ eContent ‖ SOD signature)`.

Optional disclosures (nationality, age over N) are separate zkPassport
circuits that chain from the same `integrity` commitment. They are **off by
default**; a policy that needs one would ask for that extra proof.

## The nullifier

**Unguessable without the chip.** The private nullifier includes the
SOD signature. The signature is not printed anywhere; you only get it by
reading the chip. Someone with a photocopy of the data page (name, number,
birth date, MRZ) cannot compute it. That rules out a design that hashes only
DG1 or the document number: those are printed, so anyone who has seen the
page could test whether that passport enrolled.

Who *can* compute it: anyone who has read the chip once (a hotel, an airline,
a border kiosk). They can also replay the chip's files today, so this is not
a new exposure. The issuer adds a second layer, as it does now: it keys the
nullifier with `HMAC(IDENTIFIER_HMAC_KEY, "document" ‖ "chip:ZK:<nullifier>")`
before it is stored or bound to a seed. Without the server key, a stolen
database cannot be tested against a chip dump.

**Stable.** The same passport gives the same nullifier every time (the
spike checked this: two independent proving runs, different random salts,
same nullifier). So enrolling again re-issues the same identity, exactly as
`document-chip` does. The scope is fixed per issuer (`"personhood"` in the
spike; phase 2 uses a Poseidon2 hash of `personhood:document-chip-zk:v1`).
Subscope is 0.

**Renewed, replaced, second passports.** A new passport has a new SOD, so it
gets a new nullifier. This is the same edge case `document-chip` already has
with a new document number, and it gets the same answer: **route, never
refuse.** The phone sends its optional 32-byte face template; the issuer
checks the document-only face index; on a match with a different document it
issues the credential and records a review case (docs/document-chip-anchor.md
"Dual citizens, renewals"). The two methods' identifiers differ for the same
passport (`chip:UT:…` vs `chip:ZK:…`), so someone who enrolled with
`document-chip` and then with `document-chip-zk` is the same edge case and is
routed the same way.

**Later: an OPRF salt.** zkPassport's circuits can verify an OPRF output
in-circuit (BabyJubJub vOPRF, TACEO's oprf-nr). With the issuer holding the
OPRF key, the nullifier that leaves the phone is already keyed: even a chip
reader cannot compute it, and the issuer never sees the unkeyed value. This
matters once nullifiers are published (for example on the OpenLine chain).
While the issuer only stores HMACed values it adds little, so it is phase 3.

## Active Authentication and clones

A chip dump replays perfectly through passive authentication, with or
without zero knowledge. AA is what stops it: the chip signs a fresh issuer
challenge with a key that cannot be extracted (DG15 holds the public key,
and EF.SOD covers DG15).

Options:

| Option | What leaks | Work |
|---|---|---|
| A. Out of circuit: phone sends DG15 public key + AA signature; a circuit proves DG15's hash is in eContent and outputs `Poseidon2(DG15)` | The DG15 public key is a stable, unique per-chip number. Not personal data, but a linkable identifier that every AA reader sees | Small: one new integrity-style circuit that also outputs a DG15 commitment (Rarimo's pattern) |
| B. In circuit: verify the AA signature over the issuer's challenge inside a circuit chained from `integrity`; the challenge is a public input | Nothing beyond today's proof | Medium: AA is usually RSA with ISO/IEC 9796-2 scheme 1 (SHA-1), sometimes ECDSA. New Noir circuit, roughly the size of an `id` sub-proof (~170–230 k gates) per algorithm |

Recommendation: **B in phase 3.** It keeps the "nothing leaves the phone"
property and doubles as session binding (the issuer's challenge is inside the
proof). Until then `document-chip-zk` is passive-only, which is the same
footing as `DOCUMENT_CHIP_ALLOW_PASSIVE_ONLY=1` today: strength **70**, not 80.
Chips without DG15 stay at 70 in either design.

### Session binding (needed before launch, phase 2)

The four proofs are not tied to an issuer session. Anyone who obtained a
person's bundle within the ±36 h date window could submit it and get a
credential for that person's identity. The wallet sends the bundle over TLS
from the holder's own phone, so the exposure is small, but it must be
closed. zkPassport's `bind` circuit takes the same inputs as `expiry`, also
checks that the document has not expired, outputs the same nullifier, and
commits to up to 509 bytes of custom data. Phase 2 swaps `expiry` for `bind`
(still four proofs) with the data set to the issuer's session challenge and
the holder's DID key. The issuer then checks that commitment, which needs a
Poseidon2 (Barretenberg parameters) in Go. AA option B would also provide
this.

## Face bind stays on the phone

Unchanged from `document-chip`: the phone compares the chip photo (DG2) with
a live selfie that passed the active-liveness check, and sends only `match`,
`liveness` and the optional 32-byte template for the dual-document index. The
DG2 hash is already inside the proof chain (the `integrity` commitment
carries it), so the photo the phone compared is the chip's photo *if* the
app is honest. The face match itself is a claim by the app, as today: pair
the method with `app-attest-device` (Android Key Attestation) to make lying
expensive. zkPassport has `facematch` circuits that verify an Android/iOS
attestation of the match in-circuit; worth a look in phase 3.

## How the issuer verifies (Go)

`src/methods/document-chip/zkproof` (this branch) does it:

1. Shape: each sub-proof is 14,656 bytes; public inputs are 2, 2, 2 and 8
   fields.
2. Chain: `dsc.out == id.in`, `id.out == integrity.in`,
   `integrity.out == expiry.in`.
3. Registry root is one this issuer published; scope/subscope are ours;
   `current_date` is today; nullifier type is "non-salted, real document"
   (mock documents from zkPassport's test state ZKR are refused unless a test
   flag allows them).
4. Each sub-proof verifies under a verification key from the issuer's own
   pinned list, and the circuit name matches its stage (no proving `id` with
   an `integrity` vk).
5. Verification runs Barretenberg's `bb verify` (pinned 5.0.0). There is no
   native Go UltraHonk verifier. The `bb` binary ships in the npm package
   `@aztec/bb.js` for macOS and Linux (x86-64 and arm64), so the Docker image
   copies one file. It is MIT licensed.

The result is the identifier `chip:ZK:<nullifier hex>`, which goes through
the existing identifier path unchanged (kind `document`, HMAC under
`IDENTIFIER_HMAC_KEY`, random seed, `NullifierBindingForIdentifierSeed`). The
credential is the same W3C VC with the same `nullifierBinding` scheme the
issuer issues today. No new storage.

Refusals, each with a next step (no false lockout):

| Reason | Meaning | Next step |
|---|---|---|
| `zk_registry_unknown` | Proof used a registry root we don't publish (stale app cache) | Wallet refreshes the registry and proves again, automatically |
| `zk_circuit_unsupported` | The passport needs a circuit variant we don't serve | Offer `document-chip` (sends DG1) or selfie/vouch |
| `zk_csca_untrusted` | The CSCA is not in the registry, so the phone could not even build the proof | Same as `csca_untrusted` today |
| `zk_proof_invalid`, `zk_chain_broken` | Bad or mixed proofs | Prove again; if it repeats, another path |
| `zk_date_stale` | `current_date` is not today (clock wrong, or old bundle) | Fix the clock / prove again |
| `zk_document_expired` | The phone cannot prove "not expired" | Use a valid document, or another path |
| `zk_device_too_weak` | Not enough memory to prove | Fall back to `document-chip` with consent, or a helper-proved `dsc` step (below), or selfie/vouch |

## The CSCA registry root

- **Source:** the same BSI German master list the issuer already embeds and
  verifies (609 CSCAs, pinned signer). One leaf per CSCA, in zkPassport's
  v1 leaf format: `Poseidon2(tags, type, country, public key, expiry,
  fingerprint)`. Root = `Poseidon2(version‖timestamp, Poseidon2(certificate
  root, revocation root, master-list root))`.
- **Build:** a release-time script (Node, `createPackagedCertificatesFile`
  from `@zkpassport/utils`, or our own port) writes
  `registry-<timestamp>.json`: the certificates, the serialized tree and the
  root. Everything in it is public certificate data.
- **Publish:** the issuer serves the current file at a static URL; phones
  download it (about 1 MB for 600 CSCAs) and build their Merkle path
  locally, so the issuer does not learn which CSCA a phone used. The issuer
  accepts the current root and the previous ones for 60 days, because phones
  cache the file.
- **Update:** whenever the master list is refreshed (the existing runbook in
  docs/document-chip-anchor.md, at least quarterly), rebuild the file, commit
  the new root to the issuer's accepted-roots list, open a PR, redeploy.
  Who decides is the issuer operator today. For OpenLine, Suffrage
  governance can own the root later.
- **Not checked in-circuit:** CSCA revocation. Like `document-chip`, CRLs are
  not used yet; zkPassport binds a revocation root but its circuit does not
  check it.

## Post-quantum

- UltraHonk is a pairing-based SNARK on BN254 with KZG commitments. A large
  quantum computer could **forge** such proofs. The zero-knowledge
  property of the proofs already made is not expected to fall with it, since
  the masking is statistical, but this has not been checked in detail.
- This matters less than it sounds here: proofs are checked once, at
  enrollment, and not stored. A future forger could only make *new*
  enrollments, and by then the issuer must switch proof systems anyway. The
  passport PKI itself is RSA/ECDSA, which the same quantum computer breaks:
  states must move to post-quantum CSCAs before any passport proof is
  quantum-safe.
- No hash-based passport prover with phone benchmarks exists today.
  longfellow-zk (Ligero, Apache-2.0, hash-based, fast on phones: about 60 ms
  per ECDSA signature) is the closest, but it has no RSA and no ICAO
  circuits. Writing RSA-2048/4096 for it is real research work. Hash-based
  proofs are also larger (about 300 KB vs 15 KB). Revisit when longfellow or
  a STARK stack ships RSA, or when states start issuing ECDSA-only passports
  at scale.

## Strength and limits compared with `document-chip`

| | `document-chip` | `document-chip-zk` (phase 2) |
|---|---|---|
| Privacy toward the issuer | Sees DG1 in memory | Sees nothing personal, not even the country |
| Uniqueness | One identity per document number per state | One identity per passport (SOD); renewals route |
| Forgery of passport data | Impossible without a state key | Same (soundness of the proof system, unaudited circuits) |
| Clone/replay of chip files | Stopped by AA when present | **Not stopped** until AA-in-circuit (phase 3) |
| Strength | 80 (70 passive-only) | 70 |
| Phone requirements | NFC | NFC + about 650 MB free RAM + 30–90 s (estimated, below) |
| Expired documents | Refused with next step | Same |
| CSCA trust | Issuer's master list | Same list, as a Merkle root |
| Trust in third-party code | JMRTD, Go stdlib crypto | Plus zkPassport circuits (unaudited), Barretenberg, Noir |

## Phase-1 spike: what was run

`spikes/zk-passport/run.sh` proves the personhood test vectors
(`src/methods/document-chip/icao/testdata`, specimen state Utopia "UTO")
with zkPassport's circuits at commit `11b5e04` (2026-11-03), Noir
1.0.0-beta.22 (`noir_wasm`, no nargo needed), Barretenberg 5.0.0, then runs
the Go verifier tests. Proofs from that run are committed as Go test
fixtures in `src/methods/document-chip/zkproof/testdata`.

Measured on an Apple M4 (10 cores), native `bb`:

| Vector | Sub-proof | Gates | Witness (s) | Prove, all cores (s) | Prove, 1 thread (s) | Peak RAM (MB) |
|---|---|---|---|---|---|---|
| p256 (CSCA+DSC P-256, SOD ECDSA-SHA384) | dsc | 154,809 | 0.9 | 0.9 | 2.7 | 410 |
| | id | 232,724 | 1.2 | 1.2 | 3.9 | 630 |
| | integrity | 223,628 | 0.9 | 1.1 | 3.7 | 570 |
| | expiry | 82,195 | 0.2 | 0.5 | 1.4 | 220 |
| rsa-pss (CSCA RSA-3072, DSC RSA-2048 PSS) | dsc | 214,504 | 0.3 | 1.1 | 3.6 | 540 |
| | id | 171,357 | 0.3 | 0.9 | 2.9 | 430 |
| | integrity | 79,338 | 0.04 | 0.6 | 1.5 | 190 |
| | expiry | 82,195 | 0.2 | 0.5 | 1.4 | 250 |

- **Proof size:** 14,656 bytes per sub-proof, 58.6 KB for the bundle, plus
  14 × 32 bytes of public inputs. Verification keys: 3,680 bytes each.
- **Verify time:** about 8 ms per sub-proof with `bb verify` (process start
  included); the Go verifier checks all four in 33–41 ms.
- **Totals:** p256 about 4 s on all cores, about 15 s single-threaded
  (witness + prove); rsa-pss about 3 s / 10 s.
- **Phone estimate (not measured):** a $50–100 Android phone (Cortex-A53/A55)
  is roughly 5–8× slower per core than an M4 P-core. Expect **30–90 s** for
  the four proofs with 4 threads and **about 650 MB peak**. zkPassport's
  FAQ reports 10–50 s for base proofs and under 1 GB for RSA passports on
  their app, which fits. Brainpool-512 and P-521 passports peak higher
  (zkPassport: up to 2 GB). Phones with 2 GB RAM are borderline for those.
- **Negative checks (Go tests):** a flipped nullifier, a flipped proof byte,
  an unpublished registry root, another scope, a stale date, an untrusted
  vk, two sub-proofs swapped, and sub-proofs from two different passports
  are all refused.

What did not work out of the box, and the workaround (all in `run.sh`; none
changes a circuit):

- `curl | bash` installers for nargo/bb were blocked in this environment, so
  the spike uses the npm packages: `@noir-lang/noir_wasm` to compile and
  `@aztec/bb.js`, which ships the native `bb` binary.
- `noir_wasm` resolves `sha256/sha256.nr`'s submodules one directory too
  high (nargo does not): the file is moved to `sha256/mod.nr`.
- `noir_wasm` keys library sources by alias, and two different crates are
  both aliased `common`: one alias is renamed.
- `noir_wasm` cannot fetch a git dependency whose URL ends in `.git`
  (noir-date): the archive is prefetched.
- `@zkpassport/utils` maps the DSC's 2-letter country through an ISO table
  that lacks the specimen state "UT"; the spike patches the parsed view
  (not the signed bytes) to "UTO". Real states do not need this.

CI and production should compile with `nargo` 1.0.0-beta.22, which avoids
the first three.

## Phase 2 plan

| # | Work | Estimate |
|---|---|---|
| 1 | **Issuer method** `document-chip-zk` (off unless `DOCUMENT_CHIP_ZK=1`): wrap `zkproof` as a `types.Method`, begin/complete ceremony, refusal reasons above, identifier kind `document`, strength 70, face-bind payload reused, `bb` in the Docker image, pinned vk manifest embedded. Tests with the committed fixtures. | 3 days |
| 2 | **Session binding**: replace the `expiry` sub-proof with `bind` (session challenge + holder DID; it also checks expiry), and the Go check of its parameter commitment (Poseidon2 with Barretenberg parameters in Go, cross-checked against noir test vectors). | 2–3 days |
| 3 | **Registry**: build script from the embedded BSI list, published file + accepted roots list, 60-day grace, runbook section, test that every CSCA that chains today has a leaf. | 2 days |
| 4 | **Circuit artifacts**: compile the needed variants with nargo in CI (start with the algorithms in the BSI list; about 60–100 variants cover real passports), publish artifacts to our own hosting with a hash manifest, pin vk hashes in the issuer. | 2–3 days |
| 5 | **Android proving in the wallet** (OpenLine `mobile/modules/`): Expo module around `noir_rs` (Apache-2.0) or mopro, fed by JMRTD's DG1/SOD; port or license-clear the input builder; download only the 4 artifacts a passport needs; progress UI; fall back paths. | 1.5–2 weeks |
| 6 | **Measure on a low-end phone** (2–3 GB RAM Android): time, peak memory, thermal; decide whether to offer a helper-proved `dsc` step (that step uses only public certificates plus a salt; the helper learns the DSC, which narrows the state and issue period, not the person). | 2 days |
| 7 | iOS (same module via noir_rs) | 1 week, after Android |
| 8 | Phase 3: Active Authentication in-circuit (ISO 9796-2 RSA + ECDSA), OPRF-salted nullifier, external audit of the enabled circuits | 3–5 weeks + audit |

Before anything ships: resolve the `zkpassport-packages` license question,
and get the enabled circuits reviewed.

## Reproducing

```sh
spikes/zk-passport/run.sh                       # both vectors, ~70 s first run
HARDWARE_CONCURRENCY=1 PROFILES=p256 spikes/zk-passport/run.sh
cd src/methods/document-chip && go test ./zkproof/   # needs bb: $BB, PATH, or the spike's node_modules
```

`run.sh` downloads about 250 MB of npm packages and the circuits repo into
`spikes/zk-passport/` (gitignored `node_modules/` and `target/`).
