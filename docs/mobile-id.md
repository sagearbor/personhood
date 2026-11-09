# Private mobile ID (`mobile-id-zk`)

Status: **phase 2 built, behind `MOBILE_ID_ZK=1` (off by default)**. The
issuer method, the circuit (personhood's own Noir, Apache-2.0), its
reproducible build and pinned verification keys, the Go verifier, tests and
the Android wallet flow (OpenLine `mobile/src/services/mobileId/` and
`mobile/modules/mobile-id-wallet`, sagearbor/openline#199) exist. It
has been proved only with **specimen licences from a self-made test issuer**
("Utopia", no real person, no real issuer). No real wallet has answered
it yet: Google Wallet releases mobile driving licences to an app only after
relying-party onboarding (below). Method id `mobile-id-zk`, strength **75**.

A government mobile ID is an ISO/IEC 18013-5 *mdoc*: for example a US state
mobile driving licence (mDL) in Apple, Google or Samsung Wallet, Japan's My
Number Card in Apple or Google Wallet, or an EU Digital Identity Wallet PID
in mdoc format. **The government signs it, not the phone company.** The
state's document signer signs the Mobile Security Object (MSO), and that
signer chains to the state's IACA root. Apple, Google and Samsung only store
the credential and present it. The exception is Apple's Digital ID and
Google's "ID pass", which those companies make from a passport and sign
themselves (see Reach).

## What the issuer learns

| | Phone keeps | Issuer receives |
|---|---|---|
| Name, birth date, address, photo, document number | Yes (the photo only for the face match on the phone) | Nothing |
| Issuing jurisdiction (state) | Yes | Nothing: the proof hides which IACA in the registry signed |
| MSO, signatures, device key | Yes | Nothing |
| Validity | | "Valid at `now`", via the proof |
| Uniqueness | | One scoped number, `Poseidon2(scope, jurisdiction, document_number)` |
| Liveness / copy protection | | The device key signed this session's nonce (proved inside the proof) |

The phone sends one 14,656-byte UltraHonk proof, 8 public fields, the session
transcript inputs (the phone's one-time encryption key and the app origin, so
the issuer can rebuild the transcript with its own nonce), and the face-bind
outcome. There is no "send my licence instead" path (owner rule).

## Rules this follows

1. **No personal data leaves the phone.** The phone decrypts the wallet's
   answer itself and proves on the device.
2. **Issuer method, not a chain entry point.** OpenLine
   `docs/PASSPORT_ON_CHAIN.md` ("What stays unsolved") shows why two entry
   points that cannot see each other let one person count twice. So
   `mobile-id-zk` sits behind the identity server and uses its existing
   dedupe:
   - **Identifier store:** the identifier `mdoc:ZK:<nullifier hex>` is kind
     `document` (`src/server/identifier.go`). It is HMAC-keyed under
     `IDENTIFIER_HMAC_KEY` and gets its own random seed, like
     `chip:ZK:<…>`. Enrolling the same licence again gives the same
     identity.
   - **Document face index + review queue:** shared with
     `document-chip(-zk)` (`checkFace`). A face that matches an identity
     enrolled with a *different* document (a passport, or a licence from
     another state) issues the credential **and** queues a review case
     (`GET /v1/admin/document-reviews`, `method_id: mobile-id-zk`,
     `document_country: MDOC`).
   - **Document recovery:** `RECOVERY_DOCUMENT_METHODS` can list
     `mobile-id-zk`. Its attestation digest is stable per licence:
     `HMAC(k, identifier)`, with `k` derived from `IDENTIFIER_HMAC_KEY`. The
     same licence then proves the same person in a key recovery, and a
     leaked session store cannot be brute-forced against licence numbers.
   - It is **not** linked to the OpenLine chain's own passport registry:
     there is no on-chain mdoc path to link to.
3. **No false lockout.** No refusal is permanent. Each one comes with a next
   step (table below), and duplicates are routed to review, never refused.
4. **Licenses:** everything is Apache-2.0 or MIT (below). There is no
   zkPassport code, and no `noir_bigcurve`.
5. **Post-quantum:** see "Post-quantum" below. No signed object is weakened:
   the credential is the issuer's usual hybrid-capable VC.
6. **Off by default** (`MOBILE_ID_ZK=1`, which needs `DOCUMENT_CHIP_ANCHOR=1`).

## Reach (researched 2026-11-09)

| Region | Who signs the MSO | Wallets | Format | Rough eligible population |
|---|---|---|---|---|
| US: 17 jurisdictions (AZ, AR, CA, CO, GA, HI, IL, IA, MD, MT, NM, ND, OH, OK, PR, VA, WV); UT, KY, NC announced | **State DMV** (DS under the state IACA, P-256) | Apple Wallet (17), Google Wallet (13), Samsung Wallet (AZ, IA, AR, CA, …), some state apps | ISO 18013-5 mDL | ~124 M residents; holders today are a few million (California ~1.8 M) |
| Japan, My Number Card | **J-LIS** (government IACA) | Apple Wallet (since 2025-06), Google Wallet (since 2026-10) | mdoc | ~100 M card holders. Relying parties need a Digital Agency application, and a ministerial certification for their own verifier |
| EU EUDI Wallets (FR, IT, DK live; DE 2027-01; PL, AT, CZ, SE piloting); legal deadline ~2026-12 | **Member-state PID provider** | National wallets | PID in mdoc (`eu.europa.ec.eudi.pid.1`) and/or SD-JWT | FR 5 M+, IT ~10 M users. Which states issue PID *as mdoc* in production is unverified |
| Queensland (AU) | QLD TMR | QLD app (not Apple/Google) | ISO 18013-5 | ~1/3 of 5.6 M |
| India, Aadhaar in Google Wallet (2026-04) | UIDAI? (unverified) | Google Wallet | "built on ISO 18013-5" | Up to 1 B+ if UIDAI signs a standard mdoc (unverified) |
| US, UK, BR, SG, TW passports | **Apple / Google**, not a government | Apple Digital ID, Google ID pass | `org.iso.23220.photoid.1`, `com.google.wallet.idcard.1` (P-384) | Refused here (below) |

Roughly 230 M people are *eligible* today for a government-signed mdoc in a
phone wallet (US jurisdictions plus Japan). Add the EU and Queensland in the
low tens of millions, and possibly India. People who have *actually* added
one are probably in the low tens of millions. Sources: Apple's "Verify with
Wallet" jurisdiction list, Google Wallet help 12436402, Samsung and state
announcements, the Japanese Digital Agency, the iGrant EUDI tracker, and the
Queensland government.

**Company-signed passport credentials are refused** (`mdoc_company_signed`).
Apple's Digital ID is signed by "Apple Issuing Authority ECC Root CA – G1"
(P-384), and Google's ID pass by "Identity Credential Root IACA, Google LLC"
(P-384). Their MSO validity is a company attestation of a passport chip read
and selfie. The government's own passport chip is the stronger signal, and
`document-chip-zk` already proves it privately. They are also P-384, which no
licensed in-circuit curve library supports today. The wallet says this and
offers the passport.

## Getting the licence into our app

| Path | What our app receives | Decrypt on the phone? | Approval |
|---|---|---|---|
| **Android Credential Manager, OpenID4VP over the Digital Credentials API** (`openid4vp-v1-signed`, DCQL `mso_mdoc`, `response_mode: dc_api.jwt`). This is what Google Wallet documents | A JWE whose `vp_token` is a full `DeviceResponse`: IssuerSigned (MSO, issuerAuth x5chain, the requested items) plus DeviceSigned (device signature over the session transcript) | **Yes.** The app puts its own one-time key in `client_metadata.jwks`. Google *recommends* validating on a server, but nothing forces it | **Google relying-party onboarding:** sandbox allowlist; then production needs a P-256 CSR, name, logo, privacy policy, a demo video and acceptance of the RP Terms of Service. Review takes 3–5 business days. Google then signs a certificate for the request's `x5c`. Production requests must be **signed** |
| **Android Credential Manager, ISO 18013-7 Annex C** (`org-iso-mdoc`): EncryptionInfo with the app's HPKE key, response HPKE-encrypted | The same `DeviceResponse` | Yes | Supported by Multipaz-based wallets and browsers. **Unverified whether Google Wallet answers `org-iso-mdoc` from apps** |
| Samsung Wallet ("Verify with Samsung Wallet" RP SDK, app-to-app) | DeviceResponse over ISO 18013-5 session encryption, decrypted in the partner app | Yes | Samsung partner portal plus admin approval |
| **Apple, native** ("Verify with Wallet", `PKIdentityRequest` / IdentityDocumentServices, entitlement `com.apple.developer.in-app-identity-presentment`) | `encryptedData`, encrypted to the merchant's Identity Access Certificate key | **No.** Apple: it "isn't readable on the device" and must be verified on a server | Entitlement approval. The app must sell something that *requires* identity or age verification, and Apple can withdraw it "for any reason" |
| Apple, Safari Digital Credentials API (iOS 26, `org-iso-mdoc`) | HPKE-encrypted DeviceResponse to a web page | In the page (not our native app). Apple says to keep the key on a server | ReaderAuth certificate from Apple Business Connect |

**Which path lets our app prove on the device:** the Android Credential
Manager paths. Our app generates a one-time key, the wallet encrypts the
`DeviceResponse` to it, and the app decrypts and proves locally. The issuer
only ever sees the proof.

**What needs Google's approval:** production Google Wallet. Until we pass
onboarding, the Android flow works only against Google's sandbox (with an
allowlisted test account) and against Multipaz test wallets. A signed
request needs an RP signing key. The issuer would hold it and sign the
request in `begin`. That is a **cloud secret, deliberately not created** for
this work; see "Follow-ups".

**iOS is blocked by Apple's design, not only by approval.** The native API
does not let the app read the credential, so it cannot prove on the device
without sending the licence to a server. That breaks rule 1. iOS stays a
follow-up: revisit if Apple allows on-device decryption, or use a Safari
Digital Credentials API page whose decryption key never leaves the phone
(Apple currently advises against that).

### The session transcript (copy protection)

`begin` issues a 32-byte challenge. The nonce is
`SHA-256("personhood/mobile-id/v1" 0x00 ‖ challenge ‖ SHA-256(holder))`,
which binds the session and the holder DID the credential will go to. The
phone puts it in its wallet request. The wallet's device key, held in the
phone's secure hardware and certified in the MSO, signs
`DeviceAuthentication = ["DeviceAuthentication", SessionTranscript, docType,
DeviceNameSpacesBytes]`. The issuer rebuilds the transcript from its own
nonce and checks the proof's public transcript hash:

- **Annex C (dcapi):**
  `[null, null, ["dcapi", SHA-256(CBOR [base64url(EncryptionInfo), origin])]]`.
  The phone sends `encryption_info_b64u` (the issuer checks the nonce inside
  it) and `origin`.
- **OpenID4VP DC API:**
  `[null, null, ["OpenID4VPDCAPIHandover", SHA-256(CBOR [origin, nonce, jwk_thumbprint])]]`,
  with nonce = base64url(nonce). The phone sends `origin` and
  `jwk_thumbprint_b64u`.

The app origin for a native Android app is
`android:apk-key-hash:<SHA-256 of the signing certificate>`.
`MOBILE_ID_ZK_ORIGINS` can pin it. Google's documentation says standard
base64 and Multipaz uses base64url, so the wallet sends whatever the
platform produced and the issuer just checks it. This is the mdoc equivalent
of passport Active Authentication, and it is **always** proved: there is no
mdoc without a device key. A copy of the MSO and items (for example scraped
from a previous presentation) cannot answer a fresh nonce.

Each challenge answers one `complete` within 30 minutes.

## The circuit (`tools/zk-circuits/mdoc`, Apache-2.0)

One proof, `mdoc_p256_msg_<M>` (`M` = the largest COSE Sig_structure, and so
MSO, it takes: 2048, 3072, 4096). The wallet picks the smallest that fits.

| # | Proves | How |
|---|---|---|
| 1 | An IACA in the issuer's registry signed the document signer certificate | Poseidon2 Merkle path (depth 16) from `leaf = Poseidon2("mdoc-iaca", jurisdiction, x‖y)` to the public `registry_root`; SHA-256 of the DS TBSCertificate; P-256 ECDSA with Noir's built-in secp256r1 black box. The DS key is read from the TBS by walking its DER (version, serial, signature, issuer, validity, subject) to a P-256 SubjectPublicKeyInfo |
| 2 | The DS signed the MSO | Parses COSE `Sig_structure = ["Signature1", protected, h'', #6.24(bstr MSO)]` (lengths constrained, payload ends the message); SHA-256; ECDSA |
| 3 | `docType` and validity | `docType` key followed by the public doc type; `validFrom`/`validUntil` keys followed by tdate (`C0 74`, 20 chars) inside the MSO; `validFrom ≤ now ≤ validUntil` on big-endian packed strings |
| 4 | The `document_number` item is the issuer's | The IssuerSignedItem is parsed completely (exactly four keys in any order, each once; `elementIdentifier = "document_number"`, value a text of 1–31 bytes, nothing trailing); its SHA-256 equals the digest of its `digestID` in the MSO's valueDigests, found by walking every entry of the public namespace's map |
| 5 | Device binding | MSO `deviceKey` as COSE_Key `{1:2, -1:1, -2:x, -3:y}`; the device Sig_structure is parsed to `DeviceAuthentication`, the transcript slice is hashed and equals the public hash, the docType follows it, and DeviceNameSpacesBytes ends the message; ECDSA under the device key |
| 6 | Nullifier | `Poseidon2(scope, jurisdiction, pack_be(document_number), len)`, returned as the last public input |

Public inputs: `registry_root, now, doc_type, name_space, transcript_hash_hi,
transcript_hash_lo, scope, nullifier`. Everything else is private: the
jurisdiction, all keys, certificates, signatures, the MSO, the number.

Why parsing by hinted positions is sound: the MSO and DS certificate are
signed by the government, so the holder cannot place bytes in them. The one
value a holder controls, their device key, is a curve point and cannot be
steered. The patterns the circuit checks are longer than any opaque field
(digests are 32 bytes). The item, whose value *could* contain arbitrary text
for other elements (an address), is parsed completely instead.

Not checked in the circuit (documented, as for the passport): DS certificate
validity and revocation, IACA revocation, and the item's `expiry_date`. The
MSO validity window covers freshness: AAMVA recommends 30 days or less, and
Apple uses 35 days. A state that revokes a licence stops re-signing its MSO.

### Measured (Apple M4, 10 cores, bb 5.0.0 native, `spikes/mobile-id/prove.mjs`)

| Circuit | Gates | Witness | Prove, all cores | Prove, 4 threads | Prove, 1 thread | Peak RSS |
|---|---|---|---|---|---|---|
| `mdoc_p256_msg_2048` (specimen, MSO 1,068 B) | 474,876 | 0.25–0.31 s | 2.2 s | 2.7 s | 7.3 s | 0.91–1.04 GB |
| `mdoc_p256_msg_3072` (specimen, MSO 1,068 B) | 548,628 | 0.31 s | 2.6 s | | | 1.17 GB |
| `mdoc_p256_msg_3072` (40 extra elements, MSO 2,506 B) | 548,628 | | 2.6 s | | | 1.20 GB |
| `mdoc_p256_msg_4096` | 622,380 | | | | | |

- **Proof:** 14,656 bytes plus 8 × 32 bytes of public inputs. **Verify:**
  ~10 ms (`bb verify`, process start included).
- **Artifacts:** 0.38 / 0.46 / 0.55 MB gzipped. The SRS prefix the phone
  downloads is 2^19 points (32 MB) for 2048, or 2^20 (64 MB) for the larger
  ones, cached by hash.
- **Phone estimate (not measured):** at the passport's ratio (emulator 4–8×
  slower than the host), expect **10–25 s** on a Pixel-class phone and
  **30–60 s** on a $100 phone, with **~1 GB peak**. That is above the
  passport's largest circuit (~0.7 GB). The wallet requires a "4 GB" phone
  (≥ 3.5 GB reported) for this method and otherwise routes to the passport,
  the selfie or in-person vouching. A two-proof split (DS+MSO, then item+device), chained by a
  salted commitment like the passport stages, would roughly halve the peak.
  That is the first optimisation if real phones struggle.

### Soundness checks (`spikes/mobile-id/circuit-tests.mjs`, 20 checks)

Witness generation must fail for:
- another session's transcript hash;
- `now` after `validUntil` or before `validFrom`;
- a registry root that is not ours;
- another jurisdiction for the IACA;
- the document number changed;
- the item salt changed;
- the issuer signature, an MSO byte, or a DS certificate byte flipped;
- the device signature or device message changed;
- the wrong digest entry;
- the namespace swapped to the AAMVA one;
- a company doc type;
- the device key position moved;
- `validUntil` read from `validFrom`;
- a transcript length off by one.

Two positive checks:
- the same licence **re-issued** (new IACA key, DS, MSO, device key and salts) gives the **same nullifier**;
- another document number gives another nullifier.

### Longfellow-zk (Google), evaluated and not used here

Google's longfellow-zk, now `longfellow-zk/longfellow-zk` (IETF CFRG draft
`draft-irtf-cfrg-longfellow-00`), is Apache-2.0 throughout, with no vendored
third-party code. Measured on the same M4:

| | Longfellow mdoc (v7) | Ours (UltraHonk) |
|---|---|---|
| Prove | 0.29 s, single thread | 2.2 s all cores / 7.3 s single |
| Verify | 0.15 s | 0.01 s |
| Proof | ~360 KB | 14.7 KB |
| Peak | ~170 MB | ~1 GB |
| Circuit file | 0.3 MB zstd, 94 MB in memory | 0.4 MB gz + SRS |
| Proof system | Ligero + sumcheck, hash-based (plausibly PQ-sound) | UltraHonk/KZG on BN254 (not PQ) |
| Hides the issuer | **No**: the issuer key is a public input, so the jurisdiction is revealed (an issuer-list variant exists only in a test) | Yes |
| Nullifier | **None**. Disclosed attributes are public inputs (revealed) | Scoped Poseidon2 nullifier |
| Go verifier | cgo over `run_mdoc_verifier` (reference server in repo) | pinned `bb` (already in the image) |
| Phone | Pixel 6: 1.17 s prove (Frigo & shelat, ePrint 2024/2010, via a secondary source); Multipaz ships Android/iOS binaries | noir_rs, already in the wallet (`zk-prover`) |

Longfellow is faster, smaller in memory and closer to post-quantum. But it
cannot do what this method needs without new circuits: no nullifier, and the
issuer is revealed. Adding a scoped nullifier means changing `mdoc_hash.h`
and `zk_spec.cc`, roughly a few engineer-weeks, and leaving the audited v7
circuits. Google Wallet's own ZK answers (`mso_mdoc_zk`) only prove
attribute predicates such as `age_over_18`, so they give no uniqueness
either. **Decision:** ship on the Noir/UltraHonk stack the passport already
uses (one prover in the wallet, one verifier in the issuer, pinned vks).
Revisit Longfellow when its Rust v2 (Polygero, about 0.27 s, 213 KB) settles:
a nullifier added there would bring post-quantum proof soundness and about
5× less memory.

## Trust lists

- **No list is embedded.** AAMVA's Digital Trust Service VICAL (signed CBOR,
  daily, free) has terms that forbid redistribution ("not … provide or
  distribute any download link", no republishing or repackaging). We did not
  download it, so as not to accept those terms on the owner's behalf. The
  operator supplies `MOBILE_ID_IACA_PEM`: state-published IACA certificates.
  Several are also in Google's Apache-licensed longfellow `certs.pem`, and
  every state IACA inspected (AZ, MD, NM, ND, CA, CO, GA) is P-256 /
  ecdsa-with-SHA256. Not every Apple or Google Wallet state is in the VICAL
  yet, so state-published certificates are needed either way. If an operator
  accepts AAMVA's terms, it can extract IACAs from the VICAL locally into
  that PEM. What we publish (`GET /v1/methods/mobile-id-zk/registry`) is
  public keys plus jurisdiction codes, not the VICAL. Whether that counts as
  "repackaging" under AAMVA's terms is **a question for the owner or counsel**
  before production.
- **EU:** Implementing Regulation 2024/2980 has the Commission publish
  signed lists of PID providers (ETSI TS 119 602). The first compiled list
  was reported as "being prepared" (Oct 2026). Add those IACAs when PID mdoc
  support lands.
- **Japan:** J-LIS publishes its mdoc IACA. Use needs a Digital Agency
  application and, for our own verifier, ministerial certification.
- **Jurisdiction code:** the IACA subject's `C`, plus `-ST` when it names a
  state (`US-CA`, `JP`). `MOBILE_ID_IACA_JURISDICTIONS` overrides it per
  certificate hash. Two issuers must never share a code: two states can
  issue the same number, and a shared code would make two people one
  identity. The registry refuses duplicate keys and skips IACAs without a
  country.
- **Registry:** same tree code as the passport registry (Poseidon2, depth 16,
  leaves sorted, so the root is deterministic). Built at start-up and logged.
  Phones download all of it and build their path locally, so the issuer does
  not learn the state. **Updating:** note the logged root, deploy the new
  PEM, and pass the old root in `MOBILE_ID_ZK_EXTRA_ROOTS` for a few days
  (phones cache the registry). IACA rotation inside a jurisdiction does
  **not** change anyone's nullifier, because the jurisdiction code (not the
  key) goes into it. The circuit tests check this.
- **Curves:** v1 takes P-256 IACA, P-256 DS, ES256 MSO and a P-256 device
  key. That covers every US state IACA seen. P-384/P-521 IACAs (Apple's and
  Google's company IACAs, possibly some EU PID providers) are skipped at
  registry build and counted in the log. A licence the circuit cannot take
  is told so on the phone, before proving (`mdoc_unsupported`).

## Nullifier

- **What is hashed:** `(jurisdiction, document_number)`. Document numbers
  are unique within a jurisdiction and printed on the card. The jurisdiction
  comes from the registry leaf of the IACA that actually signed, so a state
  can only mint numbers in its own namespace (the same property the
  passport's CSCA country binding has).
- **Stable across:** MSO refresh (wallets re-sign every ≤ 30–35 days, in
  batches with fresh device keys and salts); a new phone or re-provisioning;
  IACA key rotation; and **licence renewal in most states**. Enrolling again
  gives the same identity.
- **Changes on:** a new licence number. That happens with
  - Florida (new random number at the first renewal or replacement after 2024-07-31);
  - Oklahoma (renumbering at renewal);
  - a move to another state;
  - a name change in some states.

  As with a renewed passport, that is **routed, never refused**: the face
  index notices the same face with a different document, the credential is
  issued and a review case is queued.
- **Guessable, unlike the passport's:** the passport nullifier includes the
  chip's SOD signature, which is never printed. An mdoc has no stable,
  unprintable per-person value: the MSO signature, device key and salts all
  rotate. So whoever knows a licence number and state, and holds the issuer's
  scope, can recompute the nullifier. Mitigations:
  - the issuer stores only `HMAC(IDENTIFIER_HMAC_KEY, …)` of the identifier;
  - the attestation digest is keyed too;
  - the nullifier is never published.

  The fix is an issuer-held OPRF key, verified in the circuit (as planned
  for the passport). Then even the issuer's running process sees only a
  keyed value. That is phase 3, and it matters before any nullifier goes on
  a chain.
- **Passport and licence for the same person:** two different documents
  give two identifiers. These two never share a number, so the issuer counts
  the person once **through the face index**. The second enrollment,
  whichever document it uses, matches the first one's face template and
  goes to review; the reviewer decides whether the two identities are one
  human. The same holds for a licence plus a state ID card, or licences from
  two states. We considered and rejected a cross-document hash (name + birth
  date): names are written differently in the MRZ and on licences, and
  common name/date pairs collide. A collision would merge two people, which
  is a false lockout.

## Strength: 75

- **Government-signed** (like the passport): forging needs a state key.
- **Device-bound:** the device key lives in secure hardware, and the
  wallet's provisioning attests to it. This is as strong as passport Active
  Authentication. The passport with AA gets 80.
- **Minus 5** for weaker guarantees than the passport:
  - **More legitimate duplicates:** licences from two states during a move,
    re-numbering states, and a licence plus an ID card. These go to review,
    which costs reviewer time and gives more room for social engineering.
  - **Remote onboarding:** the holder was bound to the licence by the
    wallet's remote onboarding (card scan plus selfie checked against the
    DMV photo), not by an in-person check at issuance. A mistake there
    passes straight through.
  - **Face bind still a claim:** as for the passport, the phone's face match
    is a claim by the app. Pairing with `app-attest-device` makes lying
    expensive.
- **Not 70 like a passive-only passport:** a copied mdoc cannot answer the
  device challenge, while a passive-only passport chip can be cloned.

So 75, which agrees with the owner's initial guess.

## Refusals and next steps (no false lockout)

| Reason | Meaning | Next step |
|---|---|---|
| wallet: `mdoc_no_wallet_id` | No mobile ID in any wallet, or the user cancelled | Passport, selfie check or in-person vouching |
| wallet / `mdoc_company_signed` | Apple Digital ID or Google ID pass (company-signed) | Use the passport itself (`document-chip-zk`) |
| wallet: `mdoc_unsupported` | A curve, digest or size the circuits do not take (the wallet knows before proving) | Passport, selfie or vouching; the reason is shown so the variant can be added |
| wallet: `mdoc_missing_element` | The wallet did not share `document_number` | Try again and allow it; otherwise another way |
| wallet: `mdoc_device_too_weak` | No arm64 prover, or less than a "4 GB" phone | Passport (smaller circuits), selfie or vouching |
| `mdoc_registry_unknown` | The phone used a registry root we do not publish (stale cache), or the licence's state is not trusted yet | Refresh and retry once automatically; otherwise another way |
| `mdoc_circuit_unsupported` | Circuit not pinned (old app) | Update the app |
| `mdoc_session_mismatch` | Transcript, nonce, origin or holder is not this session's | Start again |
| `mdoc_origin_not_allowed` | App origin not in `MOBILE_ID_ZK_ORIGINS` (a re-signed app) | Install the official app |
| `mdoc_date_stale` | Phone clock more than 36 h off | Fix the clock, prove again |
| `mdoc_doc_type_unsupported`, `mdoc_scope_mismatch` | Not an accepted credential type, or a proof made for another service | Another way |
| `mdoc_proof_invalid`, `mdoc_bundle_malformed` | Bad proof | Prove again; if it repeats, another way |
| `face_bind_missing`, `face_bind_failed`, `face_template_invalid` | As for the passport | Same |
| `no_challenge_issued` | `complete` without `begin`, after 30 min, or a second time | Start again |

An expired MSO cannot be proved. The wallet says "open your wallet app so it
refreshes your ID, then try again", because wallets re-sign MSOs in the
background.

## Licenses

| Component | License | Where |
|---|---|---|
| personhood `tools/zk-circuits/mdoc` (circuit, generator, build) | Apache-2.0 | artifacts (phone), vks (issuer) |
| noir-lang/sha256 v0.3.0, noir-lang/poseidon v0.3.0 | Apache-2.0 (GitHub license API) | inside the artifacts |
| Noir built-in `std::ecdsa_secp256r1` | MIT/Apache-2.0 (Noir) | inside the artifacts |
| Noir (noir_wasm), noir_rs (wallet) | MIT/Apache-2.0, Apache-2.0 | build machine; phone |
| Barretenberg (bb 5.0.0) | MIT (bb.js) / Apache-2.0 | issuer; phone |
| Go: CBOR codec, registry, verifier, test issuer (`mdoczk`) | personhood, Apache-2.0; stdlib only | issuer |
| Wallet input builder (`mdocInputs.ts`) | personhood, Apache-2.0; no dependencies | phone |
| longfellow-zk | Apache-2.0 | **not used** (evaluated) |
| AAMVA VICAL | Terms forbid redistribution | **not used** (operator supplies IACAs) |

No unlicensed dependency (cf. `noir_bigcurve` for the passport). P-256 is
handled entirely by the Noir black box.

## Post-quantum

The same position as `document-chip-zk`:
- **Forgery:** UltraHonk/KZG on BN254 is pairing-based. A large quantum
  computer could forge *new* proofs. Proofs are checked once and not stored.
- **The credential itself:** the mdoc PKI (P-256 ECDSA) falls to the same
  computer, so no mdoc proof is quantum-safe until issuers move to
  post-quantum signatures. ISO 18013-5 has no PQ profile yet.
- **What would help:** Longfellow's hash-based proofs would make the
  *proof* PQ-sound (its experimental ML-DSA circuits point the same way).
  That is the path to revisit.
- **Issuer side:** the issuer's own signed objects (the VC, with ML-DSA
  hybrid when `ISSUER_MLDSA_SK` is set; `docs/POST_QUANTUM.md`) are
  unchanged by this method. Nothing is weakened.

## Running it (issuer)

```sh
tools/zk-circuits/mdoc/build.sh        # ~1 min; writes dist/ and the pinned manifest + vks
DOCUMENT_CHIP_ANCHOR=1 MOBILE_ID_ZK=1 \
MOBILE_ID_IACA_PEM=/path/to/state-iacas.pem \
MOBILE_ID_ZK_BB=tools/zk-circuits/node_modules/@aztec/bb.js/build/arm64-macos/bb \
MOBILE_ID_ZK_ARTIFACTS_DIR=tools/zk-circuits/mdoc/dist \
IDENTIFIER_HMAC_KEY=... go run ./src/server/cmd/server
```

The Docker image copies `tools/zk-circuits/mdoc/dist` to `/mdoc-artifacts`
when it exists at build time, and sets `MOBILE_ID_ZK_ARTIFACTS_DIR`. Set
`MOBILE_ID_ZK_BB` or `DOCUMENT_CHIP_ZK_BB` (the image's `/usr/local/bin/bb`).

## Reproducing the spike

```sh
spikes/mobile-id/run.sh            # build circuits, mint specimen licences, prove, 20 soundness checks, Go tests
UPDATE_FIXTURES=1 spikes/mobile-id/run.sh   # also regenerate mdoczk/testdata
```

`go run ./mdoczk/cmd/mdoc-testvector` (in `src/methods/document-chip`) mints
a specimen licence and presents it for a session. Its flags:
- `-handover openid4vp` for the OpenID4VP transcript;
- `-extra N` for a larger MSO;
- `-doc` for another number.

## Phases

| # | Work | Status |
|---|---|---|
| 1 | Design (this doc), specimen issuer, circuit, spike with measurements | Done |
| 2 | Issuer method `mobile-id-zk`, flag off, tests; Android wallet flow (OpenLine) | Done (no real wallet yet) |
| 3 | Google Wallet RP onboarding (owner): CSR, logo, privacy policy, demo video, ToS; then a request-signing key held by the issuer (a cloud secret; not created) | **Blocked on owner / Google** |
| 4 | Real licence on a real phone (owner's Pixel; sandbox first), measure | To do |
| 5 | Two-proof split to cut peak memory, if phones need it | Later |
| 6 | OPRF-keyed nullifier; audit of the circuit | Later |
| 7 | EU PID mdoc (`eu.europa.ec.eudi.pid.1`: no mandatory `document_number`, needs another stable element), Japan (certification), P-384 IACAs (needs a licensed curve library) | Later |
| 8 | iOS (Apple keeps the credential encrypted to a server) | Blocked by Apple's design |

## Open risks

- **Google's Terms of Service** for relying parties have not been read in
  full. They may restrict use cases or require server-side processing.
  Check them before onboarding.
- **AAMVA terms vs publishing the IACA registry:** see above.
- **Unaudited circuit** (personhood's own). Get a review before production.
- **Memory:** about 1 GB peak excludes 2 GB phones from this method.
  Those phones are routed to the other ways in.
- **Wallets that answer with a device MAC** instead of a signature (ISO
  allows `deviceMac`) are refused on the phone (`mdoc_unsupported`). Over
  the DC API, wallets sign, but this is unverified for every wallet.
- **Real MSO encodings may differ** from the specimen in ways the circuit's
  exact patterns do not take:
  - a COSE_Key with an `alg` entry;
  - tdates with fractional seconds;
  - digest IDs above 65535.

  The wallet checks before proving and shows `mdoc_unsupported` with the
  reason. Widening a pattern is a circuit change plus a rebuild.
