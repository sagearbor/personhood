# In-person vouching, the anchor policy, and holder revocation

Status: **implemented, off by default.** Three flags, each independent:

| Flag | Turns on |
|---|---|
| `IN_PERSON_VOUCH_ENABLED=1` | The QR-round-trip vouch ceremony. Vouches count toward `social-vouching-graph` (supplementary, 35), which is registered automatically. |
| `IN_PERSON_VOUCH_ANCHOR=1` | The **anchor policy**: registers `in-person-vouch` (anchor, 55). Needs the two flags around it. |
| `HOLDER_REVOCATION_ENABLED=1` | Issuance ledger, holder bans, nullifier-seed bans, `POST /v1/revocations/equivocation`, `POST /v1/admin/revoke-holder`. Required by the anchor. |

Code: `src/methods/social-vouching/{inperson,inperson_store,anchor,accountability}.go`,
`src/server/{inperson,holderrevoke}.go`, `src/credential/equivocation.go`,
`app/web/{lib/vouch.ts,components/steps/VouchStep.tsx,app/vouch/page.tsx}`.

## 1. Who it is for

A person with a $50 Android phone, no documents, no bank account and no fixed
address. They cannot use `government-id-liveness` or `plaid-bank-link`. A
browser selfie alone is weak: the web has no camera attestation, so a bot can
feed it a generated face. What such a person does have is neighbours. In-person
vouching turns "K people who are already in vouch for me, face to face" into a
credential signal, and makes those K people answerable for it.

## 2. The ceremony

Two phones, both online, both in the web app. The **voucher** already holds a
Personhood credential on their phone. The **newcomer** is mid-enrollment.

```
voucher phone (/vouch)                 issuer                    newcomer phone (enrol → "In-person vouch")
1 POST offer {credential} ───────────▶ verify credential, standing
  show QR "PHV1:O:<offer>"  ◀───────── offer_code, expires in 2 min
                                                                 2 scan QR (or type the code)
                                       ◀──────── POST accept {offer_code, newcomer key, sig(AcceptMessage)}
                                       return_code, expires in 90 s ────────▶ show QR "PHV1:R:<return>"
3 poll GET status → newcomer DID
  scan newcomer's QR (or type it)
  POST confirm {offer, return, sig(ConfirmMessage)} ──▶ check, quota, record vouch
                                                                 4 poll status → "confirmed"; call
                                                                   complete(in-person-vouch) → "1 of K" … success
```

Codes are 8 Crockford-base32 characters (40 bits), shown as `ABCD-1234`.
An offer is burned after 5 wrong return codes.

### Signed messages

Both are UTF-8, fields joined by `\n`, signed with the holder's Ed25519 key
(the same non-extractable WebCrypto key the web app uses for holder PoP):

```
AcceptMessage  = "personhood-in-person-vouch/v1\naccept\n<issuer DID>\n<offer code>\n<newcomer DID>"
ConfirmMessage = "personhood-in-person-vouch/v1\nvouch\n<issuer DID>\n<offer code>\n<newcomer DID>\n<return code>\n"
                 + "I met this person face to face and I believe they hold no other credential."
```

Each side signs a value only the other side's screen showed it. The issuer DID
stops replay at another issuer; the one-time codes stop replay at this one.

### Who may vouch

The voucher presents their credential at `offer`. The issuer accepts it only if
it is this issuer's, correctly signed, unexpired, not on the status list, held
by a `did:key`, and its holder is not banned. Then:

- **Anchored voucher**: the credential's anchor is still within its freshness
  window and at least `IN_PERSON_VOUCH_MIN_VOUCHER_AGE_DAYS` old (default 0;
  set 30 on a real deployment, matching OpenLine's advice for `minAgeSec`).
  Weight `0.5^strikes`. Counts toward the anchor.
- **Graph voucher**: no anchor, but social-vouching-graph trust ≥ 0.5. Weight =
  trust. Counts toward the supplementary method only, never the anchor.
- Everyone: not suspended, not revoked, fewer than `IN_PERSON_VOUCH_MAX_PER_PERIOD`
  (2) confirmed vouches in the last `IN_PERSON_VOUCH_PERIOD_DAYS` (30). The
  quota is checked again atomically at confirm, so two offers opened at once
  cannot both spend the last vouch.

### What the ceremony proves, honestly

| Evidence | What it shows | How it is spoofed |
|---|---|---|
| Both keys signed values from the other screen | One live exchange between the two keys | A relay (video call pointed at the QR, or a script forwarding images) |
| 2-minute and 90-second deadlines | The exchange was live, not prepared or batched | The same relay, done quickly |
| Same /24 (IPv4) or /48 (IPv6) at accept and confirm (`same_network`, recorded; enforced only with `IN_PERSON_VOUCH_REQUIRE_SAME_NETWORK=1`) | Probably the same Wi-Fi | A shared VPN exit; and honest villagers on two mobile carriers fail it, which is why it is off by default |
| Typed code instead of scanned | Nothing extra; the server cannot tell a typed code from a scanned one | Reading the code aloud over the phone |

**The ceremony does not prove the phones were in the same place.** Bluetooth
was considered and rejected for now: Chrome on Android can scan (behind a
picker prompt) but a web page cannot advertise, so the newcomer's phone cannot
be found. Ultrasonic audio (Web Audio) is possible future work and is also
relayable. What makes a remote vouch expensive is the voucher's accountability
(section 4), not cryptography.

## 3. The anchor policy (`IN_PERSON_VOUCH_ANCHOR=1`)

`in-person-vouch` is a **separate anchor method**, strength **55**. It succeeds
when, for the newcomer's holder DID:

1. at least K (`IN_PERSON_VOUCH_REQUIRED`, default 3) **distinct** vouchers who
   were **anchored** at vouch time confirmed in-person vouches,
2. each within the last 30 days (no banked vouches), from vouchers not revoked
   since, and
3. the same session already passed one of `IN_PERSON_VOUCH_DEDUPE_METHODS`
   (default `fuzzy-extractor-selfie`).

Condition 3 is enforced by the issuer as a **method prerequisite**
(`Server.methodPrerequisites`), not by touching the dedupe method: complete on
`in-person-vouch` returns `prerequisite_missing:<ids>` until the session holds
one. A deployment can point it at a different dedupe method (for example the
web selfie liveness method being built on `feat/selfie-liveness-web`) with no
code change. The issuer refuses to start if the anchor flag is on and none of
the listed dedupe methods is registered, or if `HOLDER_REVOCATION_ENABLED` is
off.

**Why 55.** It clears the 50-point anchor floor and stays below
`fuzzy-extractor-selfie` (70). To mint one fake, an attacker needs K anchored
accomplices, each spending one of two vouches a month and each taking a strike,
a 180-day suspension and a halved weight when the fake is caught, plus a face
the dedupe has not seen. It is not higher because the round trip is relayable:
a ring of K colluding anchored members can admit people remotely until they are
caught. The anchor/supplementary invariant is untouched (`MethodMetadata.Validate`
still enforces anchors ≥ 50, supplementary < 50); social-vouching-graph stays
supplementary at 35.

## 4. Accountability

`InPerson.Penalize(candidateDID)` runs whenever the issuer revokes a holder
(section 5). For the candidate: marked revoked (cannot vouch or be vouched for
again; its own past vouches stop counting toward anyone's anchor) and removed
from the trust graph. For **every** voucher of the candidate (in-person or the
dev HMAC route): one strike, suspension for `180 days × strikes`, graph trust
× 0.5, and an anchored voucher's future weight becomes `0.5^strikes`. It is
idempotent per candidate. It does not revoke the vouchers' own credentials (a
voucher may have been fooled) and does not cascade past one hop.

## 5. Holder revocation and the equivocation hook

### Equivocation proof format (`src/credential/equivocation.go`)

A holder that must sign something at most once (an OpenLine instant payment
spending a coin) signs a **slot statement**:

```
personhood-slot/v1
<context>          e.g. openline/<chain-id>/spend     (1..256 printable ASCII)
<slot>             e.g. <account>:<seq> or a coin id  (1..256 printable ASCII)
<payload digest>   64 lower-case hex = SHA-256 of what was signed
```

Two statements with the same context and slot, different digests, both valid
under one key, are a proof anyone can check offline:

```json
POST /v1/revocations/equivocation        (public, no token: the proof verifies itself)
{
  "scheme": "personhood-slot/v1",
  "holder_public_key_b64": "<32-byte Ed25519 key>",
  "context": "openline/openline-beta/spend",
  "slot": "acct1:7",
  "statements": [
    {"payload_digest_hex": "<64 hex>", "signature_b64": "<64-byte sig>"},
    {"payload_digest_hex": "<64 hex>", "signature_b64": "<64-byte sig>"}
  ]
}
→ 200 {"holder_did": "did:key:…", "already_banned": false, "known_holder": true,
       "revoked_credentials": 1, "nullifiers_banned": 2, "vouchers_penalized": 3}
→ 400 {"error": {"code": "proof_invalid", …}}
```

Go helpers: `credential.SlotStatementMessage`, `credential.SignSlotStatement`,
`EquivocationProof.Verify() (ed25519.PublicKey, error)`.

Operator path for duplicates found another way:

```
POST /v1/admin/revoke-holder   Authorization: Bearer $ADMIN_TOKEN
{"holder_did": "did:key:…", "reason": "duplicate of …"}   → same response shape
```

### What revoking a holder does

1. Bans the holder DID (written first, so a part-way failure still blocks
   re-enrollment; calling again finishes the job).
2. Revokes, on the status list, every credential the ledger recorded for it.
3. Bans every **nullifier commitment** those issuances touched: the
   credential's own binding, the holder-key binding, and an email/phone seed
   that a biometric binding overrode. The commitment is a pure function of the
   seed, so banning it bans the seed: a new enrollment that resolves to the same
   inbox, phone or face is refused with `403 nullifier_revoked`, whatever new
   device key it brings. The same holder key gets `403 holder_revoked`.
4. Penalizes the holder's vouchers (section 4), when in-person vouching is on.

### Data shapes (`HolderLedger`)

```
IssuanceRecord { credential_id, nullifier_commitments[], issued_at }   per holder DID
BanRecord      { reason, evidence_digest (sha256 of the proof JSON), at }   per (kind, value)
kinds: "holder" (DID), "nullifier" (commitment hex)
```

Firestore (`personhood-holder-issuances/<sha256(DID)>`,
`personhood-bans/<kind>-<sha256(value)>`, create-only), Redis
(`personhood:<ns>:<id>`), or memory, chosen like every other store.

### Appeals

A revocation can be wrong: a wallet bug can sign one slot twice. With
`NO_FALSE_LOCKOUT=1` and `ADMIN_TOKEN`, a banned holder appeals
(`POST /v1/appeals`), an operator reviews, and approval reinstates them:
bans lifted, the proof pardoned so it cannot ban again, and the vouchers'
strikes taken back. See [08-no-false-lockout.md](08-no-false-lockout.md),
section 3.

### Limits

- Credentials issued before `HOLDER_REVOCATION_ENABLED` have no ledger record:
  revoking their holder bans the DID and holder-key nullifier but cannot find
  their credential id or seed. Use `/v1/admin/revoke` for those.
- The proof must be signed by the **credential's holder key**. If OpenLine's
  payment key is a different key, OpenLine must either sign spends with the
  holder key or have the holder key sign a slot statement per spend. That is
  the main open integration question.
- A stolen holder key can be used to frame its owner. Wallets must only sign
  slot statements for spends they built themselves.
- The vouch store (offers, quotas, strikes) is in-memory in this version: a
  restart forgets quotas and suspensions (bans and revocations persist, they
  live in the ledger and status list). Persisting it is the first follow-up
  before the anchor is turned on for real users. The issuer must run as one
  instance (`--max-instances 1`), as it already does.

## 6. Fit with OpenLine's on-chain vouching (PR #161)

OpenLine's `cmd/openline-node/chain/vouch.go` admits members on chain: K member
signatures over `H("openline-vouch/v1", chainID, "admit", newcomer, expires)`,
quotas, challenges, and suspension of a removed member's vouchers. This design
is the issuer-side twin and deliberately uses the **same defaults** (K=3, 2 per
30 days, 180-day suspension, recommended 30-day minimum age) and the same
penalty rule (a fake's vouchers are suspended), so a person faces one set of
rules. They do not duplicate each other:

- Personhood's vouch produces a **credential** any integrator can check; the
  chain's produces **chain membership** no issuer can forge or revoke alone.
- The same QR round trip can carry both: after `confirm`, a wallet that also
  holds an OpenLine member key could co-sign the chain's admit digest. Not
  built here.
- An equivocation proof gossiped on OpenLine both revokes the Personhood
  credential (this endpoint) and is evidence for an on-chain `challenge`.
