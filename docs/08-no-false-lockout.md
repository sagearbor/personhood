# Never false-lockout an honest person

Status: **implemented, off by default** (`NO_FALSE_LOCKOUT=1`; needs
`HOLDER_REVOCATION_ENABLED=1`; the review queue and appeals also need
`ADMIN_TOKEN`).

**Owner principle.** A signal may route someone to another path, or raise
their friction. It must never revoke, refuse forever, or exclude an honest
person who has no alternative. Every refusal must offer a next step.

Code: `src/server/{nolockout,recovery,review}.go`, hooks in `handlers.go`,
ledger changes in `holderrevoke.go`, `Reinstate` in
`src/methods/social-vouching/accountability.go`, `OnMatch` in
`src/methods/fuzzy-extractor-selfie/method.go`. Tests:
`src/server/edge_cases_test.go` (the owner's list, see
[EDGE_CASES.md](EDGE_CASES.md)) and `nolockout_test.go`.

## 1. A face match is routed, not refused

Before: a selfie that matched an enrolled face got
`duplicate_person_detected` and nothing else. A twin, a look-alike, and the
same person on a new phone were all stuck.

Now the result is the same (`success: false`,
`error_reason: duplicate_person_detected`, so old clients behave as before),
plus a `face_match` object on the `/complete` response:

```json
"face_match": {
  "message": "This face looks like someone who is already enrolled. ...",
  "options": [
    {"action": "recover",       "endpoint": "/v1/recovery/start", "description": "This might be you: ..."},
    {"action": "other_anchor",  "endpoint": "/v1/face-match/decline", "methods": ["in-person-vouch", "..."], "description": "Not you (a twin or a look-alike): ..."},
    {"action": "manual_review", "endpoint": "/v1/reviews", "description": "Ask a person at the issuer to review your case."}
  ]
}
```

The issuer records which enrolled face matched, against the session, on its
side only. The commitment never reaches the client: if it did, anyone with a
photo of you could learn your nullifier binding.

| Choice | What happens |
|---|---|
| **The same holder key** (a native wallet that kept its key but lost its credential) | No question asked: the selfie succeeds and the credential is re-issued on the same identity. |
| **"This might be you"** | Recovery (section 2). |
| **"Not me"**: `POST /v1/face-match/decline {session_id}` | The selfie is not used. The in-person-vouch anchor's selfie prerequisite counts as met, but it asks for `FACE_MATCH_EXTRA_VOUCHES` (default 2) more vouchers than usual. A document anchor (for example the document-chip method being built in parallel), or an approved manual review, also works. The credential's nullifier comes from the person's own email/phone seed or holder key, never from the matched face. After declining, the session cannot start a recovery of that identity. |
| **Manual review**: `POST /v1/reviews {session_id, kind: "face_match"}` | An operator decides. Approval lets the holder key complete the `operator-review` anchor (section 4). |

**Abuse bound.** At most `FACE_MATCH_MAX_OTHERS` (default 2) different
holders can be issued through a declined match on one enrolled face (twins,
triplets). The next one gets `403 face_match_limit` with the manual-review
step. Each one also costs `K + 2` accountable vouchers.

**What this does not fix.** The selfie anchor's false-match rate
(docs/selfie-anchor.md) still means that past a few hundred people many
honest newcomers will see this screen. The routing turns that from a dead
end into extra friction; it does not make face dedupe work at scale.

## 2. Recovery: lost, broken or stolen phone

A recovery moves an existing identity (the same nullifier seed) to a new
holder key.

**A face match alone is never enough**, because a look-alike would steal the
identity. `POST /v1/recovery/start {session_id}` needs, in the new key's
session:

1. a selfie that matched the identity's face, and
2. at least one more factor:

| Factor | How it is checked |
|---|---|
| `identifier` | The session verified an email or phone whose seed was once issued together with this face. The link is kept per identity (`personhood-identity-links`), so it survives earlier recoveries. |
| `vouchers` | `RECOVERY_VOUCHES` (default 2) people who vouched in person for the current holder have vouched in person for the new key, through the normal ceremony. |
| `document` | The session completed a method listed in `RECOVERY_DOCUMENT_METHODS` whose attestation digest was once issued together with this face. Empty by default. Intended for the document-chip anchor: set `RECOVERY_DOCUMENT_METHODS=<its method id>` once it is merged, provided its digest is stable per document. |
| `operator_review` | An operator approved a `kind: "recovery"` review. |

Without a factor: `403 recovery_factor_missing`, with one `next_steps` entry
per factor this issuer offers, plus manual review.

**The cancel window.** A started recovery waits `RECOVERY_DELAY` (default
72 h). During it:

- the old key can see it: `GET /v1/recovery/pending?holder_did=<old DID>`
  returns it, with `role: "old_key"` and the exact `cancel_message` to sign.
  The OpenLine wallet should poll this on open (not built yet, see below);
- `RECOVERY_NOTIFY_WEBHOOK`, when set, gets a JSON POST for every event
  (`recovery_started`, `recovery_cancelled`, `recovery_completed`) with the
  old holder DID;
- either key can cancel: `POST /v1/recovery/{id}/cancel {holder_did,
  signature_b64}`, signing `personhood-recovery/v1\ncancel\n<issuer
  DID>\n<id>`;
- the new key cannot be issued anything else (`409 recovery_pending`).

The issuer stores only HMACs of email addresses and phone numbers, so it
**cannot email or text the old owner**. Notification is pull (the old
wallet) plus the webhook.

**Completion.** After the window, from a new session of the new key:
`POST /v1/recovery/{id}/complete {session_id}`. The issuer:

1. bars the old key (holder ban, reason `recovered: ...`; its nullifiers are
   *not* banned) and revokes every credential the ledger recorded for it;
2. credits the session with the identity's face, so
   `POST /v1/credentials/issue` gives the new key a credential with the
   **same** `nullifierBinding`.

**Rate limits.** One recovery in progress per identity
(`409 recovery_pending`). None for `RECOVERY_COOLDOWN` (default 30 days)
after one completes (`429 recovery_cooldown`), which stops a ping-pong
between an owner and a thief. After 3 cancelled attempts within that window,
only manual review (`403 recovery_needs_review`). Each refusal names the
manual-review step. An operator-approved recovery skips the cooldown and
cancel limits but keeps the cancel window.

**Threats, honestly.**

| Attacker has | Result |
|---|---|
| A look-alike face only | Cannot start a recovery. |
| A look-alike face **and** the victim's inbox (shared family email, phished account) | Can start one. The victim's old key sees it and cancels within 72 h. If the victim also lost their phone, they cannot: this is the residual risk, and why the window and the webhook exist. |
| The victim's unlocked phone | Can cancel the owner's recovery. The owner's way out is manual review. |
| A ring of colluding vouchers | Can start one with the voucher factor; the old key can still cancel. |

**Limits.** Only identities issued after `NO_FALSE_LOCKOUT` was turned on
are in the index; older ones get `404 recovery_identity_unknown` with the
manual-review step. Recovery moves selfie-anchored identities. An email-only
identity needs no recovery: the same inbox already gets the same nullifier on
any key (the old key's credential stays valid until revoked). The old key's
vouch standing (strikes, quota) does not move to the new key.

## 3. Audit: every refusal, revocation and ban

| Where | Refusal | Way forward for an honest person |
|---|---|---|
| Selfie dedupe (`fuzzy-extractor-selfie`) | `duplicate_person_detected` | Routed (section 1). Same key: re-issued. |
| In-person-vouch anchor | `prerequisite_missing:fuzzy-extractor-selfie` | Take the selfie; if it matches someone, decline and continue; if a selfie is impossible (blindness, palsy, face covering, no camera), `POST /v1/reviews {kind: "no_selfie"}`. |
| In-person-vouch anchor | `insufficient_vouches:have=n/k` | Collect more vouches; vouches persist across sessions. |
| Equivocation (`/v1/revocations/equivocation`) | Holder banned, credentials revoked, seeds banned, vouchers struck | Appeal: `POST /v1/appeals {holder_did, message, signature_b64?}` (signed by the banned key when it still exists, `AppealMessage`; unsigned is accepted and marked so). The operator reviews (for example reproduces a wallet bug) and approves: reinstatement. |
| Operator revoke-holder | Same as above | Same appeal. |
| Re-enrollment after a ban | `403 holder_revoked` / `403 nullifier_revoked` | The message is neutral (no longer "for cheating") and, with `NO_FALSE_LOCKOUT`, carries `next_steps: [appeal]`. |
| Vouch strikes (`voucher_suspended`) | A voucher whose candidate was revoked | Time-limited (180 days per strike). If the candidate was honest, reinstating the candidate takes the strike back and restores graph trust. The refusal text now says so. |
| `candidate_revoked` (vouch ceremony) | A revoked key cannot be vouched for | Appeal, then reinstatement clears it. |
| Identifier send limit (`identifier_rate_limited`) | 5 messages per address per hour | Temporary, with `Retry-After`. |
| Per-IP rate limiter (429) | Start 6/min, begin 4 burst | Temporary, with `Retry-After`. A family or village behind one IP is delayed by seconds, not refused (tested). |
| `device_enrollment_limit` (app-attest, `ANDROID_KEY_ATTESTATION_MAX_PER_DEVICE`) | N sessions per attested device per 30 days | Off by default. The attestation is one method, not a gate: the person can still enroll without it. **Operators: do not set N below a household (6 or more).** |
| Recovery limits | `recovery_pending`, `recovery_cooldown`, `recovery_needs_review` | Each names manual review. |
| Declined-match cap | `face_match_limit` | Manual review. |
| Recovery without a second factor | `recovery_factor_missing` | Lists every factor this issuer offers, plus manual review. |

### Reinstatement

`POST /v1/admin/reinstate {holder_did, reason}` (or approving an appeal):

- lifts the holder ban and the bans on every nullifier its issuances touched;
- records a **pardon** for the equivocation proof that caused the ban, keyed
  by a canonical digest (key, context, slot, sorted payload digests), so
  re-posting the same proof, in either statement order, gets
  `409 evidence_pardoned` instead of banning again. A *new* double-sign
  still bans;
- takes back the strikes the revocation gave the holder's vouchers (the
  store now records which vouchers a revocation struck), clears their
  suspension when no strikes remain, and divides their graph trust back;
- does **not** un-revoke the old credentials (verifiers may have cached the
  status list). The person enrolls again and, on the same seed, gets the
  same `nullifierBinding`.

A key retired by a completed recovery cannot be reinstated
(`409 retired_by_recovery`): its identity lives under the new key.

## 4. The manual review queue and the `operator-review` anchor

| Route | Who |
|---|---|
| `POST /v1/reviews {session_id, kind, message}` | Anyone with a live session and a holder key. Kinds: `face_match`, `recovery`, `no_selfie`, `other`. One open review per key per kind. |
| `POST /v1/appeals {holder_did, message, signature_b64?}` | A banned key (or someone on its behalf). |
| `GET /v1/reviews/{id}` | The person who asked: status and the operator's note. |
| `GET /v1/admin/reviews` | Operator: the open queue. |
| `POST /v1/admin/reviews/{id}/decide {approve, note, old_holder_did?}` | Operator. A note is required: say what you checked. |

Approving `face_match`, `no_selfie` or `other` lets the holder key complete
**`operator-review`**, an anchor at strength **50** (the floor), within 30
days. It is exactly as strong as the operator's process: a video call, a
meeting, a known NGO worker's word. Approving `recovery` opens a recovery
with factor `operator_review`. Approving an appeal reinstates.

The queue holds at most 5,000 open cases (`503 review_queue_full` after
that). Reviews live in the same Firestore / Redis store as the holder ledger.

## 5. Configuration

| Env | Default | Meaning |
|---|---|---|
| `NO_FALSE_LOCKOUT` | off | Turns all of this on. Needs `HOLDER_REVOCATION_ENABLED`. |
| `RECOVERY_DELAY` | `72h` | Cancel window (Go duration, at least `1m`; use `2m` on a test issuer). |
| `RECOVERY_COOLDOWN` | `720h` | No second recovery of one identity within this. |
| `RECOVERY_VOUCHES` | 2 | Old vouchers who must re-vouch for the voucher factor. |
| `RECOVERY_DOCUMENT_METHODS` | empty | Methods whose attestation identifies a document. |
| `RECOVERY_NOTIFY_WEBHOOK` | empty | URL that gets recovery events. |
| `FACE_MATCH_EXTRA_VOUCHES` | 2 | Extra in-person vouchers after declining a match. |
| `FACE_MATCH_MAX_OTHERS` | 2 | Holders per face through a declined match. |

`GET /v1/config` reports `no_false_lockout`, `manual_review` and
`recovery_delay_seconds`.

## 6. Not done here

- **OpenLine wallet**: poll `/v1/recovery/pending` for its own DID and offer
  "Cancel" (sign `cancel_message`); show the routing options. The web app in
  this repo does both.
- **Wallet double-sign prevention**: the owner's fix "the wallet never
  re-signs a slot" belongs in the OpenLine wallet. This PR adds the appeal
  path for when it happens anyway.
- **Liveness (proof of life) for UBI** and death: not started.
- The in-person vouch store is still in memory (doc 07); strikes taken back
  by a reinstatement are as durable as the strikes themselves.
