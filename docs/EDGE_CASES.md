# Edge cases: where each one is tested

The owner's edge-case list (2026-11-03), row by row. **Test** names a subtest
of `TestEdgeCases` in `src/server/edge_cases_test.go`
(`go test -run 'TestEdgeCases/<id>' -v ./src/server`), or another test.
**manual** means it needs a person or a real phone (steps in
[08-no-false-lockout.md](08-no-false-lockout.md) and the PR). **not yet**
means no code handles it. **OpenLine** means it lives in the chain or the
wallet, not in this repo.

All `TestEdgeCases` rows run with `NO_FALSE_LOCKOUT` on; `flag_off_unchanged`
checks that nothing changes with it off.

## Who you are

| Row | Expected outcome | Test |
|---|---|---|
| Identical twins | Second twin is routed, declines the match, gets their own credential with K+2 in-person vouchers; the first twin is untouched; the second cannot recover the first's identity | `identical_twin`, `twin_cap` |
| Strangers who look alike | Routed, never refused on a face alone; a face match cannot move the enrolled person's identity; manual review gives the look-alike their own credential | `lookalike_cannot_take_over`, `lookalike_manual_review` |
| Same person, changed look | A second identity at the selfie's false-non-match rate | **manual** (Pixel 10 re-enroll test in docs/selfie-anchor.md); other anchors bound it |
| Lost, stolen or broken phone | Face + one more factor starts a recovery; 72 h cancel window; same nullifier on the new key; old credential revoked, old key barred | `lost_phone_recovery`, `stolen_phone_old_key_cancels`, `recovery_by_vouchers`, `recovery_rate_limits`, `TestNoFalseLockout_DocumentFactor`, `TestNoFalseLockout_RecoveryReview` |
| (Lost credential, kept key) | Same key + same face is re-issued at once | `reenroll_same_key` |
| No ID documents | In-person vouch path | `TestIntegration_InPersonVouchAnchorAndEquivocation` (inperson_test.go). Bootstrapping a new village with no vouchers: **not yet** (manual review is the stopgap) |
| Shared family phone | 5 people, 1 phone, 1 inbox: 5 credentials, 5 nullifiers; the per-IP limiter only delays | `shared_family_phone`. `ANDROID_KEY_ATTESTATION_MAX_PER_DEVICE` must not be set below a household (doc 08, section 3) |
| Blind or low vision | Manual review leads to an `operator-review` anchor | `no_selfie_possible`. Spoken prompts: **not yet** |
| Can't blink or turn head | Same | `no_selfie_possible` |
| Religious face covering | Same; an in-person vouch still needs a selfie today | `no_selfie_possible` |
| No camera / feature phone | Same (needs someone else's phone for the web app) | `no_selfie_possible`; feature phones: **not yet** |
| Very old phone (Android 6) | No attestation is "absent, not failed" | `old_phone_no_attestation`; the 12 MB face model on that phone: **manual** |
| Dual citizen with two passports | Flag only | **not yet** (document-chip anchor, built separately) |
| Refugee or stateless person | Vouching, NGO vouchers, manual review | `no_selfie_possible` covers the review path; NGO vouchers: **not yet** |
| Death | Proof of life for UBI | **not yet** (UBI is off at launch) |

## Cheaters

| Row | Expected outcome | Test |
|---|---|---|
| Same email many times | One inbox, one nullifier | `same_email_twice` |
| Many throwaway emails | Email-only gets through; official votes need an anchor | **OpenLine** (policy); `TestResolveIdentifierSeed` covers the seed |
| Emulator or VM farm | Blocked by device attestation | `src/methods/app-attest-device` tests; real device: **manual** |
| Farm of real phones | Each fake still needs a face or vouches | `twin_cap` bounds declined matches per face; otherwise **manual** |
| Deepfake or virtual camera | Not stopped in a browser | **not yet** (docs/selfie-anchor.md threat table) |
| Rented or sold identity | Mostly undetectable | **not yet** |
| Vouch ring of colluding friends | Strikes and suspension when caught | `TestInPerson_PenalizeCascade`; undoing a wrong strike: `wallet_double_sign_bug`, `TestInPerson_ReinstateUndoesPenalize` |
| Vouch over a video call | Accepted, recorded as `same_network: false` | `vouch_over_video` |
| Coercion | Cannot be stopped remotely | **not yet** (private ballots, 2027) |

## Money

| Row | Expected outcome | Test |
|---|---|---|
| Spend the same coins twice | Chain orders payments | **OpenLine** |
| Look-alike tries to spend your money | Payments need the key, not the face | **OpenLine**; on this side a look-alike cannot move the key's identity: `lookalike_cannot_take_over` |
| Thief with your unlocked phone | Fingerprint before sending, daily limit | **OpenLine**. Here: the thief can cancel the owner's recovery; the owner's way out is manual review (doc 08) |
| Instant pay: same deposit at 10 shops | Bond covers it, identity frozen | **OpenLine**; the freeze is `/v1/revocations/equivocation` (`TestIntegration_InPersonVouchAnchorAndEquivocation`) |
| Wallet bug signs one payment twice | Banned, then appeal, review, reinstatement; the same proof cannot ban again; vouchers' strikes lifted | `wallet_double_sign_bug`. "The wallet never re-signs a slot": **OpenLine** |
| Offline payments that conflict | Instant tier only, capped by the bond | **OpenLine** |

## Voting

| Row | Expected outcome | Test |
|---|---|---|
| Vote twice with credentials from two issuers | One issuer per poll | **OpenLine** (#179) |
| Someone learns how you voted | Private ballots | **not yet** (2027) |

## Compatibility

| Row | Expected outcome | Test |
|---|---|---|
| `NO_FALSE_LOCKOUT` off | Duplicate face refused as before, no `face_match`, new routes absent | `flag_off_unchanged` |
