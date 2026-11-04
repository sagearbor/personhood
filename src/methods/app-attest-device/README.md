# app-attest-device

**Supplementary** verification method: device attestation. On Android it
uses **Android Key Attestation**, verified offline against Google's pinned
root keys. A near-free floor that stops emulator and VM bot farms cheaply.
iOS App Attest is still a dev stand-in (HMAC).

| Property | Value |
|---|---|
| Type | supplementary |
| Strength | 18 |
| Cost | $0.00 |
| Friction | low (no prompt; about a second on the phone) |
| Freshness | 30 days |
| Platforms | the native Android app (not web/kiosk); iOS dev stand-in only |

## What a pass proves, and what it does not

A pass proves: **a real, unmodified Android phone holds this key.** More
exactly, the key was generated inside the phone's secure hardware (TEE or
StrongBox), on a phone whose bootloader is locked and which booted its
manufacturer's signed system, for the app named in the certificate (and
signed with the expected key, if configured), in answer to this session's
nonce.

It does **not** prove "a unique human". One person with ten phones passes
ten times, a farm of real phones passes, and a real phone can be driven by
a remote bot. That is why it stays supplementary (strength 18) and can never
satisfy a policy's anchor requirement.

What it stops: emulators, cloud VMs, rooted phones with an unlocked
bootloader, custom ROMs, software keystores, replayed attestations from
another session, and (with the signer pinned) repackaged copies of the app.
That makes a bot farm buy and keep real phones, which is the point.

## Why Key Attestation and not Play Integrity

Play Integrity needs a call to Google's servers for every verification, and
the phone needs Google Play services. That is against the "unblockable"
goal: Google (or whoever blocks Google) could stop enrolment, and
de-Googled phones could never pass. Key Attestation is built into Android
(AOSP Keystore, Android 7+), and the issuer checks the chain offline. The
only optional network use is the revocation list, which is cached and can
be mirrored (below).

Play Integrity is not implemented. It could be added later as another
`Verifier` behind `PlatformRouter`, but Key Attestation is the default.

## Flow

1. **BeginCeremony** mints a random 32-byte nonce, stores it against the
   session, and returns it hex-encoded (`nonce`, `nonce_encoding: "hex"`).
2. The Android app generates a fresh P-256 key in the Keystore with
   `setAttestationChallenge(<the 32 nonce bytes>)` (StrongBox if the phone
   has it, else the TEE), reads the key's certificate chain, and deletes the
   key. OpenLine's wallet does this in `mobile/modules/key-attestation`.
3. It POSTs `{ "platform": "android", "certificate_chain": [<base64 DER>,
   ... leaf first] }` (or the same joined with `,` as `token`).
4. **CompleteCeremony** runs the verifier and records a digest on success.
   The chain itself never lands on the credential.

The attested key is not the wallet's holder key. The holder key is Ed25519
and the wallet can back it up and restore it on a new phone; a Keystore key
can never leave the phone, and Keystore Ed25519 needs Android 13+. The two
are tied through the session instead: the nonce belongs to the session, and
the holder key signs for that session at issuance (holder PoP).

## What the Android verifier checks (`androidkey.go`)

1. **Chain.** Each certificate is signed by the next, the issuer name
   matches, every certificate is inside its validity period, and the chain
   ends at (or is signed by) a **pinned Google root key**. Pinned (in
   `roots/`, from https://android.googleapis.com/attestation/root):
   - the RSA root `serialNumber=f92009e853b6b045` (SPKI SHA-256
     `feb2ea75…80fbae`), used since 2016 and reissued with the same key;
   - the ECDSA P-384 **Key Attestation CA1** (2025, SPKI SHA-256
     `3ee44512…cd07ec`), which Remote Key Provisioning chains use from 2026.

   Pinning is by public key, so any reissue of a root is accepted.
2. **The attestation extension** (OID `1.3.6.1.4.1.11129.2.1.17`) is in the
   leaf and **in no other certificate**. Otherwise an app could get its own
   attested key to sign a hand-made "leaf" saying anything.
3. `attestationChallenge` equals this session's nonce.
4. `attestationSecurityLevel` and `keyMintSecurityLevel` are both
   TrustedEnvironment or StrongBox (not Software).
5. A **hardware-enforced** RootOfTrust has `verifiedBootState = Verified`
   and `deviceLocked = true`.
6. Hardware-enforced `origin = GENERATED` (not imported).
7. `attestationApplicationId` lists the configured package, and, if signer
   digests are configured, every listed signing-certificate digest is one of
   them.
8. Optionally, no certificate's serial is on Google's revocation list.

Parsing is strict: trailing bytes, duplicate tags, or a non-DER boolean are
rejected.

Failure reasons (`MethodResult.ErrorReason`): `attestation_malformed`,
`attestation_chain_invalid`, `attestation_untrusted_root`,
`attestation_challenge_mismatch`, `attestation_not_hardware`,
`attestation_boot_not_verified`, `attestation_device_unlocked`,
`attestation_key_not_generated`, `attestation_wrong_app`,
`attestation_revoked`, `attestation_revocation_unavailable`,
`device_enrollment_limit`, `platform_unsupported`. The server logs each
outcome (`app-attest-device: success=… reason=…`), never the chain.

## Revocation list: fetch, cache, fail open or closed

Google publishes revoked attestation keys (mostly leaked device keys) at
https://android.googleapis.com/attestation/status. When enabled, the issuer
fetches it on first use, keeps it for an hour, and rechecks every
certificate's serial against it. If a refresh fails, the last list is kept
and used, however old. The question is only what to do when no list has
ever been fetched (Google unreachable at a cold start):

- **fail-open (default):** accept. A revoked key could pass during an
  outage, but enrolment cannot be stopped by blocking one Google URL, which
  is the owner's "unblockable" goal. The list changes slowly, and the
  realistic cost is a few leaked keys passing a supplementary check, not an
  anchor.
- **fail-closed:** reject (`attestation_revocation_unavailable`) until a
  list arrives. Stricter, but anyone who can block that URL can stop
  attestation (enrolment still works without it, for fewer points).
- **off:** don't check.

The URL is configurable, so the list can be mirrored (it is plain,
unsigned JSON, so trusting a mirror means trusting whoever serves it).

## Per-device dedupe: what is honest

Key attestation gives **no stable device id**. The certificate's
`uniqueId` and the serial/IMEI ID attestation need privileged system
permissions an ordinary app cannot get; the device-property fields a normal
app can request (brand, model) are shared by millions of phones.

What can honestly be said:

- On phones using **Remote Key Provisioning** (Android 12+, required for
  phones launching with Android 13+, so every Pixel 10), the certificate
  that signs the leaf is the phone's own short-lived attestation key, issued
  by Google's "Droid CA". The same phone shows the same key until it
  rotates (days to weeks); no other phone has it. `Evidence.DeviceHint` is
  the SHA-256 of that key.
- On older, factory-provisioned phones that certificate is a **batch key
  shared by many thousands of devices**, so no hint is given at all.

`ANDROID_KEY_ATTESTATION_MAX_PER_DEVICE=N` turns on a limiter: at most N
sessions per hint within 30 days, else `device_enrollment_limit`. It is a
speed bump against one phone enrolling many identities in a burst, not a
uniqueness check. Different hints never prove different phones, the hint
rotates, and the in-memory limiter is per process. It is **not** a
nullifier and must never feed `VerifiedIdentifier` or the credential's
nullifier binding.

## Old phones: "attestation absent" is not "attestation failed"

The owner's Alcatel Pixi 4 (Android 6) cannot pass: key attestation
arrived in Android 7, and the native wallet needs Android 7 too (React
Native's minimum), so on that phone the wallet runs as the web app, which
cannot attest at all. Cheap phones on Android 7+ with a software-only
keystore return a chain that fails as `attestation_not_hardware`.

Policy should treat these the same as not attempting:

- **Absent** (web wallet, iOS, Android < 7, issuer doesn't offer it,
  keystore refuses): the wallet skips the method. No points, no penalty.
- **Failed** (unlocked bootloader, software keystore, wrong app, wrong
  challenge): the method returns `Success: false`. Also no points. The
  reason is logged for operators. It is not a reason to refuse enrolment.

So attestation adds points to people who have it and never blocks people
who don't. Policies must leave another way to the same bar (email, SMS,
vouching, the fuzzy-extractor anchor). Note that
`docs/policies/default-floor.yaml` asks for 32 supplementary points, which
only the full floor (app-attest 18 + ip-asn 10 + turnstile 4) reaches; as
written it excludes every phone without hardware attestation. That needs an
owner decision before that policy is used for real users.

## Before turning it on for a live issuer

A policy with an `allowed_methods` list rejects any credential that carries
a method not on the list (`method_not_allowed`). OpenLine's `round1-email`
policy allows only `email`, so once the live issuer offers this method,
every credential from the Android wallet would include `app-attest-device`
and be refused by OpenLine nodes. Simply adding the method to that list is
not safe either: with `min_supplementary_points: 8` an attestation-only
credential (18 points, no email) would pass, the same hole ip-asn opened
in #55. The DSL has no "required method" today. Options for the owner:
add `required_methods` to the DSL (then allow both, require `email`), or
issue attestation only on a separate test issuer until an anchor-based
policy replaces round 1.

## Configuration (server)

All off by default. The method registers only when one of these is set
(`src/server/appattest.go`).

| Env var | Meaning |
|---|---|
| `ANDROID_KEY_ATTESTATION_PACKAGE` | Android application id to accept (`org.openline.wallet`). Turns real attestation on for platform `android`. |
| `ANDROID_KEY_ATTESTATION_SIGNER_SHA256` | Comma-separated SHA-256 of the APK signing certificate(s), as `apksigner verify --print-certs` prints them (colons fine). Optional but recommended. |
| `ANDROID_KEY_ATTESTATION_REVOCATION` | `off`, `fail-open` (default), `fail-closed`. |
| `ANDROID_KEY_ATTESTATION_STATUS_URL` | Status list URL (default Google's). |
| `ANDROID_KEY_ATTESTATION_MAX_PER_DEVICE` | Sessions per RKP device hint (0/unset: no limit). |
| `APP_ATTEST_SECRET` | HMAC dev stand-in. Alone: unchanged old behaviour for every platform. With the package set: serves `ios` only. |

```go
m := appattestdevice.NewMethod(appattestdevice.Config{
    Verifier: appattestdevice.PlatformRouter{
        appattestdevice.PlatformAndroid: appattestdevice.NewAndroidKeyVerifier(appattestdevice.AndroidKeyConfig{
            PackageName:   "org.openline.wallet",
            SignerDigests: signers,
            Revocation:    appattestdevice.NewStatusList(appattestdevice.StatusListConfig{Mode: appattestdevice.RevocationFailOpen}),
        }),
    },
    Store: appattestdevice.NewInMemoryStore(),
})
```

With several issuer replicas, the challenge store still needs a shared
backend (the nonce must be visible to the replica that gets `/complete`).

## Tests

`go test -race ./...` here. Real chains from Google's
[android/keyattestation](https://github.com/android/keyattestation) test
corpus (`testdata/android`, Apache-2.0, see NOTICE): Pixel 9 Pro StrongBox
and TEE (RSA root) and Pixel 9a StrongBox (new ECDSA root) pass; the same
chains fail with a wrong challenge, wrong package or signer, an expired
attestation key, or a missing root; a Pixel 8a and a Pixel 3 with unlocked
bootloaders fail; a real chain with a malformed RootOfTrust fails.
Synthetic chains with the same structure under a test root cover each
field: software level, missing or software-only RootOfTrust, unlocked,
self-signed boot, imported key, tampered leaf, untrusted root, an attested
app key used as an issuer, revocation (listed, stale cache, fail-open and
fail-closed), and the device-hint limiter.

## iOS

Still the `HMACDevVerifier` stand-in: not real attestation. A real
verifier parses the CBOR attestation object, validates the chain to Apple's
App Attest root, checks the nonce hash and pins the app id. iOS is low
priority for OpenLine.
