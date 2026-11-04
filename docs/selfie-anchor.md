# Selfie anchor (`fuzzy-extractor-selfie` with `SELFIE_ANCHOR=1`)

A document-free check that a phone browser can run: an on-device face model,
a randomized active-liveness ceremony, and the issuer's fuzzy-extractor
dedupe. It is off by default. This page says what it does, what it measured,
and what it does **not** prove.

**Summary.** It is useful for stopping casual double enrollment in a small
test cohort. It is **not** a Sybil-resistant anchor. A browser cannot prove
that its camera feed is real. On top of that, the face model's false-match
rate means that past a few hundred people, honest newcomers start being
refused as "already enrolled". The issuer advertises strength **50** in this
mode, which is the anchor floor, so it can be tested end to end. The evidence
supports about **25-30** for a web-only deployment (see
[Recommended strength](#recommended-strength)).

## Flow

1. `POST /v1/methods/fuzzy-extractor-selfie/begin` returns three of four
   challenges (`turn_left`, `turn_right`, `blink`, `closer`) in random order,
   plus a `challenge_token`. The token is an HMAC, under a key that never
   leaves the issuer process, over the session id, the issue time and that
   order.
2. The web app (`app/web/components/steps/SelfieStep.tsx`, `lib/face/`)
   opens the front camera and loads two models from its own origin:
   - MediaPipe Face Landmarker: 478 landmarks plus blink scores, every frame.
   - dlib's face-recognition ResNet, run through `@vladmandic/face-api` on
     TensorFlow.js: a 128-number descriptor.

   Neither model is fetched from a CDN.
3. The ceremony (`lib/face/liveness.ts`) goes like this:
   1. Look straight at the camera. The app takes 3 frontal descriptors.
   2. Do each challenge in the issued order. Each one has to start from a
      neutral pose after its prompt appears, be seen within 8 s, and take at
      least 250 ms. Exactly one face must stay in view the whole time.
   3. Look straight at the camera again. The app takes 3 more descriptors.

   If the start and end descriptors are more than 0.45 apart, the app
   refuses, because the face changed mid-ceremony.
4. The app averages the 6 descriptors, subtracts a population mean and takes
   256 signed random projections (SimHash, `lib/face/binarize.ts`). That
   gives a **32-byte template**.
5. `POST .../complete` sends four things: `template_b64`, `template_version`
   (`dlib128-simhash256-v1`), the token, and `liveness`. The `liveness` field
   holds each challenge's kind and reaction time in ms, the frame count, and
   the parallax scores.

   The issuer checks:
   - the token
   - that the challenges came back in the issued order
   - that each reaction time is between 250 ms and 10 s
   - that the reaction times add up to no more than the time since begin
   - that the ceremony took between 3 s and 10 min

   It then runs the fuzzy-extractor dedupe against every enrolled record. A
   match is refused as `duplicate_person_detected`. A new face is stored as
   helper data plus a commitment, and the credential's `nullifierBinding`
   comes from that commitment (`NullifierBindingForBiometricCommitment`).

**What leaves the phone:** 32 bytes of template plus a few timing numbers.
The photo, the video frames and the 128-number descriptor never leave the
phone.

**What the issuer stores:** per enrolled face, 32 bytes of helper data and a
32-byte commitment, in Firestore (`personhood-selfie-accumulator`) or Redis.
This counts as biometric data, for two reasons:
- The repetition code leaves only 17 secret bits per record, so anyone
  holding a record can recover the template in about 2^17 hashes.
- A template can be matched against a template computed from any photo of
  the same person.

### Why duplicates are refused, not re-issued

If a duplicate got the existing commitment back, anyone holding a photo of
you could obtain your nullifier binding and link your OpenLine activity to
your face. Refusing leaks less: it only tells the caller "this face is
enrolled".

With `NO_FALSE_LOCKOUT=1` ([08-no-false-lockout.md](08-no-false-lockout.md))
the refusal is no longer a dead end. The response carries next steps: the
same holder key is re-issued at once; "this might be you" starts a recovery
that needs a second factor and a 72-hour cancel window; "not me" (a twin or
a look-alike) continues with another anchor; or a manual review. The
matched commitment still never reaches the client.

## Measured accuracy

**Data.** The [Face Research Lab London Set](https://doi.org/10.6084/m9.figshare.5047666)
(DeBruine & Jones 2017, **CC BY 4.0**): 102 adults, one neutral and one
smiling frontal studio photo each, plus 3/4 views. It is the only multi-image
face set found whose license clearly allows this use. The photos are not in
the repo.

**Method.** `scripts/selfie-eval/eval.mjs` runs the app's own alignment and
descriptor code in headless Chrome. The issuer's real `Gen`/`Rep` then
scores the result in `TestEvalTemplates`.

**Results.** The population mean used here was computed from these same 204
photos. A 2-fold cross-validated run, where the mean comes from the other
half of the people, gave the same numbers (FNMR 3.9%, FMR 0.24%).

| Measure | Result |
|---|---|
| Descriptor distance, same person (neutral vs smiling) | mean 0.21, max 0.52 |
| Descriptor distance, different people | mean 0.77, min 0.38 |
| **False non-match** (same person not recognized, so a 2nd identity) | **3.9%** (8 of 204 directed pairs) |
| **False match** (two people collide) | **0.23%** (94 of 41,208 directed pairs) |
| Enrollment simulation: 102 people enroll in turn | 6 honest people refused as duplicates |
| ...then everyone enrolls again with their other photo | 5 of 102 got a second identity |

**How to read these numbers:**

- **The FNMR is optimistic.** Both photos of each person came from the same
  studio session, with the same light and camera. Re-enrolling on another
  day, in other light, or on another phone will miss more often. Someone
  deliberately changing glasses, lighting or angle will miss more often
  still. **Real-world FNMR is unmeasured.** The Pixel 10 test below starts
  to measure it.
- **The FMR caps the cohort size.** With FMR p = 0.0023 per pair, the chance
  that an honest newcomer collides with one of N enrolled people is
  1 - (1 - p)^N:

  | N enrolled | Chance an honest newcomer is refused |
  |---|---|
  | 100 | ~21% |
  | 300 | ~50% |
  | 1,000 | ~90% |

  A tighter threshold trades this for more second identities. At 40 bits,
  FMR drops to about 1e-5 but FNMR rises to about 25-30%. No setting of this
  model works at population scale. Even the best commercial face algorithms
  (NIST FRVT 1:N) are far from the FMR of about 1e-9 that deduplicating
  millions of people needs. Only iris systems get near that.
- **Twins.** Identical twins will collide (the second twin is refused, or
  with `NO_FALSE_LOCKOUT=1` routed to another anchor).
  Close relatives raise the false-match rate above the figure measured here
  on unrelated people.
- **Demographics.** The London Set is small and mostly of European descent.
  Both the population mean and the error rates may differ for other
  populations. This is not measured.

**Parallax** (`parallaxScore`, same data): real 3/4 head turns scored
0.27-0.44. A frontal photo warped as though a flat print were turned 25-40°
in front of the camera scored 0.001-0.063. More decisively, the warped print
never reached the yaw needed to pass a turn challenge (max 0.09, threshold
0.16), because a flat picture's nose stays centred between its face edges.
The client therefore requires a parallax score of at least 0.05 on the head
turns.

**Headless smoke test.** A still London photo fed to Chrome as a fake camera
loaded the models, passed the frontal step in about 0.6 s, and then failed
its first challenge on timeout.

**Speed.** About 32-43 ms per descriptor on a desktop GPU (WebGL). Phone
speed is not yet measured.

**Download.** The first run fetches about 12 MB compressed: a 13.5 MB WASM
runtime, a 6.4 MB recognition model and a 3.8 MB landmark model. That is a
real cost on a $50 phone with metered or intermittent data.

### Reproduce

```bash
cd app/web && npm ci && npm run face-models && cd ../..
# <dir>/<person>/<photo>.jpg, photos you have the right to use
node scripts/selfie-eval/eval.mjs --data <dir> --out tmp/selfie-eval
SELFIE_EVAL_TEMPLATES=$PWD/tmp/selfie-eval/templates.json \
  go test -v -run TestEvalTemplates ./src/methods/fuzzy-extractor-selfie
```

## Threats

| Threat | Effect | Mitigation here | Residual |
|---|---|---|---|
| **Scripted client** (no camera at all) | Posts random 32 bytes. Random bytes look like a new person every time, so it gets unlimited identities. | Must read `begin`, echo the token and send plausible timings. | **Not stopped.** This is the decisive weakness of any browser-only biometric. Only rate limits, the invite gate and pairing with device attestation slow it down. |
| **Printed photo / photo on a screen** | Fails the challenges. | Random order, reaction-time windows, yaw and parallax geometry. | Stopped for static images, including AI-generated stills. |
| **Replayed video** of the person doing challenges | Must match a random order of 3 of 4 challenges (24 orders) live, with the right timing. | Random order, 8 s windows, neutral pose between challenges. | An attacker with 24 recorded clips and a virtual camera could splice them. Unlikely, but possible. |
| **Virtual-camera injection** (OBS, a rooted phone, an emulator) | The browser cannot tell a virtual camera from a real one. `getUserMedia` gives no provenance. | None in a browser. | **Not stopped.** |
| **Real-time deepfake / face-swap puppeteering** through a virtual camera | Performs any challenge live. Lets one operator enroll many synthetic faces. | None. Parallax and blink checks are passed by good real-time 3D face swaps. | **Not stopped.** Combined with the scripted client, this is why the strength must stay low. |
| **Twins / look-alikes** | Second person refused. | With `NO_FALSE_LOCKOUT=1`: routed to another anchor (K+2 vouchers, a document, or manual review); cannot take over the first identity. | More friction for the second person; at most `FACE_MATCH_MAX_OTHERS` per face. |
| **Same person re-enrolling** with changed glasses, light or angle | Gets a second identity at the FNMR rate. | Averaging frames, a population-centred hash. | 4% in the studio, more in the field. |
| **Issuer database leak** | Templates are recoverable, and linkable to any photo of the person. | Helper data only. No photos or descriptors are stored. | Treat it as biometric data. |
| **Photo-holder learns enrollment status** | The refusal reveals "this face is enrolled". | Duplicates are refused rather than re-issued (see above). | Membership is revealed; the nullifier is not. |

### Pairing with Android key attestation

The `android-key-attestation` method (built separately) can prove that a
request came from a genuine, non-rooted Android device with a hardware-backed
key. That closes part of what the browser cannot: the scripted client and
emulator farms, though not a real-time deepfake on a real phone's
virtual-camera path. It needs a **native app**. A browser page cannot get a
key attestation chain.

The useful combination is the native OpenLine wallet doing both in one
session:
- the attestation key signs the template and the challenge token;
- the issuer refuses templates not signed by an attested device;
- the issuer allows one selfie enrollment per attested device.

The result is still "one identity per real phone, with a face that looks
live", not "one per human". The false-match limit above still applies.

## Recommended strength

| Deployment | Recommended | Why |
|---|---|---|
| Web only (this PR) | **25-30**, supplementary | The scripted client and virtual camera are unstopped, and FMR caps the cohort. Fine as a recency/liveness signal, not as an anchor. |
| Native app + Android key attestation + this ceremony, cohort under a few hundred | **50-55**, anchor floor | Device attestation raises the cost per identity to a real phone. Face dedupe is meaningful at small N. |
| Any deployment at population scale | Do not rely on face dedupe | FMR 1e-3 per pair cannot dedupe thousands. Use vouching, in-person, or iris-class hardware. |

The code advertises 50 under `SELFIE_ANCHOR=1` (`SelfieAnchorStrength`) so
the test flow produces an anchored credential. **Do not open validator seats
or value-bearing UBI on this anchor alone.**

## Pixel 10: what the hardware can and cannot add

The owner's assumptions are **confirmed**:

- **Thermal / body heat: no.** The Pixel 10 has no thermal camera. The Pixel
  8 Pro's object-temperature sensor was not carried forward, and was never a
  body-heat camera or an app-facing face sensor.
- **Iris: no.** There is no IR iris camera. Face Unlock uses the ordinary
  front camera with ML, and there is no IR depth or dot projector.
- **Fingerprint: yes/no only.** The ultrasonic under-display sensor answers
  only through `BiometricPrompt` (native) or WebAuthn user verification
  (web). The app gets a yes or no, or a key unlock. It never gets a template.
  That proves "the enrolled user of this phone is present", not uniqueness
  across people.

**What could add value:**

- **Motion parallax during head turns** (done here). It is cheap and beats
  flat images. Real-time 3D face swaps reproduce it.
- **Screen-flash photometric challenge.** The screen flashes a random colour
  sequence, and the app checks that the face's reflected colour changes in
  step, frame-accurately. That is harder for replayed video and simple
  virtual cameras. It is a cheap next step.
- **IMU correlation.** Compare `DeviceMotionEvent` accelerometer and
  gyroscope readings with the "move closer" challenge and the camera's
  apparent motion. A desktop virtual camera has no matching phone motion.
  Spoofable on an emulator, but it raises the bar for web-only attacks.
- **Key attestation plus a biometric-bound key** (native). Proves a genuine
  device whose owner passed the fingerprint or face check. This is the
  strongest per-device signal on a Pixel, and it is per device, not per
  person.
- **Rear dual-pixel or multi-camera depth.** Not exposed to the web or to
  third-party front-camera use. Not available.

## Test on a Pixel 10

**What the lead deploys first:**

1. Deploy the issuer (test mode) with `SELFIE_ANCHOR=1` and
   `FIRESTORE_PROJECT_ID` set, so enrolled faces survive restarts:
   ```bash
   PROJECT=arborfam-hub WEB_ORIGIN=<live origins>,<preview-channel-origin> \
     FIRESTORE_PROJECT_ID=arborfam-hub SELFIE_ANCHOR=1 INVITE_CODE=... \
     bash scripts/deploy-cloudrun.sh
   ```
   - Check that `GET /v1/methods` lists `fuzzy-extractor-selfie`, anchor,
     strength 50.
   - The preview-channel origin must be in `WEB_ORIGIN`, or CORS blocks
     every call.
2. Build the web app against that issuer (`npm run build` fetches the models
   into `public/face-models/`) and deploy it to a preview channel:
   ```bash
   cd app/web && NEXT_PUBLIC_PERSONHOOD_SERVER_URL=<issuer-url> npm run build && cd ../..
   firebase hosting:channel:deploy selfie-test --only web
   ```
3. Send the owner the preview URL with `?selfiedebug=1` appended.

**What the owner does, on the Pixel 10 in Chrome:**

1. Open the preview URL. Enter the invite code, then do the email step (the
   on-screen link works in test mode). Skip the ID step.
2. On "Show it is you, live", tap **Start camera** and allow camera access.
   The first load takes a few seconds while it downloads about 12 MB.
3. Look straight at the camera, then follow each prompt. The prompts appear
   in a random order: turn your head to your **own** left or right, blink,
   or bring the phone closer.
   - The debug line under the prompt shows `yaw`. It should go **positive**
     when you turn to your own left. If it goes negative, the left/right
     convention is flipped on this device. Report that, because every
     left/right challenge would then time out.
4. Expect "Selfie check complete". Continue, then **Sign & issue**. The
   credential's anchor should be `fuzzy-extractor-selfie`.
5. **Re-enroll test (FNMR):** open a fresh session in an incognito tab and
   do it again. Repeat in different light, with and without glasses. Each
   run should end in "This face already has a Personhood identity". Note
   how many runs get through instead; each one is a second identity.
6. **Different-person test (FMR):** have one or two other people enroll on
   the same phone. They should succeed.
7. **Spoof tests:**
   - Hold up a printed photo, or another phone showing a photo or video of
     you. It should fail with "took too long" or "did not look like a real
     3D face".
   - Have a second person step into the frame. It should fail with "more
     than one face".
8. Report back the debug numbers from step 3 for a few runs (`ms` and
   `parallax`) and the pass/fail counts from steps 5 to 7. These are the
   first real-device FNMR and threshold data.
