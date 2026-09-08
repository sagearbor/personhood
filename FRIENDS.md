# FRIENDS.md — enroll in under 5 minutes

You've been asked to try Personhood: a way to prove "I'm a real person" to
an app **without** telling it who you are. Round 1 uses only your email. It
takes about three minutes. Nothing is installed; nothing about you is stored
except a hash.

> **Owner: fill these two lines in before sending this file.**
>
> - App: `https://<your-web>.vercel.app`  ← the enrollment page
> - Issuer: `https://<your-app>.fly.dev`  ← the server that signs credentials
>
> Until they are filled in, the app is only reachable on the owner's laptop
> (see "Local run" at the bottom).

## What you do

1. **Open the app link** on your phone or laptop. You'll see four steps:
   Email, SMS, ID + Selfie, Credential. Only Email is required in round 1.
2. **Type your email address** and tap **Send magic link**.
3. **Open the email** ("Confirm your email") and tap the link. A page says
   "Email verified". Close it.
4. **Go back to the app tab.** Within a few seconds the Email step turns
   green by itself (it checks every few seconds; tap **Check again** if you're
   impatient). Tap **Continue**.
5. **SMS:** tap **Skip for now**. (Round 1 has no SMS delivery set up.)
6. **ID + Selfie:** tap **Skip this step**. (No ID vendor in round 1.)
7. **Credential:** tap **Sign & issue**. You now have a signed credential.
   Tap **Save to this device** (your phone may ask for FaceID/fingerprint —
   that's optional and stays on your phone).
8. If the owner asked you to send it back: tap **Copy JSON** and paste it into
   a message to them. It contains no personal data — just an opaque holder ID,
   a hash, timestamps, and a signature. Check for yourself: tap **Show full
   credential JSON**.

Done. Each person should enroll **once**; the credential is valid for a year
and the email proof for 90 days.

## Things that can go wrong

| You see | What it means | Do this |
|---|---|---|
| "Cannot reach the issuer" | The server link is wrong or the server is asleep. | Wait 10 s and reload (free-tier servers wake on first request). If it persists, tell the owner. |
| No email after 2 minutes | Spam folder, or a typo. | Check spam; tap **Change address** and retry. |
| "Disposable email addresses are not accepted." | Throwaway-mail domains are blocked. | Use your normal address. |
| Link says "Email verification failed: invalid_or_expired_token" | Links expire after 15 min, and each link works once. | Back in the app tap **Resend link**, use the newest email. |
| Step stays "waiting for click" after you clicked | The app tab lost its session (browser killed it), or you clicked a link from an older session. | Tap **Check again**; if still stuck, **Start over** and repeat from step 2. |

## What you're actually getting

A [W3C Verifiable Credential](https://www.w3.org/TR/vc-data-model/) signed by
the issuer's Ed25519 key. It says: *this holder proved control of an email
inbox at this time* (strength 8, "supplementary"). It does **not** say you're
unique — that needs an "anchor" method (ID + selfie, bank link, device
attestation) which round 2 adds. Apps that need one-person-one-vote will
reject round-1 credentials with `anchor_missing`; that's by design. Round 1
is about proving the plumbing works end to end with real people.

## Owner notes (not for friends)

- Verify a credential someone sent you:
  ```bash
  go run ./tools/verify-credential -cred friend.json \
      -policy docs/policies/round1-email.yaml -issuer-url https://<your-app>.fly.dev
  ```
  Exit 0 = good. `code` tells you why if not.
- Give OpenLine (or any integrator) the issuer key to pin:
  `curl -s https://<your-app>.fly.dev/.well-known/did.json | jq -r '.id, .verificationMethod[0].publicKeyJwk.x'`
- Each restart of the v0.1 server wipes in-flight sessions (in-memory); issued
  credentials stay valid because verification only needs the public key.
- **Keep `ISSUER_ED25519_SK_B64` stable.** Rotating it invalidates every
  credential issued so far.

### Local run (before deploying)

```bash
# terminal 1 — issuer (magic links are printed to this terminal, not emailed)
export $(go run ./src/server/cmd/gen-key 2>/dev/null | grep ISSUER_ED25519)
SERVER_ADDR=127.0.0.1:8090 SERVER_PUBLIC_URL=http://127.0.0.1:8090 \
  go run ./src/server/cmd/server
# terminal 2 — web app
cd app/web && NEXT_PUBLIC_PERSONHOOD_SERVER_URL=http://127.0.0.1:8090 npm run dev
# open http://localhost:3000 ; paste the link from terminal 1 into a tab
```

Or run the whole thing headless: `bash scripts/e2e-email.sh`.
