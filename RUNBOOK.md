# RUNBOOK — clean machine to verified on your phone

This is the only document you need to take Personhood from a fresh `git
clone` to opening a URL on your Android phone, installing it as a PWA,
and completing a real W3C credential enrollment.

Total walk-through time: **45–75 minutes**, mostly waiting for free-tier
vendor signups to email you confirmation links. The actual hands-on
time is more like 20 minutes.

---

## Verify your setup at any point

```bash
bash scripts/check-setup.sh
```

Loads `.env.local`, pings each vendor's metadata endpoint, and prints
✓ / − / ✗ per section. No emails or SMS get sent. Re-run after each step
in this RUNBOOK to confirm the previous step worked.

## TL;DR for the impatient

```bash
# 0. prereqs (one-time):
#    Go 1.22+, Node 20+, git, gh, fly CLI, vercel CLI.

# 1. clone
git clone git@github.com:sagearbor/personhood.git
cd personhood

# 2. local sanity check
bash scripts/test-all.sh                 # every go.work module, with -race
bash scripts/e2e-email.sh                # real server on loopback: enroll → issue → verify
(cd app/web && npm install && npm run build)

# 3. one-time vendor signups (see §3 for links):
#    Persona, SendGrid, Twilio, Fly.io, Vercel

# 4. local dev (one terminal each):
#    A) server:  export ISSUER_ED25519_SK_B64=$(...); go run ./src/server/cmd/server
#    B) web:     cd app/web && npm run dev
#    open http://localhost:3000 in your laptop browser to test

# 5. deploy:
fly launch --no-deploy
fly secrets set ISSUER_ED25519_SK_B64=... SENDGRID_API_KEY=... TWILIO_ACCOUNT_SID=... \
                TWILIO_AUTH_TOKEN=... TWILIO_FROM=... PERSONA_API_KEY=... \
                PERSONA_TEMPLATE_ID=... PERSONA_WEBHOOK_SECRET=... \
                SERVER_PUBLIC_URL=https://<your-app>.fly.dev \
                CORS_ALLOWED_ORIGINS=https://<your-web>.vercel.app
fly deploy

cd app/web
vercel link
vercel env add NEXT_PUBLIC_PERSONHOOD_SERVER_URL production  # <-- paste Fly URL
vercel --prod

# 6. point Persona webhooks at https://<your-app>.fly.dev/v1/methods/government-id-liveness/webhook

# 7. open https://<your-web>.vercel.app on your Android phone, Add to Home Screen, complete the flow.
```

---

## 1. Prereqs (one-time)

Install on your laptop:

| Tool | Why | Install |
|---|---|---|
| **Go 1.22+** | Server | <https://go.dev/dl/> or `brew install go` |
| **Node 20+** | Web app | <https://nodejs.org/> or `brew install node` |
| **git** | Source | `xcode-select --install` on macOS, or package manager |
| **gh** | GitHub CLI for PR auth | `brew install gh` then `gh auth login` |
| **fly** | Fly.io CLI | `brew install flyctl` |
| **vercel** | Vercel CLI | `npm i -g vercel` then `vercel login` |

Verify:

```bash
go version              # go version go1.22.x or newer
node --version          # v20.x.x or newer
fly version             # any
vercel --version        # any
gh auth status          # logged in
```

## 2. Clone + verify

```bash
git clone git@github.com:sagearbor/personhood.git
cd personhood
```

Run the tests across all modules — this confirms your Go toolchain works
end-to-end and the workspace resolves correctly:

```bash
bash scripts/test-all.sh
```

Expected: every module `ok`, ending in `test-all: all modules green`.
Total time: ~30 seconds. Then prove the round-1 path against a real server
process (builds the binary, starts it on a loopback port, enrolls by email,
issues, verifies with the CLI):

```bash
bash scripts/e2e-email.sh
```

Expected: `e2e PASSED`.

Build the web app once so `node_modules/` is primed:

```bash
cd app/web
npm install
npm run build
cd ../..
```

## 2b. Round 1 — email only (no vendor accounts except email delivery)

The first cohort (a handful of friends) needs exactly one thing to work:
**email delivery**. Everything else in §3 is optional for round 1.

| Need | Round 1 | Later |
|---|---|---|
| Email magic link | **SendGrid** (free, 100/day) — §3b | same |
| SMS OTP | skip (the web app shows **Skip for now**) | Twilio — §3c |
| ID + selfie anchor | skip (step shows "unavailable") | Persona — §3a |
| Server host | Fly.io — §6 | same |
| Web host | Vercel — §7 | same |

Round-1 credentials carry only the `email` method (strength 8, no anchor).
They satisfy [`docs/policies/round1-email.yaml`](docs/policies/round1-email.yaml)
and are rejected by every anchor-requiring policy (including OpenLine's
vote/claim policies) with `anchor_missing` — by design. The friend-facing
instructions are in [`FRIENDS.md`](FRIENDS.md); fill in the two URLs at the
top once §6 and §7 are done.

Deploy checklist for round 1, in order:

1. `fly launch --no-deploy`, then `fly secrets set` with **only**
   `ISSUER_ED25519_SK_B64`, `SENDGRID_API_KEY`, `SENDGRID_FROM` (§6).
   Leave `DEV_EXPOSE_CHALLENGE_SECRETS` unset — with it on, anyone can
   verify an address they don't own.
2. `fly deploy`; set `SERVER_PUBLIC_URL`; `fly deploy` again.
3. `vercel --prod` with `NEXT_PUBLIC_PERSONHOOD_SERVER_URL` (§7); set
   `CORS_ALLOWED_ORIGINS` on Fly to the Vercel URL.
4. Enroll yourself once from your phone using FRIENDS.md verbatim.
5. Verify your own credential the way an integrator would:
   ```bash
   go run ./tools/verify-credential -cred me.json \
       -policy docs/policies/round1-email.yaml -issuer-url https://<your-app>.fly.dev
   ```
6. Hand the issuer DID + public key to OpenLine to pin (it trusts issuers by
   an explicit allow-list, not by fetching `did.json` at runtime):
   ```bash
   curl -s https://<your-app>.fly.dev/.well-known/did.json | jq -r '.id, .verificationMethod[0].publicKeyJwk.x'
   ```
   OpenLine constructs `personhood.TrustedIssuers({ "<id>": <x decoded from base64url> })`
   and, for round 1, evaluates `docs/policies/round1-email.yaml` rather than its
   anchor policies.

**Keep the issuer key stable.** `ISSUER_ED25519_SK_B64` is the root of trust;
rotating it invalidates every credential issued so far. Back it up (e.g. a
password manager) the moment `gen-key` prints it.

## 2c. Airdrop-test anchors — fuzzy-extractor-selfie + social-vouching-graph (no vendor accounts)

STATUS.md checklist #10a/#10b: for OpenLine's UBI-claim / vote-eligibility
use cases, anchors must work for users with no ID, no bank, and no fixed
address. Unlike every other anchor/supplementary method in §3, **neither of
these needs a vendor signup** — both are self-hosted. That also means both
are off by default; turn them on with env vars.

**`fuzzy-extractor-selfie`** (anchor, strength 70, $0.00) — set:

```bash
FUZZY_EXTRACTOR_ENABLED=1
```

That's the whole configuration. See
[`src/methods/fuzzy-extractor-selfie/README.md`](src/methods/fuzzy-extractor-selfie/README.md)
for what it does and does not do — notably, it accepts an already-binarized
biometric template; the on-device face-embedding extraction and liveness
check are a client concern this session did not wire into `app/web` (out of
scope; see that README's "What this module does NOT do").

**`social-vouching-graph`** (supplementary, strength 35, $0.00) — a
BrightID-style web of trust needs a bootstrap seed set and a shared secret
for the dev voucher authenticator:

```bash
SOCIAL_VOUCHING_ENABLED=1
SOCIAL_VOUCHING_SECRET=<a long random string; treat like a password>
SOCIAL_VOUCHING_SEED_IDS=alice,bob,carol   # comma-separated, each seeded at trust 1.0
```

Without at least a few seed ids (and, per the method's `RequiredVouches`
default of 3, ideally more than that reachable via chained vouching — see
the README), nobody can ever pass the ceremony. See
[`src/methods/social-vouching/README.md`](src/methods/social-vouching/README.md)
for the vouch-submission flow and why this stays supplementary rather than
an anchor despite STATUS.md's checklist wording.

**Try it locally** (mirrors §4's local dev flow, using
[`docs/policies/airdrop-anchor-example.yaml`](docs/policies/airdrop-anchor-example.yaml)):

```bash
export PATH=$PWD/tmp/go/bin:$PATH   # this repo's private Go toolchain, if you don't have go on PATH
export FUZZY_EXTRACTOR_ENABLED=1
SEED=$(cd src/server && go run ./cmd/gen-key)
ISSUER_ED25519_SK_B64=$SEED SERVER_ADDR=127.0.0.1:8090 SERVER_PUBLIC_URL=http://127.0.0.1:8090 \
  CORS_ALLOWED_ORIGINS=http://localhost:3000 \
  go run ./src/server/cmd/server &

curl -s http://127.0.0.1:8090/v1/methods | jq '.methods[] | select(.id=="fuzzy-extractor-selfie")'
```

`tests/e2e_airdrop_anchors_test.go` runs the full flow (including the
social-vouching vouch endpoint) against a real compiled server binary — read
it for the exact request shapes if you're integrating a client.

## 3. Vendor signups

Open a notes app — you'll be copying keys into `.env.local` shortly. Each
section below explains what to copy and where to find it.

### 3a. Persona (anchor: government ID + selfie liveness)

1. Visit <https://withpersona.com/dashboard> and create a free account.
2. Switch to the **Sandbox** environment in the top-left environment picker.
3. Create an inquiry template:
   - <https://withpersona.com/dashboard/inquiry-templates>
   - Click **+ Add inquiry template** → pick the **Government ID + Selfie** preset → save.
   - Copy the **Template ID** (starts with `itmpl_`). This is `PERSONA_TEMPLATE_ID`.
4. Create an API key:
   - <https://withpersona.com/dashboard/api-keys>
   - Click **+ New API key**. Sandbox keys start with `persona_sandbox_`.
   - Copy the key once — Persona does not show it again. This is `PERSONA_API_KEY`.
5. The webhook secret comes later (after you deploy the server in §6).

### 3b. SendGrid (email magic link)

1. Visit <https://signup.sendgrid.com/> and create an account.
2. Verify a Single Sender at
   <https://app.sendgrid.com/settings/sender_auth/senders>. The easiest
   path: use your personal Gmail address; SendGrid emails you a link to
   click. Once verified, copy the verified email address — this is
   `SENDGRID_FROM`.
3. Create an API key at <https://app.sendgrid.com/settings/api_keys> with
   the **Mail Send** permission. Copy the `SG.xxxxx...` value — this is
   `SENDGRID_API_KEY`. Shown once.

### 3b-alt. Generic SMTP (no SendGrid signup — Gmail app password, Fastmail, etc.)

If you'd rather not create a SendGrid account, `src/methods/email` ships a
second, always-compiled `Sender` (`SMTPSender`, stdlib `net/smtp`, no build
tag) that talks to any SMTP relay. Set these instead of the `SENDGRID_*`
vars:

| Env var | Example | Notes |
|---|---|---|
| `SMTP_HOST` | `smtp.gmail.com` | or `smtp.fastmail.com`, your own relay, etc. |
| `SMTP_PORT` | `587` | STARTTLS (default if unset). Use `465` for implicit TLS. |
| `SMTP_USER` | `you@gmail.com` | omit entirely for an open relay that needs no auth. |
| `SMTP_PASS` | a 16-char **app password**, not your login password | see below. |
| `SMTP_FROM` | `you@gmail.com` | must be a mailbox `SMTP_USER` is allowed to send as. |

**Gmail app password:** enable 2-Step Verification on the Google account,
then visit <https://myaccount.google.com/apppasswords>, create an app
password for "Mail", and use the 16-character value (spaces stripped) as
`SMTP_PASS`. Gmail caps free accounts around 500 messages/day — plenty for a
friends-and-family round 1.

**Fastmail:** <https://www.fastmail.com/settings/security/apppasswords> →
new app password scoped to "SMTP" → use as `SMTP_PASS` with `SMTP_HOST=smtp.fastmail.com`.

`email.NewSenderFromEnv()` (`src/methods/email/factory.go`) prefers a
sendgrid-tagged build with `SENDGRID_API_KEY`+`SENDGRID_FROM` set, then falls
back to `SMTPSender` when `SMTP_HOST`+`SMTP_FROM` are set, then falls back to
`LogSender`. You can build and deploy the **default** binary (no
`-tags sendgrid` needed) and use SMTP exclusively; `SMTPSender` is covered by
a fake-SMTP-server unit test (`src/methods/email/smtp_sender_test.go`,
runs in `bash scripts/test-all.sh`, no network needed) and notes in
`src/methods/email/README.md`.

**Sanity-check credentials before wiring them into Fly:**

```bash
export PATH=$PWD/tmp/go/bin:$PATH   # if using the private Go toolchain
SMTP_HOST=smtp.gmail.com SMTP_PORT=587 \
SMTP_USER=you@gmail.com SMTP_PASS='xxxx xxxx xxxx xxxx' \
SMTP_FROM=you@gmail.com \
go run ./src/server/cmd/server &   # or the compiled binary; local dev only
# then trigger an enrollment (curl or the web app) and confirm the mail
# actually lands in the recipient inbox, not just that Send() returned nil.
```

For the round-1 `fly secrets set` step in §2b, swap
`SENDGRID_API_KEY SENDGRID_FROM` for `SMTP_HOST SMTP_PORT SMTP_USER SMTP_PASS SMTP_FROM`
if you're using SMTP instead of SendGrid.

### 3c. Twilio (SMS OTP)

1. Visit <https://www.twilio.com/try-twilio> and sign up. They give you a
   ~$15 trial credit and a free verified-trial number.
2. Once in the console:
   - **Account SID** + **Auth Token** are on the console home. Copy both.
     `TWILIO_ACCOUNT_SID` starts with `AC`. `TWILIO_AUTH_TOKEN` is a hex
     string. The auth token is shown once.
   - Get a phone number:
     <https://console.twilio.com/us1/develop/phone-numbers/manage/incoming>
     — trial accounts get one number free. Copy the E.164 form (e.g.
     `+15551234567`) — this is `TWILIO_FROM`.
   - **Verify your destination phone**:
     <https://console.twilio.com/us1/develop/phone-numbers/manage/verified>
     — trial accounts can only text verified numbers. Add the phone you
     plan to receive OTPs on.

### 3d. Fly.io (server host)

```bash
fly auth signup
```

The CLI walks you through email confirmation. Free tier is enough for
this demo (you'll deploy a single shared-cpu-1x VM with 256 MB).

### 3e. Vercel (web host)

```bash
vercel login
```

Email-link login. Free tier is fine.

## 4. Local dev test (laptop)

Verify the whole flow works locally before paying for any deploys.

In one terminal, start the server with `LogSender`s so you don't have to
wire up SendGrid / Twilio yet:

```bash
# Generate an Ed25519 signing key. The line printed to stdout goes
# in your shell for this session.
export $(go run ./src/server/cmd/gen-key 2>/dev/null | grep ISSUER_ED25519)
export SERVER_ADDR=":8080"
export SERVER_PUBLIC_URL="http://localhost:8080"
export CORS_ALLOWED_ORIGINS="http://localhost:3000"
go run ./src/server/cmd/server
```

In a second terminal, start the web app:

```bash
cd app/web
npm run dev
```

Open <http://localhost:3000>. You should see the Personhood UI. Run through
email (and optionally SMS) — the magic link and the OTP are printed in the
**server** terminal, not actually sent. Paste the link into any tab; the
email step notices within a few seconds. (`DEV_EXPOSE_CHALLENGE_SECRETS=1`
additionally returns the link in the `/begin` API response for scripts —
never set it on a deployed server.)

If something else already listens on `:8080` (e.g. an OpenLine node), pick
another port: `SERVER_ADDR=127.0.0.1:8090 SERVER_PUBLIC_URL=http://127.0.0.1:8090`
and `NEXT_PUBLIC_PERSONHOOD_SERVER_URL=http://127.0.0.1:8090 npm run dev`.

Once that's working locally, kill both processes; we move to real
delivery + deploy next.

## 5. Real local delivery (optional but recommended)

Skip this if you're confident in vendor wiring; otherwise, validate
SendGrid and Twilio against real services from your laptop before paying
for a deploy.

Put your keys in `.env.local` at the repo root (this file is
gitignored):

```bash
cp .example.env .env.local
$EDITOR .env.local
```

Fill in everything from §3. Then run with the `sendgrid twilio` build
tags so the real senders are linked in:

```bash
set -a
source .env.local
set +a
go run -tags 'sendgrid twilio' ./src/server/cmd/server
```

You can run a sanity check on SendGrid without sending mail:

```bash
bash scripts/test-sendgrid.sh
```

— this hits SendGrid's `/v3/scopes` and `/v3/verified_senders` endpoints
and prints the result. If you see your verified sender in the list,
you're ready.

## 6. Deploy the server to Fly.io

From the repo root:

```bash
fly launch --no-deploy
# Accept the defaults; let it use the existing Dockerfile and fly.toml.
# If asked to pick an app name and one is taken, append your initials.
```

Set every secret in one command (round 1: only the first three lines are
required — omit the Twilio/Persona ones and those methods simply do not
register):

```bash
SK=$(go run ./src/server/cmd/gen-key 2>/dev/null | grep ISSUER_ED25519 | cut -d= -f2)
fly secrets set \
  ISSUER_ED25519_SK_B64="$SK" \
  SENDGRID_API_KEY="SG.xxx..." \
  SENDGRID_FROM="you@yourdomain.com" \
  TWILIO_ACCOUNT_SID="AC..." \
  TWILIO_AUTH_TOKEN="..." \
  TWILIO_FROM="+1..." \
  PERSONA_API_KEY="persona_sandbox_..." \
  PERSONA_TEMPLATE_ID="itmpl_..." \
  PERSONA_WEBHOOK_SECRET="placeholder_set_in_step_8"
```

Deploy:

```bash
fly deploy
fly status              # confirm 1 machine is running
fly logs                # tail server logs (Ctrl-C to detach)
```

Once deployed, capture your URL:

```bash
APP_URL="https://$(fly status --json | jq -r '.Hostname')"
echo "Server is at: $APP_URL"
fly secrets set SERVER_PUBLIC_URL="$APP_URL"
fly deploy              # restart to pick up SERVER_PUBLIC_URL
```

Smoke test:

```bash
curl -s "$APP_URL/healthz" | jq
# {"status":"ok"}

curl -s "$APP_URL/v1/methods" | jq '.methods[].id'
# "email"
# "sms"
# (no government-id-liveness yet — PERSONA_WEBHOOK_SECRET still placeholder)
```

## 7. Deploy the web app to Vercel

```bash
cd app/web
vercel link              # select the right org, accept the default project name
vercel env add NEXT_PUBLIC_PERSONHOOD_SERVER_URL production
# Paste the Fly URL from step 6.

vercel env add NEXT_PUBLIC_PERSONHOOD_SERVER_URL preview
# Paste the same URL (preview branches hit the same server).

vercel --prod
```

Note the production URL Vercel prints (`https://<project>.vercel.app`).

Finalize CORS on the server so the web app can call it:

```bash
cd ..   # back to repo root
fly secrets set CORS_ALLOWED_ORIGINS="https://<your-project>.vercel.app"
fly deploy
```

## 8. Register the Persona webhook

In the Persona dashboard:

1. Go to <https://withpersona.com/dashboard/webhooks>.
2. Click **+ Add webhook**.
3. URL: `https://<your-app>.fly.dev/v1/methods/government-id-liveness/webhook`
4. Subscribe to `inquiry.completed` and `inquiry.expired`.
5. Save. Persona shows the **signing secret** on the confirmation screen —
   this is `whsec_…`. Copy it now (it is not shown again).

Push the real secret to Fly and redeploy so the gov-id method registers:

```bash
fly secrets set PERSONA_WEBHOOK_SECRET="whsec_..."
fly deploy
```

Verify the method is now registered:

```bash
curl -s "$APP_URL/v1/methods" | jq '.methods[].id'
# "email"
# "government-id-liveness"      <-- newly registered
# "sms"
```

## 9. Install on your Android phone

1. On your phone, open Chrome and navigate to `https://<your-project>.vercel.app`.
2. The Personhood UI should load with the four-step progress at the top.
3. Tap Chrome's overflow menu (⋮) → **Add to Home screen**. Confirm.
4. Find the Personhood icon on your home screen — tap to launch. The app
   opens **without** the Chrome address bar, in standalone mode. You're
   now running it like a native app.

## 10. Complete enrollment

1. **Email**: type your email, tap **Send magic link**. Open the link in
   the email Gmail / Outlook delivers (it can be on the same phone — the
   magic link returns you to a success page). Return to the Personhood
   app tab, tap **I clicked it**.
2. **SMS**: type the phone number you verified in Twilio's trial
   verified-numbers list (E.164 format, with `+`). Tap **Text me a code**.
   The OTP arrives in 5–15 seconds. Type it in, tap **Verify**.
3. **ID + selfie**: tap **Open Persona**. A new tab/window opens on
   `inquiry.withpersona.com`. Follow the flow: pick a country, photograph
   a government ID (driver's licence works), then complete the selfie
   liveness check. When Persona shows "all done", return to the
   Personhood tab. Within 15–30 seconds the status pill should flip to
   **verified**.
4. **Credential**: tap **Sign & issue**. The server signs a W3C VC and
   returns it. Tap **Save to this device** — if your phone supports
   biometric WebAuthn (most do), it prompts you for FaceID / fingerprint
   to register a passkey before saving. Tap **Copy JSON** if you want a
   copy to inspect.

You're done. You now have a Personhood credential bound to your device
that includes one anchor (ID + selfie) + two supplementary methods.

## 11. Troubleshooting

| Symptom | Likely cause | Fix |
|---|---|---|
| `Cannot reach the issuer` on first load | `NEXT_PUBLIC_PERSONHOOD_SERVER_URL` is wrong or the server is offline. | `vercel env ls` to confirm; `fly status` to confirm the machine is running. |
| Email magic link never arrives | SendGrid key invalid or sender not verified. | `bash scripts/test-sendgrid.sh` (from a local checkout with `.env.local` populated). |
| SMS code never arrives | Trial Twilio account hasn't verified the destination number. | <https://console.twilio.com/us1/develop/phone-numbers/manage/verified> |
| `government-id-liveness` not in `/v1/methods` | One of `PERSONA_API_KEY`, `PERSONA_TEMPLATE_ID`, `PERSONA_WEBHOOK_SECRET` not set on Fly. | `fly secrets list` to confirm all three are present. |
| Persona webhook returns 401 | `PERSONA_WEBHOOK_SECRET` mismatch. | Re-copy the secret from <https://withpersona.com/dashboard/webhooks> and `fly secrets set` it. |
| Add-to-Home-Screen has no Personhood option | Browser didn't see the manifest. | Force-reload (long-press refresh in Chrome → "Empty cache and hard reload"). |
| Icon is broken / generic | Manifest icons failed to render. | Open `https://<your-web>.vercel.app/icon.png` directly — should show the lime monogram. |
| Persona flow opens but stays on "completing inquiry" forever | Webhook URL wrong, or `SERVER_PUBLIC_URL` was set incorrectly so Persona is calling a stale URL. | Confirm in Persona's webhook delivery log; redeploy after fixing. |
| CORS errors in the browser console | `CORS_ALLOWED_ORIGINS` on the server doesn't include the Vercel URL. | `fly secrets set CORS_ALLOWED_ORIGINS=https://...` (exact origin, no trailing slash). |
| Email step stays "waiting for click" after the link was opened | The link belonged to an older session (server restarted — sessions are in-memory), or the poll cannot reach the server. | Tap **Check again**; else **Start over**. `fly logs` shows the `/v1/sessions/` polls. |
| A friend's credential fails `verify-credential` with `unknown_issuer` | The issuer key changed (`ISSUER_ED25519_SK_B64` rotated) or `-issuer-url` points at a different deployment. | `fly secrets list`; compare `.well-known/did.json` `x` with the `issuer_public_key_b64url` in the CLI output. |
| `verify-credential` says `anchor_missing` | Expected for round-1 credentials against any anchor-requiring policy. | Use `docs/policies/round1-email.yaml`, or add an anchor method (Persona §3a/§8). |

## 12. Cost expectation

Free tier covers a personal demo indefinitely.

| Service | Free tier limit | Once exceeded |
|---|---|---|
| Fly.io | 3 shared-cpu-1x VMs, 3 GB persistent storage | ~$2/mo per running VM |
| Vercel | 100 GB bandwidth / mo on Hobby | $20/mo for Pro |
| SendGrid | 100 emails/day forever | ~$20/mo for 50k/mo |
| Twilio | ~$15 trial credit, then pay-as-you-go | ~$0.0075/SMS in the US |
| Persona | Sandbox is free unlimited; production starts at ~$1.50/inquiry | Variable |
| fuzzy-extractor-selfie | $0.00 — self-hosted, no vendor | $0.00 |
| social-vouching-graph | $0.00 — self-hosted, no vendor | $0.00 |

The demo's per-verification cost is ~$2 dominated by Persona. The
single-call SMS verification is a fraction of a penny. The two airdrop-test
methods (§2c) add nothing to that bill — they exist precisely because a
deployment that needs to stay free (or reach users with no ID/bank/address)
can't rely on Persona/Plaid at all.

## Next

- Wrap as a Capacitor app for the Play Store — see Sprint 3 in
  [`STATUS.md`](STATUS.md).
- Add more methods from [`docs/06-methods-catalog.md`](docs/06-methods-catalog.md) — Plaid bank link
  is a strong second anchor; HaveIBeenPwned breach-presence is a useful
  tier-up for the email method.
