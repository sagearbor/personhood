# Launch-day runbook

How to take the live issuer from "invite-only test mode" to public, check
it, and roll it back. Commands assume the repo root, `gcloud` and
`firebase` logged in, and project `arborfam-hub`. `RUNBOOK.md`
"§6-alt / §7-alt" holds the first-deploy history; this file covers the
launch itself.

| | URL |
|---|---|
| Web | https://personhood-web.web.app |
| Issuer | https://personhood-issuer-664594784582.us-central1.run.app |
| Issuer DID | `did:web:personhood-issuer-664594784582.us-central1.run.app`, key `x=AB3aeJhjKNB7FvsX2QjsSMKbceYdAyS2KduSLj7ZjMY` |
| Relying party | OpenLine seed https://openline-seed-664594784582.us-central1.run.app (pins the key above) |

## 0. Ground rules

- **`deploy-cloudrun.sh` replaces every env var** (`--set-env-vars`). If you
  leave out `INVITE_CODE`, the gate turns off. If you leave out
  `DEV_EXPOSE_CHALLENGE_SECRETS`, it defaults to `1` (test mode). Always pass
  the full intended set.
- **Never rotate the issuer key** (`personhood-issuer-key` in Secret Manager)
  on launch day. OpenLine pins it, so a new key makes every claim fail until
  OpenLine is redeployed. `scripts/e2e-openline.sh` catches a mismatch.
- **Roll back first, debug after** (§4).

## 1. The night before

```bash
bash scripts/test-all.sh                                   # all modules, -race
gh run list --workflow live-e2e.yml --limit 3              # scheduled live checks green
gcloud run revisions list --service personhood-issuer --region us-central1 --project arborfam-hub --limit 3
```

Write down the serving revision. It is your rollback target.

## 2. Switches the owner flips (in this order)

Each switch is a separate deploy. Verify after each one (§3).

1. **Real email** (STATUS.md 4b). Put the SMTP password in Secret Manager,
   not a plain env var, then deploy with `SMTP_HOST`/`SMTP_PORT`/`SMTP_USER`/
   `SMTP_FROM` and `DEV_EXPOSE_CHALLENGE_SECRETS=0`. Send one real link to
   yourself and make sure it lands in the inbox, not spam.
   - `scripts/e2e-remote.sh`, `e2e-openline.sh` and `phone-check.mjs` all
     **need test mode** to read the link. Once it is off, the scheduled
     `live-e2e` workflow fails at the magic-link step. Before you flip it,
     either disable the workflow
     (`gh workflow disable live-e2e.yml`) or point it at a separate test-mode
     revision with a tag (`--tag e2e --no-traffic`).
2. **Drop the invite gate.** Deploy without `INVITE_CODE`. Rate limiting
   (`src/server/ratelimit.go`) is now the only brake on enrollment volume.
3. **Privacy notice live.** The owner approves the wording, then the web app
   links to it.

## 3. Verify after every deploy

```bash
curl -s $ISSUER/v1/config        # gates are what you intended
curl -s $ISSUER/.well-known/did.json | grep -o '"x":"[^"]*"'   # key unchanged
PERSONHOOD_INVITE_CODE=… bash scripts/e2e-remote.sh $ISSUER "$PERSONHOOD_INVITE_CODE"   # test mode only
PERSONHOOD_INVITE_CODE=… bash scripts/e2e-openline.sh                                  # test mode only
PERSONHOOD_INVITE_CODE=… node scripts/phone-check.mjs                                  # test mode only
gh workflow run live-e2e.yml                                   # same three from GitHub's IPs
```

Then do it by hand on a real phone: enroll, save the credential, and claim at
OpenLine (see openline's `FRIENDS.md` §4).

## 4. Roll back

```bash
gcloud run services update-traffic personhood-issuer --region us-central1 --project arborfam-hub \
  --to-revisions=<previous-revision>=100
# web: Firebase Hosting → Release history → Roll back (or `firebase hosting:clone` the previous version)
```

Traffic moves within seconds and env vars go back with the revision. Confirm
with §3.

## 5. Data retention (owner decision; deletes data)

Records expire only when read, so unclicked email tokens (with the address)
and abandoned sessions stay forever. A Firestore TTL policy removes them
within about 24h of `expires_at`:

```bash
for c in personhood-sessions personhood-email-tokens personhood-sms-otps; do
  gcloud firestore fields ttls update expires_at --collection-group=$c --enable-ttl --project arborfam-hub
done
```

TTL deletes count toward the free tier's 20k deletes/day.
`personhood-govid-*` has no expiry field. It is empty today (Persona is not
wired) and needs a retention decision before Persona goes live.

## 6. Watching it

- **Synthetic checks:** `live-e2e` runs every 6h. A failed scheduled run
  emails the repo owner.
- **Errors:** Cloud Logging, filter
  `resource.labels.service_name="personhood-issuer" severity>=ERROR`. The
  issuer writes structured JSON (`severity`, `httpRequest.requestUrl` = route
  pattern).
- **Abuse:** `jsonPayload.httpRequest.status=429` by route shows who the limiter
  is throttling. To tune it, change `DefaultRateLimitConfig` and redeploy.
  `RATE_LIMIT=off` is for load tests only.
- **Cold start:** about 1s for the first request after scale-to-zero. The web
  app shows "Waking up the issuer" after 3s and times out at 20s with a Retry
  button.

## 7. Capacity and cost ceiling (measured 2026-10-20, revision 00005)

Load test from one client (`ab`, `/health`, 2000 requests, concurrency 25):
**185 req/s, p50 104 ms, p95 216 ms, p99 312 ms, 0 failures** on one
instance (1 vCPU, 256 MiB, `--max-instances 1`). A burst of 300 requests at a
rate-limited route let through 68 (burst 60 plus refill) and answered the rest
with 429. `/health` stayed 200 throughout. A forged `X-Forwarded-For` doesn't
bypass the limiter: the key is the client IP that Cloud Run appends.

A real enrollment is about 10–40 requests, most of them session polling. One
instance comfortably handles a launch-day cohort of hundreds of people
enrolling at once. Raising `--max-instances` is now state-safe (Firestore),
but it multiplies both the per-IP limits and the cost ceiling below, so it is
an owner decision.

**Worst-case monthly cost, from list prices (check against the current
price sheet):**

| Item | Free tier | Worst case | Why it's bounded |
|---|---|---|---|
| Cloud Run CPU (request-based billing) | 180k vCPU-s | ~$59/mo if the single instance is busy 24/7 | `max-instances 1` caps it |
| Cloud Run memory | 360k GiB-s | ~$1/mo | same |
| Cloud Run requests | 2M/mo | ~$0.40 per extra million. A flood sustained at the measured ~185 req/s all month is ~480M requests, about **$190** | rate-limited requests (429) are still billed requests |
| Firestore | 50k reads, 20k writes, 20k deletes per day | about $0 while invite-gated. Without the gate, writes are capped by 6 starts/min per IP. | per-IP limiter |
| Firebase Hosting | 10 GB stored, 360 MB/day transfer | ~$0.15/GB beyond | static, ~100 kB first load |
| Cloud Logging | 50 GiB/mo ingest | $0 at this volume | one line per request |

So a single attacker flooding the issuer for a whole month costs about
**$250/mo at most**. Normal use is $0. There is no billing budget alert on
`arborfam-hub` that this repo knows of. Setting one ($10, emails at 50%/100%)
is free and is on the owner-decision list.
