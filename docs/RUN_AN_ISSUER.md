# Run your own Personhood issuer

An issuer is the server that checks a person (today: that they control an
email inbox) and signs a credential saying so. If one company or one cloud
account runs the only issuer, blocking it stops everyone from proving they
are a person. Several independent issuers, run by different people in
different places, remove that single point of failure. This guide gets one
running on any Linux machine with Docker, in about 15 minutes.

The kit lives in [`scripts/issuer-kit/`](../scripts/issuer-kit/).

## What you need

- **A small Linux server** with a public IPv4 address: any $4–6/month VPS
  (1 vCPU, 1 GB RAM, 10 GB disk is plenty; amd64 or arm64). A home machine
  works too if ports 80 and 443 reach it.
- **Docker** with the compose plugin, plus `git`, `curl` and `openssl`
  (`curl -fsSL https://get.docker.com | sh` on most distributions).
- **Ports 80 and 443 open** to the internet (HTTPS certificates are issued
  automatically by Let's Encrypt through Caddy).
- **A way to send email** (an SMTP account, e.g. a Gmail app password, or a
  SendGrid key). Without it the issuer can only run in rehearsal mode.
- **Optional: a domain name.** Without one, `--sslip` gives you a working
  HTTPS address of the form `203-0-113-7.sslip.io`.

**Cost:** the VPS, about $5/month. Everything in the kit is free software.

## Start it

```bash
git clone https://github.com/sagearbor/personhood.git
cd personhood/scripts/issuer-kit
./up.sh --sslip                    # or: ./up.sh --domain issuer.example.org
```

The first run creates `issuer.env` (readable only by you) with three fresh
secrets, builds the issuer, starts it with Redis and Caddy, and prints:

```
== issuer is up ==
public URL : https://203-0-113-7.sslip.io
DID        : did:web:203-0-113-7.sslip.io
public key : 9Xb...Qk   (Ed25519, base64url "x")
```

The DID and public key are public. They are what integrators pin.

Then set up email: open `issuer.env`, fill in the `SMTP_*` lines (or the
`SENDGRID_*` lines) and run `./up.sh --sslip` again. Optionally set
`ENROLLMENT_INVITE_CODE` to keep enrollment to people you give the code to.

To try it out first without email or HTTPS, run `./up.sh --local --test-mode`.
The issuer then listens on `http://127.0.0.1:8090` and shows sign-in links on
screen instead of emailing them. **Test mode lets anyone enroll any address,
so never use it for real.** Run `./up.sh` without `--test-mode` to switch it off.

Check the issuer from anywhere: `curl https://<your-address>/health`.

## Getting trusted

A credential is only useful where a verifier trusts its issuer. Send the
**DID and public key** that `up.sh` printed to the people running the
verifier; for OpenLine:

- **OpenLine nodes (testnet)** pin issuers in `OPENLINE_TRUSTED_ISSUERS`
  as `did=publicKey` entries (`did:web:203-0-113-7.sslip.io=9Xb...Qk`), next to
  the issuers already there. The node's `/health` lists them under
  `personhoodTrustedIssuers`.
- **OpenLine chain** keeps the trusted issuers in its genesis
  (`app_state.personhood.issuers`). Adding one later is a binding
  `personhood.issuers` proposal: a one-person-one-vote supermajority, so no
  single operator can add or remove an issuer.
- **The OpenLine wallet** already works with several issuers: it ships a list,
  fails over when one is unreachable, and tries issuers the user's node
  trusts first (OpenLine `docs/WALLET_NODES.md`, "Personhood issuers"). A
  wallet build can name yours with `EXPO_PUBLIC_PERSONHOOD_ISSUER_URLS`.
  Add your wallet's origin to `CORS_ALLOWED_ORIGINS` if it is not
  `https://openline-wallet.web.app`.

**Know the limit:** this kit checks email only (the `round1-email` policy).
That proves someone controls an inbox, not that they are one human, so
OpenLine's value chain does not accept it for voting or the airdrop; it is for
testnets and advisory polls until an anchor method (a real one-human check)
ships.

## Keep it safe

Back up right after the first start, and again from time to time:

```bash
./backup.sh            # writes backups/personhood-issuer-<time>.tar.gz (mode 0600)
```

The backup holds `issuer.env` and the Redis data. Move it **off the server**,
somewhere only you can read (an encrypted USB stick, a password manager file
attachment).

**Never do these:**

- **Never lose `ISSUER_ED25519_SK_B64`** (the signing key in `issuer.env`).
  Without it you cannot issue under the same DID again, and verifiers must
  pin a new key.
- **Never share or commit `issuer.env`.** Anyone with the signing key can
  forge credentials in your name. If it leaks, tell the integrators to remove
  your DID at once, then start over with a new key.
- **Never change `IDENTIFIER_HMAC_KEY`** once people have enrolled. It is
  what ties one inbox to one person. A new value forgets every binding, and
  every inbox can enroll again as a "new" person.
- **Never delete the `redis-data` volume** (`docker compose down -v`). It
  holds revocations and the one-inbox-one-voter records. `docker compose down`
  (without `-v`) is safe.
- **Never leave `--test-mode` on.**

## Day-to-day

| Task | Command (in `scripts/issuer-kit/`) |
|---|---|
| Status | `docker compose ps` |
| Logs | `docker compose logs -f issuer` |
| Update to the latest code | `git pull && ./up.sh --sslip` (same flags as before) |
| Stop | `docker compose --profile tls down` (keeps all data) |
| Revoke a credential | `curl -X POST https://<addr>/v1/admin/revoke -H "Authorization: Bearer $ADMIN_TOKEN" -d '{"credential_id":"urn:..."}'` with `ADMIN_TOKEN` from `issuer.env` |

**Restore on a new server:** clone the repo, unpack the backup into
`scripts/issuer-kit/` (`issuer.env` goes in place, `redis-data.tar` into the
volume: `docker compose up -d redis`, then
`docker compose exec -T redis sh -c 'tar -C /data -xf -' < redis-data.tar`,
then `docker compose restart redis`), point your domain at the new address and
run `./up.sh` with your usual flags. The DID stays the same as long as the
address does; with `--sslip` a new IP means a new DID, so a real domain is
better for anything long-lived.

## How it is built

- `docker-compose.yml`: the issuer (built from this checkout), Redis with
  append-only persistence on the `redis-data` volume, and Caddy for HTTPS
  (the `tls` profile; `--local` leaves it out). The issuer listens on
  loopback only; Caddy is the only thing exposed.
- With `REDIS_URL` set (the compose file does it), sessions, sign-in links,
  status-list slots, revocations and the one-inbox-one-voter seeds all live in
  Redis. Google Cloud deployments use Firestore for the same data.
- `up.sh` owns four lines of `issuer.env` (`SERVER_PUBLIC_URL`,
  `TRUSTED_PROXY_HOPS`, `DEV_EXPOSE_CHALLENGE_SECRETS` and, once, the three
  generated keys) and leaves the rest to you. It never prints a secret.
- One issuer runs as one instance. The kit does not scale out; it does not
  need to for a community-sized issuer (one Cloud Run instance measured
  ~185 requests/s).
