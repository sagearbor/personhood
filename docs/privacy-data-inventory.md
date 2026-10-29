# Privacy data inventory — the live reference deployment

This is an engineering inventory of the personal data the reference issuer
(`personhood-issuer` on Cloud Run, project `arborfam-hub`) and web app
(`personhood-web.web.app`) handle today, and how long each item lasts. It
is a set of facts read from the code. It is **not** a privacy policy. The
owner reviews the wording of any policy that goes to users.

Last checked: 2026-10-20, against issuer revision `personhood-issuer-00005`
(round-1, email-only, test mode on).

## What a user gives us

| Data | Where it goes | How long it stays | Notes |
|---|---|---|---|
| **Email address** | Firestore `personhood-email-tokens/{sessionId}`, together with the magic-link token | Deleted when the link is clicked, or when the expired token is next read. **A link that is never clicked leaves its document, address included, in Firestore indefinitely** (see Gaps). | Needed to send the link. It is not copied into the session record or the credential. |
| Email address (derived) | `attestation_digest` in the session record and the credential | Same as the credential | SHA-256 over (session ID, one-time token, address). Without the one-time token, the digest can't be linked back to the address. |
| **Phone number** | `personhood-sms-otps` (OTP + attempt count, keyed by session) | Same pattern as email tokens | **Not collected today.** The live issuer has no SMS sender, and the web app hides the SMS step (`sms_delivery: "log"`). |
| **Invite code** | Request body only | Not stored or logged | Compared in constant time. |
| **Holder public key** | Firestore `personhood-sessions/{sessionId}` and the credential subject (`did:key`) | Session: until it expires (60 min) **and** is next read, otherwise indefinitely (see Gaps). Credential: held by the user. | The keypair is generated on the user's device. The private key never leaves it. |
| **IP address** | Cloud Run's platform request log; the issuer's in-memory rate-limit buckets | Platform log: Cloud Logging `_Default` retention (30 days). Buckets: about 10 min idle, memory only. | The issuer's own request log does not record IPs. |

## What the issuer produces

| Data | Where | Retention |
|---|---|---|
| Session record: holder DID and key, verified method IDs, strengths, timestamps, attestation digests, issued credential ID | Firestore `personhood-sessions` | 60-minute TTL, enforced only on read. See Gaps. |
| **The credential itself** | Returned once to the browser. Not stored by the issuer: only its ID goes on the session record. | Held by the user (on-device storage, a downloaded file, or a share). It expires after 1 year. |
| Status-list slot per credential: credential ID and a random slot number | Firestore `personhood-status-slots`, `personhood-credential-status` (keyed by a hash of the credential ID) | Indefinitely, so the credential stays revocable until it expires (1 year). No email or key is stored there. |
| Per-identifier nullifier seed: HMAC-SHA256 of the normalized email or phone (keyed with the `personhood-identifier-hmac-key` secret) → a random seed | Firestore `personhood-identifier-seeds/{hmac}`; the session record carries the same HMAC until it expires | Indefinitely: it is what makes a second enrollment by the same inbox a re-issue rather than a new person. No raw address or number is stored; without the secret the HMACs can't be tested against guessed addresses. The seed feeds the credential's `nullifierBinding` commitment, which OpenLine sees. |
| Revoked slot numbers | Firestore `personhood-status-lists/default`, served publicly at `/v1/status-list/default` | Indefinitely. The public list shows only which slot numbers are revoked. |

## Logs

| Log | Contents | Retention |
|---|---|---|
| Issuer request log (`src/server/router.go`) | Method, **route pattern** (e.g. `/v1/sessions/{sessionId}`), status, latency, trace ID. No raw paths, query strings, IPs or bodies. | Cloud Logging `_Default`, 30 days |
| Dev senders (`LogSender`, active on the live issuer because no SMTP is configured) | **Masked** recipient (`a***@example.com`), plus the magic link | 30 days. While test mode is on, the same link is shown on screen anyway. |
| Cloud Run platform request log (Google-managed) | **Full request URL**, including bearer session IDs in `/v1/sessions/{id}` paths and the magic-link token in `/v1/methods/email/verify?...`; client IP; user agent | 30 days. Readable only by people with log access to `arborfam-hub`. These are short-lived bearer values (60-min session, 15-min token, single use), but they are in the log. |

## Third parties

| Party | What they see |
|---|---|
| Google Cloud (Cloud Run, Firestore, Cloud Logging, Secret Manager) | Everything above, as processor |
| Firebase Hosting | Requests for the static web app (IP, user agent) |
| Email provider | **None today**: test mode, no mail sent. Once SMTP is on, the provider sees the recipient address and the magic link. |
| OpenLine (relying party) | Only what the user presents: the credential (holder DID, method IDs, strengths, digests, dates). Never the email address. |

## Gaps (owner decisions, not yet done)

1. **No server-side expiry in Firestore.** Expiry is checked only when a record
   is read, so unread expired sessions and unclicked email tokens, with their
   addresses, accumulate indefinitely. The fix is a Firestore TTL policy on the
   `expires_at` field of each collection group. It permanently deletes expired
   documents, so it waits for the owner (exact commands are in
   `docs/LAUNCH-RUNBOOK.md` §5).
2. **The Cloud Run platform log records full URLs.** It could be shortened with a
   `_Default` sink exclusion or a shorter bucket retention. Either one loses
   debugging data, so this is also the owner's call.
3. **No user-facing privacy notice yet.** A draft is with the owner.
