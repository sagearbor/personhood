# app/web — Personhood enrollment PWA

A Next.js 14 App Router application that drives an end-user through the
Personhood enrollment ceremony: email magic link → SMS OTP → government ID +
selfie (Persona) → issued W3C Verifiable Credential.

The app is installable as a PWA on Android (Add to Home Screen) and iOS.

## Run locally

Requires Node 18.18+ and a Personhood server reachable at
`NEXT_PUBLIC_PERSONHOOD_SERVER_URL` (default `http://localhost:8080`).

```bash
cd app/web
npm install
npm run dev
# open http://localhost:3000
```

In a second terminal, run the server:

```bash
# from repo root
export ISSUER_ED25519_SK_B64=$(go run ./src/server/cmd/gen-key 2>/dev/null | awk -F= '/^ISSUER_ED25519/ {print $2}')
export CORS_ALLOWED_ORIGINS="http://localhost:3000"
go run ./src/server/cmd/server
```

## Configuration

| Variable | Required | Default | Purpose |
|---|---|---|---|
| `NEXT_PUBLIC_PERSONHOOD_SERVER_URL` | no | `http://localhost:8080` | Where the browser-side API client points. |

(Persona-related env vars are read by the *server*, not the web app, so the
web app does not embed any client-side Persona keys.)

## Architecture

```
app/web/
├── app/
│   ├── layout.tsx        — root layout + font loading + SW registration
│   ├── page.tsx          — flow orchestrator (4 steps + state)
│   ├── globals.css       — design tokens + reset
│   ├── manifest.ts       — Next.js manifest route (/manifest.webmanifest)
│   ├── icon.tsx          — auto-generated PWA icon (512x512 PNG via next/og)
│   └── apple-icon.tsx    — auto-generated apple-touch-icon (180x180)
├── components/
│   ├── Brand.tsx         — header with monogram + tagline
│   ├── Progress.tsx      — sticky 4-step indicator
│   ├── Card.tsx          — step container with title + status pill
│   ├── Field.tsx         — labeled input with iOS-safe sizing
│   ├── Button.tsx        — primary / ghost / danger variants
│   ├── StatusPill.tsx    — idle / pending / ok / error chip
│   ├── ServiceWorkerRegister.tsx — runtime SW registration
│   └── steps/
│       ├── EmailStep.tsx     — magic-link send + "I clicked it"
│       ├── SmsStep.tsx       — phone number → OTP entry
│       ├── IdStep.tsx        — Persona hosted flow + poll-until-approved
│       └── CredentialStep.tsx — issue + view + save to IndexedDB
├── lib/
│   ├── api.ts            — Personhood server client (fetch-based)
│   ├── storage.ts        — IndexedDB wrapper (credentials + session checkpoint)
│   └── webauthn.ts       — registerDevicePasskey + verifyDevicePasskey
└── public/
    └── sw.js             — service worker (offline shell + installability)
```

## Design notes

- **Aesthetic**: "trusted terminal". Near-black canvas (`#08090c`), a single
  electric-lime accent (`#cffd2c`), JetBrains Mono for technical data,
  Mona Sans for body copy. Dark by default; no light-mode toggle.
- **Brand thread**: each step explains what we learn and what we don't
  learn. The point is to make the trust model legible.
- **Mobile first**: ≤ 560px wide column; tap targets ≥ 44px; `font-size:
  16px` on inputs to prevent iOS zoom-on-focus; `env(safe-area-inset-bottom)`
  honored.
- **PWA**: `app/manifest.ts` declares two icons (any + maskable) and a
  standalone display mode. `public/sw.js` provides the minimum fetch handler
  Chrome needs for the install banner to appear.

## Steps in detail

### 1. Email (supplementary, strength 8)

POST `/v1/methods/email/begin` with `user_input = email`. Server sends a
magic link (via SendGrid in prod, LogSender in dev). User clicks the link,
landing on the server's `/v1/methods/email/verify` page; server records the
verification. Returning to this tab, the user taps "I clicked it" to advance.

### 2. SMS (supplementary, strength 12)

POST `/v1/methods/sms/begin` with the E.164 phone number. Server sends a
6-digit OTP. User types it in; POST `/v1/methods/sms/complete` returns the
result.

### 3. Government ID + selfie (anchor, strength 90)

POST `/v1/methods/government-id-liveness/begin`. Server creates a Persona
inquiry, returns the hosted-flow URL. Web app opens it in a new tab; user
completes ID upload + selfie on Persona's domain. Persona POSTs a webhook
to the server. The web app polls
`/v1/methods/government-id-liveness/complete` every 3s until the result
arrives. If the server is running without `PERSONA_API_KEY` set, this method
is not registered and the step shows a "skip" option.

### 4. Credential

POST `/v1/credentials/issue`. Server signs the accumulated `VerifiedMethods`
into a W3C VC and returns the signed JSON. The viewer pretty-prints the VC,
shows the issuer DID, the holder DID, the anchor (or warns if none), and
offers a "save to this device" button that writes the credential to
IndexedDB (optionally biometric-gating via WebAuthn).

## TypeScript checks

```bash
npm run typecheck
```

## Install on Android (production-style)

1. Deploy the web app (e.g. Vercel — see PR #5).
2. Deploy the server (e.g. Fly.io — see PR #5) and set
   `NEXT_PUBLIC_PERSONHOOD_SERVER_URL` on the Vercel project.
3. Open the production URL on Chrome for Android.
4. Tap the address-bar overflow → "Add to Home screen".
5. The app launches in standalone mode with the Personhood icon.

For Capacitor / Play Store wrapping, see Sprint 3 in `STATUS.md`.
