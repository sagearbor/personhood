# app/mobile — Personhood mobile shell (Capacitor 6)

A thin native shell that wraps the live enrollment PWA (`../web/`, deployed to
Vercel) so Personhood can ship through the Play Store / App Store and reach
device APIs a PWA cannot — FCM push and Play Integrity / App Attest.

This is **checklist #3a** in `STATUS.md`: scaffold only. It loads the web app
over the network via Capacitor's `server.url`, so a new web deploy reaches the
wrapped app instantly (OTA) without a store roll. The web app does all the
heavy lifting; this shell is the native container.

## What's here (committed)

```
app/mobile/
├── capacitor.config.ts   # appId, appName, server.url → the live PWA, allowNavigation
├── package.json          # @capacitor/{core,cli,android,ios,app}
├── www/index.html        # offline fallback page (shown only if the network load fails)
├── .gitignore            # native projects + signing material are NOT committed
└── README.md             # this file
```

The generated native projects (`android/`, `ios/`) and `node_modules/` are
**not** committed — they are machine-specific and regenerated locally with
`npx cap add` (see below).

## Configure

The shell loads whatever `PERSONHOOD_WEB_URL` points at (read by
`capacitor.config.ts`; default `https://personhood.vercel.app`):

```bash
export PERSONHOOD_WEB_URL=https://your-personhood.vercel.app
```

Before any store upload, change `appId` in `capacitor.config.ts` from the
placeholder `protocol.personhood.app` to a reverse-DNS id on a domain you own —
the id is permanent once published.

## Generate the native projects and run

> Requires Node ≥ 18.18. Android needs **Android Studio + JDK 17**; iOS needs
> **Xcode** (macOS only). These are the platform SDKs, not something this repo
> can vendor.

```bash
cd app/mobile
npm install
npx cap add android        # generates app/mobile/android/ (gitignored)
npx cap add ios            # generates app/mobile/ios/ (gitignored, macOS only)
npx cap sync               # copies config into the native projects
npx cap open android       # opens Android Studio → Run on a device/emulator
npx cap open ios           # opens Xcode → Run
```

Because `server.url` is set, there is no web bundle to copy — the native app
loads the live PWA directly. `www/index.html` is only shown if that network
load fails.

## Not in this PR — needs real accounts / devices (checklist #3b–#3d)

| Item | Blocked on |
|---|---|
| **#3b** Play Integrity + App Attest as a second anchor (posts attestation to `src/methods/phone-liveness/`) | Apple Developer account, App Attest keys, Google Play app + service-account JSON |
| **#3c** Signed Android AAB → Play Console internal track | Play Console account ($25 one-time), upload keystore, privacy questionnaire |
| **#3d** iOS TestFlight build | Apple Developer Program ($99/yr), signing certs, a physical device |

These require credentials, signing keys, and developer accounts that can't be
provisioned from code. The scaffold here is everything that **can** be built
without them; once the accounts exist, `npx cap add` + the steps above produce
an installable app.
