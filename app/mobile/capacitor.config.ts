import type { CapacitorConfig } from '@capacitor/cli';

/**
 * Personhood mobile shell configuration.
 *
 * The web app (app/web, deployed to Vercel) does all the work. This Capacitor
 * shell loads it over the network via `server.url`, so shipping a new web
 * build reaches the wrapped app instantly (OTA) without a store roll. The
 * native shell exists to add device APIs a PWA cannot reach — FCM push and
 * Play Integrity / App Attest (checklist #3b) — and to get a real store
 * listing (checklist #3c/#3d).
 *
 * Set PERSONHOOD_WEB_URL to your deployed PWA before building. The default is a
 * placeholder; a store build MUST point at the real, HTTPS, owned domain.
 */
const webUrl = process.env.PERSONHOOD_WEB_URL || 'https://personhood.vercel.app';

const config: CapacitorConfig = {
  // Reverse-DNS app id. Change to a domain you own before any store upload —
  // the id is permanent once published and must be globally unique.
  appId: 'protocol.personhood.app',
  appName: 'Personhood',

  // Capacitor requires a webDir even when server.url is set; www/ holds a
  // tiny fallback page shown only if the network load fails.
  webDir: 'www',

  server: {
    // Load the live PWA over the network (OTA updates, no store roll).
    url: webUrl,
    // Never allow cleartext; the enrollment flow handles credentials.
    cleartext: false,
    androidScheme: 'https',
    iosScheme: 'https',
    // Domains the in-app webview may navigate to. The enrollment ceremony
    // hands off to vendor-hosted flows (Persona ID+selfie, Plaid bank link,
    // Stripe 3DS), so those origins must be allowed or the webview blocks them.
    allowNavigation: [
      'personhood.vercel.app',
      '*.vercel.app',
      'withpersona.com',
      '*.withpersona.com',
      'cdn.plaid.com',
      '*.plaid.com',
      'js.stripe.com',
      '*.stripe.com',
    ],
  },

  android: {
    // Allow the system back button to navigate the webview history.
    allowMixedContent: false,
  },

  ios: {
    // Use the system WKWebView; required for App Attest in a later sprint.
    contentInset: 'always',
  },
};

export default config;
