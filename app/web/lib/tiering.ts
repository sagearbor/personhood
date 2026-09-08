// Method-tier selection (STATUS.md checklist #8).
//
// The server can register a strength-22 "email-tier" alongside plain
// strength-8 "email" (when HIBP_API_KEY is set) and a strength-28
// "phone-carrier-tier" alongside plain strength-12 "sms" (when Twilio Lookup
// creds are set) — see src/server/server.go BuildDependencies. Both tiered
// methods share the exact same ceremony wire shape as their plain
// counterpart (same ChallengeData.Type, same ResponseData.Type + payload
// keys), so the web app can stay a single set of screens and simply pick the
// strongest method the server actually advertises for this session instead
// of hardcoding 'email' / 'sms'. This is what "retires" the plain-only path:
// the UI no longer assumes a fixed method id, it asks the server what's
// available and prefers the tiered variant whenever present.

import type { MethodSummary } from './api';

// Fallbacks in case a session's available_methods is missing an entry we
// expect (defensive only — DefaultMethods always registers plain email, and
// SmsStep's own "Skip for now" already handles no-SMS deployments).
const FALLBACK_EMAIL: MethodSummary = {
  id: 'email',
  type: 'supplementary',
  strength: 8,
  ux_friction: 'low',
  cost_usd: 0,
  version: '0.1.0',
};

/**
 * Picks the email method to drive: 'email-tier' (strength 22) if the server
 * advertises it, otherwise plain 'email' (strength 8). Always returns
 * something usable — round-1 servers register plain email unconditionally.
 */
export function selectEmailMethod(methods: MethodSummary[]): MethodSummary {
  return (
    methods.find((m) => m.id === 'email-tier') ??
    methods.find((m) => m.id === 'email') ??
    FALLBACK_EMAIL
  );
}

/**
 * Picks the SMS method to drive: 'phone-carrier-tier' (strength 28) if the
 * server advertises it, otherwise plain 'sms' (strength 12). Returns null
 * when the server has neither registered (round-1 deployments skip SMS
 * delivery entirely) so callers can keep offering "Skip for now".
 */
export function selectSmsMethod(methods: MethodSummary[]): MethodSummary | null {
  return (
    methods.find((m) => m.id === 'phone-carrier-tier') ??
    methods.find((m) => m.id === 'sms') ??
    null
  );
}
