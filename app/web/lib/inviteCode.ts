// Invite-code persistence + friendly error copy.
//
// When GET /v1/config reports invite_code_required: true, the enrollment
// flow shows an invite-code field before it will create a session (see
// components/InviteGate.tsx + app/page.tsx). We remember the last code a
// visitor typed in localStorage so that tapping "Start over" — which is
// common right after finishing, to let a friend enroll on the same phone —
// doesn't make them retype a code they were handed once, in person or over
// text.
//
// localStorage (not IndexedDB) is deliberate here: the value is small,
// synchronous to read, and not sensitive in the way the holder's private key
// is (lib/holderkey.ts uses IndexedDB for that) — an invite code is shared
// by design, so there's nothing gained from IndexedDB's extra ceremony.

export const INVITE_CODE_STORAGE_KEY = 'personhood:inviteCode:v1';

/** Reads the last invite code the visitor entered, or '' if none/unavailable. */
export function readSavedInviteCode(): string {
  if (typeof window === 'undefined') return '';
  try {
    return window.localStorage.getItem(INVITE_CODE_STORAGE_KEY) ?? '';
  } catch {
    // Private browsing / storage disabled / quota — degrade to "not remembered".
    return '';
  }
}

/** Persists the invite code the visitor last successfully used. */
export function saveInviteCode(code: string): void {
  if (typeof window === 'undefined') return;
  try {
    window.localStorage.setItem(INVITE_CODE_STORAGE_KEY, code);
  } catch {
    // Not fatal — the field just won't be prefilled next time.
  }
}

/**
 * Maps an ApiError.code from a gated /enrollment/start rejection to
 * user-facing copy. Returns null for any other/unknown code so callers can
 * fall back to the raw error message instead of hiding it.
 */
export function inviteErrorMessage(code: string | undefined): string | null {
  switch (code) {
    case 'invite_code_required':
      return 'An invite code is required tonight. Ask whoever invited you for the code.';
    case 'invite_code_invalid':
      return "That invite code isn't valid. Double-check it and try again.";
    default:
      return null;
  }
}
