import { afterEach, describe, expect, it } from 'vitest';
import { INVITE_CODE_STORAGE_KEY, inviteErrorMessage, readSavedInviteCode, saveInviteCode } from './inviteCode';

// This suite runs under vitest's 'node' environment (see vitest.config.ts),
// which has no `window` — matching the SSR/build-time path these functions
// must also tolerate. We stub a minimal window.localStorage for the
// browser-path assertions and delete it again afterwards.

function setFakeWindow(localStorage: Partial<Storage>) {
  // @ts-expect-error -- test-only global shim; we only need the shape
  // readSavedInviteCode/saveInviteCode actually touch (window.localStorage).
  globalThis.window = { localStorage };
}

function installFakeLocalStorage() {
  const store = new Map<string, string>();
  setFakeWindow({
    getItem: (k: string) => (store.has(k) ? store.get(k)! : null),
    setItem: (k: string, v: string) => {
      store.set(k, v);
    },
    removeItem: (k: string) => {
      store.delete(k);
    },
  });
  return store;
}

afterEach(() => {
  // @ts-expect-error -- test-only global shim
  delete globalThis.window;
});

describe('readSavedInviteCode / saveInviteCode', () => {
  it('returns "" when window is unavailable (SSR/build)', () => {
    expect(readSavedInviteCode()).toBe('');
  });

  it('saveInviteCode is a no-op when window is unavailable', () => {
    expect(() => saveInviteCode('ABC123')).not.toThrow();
  });

  it('round-trips a saved code through the documented storage key', () => {
    const store = installFakeLocalStorage();
    expect(readSavedInviteCode()).toBe('');
    saveInviteCode('FRIENDS2026');
    expect(store.get(INVITE_CODE_STORAGE_KEY)).toBe('FRIENDS2026');
    expect(readSavedInviteCode()).toBe('FRIENDS2026');
  });

  it('degrades to "" if localStorage.getItem throws (private browsing etc.)', () => {
    setFakeWindow({
      getItem: () => {
        throw new Error('SecurityError');
      },
    });
    expect(readSavedInviteCode()).toBe('');
  });

  it('degrades silently if localStorage.setItem throws', () => {
    setFakeWindow({
      setItem: () => {
        throw new Error('QuotaExceededError');
      },
    });
    expect(() => saveInviteCode('X')).not.toThrow();
  });
});

describe('inviteErrorMessage', () => {
  it('maps the two known server error codes to friendly copy', () => {
    expect(inviteErrorMessage('invite_code_required')).toMatch(/invite code/i);
    expect(inviteErrorMessage('invite_code_invalid')).toMatch(/isn't valid/i);
  });

  it('returns null for any other/unknown code so callers fall back to the raw message', () => {
    expect(inviteErrorMessage('session_expired')).toBeNull();
    expect(inviteErrorMessage(undefined)).toBeNull();
  });
});
