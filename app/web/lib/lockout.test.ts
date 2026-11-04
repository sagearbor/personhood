import { describe, expect, it } from 'vitest';
import { ApiError, apiErrorFromResponse, normalizeConfig } from './api';
import { forgetRecovery, recalledRecovery, recoveryCancelMessage, recoveryErrorMessage, rememberRecovery, untilPhrase } from './lockout';

function memStore(): Storage {
  const m = new Map<string, string>();
  return {
    get length() {
      return m.size;
    },
    clear: () => m.clear(),
    getItem: (k) => m.get(k) ?? null,
    key: (i) => Array.from(m.keys())[i] ?? null,
    removeItem: (k) => void m.delete(k),
    setItem: (k, v) => void m.set(k, v),
  };
}

describe('lockout', () => {
  it('signs the same cancel message the issuer checks', () => {
    expect(recoveryCancelMessage('did:web:issuer', 'abc')).toBe('personhood-recovery/v1\ncancel\ndid:web:issuer\nabc');
  });

  it('keeps next steps and extra fields from an error body', () => {
    const e = apiErrorFromResponse(
      403,
      JSON.stringify({
        error: {
          code: 'recovery_factor_missing',
          message: 'm',
          next_steps: [{ action: 'verify_identifier', description: 'd' }, { bogus: true }],
        },
      }),
    );
    expect(e.code).toBe('recovery_factor_missing');
    expect(e.nextSteps).toEqual([{ action: 'verify_identifier', description: 'd' }]);
    expect(recoveryErrorMessage(e)).toMatch(/look-alike/);
    expect(recoveryErrorMessage(new ApiError(500, 'x', 'other'))).toBeNull();
    expect(apiErrorFromResponse(409, JSON.stringify({ error: { code: 'review_open', review_id: 'r1' } })).details?.review_id).toBe('r1');
  });

  it('remembers a recovery per holder key', () => {
    const s = memStore();
    rememberRecovery('did:key:a', { id: '1', executes_at: '2026-11-07T00:00:00Z' }, s);
    rememberRecovery('did:key:b', { id: '2', executes_at: '2026-11-07T00:00:00Z' }, s);
    expect(recalledRecovery('did:key:a', s)?.id).toBe('1');
    forgetRecovery('did:key:a', s);
    expect(recalledRecovery('did:key:a', s)).toBeNull();
    expect(recalledRecovery('did:key:b', s)?.id).toBe('2');
    s.setItem('personhood.recovery.v1', 'not json');
    expect(recalledRecovery('did:key:b', s)).toBeNull();
  });

  it('phrases the wait', () => {
    const now = Date.parse('2026-11-04T00:00:00Z');
    expect(untilPhrase('2026-11-04T00:00:00Z', now)).toBe('now');
    expect(untilPhrase('2026-11-04T00:02:00Z', now)).toBe('in 2 minutes');
    expect(untilPhrase('2026-11-04T05:00:00Z', now)).toBe('in 5 hours');
    expect(untilPhrase('2026-11-07T00:00:00Z', now)).toBe('in 3 days');
  });

  it('reads the lockout flags from /v1/config', () => {
    const c = normalizeConfig({ no_false_lockout: true, manual_review: true, recovery_delay_seconds: 259200 });
    expect(c.no_false_lockout).toBe(true);
    expect(c.manual_review).toBe(true);
    expect(c.recovery_delay_seconds).toBe(259200);
    expect(normalizeConfig({}).no_false_lockout).toBeUndefined();
  });
});
