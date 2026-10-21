import { describe, expect, it } from 'vitest';
import {
  ApiError,
  DEFAULT_CONFIG,
  apiErrorFromResponse,
  extractMagicLinkUrl,
  isLocalServerUrl,
  normalizeConfig,
  parseRetryAfter,
  smsUsable,
} from './api';

describe('normalizeConfig', () => {
  it('defaults to all-false/unknown for a garbage/missing value', () => {
    expect(normalizeConfig(undefined)).toEqual(DEFAULT_CONFIG);
    expect(normalizeConfig(null)).toEqual(DEFAULT_CONFIG);
    expect(normalizeConfig('not an object')).toEqual(DEFAULT_CONFIG);
    expect(normalizeConfig(42)).toEqual(DEFAULT_CONFIG);
    expect(normalizeConfig({})).toEqual(DEFAULT_CONFIG);
  });

  it('passes through a well-formed response', () => {
    expect(
      normalizeConfig({
        invite_code_required: true,
        challenge_secrets_exposed: true,
        email_delivery: 'log',
      }),
    ).toEqual({
      invite_code_required: true,
      challenge_secrets_exposed: true,
      email_delivery: 'log',
    });
  });

  it('accepts each known email_delivery value', () => {
    for (const v of ['log', 'smtp', 'sendgrid', 'unknown'] as const) {
      expect(normalizeConfig({ email_delivery: v }).email_delivery).toBe(v);
    }
  });

  it('falls back to "unknown" for an unrecognized email_delivery value', () => {
    expect(normalizeConfig({ email_delivery: 'carrier-pigeon' }).email_delivery).toBe('unknown');
    expect(normalizeConfig({ email_delivery: 123 }).email_delivery).toBe('unknown');
  });

  it('coerces non-boolean truthy/falsy values to strict booleans', () => {
    // A server sending e.g. 1/0 or "true" instead of real booleans should
    // not silently gate (or ungate) enrollment — only a literal `true`
    // counts.
    expect(normalizeConfig({ invite_code_required: 1 }).invite_code_required).toBe(false);
    expect(normalizeConfig({ invite_code_required: 'true' }).invite_code_required).toBe(false);
    expect(normalizeConfig({ invite_code_required: true }).invite_code_required).toBe(true);
  });
});

describe('extractMagicLinkUrl', () => {
  it('returns null when the challenge is missing entirely', () => {
    expect(extractMagicLinkUrl(null)).toBeNull();
    expect(extractMagicLinkUrl(undefined)).toBeNull();
  });

  it('returns null for a normal (no-secret) challenge payload', () => {
    expect(extractMagicLinkUrl({ type: 'email', payload: {} })).toBeNull();
    expect(extractMagicLinkUrl({ type: 'email', payload: { expires_at: '2026-01-01T00:00:00Z' } })).toBeNull();
  });

  it('extracts the URL when DEV_EXPOSE_CHALLENGE_SECRETS=1 includes one', () => {
    expect(
      extractMagicLinkUrl({
        type: 'email',
        payload: { magic_link_url: 'https://issuer.example/v1/methods/email/verify?token=abc' },
      }),
    ).toBe('https://issuer.example/v1/methods/email/verify?token=abc');
  });

  it('ignores a non-string or empty magic_link_url rather than rendering it', () => {
    expect(extractMagicLinkUrl({ type: 'email', payload: { magic_link_url: '' } })).toBeNull();
    expect(extractMagicLinkUrl({ type: 'email', payload: { magic_link_url: 12345 } })).toBeNull();
    expect(extractMagicLinkUrl({ type: 'email', payload: { magic_link_url: null } })).toBeNull();
  });
});

describe('normalizeConfig sms_delivery', () => {
  it('leaves sms_delivery absent when the server omits it (older servers)', () => {
    expect('sms_delivery' in normalizeConfig({})).toBe(false);
  });
  it('accepts known values and maps unknown strings to "unknown"', () => {
    expect(normalizeConfig({ sms_delivery: 'log' }).sms_delivery).toBe('log');
    expect(normalizeConfig({ sms_delivery: 'twilio' }).sms_delivery).toBe('twilio');
    expect(normalizeConfig({ sms_delivery: 'pigeon' }).sms_delivery).toBe('unknown');
  });
});

describe('smsUsable', () => {
  const remote = 'https://personhood-issuer.example.run.app';
  it('hides SMS for a log-only sender on a non-local server', () => {
    expect(smsUsable({ ...DEFAULT_CONFIG, sms_delivery: 'log' }, remote)).toBe(false);
  });
  it('keeps SMS for a log-only sender on localhost (dev reads the server log)', () => {
    expect(smsUsable({ ...DEFAULT_CONFIG, sms_delivery: 'log' }, 'http://localhost:8090')).toBe(true);
    expect(smsUsable({ ...DEFAULT_CONFIG, sms_delivery: 'log' }, 'http://127.0.0.1:8090')).toBe(true);
  });
  it('keeps current behaviour when the field is missing or not "log"', () => {
    expect(smsUsable(DEFAULT_CONFIG, remote)).toBe(true);
    expect(smsUsable(null, remote)).toBe(true);
    expect(smsUsable({ ...DEFAULT_CONFIG, sms_delivery: 'twilio' }, remote)).toBe(true);
    expect(smsUsable({ ...DEFAULT_CONFIG, sms_delivery: 'unknown' }, remote)).toBe(true);
  });
});

describe('isLocalServerUrl', () => {
  it('recognises localhost and loopback addresses only', () => {
    expect(isLocalServerUrl('http://localhost:8080')).toBe(true);
    expect(isLocalServerUrl('http://127.0.0.1:8090')).toBe(true);
    expect(isLocalServerUrl('https://personhood-web.web.app')).toBe(false);
    expect(isLocalServerUrl('not a url')).toBe(false);
  });
});

describe('apiErrorFromResponse', () => {
  it('unpacks the {error:{code,message}} envelope', () => {
    const e = apiErrorFromResponse(404, JSON.stringify({ error: { code: 'session_not_found', message: 'no such session' } }));
    expect(e).toBeInstanceOf(ApiError);
    expect(e.status).toBe(404);
    expect(e.code).toBe('session_not_found');
    expect(e.message).toBe('404: no such session');
  });
  it('falls back to the raw body for non-JSON', () => {
    const e = apiErrorFromResponse(502, '<html>Bad Gateway</html>');
    expect(e.code).toBeUndefined();
    expect(e.message).toBe('502: <html>Bad Gateway</html>');
  });
  it('carries Retry-After seconds', () => {
    const e = apiErrorFromResponse(429, JSON.stringify({ error: { code: 'rate_limited', message: 'slow down' } }), '42');
    expect(e.retryAfterSeconds).toBe(42);
  });
});

describe('parseRetryAfter', () => {
  it('parses delta-seconds and HTTP dates', () => {
    expect(parseRetryAfter('120')).toBe(120);
    expect(parseRetryAfter(null)).toBeUndefined();
    expect(parseRetryAfter('soon')).toBeUndefined();
    const now = Date.parse('2026-10-20T12:00:00Z');
    expect(parseRetryAfter('Tue, 20 Oct 2026 12:00:30 GMT', now)).toBe(30);
  });
});
