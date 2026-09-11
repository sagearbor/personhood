import { describe, expect, it } from 'vitest';
import { DEFAULT_CONFIG, extractMagicLinkUrl, normalizeConfig } from './api';

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
