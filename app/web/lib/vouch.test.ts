import { describe, expect, it } from 'vitest';
import { acceptMessage, confirmMessage, displayCode, normalizeCode, parseScan, VOUCH_STATEMENT } from './vouch';

describe('vouch messages', () => {
  // Pinned to TestMessagesAreStable in src/methods/social-vouching/inperson_test.go.
  it('acceptMessage matches the server', () => {
    expect(acceptMessage('did:web:i', 'ABCD1234', 'did:key:z6M')).toBe(
      'personhood-in-person-vouch/v1\naccept\ndid:web:i\nABCD1234\ndid:key:z6M',
    );
  });
  it('confirmMessage matches the server', () => {
    expect(confirmMessage('did:web:i', 'ABCD1234', 'did:key:z6M', 'WXYZ5678')).toBe(
      'personhood-in-person-vouch/v1\nvouch\ndid:web:i\nABCD1234\ndid:key:z6M\nWXYZ5678\n' + VOUCH_STATEMENT,
    );
    expect(VOUCH_STATEMENT).toBe('I met this person face to face and I believe they hold no other credential.');
  });
});

describe('codes', () => {
  it('normalizes like the server', () => {
    expect(normalizeCode('abcd-1234')).toBe('ABCD1234');
    expect(normalizeCode(' PHV1:O:abcd1234')).toBe('ABCD1234');
    expect(normalizeCode('oIl0 0000')).toBe('01100000');
    expect(normalizeCode('ABCD123')).toBe('');
    expect(normalizeCode('ABCDU234')).toBe('');
  });
  it('parseScan accepts only the expected kind of QR', () => {
    expect(parseScan('PHV1:O:ABCD1234', 'offer')).toBe('ABCD1234');
    expect(parseScan('PHV1:R:ABCD1234', 'offer')).toBeNull();
    expect(parseScan('PHV1:R:ABCD1234', 'return')).toBe('ABCD1234');
    expect(parseScan('https://example.com', 'return')).toBeNull();
    expect(parseScan('PHV1:O:bad', 'offer')).toBeNull();
  });
  it('displays codes in two groups', () => {
    expect(displayCode('ABCD1234')).toBe('ABCD-1234');
  });
});
