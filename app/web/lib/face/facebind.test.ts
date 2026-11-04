import { describe, expect, it } from 'vitest';
import { bindResult, DOCUMENT_MATCH_MAX, parsePhotoMessage, pickChallenges } from './facebind';

describe('face bind helpers', () => {
  it('matches at and under the threshold only', () => {
    expect(bindResult(DOCUMENT_MATCH_MAX, true, 't', 'e').match).toBe(true);
    expect(bindResult(DOCUMENT_MATCH_MAX + 0.01, true, 't', 'e').match).toBe(false);
    expect(bindResult(Number.NaN, true, 't', 'e').match).toBe(false);
  });

  it('reads the wallet message as an object or a JSON string', () => {
    expect(parsePhotoMessage({ type: 'document-photo', jpeg_b64: 'abc' })).toBe('abc');
    expect(parsePhotoMessage(JSON.stringify({ type: 'document-photo', jpeg_b64: 'abc' }))).toBe('abc');
    expect(parsePhotoMessage({ type: 'other', jpeg_b64: 'abc' })).toBeNull();
    expect(parsePhotoMessage('not json')).toBeNull();
    expect(parsePhotoMessage({ type: 'document-photo', jpeg_b64: '' })).toBeNull();
  });

  it('picks two distinct challenges', () => {
    for (let i = 0; i < 20; i++) {
      const c = pickChallenges();
      expect(c).toHaveLength(2);
      expect(new Set(c).size).toBe(2);
    }
  });
});
