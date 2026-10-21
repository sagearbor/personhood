import { describe, expect, it } from 'vitest';
import { CREDENTIAL_FILENAME, credentialJSON, pickShareMode } from './credentialFile';

const file = new File(['{}'], CREDENTIAL_FILENAME, { type: 'application/json' });

describe('pickShareMode', () => {
  it('is "none" without navigator.share', () => {
    expect(pickShareMode(undefined, file)).toBe('none');
    expect(pickShareMode({}, file)).toBe('none');
  });
  it('is "files" when canShare accepts the file', () => {
    expect(pickShareMode({ share: async () => {}, canShare: () => true }, file)).toBe('files');
  });
  it('falls back to "text" when files are not shareable', () => {
    expect(pickShareMode({ share: async () => {}, canShare: () => false }, file)).toBe('text');
    expect(pickShareMode({ share: async () => {} }, file)).toBe('text');
    expect(pickShareMode({ share: async () => {}, canShare: () => true }, null)).toBe('text');
    expect(
      pickShareMode(
        {
          share: async () => {},
          canShare: () => {
            throw new TypeError('unsupported');
          },
        },
        file,
      ),
    ).toBe('text');
  });
});

describe('credentialJSON', () => {
  it('pretty-prints with two-space indent', () => {
    expect(credentialJSON({ a: 1 })).toBe('{\n  "a": 1\n}');
  });
});
