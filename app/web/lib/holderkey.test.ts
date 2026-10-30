import { describe, expect, it } from 'vitest';
import { generateHolderKeyPair, migrateLegacy, signWith } from './holderkey';

const ED = { name: 'Ed25519' };
const b64 = (buf: ArrayBuffer) => Buffer.from(buf).toString('base64');

async function verifies(publicKeyB64: string, message: string, sigB64: string): Promise<boolean> {
  const pub = await crypto.subtle.importKey('raw', Buffer.from(publicKeyB64, 'base64'), ED, false, ['verify']);
  return crypto.subtle.verify(ED, pub, Buffer.from(sigB64, 'base64'), new TextEncoder().encode(message));
}

describe('holder key', () => {
  it('generates a private key that cannot be exported but signs', async () => {
    const pair = await generateHolderKeyPair();
    expect(pair.privateKey.extractable).toBe(false);
    await expect(crypto.subtle.exportKey('pkcs8', pair.privateKey)).rejects.toThrow();
    expect(Buffer.from(pair.publicKeyB64, 'base64')).toHaveLength(32);
    const msg = 'personhood-holder-pop:v1:did:web:issuer:session';
    expect(await verifies(pair.publicKeyB64, msg, await signWith(pair.privateKey, msg))).toBe(true);
  });

  it('migrates a legacy base64 key to a non-extractable one with the same public key', async () => {
    const old = (await crypto.subtle.generateKey(ED, true, ['sign', 'verify'])) as CryptoKeyPair;
    const legacy = {
      publicKeyB64: b64(await crypto.subtle.exportKey('raw', old.publicKey)),
      privateKeyB64: b64(await crypto.subtle.exportKey('pkcs8', old.privateKey)),
    };
    const migrated = await migrateLegacy(legacy);
    expect(migrated.publicKeyB64).toBe(legacy.publicKeyB64);
    expect(migrated.privateKey.extractable).toBe(false);
    expect(await verifies(legacy.publicKeyB64, 'hi', await signWith(migrated.privateKey, 'hi'))).toBe(true);
  });
});
