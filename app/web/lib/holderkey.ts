// Holder Ed25519 keypair — generation, persistence, signing.
//
// The web app generates an Ed25519 keypair via WebCrypto on first boot,
// sends the raw public key to POST /enrollment/start
// (holder_public_key_b64), and the issuer binds it into a did:key holder
// DID and the credential's nullifierBinding (src/server/did.go). At
// issuance the private key signs the session's holder_proof_message
// (signHolderMessage), proving to the issuer that this browser holds the
// key it declared.
//
// The private key is generated NON-EXTRACTABLE and persisted as a CryptoKey
// in IndexedDB (structured clone keeps it opaque): page script, including
// anything injected into the page, can ask the browser to sign with it but
// can never read its bytes, so it can't be copied to another device. Keys
// saved by earlier versions as base64 pkcs8 are re-imported non-extractable
// on first load and the base64 copy is overwritten (migrateLegacy).
//
// Biometric lock: once the visitor registers a device passkey (the "save"
// step), signHolderMessage asks for that passkey's fingerprint / face / PIN
// check before signing. That is a local gate, not a cryptographic one: the
// signature itself is a plain Ed25519 signature, which is what verifiers
// (OpenLine) check. Binding the key itself to the biometric needs a
// WebAuthn PRF-wrapped key or a native keystore; see STATUS.md.
//
// Browsers without WebCrypto Ed25519 support (isEd25519Available() false)
// fall back gracefully: getOrCreateHolderKeyPair() resolves to null, the
// caller omits holder_public_key_b64, and the server issues the v0.1
// placeholder did:personhood:holder:<sha256> DID with no nullifierBinding.

import { loadDevicePasskeyId, loadHolderKeyPair, saveHolderKeyPair } from './storage';
import { verifyDevicePasskey } from './webauthn';

export type HolderKeyPair = {
  publicKeyB64: string;
  /** Non-extractable; usable only through crypto.subtle.sign. */
  privateKey: CryptoKey;
};

/** The shape earlier versions stored: the private key as base64 pkcs8. */
type LegacyHolderKeyPair = {
  publicKeyB64: string;
  privateKeyB64: string;
};

const ED25519_ALG = { name: 'Ed25519' };

export function isEd25519Available(): boolean {
  return (
    typeof crypto !== 'undefined' &&
    typeof crypto.subtle !== 'undefined' &&
    typeof crypto.subtle.generateKey === 'function'
  );
}

/**
 * generateHolderKeyPair creates a fresh Ed25519 keypair whose private key
 * can't be exported. The public key (always exportable) comes back as raw
 * base64, the 32 bytes src/server/did.go's DIDKeyFromEd25519 expects.
 */
export async function generateHolderKeyPair(): Promise<HolderKeyPair> {
  const pair = (await crypto.subtle.generateKey(ED25519_ALG, false, ['sign', 'verify'])) as CryptoKeyPair;
  const rawPub = await crypto.subtle.exportKey('raw', pair.publicKey);
  return { publicKeyB64: bufToB64(rawPub), privateKey: pair.privateKey };
}

/**
 * migrateLegacy turns a stored base64 pkcs8 key into a non-extractable
 * CryptoKey with the same public key, so the holder DID doesn't change.
 */
export async function migrateLegacy(legacy: LegacyHolderKeyPair): Promise<HolderKeyPair> {
  const privateKey = await crypto.subtle.importKey('pkcs8', b64ToBuf(legacy.privateKeyB64), ED25519_ALG, false, [
    'sign',
  ]);
  return { publicKeyB64: legacy.publicKeyB64, privateKey };
}

function isLegacy(v: unknown): v is LegacyHolderKeyPair {
  return typeof v === 'object' && v !== null && typeof (v as LegacyHolderKeyPair).privateKeyB64 === 'string';
}

async function loadHolderKey(): Promise<HolderKeyPair | null> {
  const stored = await loadHolderKeyPair();
  if (!stored) return null;
  if (isLegacy(stored)) {
    const migrated = await migrateLegacy(stored);
    await saveHolderKeyPair(migrated);
    return migrated;
  }
  return stored as HolderKeyPair;
}

/**
 * getOrCreateHolderKeyPair returns the persisted holder keypair, generating
 * and saving one on first call. Returns null on browsers without Ed25519
 * WebCrypto support (isEd25519Available() false) or if key generation fails
 * for any other reason — callers should treat null as "proceed without a
 * holder key", not as a fatal error.
 */
export async function getOrCreateHolderKeyPair(): Promise<HolderKeyPair | null> {
  if (!isEd25519Available()) return null;
  try {
    const existing = await loadHolderKey();
    if (existing) return existing;
    const pair = await generateHolderKeyPair();
    await saveHolderKeyPair(pair);
    return pair;
  } catch {
    return null;
  }
}

/** Thrown when the visitor cancels or fails the passkey check before signing. */
export class HolderKeyLockedError extends Error {
  constructor() {
    super('Unlock with your fingerprint, face or device PIN to continue.');
    this.name = 'HolderKeyLockedError';
  }
}

/**
 * signHolderMessage signs message (UTF-8) with the persisted holder key and
 * returns the base64 Ed25519 signature, or null when there is no holder key
 * (the caller then issues without a proof, as before). When a device passkey
 * is registered, the passkey check runs first; failing it throws
 * HolderKeyLockedError.
 */
export async function signHolderMessage(message: string): Promise<string | null> {
  if (!isEd25519Available()) return null;
  const pair = await loadHolderKey();
  if (!pair) return null;
  const passkeyId = await loadDevicePasskeyId().catch(() => null);
  if (passkeyId && !(await verifyDevicePasskey(passkeyId))) throw new HolderKeyLockedError();
  return signWith(pair.privateKey, message);
}

/** signWith signs message (UTF-8) with key and returns base64. Exported for tests. */
export async function signWith(key: CryptoKey, message: string): Promise<string> {
  const sig = await crypto.subtle.sign(ED25519_ALG, key, new TextEncoder().encode(message));
  return bufToB64(sig);
}

function b64ToBuf(b64: string): ArrayBuffer {
  const s = atob(b64);
  const bytes = new Uint8Array(s.length);
  for (let i = 0; i < s.length; i++) bytes[i] = s.charCodeAt(i);
  return bytes.buffer;
}

function bufToB64(buf: ArrayBuffer): string {
  const bytes = new Uint8Array(buf);
  let s = '';
  for (const b of bytes) s += String.fromCharCode(b);
  return btoa(s);
}
