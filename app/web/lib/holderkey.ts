// Holder Ed25519 keypair — generation + persistence.
//
// v0.1: the web app generates a real Ed25519 keypair via WebCrypto on first
// boot, sends the raw public key to POST /enrollment/start
// (holder_public_key_b64), and the issuer binds it into a real did:key
// holder DID plus a stub nullifierBinding on the issued credential (see
// src/server/did.go DIDKeyFromEd25519 / NullifierBindingForHolder). The
// private key is generated and persisted but not used for anything yet —
// presentation-time proof-of-possession is a v0.2 concern per
// docs/03-credential-format.md — but generating and binding a real key now
// is what makes nullifierBinding (and therefore nullifier_required
// policies) work end to end.
//
// Persisted as raw base64 bytes in IndexedDB (lib/storage.ts) rather than as
// a non-extractable CryptoKey via structured clone, so the wire format stays
// simple and inspectable. v0.2 will wrap the private key behind a WebAuthn
// PRF-derived secret (storage.ts's existing note); this module's export
// shape is intentionally simple so that upgrade does not need to change
// callers of getOrCreateHolderKeyPair().
//
// Browsers without WebCrypto Ed25519 support (isEd25519Available() false)
// fall back gracefully: getOrCreateHolderKeyPair() resolves to null, the
// caller omits holder_public_key_b64, and the server issues the v0.1
// placeholder did:personhood:holder:<sha256> DID with no nullifierBinding —
// the same behavior as before this feature existed.

import { loadHolderKeyPair, saveHolderKeyPair } from './storage';

export type HolderKeyPair = {
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
 * generateHolderKeyPair creates a fresh Ed25519 keypair and exports both
 * halves as base64: the public key in 'raw' form (32 bytes — what
 * src/server/did.go's DIDKeyFromEd25519 expects) and the private key in
 * 'pkcs8' form (for future presentation-signing use).
 */
export async function generateHolderKeyPair(): Promise<HolderKeyPair> {
  const pair = (await crypto.subtle.generateKey(ED25519_ALG, true, [
    'sign',
    'verify',
  ])) as CryptoKeyPair;
  const rawPub = await crypto.subtle.exportKey('raw', pair.publicKey);
  const pkcs8Priv = await crypto.subtle.exportKey('pkcs8', pair.privateKey);
  return {
    publicKeyB64: bufToB64(rawPub),
    privateKeyB64: bufToB64(pkcs8Priv),
  };
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
    const existing = await loadHolderKeyPair();
    if (existing) return existing;
    const pair = await generateHolderKeyPair();
    await saveHolderKeyPair(pair);
    return pair;
  } catch {
    return null;
  }
}

function bufToB64(buf: ArrayBuffer): string {
  const bytes = new Uint8Array(buf);
  let s = '';
  for (const b of bytes) s += String.fromCharCode(b);
  return btoa(s);
}
