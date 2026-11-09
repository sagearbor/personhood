// WebAuthn helpers.
//
//   1. registerDevicePasskey() — registers a discoverable platform passkey
//      (fingerprint / face / device PIN) at the credential save step. Its id
//      is stored (lib/storage.ts saveDevicePasskeyId).
//   2. verifyDevicePasskey() — re-prompts for that biometric / PIN check.
//      lib/holderkey.ts runs it before the holder key signs anything, so a
//      registered passkey locks the key. The lock is local: the holder key
//      itself is a separate non-extractable Ed25519 key, and a PRF-wrapped
//      key (the passkey deriving the key's protection) is future work.
//
// Both are no-ops on browsers without WebAuthn: register returns null and
// verify returns true, so the UI saves without a biometric lock.

export function isWebAuthnAvailable(): boolean {
  return (
    typeof window !== 'undefined' &&
    typeof window.PublicKeyCredential !== 'undefined' &&
    typeof navigator !== 'undefined' &&
    typeof navigator.credentials !== 'undefined'
  );
}

const RP_NAME = 'Personhood';
const USER_NAME = 'personhood-credential-vault';
const USER_ID = new TextEncoder().encode('personhood-vault-v1').slice(0, 32);

function randomChallenge(): Uint8Array<ArrayBuffer> {
  const c = new Uint8Array(32);
  crypto.getRandomValues(c);
  return c;
}

/**
 * registerDevicePasskey creates a discoverable platform-authenticator
 * credential and returns its credentialId (base64url). Stored alongside the
 * VC in IndexedDB so future reads can verify possession.
 *
 * Throws on user cancellation or unsupported devices; callers fall back to
 * saving without biometric gating.
 */
export async function registerDevicePasskey(): Promise<string | null> {
  if (!isWebAuthnAvailable()) return null;
  const cred = (await navigator.credentials.create({
    publicKey: {
      challenge: randomChallenge(),
      rp: { name: RP_NAME, id: window.location.hostname },
      user: { id: USER_ID, name: USER_NAME, displayName: 'Personhood vault' },
      pubKeyCredParams: [
        { type: 'public-key', alg: -7 },   // ES256
        { type: 'public-key', alg: -257 }, // RS256
      ],
      authenticatorSelection: {
        residentKey: 'preferred',
        userVerification: 'required',
        authenticatorAttachment: 'platform',
      },
      timeout: 60_000,
      attestation: 'none',
    },
  })) as PublicKeyCredential | null;
  if (!cred) return null;
  return bufToB64Url(cred.rawId);
}

/**
 * verifyDevicePasskey prompts for biometric / PIN and returns true on
 * success. Stub-safe on platforms without WebAuthn.
 */
export async function verifyDevicePasskey(credentialIdB64: string): Promise<boolean> {
  if (!isWebAuthnAvailable()) return true;
  try {
    const id = b64UrlToBuf(credentialIdB64);
    const assertion = (await navigator.credentials.get({
      publicKey: {
        challenge: randomChallenge(),
        allowCredentials: [{ id, type: 'public-key' }],
        userVerification: 'required',
        timeout: 60_000,
      },
    })) as PublicKeyCredential | null;
    return assertion !== null;
  } catch {
    return false;
  }
}

function bufToB64Url(buf: ArrayBuffer): string {
  const bytes = new Uint8Array(buf);
  let s = '';
  for (const b of bytes) s += String.fromCharCode(b);
  return btoa(s).replace(/=+$/, '').replace(/\+/g, '-').replace(/\//g, '_');
}

function b64UrlToBuf(s: string): ArrayBuffer {
  const padded = s.replace(/-/g, '+').replace(/_/g, '/') + '==='.slice((s.length + 3) % 4);
  const bin = atob(padded);
  const out = new Uint8Array(bin.length);
  for (let i = 0; i < bin.length; i++) out[i] = bin.charCodeAt(i);
  return out.buffer;
}
