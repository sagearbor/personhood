// Cryptographic primitives, using the WebCrypto API available in Node.js 20+
// and modern browsers. No third-party dependencies.

/** Decode unpadded or padded base64url (used by proofValue). */
export function base64urlToBytes(s: string): Uint8Array {
  let b64 = s.replace(/-/g, "+").replace(/_/g, "/");
  while (b64.length % 4 !== 0) b64 += "=";
  return base64ToBytes(b64);
}

/** Decode standard base64 (used for issuer public keys). atob is available in
 *  Node.js 18+ and all modern browsers. */
export function base64ToBytes(s: string): Uint8Array {
  const bin = atob(s);
  const out = new Uint8Array(bin.length);
  for (let i = 0; i < bin.length; i++) out[i] = bin.charCodeAt(i);
  return out;
}

export function bytesToHex(b: Uint8Array): string {
  let out = "";
  for (const byte of b) out += byte.toString(16).padStart(2, "0");
  return out;
}

/**
 * verifyEd25519 returns true iff sig is a valid Ed25519 signature over msg
 * under the 32-byte raw public key pub.
 */
export async function verifyEd25519(
  pub: Uint8Array,
  msg: Uint8Array,
  sig: Uint8Array,
): Promise<boolean> {
  const key = await crypto.subtle.importKey(
    "raw",
    pub as BufferSource,
    { name: "Ed25519" },
    false,
    ["verify"],
  );
  return crypto.subtle.verify(
    { name: "Ed25519" },
    key,
    sig as BufferSource,
    msg as BufferSource,
  );
}

/** sha256Hex returns the lowercase hex SHA-256 digest of data. */
export async function sha256Hex(data: Uint8Array): Promise<string> {
  const digest = await crypto.subtle.digest("SHA-256", data as BufferSource);
  return bytesToHex(new Uint8Array(digest));
}
