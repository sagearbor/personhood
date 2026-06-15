// W3C Status List 2021 revocation checking. Mirrors the Go src/credential
// status.go: base64url-decode + gunzip the encodedList, then read the bit at
// statusListIndex (least-significant-bit-first within each byte).

import { base64urlToBytes } from "./crypto.js";
import type { PersonhoodCredential } from "./types.js";

export const STATUS_LIST_2021_ENTRY = "StatusList2021Entry";

async function gunzip(data: Uint8Array): Promise<Uint8Array> {
  // DecompressionStream is available in Node 18+ and modern browsers.
  const ds = new DecompressionStream("gzip");
  const stream = new Blob([data as BufferSource]).stream().pipeThrough(ds);
  const buf = await new Response(stream).arrayBuffer();
  return new Uint8Array(buf);
}

/** Returns true iff bit i is set, LSB-first within each byte. */
function bitSet(bytes: Uint8Array, i: number): boolean {
  if (i < 0) return false;
  const byteIdx = Math.floor(i / 8);
  if (byteIdx >= bytes.length) return false;
  const bitIdx = i % 8;
  return ((bytes[byteIdx]! >> bitIdx) & 0x01) === 1;
}

export type FetchLike = (url: string) => Promise<Response>;

/**
 * isRevoked reports whether the credential is revoked per its referenced Status
 * List 2021 credential. Returns false when the credential carries no
 * credentialStatus. Throws on transport/parse failure (the caller should fail
 * closed).
 */
export async function isRevoked(
  cred: PersonhoodCredential,
  fetchImpl: FetchLike = fetch,
): Promise<boolean> {
  const status = cred.credentialStatus;
  if (!status) return false;
  if (status.type !== STATUS_LIST_2021_ENTRY) {
    throw new Error(`isRevoked: unsupported credentialStatus.type ${status.type}`);
  }
  if (status.statusListIndex < 0) {
    throw new Error(`isRevoked: negative statusListIndex ${status.statusListIndex}`);
  }
  const resp = await fetchImpl(status.statusListCredential);
  if (!resp.ok) {
    throw new Error(`isRevoked: ${status.statusListCredential} returned status ${resp.status}`);
  }
  const doc = (await resp.json()) as { credentialSubject?: { encodedList?: string } };
  const encoded = doc.credentialSubject?.encodedList;
  if (!encoded) {
    throw new Error(`isRevoked: ${status.statusListCredential} missing credentialSubject.encodedList`);
  }
  const bytes = await gunzip(base64urlToBytes(encoded));
  return bitSet(bytes, status.statusListIndex);
}
