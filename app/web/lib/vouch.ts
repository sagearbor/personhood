// In-person vouching: client side of the QR round trip.
//
// The server side, and what the ceremony does and does not prove, is in
// src/methods/social-vouching/inperson.go and its README. In short:
//
//   voucher phone                    issuer                   newcomer phone
//   POST offer {credential}  ─────▶  checks credential
//   shows QR "PHV1:O:<code>" ◀─────  offer_code (2 min)
//                                                   ◀─────  scans QR
//                                    POST accept {code, key, sig}
//                                    return_code (90 s) ─────▶ shows QR "PHV1:R:<code>"
//   polls status → sees newcomer DID
//   scans newcomer's QR
//   POST confirm {code, return, sig}▶ records the vouch
//                                                   newcomer polls status → "confirmed"
//
// The strings both phones sign must match AcceptMessage / ConfirmMessage in
// inperson.go byte for byte; lib/vouch.test.ts pins them to the Go tests.

import { SERVER_URL, ApiError, apiErrorFromResponse, REQUEST_TIMEOUT_MS, type Credential } from './api';

export const IN_PERSON_METHOD_ID = 'in-person-vouch';
export const GRAPH_METHOD_ID = 'social-vouching-graph';

const TAG = 'personhood-in-person-vouch/v1';
export const VOUCH_STATEMENT = 'I met this person face to face and I believe they hold no other credential.';

export const QR_PREFIX_OFFER = 'PHV1:O:';
export const QR_PREFIX_RETURN = 'PHV1:R:';

export function acceptMessage(issuerDID: string, offerCode: string, candidateDID: string): string {
  return [TAG, 'accept', issuerDID, offerCode, candidateDID].join('\n');
}

export function confirmMessage(issuerDID: string, offerCode: string, candidateDID: string, returnCode: string): string {
  return [TAG, 'vouch', issuerDID, offerCode, candidateDID, returnCode, VOUCH_STATEMENT].join('\n');
}

const CROCKFORD = '0123456789ABCDEFGHJKMNPQRSTVWXYZ';

/**
 * normalizeCode mirrors the server's NormalizeCode: strips a QR prefix,
 * spaces and dashes, upper-cases, folds O→0 and I/L→1, and returns '' unless
 * 8 Crockford base32 characters remain.
 */
export function normalizeCode(raw: string): string {
  let s = raw.trim();
  for (const p of [QR_PREFIX_OFFER, QR_PREFIX_RETURN]) if (s.startsWith(p)) s = s.slice(p.length);
  s = s
    .toUpperCase()
    .replace(/[\s-]/g, '')
    .replace(/O/g, '0')
    .replace(/[IL]/g, '1');
  if (s.length !== 8) return '';
  for (const c of s) if (!CROCKFORD.includes(c)) return '';
  return s;
}

/**
 * parseScan reads a scanned QR. It returns the code when the QR is the kind
 * expected ('offer' on the newcomer's phone, 'return' on the voucher's), and
 * null otherwise, so pointing the camera at the wrong code does nothing.
 */
export function parseScan(text: string, want: 'offer' | 'return'): string | null {
  const prefix = want === 'offer' ? QR_PREFIX_OFFER : QR_PREFIX_RETURN;
  const t = text.trim();
  if (!t.startsWith(prefix)) return null;
  return normalizeCode(t) || null;
}

/** Formats a code for reading aloud / typing: ABCD-1234. */
export function displayCode(code: string): string {
  return code.length === 8 ? `${code.slice(0, 4)}-${code.slice(4)}` : code;
}

/** True when the credential has an anchor (the server makes the final call). */
export function credentialHasAnchor(c: Credential): boolean {
  return !!c.credentialSubject.anchorMethodId;
}

// --- HTTP ------------------------------------------------------------------

async function call<T>(path: string, init?: RequestInit): Promise<T> {
  const ctrl = new AbortController();
  const timer = setTimeout(() => ctrl.abort(), REQUEST_TIMEOUT_MS);
  let res: Response;
  try {
    res = await fetch(`${SERVER_URL}/v1/methods/${IN_PERSON_METHOD_ID}/${path}`, { ...init, signal: ctrl.signal });
  } catch (e) {
    if (ctrl.signal.aborted) throw new ApiError(0, 'request timed out', 'timeout');
    throw new ApiError(0, e instanceof Error ? e.message : String(e), 'network_error');
  } finally {
    clearTimeout(timer);
  }
  if (!res.ok) throw apiErrorFromResponse(res.status, await res.text(), res.headers.get('Retry-After'));
  return (await res.json()) as T;
}

function post<T>(path: string, body: unknown): Promise<T> {
  return call<T>(path, { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify(body) });
}

export type OfferResponse = {
  offer_code: string;
  qr_text: string;
  expires_at: string;
  voucher_did: string;
  voucher_anchored: boolean;
  vouches_left: number;
};

export type AcceptResponse = {
  return_code: string;
  qr_text: string;
  expires_at: string;
  candidate_did: string;
  voucher_did: string;
  voucher_anchored: boolean;
};

export type OfferStatus = {
  state: 'open' | 'accepted' | 'confirmed' | 'burned' | 'expired';
  expires_at: string;
  voucher_did: string;
  voucher_anchored: boolean;
  candidate_did?: string;
  return_expires_at?: string;
};

export type ConfirmResponse = {
  recorded: boolean;
  candidate_did: string;
  voucher_anchored: boolean;
  weight: number;
  round_trip_ms: number;
  same_network: boolean;
  candidate_vouches: number;
  required: number;
};

export function createOffer(credential: Credential): Promise<OfferResponse> {
  return post('offer', { credential });
}

export function acceptOffer(offerCode: string, candidatePublicKeyB64: string, signatureB64: string): Promise<AcceptResponse> {
  return post('accept', { offer_code: offerCode, candidate_public_key_b64: candidatePublicKeyB64, signature_b64: signatureB64 });
}

export function offerStatus(offerCode: string): Promise<OfferStatus> {
  return call(`status?code=${encodeURIComponent(offerCode)}`);
}

export function confirmVouch(offerCode: string, returnCode: string, signatureB64: string): Promise<ConfirmResponse> {
  return post('confirm', { offer_code: offerCode, return_code: returnCode, signature_b64: signatureB64 });
}

/** Friendly copy for the ceremony's error codes; null falls back to lib/errors. */
export function vouchErrorMessage(code: string | undefined): string | null {
  switch (code) {
    case 'credential_invalid':
      return 'This issuer does not accept that credential (expired, revoked, or from another issuer).';
    case 'voucher_not_eligible':
      return 'To vouch you need a credential with an anchor (for example the selfie step), or a high enough vouch score.';
    case 'voucher_too_new':
    case 'voucher_suspended':
    case 'voucher_revoked':
    case 'quota_exhausted':
    case 'candidate_revoked':
    case 'self_vouch_not_allowed':
    case 'not_same_network':
      return null; // the server's own message says it best
    case 'offer_expired':
      return 'Too slow — the code expired. Start again; scan within a minute or two.';
    case 'offer_used':
      return 'That code was already used. Ask the voucher to show a new one.';
    case 'offer_not_found':
      return 'No vouch with that code. Check it, or ask the voucher for a new one.';
    case 'return_code_wrong':
      return "That isn't the code on the newcomer's screen. Scan it again.";
    case 'already_vouched':
      return 'You already vouched for this person.';
    default:
      return null;
  }
}
