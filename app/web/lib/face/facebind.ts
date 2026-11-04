// Document face bind: does the live person in front of the camera match the
// photo on their passport chip (DG2) or ID card QR?
//
// Runs inside the OpenLine wallet's WebView (app/face-bind). The wallet
// posts the document photo; this page runs a short active-liveness check
// with the same on-device models as the selfie anchor, compares the live
// face with the document face, and posts back only
//   { match, liveness, distance, template_b64 }
// The document photo and the camera frames never leave the phone.
//
// What the result is worth: it is computed on the phone, so the issuer has
// to trust the phone's word. A modified app can lie; a real, attested phone
// running the real app (app-attest-device) makes that much harder.

import { CHALLENGE_KINDS, type ChallengeKind } from './liveness';

/**
 * Largest descriptor distance accepted between the live face and the
 * document photo. dlib's model is usually run at 0.6 for "same person";
 * document photos are older and smaller than a selfie, so this sits a
 * little under that to keep false matches rare. Different faces averaged
 * 0.77 on the London Set (docs/selfie-anchor.md); the same face seconds
 * apart stays under 0.3, and the same face years apart under ~0.5.
 */
export const DOCUMENT_MATCH_MAX = 0.55;

/** Two random, distinct liveness challenges (local; the issuer cannot check them). */
export function pickChallenges(rand: () => number = Math.random): ChallengeKind[] {
  const pool = [...CHALLENGE_KINDS];
  const out: ChallengeKind[] = [];
  while (out.length < 2) {
    const i = Math.floor(rand() * pool.length) % pool.length;
    out.push(pool.splice(i, 1)[0]);
  }
  return out;
}

export type FaceBindResult = {
  type: 'face-bind-result';
  match: boolean;
  liveness: boolean;
  distance: number;
  template_b64: string;
  engine: string;
};

export type FaceBindError = { type: 'face-bind-error'; reason: string };

/** Builds the message the wallet receives. */
export function bindResult(distance: number, liveness: boolean, templateB64: string, engine: string): FaceBindResult {
  return {
    type: 'face-bind-result',
    match: Number.isFinite(distance) && distance <= DOCUMENT_MATCH_MAX,
    liveness,
    distance: Math.round(distance * 1000) / 1000,
    template_b64: templateB64,
    engine,
  };
}

/**
 * Reads the wallet's message. react-native-webview's postMessage may hand
 * the page a string (JSON) or an object.
 */
export function parsePhotoMessage(data: unknown): string | null {
  let v: unknown = data;
  if (typeof v === 'string') {
    try {
      v = JSON.parse(v);
    } catch {
      return null;
    }
  }
  if (typeof v !== 'object' || v === null) return null;
  const m = v as { type?: unknown; jpeg_b64?: unknown };
  if (m.type !== 'document-photo' || typeof m.jpeg_b64 !== 'string' || m.jpeg_b64.length === 0) return null;
  // ~2 MB base64 is far beyond any DG2 or QR photo.
  if (m.jpeg_b64.length > 2_800_000) return null;
  return m.jpeg_b64;
}
