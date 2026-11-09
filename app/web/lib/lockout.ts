// No-false-lockout client (issuer NO_FALSE_LOCKOUT, docs/08-no-false-lockout.md).
//
// When the selfie matches someone already enrolled, the issuer offers ways
// forward instead of a dead end: recover your own identity onto this phone,
// continue with another anchor ("not me": a twin or a look-alike), or ask
// for a manual review. This module wraps those calls, plus the old phone's
// side of a recovery (see a pending one and cancel it).

import { getJSON, postJSON, type ApiError, type NextStep, type SessionView } from './api';

export type RecoveryView = {
  recovery_id: string;
  status: 'pending' | 'cancelled' | 'completed';
  factors: string[];
  created_at: string;
  executes_at: string;
  closed_at?: string;
};

export type PendingRecovery = {
  pending: RecoveryView[];
  role?: 'old_key' | 'new_key';
  cancel_message?: string;
};

/** The exact text a holder key signs to cancel recovery id (server: RecoveryCancelMessage). */
export function recoveryCancelMessage(issuerDID: string, id: string): string {
  return `personhood-recovery/v1\ncancel\n${issuerDID}\n${id}`;
}

export function declineFaceMatch(sessionID: string): Promise<{ declined: boolean; extra_vouches: number; options: NextStep[] }> {
  return postJSON('/v1/face-match/decline', { session_id: sessionID });
}

export function startRecovery(sessionID: string): Promise<RecoveryView> {
  return postJSON('/v1/recovery/start', { session_id: sessionID });
}

export function getRecovery(id: string): Promise<RecoveryView> {
  return getJSON(`/v1/recovery/${encodeURIComponent(id)}`);
}

export function pendingRecovery(holderDID: string): Promise<PendingRecovery> {
  return getJSON(`/v1/recovery/pending?holder_did=${encodeURIComponent(holderDID)}`);
}

export function cancelRecovery(id: string, holderDID: string, signatureB64: string): Promise<RecoveryView> {
  return postJSON(`/v1/recovery/${encodeURIComponent(id)}/cancel`, { holder_did: holderDID, signature_b64: signatureB64 });
}

export function completeRecovery(id: string, sessionID: string): Promise<{ recovery: RecoveryView; revoked_credentials: number; session: SessionView }> {
  return postJSON(`/v1/recovery/${encodeURIComponent(id)}/complete`, { session_id: sessionID });
}

export type ReviewKind = 'face_match' | 'recovery' | 'no_selfie' | 'other';

export function requestReview(sessionID: string, kind: ReviewKind, message: string): Promise<{ review_id: string; status: string }> {
  return postJSON('/v1/reviews', { session_id: sessionID, kind, message });
}

/** Human copy for a recovery factor id. */
export function factorLabel(f: string): string {
  switch (f) {
    case 'identifier':
      return 'your original email or phone';
    case 'vouchers':
      return 'your vouchers, in person';
    case 'document':
      return 'the same identity document';
    case 'operator_review':
      return 'a review by the issuer';
    default:
      return f;
  }
}

/** Plain-language copy for the recovery refusals; null falls back to lib/errors. */
export function recoveryErrorMessage(e: ApiError): string | null {
  switch (e.code) {
    case 'recovery_factor_missing':
      return 'A face match alone cannot move an identity, because a look-alike could steal it. Prove one more thing:';
    case 'recovery_pending':
      return 'A recovery of this identity is already waiting.';
    case 'recovery_cooldown':
      return 'This identity was recovered recently. Another recovery so soon needs a person at the issuer to look at it.';
    case 'recovery_needs_review':
      return 'Several recoveries of this identity were cancelled. The next one needs a person at the issuer to look at it.';
    case 'recovery_identity_unknown':
      return 'The issuer has no record of which phone holds this identity (it enrolled before recovery existed).';
    case 'recovery_not_ready':
      return 'The waiting period is not over yet.';
    case 'recovery_closed':
      return 'This recovery was cancelled or already finished.';
    case 'face_match_declined':
      return 'You said the matched face is not yours, so this session cannot recover it. Start over to recover instead.';
    default:
      return null;
  }
}

// --- the new phone remembers its recovery across sessions -------------------
//
// The cancel window is days long, longer than an enrollment session. The id
// is kept in localStorage per holder DID so the selfie step can offer
// "Finish recovery" when the person comes back.

const KEY = 'personhood.recovery.v1';

type Remembered = Record<string, { id: string; executes_at: string }>;

function readAll(store: Pick<Storage, 'getItem'>): Remembered {
  try {
    const v = JSON.parse(store.getItem(KEY) ?? '{}');
    return v && typeof v === 'object' ? (v as Remembered) : {};
  } catch {
    return {};
  }
}

export function rememberRecovery(holderDID: string, r: { id: string; executes_at: string }, store: Storage | undefined = safeStorage()): void {
  if (!store) return;
  try {
    const all = readAll(store);
    all[holderDID] = r;
    store.setItem(KEY, JSON.stringify(all));
  } catch {
    // storage blocked: the person can still finish within this session
  }
}

export function recalledRecovery(holderDID: string, store: Storage | undefined = safeStorage()): { id: string; executes_at: string } | null {
  if (!store) return null;
  return readAll(store)[holderDID] ?? null;
}

export function forgetRecovery(holderDID: string, store: Storage | undefined = safeStorage()): void {
  if (!store) return;
  try {
    const all = readAll(store);
    delete all[holderDID];
    store.setItem(KEY, JSON.stringify(all));
  } catch {
    // ignore
  }
}

function safeStorage(): Storage | undefined {
  try {
    return typeof window !== 'undefined' ? window.localStorage : undefined;
  } catch {
    return undefined;
  }
}

/** "in 2 days", "in 3 hours", "in 4 minutes", or "now". */
export function untilPhrase(iso: string, now: number = Date.now()): string {
  const ms = Date.parse(iso) - now;
  if (!Number.isFinite(ms) || ms <= 0) return 'now';
  const min = Math.ceil(ms / 60_000);
  if (min < 60) return `in ${min} minute${min === 1 ? '' : 's'}`;
  const h = Math.ceil(min / 60);
  if (h < 48) return `in ${h} hour${h === 1 ? '' : 's'}`;
  const d = Math.ceil(h / 24);
  return `in ${d} days`;
}
