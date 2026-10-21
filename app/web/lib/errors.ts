// User-facing error copy.
//
// Maps whatever a step's try/catch caught (usually an ApiError from
// lib/api.ts) to a short plain-language sentence a phone user can act on.
// Raw server text is only ever shown for 4xx responses, where it's the
// server explaining what was wrong with the request; 5xx bodies can contain
// internals and are replaced with a generic message.
//
// Pure — see lib/errors.test.ts.

import { ApiError } from './api';

export const MSG_NETWORK = "Couldn't reach the issuer. Check your connection and retry.";
export const MSG_SESSION_EXPIRED = 'Your session expired. Start over.';
export const MSG_SERVER = 'Something went wrong on our side. Please try again in a moment.';
export const MSG_RATE_LIMITED = 'Too many attempts. Please wait a minute and try again.';

function waitPhrase(seconds: number): string {
  if (seconds <= 1) return 'a second';
  if (seconds < 60) return `${seconds} seconds`;
  const minutes = Math.ceil(seconds / 60);
  return minutes === 1 ? 'a minute' : `${minutes} minutes`;
}

/** Message for a rate-limit response, using Retry-After (seconds) when known. */
export function rateLimitedMessage(retryAfterSeconds?: number): string {
  if (retryAfterSeconds === undefined || !Number.isFinite(retryAfterSeconds) || retryAfterSeconds < 0) {
    return MSG_RATE_LIMITED;
  }
  return `Too many attempts. Please wait ${waitPhrase(Math.ceil(retryAfterSeconds))} and try again.`;
}

/** True for errors the session can't recover from — the user must start over. */
export function isSessionExpired(e: unknown): boolean {
  return e instanceof ApiError && e.code === 'session_not_found';
}

/** True for network failures and timeouts (no HTTP response at all). */
export function isNetworkError(e: unknown): boolean {
  return e instanceof ApiError && (e.status === 0 || e.code === 'network_error' || e.code === 'timeout');
}

/** Strips the "NNN: " prefix ApiError puts on its message. */
function stripStatus(message: string): string {
  return message.replace(/^\d{3}:\s*/, '');
}

/** Maps any caught error to friendly, user-facing text. */
export function friendlyError(e: unknown): string {
  if (e instanceof ApiError) {
    if (isNetworkError(e)) return MSG_NETWORK;
    if (e.code === 'rate_limited' || e.status === 429) return rateLimitedMessage(e.retryAfterSeconds);
    if (isSessionExpired(e)) return MSG_SESSION_EXPIRED;
    if (e.status >= 500) return MSG_SERVER;
    const detail = stripStatus(e.message).trim();
    return detail || 'The request was rejected. Please check what you entered and try again.';
  }
  // A bare TypeError from fetch (shouldn't happen — lib/api.ts wraps fetch —
  // but cheap to guard) is a network failure too.
  if (e instanceof TypeError && /fetch|network/i.test(e.message)) return MSG_NETWORK;
  if (e instanceof Error) return e.message || MSG_SERVER;
  return String(e) || MSG_SERVER;
}
