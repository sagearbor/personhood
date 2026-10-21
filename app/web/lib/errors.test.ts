import { describe, expect, it } from 'vitest';
import { ApiError } from './api';
import {
  MSG_NETWORK,
  MSG_RATE_LIMITED,
  MSG_SERVER,
  MSG_SESSION_EXPIRED,
  friendlyError,
  isNetworkError,
  isSessionExpired,
  rateLimitedMessage,
} from './errors';

describe('friendlyError', () => {
  it('maps network failures and timeouts to the connection message', () => {
    expect(friendlyError(new ApiError(0, 'Failed to fetch', 'network_error'))).toBe(MSG_NETWORK);
    expect(friendlyError(new ApiError(0, 'request timed out', 'timeout'))).toBe(MSG_NETWORK);
    expect(friendlyError(new TypeError('Failed to fetch'))).toBe(MSG_NETWORK);
  });

  it('maps rate_limited / 429 to the wait message, using Retry-After when present', () => {
    expect(friendlyError(new ApiError(429, '429: slow down', 'rate_limited'))).toBe(MSG_RATE_LIMITED);
    expect(friendlyError(new ApiError(429, '429: slow down'))).toBe(MSG_RATE_LIMITED);
    expect(friendlyError(new ApiError(429, '429: slow down', 'rate_limited', 30))).toBe(
      'Too many attempts. Please wait 30 seconds and try again.',
    );
  });

  it('maps session_not_found to the start-over message', () => {
    const e = new ApiError(404, '404: session not found', 'session_not_found');
    expect(friendlyError(e)).toBe(MSG_SESSION_EXPIRED);
    expect(isSessionExpired(e)).toBe(true);
    expect(isSessionExpired(new ApiError(404, '404: nope', 'not_found'))).toBe(false);
  });

  it('never shows raw server text for 5xx', () => {
    expect(friendlyError(new ApiError(500, '500: pq: connection refused at 10.0.0.3', 'issue_failed'))).toBe(MSG_SERVER);
    expect(friendlyError(new ApiError(503, '503: Service Unavailable'))).toBe(MSG_SERVER);
  });

  it('shows the server explanation (without the status prefix) for other 4xx', () => {
    expect(friendlyError(new ApiError(400, '400: phone number must be E.164', 'invalid_request'))).toBe(
      'phone number must be E.164',
    );
  });

  it('passes through plain Error messages', () => {
    expect(friendlyError(new Error('camera permission denied'))).toBe('camera permission denied');
  });
});

describe('isNetworkError', () => {
  it('is true only for status-0 / network / timeout errors', () => {
    expect(isNetworkError(new ApiError(0, 'x', 'network_error'))).toBe(true);
    expect(isNetworkError(new ApiError(500, 'x'))).toBe(false);
    expect(isNetworkError(new Error('x'))).toBe(false);
  });
});

describe('rateLimitedMessage', () => {
  it('formats seconds and minutes', () => {
    expect(rateLimitedMessage(undefined)).toBe(MSG_RATE_LIMITED);
    expect(rateLimitedMessage(1)).toBe('Too many attempts. Please wait a second and try again.');
    expect(rateLimitedMessage(45)).toBe('Too many attempts. Please wait 45 seconds and try again.');
    expect(rateLimitedMessage(60)).toBe('Too many attempts. Please wait a minute and try again.');
    expect(rateLimitedMessage(150)).toBe('Too many attempts. Please wait 3 minutes and try again.');
    expect(rateLimitedMessage(-5)).toBe(MSG_RATE_LIMITED);
  });
});
