// Personhood server client.
//
// All methods are async and throw on non-2xx. Callers wrap them in try/catch
// or surface the error to the UI's status pill.
//
// The server URL is taken from NEXT_PUBLIC_PERSONHOOD_SERVER_URL at build
// time. If unset, we fall back to http://localhost:8080 (the default the
// server in src/server uses).

export const SERVER_URL =
  (typeof process !== 'undefined' && process.env.NEXT_PUBLIC_PERSONHOOD_SERVER_URL) ||
  'http://localhost:8080';

export type MethodSummary = {
  id: string;
  type: 'anchor' | 'supplementary';
  strength: number;
  ux_friction: 'low' | 'med' | 'high';
  cost_usd: number;
  version: string;
};

export type StartEnrollmentResponse = {
  session_id: string;
  holder_did: string;
  issuer_did: string;
  expires_at: string;
  available_methods: MethodSummary[];
  /**
   * Present when the session declared a holder key: the exact string to sign
   * with that key (lib/holderkey.ts signHolderMessage) and send back as
   * holder_proof_b64 at issuance, proving the browser holds the key.
   */
  holder_proof_message?: string;
};

export type ChallengeData = {
  type: string;
  payload: Record<string, unknown>;
};

export type MethodResult = {
  success: boolean;
  method_id: string;
  verified_at?: string;
  attestation_digest?: string;
  error_reason?: string;
};

export type VerifiedMethod = {
  method_id: string;
  strength: number;
  verified_at: string;
  freshness_lifetime: number;
  attestation_digest: string;
};

export type SessionView = {
  id: string;
  holder_did: string;
  created_at: string;
  expires_at: string;
  verified_methods: VerifiedMethod[];
  anchor_method_id?: string | null;
  issued_credential_id?: string;
};

export type Credential = {
  '@context': string[];
  id: string;
  type: string[];
  issuer: string;
  issuanceDate: string;
  expirationDate: string;
  credentialSubject: {
    id: string;
    verifiedMethods: VerifiedMethod[];
    anchorMethodId?: string | null;
    nullifierBinding?: {
      commitment: string;
      curve: string;
      scheme: string;
    } | null;
  };
  proof?: {
    type: string;
    created: string;
    proofPurpose: string;
    verificationMethod: string;
    proofValue: string;
  };
};

/** How long any single request may take before we give up (ms). Generous
 * enough to ride out a Cloud Run cold start, short enough that a phone on a
 * dead connection gets a Retry button instead of an endless spinner. */
export const REQUEST_TIMEOUT_MS = 20_000;

/**
 * Thrown by postJSON/getJSON on any non-2xx response, and on network
 * failure / timeout. Carries the server's error `code` (e.g.
 * `invite_code_required`, `rate_limited`, `session_not_found`) alongside the
 * usual message, so callers can branch on it instead of string-matching the
 * message text. See lib/errors.ts for the user-facing copy.
 *
 * Network failures use status 0 with code `network_error`; timeouts use
 * status 0 with code `timeout`.
 */
export class ApiError extends Error {
  readonly status: number;
  readonly code?: string;
  /** Parsed Retry-After header (seconds), when the server sent one. */
  readonly retryAfterSeconds?: number;

  constructor(status: number, message: string, code?: string, retryAfterSeconds?: number) {
    super(message);
    this.name = 'ApiError';
    this.status = status;
    this.code = code;
    this.retryAfterSeconds = retryAfterSeconds;
  }
}

/**
 * Parses a Retry-After header value. Accepts delta-seconds or an HTTP date;
 * returns undefined for anything unusable. Pure — see lib/api.test.ts.
 */
export function parseRetryAfter(value: string | null | undefined, now: number = Date.now()): number | undefined {
  if (!value) return undefined;
  const v = value.trim();
  if (/^\d+$/.test(v)) return parseInt(v, 10);
  const t = Date.parse(v);
  if (Number.isNaN(t)) return undefined;
  return Math.max(0, Math.ceil((t - now) / 1000));
}

/**
 * Builds an ApiError from a non-2xx response's status, body text and
 * Retry-After header, unpacking the server's `{error:{code,message}}`
 * envelope when present. Pure — see lib/api.test.ts.
 */
export function apiErrorFromResponse(status: number, raw: string, retryAfter?: string | null): ApiError {
  let detail = raw;
  let code: string | undefined;
  try {
    const json = JSON.parse(raw);
    if (typeof json?.error?.message === 'string' && json.error.message) detail = json.error.message;
    code = typeof json?.error?.code === 'string' ? json.error.code : undefined;
  } catch {
    // not JSON; surface the raw body
  }
  return new ApiError(status, `${status}: ${detail}`, code, parseRetryAfter(retryAfter));
}

/** fetch() with a timeout; network failures and timeouts become ApiError. */
async function request(path: string, init?: RequestInit): Promise<Response> {
  const ctrl = new AbortController();
  const timer = setTimeout(() => ctrl.abort(), REQUEST_TIMEOUT_MS);
  try {
    return await fetch(`${SERVER_URL}${path}`, { ...init, signal: ctrl.signal });
  } catch (e) {
    if (ctrl.signal.aborted) {
      throw new ApiError(0, 'request timed out', 'timeout');
    }
    throw new ApiError(0, e instanceof Error ? e.message : String(e), 'network_error');
  } finally {
    clearTimeout(timer);
  }
}

async function readJSON<T>(res: Response): Promise<T> {
  if (!res.ok) {
    throw apiErrorFromResponse(res.status, await res.text(), res.headers.get('Retry-After'));
  }
  return (await res.json()) as T;
}

async function postJSON<T>(path: string, body: unknown): Promise<T> {
  const res = await request(path, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify(body),
  });
  return readJSON<T>(res);
}

async function getJSON<T>(path: string): Promise<T> {
  return readJSON<T>(await request(path));
}

export async function startEnrollment(opts: {
  userAgent?: string;
  platform?: string;
  /**
   * Base64-encoded raw Ed25519 public key (see lib/holderkey.ts). When
   * supplied, the server binds a real did:key holder DID and a
   * nullifierBinding onto the eventual credential instead of the v0.1
   * placeholder DID with no nullifierBinding. Omit to fall back to the old
   * behavior.
   */
  holderPublicKeyB64?: string;
  /**
   * Required only when GET /v1/config reports invite_code_required: true.
   * The server validates it and returns HTTP 403 with error.code
   * `invite_code_required` (missing) or `invite_code_invalid` (wrong) —
   * see ApiError.code.
   */
  inviteCode?: string;
}): Promise<StartEnrollmentResponse> {
  return postJSON<StartEnrollmentResponse>('/enrollment/start', {
    user_agent: opts.userAgent || (typeof navigator !== 'undefined' ? navigator.userAgent : ''),
    platform: opts.platform || 'web',
    holder_public_key_b64: opts.holderPublicKeyB64 || undefined,
    invite_code: opts.inviteCode || undefined,
  });
}

// --- server config (GET /v1/config) --------------------------------------
//
// A parallel server-side PR adds this endpoint so the web app can discover,
// before starting a session:
//   - whether an invite code is required (gated deployments)
//   - whether challenge secrets (e.g. magic link URLs) are exposed in
//     begin-method responses, and how email is actually being delivered —
//     both signal "this is a test/dev deployment, show the on-screen link"
//
// Deployments running the pre-/v1/config server version (this repo's own
// worktree, tonight) 404 on this route; getConfig() treats that as "nothing
// special", i.e. the all-false / 'unknown' defaults, so the app degrades to
// its current behavior rather than breaking. Network failures / timeouts are
// NOT swallowed: they throw, and the boot screen offers a Retry.

export type ConfigResponse = {
  invite_code_required: boolean;
  challenge_secrets_exposed: boolean;
  email_delivery: 'log' | 'smtp' | 'sendgrid' | 'unknown';
  /**
   * How the issuer delivers SMS OTPs. Optional: older servers omit it, in
   * which case the app behaves as before. 'log' means codes only go to the
   * server log — see smsUsable().
   */
  sms_delivery?: 'log' | 'twilio' | 'unknown';
};

export const DEFAULT_CONFIG: ConfigResponse = {
  invite_code_required: false,
  challenge_secrets_exposed: false,
  email_delivery: 'unknown',
};

const EMAIL_DELIVERY_VALUES = new Set(['log', 'smtp', 'sendgrid', 'unknown']);
const SMS_DELIVERY_VALUES = new Set(['log', 'twilio', 'unknown']);

/**
 * Coerces an arbitrary decoded JSON value into a well-formed ConfigResponse,
 * defaulting any missing/mistyped field. Pure and side-effect free so it's
 * unit-testable without a network stack — see lib/api.test.ts.
 */
export function normalizeConfig(json: unknown): ConfigResponse {
  if (!json || typeof json !== 'object') return { ...DEFAULT_CONFIG };
  const j = json as Record<string, unknown>;
  const email_delivery = EMAIL_DELIVERY_VALUES.has(j.email_delivery as string)
    ? (j.email_delivery as ConfigResponse['email_delivery'])
    : DEFAULT_CONFIG.email_delivery;
  const out: ConfigResponse = {
    invite_code_required: j.invite_code_required === true,
    challenge_secrets_exposed: j.challenge_secrets_exposed === true,
    email_delivery,
  };
  // sms_delivery stays absent when the server didn't send it, so "missing"
  // keeps meaning "older server, current behaviour".
  if (typeof j.sms_delivery === 'string') {
    out.sms_delivery = SMS_DELIVERY_VALUES.has(j.sms_delivery)
      ? (j.sms_delivery as ConfigResponse['sms_delivery'])
      : 'unknown';
  }
  return out;
}

/** True when a server URL points at this machine (local development). */
export function isLocalServerUrl(url: string): boolean {
  try {
    const host = new URL(url).hostname;
    return host === 'localhost' || host === '127.0.0.1' || host === '[::1]' || host === '::1';
  } catch {
    return false;
  }
}

/** True when SERVER_URL is a local dev server — gates developer-only hints. */
export const SERVER_IS_LOCAL = isLocalServerUrl(SERVER_URL);

/**
 * Whether the SMS step is worth showing. A server whose SMS sender only
 * logs codes (sms_delivery === 'log') can't actually text anyone, so for a
 * non-local deployment that's a dead end and we hide the step entirely. On
 * a local server the developer can read the code from the server log, so we
 * keep it. A missing sms_delivery (older server) keeps current behaviour.
 */
export function smsUsable(config: ConfigResponse | null, serverUrl: string = SERVER_URL): boolean {
  if (config?.sms_delivery !== 'log') return true;
  return isLocalServerUrl(serverUrl);
}

/**
 * Fetches GET /v1/config. A 404 (older server without the route) resolves to
 * DEFAULT_CONFIG — config is an enhancement there. A network failure,
 * timeout or other non-2xx (e.g. a cold-start 503) throws ApiError so the
 * boot screen can show a friendly error + Retry instead of guessing.
 */
export async function getConfig(): Promise<ConfigResponse> {
  const res = await request('/v1/config');
  if (res.status === 404) return { ...DEFAULT_CONFIG };
  if (!res.ok) {
    throw apiErrorFromResponse(res.status, await res.text(), res.headers.get('Retry-After'));
  }
  try {
    return normalizeConfig(await res.json());
  } catch {
    return { ...DEFAULT_CONFIG };
  }
}

/**
 * Pulls the on-screen magic link URL out of an email-begin challenge, when
 * the server includes one (DEV_EXPOSE_CHALLENGE_SECRETS=1 deployments only).
 * Pure/testable — see lib/api.test.ts.
 */
export function extractMagicLinkUrl(challenge: ChallengeData | null | undefined): string | null {
  const v = challenge?.payload?.magic_link_url;
  return typeof v === 'string' && v.length > 0 ? v : null;
}

export async function beginMethod(
  methodID: string,
  sessionID: string,
  userInput: string,
): Promise<{ challenge: ChallengeData }> {
  return postJSON(`/v1/methods/${encodeURIComponent(methodID)}/begin`, {
    session_id: sessionID,
    user_input: userInput,
  });
}

export async function completeMethod(
  methodID: string,
  sessionID: string,
  response: { type: string; payload: Record<string, unknown> },
): Promise<{ result: MethodResult; session: SessionView }> {
  return postJSON(`/v1/methods/${encodeURIComponent(methodID)}/complete`, {
    session_id: sessionID,
    response,
  });
}

export async function issueCredential(
  sessionID: string,
  holderProofB64?: string,
): Promise<{ credential: Credential }> {
  return postJSON('/v1/credentials/issue', {
    session_id: sessionID,
    holder_proof_b64: holderProofB64 || undefined,
  });
}

export async function listMethods(): Promise<{ methods: MethodSummary[] }> {
  return getJSON('/v1/methods');
}

/**
 * Poll the server's view of a session. Used to detect progress made out of
 * band — e.g. the email magic link was clicked in another tab or on another
 * device — instead of trusting the user to say "I clicked it".
 */
export async function getSession(sessionID: string): Promise<SessionView> {
  return getJSON(`/v1/sessions/${encodeURIComponent(sessionID)}`);
}

/** True when the session has a successful ceremony recorded for methodID. */
export function hasVerified(session: SessionView, methodID: string): boolean {
  return session.verified_methods.some((m) => m.method_id === methodID);
}
