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

/**
 * Thrown by postJSON on any non-2xx response. Carries the server's error
 * `code` (e.g. `invite_code_required`, `invite_code_invalid`) alongside the
 * usual message, so callers that care can branch on it instead of
 * string-matching the message text.
 */
export class ApiError extends Error {
  readonly status: number;
  readonly code?: string;

  constructor(status: number, message: string, code?: string) {
    super(message);
    this.name = 'ApiError';
    this.status = status;
    this.code = code;
  }
}

async function postJSON<T>(path: string, body: unknown): Promise<T> {
  const res = await fetch(`${SERVER_URL}${path}`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify(body),
  });
  if (!res.ok) {
    const raw = await res.text();
    let detail = raw;
    let code: string | undefined;
    try {
      const json = JSON.parse(raw);
      detail = json?.error?.message || detail;
      code = typeof json?.error?.code === 'string' ? json.error.code : undefined;
    } catch {
      // not JSON; surface the raw body
    }
    throw new ApiError(res.status, `${res.status}: ${detail}`, code);
  }
  return (await res.json()) as T;
}

async function getJSON<T>(path: string): Promise<T> {
  const res = await fetch(`${SERVER_URL}${path}`);
  if (!res.ok) {
    throw new Error(`${res.status}: ${await res.text()}`);
  }
  return (await res.json()) as T;
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
// worktree, tonight) 404 on this route; normalizeConfig()/getConfig() treat
// that — and any other failure — as "nothing special", i.e. the all-false /
// 'unknown' defaults, so the app degrades to its current behavior rather
// than breaking.

export type ConfigResponse = {
  invite_code_required: boolean;
  challenge_secrets_exposed: boolean;
  email_delivery: 'log' | 'smtp' | 'sendgrid' | 'unknown';
};

export const DEFAULT_CONFIG: ConfigResponse = {
  invite_code_required: false,
  challenge_secrets_exposed: false,
  email_delivery: 'unknown',
};

const EMAIL_DELIVERY_VALUES = new Set(['log', 'smtp', 'sendgrid', 'unknown']);

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
  return {
    invite_code_required: j.invite_code_required === true,
    challenge_secrets_exposed: j.challenge_secrets_exposed === true,
    email_delivery,
  };
}

/**
 * Fetches GET /v1/config. Tolerates a 404 (older server without the route)
 * and any other network/parse failure by resolving to DEFAULT_CONFIG rather
 * than throwing — config is an enhancement, never a boot blocker.
 */
export async function getConfig(): Promise<ConfigResponse> {
  try {
    const res = await fetch(`${SERVER_URL}/v1/config`);
    if (!res.ok) return { ...DEFAULT_CONFIG };
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

export async function issueCredential(sessionID: string): Promise<{ credential: Credential }> {
  return postJSON('/v1/credentials/issue', { session_id: sessionID });
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
