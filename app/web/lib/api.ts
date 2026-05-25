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
  };
  proof?: {
    type: string;
    created: string;
    proofPurpose: string;
    verificationMethod: string;
    proofValue: string;
  };
};

async function postJSON<T>(path: string, body: unknown): Promise<T> {
  const res = await fetch(`${SERVER_URL}${path}`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify(body),
  });
  if (!res.ok) {
    let detail = await res.text();
    try {
      const json = JSON.parse(detail);
      detail = json?.error?.message || detail;
    } catch {
      // not JSON; surface the raw body
    }
    throw new Error(`${res.status}: ${detail}`);
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
}): Promise<StartEnrollmentResponse> {
  return postJSON<StartEnrollmentResponse>('/enrollment/start', {
    user_agent: opts.userAgent || (typeof navigator !== 'undefined' ? navigator.userAgent : ''),
    platform: opts.platform || 'web',
  });
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
