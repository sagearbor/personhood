// @personhood/sdk — TypeScript SDK for integrators verifying Personhood W3C
// Verifiable Credentials against integrator policies.
//
// It mirrors the Go SDK (sdk/go): one call composes issuer-signature
// verification (Ed25519 over RFC 8785 / JCS), Status List 2021 revocation,
// policy evaluation, and nullifier derivation. Cross-language interop with the
// Go issuer is covered by a fixture test (test/interop.test.ts).

import { canonicalizeWithoutProof } from "./jcs.js";
import { base64urlToBytes, verifyEd25519 } from "./crypto.js";
import { evaluate, deriveNullifier } from "./policy.js";
import { isRevoked, type FetchLike } from "./statuslist.js";
import {
  EvaluationCode,
  type PersonhoodCredential,
  type Policy,
  type Result,
} from "./types.js";

const PROOF_TYPE_ED25519 = "Ed25519Signature2020";
const PROOF_PURPOSE_ASSERTION = "assertionMethod";

export interface VerifierOptions {
  /** Time source for expiry/freshness checks. Defaults to () => new Date(). */
  now?: () => Date;
  /** fetch implementation for the revocation list. Defaults to global fetch. */
  fetch?: FetchLike;
  /** Skip the Status List 2021 fetch (offline / out-of-band revocation). */
  skipRevocationCheck?: boolean;
}

/**
 * TrustedIssuers maps each trusted issuer DID to its 32-byte raw Ed25519 public
 * key. A credential whose issuer is absent fails with UnknownIssuer.
 */
export type TrustedIssuers = Record<string, Uint8Array>;

export class Verifier {
  private readonly trusted: TrustedIssuers;
  private readonly now: () => Date;
  private readonly fetchImpl: FetchLike;
  private readonly skipRevoke: boolean;

  constructor(trusted: TrustedIssuers, opts: VerifierOptions = {}) {
    this.trusted = trusted;
    this.now = opts.now ?? (() => new Date());
    this.fetchImpl = opts.fetch ?? fetch;
    this.skipRevoke = opts.skipRevocationCheck ?? false;
  }

  /**
   * verify runs signature + revocation + policy checks against the credential.
   *
   * Pass the credential as the raw JSON **string** when possible: it is
   * canonicalized for signature verification, and the raw text avoids any
   * number-precision loss. Passing a parsed object also works for the value
   * range Personhood credentials use.
   *
   * Throws only for unattributable transport/internal failures (e.g. a
   * revocation-list fetch that failed) so callers can fail closed; an invalid,
   * revoked, or non-compliant credential resolves to { ok: false, ... }.
   */
  async verify(credential: string | PersonhoodCredential, policy: Policy): Promise<Result> {
    const rawText = typeof credential === "string" ? credential : JSON.stringify(credential);
    let cred: PersonhoodCredential;
    try {
      cred = (typeof credential === "string" ? JSON.parse(credential) : credential) as PersonhoodCredential;
    } catch (e) {
      return deny(EvaluationCode.SignatureInvalid, "This credential could not be parsed.", {
        reason: String(e),
      });
    }

    // 1. Signature + structure.
    const sigResult = await this.verifySignature(rawText, cred);
    if (sigResult) return sigResult;

    // 2. Revocation.
    if (!this.skipRevoke) {
      const revoked = await isRevoked(cred, this.fetchImpl); // may throw → fail closed
      if (revoked) {
        return deny(EvaluationCode.Revoked, "This credential has been revoked. Please re-verify.");
      }
    }

    // 3. Policy evaluation.
    const outcome = evaluate(cred, policy, this.now());
    if (!outcome.ok) {
      return { ok: false, code: outcome.code, human: outcome.human, details: outcome.details };
    }

    const result: Result = {
      ok: true,
      code: outcome.code,
      human: outcome.human,
      details: outcome.details,
    };

    // 4. Nullifier derivation when required.
    if (policy.nullifier_required) {
      const binding = cred.credentialSubject.nullifierBinding!;
      try {
        result.nullifier = await deriveNullifier(binding, policy.nullifier_context_tag ?? "");
      } catch (e) {
        return deny(EvaluationCode.NullifierMissing, "Your credential's privacy binding is malformed.", {
          reason: String(e),
        });
      }
    }
    return result;
  }

  /** Returns a deny Result on failure, or null when the signature is valid. */
  private async verifySignature(rawText: string, cred: PersonhoodCredential): Promise<Result | null> {
    const pub = this.trusted[cred.issuer];
    if (!pub) {
      return deny(EvaluationCode.UnknownIssuer, "This credential was issued by a party this service does not trust.", {
        issuer: cred.issuer,
      });
    }
    const proof = cred.proof;
    if (!proof || !proof.proofValue) {
      return deny(EvaluationCode.SignatureInvalid, "This credential could not be verified. Please re-verify.", {
        reason: "proof missing",
      });
    }
    if (proof.type !== PROOF_TYPE_ED25519 || proof.proofPurpose !== PROOF_PURPOSE_ASSERTION) {
      return deny(EvaluationCode.SignatureInvalid, "This credential could not be verified. Please re-verify.", {
        reason: `unsupported proof ${proof.type}/${proof.proofPurpose}`,
      });
    }
    let message: Uint8Array;
    let sig: Uint8Array;
    try {
      message = canonicalizeWithoutProof(rawText);
      sig = base64urlToBytes(proof.proofValue);
    } catch (e) {
      return deny(EvaluationCode.SignatureInvalid, "This credential could not be verified. Please re-verify.", {
        reason: String(e),
      });
    }
    const ok = await verifyEd25519(pub, message, sig);
    if (!ok) {
      return deny(EvaluationCode.SignatureInvalid, "This credential could not be verified. Please re-verify.", {
        reason: "signature invalid",
      });
    }
    return null;
  }
}

function deny(code: EvaluationCode, human: string, details?: Record<string, unknown>): Result {
  return { ok: false, code, human, details };
}

/** createVerifier is a convenience factory for Verifier. */
export function createVerifier(trusted: TrustedIssuers, opts?: VerifierOptions): Verifier {
  return new Verifier(trusted, opts);
}

export { EvaluationCode } from "./types.js";
export type {
  PersonhoodCredential,
  Policy,
  Result,
  CredentialSubject,
  VerifiedMethod,
  NullifierBinding,
} from "./types.js";
export { deriveNullifier } from "./policy.js";
export { base64ToBytes, base64urlToBytes } from "./crypto.js";
export { canonicalize } from "./jcs.js";
