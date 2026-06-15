// Port of the Go policy evaluator (src/policy/evaluate.go) and nullifier
// derivation (src/policy/nullifier.go). Behaviour and ordering match the Go
// implementation so both SDKs agree on every outcome.

import { sha256Hex } from "./crypto.js";
import {
  EvaluationCode,
  type PersonhoodCredential,
  type Policy,
  type NullifierBinding,
} from "./types.js";

const SUPPLEMENTARY_STRENGTH_CEILING = 50;
const NS_PER_MS = 1_000_000;

export interface EvalOutcome {
  ok: boolean;
  code: EvaluationCode;
  human: string;
  details?: Record<string, unknown>;
}

function ms(rfc3339: string): number {
  const t = Date.parse(rfc3339);
  if (Number.isNaN(t)) throw new Error(`policy: invalid timestamp ${rfc3339}`);
  return t;
}

/** Structural validation mirroring types.PersonhoodCredential.Validate. */
function validateStructure(cred: PersonhoodCredential): string | null {
  const ctx = cred["@context"] ?? [];
  const W3C = "https://www.w3.org/2018/credentials/v1";
  const PH = "https://personhood.protocol/credentials/v1";
  if (!ctx.includes(W3C)) return `missing required @context ${W3C}`;
  if (!ctx.includes(PH)) return `missing required @context ${PH}`;
  if (ctx.length < 2 || ctx[0] !== W3C) return `@context[0] must be ${W3C}`;
  if (!cred.issuer) return "issuer is required";
  if (!cred.issuanceDate) return "issuanceDate is required";
  if (!cred.expirationDate) return "expirationDate is required";
  if (!(ms(cred.issuanceDate) < ms(cred.expirationDate))) {
    return "issuanceDate must be before expirationDate";
  }
  const methods = cred.credentialSubject?.verifiedMethods ?? [];
  if (methods.length === 0) return "verifiedMethods must be non-empty";
  const anchor = cred.credentialSubject.anchorMethodId;
  if (anchor != null && !methods.some((m) => m.method_id === anchor)) {
    return `anchorMethodId ${anchor} not present in verifiedMethods`;
  }
  return null;
}

/**
 * evaluate checks the credential against the policy at time `now`. It performs
 * no I/O and no signature/revocation checks (the caller runs those first).
 */
export function evaluate(cred: PersonhoodCredential, policy: Policy, now: Date): EvalOutcome {
  const nowMs = now.getTime();

  // 1. Structural validity.
  const structErr = validateStructure(cred);
  if (structErr) {
    return deny(EvaluationCode.SignatureInvalid, "This credential is not a valid Personhood credential.", {
      reason: structErr,
    });
  }

  const sub = cred.credentialSubject;

  // 2. Credential-age check.
  const maxCredAge = policy.max_credential_age_seconds ?? 0;
  if (maxCredAge > 0) {
    const ageSec = (nowMs - ms(cred.issuanceDate)) / 1000;
    if (ageSec > maxCredAge) {
      return deny(EvaluationCode.VCExpired, "Your verification is too old for this action. Please re-verify.", {
        age_seconds: Math.floor(ageSec),
        max_age_seconds: maxCredAge,
      });
    }
  }

  // 3. Hard expiration.
  if (nowMs > ms(cred.expirationDate)) {
    return deny(EvaluationCode.VCExpired, "Your verification has expired. Please re-verify.", {
      expiration_date: cred.expirationDate,
    });
  }

  // 4. Anchor presence.
  if ((policy.anchor_required ?? false) && sub.anchorMethodId == null) {
    return deny(
      EvaluationCode.AnchorMissing,
      "This action requires a stronger verification method (an anchor). Please add one.",
    );
  }

  // 5. Anchor freshness.
  if (sub.anchorMethodId != null) {
    const anchor = sub.verifiedMethods.find((m) => m.method_id === sub.anchorMethodId);
    if (!anchor) {
      return deny(EvaluationCode.AnchorMissing, "The credential's anchor method is not present in verifiedMethods.", {
        anchor_method_id: sub.anchorMethodId,
      });
    }
    const overrideSec = policy.max_anchor_method_age_seconds ?? 0;
    const windowMs = overrideSec > 0 ? overrideSec * 1000 : anchor.freshness_lifetime / NS_PER_MS;
    if (windowMs > 0 && nowMs - ms(anchor.verified_at) > windowMs) {
      return deny(EvaluationCode.AnchorMethodExpired, "Your anchor verification is too old. Please re-verify the anchor method.", {
        anchor_method_id: sub.anchorMethodId,
        verified_at: anchor.verified_at,
        window_seconds: Math.floor(windowMs / 1000),
      });
    }
  }

  // 6. Per-method allow/block/strength.
  const allowed = new Set(policy.allowed_methods ?? []);
  const blocked = new Set(policy.blocked_methods ?? []);
  const minStrength = policy.min_strength_per_method ?? {};
  for (const vm of sub.verifiedMethods) {
    if (blocked.has(vm.method_id)) {
      return deny(EvaluationCode.MethodBlocked, "Your credential relies on a verification method that is not accepted for this action.", {
        method_id: vm.method_id,
      });
    }
    if (allowed.size > 0 && !allowed.has(vm.method_id)) {
      return deny(EvaluationCode.MethodNotAllowed, "Your credential includes a verification method that is not accepted for this action.", {
        method_id: vm.method_id,
      });
    }
    if (vm.method_id in minStrength && vm.strength < minStrength[vm.method_id]!) {
      return deny(EvaluationCode.MethodStrengthInsufficient, "One of your verification methods is below the required strength for this action.", {
        method_id: vm.method_id,
        have_strength: vm.strength,
        need_strength: minStrength[vm.method_id],
      });
    }
  }

  // 7. Supplementary points.
  let supp = 0;
  for (const vm of sub.verifiedMethods) {
    if (vm.strength >= SUPPLEMENTARY_STRENGTH_CEILING) continue;
    const fl = vm.freshness_lifetime;
    if (fl > 0 && nowMs - ms(vm.verified_at) > fl / NS_PER_MS) continue;
    supp += vm.strength;
  }
  const needSupp = policy.min_supplementary_points ?? 0;
  if (supp < needSupp) {
    return deny(EvaluationCode.InsufficientSupplementary, "Please complete additional verification methods before continuing.", {
      have_points: supp,
      need_points: needSupp,
    });
  }

  // 8. Nullifier presence.
  if ((policy.nullifier_required ?? false) && sub.nullifierBinding == null) {
    return deny(EvaluationCode.NullifierMissing, "Your credential is missing the privacy binding needed for this action.");
  }

  // 9. Pass (nullifier derivation happens in the caller, async).
  const details: Record<string, unknown> = { supplementary_points: supp };
  if (policy.require_fresh_anchor_proof) details["fresh_anchor_required"] = true;
  const human = policy.require_fresh_anchor_proof
    ? "Verified — a fresh anchor proof is still required at presentation time."
    : "Verified.";
  return { ok: true, code: EvaluationCode.OK, human, details };
}

function deny(code: EvaluationCode, human: string, details?: Record<string, unknown>): EvalOutcome {
  return { ok: false, code, human, details };
}

/**
 * deriveNullifier reproduces the Go SHA-256 derivation:
 * SHA-256(commitment || ":" || contextTag), hex-encoded.
 */
export async function deriveNullifier(binding: NullifierBinding, contextTag: string): Promise<string> {
  if (!binding.commitment) throw new Error("nullifier: binding commitment is empty");
  if (!binding.scheme) throw new Error("nullifier: binding scheme is empty");
  if (!binding.curve) throw new Error("nullifier: binding curve is empty");
  if (!contextTag) throw new Error("nullifier: context tag is empty");
  const data = new TextEncoder().encode(`${binding.commitment}:${contextTag}`);
  return sha256Hex(data);
}
