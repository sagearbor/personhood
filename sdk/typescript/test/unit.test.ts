import { describe, it, expect } from "vitest";
import { canonicalize } from "../src/jcs.js";
import { evaluate } from "../src/policy.js";
import { EvaluationCode, type PersonhoodCredential, type Policy } from "../src/types.js";

describe("JCS canonicalization", () => {
  it("sorts object keys by code unit", () => {
    expect(canonicalize('{"b":1,"a":2,"c":3}')).toBe('{"a":2,"b":1,"c":3}');
  });

  it("preserves large integers exactly (no Number precision loss)", () => {
    // 7776000000000000 > 2^53 boundary territory; must round-trip verbatim.
    expect(canonicalize('{"freshness_lifetime":7776000000000000}')).toBe(
      '{"freshness_lifetime":7776000000000000}',
    );
    expect(canonicalize("{\"n\":99999999999999999999}")).toBe('{"n":99999999999999999999}');
  });

  it("escapes only mandatory characters", () => {
    expect(canonicalize('{"k":"a/b\\nc"}')).toBe('{"k":"a/b\\nc"}');
  });
});

function baseCredential(): PersonhoodCredential {
  return {
    "@context": [
      "https://www.w3.org/2018/credentials/v1",
      "https://personhood.protocol/credentials/v1",
    ],
    id: "urn:test:1",
    type: ["VerifiableCredential", "PersonhoodCredential"],
    issuer: "did:web:issuer.example",
    issuanceDate: "2026-06-15T11:00:00Z",
    expirationDate: "2026-09-13T11:00:00Z",
    credentialSubject: {
      id: "did:web:holder.example",
      verifiedMethods: [
        {
          method_id: "government-id-liveness",
          strength: 90,
          verified_at: "2026-06-15T11:30:00Z",
          freshness_lifetime: 7776000000000000,
          attestation_digest: "deadbeef",
        },
        {
          method_id: "email",
          strength: 12,
          verified_at: "2026-06-15T10:00:00Z",
          freshness_lifetime: 2592000000000000,
          attestation_digest: "cafebabe",
        },
      ],
      anchorMethodId: "government-id-liveness",
    },
  };
}

const now = new Date("2026-06-15T12:00:00Z");

function policy(overrides: Partial<Policy> = {}): Policy {
  return {
    version: "1.0",
    policy_id: "p",
    action: "a",
    anchor_required: true,
    ...overrides,
  };
}

describe("policy evaluate (parity with Go)", () => {
  it("passes when the anchor is present and fresh", () => {
    const out = evaluate(baseCredential(), policy(), now);
    expect(out.ok).toBe(true);
    expect(out.code).toBe(EvaluationCode.OK);
  });

  it("fails anchor_missing when no anchor", () => {
    const cred = baseCredential();
    delete cred.credentialSubject.anchorMethodId;
    cred.credentialSubject.verifiedMethods = [cred.credentialSubject.verifiedMethods[1]!];
    const out = evaluate(cred, policy(), now);
    expect(out.code).toBe(EvaluationCode.AnchorMissing);
  });

  it("fails anchor_method_expired past the freshness window", () => {
    const out = evaluate(baseCredential(), policy({ max_anchor_method_age_seconds: 60 }), now);
    expect(out.code).toBe(EvaluationCode.AnchorMethodExpired);
  });

  it("fails vc_expired past expiration", () => {
    const out = evaluate(baseCredential(), policy(), new Date("2027-01-01T00:00:00Z"));
    expect(out.code).toBe(EvaluationCode.VCExpired);
  });

  it("fails insufficient_supplementary", () => {
    const out = evaluate(baseCredential(), policy({ min_supplementary_points: 50 }), now);
    expect(out.code).toBe(EvaluationCode.InsufficientSupplementary);
  });

  it("fails nullifier_missing when required but absent", () => {
    const out = evaluate(
      baseCredential(),
      policy({ nullifier_required: true, nullifier_context_tag: "ctx" }),
      now,
    );
    expect(out.code).toBe(EvaluationCode.NullifierMissing);
  });
});
