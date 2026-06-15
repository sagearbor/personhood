import { describe, it, expect } from "vitest";
import { readFileSync } from "node:fs";
import { fileURLToPath } from "node:url";
import { Verifier, EvaluationCode, base64ToBytes, deriveNullifier } from "../src/index.js";
import type { Policy, NullifierBinding } from "../src/index.js";

// Fixture produced by the Go issuer (tools/gen-ts-fixture). This proves the TS
// SDK reproduces Go's JCS canonicalization + Ed25519 signature + SHA-256
// nullifier exactly.
const fixturePath = fileURLToPath(new URL("./fixtures/credential.json", import.meta.url));
const fixture = JSON.parse(readFileSync(fixturePath, "utf8")) as {
  issuerDID: string;
  issuerPublicKeyB64: string;
  credentialJSON: string;
  nowRFC3339: string;
  nullifierContext: string;
  expectedNullifier: string;
};

const pub = base64ToBytes(fixture.issuerPublicKeyB64);
const now = () => new Date(fixture.nowRFC3339);

function votePolicy(): Policy {
  return {
    version: "1.0",
    policy_id: "openline/suffrage/vote/v1",
    action: "vote.cast",
    anchor_required: true,
    max_anchor_method_age_seconds: 86400,
    nullifier_required: true,
    nullifier_context_tag: fixture.nullifierContext,
  };
}

describe("cross-language interop with the Go issuer", () => {
  it("verifies a Go-signed credential and derives the matching nullifier", async () => {
    const v = new Verifier({ [fixture.issuerDID]: pub }, { now, skipRevocationCheck: true });
    const res = await v.verify(fixture.credentialJSON, votePolicy());
    expect(res.code).toBe(EvaluationCode.OK);
    expect(res.ok).toBe(true);
    expect(res.nullifier).toBe(fixture.expectedNullifier);
  });

  it("rejects a tampered credential (signature no longer valid)", async () => {
    // Flip one hex digit inside the commitment without touching the proof.
    const tampered = fixture.credentialJSON.replace(
      '"commitment":"0a1b2c3d4e5f60718293a4b5c6d7e8f9"',
      '"commitment":"0a1b2c3d4e5f60718293a4b5c6d7e8fa"',
    );
    expect(tampered).not.toBe(fixture.credentialJSON);
    const v = new Verifier({ [fixture.issuerDID]: pub }, { now, skipRevocationCheck: true });
    const res = await v.verify(tampered, votePolicy());
    expect(res.ok).toBe(false);
    expect(res.code).toBe(EvaluationCode.SignatureInvalid);
  });

  it("rejects an untrusted issuer", async () => {
    const v = new Verifier({}, { now, skipRevocationCheck: true });
    const res = await v.verify(fixture.credentialJSON, votePolicy());
    expect(res.ok).toBe(false);
    expect(res.code).toBe(EvaluationCode.UnknownIssuer);
  });

  it("deriveNullifier matches the Go DeriveNullifier output", async () => {
    const binding: NullifierBinding = {
      commitment: "0a1b2c3d4e5f60718293a4b5c6d7e8f9",
      curve: "bn254",
      scheme: "pedersen-v1",
    };
    const got = await deriveNullifier(binding, fixture.nullifierContext);
    expect(got).toBe(fixture.expectedNullifier);
  });
});
