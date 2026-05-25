# 03 — Credential Format: W3C VC with ZK Extension Hooks

> Status: design spec for v0.1. Companion docs: [01-architecture.md](./01-architecture.md), [02-methods.md](./02-methods.md), [04-policy-dsl.md](./04-policy-dsl.md).

## Why W3C Verifiable Credentials

Personhood ships with the W3C Verifiable Credentials Data Model (1.1) as the credential format. The alternatives we considered:

- **JWT / SD-JWT.** Smaller wire size, simpler tooling on the JS side. We rejected this because (a) JWT does not carry a typed, extensible schema graph — every consumer would have to coordinate on field names in prose; (b) selective disclosure in SD-JWT is bolted on, where W3C VC has a clean roadmap to BBS+ signatures; (c) the OpenLine use case needs the optional `nullifierBinding` Pedersen commitment to interop with the existing Circom ZK stack, and that fits cleanly as a typed JSON-LD term but awkwardly as a JWT extension.
- **Custom Protobuf credential.** Cheapest to encode/decode, but a credential format is a long-term commitment that integrators will write against for years. Using a standard with an existing tooling ecosystem (didkit, Spruce, Veramo, did-jwt-vc) lowers integrator friction more than the marginal payload savings buy us.
- **OpenID4VC presentation format.** We adopt OpenID4VP at the *presentation* layer for the browser flow (it solves the wallet-redirect problem cleanly), but the underlying credential is still a W3C VC.

W3C VC + JSON-LD also gives us a clean upgrade story: today's credential ships with Ed25519Signature2020; tomorrow's adds a BBS+ proof for selective disclosure; the day after's adds a nullifierBinding ZK predicate — all as added terms in our `@context`, with backwards-compatible parsers.

## PersonhoodCredential schema

The credential is a JSON-LD document with two contexts: the W3C base and Personhood's. The Personhood context URI is **`https://personhood.protocol/credentials/v1`** and is served by the reference deployment at that URL as a stable JSON-LD context file. The repo-local source of truth is `pkg/proto/context-v1.jsonld` (authored by Agent A in a sibling PR).

The type name added by Personhood is `PersonhoodCredential` (alongside the standard `VerifiableCredential`).

### Required vs optional fields

| Field | Required? | Type | Notes |
|---|---|---|---|
| `@context` | required | array | MUST include `https://www.w3.org/2018/credentials/v1` and `https://personhood.protocol/credentials/v1` |
| `id` | required | URI | Unique per credential, typically `urn:uuid:…` |
| `type` | required | array | MUST include `VerifiableCredential` and `PersonhoodCredential` |
| `issuer` | required | DID or object | `did:web:issuer.personhood.example` for the reference issuer; an object form `{ id, name }` is allowed |
| `issuanceDate` | required | ISO-8601 datetime | RFC3339 with Z |
| `expirationDate` | required (v0.1) | ISO-8601 datetime | One year from issuance in v0.1 |
| `credentialSubject` | required | object | Holds the holder DID and the verified-methods array |
| `credentialSubject.id` | required | `did:key` | The holder's DID; the holder must be able to sign with the matching private key |
| `credentialSubject.verifiedMethods` | required | array, length ≥ 1, MUST include ≥ 1 anchor | The list of completed methods that backs this credential |
| `credentialSubject.anchorPresent` | required | boolean | Convenience flag; MUST be `true` (issuance refuses anchorless credentials) |
| `credentialSubject.nullifierBinding` | optional | object | Pedersen-BN254 commitment for ZK-aware integrators |
| `credentialSchema` | recommended | object | Points to the JSON Schema at `https://personhood.protocol/credentials/v1/schema.json` |
| `credentialStatus` | recommended | object | W3C Status List 2021 entry for revocation |
| `proof` | required | object | Ed25519Signature2020 over URDNA2015 canonical form |

Each entry in `verifiedMethods` has:

| Field | Required? | Type | Notes |
|---|---|---|---|
| `method` | required | string | Method ID, e.g. `"phone-liveness"` |
| `methodType` | required | `anchor` \| `supplementary` | Mirrors the registry's `Method.Type()` at completion time |
| `strength` | required | integer 0–100 | Frozen at completion; later registry recalibrations don't change issued credentials |
| `completedAt` | required | ISO-8601 datetime | The per-method freshness reference |
| `evidence` | optional | object | Method-specific opaque metadata (vendor name, attestation excerpt, hashed identifier) |

The schema is small and additive on purpose. Anything a particular method wants to record (FaceTec audit-trail ID, Twilio Lookup carrier info, etc.) goes in `evidence` and never breaks the parser.

### Full JSON example: standard credential (phone-liveness + email)

```json
{
  "@context": [
    "https://www.w3.org/2018/credentials/v1",
    "https://personhood.protocol/credentials/v1"
  ],
  "id": "urn:uuid:f4a9c1d2-3b6e-4a8d-9c11-2b6c7e8d1234",
  "type": ["VerifiableCredential", "PersonhoodCredential"],
  "issuer": {
    "id": "did:web:issuer.personhood.example",
    "name": "Personhood Reference Issuer"
  },
  "issuanceDate": "2026-05-24T18:32:11Z",
  "expirationDate": "2027-05-24T18:32:11Z",
  "credentialSchema": {
    "id": "https://personhood.protocol/credentials/v1/schema.json",
    "type": "JsonSchemaValidator2018"
  },
  "credentialStatus": {
    "id": "https://issuer.personhood.example/status/3#94567",
    "type": "StatusList2021Entry",
    "statusPurpose": "revocation",
    "statusListIndex": "94567",
    "statusListCredential": "https://issuer.personhood.example/status/3"
  },
  "credentialSubject": {
    "id": "did:key:z6MkpTHR8VNsBxYAAWHut2Geadd9jSrnqGtVQNbjkW1z3PqM",
    "anchorPresent": true,
    "verifiedMethods": [
      {
        "method": "phone-liveness",
        "methodType": "anchor",
        "strength": 75,
        "completedAt": "2026-05-24T18:30:42Z",
        "evidence": {
          "vendor": "facetec",
          "padLevel": 2,
          "deviceAttestation": "apple-app-attest",
          "vendorReceiptId": "ft_8c2e1a47b9d3"
        }
      },
      {
        "method": "email",
        "methodType": "supplementary",
        "strength": 8,
        "completedAt": "2026-05-24T18:21:09Z",
        "evidence": {
          "emailHash": "sha256:7f8a1c…b3"
        }
      }
    ]
  },
  "proof": {
    "type": "Ed25519Signature2020",
    "created": "2026-05-24T18:32:11Z",
    "verificationMethod": "did:web:issuer.personhood.example#key-1",
    "proofPurpose": "assertionMethod",
    "proofValue": "z4oey5q2M3XKaxup3tmzN4DRFTLVqpLMweBrSxFPxKfSjpaBdsj1LZ8FzQk5XzWqXxQzS2VkrG8nC6Vh8jGfA7sM6"
  }
}
```

### Full JSON example: ZK-bound credential (with nullifierBinding for OpenLine Suffrage)

```json
{
  "@context": [
    "https://www.w3.org/2018/credentials/v1",
    "https://personhood.protocol/credentials/v1"
  ],
  "id": "urn:uuid:b0a72e15-9c4a-4d3c-8e2f-5fa3d12b7a90",
  "type": ["VerifiableCredential", "PersonhoodCredential"],
  "issuer": "did:web:issuer.personhood.example",
  "issuanceDate": "2026-05-24T19:14:02Z",
  "expirationDate": "2027-05-24T19:14:02Z",
  "credentialSchema": {
    "id": "https://personhood.protocol/credentials/v1/schema.json",
    "type": "JsonSchemaValidator2018"
  },
  "credentialStatus": {
    "id": "https://issuer.personhood.example/status/3#94568",
    "type": "StatusList2021Entry",
    "statusPurpose": "revocation",
    "statusListIndex": "94568",
    "statusListCredential": "https://issuer.personhood.example/status/3"
  },
  "credentialSubject": {
    "id": "did:key:z6MkrJVTbAjkvr2zHv9NJxh7m7gKpzZ4z1ttU8sP6Q2vN3xR",
    "anchorPresent": true,
    "verifiedMethods": [
      {
        "method": "phone-liveness",
        "methodType": "anchor",
        "strength": 75,
        "completedAt": "2026-05-24T19:12:35Z",
        "evidence": {
          "vendor": "facetec",
          "padLevel": 2,
          "deviceAttestation": "android-play-integrity"
        }
      },
      {
        "method": "sms",
        "methodType": "supplementary",
        "strength": 12,
        "completedAt": "2026-05-24T19:08:14Z",
        "evidence": {
          "phoneHash": "sha256:9d6b…02",
          "carrierType": "mobile"
        }
      }
    ],
    "nullifierBinding": {
      "type": "PedersenBN254Commitment2026",
      "curve": "bn254",
      "commitment": "0x1f2a3b4c5d6e7f8091a2b3c4d5e6f7081923a4b5c6d7e8f9012345678901abcd",
      "domainSeparationHashAlgorithm": "poseidon",
      "nullifierDerivation": "poseidon(commitment, poseidon(utf8(context_tag)))",
      "note": "Holder retains the opening (the secret committed to). Per-context nullifiers are derived by the holder client-side and revealed to integrators in a ZK proof; the commitment alone reveals nothing about the secret."
    }
  },
  "proof": {
    "type": "Ed25519Signature2020",
    "created": "2026-05-24T19:14:02Z",
    "verificationMethod": "did:web:issuer.personhood.example#key-1",
    "proofPurpose": "assertionMethod",
    "proofValue": "z3MTHpQ8FvuzL6sgX2k1NyP2N9Hx5fy7vqJzKqXVUWaspY4N8VkV3y3LRT6X7eDjEcMTSzCgYjY4N5pq8rXxHvSgZ"
  }
}
```

## ZK extension hooks

The `nullifierBinding` field exists so that integrators using a ZK stack (today: OpenLine's existing Circom + Poseidon machinery) can derive per-context nullifiers from a single credential, proving in zero knowledge that the holder is the unique human who was issued the credential, without revealing the credential itself.

Design:

- **Commitment scheme:** Pedersen over BN254. Chosen for interop with the existing OpenLine Circom circuits and snarkjs Groth16 verifier, which already operate over BN254 with Poseidon hashing. The issuer commits to a fresh secret scalar `s` (32-byte uniformly-random over the BN254 scalar field) that is bound to the issued credential. The holder is the only party who learns `s` (the issuer hands it to the holder over the issuance channel and **does not persist it** after issuance, only the commitment).
- **Nullifier derivation (off-chain, holder-side):**
  `nullifier = Poseidon(s, Poseidon(utf8(context_tag)))`
  where `context_tag` is the policy's `nullifier_context_tag` (e.g. `"openline/suffrage/vote/election-2026-municipal"`). Domain separation is single-level Poseidon so the constraint cost is small.
- **ZK predicate (proven in Circom circuit, supplied by integrator):**
  The holder proves they know `s` such that `pedersen_bn254(s) == commitment` AND `nullifier == Poseidon(s, Poseidon(utf8(context_tag)))`, without revealing `s`. The integrator's smart contract or off-chain verifier receives `(commitment, context_tag, nullifier, zk_proof)` and accepts if the proof verifies. The commitment is bound to the W3C VC by the issuer's Ed25519 signature, so the integrator transitively trusts that this commitment belongs to a verified human.
- **What Personhood explicitly does NOT define:** the Circom circuit itself. That is integrator-specific (OpenLine has VoteProof / ClaimProof; another integrator may have different predicates). Personhood ships only the commitment, the domain-separation function, and the documented derivation formula. Future versions of Personhood may publish a reference Circom library, but v0.1 deliberately keeps this surface minimal so we don't lock integrators into a specific proving system.

The non-ZK integrators (the simple case — Personhood verifier SDK alone) can ignore `nullifierBinding` entirely. The credential is fully self-contained without it.

## Issuance protocol

1. End user completes one or more enrollment ceremonies through the wallet (see [01-architecture.md](./01-architecture.md) Enrollment data flow).
2. Wallet calls `POST /enrollment/issue`. Optionally requests `nullifierBinding` in the request body (`{ "include_nullifier_binding": true }`).
3. Server-side, the issuer:
   a. Loads all stored `MethodResult`s for the enrollment.
   b. Validates the minimum issuance bar (≥ 1 anchor method completed).
   c. If `nullifierBinding` requested, generates a fresh secret scalar `s` over BN254 (via cryptographically secure RNG), computes the Pedersen commitment, and prepares to hand `s` back to the holder out-of-band.
   d. Builds the JSON-LD `PersonhoodCredential` document, including `credentialSubject.id` = holder DID, the `verifiedMethods` array, `anchorPresent: true`, optional `nullifierBinding`, and `credentialStatus` pointing to the issuer's Status List 2021.
   e. Canonicalizes the document using **URDNA2015** (per the W3C VC spec).
   f. Signs the canonical form with the issuer's Ed25519 key (`Ed25519Signature2020`), embedding the resulting `proof` block.
4. Server returns `{ credential: <signed VC>, nullifierSecret?: <hex s> }`. The `nullifierSecret` is sent **only** in the response body of this one issuance call (HTTPS-only, never logged); the issuer immediately forgets it.
5. Wallet persists the VC and the optional secret in encrypted local storage. The holder's private key is the only thing that can decrypt either at rest.

## Presentation protocol

1. Integrator generates a 128-bit cryptographically random `challenge` and notes its origin as `domain` (e.g. `https://commons.openline.example`).
2. Integrator redirects the user to the wallet with `(challenge, domain, requested_policy_id)`. v0.1 supports both query-string redirect and `postMessage` for embedded flows; v0.2 will adopt OpenID4VP fully.
3. Wallet selects the highest-quality VC that satisfies the requested policy (it can preview-evaluate locally using the same policy code as the SDK).
4. Wallet builds a W3C Verifiable Presentation (the `verifiableCredential` array contains the full VC document shown earlier, elided here as `"<see PersonhoodCredential JSON above>"` for brevity):

```json
{
  "@context": [
    "https://www.w3.org/2018/credentials/v1",
    "https://personhood.protocol/credentials/v1"
  ],
  "type": ["VerifiablePresentation"],
  "holder": "did:key:z6MkpTHR8VNsBxYAAWHut2Geadd9jSrnqGtVQNbjkW1z3PqM",
  "verifiableCredential": ["<see PersonhoodCredential JSON above>"],
  "proof": {
    "type": "Ed25519Signature2020",
    "created": "2026-05-24T20:00:01Z",
    "verificationMethod": "did:key:z6MkpTHR8VNsBxYAAWHut2Geadd9jSrnqGtVQNbjkW1z3PqM#z6MkpTHR",
    "proofPurpose": "authentication",
    "challenge": "9b3e2c1f8a4d56e7b2a90c4d1f6e2b73",
    "domain": "https://commons.openline.example",
    "proofValue": "z2dA1Zj4Rn"
  }
}
```

5. Wallet posts the VP back to the integrator. The integrator's SDK verifies (a) the holder's signature over `(challenge || domain)`, (b) the issuer's signature over the VC, (c) the issuer's revocation status, then (d) evaluates the credential against the loaded policy.

## Key management

- **Issuer key (Ed25519):** lives behind an HSM in production deployments. The reference local-dev issuer uses an unencrypted key file under `~/.personhood/issuer.key` with a loud warning. Key rotation is supported by adding `key-2`, `key-3` entries to the issuer's DID document and signing new credentials with the rotated key while old credentials remain verifiable against the historical key.
- **Holder key (mobile):** generated inside the device's secure enclave / Android Keystore via Apple's `SecureEnclave.P256` (we use Ed25519 via the standard fallback path) or Android's `KeyGenParameterSpec` with `STRONGBOX_BACKED` where available. The private key never leaves the enclave; signature operations are performed inside the secure boundary.
- **Holder key (web):** generated by the wallet, encrypted at rest in IndexedDB using a key derived from a WebAuthn-bound platform authenticator (Touch ID, Windows Hello, etc.). The user's biometric or PIN gates every sign operation. The wrapping key never leaves the browser.
- **Nullifier secret (optional):** treated identically to the holder key — encrypted at rest in the wallet, never exfiltrated. Loss of the secret means the holder can no longer compute consistent nullifiers, which is equivalent to losing the credential and re-enrolling.

## Revocation

We adopt **W3C Status List 2021** as the recommended revocation mechanism. The issuer publishes a single Status List 2021 credential at a stable URL (`https://issuer.personhood.example/status/3`); each issued VC carries a `credentialStatus` entry with the index into the list. Verifiers fetch the list (with sensible cache TTL — default 1 hour in the SDK) and check the bit at the entry's index.

Status List 2021 is preferred over per-credential OCSP-style lookups because (a) it's privacy-preserving (the verifier fetches a generic list, not a per-user query, so the issuer learns nothing about which credential was checked), (b) it's cacheable, and (c) it scales to millions of credentials in a single fetch (the list is GZIPped and pads out to ~16KB per million bits). Revocation is reversible (the issuer can flip a bit back to 0), which v0.1 disallows by convention — once revoked, always revoked — but the format permits future use cases.

The issuer also exposes a `POST /admin/revoke` endpoint protected by issuer auth that takes a credential ID and flips its status bit. Reasons for revocation are logged but not exposed in the Status List itself (the list is just a bitfield).

## Expiry

`expirationDate` is **1 year from issuance** in v0.1. After expiry the holder must re-enroll. The rationale: shorter expiry forces fresher anchors at the cost of UX; longer expiry weakens the freshness signal. Per-action freshness windows are handled by the policy (`max_credential_age_seconds`, `max_anchor_method_age_seconds`) rather than by short credential lifetimes, so v0.1's 1-year window is a safe default for the credential and integrators tighten it where they need to.

## Future: selective disclosure

The current Ed25519Signature2020 reveals the entire credential at presentation time. v0.2 introduces an additional proof variant — **BBS+ signatures with the BBS+ Signature 2020 suite** — that lets the holder present only a subset of the credential (e.g. "I have a verified anchor" without revealing which anchor or any supplementary methods). The credential format is unchanged; we add a new `proof.type` value and a new SDK code path that builds derived proofs at presentation time.

This is a strictly additive change: a v0.1 verifier that doesn't understand BBS+ will refuse to verify a BBS+-only VC, but the holder can also keep an Ed25519-signed copy and present whichever the integrator's SDK accepts. The implementation depends on a stable BBS+ library in Go; we are tracking `gnark-crypto` and `pairing-bn256` work upstream.

## Cross-references

- The system-level data flows (Enrollment, Issuance, Presentation, Verification): [01-architecture.md](./01-architecture.md).
- The `Method` plugin interface that produces the `verifiedMethods` entries: [02-methods.md](./02-methods.md).
- The policy schema and evaluator that consumes these credentials: [04-policy-dsl.md](./04-policy-dsl.md).
