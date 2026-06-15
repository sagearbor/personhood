// Canonical types mirroring the Go pkg/types JSON shape. Field names match the
// on-the-wire JSON exactly (note the snake_case inside verifiedMethods).

export type DID = string;

export interface NullifierBinding {
  commitment: string;
  curve: string;
  scheme: string;
}

export interface VerifiedMethod {
  method_id: string;
  strength: number;
  verified_at: string; // RFC3339
  freshness_lifetime: number; // nanoseconds (Go time.Duration)
  attestation_digest: string;
}

export interface CredentialSubject {
  id: DID;
  verifiedMethods: VerifiedMethod[];
  anchorMethodId?: string;
  nullifierBinding?: NullifierBinding;
}

export interface CredentialStatus {
  id: string;
  type: string;
  statusPurpose: string;
  statusListIndex: number;
  statusListCredential: string;
}

export interface Proof {
  type: string;
  created: string;
  proofPurpose: string;
  verificationMethod: string;
  proofValue: string;
}

export interface PersonhoodCredential {
  "@context": string[];
  id: string;
  type: string[];
  issuer: DID;
  issuanceDate: string;
  expirationDate: string;
  credentialSubject: CredentialSubject;
  credentialStatus?: CredentialStatus;
  proof?: Proof;
}

export interface Policy {
  version: string;
  policy_id: string;
  action: string;
  anchor_required?: boolean;
  min_supplementary_points?: number;
  allowed_methods?: string[];
  blocked_methods?: string[];
  min_strength_per_method?: Record<string, number>;
  max_credential_age_seconds?: number;
  max_anchor_method_age_seconds?: number;
  require_fresh_anchor_proof?: boolean;
  nullifier_required?: boolean;
  nullifier_context_tag?: string;
}

// EvaluationCode values are byte-for-byte identical to the Go EvaluationCode
// constants so both SDKs share one code space.
export enum EvaluationCode {
  OK = "ok",
  AnchorMissing = "anchor_missing",
  InsufficientSupplementary = "insufficient_supplementary",
  VCExpired = "vc_expired",
  AnchorMethodExpired = "anchor_method_expired",
  MethodBlocked = "method_blocked",
  MethodNotAllowed = "method_not_allowed",
  MethodStrengthInsufficient = "method_strength_insufficient",
  FreshAnchorRequired = "fresh_anchor_required",
  NullifierMissing = "nullifier_missing",
  SignatureInvalid = "signature_invalid",
  Revoked = "revoked",
  UnknownIssuer = "unknown_issuer",
}

// Result is the outcome of verify(). Mirrors the Go SDK's Result.
export interface Result {
  ok: boolean;
  code: EvaluationCode;
  human: string;
  details?: Record<string, unknown>;
  // Non-empty iff policy.nullifier_required and ok.
  nullifier?: string;
}
