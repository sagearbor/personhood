package types

import (
	"strings"
	"testing"
	"time"
)

func TestMethodMetadataValidate(t *testing.T) {
	t.Parallel()

	cases := []struct {
		name      string
		md        MethodMetadata
		wantErr   bool
		wantInErr string
	}{
		{
			name: "valid anchor",
			md: MethodMetadata{
				ID: "phone-liveness", Type: MethodTypeAnchor, Strength: 75,
				UXFriction: FrictionHigh, FreshnessLifetime: 24 * time.Hour, Version: "0.1.0",
			},
			wantErr: false,
		},
		{
			name: "valid supplementary",
			md: MethodMetadata{
				ID: "email", Type: MethodTypeSupplementary, Strength: 5,
				UXFriction: FrictionLow, FreshnessLifetime: 30 * 24 * time.Hour, Version: "0.1.0",
			},
			wantErr: false,
		},
		{
			name: "anchor with too low strength",
			md: MethodMetadata{
				ID: "phone-liveness", Type: MethodTypeAnchor, Strength: 30,
				UXFriction: FrictionHigh, FreshnessLifetime: time.Hour, Version: "0.1.0",
			},
			wantErr: true, wantInErr: "anchor method must have strength >= 50",
		},
		{
			name: "supplementary with too high strength",
			md: MethodMetadata{
				ID: "sms", Type: MethodTypeSupplementary, Strength: 80,
				UXFriction: FrictionMed, FreshnessLifetime: time.Hour, Version: "0.1.0",
			},
			wantErr: true, wantInErr: "supplementary method must have strength < 50",
		},
		{
			name: "strength out of range",
			md: MethodMetadata{
				ID: "x", Type: MethodTypeAnchor, Strength: 150,
				Version: "0.1.0",
			},
			wantErr: true, wantInErr: "out of range",
		},
		{
			name: "missing id",
			md: MethodMetadata{
				Type: MethodTypeAnchor, Strength: 60, Version: "0.1.0",
			},
			wantErr: true, wantInErr: "id is required",
		},
		{
			name: "missing version",
			md: MethodMetadata{
				ID: "phone-liveness", Type: MethodTypeAnchor, Strength: 60,
			},
			wantErr: true, wantInErr: "version is required",
		},
		{
			name: "unknown type",
			md: MethodMetadata{
				ID: "foo", Type: "weird", Strength: 60, Version: "0.1.0",
			},
			wantErr: true, wantInErr: "unknown type",
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			err := tc.md.Validate()
			if tc.wantErr && err == nil {
				t.Fatalf("expected error, got nil")
			}
			if !tc.wantErr && err != nil {
				t.Fatalf("expected no error, got %v", err)
			}
			if err != nil && tc.wantInErr != "" && !strings.Contains(err.Error(), tc.wantInErr) {
				t.Fatalf("error %q does not contain %q", err.Error(), tc.wantInErr)
			}
		})
	}
}

func TestPolicyValidate(t *testing.T) {
	t.Parallel()

	cases := []struct {
		name      string
		p         Policy
		wantErr   bool
		wantInErr string
	}{
		{
			name: "valid simple policy",
			p: Policy{
				Version: "1.0", PolicyID: "ubi.claim", Action: "ubi.claim",
				AnchorRequired: true, MinSupplementaryPoints: 10,
			},
			wantErr: false,
		},
		{
			name: "unsupported version",
			p: Policy{
				Version: "9.9", PolicyID: "x", Action: "x",
			},
			wantErr: true, wantInErr: "unsupported version",
		},
		{
			name: "missing policy_id",
			p: Policy{
				Version: "1.0", Action: "x",
			},
			wantErr: true, wantInErr: "policy_id is required",
		},
		{
			name: "missing action",
			p: Policy{
				Version: "1.0", PolicyID: "x",
			},
			wantErr: true, wantInErr: "action is required",
		},
		{
			name: "negative supplementary points",
			p: Policy{
				Version: "1.0", PolicyID: "x", Action: "x", MinSupplementaryPoints: -5,
			},
			wantErr: true, wantInErr: "min_supplementary_points",
		},
		{
			name: "nullifier required without context tag",
			p: Policy{
				Version: "1.0", PolicyID: "vote", Action: "vote.cast",
				AnchorRequired: true, NullifierRequired: true,
			},
			wantErr: true, wantInErr: "nullifier_context_tag is required",
		},
		{
			name: "nullifier required with context tag",
			p: Policy{
				Version: "1.0", PolicyID: "vote", Action: "vote.cast",
				AnchorRequired: true, NullifierRequired: true,
				NullifierContextTag: "vote:proposal-42",
			},
			wantErr: false,
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			err := tc.p.Validate()
			if tc.wantErr && err == nil {
				t.Fatalf("expected error, got nil")
			}
			if !tc.wantErr && err != nil {
				t.Fatalf("expected no error, got %v", err)
			}
			if err != nil && tc.wantInErr != "" && !strings.Contains(err.Error(), tc.wantInErr) {
				t.Fatalf("error %q does not contain %q", err.Error(), tc.wantInErr)
			}
		})
	}
}

func TestPolicyRequiresNullifier(t *testing.T) {
	t.Parallel()

	if (Policy{}).RequiresNullifier() {
		t.Fatal("zero-value policy must not require nullifier")
	}
	if !(Policy{NullifierRequired: true}).RequiresNullifier() {
		t.Fatal("policy with NullifierRequired=true must require nullifier")
	}
}

func TestPersonhoodCredentialValidate(t *testing.T) {
	t.Parallel()

	now := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	good := PersonhoodCredential{
		Context:        []string{W3CVCContext, PersonhoodVCContext},
		ID:             "urn:uuid:11111111-1111-1111-1111-111111111111",
		Type:           []string{"VerifiableCredential", "PersonhoodCredential"},
		Issuer:         DID("did:web:personhood.example"),
		IssuanceDate:   now,
		ExpirationDate: now.Add(90 * 24 * time.Hour),
		CredentialSubject: CredentialSubject{
			ID: DID("did:key:z6Mkholder"),
			VerifiedMethods: []VerifiedMethod{
				{MethodID: "phone-liveness", Strength: 75, VerifiedAt: now, FreshnessLifetime: 24 * time.Hour, AttestationDigest: "deadbeef"},
			},
			AnchorMethodID: ptr("phone-liveness"),
		},
	}

	if err := good.Validate(); err != nil {
		t.Fatalf("valid credential rejected: %v", err)
	}

	t.Run("missing W3C context", func(t *testing.T) {
		bad := good
		bad.Context = []string{PersonhoodVCContext}
		if err := bad.Validate(); err == nil {
			t.Fatal("expected error for missing W3C context")
		}
	})

	t.Run("missing Personhood context", func(t *testing.T) {
		bad := good
		bad.Context = []string{W3CVCContext}
		if err := bad.Validate(); err == nil {
			t.Fatal("expected error for missing Personhood context")
		}
	})

	t.Run("W3C context not first", func(t *testing.T) {
		bad := good
		bad.Context = []string{PersonhoodVCContext, W3CVCContext}
		if err := bad.Validate(); err == nil {
			t.Fatal("expected error when W3C context is not first")
		}
	})

	t.Run("missing issuer", func(t *testing.T) {
		bad := good
		bad.Issuer = ""
		if err := bad.Validate(); err == nil {
			t.Fatal("expected error for missing issuer")
		}
	})

	t.Run("issuance after expiration", func(t *testing.T) {
		bad := good
		bad.IssuanceDate = now.Add(48 * time.Hour)
		bad.ExpirationDate = now
		if err := bad.Validate(); err == nil {
			t.Fatal("expected error when issuanceDate >= expirationDate")
		}
	})

	t.Run("empty verified methods", func(t *testing.T) {
		bad := good
		bad.CredentialSubject = CredentialSubject{
			ID:              good.CredentialSubject.ID,
			VerifiedMethods: nil,
		}
		if err := bad.Validate(); err == nil {
			t.Fatal("expected error for empty verifiedMethods")
		}
	})

	t.Run("anchor not in verified methods", func(t *testing.T) {
		bad := good
		bad.CredentialSubject = CredentialSubject{
			ID:              good.CredentialSubject.ID,
			VerifiedMethods: good.CredentialSubject.VerifiedMethods,
			AnchorMethodID:  ptr("does-not-exist"),
		}
		if err := bad.Validate(); err == nil {
			t.Fatal("expected error when anchorMethodId is not in verifiedMethods")
		}
	})
}

// ptr returns a pointer to the given string.
func ptr(s string) *string { return &s }
