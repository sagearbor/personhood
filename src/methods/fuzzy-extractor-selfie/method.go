// Package fuzzyextractorselfie implements the Personhood
// "fuzzy-extractor-selfie" ANCHOR verification method (STATUS.md checklist
// #10a): the airdrop-test-compatible anchor for users with no government ID,
// no bank account, and no fixed address.
//
// Strength 90->70, anchor (well above the 50 threshold), cost $0.00, med
// friction, per docs/06-methods-catalog.md's `fuzzy-extractor-selfie` row
// (strength 70). Unlike government-id-liveness (Persona) and plaid-bank-link
// (Plaid), this method wraps NO third-party vendor: the on-device biometric
// feature extraction (a face-embedding model running in the client app,
// out of scope for this Go server module) plus the server-side fuzzy
// extractor (extractor.go) and accumulator (accumulator.go) are the entire
// implementation. There is nothing to sign up for and no vendor credential
// to configure — that is precisely what makes it airdrop-test compatible.
//
// STATUS.md's checklist text pointed at a Rust prototype in the OpenLine
// sibling repo (openline/src/suffrage/fuzzy-extractor/). This implementation
// does not wrap or FFI-bind that crate: cgo/FFI-bridging a separate
// language's crate into every one of this repo's plain-net-client Go
// modules would be a large, repo-wide dependency-shape change out of
// proportion to one method, and this session's working rules restrict work
// to the personhood repo itself. Instead this is a from-scratch, pure-Go
// implementation of the same fuzzy-extractor CONCEPT (Juels-Wattenberg fuzzy
// commitment — see extractor.go's doc comment for the construction), which
// keeps the method fully self-contained, dependency-free, and testable like
// every other method in this repo. See the wrapup for this session's
// decision record.
//
// Wire model:
//  1. BeginCeremony returns instructions (no server-side state needed yet —
//     unlike sms/app-attest-device there is no nonce to bind, because the
//     entire ceremony input arrives in one shot at CompleteCeremony).
//  2. The client captures a selfie, runs on-device liveness + face-embedding
//     extraction, binarizes the embedding to a fixed TemplateBytes-length
//     template, and POSTs it as base64.
//  3. CompleteCeremony decodes the template and asks the Accumulator whether
//     it duplicates an already-enrolled person (FindDuplicate, via the
//     fuzzy-extractor Rep operation against every stored helper-data
//     record). A duplicate means this biometric already has a Personhood
//     identity — reject as Sybil. Otherwise this is a new person: Gen
//     produces fresh helper data + a Commitment, both are stored in the
//     Accumulator, and the hex Commitment becomes this method's
//     AttestationDigest.
//
// nullifierBinding integration: src/server/did.go's
// NullifierBindingForBiometricCommitment derives the credential's
// nullifierBinding from this method's AttestationDigest when it is the
// credential's anchor, instead of (or in addition to) the holder's device
// keypair. That ties the nullifier to the PERSON (their biometric
// commitment) rather than to whichever device key they happened to generate
// for this session — the anti-Sybil property OpenLine's UBI claim/vote use
// cases need from an airdrop-test anchor. See src/server/handlers.go.
package fuzzyextractorselfie

import (
	"context"
	"encoding/base64"
	"errors"
	"fmt"
	"time"

	"github.com/sagearbor/personhood/pkg/types"
)

// methodPlugin mirrors registry.Method so this module stays independently
// compilable (see the same pattern in every other method package).
type methodPlugin interface {
	Metadata() types.MethodMetadata
	IsAvailableForUser(ctx types.UserContext) (available bool, reason string)
	BeginCeremony(ctx context.Context, cc types.CeremonyContext) (types.ChallengeData, error)
	CompleteCeremony(ctx context.Context, cc types.CeremonyContext, resp types.ResponseData) (types.MethodResult, error)
	HealthCheck(ctx context.Context) error
}

var _ methodPlugin = (*Method)(nil)

const (
	// MethodID is the stable plugin identifier, matching
	// docs/06-methods-catalog.md's `fuzzy-extractor-selfie` row.
	MethodID = "fuzzy-extractor-selfie"

	// MethodVersion tracks the plugin implementation version.
	MethodVersion = "0.1.0"

	// MethodStrength is the on-credential anchor point value. 70 per
	// docs/06-methods-catalog.md (well above the 50-point anchor floor).
	MethodStrength = 70

	// MethodCostUSD is the per-verification cost. On-device computation +
	// a local accumulator scan: free.
	MethodCostUSD = 0.00

	// MethodFreshnessLifetime mirrors the other anchors (government-id-
	// liveness, plaid-bank-link): 180 days.
	MethodFreshnessLifetime = 180 * 24 * time.Hour
)

// Method implements the Personhood fuzzy-extractor-selfie anchor method.
// Safe for concurrent use: all state lives in the injected Accumulator.
type Method struct {
	accumulator Accumulator
}

// Config bundles NewMethod's dependencies.
type Config struct {
	// Accumulator is required.
	Accumulator Accumulator
}

// NewMethod constructs a Method. A nil Accumulator is a programmer error and
// panics.
func NewMethod(cfg Config) *Method {
	if cfg.Accumulator == nil {
		panic("fuzzy-extractor-selfie.NewMethod: Accumulator must not be nil")
	}
	return &Method{accumulator: cfg.Accumulator}
}

// Metadata implements registry.Method.
func (m *Method) Metadata() types.MethodMetadata {
	return types.MethodMetadata{
		ID:                MethodID,
		Type:              types.MethodTypeAnchor,
		Strength:          MethodStrength,
		CostUSD:           MethodCostUSD,
		UXFriction:        types.FrictionMed,
		FreshnessLifetime: MethodFreshnessLifetime,
		Version:           MethodVersion,
	}
}

// IsAvailableForUser implements registry.Method. Selfie capture requires a
// camera but not any specific platform capability the UserContext reports
// (no document scanning, no bank account, no fixed address) — this is
// deliberately the most widely available anchor, per its airdrop-test
// design goal.
func (m *Method) IsAvailableForUser(_ types.UserContext) (bool, string) {
	return true, ""
}

// BeginCeremony implements registry.Method. No server-side state is needed
// before CompleteCeremony: the entire ceremony input (the binarized
// template) arrives in one shot, unlike the nonce-based ceremonies
// elsewhere in this repo.
func (m *Method) BeginCeremony(_ context.Context, cc types.CeremonyContext) (types.ChallengeData, error) {
	if cc.SessionID == "" {
		return types.ChallengeData{}, errors.New("fuzzy-extractor-selfie: CeremonyContext.SessionID is required")
	}
	return types.ChallengeData{
		Type: "fuzzy-extractor-challenge",
		Payload: map[string]any{
			"template_bytes":    TemplateBytes,
			"complete_endpoint": "/v1/methods/" + MethodID + "/complete",
			"instructions":      "Capture a selfie, run on-device liveness + face-embedding extraction, binarize to template_bytes bytes, and submit base64 as template_b64.",
		},
	}, nil
}

// CompleteCeremony implements registry.Method. It decodes the client-
// supplied template, checks the Accumulator for a duplicate enrollment
// (Sybil defense), and on success stores fresh helper data + Commitment.
//
// Accumulator errors (a Go error) are distinguished from "this template
// belongs to someone already enrolled" (Success: false with ErrorReason —
// an ordinary ceremony outcome, not a system failure), mirroring every other
// method in this repo.
func (m *Method) CompleteCeremony(ctx context.Context, cc types.CeremonyContext, resp types.ResponseData) (types.MethodResult, error) {
	if cc.SessionID == "" {
		return types.MethodResult{Success: false, MethodID: MethodID, ErrorReason: "missing_session_id"}, nil
	}

	templateB64, _ := stringField(resp.Payload, "template_b64")
	if templateB64 == "" {
		return types.MethodResult{Success: false, MethodID: MethodID, ErrorReason: "missing_template"}, nil
	}
	template, err := base64.StdEncoding.DecodeString(templateB64)
	if err != nil {
		return types.MethodResult{Success: false, MethodID: MethodID, ErrorReason: "invalid_template_encoding"}, nil
	}
	if len(template) != TemplateBytes {
		return types.MethodResult{Success: false, MethodID: MethodID, ErrorReason: fmt.Sprintf("invalid_template_length:want=%d,got=%d", TemplateBytes, len(template))}, nil
	}

	if _, found, err := m.accumulator.FindDuplicate(ctx, template); err != nil {
		return types.MethodResult{}, fmt.Errorf("fuzzy-extractor-selfie: accumulator lookup: %w", err)
	} else if found {
		return types.MethodResult{Success: false, MethodID: MethodID, ErrorReason: "duplicate_person_detected"}, nil
	}

	helper, commitment, err := Gen(template)
	if err != nil {
		return types.MethodResult{}, fmt.Errorf("fuzzy-extractor-selfie: gen: %w", err)
	}
	now := time.Now().UTC()
	if err := m.accumulator.Add(ctx, EnrollmentRecord{Helper: helper, Commitment: commitment, EnrolledAt: now}); err != nil {
		return types.MethodResult{}, fmt.Errorf("fuzzy-extractor-selfie: accumulator add: %w", err)
	}

	return types.MethodResult{
		Success:           true,
		MethodID:          MethodID,
		VerifiedAt:        now,
		AttestationDigest: commitment.Hex(),
	}, nil
}

// HealthCheck implements registry.Method. No external dependency to probe;
// the in-memory accumulator is local. v0.1 is a no-op success.
func (m *Method) HealthCheck(_ context.Context) error { return nil }

func stringField(m map[string]any, key string) (string, bool) {
	v, ok := m[key]
	if !ok {
		return "", false
	}
	s, ok := v.(string)
	return s, ok && s != ""
}
