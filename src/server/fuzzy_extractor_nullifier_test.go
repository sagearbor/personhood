package server

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"net/http"
	"testing"
	"time"

	"github.com/sagearbor/personhood/pkg/types"
	fuzzyextractorselfie "github.com/sagearbor/personhood/src/methods/fuzzy-extractor-selfie"
	"github.com/sagearbor/personhood/src/registry"
)

// newFuzzyExtractorTestServer builds a test server whose registry holds
// ONLY fuzzy-extractor-selfie, so a session that completes it has that
// method as its sole (and therefore anchor) verified method.
func newFuzzyExtractorTestServer(t *testing.T) (string, func()) {
	t.Helper()
	reg := registry.New()
	fuzzy := fuzzyextractorselfie.NewMethod(fuzzyextractorselfie.Config{
		Accumulator: fuzzyextractorselfie.NewInMemoryAccumulator(),
	})
	if err := reg.Register(fuzzy); err != nil {
		t.Fatalf("register fuzzy-extractor-selfie: %v", err)
	}

	listener, err := newLocalListener()
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	publicURL := "http://" + listener.Addr().String()

	_, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("gen key: %v", err)
	}
	cfg := Config{
		Addr:               listener.Addr().String(),
		PublicURL:          publicURL,
		IssuerPrivateKey:   priv,
		CORSAllowedOrigins: []string{"http://localhost:3000"},
		SessionTTL:         10 * time.Minute,
	}
	srv, err := NewServer(cfg, Dependencies{Registry: reg})
	if err != nil {
		t.Fatalf("new server: %v", err)
	}
	httpServer := &http.Server{Handler: srv.Router()}
	go func() { _ = httpServer.Serve(listener) }()
	cleanup := func() {
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		_ = httpServer.Shutdown(ctx)
	}
	return publicURL, cleanup
}

// TestIntegration_FuzzyExtractorAnchor_NullifierBindingPrefersBiometric
// drives a full HTTP enrollment through the fuzzy-extractor-selfie anchor —
// WITH a client-supplied holder Ed25519 key present too — and proves the
// issued credential's nullifierBinding is derived from the biometric
// AttestationDigest (NullifierBindingForBiometricCommitment), not the
// holder device key (NullifierBindingForHolder), per handlers.go's stated
// precedence.
func TestIntegration_FuzzyExtractorAnchor_NullifierBindingPrefersBiometric(t *testing.T) {
	base, cleanup := newFuzzyExtractorTestServer(t)
	defer cleanup()

	holderPub, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("gen holder key: %v", err)
	}

	var start startEnrollmentResponse
	mustPOST(t, base+"/enrollment/start", mustJSON(t, map[string]any{
		"holder_public_key_b64": base64.StdEncoding.EncodeToString(holderPub),
	}), &start)
	if start.SessionID == "" {
		t.Fatal("session_id is empty")
	}

	var beginResp beginMethodResponse
	mustPOST(t, base+"/v1/methods/"+fuzzyextractorselfie.MethodID+"/begin", mustJSON(t, map[string]any{
		"session_id": start.SessionID,
	}), &beginResp)
	if beginResp.Challenge.Type != "fuzzy-extractor-challenge" {
		t.Fatalf("challenge type = %q", beginResp.Challenge.Type)
	}

	template := fuzzyextractorselfie.RandomTemplateForTesting()
	var completeResp completeMethodResponse
	mustPOST(t, base+"/v1/methods/"+fuzzyextractorselfie.MethodID+"/complete", mustJSON(t, map[string]any{
		"session_id": start.SessionID,
		"response": types.ResponseData{
			Type:    "fuzzy-extractor-response",
			Payload: map[string]any{"template_b64": base64.StdEncoding.EncodeToString(template)},
		},
	}), &completeResp)
	if !completeResp.Result.Success {
		t.Fatalf("complete ceremony failed: %s", completeResp.Result.ErrorReason)
	}
	bioDigest := completeResp.Result.AttestationDigest
	if bioDigest == "" {
		t.Fatal("AttestationDigest is empty")
	}

	var issued issueCredentialResponse
	mustPOST(t, base+"/v1/credentials/issue", mustJSON(t, map[string]any{"session_id": start.SessionID}), &issued)
	cred := issued.Credential

	if cred.CredentialSubject.AnchorMethodID == nil || *cred.CredentialSubject.AnchorMethodID != fuzzyextractorselfie.MethodID {
		t.Fatalf("AnchorMethodID = %v, want %q", cred.CredentialSubject.AnchorMethodID, fuzzyextractorselfie.MethodID)
	}
	if cred.CredentialSubject.NullifierBinding == nil {
		t.Fatal("issued credential has no nullifierBinding")
	}

	wantBinding := NullifierBindingForBiometricCommitment(bioDigest)
	if cred.CredentialSubject.NullifierBinding.Commitment != wantBinding.Commitment {
		t.Errorf("nullifierBinding.Commitment = %q, want the biometric-derived %q",
			cred.CredentialSubject.NullifierBinding.Commitment, wantBinding.Commitment)
	}

	holderDerived := NullifierBindingForHolder(holderPub)
	if cred.CredentialSubject.NullifierBinding.Commitment == holderDerived.Commitment {
		t.Error("nullifierBinding matched the holder-key derivation instead of the biometric one — precedence is wrong")
	}
}

// TestIntegration_FuzzyExtractorAnchor_DuplicateBiometricRejectedAcrossSessions
// proves the accumulator's Sybil defense holds through the real HTTP API: a
// second, independent session presenting the same (noisily re-read)
// biometric cannot also complete the ceremony.
func TestIntegration_FuzzyExtractorAnchor_DuplicateBiometricRejectedAcrossSessions(t *testing.T) {
	base, cleanup := newFuzzyExtractorTestServer(t)
	defer cleanup()

	template := fuzzyextractorselfie.RandomTemplateForTesting()

	completeSession := func(templateForThisSession []byte) types.MethodResult {
		var start startEnrollmentResponse
		mustPOST(t, base+"/enrollment/start", mustJSON(t, map[string]any{}), &start)

		var beginResp beginMethodResponse
		mustPOST(t, base+"/v1/methods/"+fuzzyextractorselfie.MethodID+"/begin", mustJSON(t, map[string]any{
			"session_id": start.SessionID,
		}), &beginResp)

		var completeResp completeMethodResponse
		mustPOST(t, base+"/v1/methods/"+fuzzyextractorselfie.MethodID+"/complete", mustJSON(t, map[string]any{
			"session_id": start.SessionID,
			"response": types.ResponseData{
				Type:    "fuzzy-extractor-response",
				Payload: map[string]any{"template_b64": base64.StdEncoding.EncodeToString(templateForThisSession)},
			},
		}), &completeResp)
		return completeResp.Result
	}

	first := completeSession(template)
	if !first.Success {
		t.Fatalf("first session: expected success, got %s", first.ErrorReason)
	}

	noisy := fuzzyextractorselfie.NoisyTemplateForTesting(template, 5)
	second := completeSession(noisy)
	if second.Success {
		t.Fatal("second session with the same (noisy) biometric: expected rejection, got success")
	}
	if second.ErrorReason != "duplicate_person_detected" {
		t.Errorf("ErrorReason = %q, want duplicate_person_detected", second.ErrorReason)
	}
}
