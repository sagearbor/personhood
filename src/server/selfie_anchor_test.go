package server

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"net/http"
	"sync/atomic"
	"testing"
	"time"

	"github.com/sagearbor/personhood/pkg/types"
	fuzzyextractorselfie "github.com/sagearbor/personhood/src/methods/fuzzy-extractor-selfie"
	"github.com/sagearbor/personhood/src/registry"
)

func TestBuildDependencies_SelfieAnchor(t *testing.T) {
	t.Setenv("SELFIE_ANCHOR", "1")
	t.Setenv("FIRESTORE_PROJECT_ID", "")
	t.Setenv("REDIS_URL", "")
	deps, err := BuildDependencies("http://example.invalid/v1/methods/email/verify", "")
	if err != nil {
		t.Fatalf("BuildDependencies: %v", err)
	}
	m, ok := deps.Registry.Get(fuzzyextractorselfie.MethodID)
	if !ok {
		t.Fatal("fuzzy-extractor-selfie not registered with SELFIE_ANCHOR=1")
	}
	if md := m.Metadata(); md.Strength != SelfieAnchorStrength || md.Type != types.MethodTypeAnchor {
		t.Fatalf("metadata = %+v, want anchor strength %d", md, SelfieAnchorStrength)
	}
	ch, err := m.BeginCeremony(context.Background(), types.CeremonyContext{SessionID: "s"})
	if err != nil {
		t.Fatalf("BeginCeremony: %v", err)
	}
	if ch.Payload["liveness"] != "active-v1" || ch.Payload["challenge_token"] == nil {
		t.Fatalf("SELFIE_ANCHOR begin payload has no liveness challenge: %+v", ch.Payload)
	}
}

func TestBuildDependencies_SelfieAnchorAndLegacyFlagExclusive(t *testing.T) {
	t.Setenv("SELFIE_ANCHOR", "1")
	t.Setenv("FUZZY_EXTRACTOR_ENABLED", "1")
	if _, err := BuildDependencies("http://example.invalid/v1/methods/email/verify", ""); err == nil {
		t.Fatal("BuildDependencies with both selfie flags: want error")
	}
}

func TestBuildDependencies_SelfieAnchorOnlyWhenExactlyOne(t *testing.T) {
	t.Setenv("SELFIE_ANCHOR", "true")
	deps, err := BuildDependencies("http://example.invalid/v1/methods/email/verify", "")
	if err != nil {
		t.Fatalf("BuildDependencies: %v", err)
	}
	if _, ok := deps.Registry.Get(fuzzyextractorselfie.MethodID); ok {
		t.Fatal("SELFIE_ANCHOR=true registered the method; only \"1\" turns it on")
	}
}

// TestIntegration_SelfieAnchor_EndToEnd drives the SELFIE_ANCHOR ceremony
// through the HTTP API: begin hands out challenges, complete with matching
// evidence verifies, the credential's nullifier comes from the face, and a
// second enrollment of the same face is refused.
func TestIntegration_SelfieAnchor_EndToEnd(t *testing.T) {
	var offset atomic.Int64 // simulated ceremony time, ns
	now := func() time.Time { return time.Now().Add(time.Duration(offset.Load())) }

	reg := registry.New()
	if err := reg.Register(fuzzyextractorselfie.NewMethod(fuzzyextractorselfie.Config{
		Accumulator: fuzzyextractorselfie.NewInMemoryAccumulator(),
		Liveness:    &fuzzyextractorselfie.LivenessConfig{Key: make([]byte, 32), Now: now},
		Strength:    SelfieAnchorStrength,
	})); err != nil {
		t.Fatal(err)
	}
	listener, err := newLocalListener()
	if err != nil {
		t.Fatal(err)
	}
	_, priv, _ := ed25519.GenerateKey(rand.Reader)
	srv, err := NewServer(Config{
		Addr:             listener.Addr().String(),
		PublicURL:        "http://" + listener.Addr().String(),
		IssuerPrivateKey: priv,
		SessionTTL:       10 * time.Minute,
	}, Dependencies{Registry: reg})
	if err != nil {
		t.Fatal(err)
	}
	httpServer := &http.Server{Handler: srv.Router()}
	go func() { _ = httpServer.Serve(listener) }()
	defer httpServer.Close()
	base := "http://" + listener.Addr().String()

	face := fuzzyextractorselfie.RandomTemplateForTesting()
	enroll := func(template []byte) (string, types.MethodResult) {
		var start startEnrollmentResponse
		mustPOST(t, base+"/enrollment/start", mustJSON(t, map[string]any{}), &start)
		var begin beginMethodResponse
		mustPOST(t, base+"/v1/methods/"+fuzzyextractorselfie.MethodID+"/begin", mustJSON(t, map[string]any{"session_id": start.SessionID}), &begin)
		kinds, _ := begin.Challenge.Payload["challenges"].([]any)
		if len(kinds) != fuzzyextractorselfie.ChallengeCount {
			t.Fatalf("begin challenges = %v", begin.Challenge.Payload["challenges"])
		}
		answers := make([]map[string]any, len(kinds))
		for i, k := range kinds {
			answers[i] = map[string]any{"kind": k, "ms": 900}
		}
		offset.Add(int64(10 * time.Second))
		var complete completeMethodResponse
		mustPOST(t, base+"/v1/methods/"+fuzzyextractorselfie.MethodID+"/complete", mustJSON(t, map[string]any{
			"session_id": start.SessionID,
			"response": types.ResponseData{Type: "fuzzy-extractor-response", Payload: map[string]any{
				"template_b64":     base64.StdEncoding.EncodeToString(template),
				"template_version": fuzzyextractorselfie.DefaultTemplateVersion,
				"challenge_token":  begin.Challenge.Payload["challenge_token"],
				"liveness":         map[string]any{"challenges": answers, "frames": 6, "parallax": []float64{0.08}},
			}},
		}), &complete)
		return start.SessionID, complete.Result
	}

	session, res := enroll(face)
	if !res.Success {
		t.Fatalf("first enrollment: %s", res.ErrorReason)
	}
	var issued issueCredentialResponse
	mustPOST(t, base+"/v1/credentials/issue", mustJSON(t, map[string]any{"session_id": session}), &issued)
	subj := issued.Credential.CredentialSubject
	if subj.AnchorMethodID == nil || *subj.AnchorMethodID != fuzzyextractorselfie.MethodID {
		t.Fatalf("anchor = %v", subj.AnchorMethodID)
	}
	if subj.NullifierBinding == nil || subj.NullifierBinding.Commitment != NullifierBindingForBiometricCommitment(res.AttestationDigest).Commitment {
		t.Fatalf("nullifierBinding not derived from the face commitment: %+v", subj.NullifierBinding)
	}

	if _, res := enroll(fuzzyextractorselfie.NoisyTemplateForTesting(face, 25)); res.Success || res.ErrorReason != "duplicate_person_detected" {
		t.Fatalf("same face again: %+v, want duplicate_person_detected", res)
	}
	if _, res := enroll(fuzzyextractorselfie.RandomTemplateForTesting()); !res.Success {
		t.Fatalf("different face: %s", res.ErrorReason)
	}
}

// accumulatorContract checks any Accumulator: a face matches itself with
// noise, a different face does not, Count counts.
func accumulatorContract(t *testing.T, acc fuzzyextractorselfie.Accumulator) {
	t.Helper()
	ctx := context.Background()
	before, err := acc.Count(ctx)
	if err != nil {
		t.Fatalf("Count: %v", err)
	}
	face := fuzzyextractorselfie.RandomTemplateForTesting()
	if _, found, err := acc.FindDuplicate(ctx, face); err != nil || found {
		t.Fatalf("FindDuplicate before Add = %v, %v", found, err)
	}
	helper, commitment, err := fuzzyextractorselfie.Gen(face)
	if err != nil {
		t.Fatal(err)
	}
	if err := acc.Add(ctx, fuzzyextractorselfie.EnrollmentRecord{Helper: helper, Commitment: commitment, EnrolledAt: time.Now().UTC()}); err != nil {
		t.Fatalf("Add: %v", err)
	}
	rec, found, err := acc.FindDuplicate(ctx, fuzzyextractorselfie.NoisyTemplateForTesting(face, 20))
	if err != nil || !found || rec.Commitment != commitment {
		t.Fatalf("FindDuplicate(noisy same face) = %v, %v (commitment match %v)", found, err, rec.Commitment == commitment)
	}
	if _, found, err := acc.FindDuplicate(ctx, fuzzyextractorselfie.RandomTemplateForTesting()); err != nil || found {
		t.Fatalf("FindDuplicate(other face) = %v, %v", found, err)
	}
	if after, err := acc.Count(ctx); err != nil || after != before+1 {
		t.Fatalf("Count after Add = %d, %v; want %d", after, err, before+1)
	}
}

func TestSelfieAccumulator_InMemory(t *testing.T) {
	accumulatorContract(t, fuzzyextractorselfie.NewInMemoryAccumulator())
}

func TestSelfieAccumulator_Redis(t *testing.T) {
	accumulatorContract(t, NewRedisSelfieAccumulator(redisTestClient(t)))
}

func TestSelfieAccumulator_Firestore(t *testing.T) {
	accumulatorContract(t, NewFirestoreSelfieAccumulator(firestoreTestClient(t)))
}

func TestSelfieRecordRoundTrip(t *testing.T) {
	helper, commitment, err := fuzzyextractorselfie.Gen(fuzzyextractorselfie.RandomTemplateForTesting())
	if err != nil {
		t.Fatal(err)
	}
	in := fuzzyextractorselfie.EnrollmentRecord{Helper: helper, Commitment: commitment, EnrolledAt: time.Date(2026, 11, 3, 0, 0, 0, 0, time.UTC)}
	b, err := encodeSelfieRecord(in)
	if err != nil {
		t.Fatal(err)
	}
	out, err := decodeSelfieRecord(b)
	if err != nil || out.Commitment != in.Commitment || string(out.Helper) != string(in.Helper) || !out.EnrolledAt.Equal(in.EnrolledAt) {
		t.Fatalf("round trip = %+v, %v", out, err)
	}
	if _, err := decodeSelfieRecord([]byte(`{"helper":"AA==","commitment":"zz"}`)); err == nil {
		t.Fatal("corrupt commitment decoded without error")
	}
}
