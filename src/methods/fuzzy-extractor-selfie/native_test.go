package fuzzyextractorselfie

import (
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	mrand "math/rand"
	"sync/atomic"
	"testing"
	"time"

	"github.com/sagearbor/personhood/pkg/types"
)

// fakeAttester stands in for Android Key Attestation: it "attests" one
// ECDSA key and checks the challenge it was asked about.
type fakeAttester struct {
	key       *ecdsa.PrivateKey
	refuse    string
	challenge []byte
}

func (f *fakeAttester) VerifyAttestedKey(_ context.Context, chain []string, challenge []byte) (crypto.PublicKey, error) {
	f.challenge = challenge
	if f.refuse != "" {
		return nil, &AttestationError{Reason: f.refuse}
	}
	if len(chain) != 2 {
		return nil, &AttestationError{Reason: "attestation_malformed"}
	}
	return &f.key.PublicKey, nil
}

type nativeFixture struct {
	web    *Method
	native *NativeMethod
	att    *fakeAttester
	offset *atomic.Int64
}

func newNativeFixture(t *testing.T) *nativeFixture {
	t.Helper()
	var offset atomic.Int64
	now := func() time.Time { return time.Now().Add(time.Duration(offset.Load())) }
	web := NewMethod(Config{
		Accumulator: NewInMemoryAccumulator(),
		Liveness:    &LivenessConfig{Key: []byte("0123456789abcdef0123456789abcdef"), Now: now},
		Strength:    50,
	})
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	att := &fakeAttester{key: key}
	return &nativeFixture{web: web, native: NewNativeMethod(NativeConfig{Web: web, Attester: att, Logf: t.Logf}), att: att, offset: &offset}
}

// ceremony runs begin, simulates the capture and returns the complete
// payload as the wallet would send it.
func (f *nativeFixture) ceremony(t *testing.T, session string, template []byte, mutate func(*NativeSummary)) (map[string]any, types.ChallengeData) {
	t.Helper()
	ch, err := f.native.BeginCeremony(context.Background(), types.CeremonyContext{SessionID: session})
	if err != nil {
		t.Fatal(err)
	}
	p := ch.Payload
	token := p["challenge_token"].(string)
	kinds := p["challenges"].([]string)
	var colours []int
	for _, name := range p["flash_colors"].([]string) {
		for i, n := range FlashColourNames {
			if n == name {
				colours = append(colours, i)
			}
		}
	}
	o := honestOpts(mrand.New(mrand.NewSource(7)), 7)
	o.bgTexture, o.flashAmp, o.flashBgAmp, o.lever = 0.6, 0.02, 0.002, 0.25
	ev := LivenessEvidence{Frames: 6, Parallax: []float64{0.3}}
	for _, k := range kinds {
		ev.Challenges = append(ev.Challenges, ChallengeResult{Kind: k, MS: 900})
	}
	sum := NativeSummary{
		Version:         NativeSummaryVersion,
		SessionID:       session,
		ChallengeToken:  token,
		TemplateB64:     base64.StdEncoding.EncodeToString(template),
		TemplateVersion: DefaultTemplateVersion,
		Liveness:        ev,
		Trace:           simulate(o, colours),
	}
	if mutate != nil {
		mutate(&sum)
	}
	raw, _ := json.Marshal(sum)
	digest := sha256.Sum256(raw)
	sig, err := ecdsa.SignASN1(rand.Reader, f.att.key, digest[:])
	if err != nil {
		t.Fatal(err)
	}
	f.offset.Add(int64(12 * time.Second)) // the ceremony took 12 s
	payload := map[string]any{
		// The web fields too, so the client can fall back unchanged.
		"template_b64":     sum.TemplateB64,
		"template_version": sum.TemplateVersion,
		"challenge_token":  token,
		"liveness":         ev,
		"native": map[string]any{
			"summary_b64":       base64.StdEncoding.EncodeToString(raw),
			"signature_b64":     base64.StdEncoding.EncodeToString(sig),
			"certificate_chain": []any{"leaf", "root"},
		},
	}
	// Round-trip through JSON, as the HTTP server does.
	b, _ := json.Marshal(payload)
	var wire map[string]any
	_ = json.Unmarshal(b, &wire)
	return wire, ch
}

func (f *nativeFixture) complete(t *testing.T, m interface {
	CompleteCeremony(context.Context, types.CeremonyContext, types.ResponseData) (types.MethodResult, error)
}, session string, payload map[string]any) types.MethodResult {
	t.Helper()
	res, err := m.CompleteCeremony(context.Background(), types.CeremonyContext{SessionID: session}, types.ResponseData{Payload: payload})
	if err != nil {
		t.Fatal(err)
	}
	return res
}

func TestNative_EnrollsAtHigherStrengthAndSharesDedupe(t *testing.T) {
	f := newNativeFixture(t)
	if md := f.native.Metadata(); md.ID != NativeMethodID || md.Strength != NativeMethodStrength || md.Type != types.MethodTypeAnchor || md.Strength <= f.web.Metadata().Strength {
		t.Fatalf("metadata %+v", md)
	}
	if err := f.native.Metadata().Validate(); err != nil {
		t.Fatal(err)
	}
	tpl := RandomTemplateForTesting()
	payload, ch := f.ceremony(t, "s1", tpl, nil)
	if got := hex.EncodeToString(attestationChallenge("s1", ch.Payload["challenge_token"].(string))); got != ch.Payload["attestation_challenge"] {
		t.Fatalf("begin advertised challenge %v, want %s", ch.Payload["attestation_challenge"], got)
	}
	res := f.complete(t, f.native, "s1", payload)
	if !res.Success || res.MethodID != NativeMethodID || res.AttestationDigest == "" {
		t.Fatalf("native complete: %+v", res)
	}
	if hex.EncodeToString(f.att.challenge) != ch.Payload["attestation_challenge"] {
		t.Fatal("attester was not asked about this session's challenge")
	}
	// The same face through the web ceremony is the same person.
	webCh, _ := f.web.BeginCeremony(context.Background(), types.CeremonyContext{SessionID: "s2"})
	f.offset.Add(int64(5 * time.Second))
	var ev LivenessEvidence
	for _, k := range webCh.Payload["challenges"].([]string) {
		ev.Challenges = append(ev.Challenges, ChallengeResult{Kind: k, MS: 800})
	}
	again := f.complete(t, f.web, "s2", map[string]any{
		"template_b64": base64.StdEncoding.EncodeToString(NoisyTemplateForTesting(tpl, 3)), "template_version": DefaultTemplateVersion,
		"challenge_token": webCh.Payload["challenge_token"], "liveness": ev,
	})
	if again.Success || again.ErrorReason != "duplicate_person_detected" {
		t.Fatalf("web re-enrol of a native face: %+v", again)
	}
}

func TestNative_FailuresFallBackToWebStrength(t *testing.T) {
	cases := map[string]struct {
		mutate func(*NativeSummary)
		prep   func(*nativeFixture, map[string]any)
		reason string
	}{
		"attestation refused": {prep: func(f *nativeFixture, _ map[string]any) { f.att.refuse = "attestation_device_unlocked" }, reason: "attestation_device_unlocked"},
		"signature over other bytes": {prep: func(_ *nativeFixture, p map[string]any) {
			nat := p["native"].(map[string]any)
			raw, _ := base64.StdEncoding.DecodeString(nat["summary_b64"].(string))
			raw = append(raw, ' ')
			nat["summary_b64"] = base64.StdEncoding.EncodeToString(raw)
		}, reason: "native_signature_invalid"},
		"video not from this motion": {mutate: func(s *NativeSummary) {
			other := simulate(honestOpts(mrand.New(mrand.NewSource(77)), 77), nil)
			s.Trace.IMU = other.IMU
		}, reason: "native_motion_inconsistent"},
		"no gyro": {mutate: func(s *NativeSummary) { s.Trace.Device.Gyro = false }, reason: "native_no_gyro"},
	}
	for name, tc := range cases {
		t.Run(name, func(t *testing.T) {
			f := newNativeFixture(t)
			payload, _ := f.ceremony(t, "s", RandomTemplateForTesting(), tc.mutate)
			if tc.prep != nil {
				tc.prep(f, payload)
			}
			res := f.complete(t, f.native, "s", payload)
			if res.Success || res.ErrorReason != tc.reason || !IsNativeFallbackReason(res.ErrorReason) {
				t.Fatalf("native: %+v, want fallback reason %s", res, tc.reason)
			}
			// Same payload to the web method: enrolled at web strength.
			web := f.complete(t, f.web, "s", payload)
			if !web.Success || web.MethodID != MethodID {
				t.Fatalf("web fallback: %+v", web)
			}
		})
	}
}

func TestNative_RefusesWrongSessionAndMissingEvidence(t *testing.T) {
	f := newNativeFixture(t)
	payload, _ := f.ceremony(t, "s1", RandomTemplateForTesting(), nil)
	if res := f.complete(t, f.native, "other", payload); res.ErrorReason != "native_summary_mismatch" {
		t.Fatalf("other session: %+v", res)
	}
	delete(payload, "native")
	if res := f.complete(t, f.native, "s1", payload); res.ErrorReason != "native_evidence_missing" {
		t.Fatalf("no native evidence: %+v", res)
	}
	if IsNativeFallbackReason("duplicate_person_detected") || IsNativeFallbackReason("liveness_too_fast") {
		t.Fatal("web-ceremony reasons must not fall back")
	}
}

func TestNative_LivenessChecksStillApply(t *testing.T) {
	f := newNativeFixture(t)
	payload, _ := f.ceremony(t, "s1", RandomTemplateForTesting(), func(s *NativeSummary) {
		s.Liveness.Challenges[0].MS = 10 // faster than a person
	})
	if res := f.complete(t, f.native, "s1", payload); res.ErrorReason != "liveness_timing_implausible" {
		t.Fatalf("too fast: %+v", res)
	}
}

func TestNative_NotOfferedToWeb(t *testing.T) {
	f := newNativeFixture(t)
	if ok, _ := f.native.IsAvailableForUser(types.UserContext{Platform: "web"}); ok {
		t.Fatal("native method offered to the web app")
	}
	if ok, _ := f.native.IsAvailableForUser(types.UserContext{Platform: "openline-wallet"}); !ok {
		t.Fatal("native method not offered to the wallet")
	}
}

func TestFlashColours_DeterministicAndAlternating(t *testing.T) {
	lc := &LivenessConfig{Key: make([]byte, 32)}
	a, b := lc.flashColours("t1", 8), lc.flashColours("t1", 8)
	if !equalInts(a, b) {
		t.Fatal("not deterministic")
	}
	for i := 1; i < len(a); i++ {
		if a[i] == a[i-1] || a[i] < 0 || a[i] > 2 {
			t.Fatalf("sequence %v", a)
		}
	}
	if equalInts(a, lc.flashColours("t2", 8)) && equalInts(a, lc.flashColours("t3", 8)) {
		t.Fatal("sequence does not depend on the token")
	}
}
