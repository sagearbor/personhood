package server

import (
	"bytes"
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"math"
	"net/http"
	"testing"
	"time"

	fuzzyextractorselfie "github.com/sagearbor/personhood/src/methods/fuzzy-extractor-selfie"
)

// The native selfie on a test issuer with in-memory stores only (no
// Firestore, no Redis), with NO_FALSE_LOCKOUT on: a native face match gets
// the same routing as a web one (recover / not me / review), the same key
// re-enrols at once, and recovery starts from a native match.

type testKeyAttester struct{ key *ecdsa.PrivateKey }

func (a testKeyAttester) VerifyAttestedKey(context.Context, []string, []byte) (crypto.PublicKey, error) {
	return &a.key.PublicKey, nil
}

type nativeEnv struct {
	*lockoutEnv
	key *ecdsa.PrivateKey
}

func newNativeLockoutEnv(t *testing.T) *nativeEnv {
	t.Helper()
	t.Setenv("FIRESTORE_PROJECT_ID", "")
	t.Setenv("REDIS_URL", "")
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	env := &lockoutEnv{clock: &fakeClock{}}
	relay := &SelfieMatchRelay{}
	base, srv, email, _, cleanup := newTestServerWithDeps(t, func(c *Config) {
		c.HolderRevocation = true
		c.AdminToken = testAdminToken
		c.IdentifierHMACKey = bytes.Repeat([]byte{7}, 32)
		c.NoFalseLockout = true
		c.Lockout = LockoutConfig{RecoveryDelay: 72 * time.Hour}
	}, func(d *Dependencies) {
		web := fuzzyextractorselfie.NewMethod(fuzzyextractorselfie.Config{
			Accumulator: fuzzyextractorselfie.NewInMemoryAccumulator(),
			Liveness:    &fuzzyextractorselfie.LivenessConfig{Key: bytes.Repeat([]byte{9}, 32), Now: env.clock.now},
			Strength:    SelfieAnchorStrength,
			OnMatch:     relay.OnMatch,
		})
		if err := d.Registry.Register(web); err != nil {
			t.Fatal(err)
		}
		native := fuzzyextractorselfie.NewNativeMethod(fuzzyextractorselfie.NativeConfig{Web: web, Attester: testKeyAttester{key}, Logf: t.Logf})
		if err := d.Registry.Register(native); err != nil {
			t.Fatal(err)
		}
		d.SelfieMatches = relay
	})
	t.Cleanup(cleanup)
	srv.SetNowFunc(env.clock.now)
	env.base, env.srv, env.email = base, srv, email
	return &nativeEnv{lockoutEnv: env, key: key}
}

// syntheticTrace: a hand sweep whose background shift follows the gyro
// exactly and whose face, nearer, moves 40% more (parallax).
func syntheticTrace() fuzzyextractorselfie.NativeTrace {
	const f = 500.0
	angle := func(t float64) float64 { // rad, about the device y axis
		if t < 2000 || t > 5000 {
			return 0
		}
		return 0.2 * math.Sin(2*math.Pi*(t-2000)/1500) * math.Pow(math.Sin(math.Pi*(t-2000)/3000), 2)
	}
	tr := fuzzyextractorselfie.NativeTrace{
		Device: fuzzyextractorselfie.NativeDevice{Model: "test", SDK: 36, Gyro: true, Clock: "realtime", FocalPx: f, Width: 480, Height: 640},
		Sweep:  [2]float64{2000, 5000},
	}
	for t := 0.0; t <= 8000; t += 5 {
		w := (angle(t+0.5) - angle(t-0.5)) * 1000
		tr.IMU = append(tr.IMU, []float64{t, 0, w, 0, 0, 9.81, 0})
	}
	prev := 0.0
	for t := 0.0; t <= 8000; t += 33.3 {
		a := angle(t)
		tr.Frames = append(tr.Frames, []float64{t, 240 + f*a*1.4, 300, 200, f * (a - prev), 0, 0.7, 180, 130, 110, 120, 115, 105})
		prev = a
	}
	tr.Flash = []float64{5300, 5600, 5900, 6200, 6500, 6800, 7100, 7400, 7700}
	return tr
}

// nativeSelfie runs begin + complete for e with face, signing like the wallet.
func (env *nativeEnv) nativeSelfie(t *testing.T, e enrollee, face []byte) map[string]any {
	t.Helper()
	path := env.base + "/v1/methods/" + fuzzyextractorselfie.NativeMethodID
	st, begin := do(t, http.MethodPost, path+"/begin", map[string]any{"session_id": e.session.SessionID}, nil)
	if st != 200 {
		t.Fatalf("native begin: %d %v", st, begin)
	}
	p := begin["challenge"].(map[string]any)["payload"].(map[string]any)
	ev := fuzzyextractorselfie.LivenessEvidence{Frames: 6}
	for _, k := range p["challenges"].([]any) {
		ev.Challenges = append(ev.Challenges, fuzzyextractorselfie.ChallengeResult{Kind: k.(string), MS: 900})
	}
	sum := fuzzyextractorselfie.NativeSummary{
		Version:         fuzzyextractorselfie.NativeSummaryVersion,
		SessionID:       e.session.SessionID,
		ChallengeToken:  p["challenge_token"].(string),
		TemplateB64:     base64.StdEncoding.EncodeToString(face),
		TemplateVersion: fuzzyextractorselfie.DefaultTemplateVersion,
		Liveness:        ev,
		Trace:           syntheticTrace(),
	}
	raw, _ := json.Marshal(sum)
	digest := sha256.Sum256(raw)
	sig, err := ecdsa.SignASN1(rand.Reader, env.key, digest[:])
	if err != nil {
		t.Fatal(err)
	}
	env.clock.advance(12 * time.Second)
	st, out := do(t, http.MethodPost, path+"/complete", map[string]any{
		"session_id": e.session.SessionID,
		"response": map[string]any{"type": "fuzzy-extractor-response", "payload": map[string]any{
			"template_b64": sum.TemplateB64, "template_version": sum.TemplateVersion,
			"challenge_token": sum.ChallengeToken, "liveness": ev,
			"native": map[string]any{
				"summary_b64":       base64.StdEncoding.EncodeToString(raw),
				"signature_b64":     base64.StdEncoding.EncodeToString(sig),
				"certificate_chain": []string{"leaf", "root"},
			},
		}},
	}, nil)
	if st != 200 {
		t.Fatalf("native complete: %d %v", st, out)
	}
	return out
}

func TestNativeSelfie_InMemory_FaceMatchRouting(t *testing.T) {
	env := newNativeLockoutEnv(t)
	face := fuzzyextractorselfie.RandomTemplateForTesting()

	// Ann enrols natively (email + native selfie) on an in-memory issuer.
	ann := env.person(t)
	env.verifyEmail(t, ann, "ann@example.com")
	out := env.nativeSelfie(t, ann, face)
	if ok, reason := resultOf(out); !ok {
		t.Fatalf("native enrol: %s %v", reason, out)
	}
	aCred := env.mustIssue(t, ann)
	if aCred.CredentialSubject.NullifierBinding == nil {
		t.Fatal("native-anchored credential has no nullifier")
	}

	// Same key, same face, new session: re-issued at once, same nullifier.
	again := env.again(t, ann)
	if ok, reason := resultOf(env.nativeSelfie(t, again, fuzzyextractorselfie.NoisyTemplateForTesting(face, 3))); !ok {
		t.Fatalf("same key re-enrol: %s", reason)
	}
	if c := env.mustIssue(t, again); nullifierOf(c) != nullifierOf(aCred) {
		t.Fatal("same key re-enrol changed the nullifier")
	}

	// A new key with the same face (a new phone, or a twin): routed, not refused.
	other := env.person(t)
	out = env.nativeSelfie(t, other, fuzzyextractorselfie.NoisyTemplateForTesting(face, 5))
	ok, reason := resultOf(out)
	acts := faceMatchActions(out)
	if ok || reason != fuzzyextractorselfie.ReasonDuplicate || !containsStr(acts, "recover") || !containsStr(acts, "other_anchor") {
		t.Fatalf("native face match: ok=%v reason=%s actions=%v", ok, reason, acts)
	}
	// The web selfie of the same face routes the same way (one dedupe system).
	webOut := env.selfie(t, env.person(t), fuzzyextractorselfie.NoisyTemplateForTesting(face, 4))
	if ok, _ := resultOf(webOut); ok {
		t.Fatalf("web selfie of a native-enrolled face: %v", webOut)
	}

	// "This is me on a new phone": recovery starts from the native match.
	env.verifyEmail(t, other, "ann@example.com")
	if st, rec := env.startRecovery(t, other); st != 200 || rec["status"] != RecoveryPending {
		t.Fatalf("recovery from a native match: %d %v", st, rec)
	}
}

func containsStr(xs []string, x string) bool {
	for _, s := range xs {
		if s == x {
			return true
		}
	}
	return false
}
