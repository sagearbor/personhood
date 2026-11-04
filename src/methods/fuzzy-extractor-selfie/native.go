package fuzzyextractorselfie

// The native selfie ceremony: "fuzzy-extractor-selfie-native" (SELFIE_NATIVE=1
// on the reference server, on top of SELFIE_ANCHOR=1).
//
// It is the same face, the same template format and the same accumulator as
// the web ceremony (one dedupe system), run by the native Android wallet
// instead of a browser, with three additions the browser cannot make:
//
//  1. Device attestation bound to the result. BeginCeremony derives an
//     attestation challenge from the session and the challenge token. The
//     app makes a fresh Android Keystore key with that challenge, signs the
//     whole ceremony summary with it, and sends the key's certificate chain.
//     The issuer verifies the chain (genuine phone, locked bootloader,
//     verified boot, this app's package and signer: app-attest-device's
//     verifier) and the signature over the summary. So the template, the
//     challenge results and the sensor trace below were produced by the
//     real app on a real phone during this session, not typed in by a
//     script or an emulator.
//  2. A sensor trace that the issuer checks itself (motion.go): camera
//     motion must agree with the gyroscope, the face must sit at a
//     different depth from the background, and the face must reflect the
//     screen's issuer-chosen colour sequence.
//  3. Nothing else: no extra biometric data leaves the phone. The trace is
//     face position, size and mean colour per frame, not images.
//
// A failure in any native-only check (reasons starting "native_" or
// "attestation_") is not a refusal of the person: the client resubmits the
// same template, token and liveness evidence to the web method, which
// accepts the token (both methods share one LivenessConfig) and enrolls at
// the web strength. A phone without a gyroscope or without key attestation
// goes to the web method directly. docs/selfie-anchor.md has the strength
// reasoning and what this still does not prove.

import (
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"strings"

	"github.com/sagearbor/personhood/pkg/types"
)

const (
	// NativeMethodID is the native ceremony's plugin id.
	NativeMethodID = "fuzzy-extractor-selfie-native"

	// NativeMethodStrength: see docs/selfie-anchor.md, "Recommended
	// strength". Device attestation moves the cheapest attack from a
	// script (free) to a real, locked phone per identity, and the sensor
	// checks make a replayed or injected video disagree with the phone's
	// own motion and screen light. Face dedupe at small N is unchanged.
	NativeMethodStrength = 55

	// NativeSummaryVersion is the summary format this code reads.
	NativeSummaryVersion = "native-selfie-v1"

	// Defaults for the flash and sweep phases the client runs.
	DefaultFlashColours   = 8
	DefaultFlashSegmentMS = 300
	DefaultSweepMS        = 3000

	maxSummaryBytes = 2 << 20

	attestTag = "personhood-selfie-native-v1"
	flashTag  = "personhood-selfie-flash-v1"
)

// KeyAttester verifies a device-attested key: that the certificate chain
// (base64 DER, leaf first) is a hardware key attestation for this
// challenge, by the expected app, on a genuine locked phone. It returns the
// attested public key. A refusal should be an *AttestationError so its
// reason reaches the client.
type KeyAttester interface {
	VerifyAttestedKey(ctx context.Context, chain []string, challenge []byte) (crypto.PublicKey, error)
}

// AttestationError is a refused attestation; Reason becomes the
// ErrorReason (e.g. "attestation_device_unlocked").
type AttestationError struct{ Reason string }

func (e *AttestationError) Error() string { return "attestation refused: " + e.Reason }

// NativeConfig bundles NewNativeMethod's dependencies.
type NativeConfig struct {
	// Web is the SELFIE_ANCHOR method this one shares its accumulator,
	// lock and challenge tokens with. It must have Liveness configured.
	Web *Method
	// Attester verifies the device key. Required.
	Attester KeyAttester
	// Strength overrides NativeMethodStrength. Zero means the default.
	Strength int
	// Thresholds tunes motion.go's checks.
	Thresholds NativeThresholds
	// Logf, when set, receives one line per ceremony with the motion
	// scores (no biometric data). Default log.Printf.
	Logf func(format string, args ...any)
	// LogTraces also logs each raw sensor trace (face position, size and
	// mean colour per frame, IMU samples) in the shape
	// TestNativeTraces_Recorded replays, for calibrating thresholds on a
	// test issuer. Mean skin colour is personal data: test issuers only.
	LogTraces bool
}

// NativeMethod implements the native selfie ceremony.
type NativeMethod struct {
	web      *Method
	attester KeyAttester
	strength int
	th       NativeThresholds
	logf     func(string, ...any)
	traces   bool
}

var _ methodPlugin = (*NativeMethod)(nil)

// NewNativeMethod constructs a NativeMethod. Missing dependencies are a
// programmer error and panic.
func NewNativeMethod(cfg NativeConfig) *NativeMethod {
	if cfg.Web == nil || cfg.Web.liveness == nil {
		panic("fuzzy-extractor-selfie.NewNativeMethod: Web must be a liveness-enabled Method")
	}
	if cfg.Attester == nil {
		panic("fuzzy-extractor-selfie.NewNativeMethod: Attester must not be nil")
	}
	n := &NativeMethod{web: cfg.Web, attester: cfg.Attester, strength: cfg.Strength, th: cfg.Thresholds, logf: cfg.Logf, traces: cfg.LogTraces}
	if n.strength == 0 {
		n.strength = NativeMethodStrength
	}
	if n.logf == nil {
		n.logf = log.Printf
	}
	return n
}

// Metadata implements registry.Method.
func (n *NativeMethod) Metadata() types.MethodMetadata {
	md := n.web.Metadata()
	md.ID = NativeMethodID
	md.Strength = n.strength
	return md
}

// IsAvailableForUser implements registry.Method: it needs the native app.
func (n *NativeMethod) IsAvailableForUser(ctx types.UserContext) (bool, string) {
	switch strings.ToLower(strings.TrimSpace(ctx.Platform)) {
	case "web", "kiosk":
		return false, "The native selfie check needs the Android app; the web selfie check is available instead."
	}
	return true, ""
}

// HealthCheck implements registry.Method.
func (n *NativeMethod) HealthCheck(context.Context) error { return nil }

// BeginCeremony implements registry.Method.
func (n *NativeMethod) BeginCeremony(_ context.Context, cc types.CeremonyContext) (types.ChallengeData, error) {
	if cc.SessionID == "" {
		return types.ChallengeData{}, errors.New("fuzzy-extractor-selfie-native: CeremonyContext.SessionID is required")
	}
	lc := n.web.liveness
	kinds, token, err := lc.issueToken(cc.SessionID)
	if err != nil {
		return types.ChallengeData{}, err
	}
	colours := lc.flashColours(token, DefaultFlashColours)
	names := make([]string, len(colours))
	for i, c := range colours {
		names[i] = FlashColourNames[c]
	}
	return types.ChallengeData{
		Type: "fuzzy-extractor-native-challenge",
		Payload: map[string]any{
			"template_bytes":        TemplateBytes,
			"template_version":      lc.TemplateVersion,
			"liveness":              "active-v1",
			"challenges":            kinds,
			"challenge_token":       token,
			"summary_version":       NativeSummaryVersion,
			"attestation_challenge": hex.EncodeToString(attestationChallenge(cc.SessionID, token)),
			"flash_colors":          names,
			"flash_segment_ms":      DefaultFlashSegmentMS,
			"sweep_ms":              DefaultSweepMS,
			"complete_endpoint":     "/v1/methods/" + NativeMethodID + "/complete",
			// Where to send the same template, token and liveness if a
			// native-only check fails: the web ceremony, at its strength.
			"fallback_method": MethodID,
		},
	}, nil
}

// attestationChallenge binds the device key to this session and token.
func attestationChallenge(sessionID, token string) []byte {
	h := sha256.New()
	h.Write([]byte(attestTag))
	h.Write([]byte{0})
	h.Write([]byte(sessionID))
	h.Write([]byte{0})
	h.Write([]byte(token))
	return h.Sum(nil)
}

// flashColours derives the colour sequence from the token with the
// liveness key: unpredictable before begin, recomputable at complete,
// no server state. Consecutive colours always differ.
func (c *LivenessConfig) flashColours(token string, n int) []int {
	m := hmac.New(sha256.New, c.Key)
	m.Write([]byte(flashTag))
	m.Write([]byte{0})
	m.Write([]byte(token))
	b := m.Sum(nil)
	out := make([]int, n)
	out[0] = int(b[0]) % 3
	for i := 1; i < n; i++ {
		out[i] = (out[i-1] + 1 + int(b[i%len(b)])%2) % 3
	}
	return out
}

// NativeSummary is the signed ceremony summary.
type NativeSummary struct {
	Version         string           `json:"v"`
	SessionID       string           `json:"session_id"`
	ChallengeToken  string           `json:"challenge_token"`
	TemplateB64     string           `json:"template_b64"`
	TemplateVersion string           `json:"template_version"`
	Liveness        LivenessEvidence `json:"liveness"`
	Trace           NativeTrace      `json:"trace"`
}

// CompleteCeremony implements registry.Method.
func (n *NativeMethod) CompleteCeremony(ctx context.Context, cc types.CeremonyContext, resp types.ResponseData) (types.MethodResult, error) {
	fail := func(reason string) (types.MethodResult, error) {
		n.logf("fuzzy-extractor-selfie-native: success=false reason=%q", reason)
		return types.MethodResult{Success: false, MethodID: NativeMethodID, ErrorReason: reason}, nil
	}
	if cc.SessionID == "" {
		return fail("missing_session_id")
	}
	nat, _ := resp.Payload["native"].(map[string]any)
	if nat == nil {
		return fail("native_evidence_missing")
	}
	summaryB64, _ := stringField(nat, "summary_b64")
	sigB64, _ := stringField(nat, "signature_b64")
	chain := stringList(nat["certificate_chain"])
	if summaryB64 == "" || sigB64 == "" || len(chain) == 0 {
		return fail("native_evidence_missing")
	}
	if len(summaryB64) > maxSummaryBytes*4/3+4 {
		return fail("native_summary_invalid")
	}
	summaryBytes, err1 := base64.StdEncoding.DecodeString(summaryB64)
	sig, err2 := base64.StdEncoding.DecodeString(sigB64)
	if err1 != nil || err2 != nil {
		return fail("native_summary_invalid")
	}
	var sum NativeSummary
	if err := json.Unmarshal(summaryBytes, &sum); err != nil || sum.Version != NativeSummaryVersion {
		return fail("native_summary_invalid")
	}
	if sum.SessionID != cc.SessionID || sum.ChallengeToken == "" {
		return fail("native_summary_mismatch")
	}

	// 1. The key is a genuine device key, made for this session and token.
	pub, err := n.attester.VerifyAttestedKey(ctx, chain, attestationChallenge(cc.SessionID, sum.ChallengeToken))
	if err != nil {
		var ae *AttestationError
		if errors.As(err, &ae) && ae.Reason != "" {
			return fail(ae.Reason)
		}
		return fail("attestation_invalid")
	}
	// 2. That key signed exactly this summary.
	ec, ok := pub.(*ecdsa.PublicKey)
	digest := sha256.Sum256(summaryBytes)
	if !ok || !ecdsa.VerifyASN1(ec, digest[:], sig) {
		return fail("native_signature_invalid")
	}

	// 3. The web ceremony's checks, on the signed values.
	payload := map[string]any{
		"template_b64":     sum.TemplateB64,
		"template_version": sum.TemplateVersion,
		"challenge_token":  sum.ChallengeToken,
		"liveness":         sum.Liveness,
	}
	template, reason := decodeTemplate(payload)
	if reason != "" {
		return fail(reason)
	}
	lc := n.web.liveness
	if reason := lc.checkLiveness(cc.SessionID, payload); reason != "" {
		return fail(reason)
	}

	// 4. Camera, gyroscope and screen light agree.
	colours := lc.flashColours(sum.ChallengeToken, DefaultFlashColours)
	rep := AnalyzeNativeTrace(sum.Trace, colours, n.th)
	if n.traces {
		if b, err := json.Marshal(map[string]any{"expect": "pass", "colours": colours, "trace": sum.Trace}); err == nil {
			n.logf("fuzzy-extractor-selfie-native: trace %s", b)
		}
	}
	if b, err := json.Marshal(rep); err == nil {
		n.logf("fuzzy-extractor-selfie-native: motion %s device=%q sdk=%d", b, sum.Trace.Device.Model, sum.Trace.Device.SDK)
	}
	if !rep.Pass {
		return fail(rep.Reason)
	}

	res, err := n.web.enroll(ctx, cc.SessionID, NativeMethodID, template)
	if err != nil {
		return types.MethodResult{}, fmt.Errorf("fuzzy-extractor-selfie-native: %w", err)
	}
	n.logf("fuzzy-extractor-selfie-native: success=%v reason=%q", res.Success, res.ErrorReason)
	return res, nil
}

// IsNativeFallbackReason reports whether a native ErrorReason should send
// the client to the web ceremony instead of stopping: every check that
// only the native path makes.
func IsNativeFallbackReason(reason string) bool {
	return strings.HasPrefix(reason, "native_") || strings.HasPrefix(reason, "attestation_")
}

func stringList(v any) []string {
	arr, ok := v.([]any)
	if !ok {
		if s, ok := v.([]string); ok {
			return s
		}
		return nil
	}
	out := make([]string, 0, len(arr))
	for _, x := range arr {
		s, ok := x.(string)
		if !ok || strings.TrimSpace(s) == "" {
			return nil
		}
		out = append(out, strings.TrimSpace(s))
	}
	return out
}
