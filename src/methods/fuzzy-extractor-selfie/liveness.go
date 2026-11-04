package fuzzyextractorselfie

// Active-liveness ceremony (SELFIE_ANCHOR=1 on the reference server).
//
// BeginCeremony picks a random order of ChallengeCount head/eye challenges
// and hands the client a challenge token: an HMAC, under a key that never
// leaves this process, over the session id, the time and the order. The
// client (app/web) prompts the person through that order with its camera
// and an on-device face model, then returns the template, the token and
// what it measured. CompleteCeremony checks the token, that the reported
// challenges are the ones issued in the issued order, that each took a
// human amount of time, and that the whole ceremony did too.
//
// What this does NOT prove. Every measurement is made by the client, and a
// browser cannot prove its camera feed is a real camera pointed at a real
// face. A scripted client can skip the camera and post any 32 bytes, and
// random bytes look like a new person to the fuzzy extractor. These checks
// only make a scripted attacker read the protocol; they stop nobody who
// does. docs/selfie-anchor.md has the threat model and the strength this
// supports.

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"math/big"
	"time"
)

// Challenge kinds, as the client names them. "turn_left" means the
// person's own left.
const (
	ChallengeTurnLeft  = "turn_left"
	ChallengeTurnRight = "turn_right"
	ChallengeBlink     = "blink"
	ChallengeCloser    = "closer"
)

// ChallengeKinds lists every challenge kind, in wire-code order.
var ChallengeKinds = []string{ChallengeTurnLeft, ChallengeTurnRight, ChallengeBlink, ChallengeCloser}

const (
	// ChallengeCount challenges are issued per ceremony, all different,
	// in random order (4*3*2 = 24 possible orders).
	ChallengeCount = 3

	// A challenge answered faster than this is faster than a person can
	// react to a prompt; slower than MaxChallengeMS and the client should
	// have restarted.
	MinChallengeMS = 250
	MaxChallengeMS = 10000

	// DefaultTemplateVersion names the client pipeline whose templates
	// this issuer dedupes against each other (app/web lib/face). Templates
	// from different pipelines are not comparable.
	DefaultTemplateVersion = "dlib128-simhash256-v1"

	livenessTokenTag = "personhood-selfie-liveness-v1"
	livenessMACBytes = 16
)

// LivenessConfig turns on the active-liveness ceremony. A nil
// Config.Liveness keeps the original one-shot behaviour (template only).
type LivenessConfig struct {
	// Key signs challenge tokens. Required, at least 32 bytes. A random
	// per-process key is fine: a restart only fails ceremonies in flight.
	Key []byte

	// TemplateVersion the client must report. Default DefaultTemplateVersion.
	TemplateVersion string

	// MinCeremony is the least time a ceremony can take from begin to
	// complete (default 3s); MaxCeremony the most (default 10 minutes).
	MinCeremony time.Duration
	MaxCeremony time.Duration

	// Now defaults to time.Now.
	Now func() time.Time
}

func (c *LivenessConfig) withDefaults() (*LivenessConfig, error) {
	if len(c.Key) < 32 {
		return nil, errors.New("fuzzy-extractor-selfie: LivenessConfig.Key must be at least 32 bytes")
	}
	out := *c
	out.Key = append([]byte(nil), c.Key...)
	if out.TemplateVersion == "" {
		out.TemplateVersion = DefaultTemplateVersion
	}
	if out.MinCeremony == 0 {
		out.MinCeremony = 3 * time.Second
	}
	if out.MaxCeremony == 0 {
		out.MaxCeremony = 10 * time.Minute
	}
	if out.Now == nil {
		out.Now = time.Now
	}
	return &out, nil
}

// randomChallengeOrder draws ChallengeCount distinct kinds in random order,
// returned as indexes into ChallengeKinds.
func randomChallengeOrder() ([]byte, error) {
	pool := []byte{0, 1, 2, 3}
	out := make([]byte, 0, ChallengeCount)
	for len(out) < ChallengeCount {
		n, err := rand.Int(rand.Reader, big.NewInt(int64(len(pool))))
		if err != nil {
			return nil, err
		}
		i := int(n.Int64())
		out = append(out, pool[i])
		pool = append(pool[:i], pool[i+1:]...)
	}
	return out, nil
}

func (c *LivenessConfig) mac(sessionID string, body []byte) []byte {
	m := hmac.New(sha256.New, c.Key)
	m.Write([]byte(livenessTokenTag))
	m.Write([]byte{0})
	m.Write([]byte(sessionID))
	m.Write([]byte{0})
	m.Write(body)
	return m.Sum(nil)[:livenessMACBytes]
}

// issueToken returns the challenge order (as kind names) and a token
// binding it to sessionID and the current time.
func (c *LivenessConfig) issueToken(sessionID string) ([]string, string, error) {
	order, err := randomChallengeOrder()
	if err != nil {
		return nil, "", fmt.Errorf("fuzzy-extractor-selfie: challenge order: %w", err)
	}
	body := make([]byte, 8, 8+len(order))
	binary.BigEndian.PutUint64(body, uint64(c.Now().UnixMilli()))
	body = append(body, order...)
	token := base64.RawURLEncoding.EncodeToString(append(body, c.mac(sessionID, body)...))
	kinds := make([]string, len(order))
	for i, o := range order {
		kinds[i] = ChallengeKinds[o]
	}
	return kinds, token, nil
}

// openToken verifies token for sessionID and returns the issue time and
// the challenge order. It fails closed on any malformation.
func (c *LivenessConfig) openToken(sessionID, token string) (time.Time, []string, bool) {
	raw, err := base64.RawURLEncoding.DecodeString(token)
	if err != nil || len(raw) != 8+ChallengeCount+livenessMACBytes {
		return time.Time{}, nil, false
	}
	body, mac := raw[:8+ChallengeCount], raw[8+ChallengeCount:]
	if !hmac.Equal(mac, c.mac(sessionID, body)) {
		return time.Time{}, nil, false
	}
	issued := time.UnixMilli(int64(binary.BigEndian.Uint64(body[:8])))
	kinds := make([]string, ChallengeCount)
	for i, o := range body[8:] {
		if int(o) >= len(ChallengeKinds) {
			return time.Time{}, nil, false
		}
		kinds[i] = ChallengeKinds[o]
	}
	return issued, kinds, true
}

// LivenessEvidence is what the client reports about the ceremony it ran.
// Only the challenge list is checked here; the rest is kept for audit and
// tuning, never trusted.
type LivenessEvidence struct {
	Challenges []ChallengeResult `json:"challenges"`
	// Frames is how many camera frames went into the averaged descriptor.
	Frames int `json:"frames,omitempty"`
	// Parallax is the client's motion-parallax score per head turn
	// (lib/face/liveness.ts); informational.
	Parallax []float64 `json:"parallax,omitempty"`
}

// ChallengeResult is one answered challenge.
type ChallengeResult struct {
	Kind string `json:"kind"`
	// MS is the time from showing the prompt to the action being seen.
	MS int `json:"ms"`
}

// checkLiveness validates the liveness part of a complete request and
// returns "" when it passes, else an ErrorReason.
func (c *LivenessConfig) checkLiveness(sessionID string, payload map[string]any) string {
	if v, _ := stringField(payload, "template_version"); v != c.TemplateVersion {
		return "unsupported_template_version"
	}
	token, _ := stringField(payload, "challenge_token")
	if token == "" {
		return "missing_challenge_token"
	}
	issued, want, ok := c.openToken(sessionID, token)
	if !ok {
		return "invalid_challenge_token"
	}
	elapsed := c.Now().Sub(issued)
	if elapsed < c.MinCeremony {
		return "liveness_too_fast"
	}
	if elapsed > c.MaxCeremony {
		return "challenge_expired"
	}
	raw, ok := payload["liveness"]
	if !ok {
		return "missing_liveness"
	}
	b, err := json.Marshal(raw)
	if err != nil {
		return "invalid_liveness"
	}
	var ev LivenessEvidence
	if err := json.Unmarshal(b, &ev); err != nil {
		return "invalid_liveness"
	}
	if len(ev.Challenges) != len(want) {
		return "liveness_challenge_mismatch"
	}
	total := 0
	for i, ch := range ev.Challenges {
		if ch.Kind != want[i] {
			return "liveness_challenge_mismatch"
		}
		if ch.MS < MinChallengeMS || ch.MS > MaxChallengeMS {
			return "liveness_timing_implausible"
		}
		total += ch.MS
	}
	if time.Duration(total)*time.Millisecond > elapsed {
		return "liveness_timing_implausible"
	}
	return ""
}
