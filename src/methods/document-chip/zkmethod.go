package documentchip

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"embed"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"net/http"
	"path"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/sagearbor/personhood/pkg/types"
	"github.com/sagearbor/personhood/src/methods/document-chip/zkproof"
)

// document-chip-zk (docs/zk-passport.md): the same passport chip as
// document-chip, but the phone proves the passive-authentication checks in
// zero knowledge and sends four proofs instead of the passport's files. The
// issuer learns that some passport under a CSCA in its registry is valid
// today, and one per-passport number scoped to this issuer; not the name,
// number, birth date, photo, or even the country.
//
// No Active Authentication yet (phase 3), so a copied chip passes like a
// passive-only document-chip enrollment: strength ZKStrength (70).

const (
	ZKMethodID = "document-chip-zk"
	// ZKStrength matches ChipPassiveOnlyStrength: passive authentication,
	// face bound on the phone, no clone resistance yet.
	ZKStrength = ChipPassiveOnlyStrength

	// zkChallengeTTL is longer than the chip method's: proving takes from
	// tens of seconds to a few minutes on a cheap phone, after the chip
	// read and the selfie.
	zkChallengeTTL = 30 * time.Minute

	// zkMaxConcurrentVerify bounds concurrent bb processes.
	zkMaxConcurrentVerify = 4

	maxProofB64  = 32 << 10
	maxPublicB64 = 1 << 10
)

//go:embed zk/circuits.json zk/vks
var zkEmbedded embed.FS

// ZKCircuitManifest is zk/circuits.json: the circuit variants this issuer
// accepts (one pinned verification key each, in zk/vks/<name>.vk) and the
// artifacts the wallet downloads to prove with them. Written by
// tools/zk-circuits/build.sh.
type ZKCircuitManifest struct {
	Version   int                          `json:"version"`
	Toolchain map[string]string            `json:"toolchain"`
	BaseURL   string                       `json:"base_url,omitempty"`
	SRS       map[string]ZKArtifact        `json:"srs"`
	Circuits  map[string]ZKCircuitArtifact `json:"circuits"`
}

// ZKArtifact is one downloadable file.
type ZKArtifact struct {
	File   string `json:"file"`
	SHA256 string `json:"sha256"`
	Bytes  int64  `json:"bytes"`
	Points int    `json:"points,omitempty"`
	// PrefixSHA256 maps a point count (a power of two) to the SHA-256 of
	// the file's first count*64 bytes: a phone downloads only the prefix
	// its largest circuit needs (HTTP Range) and checks it against this.
	PrefixSHA256 map[string]string `json:"prefix_sha256,omitempty"`
}

// ZKCircuitArtifact is one circuit variant.
type ZKCircuitArtifact struct {
	File      string `json:"file"`
	SHA256    string `json:"sha256"`
	Bytes     int64  `json:"bytes"`
	Gates     int    `json:"gates"`
	VKSHA256  string `json:"vk_sha256"`
	License   string `json:"license"`
	SourceDir string `json:"source"`
}

// LoadZKCircuits reads the embedded manifest and verification keys, and
// checks each key against the hash the manifest pins.
func LoadZKCircuits() (*ZKCircuitManifest, map[string][]byte, error) {
	raw, err := zkEmbedded.ReadFile("zk/circuits.json")
	if err != nil {
		return nil, nil, err
	}
	var m ZKCircuitManifest
	if err := json.Unmarshal(raw, &m); err != nil {
		return nil, nil, fmt.Errorf("document-chip-zk: zk/circuits.json: %w", err)
	}
	vks := map[string][]byte{}
	for name, c := range m.Circuits {
		vk, err := zkEmbedded.ReadFile("zk/vks/" + name + ".vk")
		if err != nil {
			return nil, nil, fmt.Errorf("document-chip-zk: no verification key for %s: %w", name, err)
		}
		sum := sha256.Sum256(vk)
		if hex.EncodeToString(sum[:]) != c.VKSHA256 {
			return nil, nil, fmt.Errorf("document-chip-zk: verification key for %s does not match its pinned hash", name)
		}
		vks[name] = vk
	}
	if _, ok := vks[zkproof.BindCircuit]; !ok && len(vks) > 0 {
		return nil, nil, errors.New("document-chip-zk: the manifest has no bind circuit")
	}
	return &m, vks, nil
}

// ZKConfig is what document-chip-zk needs on top of Config.
type ZKConfig struct {
	// BB is the path to the pinned Barretenberg CLI (bb 5.0.0).
	BB string
	// Registry is the CSCA registry built from Config.Trust.
	Registry *ZKRegistry
	// Roots are the accepted registry roots (ZKAcceptedRoots).
	Roots map[[zkproof.FieldSize]byte]bool
	// Circuits and VKs come from LoadZKCircuits.
	Circuits *ZKCircuitManifest
	VKs      map[string][]byte
	// PublicURL is the issuer's public base URL (SERVER_PUBLIC_URL); the
	// registry and circuit URLs handed to the wallet hang off it.
	PublicURL string
	// ArtifactsBaseURL, when set, is where the wallet downloads circuit
	// artifacts and the SRS (a CDN or the web app). Otherwise the issuer
	// serves them from ArtifactsDir.
	ArtifactsBaseURL string
	ArtifactsDir     fs.FS
	// AllowMock accepts zkPassport's mock state "ZKR". Tests only.
	AllowMock bool
}

// ZKMethod is the "document-chip-zk" anchor.
type ZKMethod struct {
	common
	zk         ZKConfig
	verifier   *zkproof.Verifier
	challenges *zkChallengeStore
	sem        chan struct{}
	random     func([]byte) error
}

// NewZKMethod builds the method. It panics on a missing registry, bb path
// or circuit set: those are start-up configuration errors.
func NewZKMethod(cfg Config, zk ZKConfig, onReview func(ReviewCase)) *ZKMethod {
	if zk.Registry == nil || zk.BB == "" || zk.Circuits == nil || len(zk.VKs) == 0 {
		panic("document-chip-zk: Registry, BB and the circuit set are required")
	}
	return &ZKMethod{
		common: common{cfg: cfg, logFlag: onReview},
		zk:     zk,
		verifier: &zkproof.Verifier{
			BB: zk.BB, VKs: zk.VKs, Roots: zk.Roots,
			Scope: zkproof.ServiceScope(), AllowMock: zk.AllowMock, Now: cfg.Now,
		},
		challenges: &zkChallengeStore{m: map[string]zkChallenge{}},
		sem:        make(chan struct{}, zkMaxConcurrentVerify),
		random: func(b []byte) error {
			_, err := rand.Read(b)
			return err
		},
	}
}

func (m *ZKMethod) Metadata() types.MethodMetadata {
	return types.MethodMetadata{
		ID: ZKMethodID, Type: types.MethodTypeAnchor, Strength: ZKStrength, CostUSD: 0,
		UXFriction: types.FrictionLow, FreshnessLifetime: freshness, Version: Version,
	}
}

func (m *ZKMethod) IsAvailableForUser(ctx types.UserContext) (bool, string) {
	switch strings.ToLower(strings.TrimSpace(ctx.Platform)) {
	case "web", "kiosk":
		return false, "Proving a passport in zero knowledge needs the Android app on a phone with NFC."
	}
	return true, ""
}

// holderBinding is what the bind proof commits to besides the challenge.
// Without a holder DID (only in tests and old clients) the session id
// stands in, which still ties the proof to this one session.
func holderBinding(cc types.CeremonyContext) string {
	if d := strings.TrimSpace(string(cc.HolderDID)); d != "" {
		return d
	}
	return "session:" + cc.SessionID
}

func (m *ZKMethod) url(p string) string {
	return strings.TrimRight(m.zk.PublicURL, "/") + "/v1/methods/" + ZKMethodID + "/" + p
}

// BeginCeremony issues the session challenge and returns the exact bind
// data the phone's last sub-proof must commit to.
func (m *ZKMethod) BeginCeremony(_ context.Context, cc types.CeremonyContext) (types.ChallengeData, error) {
	if cc.SessionID == "" {
		return types.ChallengeData{}, errors.New("document-chip-zk: SessionID is required")
	}
	var ch [32]byte
	if err := m.random(ch[:]); err != nil {
		return types.ChallengeData{}, err
	}
	holder := holderBinding(cc)
	m.challenges.put(cc.SessionID, zkChallenge{challenge: ch, holder: holder, at: m.now()})
	data := zkproof.BindData(ch, holder)
	scope := zkproof.ServiceScope()
	return types.ChallengeData{
		Type: "document-chip-zk-challenge",
		Payload: map[string]any{
			"bind_data_hex":       hex.EncodeToString(data[:]),
			"service_scope":       "0x" + hex.EncodeToString(scope[:]),
			"service_subscope":    "0x" + strings.Repeat("0", 64),
			"registry_url":        m.url("registry"),
			"registry_root":       m.zk.Registry.Root,
			"circuits_url":        m.url("circuits"),
			"face_bind_url":       m.cfg.FaceBindURL,
			"complete_endpoint":   "/v1/methods/" + ZKMethodID + "/complete",
			"max_date_skew_hours": 36,
		},
	}, nil
}

func parseSubProof(payload map[string]any, stage string) (zkproof.SubProof, bool) {
	proofs, _ := payload["proofs"].(map[string]any)
	raw, _ := proofs[stage].(map[string]any)
	if raw == nil {
		return zkproof.SubProof{}, false
	}
	name, _ := raw["circuit"].(string)
	proof, err1 := b64Field(raw, "proof_b64", maxProofB64)
	pub, err2 := b64Field(raw, "public_inputs_b64", maxPublicB64)
	if err1 != nil || err2 != nil || proof == nil || pub == nil || name == "" || len(name) > 128 {
		return zkproof.SubProof{}, false
	}
	return zkproof.SubProof{Circuit: name, Proof: proof, PublicInputs: pub}, true
}

// zkReason maps a verifier error to the refusal reason the wallet turns
// into a next step (docs/zk-passport.md, refusal table).
func zkReason(err error) string {
	switch {
	case errors.Is(err, zkproof.ErrRegistryUnknown):
		return "zk_registry_unknown"
	case errors.Is(err, zkproof.ErrUnknownCircuit):
		return "zk_circuit_unsupported"
	case errors.Is(err, zkproof.ErrChainBroken):
		return "zk_chain_broken"
	case errors.Is(err, zkproof.ErrStaleDate):
		return "zk_date_stale"
	case errors.Is(err, zkproof.ErrBindMismatch):
		return "zk_bind_mismatch"
	case errors.Is(err, zkproof.ErrScope):
		return "zk_scope_mismatch"
	case errors.Is(err, zkproof.ErrMockDocument):
		return "zk_mock_document"
	case errors.Is(err, zkproof.ErrMalformed):
		return "zk_bundle_malformed"
	case errors.Is(err, zkproof.ErrProofInvalid):
		return "zk_proof_invalid"
	default:
		return ""
	}
}

func (m *ZKMethod) CompleteCeremony(ctx context.Context, cc types.CeremonyContext, resp types.ResponseData) (types.MethodResult, error) {
	if cc.SessionID == "" {
		return fail(ZKMethodID, "missing_session_id"), nil
	}
	ch, ok := m.challenges.take(cc.SessionID, m.now())
	if !ok {
		return fail(ZKMethodID, "no_challenge_issued"), nil
	}
	if ch.holder != holderBinding(cc) {
		return fail(ZKMethodID, "zk_bind_mismatch"), nil
	}
	var b zkproof.Bundle
	var okAll = true
	for i, dst := range []*zkproof.SubProof{&b.DSC, &b.ID, &b.Integrity, &b.Bind} {
		sp, ok := parseSubProof(resp.Payload, zkproof.Stages[i])
		okAll = okAll && ok
		*dst = sp
	}
	if !okAll {
		return fail(ZKMethodID, "zk_bundle_malformed"), nil
	}

	// Cheap face-bind shape check before spending CPU on proofs.
	if fb, ok := parseFaceBind(resp.Payload); !ok {
		return fail(ZKMethodID, "face_bind_missing"), nil
	} else if !fb.Match || !fb.Liveness {
		return fail(ZKMethodID, "face_bind_failed"), nil
	}

	select {
	case m.sem <- struct{}{}:
	case <-ctx.Done():
		return types.MethodResult{}, ctx.Err()
	}
	res, err := m.verifier.Verify(ctx, b, zkproof.BindData(ch.challenge, ch.holder))
	<-m.sem
	if err != nil {
		if reason := zkReason(err); reason != "" {
			return fail(ZKMethodID, reason), nil
		}
		return types.MethodResult{}, fmt.Errorf("document-chip-zk: %w", err)
	}

	identifier := res.Identifier()
	if reason, err := m.checkFace(ctx, ZKMethodID, cc.SessionID, identifier, "ZK", resp.Payload); err != nil {
		return types.MethodResult{}, fmt.Errorf("document-chip-zk: %w", err)
	} else if reason != "" {
		return fail(ZKMethodID, reason), nil
	}
	return types.MethodResult{
		Success:            true,
		MethodID:           ZKMethodID,
		VerifiedAt:         m.now(),
		AttestationDigest:  digestOf(cc.SessionID, "zk", hex.EncodeToString(res.RegistryRoot[:]), b.DSC.Circuit, b.ID.Circuit, b.Integrity.Circuit),
		VerifiedIdentifier: identifier,
	}, nil
}

func (m *ZKMethod) HealthCheck(_ context.Context) error {
	if len(m.zk.Registry.Certificates) == 0 {
		return errors.New("document-chip-zk: empty CSCA registry")
	}
	return nil
}

// ------------------------------------------------------------ HTTP

// RegistryHandler serves the CSCA registry file (GET .../registry).
func (m *ZKMethod) RegistryHandler() http.Handler {
	body, _ := json.Marshal(m.zk.Registry)
	etag := fmt.Sprintf("%q", m.zk.Registry.Root)
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.Header().Set("Cache-Control", "public, max-age=3600")
		w.Header().Set("ETag", etag)
		if r.Header.Get("If-None-Match") == etag {
			w.WriteHeader(http.StatusNotModified)
			return
		}
		_, _ = w.Write(body)
	})
}

// CircuitsHandler serves the circuit manifest (GET .../circuits), with
// base_url pointing at wherever the artifacts are hosted.
func (m *ZKMethod) CircuitsHandler() http.Handler {
	mf := *m.zk.Circuits
	mf.BaseURL = m.zk.ArtifactsBaseURL
	if mf.BaseURL == "" {
		mf.BaseURL = m.url("artifacts/")
	}
	if !strings.HasSuffix(mf.BaseURL, "/") {
		mf.BaseURL += "/"
	}
	body, _ := json.Marshal(mf)
	return http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.Header().Set("Cache-Control", "public, max-age=3600")
		_, _ = w.Write(body)
	})
}

// ArtifactsHandler serves circuit artifacts and the SRS from ArtifactsDir
// (GET .../artifacts/<file>). Only files the manifest lists are served.
func (m *ZKMethod) ArtifactsHandler() http.Handler {
	allowed := map[string]bool{}
	for _, c := range m.zk.Circuits.Circuits {
		allowed[c.File] = true
	}
	for _, s := range m.zk.Circuits.SRS {
		allowed[s.File] = true
	}
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		name := path.Base(r.URL.Path)
		if m.zk.ArtifactsDir == nil || !allowed[name] {
			http.NotFound(w, r)
			return
		}
		f, err := m.zk.ArtifactsDir.Open(name)
		if err != nil {
			http.NotFound(w, r)
			return
		}
		defer f.Close()
		st, err := f.Stat()
		if err != nil {
			http.NotFound(w, r)
			return
		}
		rs, ok := f.(interface {
			Read([]byte) (int, error)
			Seek(int64, int) (int64, error)
		})
		if !ok {
			http.Error(w, "artifact store cannot seek", http.StatusInternalServerError)
			return
		}
		w.Header().Set("Cache-Control", "public, max-age=31536000, immutable")
		w.Header().Set("Content-Type", "application/octet-stream")
		http.ServeContent(w, r, name, st.ModTime(), rs)
	})
}

// ------------------------------------------------------------ challenges

type zkChallenge struct {
	challenge [32]byte
	holder    string
	at        time.Time
}

type zkChallengeStore struct {
	mu sync.Mutex
	m  map[string]zkChallenge
}

func (s *zkChallengeStore) put(session string, c zkChallenge) {
	s.mu.Lock()
	defer s.mu.Unlock()
	for k, v := range s.m {
		if c.at.Sub(v.at) > zkChallengeTTL {
			delete(s.m, k)
		}
	}
	s.m[session] = c
}

// take returns and forgets the session's challenge: one challenge answers
// one completion, so a bundle cannot be submitted twice.
func (s *zkChallengeStore) take(session string, now time.Time) (zkChallenge, bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	c, ok := s.m[session]
	delete(s.m, session)
	if !ok || now.Sub(c.at) > zkChallengeTTL {
		return zkChallenge{}, false
	}
	return c, true
}

// zkEncodeSubProof is the wire form of a sub-proof (tests and tools).
func zkEncodeSubProof(sp zkproof.SubProof) map[string]any {
	return map[string]any{
		"circuit":           sp.Circuit,
		"proof_b64":         base64.StdEncoding.EncodeToString(sp.Proof),
		"public_inputs_b64": base64.StdEncoding.EncodeToString(sp.PublicInputs),
	}
}

// ZKBBVersion is the Barretenberg release the pinned verification keys and
// the wallet's prover belong to; `bb --version` must report it.
const ZKBBVersion = "5.0.0"

// MissingZKArtifacts lists manifest files absent from dir or whose SHA-256
// differs from the manifest.
func MissingZKArtifacts(dir fs.FS, m *ZKCircuitManifest) []string {
	var missing []string
	check := func(file, want string) {
		f, err := dir.Open(file)
		if err != nil {
			missing = append(missing, file)
			return
		}
		defer f.Close()
		h := sha256.New()
		if _, err := io.Copy(h, f); err != nil || hex.EncodeToString(h.Sum(nil)) != want {
			missing = append(missing, file)
		}
	}
	for _, s := range m.SRS {
		check(s.File, s.SHA256)
	}
	for _, c := range m.Circuits {
		check(c.File, c.SHA256)
	}
	sort.Strings(missing)
	return missing
}
