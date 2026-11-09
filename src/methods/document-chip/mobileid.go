package documentchip

import (
	"context"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"net/http"
	"strings"
	"time"

	"github.com/sagearbor/personhood/pkg/types"
	"github.com/sagearbor/personhood/src/methods/document-chip/mdoczk"
	"github.com/sagearbor/personhood/src/methods/document-chip/zkproof"
)

// mobile-id-zk (docs/mobile-id.md): a government mobile ID (an ISO/IEC
// 18013-5 mdoc, e.g. a US state mobile driving licence in Apple, Google or
// Samsung Wallet) proved in zero knowledge on the phone. The phone gets the
// licence from its wallet (Android Credential Manager, the response
// encrypted to a key only the phone holds), proves that a government IACA
// in this issuer's registry stands behind it, that it is valid now and that
// its device key (in the phone's secure hardware) signed this session's
// nonce, and sends one proof plus a scoped nullifier. The issuer learns no
// name, number, birth date, photo or jurisdiction.
//
// It is an issuer method on purpose, not a separate chain entry point: the
// licence's identifier goes through the same identifier store (kind
// "document"), the same document face index and review queue as the
// passport methods, so one person arriving with a passport and a licence is
// noticed (routed to review, never refused).

const (
	MobileIDMethodID = "mobile-id-zk"
	// MobileIDStrength: a government-signed credential, copy-protected by a
	// device key in secure hardware (as strong as passport Active
	// Authentication), face bound on the phone; five below the passport
	// with AA because a person can legitimately hold licences from two
	// jurisdictions or a re-numbered licence (more duplicates go to review
	// than for passports), and because the holder was bound to the licence
	// by the wallet's remote onboarding, not by an in-person check
	// (docs/mobile-id.md, "Strength").
	MobileIDStrength = 75

	mobileIDChallengeTTL = 30 * time.Minute
)

// MobileIDConfig is what mobile-id-zk needs on top of Config.
type MobileIDConfig struct {
	BB       string
	Registry *mdoczk.Registry
	Roots    map[[zkproof.FieldSize]byte]bool
	Circuits *ZKCircuitManifest
	VKs      map[string][]byte
	// PublicURL, ArtifactsBaseURL, ArtifactsDir: as ZKConfig.
	PublicURL        string
	ArtifactsBaseURL string
	ArtifactsDir     fs.FS
	// AllowedOrigins, when non-empty, are the only session-transcript
	// origins accepted (e.g. the app's "android:apk-key-hash:...").
	AllowedOrigins []string
	// DocTypes maps accepted docType -> namespace (mdoczk.DefaultDocTypes
	// when nil).
	DocTypes map[string]string
	// DigestKey, when set, makes the attestation digest stable per licence
	// (HMAC of the identifier), so RECOVERY_DOCUMENT_METHODS can name this
	// method: the same licence then proves the same person in a key
	// recovery. Without it the digest is per session.
	DigestKey []byte
}

// LoadMobileIDCircuits reads the embedded manifest and verification keys.
func LoadMobileIDCircuits() (*ZKCircuitManifest, map[string][]byte, error) {
	var m ZKCircuitManifest
	if err := json.Unmarshal(mdoczk.CircuitsJSON(), &m); err != nil {
		return nil, nil, fmt.Errorf("mobile-id-zk: circuits.json: %w", err)
	}
	vks := map[string][]byte{}
	for name, c := range m.Circuits {
		vk, err := mdoczk.VK(name)
		if err != nil {
			return nil, nil, fmt.Errorf("mobile-id-zk: no verification key for %s: %w", name, err)
		}
		sum := sha256.Sum256(vk)
		if hex.EncodeToString(sum[:]) != c.VKSHA256 {
			return nil, nil, fmt.Errorf("mobile-id-zk: verification key for %s does not match its pinned hash", name)
		}
		vks[name] = vk
	}
	return &m, vks, nil
}

// MobileIDMethod is the "mobile-id-zk" anchor.
type MobileIDMethod struct {
	common
	mc         MobileIDConfig
	verifier   *mdoczk.Verifier
	challenges *zkChallengeStore
	sem        chan struct{}
	random     func([]byte) error
}

// NewMobileIDMethod builds the method; it panics on missing configuration.
func NewMobileIDMethod(cfg Config, mc MobileIDConfig, onReview func(ReviewCase)) *MobileIDMethod {
	if mc.Registry == nil || mc.BB == "" || mc.Circuits == nil || len(mc.VKs) == 0 {
		panic("mobile-id-zk: Registry, BB and the circuit set are required")
	}
	m := &MobileIDMethod{
		common: common{cfg: cfg, logFlag: onReview},
		mc:     mc,
		verifier: &mdoczk.Verifier{
			BB: mc.BB, VKs: mc.VKs, Roots: mc.Roots, Scope: mdoczk.ServiceScope(), DocTypes: mc.DocTypes,
			Now: cfg.Now,
		},
		challenges: &zkChallengeStore{m: map[string]zkChallenge{}},
		sem:        make(chan struct{}, zkMaxConcurrentVerify),
		random: func(b []byte) error {
			_, err := rand.Read(b)
			return err
		},
	}
	return m
}

func (m *MobileIDMethod) Metadata() types.MethodMetadata {
	return types.MethodMetadata{
		ID: MobileIDMethodID, Type: types.MethodTypeAnchor, Strength: MobileIDStrength, CostUSD: 0,
		UXFriction: types.FrictionLow, FreshnessLifetime: freshness, Version: Version,
	}
}

func (m *MobileIDMethod) IsAvailableForUser(ctx types.UserContext) (bool, string) {
	switch strings.ToLower(strings.TrimSpace(ctx.Platform)) {
	case "web", "kiosk":
		return false, "Proving a mobile ID privately needs the Android app on the phone that holds the ID."
	}
	return true, ""
}

func (m *MobileIDMethod) url(p string) string {
	return strings.TrimRight(m.mc.PublicURL, "/") + "/v1/methods/" + MobileIDMethodID + "/" + p
}

// BeginCeremony issues the session nonce the wallet's device signature must
// cover, and tells the phone what to request.
func (m *MobileIDMethod) BeginCeremony(_ context.Context, cc types.CeremonyContext) (types.ChallengeData, error) {
	if cc.SessionID == "" {
		return types.ChallengeData{}, errors.New("mobile-id-zk: SessionID is required")
	}
	var ch [32]byte
	if err := m.random(ch[:]); err != nil {
		return types.ChallengeData{}, err
	}
	holder := holderBinding(cc)
	m.challenges.put(cc.SessionID, zkChallenge{challenge: ch, holder: holder, at: m.now()})
	nonce := mdoczk.Nonce(ch, holder)
	scope := mdoczk.ServiceScope()
	types_ := m.mc.DocTypes
	if types_ == nil {
		types_ = mdoczk.DefaultDocTypes
	}
	var docs []map[string]any
	for dt, ns := range types_ {
		docs = append(docs, map[string]any{
			"doc_type": dt, "name_space": ns,
			// Requested from the wallet; both stay on the phone. The
			// portrait is only for the on-phone face match.
			"elements": []string{"document_number", "portrait"},
		})
	}
	return types.ChallengeData{Type: "mobile-id-zk-challenge", Payload: map[string]any{
		"nonce_hex":           hex.EncodeToString(nonce[:]),
		"nonce_b64u":          mdoczk.NonceString(nonce),
		"documents":           docs,
		"handovers":           []string{"dcapi", "openid4vp"},
		"service_scope":       "0x" + hex.EncodeToString(scope[:]),
		"registry_url":        m.url("registry"),
		"registry_root":       m.mc.Registry.Root,
		"circuits_url":        m.url("circuits"),
		"face_bind_url":       m.cfg.FaceBindURL,
		"complete_endpoint":   "/v1/methods/" + MobileIDMethodID + "/complete",
		"max_date_skew_hours": 36,
	}}, nil
}

// transcript rebuilds the session transcript the device key must have
// signed, from what the phone says it sent its wallet, checking that it
// carries this session's nonce.
func (m *MobileIDMethod) transcript(payload map[string]any, nonce [32]byte) ([]byte, string) {
	origin, _ := payload["origin"].(string)
	if err := mdoczk.CheckOrigin(origin, m.mc.AllowedOrigins); err != nil {
		return nil, "mdoc_origin_not_allowed"
	}
	switch handover, _ := payload["handover"].(string); handover {
	case "dcapi":
		info, _ := payload["encryption_info_b64u"].(string)
		if err := mdoczk.CheckEncryptionInfo(info, nonce); err != nil {
			return nil, "mdoc_session_mismatch"
		}
		return mdoczk.SessionTranscript(info, origin), ""
	case "openid4vp":
		var thumb []byte
		if s, _ := payload["jwk_thumbprint_b64u"].(string); s != "" {
			b, err := base64.RawURLEncoding.DecodeString(s)
			if err != nil || len(b) != 32 {
				return nil, "mdoc_bundle_malformed"
			}
			thumb = b
		}
		return mdoczk.OpenID4VPSessionTranscript(origin, mdoczk.NonceString(nonce), thumb), ""
	default:
		return nil, "mdoc_bundle_malformed"
	}
}

func mobileIDReason(err error) string {
	switch {
	case errors.Is(err, mdoczk.ErrRegistryUnknown):
		return "mdoc_registry_unknown"
	case errors.Is(err, mdoczk.ErrUnknownCircuit):
		return "mdoc_circuit_unsupported"
	case errors.Is(err, mdoczk.ErrTranscript):
		return "mdoc_session_mismatch"
	case errors.Is(err, mdoczk.ErrStaleDate):
		return "mdoc_date_stale"
	case errors.Is(err, mdoczk.ErrScope):
		return "mdoc_scope_mismatch"
	case errors.Is(err, mdoczk.ErrCompanySigned):
		return "mdoc_company_signed"
	case errors.Is(err, mdoczk.ErrDocType):
		return "mdoc_doc_type_unsupported"
	case errors.Is(err, mdoczk.ErrMalformed):
		return "mdoc_bundle_malformed"
	case errors.Is(err, mdoczk.ErrProofInvalid):
		return "mdoc_proof_invalid"
	default:
		return ""
	}
}

func (m *MobileIDMethod) CompleteCeremony(ctx context.Context, cc types.CeremonyContext, resp types.ResponseData) (types.MethodResult, error) {
	if cc.SessionID == "" {
		return fail(MobileIDMethodID, "missing_session_id"), nil
	}
	ch, ok := m.challenges.take(cc.SessionID, m.now())
	if !ok {
		return fail(MobileIDMethodID, "no_challenge_issued"), nil
	}
	holder := holderBinding(cc)
	if ch.holder != holder {
		return fail(MobileIDMethodID, "mdoc_session_mismatch"), nil
	}
	raw, _ := resp.Payload["proof"].(map[string]any)
	if raw == nil {
		return fail(MobileIDMethodID, "mdoc_bundle_malformed"), nil
	}
	name, _ := raw["circuit"].(string)
	proof, err1 := b64Field(raw, "proof_b64", maxProofB64)
	pub, err2 := b64Field(raw, "public_inputs_b64", maxPublicB64)
	if err1 != nil || err2 != nil || proof == nil || pub == nil || name == "" || len(name) > 128 {
		return fail(MobileIDMethodID, "mdoc_bundle_malformed"), nil
	}
	transcript, reason := m.transcript(resp.Payload, mdoczk.Nonce(ch.challenge, holder))
	if reason != "" {
		return fail(MobileIDMethodID, reason), nil
	}
	if fb, ok := parseFaceBind(resp.Payload); !ok {
		return fail(MobileIDMethodID, "face_bind_missing"), nil
	} else if !fb.Match || !fb.Liveness {
		return fail(MobileIDMethodID, "face_bind_failed"), nil
	}

	select {
	case m.sem <- struct{}{}:
	case <-ctx.Done():
		return types.MethodResult{}, ctx.Err()
	}
	res, err := m.verifier.Verify(ctx, mdoczk.Proof{Circuit: name, Proof: proof, PublicInputs: pub}, mdoczk.TranscriptHash(transcript))
	<-m.sem
	if err != nil {
		if r := mobileIDReason(err); r != "" {
			return fail(MobileIDMethodID, r), nil
		}
		return types.MethodResult{}, fmt.Errorf("mobile-id-zk: %w", err)
	}
	identifier := res.Identifier()
	if reason, err := m.checkFace(ctx, MobileIDMethodID, cc.SessionID, identifier, "MDOC", resp.Payload); err != nil {
		return types.MethodResult{}, fmt.Errorf("mobile-id-zk: %w", err)
	} else if reason != "" {
		return fail(MobileIDMethodID, reason), nil
	}
	digest := digestOf(cc.SessionID, "mdoc", hex.EncodeToString(res.RegistryRoot[:]), name)
	if len(m.mc.DigestKey) > 0 {
		mac := hmac.New(sha256.New, m.mc.DigestKey)
		mac.Write([]byte("mobile-id-zk/attestation/v1\x00" + identifier))
		digest = hex.EncodeToString(mac.Sum(nil))
	}
	return types.MethodResult{
		Success:            true,
		MethodID:           MobileIDMethodID,
		VerifiedAt:         m.now(),
		AttestationDigest:  digest,
		VerifiedIdentifier: identifier,
		Strength:           MobileIDStrength,
	}, nil
}

func (m *MobileIDMethod) HealthCheck(_ context.Context) error {
	if len(m.mc.Registry.Entries) == 0 {
		return errors.New("mobile-id-zk: empty IACA registry")
	}
	return nil
}

// RegistryHandler serves the IACA registry (GET .../registry).
func (m *MobileIDMethod) RegistryHandler() http.Handler {
	return jsonHandler(m.mc.Registry, fmt.Sprintf("%q", m.mc.Registry.Root))
}

// CircuitsHandler serves the circuit manifest (GET .../circuits).
func (m *MobileIDMethod) CircuitsHandler() http.Handler {
	return circuitsHandler(m.mc.Circuits, m.mc.ArtifactsBaseURL, m.url("artifacts/"))
}

// ArtifactsHandler serves circuit artifacts and the SRS (GET .../artifacts/<file>).
func (m *MobileIDMethod) ArtifactsHandler() http.Handler {
	return artifactsHandler(m.mc.Circuits, m.mc.ArtifactsDir)
}
