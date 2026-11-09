// Package documentchip implements two Personhood ANCHOR methods built on
// government documents that are cryptographically signed by the issuing
// state, with no vendor and no per-check fee:
//
//   - "document-chip": an ePassport or eID card chip (ICAO 9303), read by
//     the phone over NFC. Passive authentication (icao package) proves a
//     state signed the data; Active Authentication, when the chip has it,
//     proves the chip is the original and not a copy.
//   - "document-signed-qr": a national ID whose QR code is signed by the
//     issuing authority (signedqr package; first format: India's Aadhaar
//     Secure QR). Works with any camera, no NFC.
//
// Uniqueness: one identity per document. The method hands the issuer a
// document identifier (country + document number, or the QR format's
// uniqueness fields), which the issuer turns into HMAC(IDENTIFIER_HMAC_KEY,
// ...) and binds to a nullifier seed, exactly like an email address. The raw
// number, the name and the birth date are never stored.
//
// Binding to the holder: the phone compares the document photo with a live
// selfie and reports match + liveness. The photo stays on the phone.
//
// docs/document-chip-anchor.md says what this does and does not prove.
package documentchip

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"strings"
	"sync"
	"time"

	"github.com/sagearbor/personhood/pkg/types"
	"github.com/sagearbor/personhood/src/methods/document-chip/icao"
	"github.com/sagearbor/personhood/src/methods/document-chip/signedqr"
	fes "github.com/sagearbor/personhood/src/methods/fuzzy-extractor-selfie"
)

type methodPlugin interface {
	Metadata() types.MethodMetadata
	IsAvailableForUser(ctx types.UserContext) (available bool, reason string)
	BeginCeremony(ctx context.Context, cc types.CeremonyContext) (types.ChallengeData, error)
	CompleteCeremony(ctx context.Context, cc types.CeremonyContext, resp types.ResponseData) (types.MethodResult, error)
	HealthCheck(ctx context.Context) error
}

var (
	_ methodPlugin = (*ChipMethod)(nil)
	_ methodPlugin = (*QRMethod)(nil)
)

const (
	ChipMethodID = "document-chip"
	QRMethodID   = "document-signed-qr"
	Version      = "0.1.0"

	// ChipStrength: a state-signed document read from its original chip
	// (Active Authentication), bound on device to a live face, unique per
	// document worldwide. The remaining attacks are renting a real person
	// with their passport, and dual citizens (flagged by face, see
	// ReviewCase). Comparable to a paid KYC vendor without the vendor.
	ChipStrength = 80
	// ChipPassiveOnlyStrength applies when chips without Active
	// Authentication are accepted: a copied chip's files (a "dump", e.g.
	// from a hotel's passport reader) then pass, and only the phone's face
	// match stands between the dump and an enrollment.
	ChipPassiveOnlyStrength = 70
	// QRStrength: a signed QR is a static blob anyone can photograph, so
	// the on-device face match carries all the holder binding. Uniqueness
	// still holds (one card, one identity).
	QRStrength = 60

	freshness    = 365 * 24 * time.Hour
	challengeTTL = 10 * time.Minute

	maxSOD  = 64 << 10
	maxDG1  = 1 << 10
	maxDGxx = 16 << 10
	maxQR   = 8 << 10
)

// FaceIndex is the set of face templates enrolled through document methods,
// used only to notice the same face arriving with a different document. It
// is the fuzzy extractor's accumulator: helper data + commitments, no photos.
type FaceIndex = fes.Accumulator

// Config is shared by both methods.
type Config struct {
	// Trust holds the CSCA certificates (chip method). Required for it.
	Trust *icao.TrustStore
	// QRFormats holds the signed QR formats (QR method). Required for it.
	QRFormats *signedqr.Registry

	// AllowPassiveOnly accepts chips without Active Authentication, at
	// ChipPassiveOnlyStrength. Default false: such chips are refused with
	// "active_auth_unavailable" and the person is pointed to another path.
	AllowPassiveOnly bool

	// FaceBindURL is the page the wallet opens for the selfie-to-document
	// face match (the personhood web app's /face-bind). Passed through.
	FaceBindURL string

	// Faces and Reviews implement the dual-document flag. Both optional;
	// without them no flag is raised.
	Faces   FaceIndex
	Reviews ReviewQueue

	// KnownIdentifier reports whether a document identifier already holds
	// a nullifier seed at this issuer (a re-enrollment, not a new person).
	// Optional; without it a matching face on any document is flagged.
	KnownIdentifier func(ctx context.Context, identifier string) (bool, error)

	// Now is injectable for tests.
	Now func() time.Time
}

type common struct {
	cfg     Config
	faceMu  sync.Mutex
	logFlag func(ReviewCase)
}

func (c *common) now() time.Time {
	if c.cfg.Now != nil {
		return c.cfg.Now().UTC()
	}
	return time.Now().UTC()
}

func fail(id, reason string) types.MethodResult {
	return types.MethodResult{Success: false, MethodID: id, ErrorReason: reason}
}

// checkFace validates the face bind and runs the dual-document check. It
// never refuses on a face match: it records a review case and lets the
// enrollment through (no false lockout for dual citizens).
func (c *common) checkFace(ctx context.Context, methodID, sessionID, identifier, country string, payload map[string]any) (string, error) {
	fb, ok := parseFaceBind(payload)
	if !ok {
		return "face_bind_missing", nil
	}
	if !fb.Match || !fb.Liveness {
		return "face_bind_failed", nil
	}
	tmpl, err := faceTemplate(payload)
	if err != nil {
		return "face_template_invalid", nil
	}
	if tmpl == nil || c.cfg.Faces == nil {
		return "", nil
	}
	c.faceMu.Lock()
	defer c.faceMu.Unlock()
	rec, found, err := c.cfg.Faces.FindDuplicate(ctx, tmpl)
	if err != nil {
		return "", fmt.Errorf("face index lookup: %w", err)
	}
	if found {
		known := false
		if c.cfg.KnownIdentifier != nil {
			if known, err = c.cfg.KnownIdentifier(ctx, identifier); err != nil {
				return "", fmt.Errorf("known identifier: %w", err)
			}
		}
		if !known && c.cfg.Reviews != nil {
			rc := ReviewCase{
				ID: randomID(), SessionID: sessionID, MethodID: methodID,
				MatchedFaceID: rec.Commitment.Hex(), DocumentCountry: country, CreatedAt: c.now(),
			}
			if err := c.cfg.Reviews.Add(ctx, rc); err != nil {
				return "", fmt.Errorf("review queue: %w", err)
			}
			if c.logFlag != nil {
				c.logFlag(rc)
			}
		}
		return "", nil
	}
	helper, commitment, err := fes.Gen(tmpl)
	if err != nil {
		return "", fmt.Errorf("face index gen: %w", err)
	}
	if err := c.cfg.Faces.Add(ctx, fes.EnrollmentRecord{Helper: helper, Commitment: commitment, EnrolledAt: c.now()}); err != nil {
		return "", fmt.Errorf("face index add: %w", err)
	}
	return "", nil
}

func digestOf(parts ...string) string {
	h := sha256.New()
	for _, p := range parts {
		h.Write([]byte(p))
		h.Write([]byte{0})
	}
	return hex.EncodeToString(h.Sum(nil))
}

// ---------------------------------------------------------------- chip

// ChipMethod is the "document-chip" anchor.
type ChipMethod struct {
	common
	challenges *challengeStore
}

// NewChipMethod builds the chip method. A nil Trust panics.
func NewChipMethod(cfg Config, onReview func(ReviewCase)) *ChipMethod {
	if cfg.Trust == nil {
		panic("document-chip: Config.Trust is required")
	}
	return &ChipMethod{common: common{cfg: cfg, logFlag: onReview}, challenges: newChallengeStore(challengeTTL)}
}

func (m *ChipMethod) Metadata() types.MethodMetadata {
	s := ChipStrength
	if m.cfg.AllowPassiveOnly {
		s = ChipPassiveOnlyStrength
	}
	return types.MethodMetadata{
		ID: ChipMethodID, Type: types.MethodTypeAnchor, Strength: s, CostUSD: 0,
		UXFriction: types.FrictionLow, FreshnessLifetime: freshness, Version: Version,
	}
}

func (m *ChipMethod) IsAvailableForUser(ctx types.UserContext) (bool, string) {
	switch strings.ToLower(strings.TrimSpace(ctx.Platform)) {
	case "web", "kiosk":
		return false, "Reading a passport chip needs the Android app on a phone with NFC."
	}
	return true, ""
}

// BeginCeremony issues the Active Authentication challenge. Each challenge
// serves one completion; a retry starts with a new begin (and a new tap).
func (m *ChipMethod) BeginCeremony(_ context.Context, cc types.CeremonyContext) (types.ChallengeData, error) {
	if cc.SessionID == "" {
		return types.ChallengeData{}, errors.New("document-chip: SessionID is required")
	}
	nonce, err := randomBytes(8)
	if err != nil {
		return types.ChallengeData{}, err
	}
	m.challenges.put(cc.SessionID, nonce, m.now())
	return types.ChallengeData{
		Type: "document-chip-challenge",
		Payload: map[string]any{
			"aa_challenge_hex":    hex.EncodeToString(nonce),
			"face_bind_url":       m.cfg.FaceBindURL,
			"require_active_auth": !m.cfg.AllowPassiveOnly,
			"complete_endpoint":   "/v1/methods/" + ChipMethodID + "/complete",
		},
	}, nil
}

func (m *ChipMethod) CompleteCeremony(ctx context.Context, cc types.CeremonyContext, resp types.ResponseData) (types.MethodResult, error) {
	if cc.SessionID == "" {
		return fail(ChipMethodID, "missing_session_id"), nil
	}
	challenge, ok := m.challenges.take(cc.SessionID, m.now())
	if !ok {
		return fail(ChipMethodID, "no_challenge_issued"), nil
	}
	p := resp.Payload
	sodRaw, err1 := b64Field(p, "sod_b64", maxSOD)
	dg1, err2 := b64Field(p, "dg1_b64", maxDG1)
	dg14, err3 := b64Field(p, "dg14_b64", maxDGxx)
	dg15, err4 := b64Field(p, "dg15_b64", maxDGxx)
	aaSig, err5 := b64Field(p, "aa_signature_b64", maxDGxx)
	if err := errors.Join(err1, err2, err3, err4, err5); err != nil || sodRaw == nil || dg1 == nil {
		return fail(ChipMethodID, "sod_invalid"), nil
	}

	sod, err := icao.ParseSOD(sodRaw)
	if err != nil {
		return fail(ChipMethodID, chipReason(err)), nil
	}
	pa, err := sod.VerifySignature(m.cfg.Trust)
	if err != nil {
		return fail(ChipMethodID, chipReason(err)), nil
	}
	if err := sod.CheckDataGroup(1, dg1); err != nil {
		return fail(ChipMethodID, "dg_hash_mismatch"), nil
	}
	mrz, err := icao.ParseDG1(dg1)
	if err != nil {
		return fail(ChipMethodID, "mrz_invalid"), nil
	}
	if expired, err := mrz.Expired(m.now()); err != nil {
		return fail(ChipMethodID, "mrz_invalid"), nil
	} else if expired {
		return fail(ChipMethodID, "document_expired"), nil
	}

	// Active Authentication. If the signed SOD lists DG15, the chip has an
	// AA key and AA is mandatory: otherwise a clone could simply omit DG15.
	aa := "none"
	if sod.HasDataGroup(15) {
		if dg15 == nil || aaSig == nil {
			return fail(ChipMethodID, "active_auth_missing"), nil
		}
		if sod.CheckDataGroup(15, dg15) != nil {
			return fail(ChipMethodID, "dg_hash_mismatch"), nil
		}
		if dg14 != nil && sod.CheckDataGroup(14, dg14) != nil {
			return fail(ChipMethodID, "dg_hash_mismatch"), nil
		}
		if err := icao.VerifyActiveAuth(dg15, dg14, challenge, aaSig); err != nil {
			return fail(ChipMethodID, "active_auth_failed"), nil
		}
		aa = "verified"
	} else if !m.cfg.AllowPassiveOnly {
		return fail(ChipMethodID, "active_auth_unavailable"), nil
	}

	identifier := ChipIdentifier(pa.Country, mrz.DocumentNumber)
	if reason, err := m.checkFace(ctx, ChipMethodID, cc.SessionID, identifier, pa.Country, p); err != nil {
		return types.MethodResult{}, fmt.Errorf("document-chip: %w", err)
	} else if reason != "" {
		return fail(ChipMethodID, reason), nil
	}

	dscFP := sha256.Sum256(pa.DSC.Raw)
	return types.MethodResult{
		Success:            true,
		MethodID:           ChipMethodID,
		VerifiedAt:         m.now(),
		AttestationDigest:  digestOf(cc.SessionID, pa.Country, hex.EncodeToString(dscFP[:]), aa),
		VerifiedIdentifier: identifier,
	}, nil
}

func (m *ChipMethod) HealthCheck(_ context.Context) error {
	if m.cfg.Trust.Len() == 0 {
		return errors.New("document-chip: no CSCA certificates loaded")
	}
	return nil
}

// ChipIdentifier is the uniqueness identifier for a chip document: the
// issuing state (from the trusted CSCA, so a state can only mint numbers in
// its own namespace) and the document number. It is hashed here and keyed
// again by the issuer, and never stored as is.
func ChipIdentifier(country, documentNumber string) string {
	n := strings.ToUpper(strings.ReplaceAll(strings.TrimSpace(documentNumber), "<", ""))
	sum := sha256.Sum256([]byte("personhood/document-number/v1\x00" + strings.ToUpper(country) + "\x00" + n))
	return "chip:" + strings.ToUpper(country) + ":" + hex.EncodeToString(sum[:])
}

func chipReason(err error) string {
	switch {
	case errors.Is(err, icao.ErrUnsupportedAlgorithm):
		return "signature_unsupported"
	case errors.Is(err, icao.ErrUntrusted):
		return "csca_untrusted"
	default:
		return "sod_invalid"
	}
}

// ------------------------------------------------------------------ QR

// QRMethod is the "document-signed-qr" anchor.
type QRMethod struct {
	common
}

// NewQRMethod builds the QR method. A nil QRFormats panics.
func NewQRMethod(cfg Config, onReview func(ReviewCase)) *QRMethod {
	if cfg.QRFormats == nil {
		panic("document-signed-qr: Config.QRFormats is required")
	}
	return &QRMethod{common: common{cfg: cfg, logFlag: onReview}}
}

func (m *QRMethod) Metadata() types.MethodMetadata {
	return types.MethodMetadata{
		ID: QRMethodID, Type: types.MethodTypeAnchor, Strength: QRStrength, CostUSD: 0,
		UXFriction: types.FrictionLow, FreshnessLifetime: freshness, Version: Version,
	}
}

func (m *QRMethod) IsAvailableForUser(ctx types.UserContext) (bool, string) {
	switch strings.ToLower(strings.TrimSpace(ctx.Platform)) {
	case "web", "kiosk":
		return false, "Scanning an ID card's QR code needs the phone app (it matches your face to the card photo on the phone)."
	}
	return true, ""
}

func (m *QRMethod) BeginCeremony(_ context.Context, cc types.CeremonyContext) (types.ChallengeData, error) {
	if cc.SessionID == "" {
		return types.ChallengeData{}, errors.New("document-signed-qr: SessionID is required")
	}
	return types.ChallengeData{
		Type: "document-signed-qr-challenge",
		Payload: map[string]any{
			"formats":           m.cfg.QRFormats.IDs(),
			"face_bind_url":     m.cfg.FaceBindURL,
			"complete_endpoint": "/v1/methods/" + QRMethodID + "/complete",
		},
	}, nil
}

func (m *QRMethod) CompleteCeremony(ctx context.Context, cc types.CeremonyContext, resp types.ResponseData) (types.MethodResult, error) {
	if cc.SessionID == "" {
		return fail(QRMethodID, "missing_session_id"), nil
	}
	qr, _ := resp.Payload["qr_text"].(string)
	format, _ := resp.Payload["format"].(string)
	if strings.TrimSpace(qr) == "" || len(qr) > maxQR {
		return fail(QRMethodID, "qr_invalid"), nil
	}
	res, err := m.cfg.QRFormats.Verify(qr, strings.TrimSpace(format))
	if err != nil {
		switch {
		case errors.Is(err, signedqr.ErrSignatureInvalid):
			return fail(QRMethodID, "qr_signature_invalid"), nil
		case errors.Is(err, signedqr.ErrFormatUnknown):
			return fail(QRMethodID, "qr_format_unknown"), nil
		default:
			return fail(QRMethodID, "qr_invalid"), nil
		}
	}
	identifier := "qr:" + res.UniqueKey
	if reason, err := m.checkFace(ctx, QRMethodID, cc.SessionID, identifier, res.Country, resp.Payload); err != nil {
		return types.MethodResult{}, fmt.Errorf("document-signed-qr: %w", err)
	} else if reason != "" {
		return fail(QRMethodID, reason), nil
	}
	return types.MethodResult{
		Success:            true,
		MethodID:           QRMethodID,
		VerifiedAt:         m.now(),
		AttestationDigest:  digestOf(cc.SessionID, res.FormatID, res.SignedAt.Format(time.RFC3339)),
		VerifiedIdentifier: identifier,
	}, nil
}

func (m *QRMethod) HealthCheck(_ context.Context) error { return nil }

// IsDocumentIdentifier reports whether s has the shape this package's
// identifiers have ("chip:CC:<64 hex>", "qr:CC-doc:<64 hex>", or
// "mdoc:ZK:<64 hex>" from mobile-id-zk).
func IsDocumentIdentifier(s string) bool {
	var rest string
	switch {
	case strings.HasPrefix(s, "chip:"):
		rest = s[len("chip:"):]
	case strings.HasPrefix(s, "qr:"):
		rest = s[len("qr:"):]
	case strings.HasPrefix(s, "mdoc:"):
		rest = s[len("mdoc:"):]
	default:
		return false
	}
	i := strings.LastIndexByte(rest, ':')
	if i <= 0 || len(rest)-i-1 != 64 {
		return false
	}
	_, err := hex.DecodeString(rest[i+1:])
	return err == nil
}
