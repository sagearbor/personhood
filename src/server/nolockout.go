package server

// Never false-lockout an honest person (Config.NoFalseLockout, env
// NO_FALSE_LOCKOUT). docs/08-no-false-lockout.md is the design; this file
// holds the shared pieces:
//
//   - LockoutConfig and its env loader;
//   - lockoutStore, the durable records (face matches per session, an
//     index from nullifier commitment to its current holder, recoveries,
//     reviews), on the same Firestore / Redis / memory kv as the holder
//     ledger;
//   - face-match ROUTING: when the selfie dedupe matches an enrolled face,
//     the issuer records which face (server-side only) and answers with
//     next steps instead of a dead end:
//       1. "This might be you": POST /v1/recovery/start (recovery.go).
//       2. "Not you (twin or look-alike)": POST /v1/face-match/decline,
//          then another anchor (in-person vouch with extra vouchers, a
//          document, or the manual review queue).
//       3. Manual review: POST /v1/reviews (review.go).
//     The matched face never becomes this session's nullifier, and a
//     declined match can never move that identity.
//   - the same holder key re-enrolling its own face (a wallet that kept its
//     key but lost its credential) is re-issued at once.
//
// Signals still route, raise friction or ask for review; none of the paths
// here refuses an honest person without telling them what to do next.

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/sagearbor/personhood/pkg/types"
	fuzzyextractorselfie "github.com/sagearbor/personhood/src/methods/fuzzy-extractor-selfie"
)

// LockoutConfig tunes the no-false-lockout paths. Zero fields take the
// defaults in withDefaults.
type LockoutConfig struct {
	// RecoveryDelay is the window between starting a recovery and being
	// able to complete it, during which the old key can cancel. Default
	// 72h. Env RECOVERY_DELAY (a Go duration, e.g. "72h" or "2m" for a
	// test deployment).
	RecoveryDelay time.Duration
	// RecoveryCooldown: after a completed recovery, the same identity can
	// not be recovered again for this long (stops a ping-pong between an
	// owner and a thief); the person is pointed at manual review instead.
	// Default 30 days. Env RECOVERY_COOLDOWN.
	RecoveryCooldown time.Duration
	// MaxCancelledRecoveries in RecoveryCooldown before further attempts
	// on an identity go to manual review only. Default 3.
	MaxCancelledRecoveries int
	// RecoveryVouches is how many of the old holder's in-person vouchers
	// must re-vouch for the new key for the voucher factor. Default 2.
	// Env RECOVERY_VOUCHES.
	RecoveryVouches int
	// RecoveryDocumentMethods lists anchor methods whose attestation
	// digest is stable per document (a document-chip anchor), so the same
	// document proves the same person. Empty by default. Env
	// RECOVERY_DOCUMENT_METHODS (comma-separated).
	RecoveryDocumentMethods []string
	// FaceMatchExtraVouches is added to the in-person-vouch K for a session
	// whose face matched someone else's and was declined (twin or
	// look-alike). Default 2. Env FACE_MATCH_EXTRA_VOUCHES.
	FaceMatchExtraVouches int
	// FaceMatchMaxOthers caps how many different holders may be issued a
	// credential through a declined match on one enrolled face (twins,
	// triplets); past that only manual review. Default 2. Env
	// FACE_MATCH_MAX_OTHERS.
	FaceMatchMaxOthers int
	// NotifyWebhook, when set, receives a JSON POST for every recovery
	// event (started, cancelled, completed) naming the old holder DID, so
	// an integrator can push it to the old key's wallet. Env
	// RECOVERY_NOTIFY_WEBHOOK.
	NotifyWebhook string
}

func (c LockoutConfig) withDefaults() LockoutConfig {
	if c.RecoveryDelay <= 0 {
		c.RecoveryDelay = 72 * time.Hour
	}
	if c.RecoveryCooldown <= 0 {
		c.RecoveryCooldown = 30 * 24 * time.Hour
	}
	if c.MaxCancelledRecoveries <= 0 {
		c.MaxCancelledRecoveries = 3
	}
	if c.RecoveryVouches <= 0 {
		c.RecoveryVouches = 2
	}
	if c.FaceMatchExtraVouches < 0 {
		c.FaceMatchExtraVouches = 0
	} else if c.FaceMatchExtraVouches == 0 {
		c.FaceMatchExtraVouches = 2
	}
	if c.FaceMatchMaxOthers <= 0 {
		c.FaceMatchMaxOthers = 2
	}
	return c
}

func lockoutConfigFromEnv() (LockoutConfig, error) {
	var c LockoutConfig
	durs := []struct {
		env string
		dst *time.Duration
	}{
		{"RECOVERY_DELAY", &c.RecoveryDelay},
		{"RECOVERY_COOLDOWN", &c.RecoveryCooldown},
	}
	for _, d := range durs {
		if v := strings.TrimSpace(os.Getenv(d.env)); v != "" {
			dur, err := time.ParseDuration(v)
			if err != nil || dur < time.Minute {
				return c, fmt.Errorf("%s: want a duration of at least 1m (e.g. 72h), got %q", d.env, v)
			}
			*d.dst = dur
		}
	}
	ints := []struct {
		env string
		dst *int
	}{
		{"RECOVERY_VOUCHES", &c.RecoveryVouches},
		{"FACE_MATCH_EXTRA_VOUCHES", &c.FaceMatchExtraVouches},
		{"FACE_MATCH_MAX_OTHERS", &c.FaceMatchMaxOthers},
	}
	for _, f := range ints {
		if v := strings.TrimSpace(os.Getenv(f.env)); v != "" {
			n, err := strconv.Atoi(v)
			if err != nil || n < 1 || n > 16 {
				return c, fmt.Errorf("%s: want an integer 1..16, got %q", f.env, v)
			}
			*f.dst = n
		}
	}
	c.RecoveryDocumentMethods = splitCSV(os.Getenv("RECOVERY_DOCUMENT_METHODS"))
	c.NotifyWebhook = strings.TrimSpace(os.Getenv("RECOVERY_NOTIFY_WEBHOOK"))
	return c, nil
}

// nextStep is one way forward offered with a refusal or a routing answer.
type nextStep struct {
	Action      string   `json:"action"`
	Endpoint    string   `json:"endpoint,omitempty"`
	Methods     []string `json:"methods,omitempty"`
	Description string   `json:"description"`
}

// faceMatchRouting is returned with a selfie result whose face matched an
// enrolled person (completeMethodResponse.FaceMatch).
type faceMatchRouting struct {
	Message string     `json:"message"`
	Options []nextStep `json:"options"`
}

// writeErrorNext is writeError plus the ways forward.
func writeErrorNext(w http.ResponseWriter, status int, code, message string, next []nextStep, extra map[string]any) {
	body := map[string]any{"code": code, "message": message}
	if len(next) > 0 {
		body["next_steps"] = next
	}
	for k, v := range extra {
		body[k] = v
	}
	writeJSON(w, status, map[string]any{"error": body})
}

// SelfieMatchRelay connects the selfie method's OnMatch hook, which is
// built before the Server exists (BuildDependencies), to the Server.
type SelfieMatchRelay struct {
	mu sync.RWMutex
	fn fuzzyextractorselfie.MatchFunc
}

// OnMatch is the fuzzyextractorselfie.Config.OnMatch to pass in.
func (r *SelfieMatchRelay) OnMatch(ctx context.Context, sessionID string, c fuzzyextractorselfie.Commitment) error {
	r.mu.RLock()
	fn := r.fn
	r.mu.RUnlock()
	if fn == nil {
		return nil
	}
	return fn(ctx, sessionID, c)
}

func (r *SelfieMatchRelay) set(fn fuzzyextractorselfie.MatchFunc) {
	r.mu.Lock()
	r.fn = fn
	r.mu.Unlock()
}

// wireNoFalseLockout opens the store, hooks the selfie relay and, with an
// admin token, registers the operator-review anchor.
func (s *Server) wireNoFalseLockout(relay *SelfieMatchRelay) error {
	if s.holders == nil {
		return fmt.Errorf("server: NO_FALSE_LOCKOUT needs HOLDER_REVOCATION_ENABLED")
	}
	k, err := newKVFromEnv()
	if err != nil {
		return fmt.Errorf("server: no-false-lockout store: %w", err)
	}
	s.lockout = &lockoutStore{kv: k}
	s.cfg.Lockout = s.cfg.Lockout.withDefaults()
	if relay != nil {
		relay.set(s.recordFaceMatch)
	}
	if s.cfg.AdminToken != "" {
		if err := s.registry.Register(operatorReviewMethod{s: s}); err != nil {
			return fmt.Errorf("register %s: %w", OperatorReviewMethodID, err)
		}
	}
	return nil
}

// ----------------------------------------------------------------------------
// Store
// ----------------------------------------------------------------------------

const (
	nsFaceMatches     = "personhood-face-matches"
	nsIdentityIndex   = "personhood-identity-index"
	nsIdentityLinks   = "personhood-identity-links"
	nsFaceMatchOthers = "personhood-face-match-others"
	nsRecoveries      = "personhood-recoveries"
	nsRecoveryByKey   = "personhood-recovery-pointers"
	nsRecoveryHistory = "personhood-recovery-history"
	nsReviews         = "personhood-reviews"
	nsReviewOpen      = "personhood-review-open"
	nsReviewApprovals = "personhood-review-approvals"
)

// lockoutStore keeps the no-false-lockout records. Read-modify-writes take
// mu: safe while the issuer runs as one instance, like kvHolderLedger.
type lockoutStore struct {
	kv kv
	mu sync.Mutex
}

func (l *lockoutStore) getJSON(ctx context.Context, ns, id string, dst any) (bool, error) {
	raw, found, err := l.kv.get(ctx, ns, id)
	if err != nil || !found {
		return false, err
	}
	if err := json.Unmarshal(raw, dst); err != nil {
		return false, fmt.Errorf("server: corrupt %s record: %w", ns, err)
	}
	return true, nil
}

func (l *lockoutStore) setJSON(ctx context.Context, ns, id string, v any) error {
	b, err := json.Marshal(v)
	if err != nil {
		return err
	}
	return l.kv.set(ctx, ns, id, b)
}

// faceMatchDoc records, per session, which enrolled face its selfie matched.
type faceMatchDoc struct {
	Commitment string    `json:"commitment"`
	At         time.Time `json:"at"`
	// Declined: the person said the match is not them (a twin or a
	// look-alike) and continues with another anchor.
	Declined bool `json:"declined,omitempty"`
}

func (l *lockoutStore) faceMatch(ctx context.Context, sessionID string) (faceMatchDoc, bool, error) {
	var d faceMatchDoc
	found, err := l.getJSON(ctx, nsFaceMatches, sha256Hex(sessionID), &d)
	return d, found, err
}

func (l *lockoutStore) putFaceMatch(ctx context.Context, sessionID string, d faceMatchDoc) error {
	return l.setJSON(ctx, nsFaceMatches, sha256Hex(sessionID), d)
}

// identityDoc maps a nullifier commitment (or a document attestation) to
// the holder that was last issued a credential on it.
type identityDoc struct {
	HolderDID types.DID `json:"holder_did"`
	At        time.Time `json:"at"`
}

func identityKeyNullifier(commitment string) string { return "nullifier:" + commitment }
func identityKeyAttestation(methodID, digest string) string {
	return "attestation:" + methodID + ":" + digest
}

func (l *lockoutStore) holderOf(ctx context.Context, key string) (types.DID, bool, error) {
	var d identityDoc
	found, err := l.getJSON(ctx, nsIdentityIndex, sha256Hex(key), &d)
	return d.HolderDID, found, err
}

func (l *lockoutStore) setHolderOf(ctx context.Context, key string, holder types.DID, at time.Time) error {
	return l.setJSON(ctx, nsIdentityIndex, sha256Hex(key), identityDoc{HolderDID: holder, At: at})
}

// linksDoc lists, per face identity (keyed by its biometric nullifier
// commitment), every other proof that was ever issued together with it: the
// email/phone seed commitments and document attestations. A recovery factor
// is "this session proves one of these". Kept per identity, not per holder,
// so it survives the identity moving between keys.
type linksDoc struct {
	Keys []string `json:"keys"`
}

func (l *lockoutStore) identityLinks(ctx context.Context, bioNB string) (map[string]bool, error) {
	var d linksDoc
	if _, err := l.getJSON(ctx, nsIdentityLinks, sha256Hex(bioNB), &d); err != nil {
		return nil, err
	}
	out := make(map[string]bool, len(d.Keys))
	for _, k := range d.Keys {
		out[k] = true
	}
	return out, nil
}

func (l *lockoutStore) addIdentityLinks(ctx context.Context, bioNB string, keys []string) error {
	if len(keys) == 0 {
		return nil
	}
	l.mu.Lock()
	defer l.mu.Unlock()
	var d linksDoc
	if _, err := l.getJSON(ctx, nsIdentityLinks, sha256Hex(bioNB), &d); err != nil {
		return err
	}
	have := map[string]bool{}
	for _, k := range d.Keys {
		have[k] = true
	}
	for _, k := range keys {
		if !have[k] {
			d.Keys, have[k] = append(d.Keys, k), true
		}
	}
	return l.setJSON(ctx, nsIdentityLinks, sha256Hex(bioNB), d)
}

// othersDoc lists the holders issued a credential through a declined match
// on one enrolled face.
type othersDoc struct {
	Holders []types.DID `json:"holders"`
}

func (l *lockoutStore) faceMatchOthers(ctx context.Context, commitment string) ([]types.DID, error) {
	var d othersDoc
	_, err := l.getJSON(ctx, nsFaceMatchOthers, sha256Hex(commitment), &d)
	return d.Holders, err
}

func (l *lockoutStore) addFaceMatchOther(ctx context.Context, commitment string, holder types.DID) error {
	l.mu.Lock()
	defer l.mu.Unlock()
	var d othersDoc
	if _, err := l.getJSON(ctx, nsFaceMatchOthers, sha256Hex(commitment), &d); err != nil {
		return err
	}
	for _, h := range d.Holders {
		if h == holder {
			return nil
		}
	}
	d.Holders = append(d.Holders, holder)
	return l.setJSON(ctx, nsFaceMatchOthers, sha256Hex(commitment), d)
}

// ----------------------------------------------------------------------------
// Face-match routing
// ----------------------------------------------------------------------------

// recordFaceMatch is the selfie method's OnMatch hook.
func (s *Server) recordFaceMatch(ctx context.Context, sessionID string, c fuzzyextractorselfie.Commitment) error {
	return s.lockout.putFaceMatch(ctx, sessionID, faceMatchDoc{Commitment: c.Hex(), At: s.nowFunc()})
}

// routeFaceMatch runs after a selfie was refused as a duplicate. If the
// session's own holder key already holds that face's identity, it is
// re-issued (the result becomes a success). Otherwise it returns the next
// steps.
func (s *Server) routeFaceMatch(ctx context.Context, sess SessionView, method types.MethodMetadata) (types.MethodResult, *faceMatchRouting, error) {
	fm, found, err := s.lockout.faceMatch(ctx, sess.ID)
	if err != nil || !found {
		return types.MethodResult{}, nil, err
	}
	holder, known, err := s.lockout.holderOf(ctx, identityKeyNullifier(NullifierBindingForBiometricCommitment(fm.Commitment).Commitment))
	if err != nil {
		return types.MethodResult{}, nil, err
	}
	if known && holder == sess.HolderDID && strings.HasPrefix(string(holder), "did:key:") {
		res := types.MethodResult{Success: true, MethodID: method.ID, VerifiedAt: s.nowFunc(), AttestationDigest: fm.Commitment}
		if err := s.sessions.RecordMethodResult(sess.ID, res, method); err != nil {
			return types.MethodResult{}, nil, err
		}
		return res, nil, nil
	}
	return types.MethodResult{}, s.faceMatchOptions(), nil
}

// faceMatchOptions lists what a person whose face matched can do next.
func (s *Server) faceMatchOptions() *faceMatchRouting {
	var others []string
	for _, m := range s.registry.List() {
		md := m.Metadata()
		if md.Type == types.MethodTypeAnchor && !isSelfieMethod(md.ID) && md.ID != OperatorReviewMethodID {
			others = append(others, md.ID)
		}
	}
	r := &faceMatchRouting{
		Message: "This face looks like someone who is already enrolled. That can be you on a new phone, or a twin or look-alike. Nobody is refused for a face alone: pick what fits.",
		Options: []nextStep{
			{
				Action:      "recover",
				Endpoint:    "/v1/recovery/start",
				Description: fmt.Sprintf("This might be you: recover your identity onto this phone. Needs one more proof (your original email or phone, %d of your vouchers meeting you again, or the same document), then a %s wait during which your old phone can cancel.", s.cfg.Lockout.RecoveryVouches, humanDuration(s.cfg.Lockout.RecoveryDelay)),
			},
			{
				Action:      "other_anchor",
				Endpoint:    "/v1/face-match/decline",
				Methods:     others,
				Description: "Not you (a twin or a look-alike): continue with another anchor. Your selfie is not used, so you get your own identity, not theirs.",
			},
		},
	}
	if s.reviewsEnabled() {
		r.Options = append(r.Options, nextStep{
			Action:      "manual_review",
			Endpoint:    "/v1/reviews",
			Description: "Ask a person at the issuer to review your case.",
		})
	}
	return r
}

type faceMatchDeclineRequest struct {
	SessionID string `json:"session_id"`
}

// handleFaceMatchDecline is POST /v1/face-match/decline: the person says
// the matched face is not theirs. The session may then use another anchor
// (in-person vouching asks for FaceMatchExtraVouches more vouchers), and
// can no longer start a recovery of the matched identity.
func (s *Server) handleFaceMatchDecline(w http.ResponseWriter, r *http.Request) {
	var req faceMatchDeclineRequest
	if err := decodeJSON(r, &req); err != nil {
		writeError(w, 400, "invalid_request", err.Error())
		return
	}
	sess, err := s.sessions.Get(req.SessionID)
	if err != nil {
		writeError(w, 404, "session_not_found", err.Error())
		return
	}
	ctx := r.Context()
	fm, found, err := s.lockout.faceMatch(ctx, sess.ID)
	if err != nil {
		writeError(w, 500, "store_failed", err.Error())
		return
	}
	if !found {
		writeError(w, 409, "no_face_match", "this session's selfie did not match anyone; nothing to decline")
		return
	}
	active, err := s.activeRecoveryFor(ctx, sess.HolderDID)
	if err != nil {
		writeError(w, 500, "store_failed", err.Error())
		return
	}
	if active != "" {
		writeError(w, 409, "recovery_pending", "this holder key has a recovery in progress; cancel it before choosing another anchor")
		return
	}
	fm.Declined = true
	if err := s.lockout.putFaceMatch(ctx, sess.ID, fm); err != nil {
		writeError(w, 500, "store_failed", err.Error())
		return
	}
	writeJSON(w, 200, map[string]any{
		"declined":      true,
		"extra_vouches": s.cfg.Lockout.FaceMatchExtraVouches,
		"options":       s.faceMatchOptions().Options[1:],
	})
}

// faceMatchDeclined reports whether sess matched a face and declined it.
func (s *Server) faceMatchDeclined(ctx context.Context, sessionID string) (faceMatchDoc, bool, error) {
	fm, found, err := s.lockout.faceMatch(ctx, sessionID)
	if err != nil || !found || !fm.Declined {
		return faceMatchDoc{}, false, err
	}
	return fm, true, nil
}

// checkDeclinedVouches asks a declined-match session for K + extra
// in-person vouchers. It returns a replacement failure reason, or "".
func (s *Server) checkDeclinedVouches(ctx context.Context, sess SessionView) (string, error) {
	if s.inPerson == nil {
		return "", nil
	}
	if _, declined, err := s.faceMatchDeclined(ctx, sess.ID); err != nil || !declined {
		return "", err
	}
	have, err := s.inPerson.AnchorVouchers(ctx, string(sess.HolderDID))
	if err != nil {
		return "", err
	}
	need := s.inPerson.Required() + s.cfg.Lockout.FaceMatchExtraVouches
	if len(have) < need {
		return fmt.Sprintf("insufficient_vouches:have=%d/%d", len(have), need), nil
	}
	return "", nil
}

// lockoutIssuanceCheck runs before issuance: a holder with a recovery in
// progress gets nothing else, and a declined match is capped per face.
func (s *Server) lockoutIssuanceCheck(ctx context.Context, view SessionView) (int, string, string, []nextStep, error) {
	if active, err := s.activeRecoveryFor(ctx, view.HolderDID); err != nil {
		return 0, "", "", nil, err
	} else if active != "" {
		return 409, "recovery_pending", "this holder key has a recovery in progress; finish it with POST /v1/recovery/{id}/complete or cancel it first", nil, nil
	}
	fm, declined, err := s.faceMatchDeclined(ctx, view.ID)
	if err != nil || !declined || hasVerified(view, OperatorReviewMethodID) {
		return 0, "", "", nil, err
	}
	others, err := s.lockout.faceMatchOthers(ctx, fm.Commitment)
	if err != nil {
		return 0, "", "", nil, err
	}
	for _, h := range others {
		if h == view.HolderDID {
			return 0, "", "", nil, nil
		}
	}
	if len(others) >= s.cfg.Lockout.FaceMatchMaxOthers {
		var next []nextStep
		if s.reviewsEnabled() {
			next = append(next, nextStep{Action: "manual_review", Endpoint: "/v1/reviews", Description: "Several people already enrolled with a face like this one. A person at the issuer can review your case."})
		}
		return 403, "face_match_limit", "several people have already enrolled through a match on this face; this case needs a manual review", next, nil
	}
	return 0, "", "", nil, nil
}

// lockoutRecordIssuance runs after a credential is issued: it points every
// nullifier commitment the session used at this holder, links a face
// identity to the email/phone seeds and documents issued with it, and
// counts a declined match.
func (s *Server) lockoutRecordIssuance(ctx context.Context, view SessionView, commitments []string) error {
	now := s.nowFunc()
	for _, c := range commitments {
		if err := s.lockout.setHolderOf(ctx, identityKeyNullifier(c), view.HolderDID, now); err != nil {
			return err
		}
	}
	if bio := selfieCommitment(view.VerifiedMethods); bio != "" {
		bioNB := NullifierBindingForBiometricCommitment(bio).Commitment
		holderNB := ""
		if b := NullifierBindingForHolder(view.HolderPublicKey); b != nil {
			holderNB = b.Commitment
		}
		var links []string
		for _, c := range commitments {
			if c != bioNB && c != holderNB {
				links = append(links, identityKeyNullifier(c))
			}
		}
		for _, vm := range view.VerifiedMethods {
			if contains(s.cfg.Lockout.RecoveryDocumentMethods, vm.MethodID) && vm.AttestationDigest != "" {
				links = append(links, identityKeyAttestation(vm.MethodID, vm.AttestationDigest))
			}
		}
		if err := s.lockout.addIdentityLinks(ctx, bioNB, links); err != nil {
			return err
		}
	}
	if fm, declined, err := s.faceMatchDeclined(ctx, view.ID); err != nil {
		return err
	} else if declined {
		return s.lockout.addFaceMatchOther(ctx, fm.Commitment, view.HolderDID)
	}
	return nil
}

func hasVerified(view SessionView, methodID string) bool {
	for _, vm := range view.VerifiedMethods {
		if vm.MethodID == methodID {
			return true
		}
	}
	return false
}

func humanDuration(d time.Duration) string {
	switch {
	case d >= 48*time.Hour && d%(24*time.Hour) == 0:
		return fmt.Sprintf("%d-day", int(d/(24*time.Hour)))
	case d >= time.Hour && d%time.Hour == 0:
		return fmt.Sprintf("%d-hour", int(d/time.Hour))
	default:
		return fmt.Sprintf("%d-minute", int(d.Round(time.Minute)/time.Minute))
	}
}
