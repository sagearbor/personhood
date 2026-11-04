package server

// Identity recovery (lost, broken or stolen phone), under NO_FALSE_LOCKOUT.
//
// A recovery moves an existing identity, meaning the same nullifier seed,
// to a new holder key. The old key's credentials are revoked and the old
// key is barred from new credentials; the new key is issued a credential
// with the SAME nullifierBinding, so every integrator still sees one person.
//
// A face match alone is never enough: a look-alike would steal the
// identity. Starting a recovery needs, in the new key's session:
//
//   - a selfie that matched the identity's enrolled face, AND
//   - at least one more factor:
//       identifier: an email or phone that was once issued together with
//                   this face, verified again;
//       vouchers:   RecoveryVouches of the old holder's in-person vouchers
//                   vouched in person for the new key;
//       document:   a RecoveryDocumentMethods anchor whose attestation was
//                   once issued together with this face (the same chip);
//     or an operator's approval of a manual review.
//
// Then a delay (RecoveryDelay, 72 h by default) during which either key can
// cancel. The old key's holder learns of it from GET
// /v1/recovery/pending?holder_did=... (its wallet polls) and, when
// configured, a webhook. Rate limits: one recovery in progress per
// identity; none for RecoveryCooldown after one completes; after
// MaxCancelledRecoveries cancelled attempts in that window, manual review
// only. Each of those refusals names the way forward.
//
// Routes:
//
//	POST /v1/recovery/start            {session_id}
//	GET  /v1/recovery/{id}
//	GET  /v1/recovery/pending?holder_did=did:key:...
//	POST /v1/recovery/{id}/cancel      {holder_did, signature_b64}
//	POST /v1/recovery/{id}/complete    {session_id}   (a session of the new key)

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"net/http"
	"strings"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/sagearbor/personhood/pkg/types"
	fuzzyextractorselfie "github.com/sagearbor/personhood/src/methods/fuzzy-extractor-selfie"
)

// Recovery factors.
const (
	FactorIdentifier     = "identifier"
	FactorVouchers       = "vouchers"
	FactorDocument       = "document"
	FactorOperatorReview = "operator_review"
)

// Recovery states.
const (
	RecoveryPending   = "pending"
	RecoveryCancelled = "cancelled"
	RecoveryCompleted = "completed"
)

// recoveryDoc is one recovery request.
type recoveryDoc struct {
	ID         string    `json:"id"`
	OldHolder  types.DID `json:"old_holder"`
	NewHolder  types.DID `json:"new_holder"`
	Commitment string    `json:"commitment"` // the face's fuzzy-extractor commitment
	Factors    []string  `json:"factors"`
	Status     string    `json:"status"`
	CreatedAt  time.Time `json:"created_at"`
	ExecutesAt time.Time `json:"executes_at"`
	ClosedAt   time.Time `json:"closed_at,omitempty"`
	ClosedBy   string    `json:"closed_by,omitempty"` // "old_key", "new_key"
}

// recoveryHistory is kept per identity (per face commitment).
type recoveryHistory struct {
	Active    string      `json:"active,omitempty"`
	Completed []time.Time `json:"completed,omitempty"`
	Cancelled []time.Time `json:"cancelled,omitempty"`
}

type recoveryPointer struct {
	ID string `json:"id"`
}

// RecoveryCancelMessage is what the old or the new holder key signs to
// cancel recovery id.
func RecoveryCancelMessage(issuerDID types.DID, id string) string {
	return "personhood-recovery/v1\ncancel\n" + string(issuerDID) + "\n" + id
}

func (l *lockoutStore) recovery(ctx context.Context, id string) (recoveryDoc, bool, error) {
	var d recoveryDoc
	found, err := l.getJSON(ctx, nsRecoveries, id, &d)
	return d, found, err
}

func (l *lockoutStore) history(ctx context.Context, commitment string) (recoveryHistory, error) {
	var h recoveryHistory
	_, err := l.getJSON(ctx, nsRecoveryHistory, sha256Hex(commitment), &h)
	return h, err
}

// activeRecoveryFor returns the id of the pending recovery holder is the
// old or the new key of, or "".
func (s *Server) activeRecoveryFor(ctx context.Context, holder types.DID) (string, error) {
	if s.lockout == nil {
		return "", nil
	}
	var p recoveryPointer
	found, err := s.lockout.getJSON(ctx, nsRecoveryByKey, sha256Hex(string(holder)), &p)
	if err != nil || !found || p.ID == "" {
		return "", err
	}
	d, found, err := s.lockout.recovery(ctx, p.ID)
	if err != nil || !found || d.Status != RecoveryPending {
		return "", err
	}
	return d.ID, nil
}

func pruneSince(ts []time.Time, since time.Time) []time.Time {
	out := ts[:0]
	for _, t := range ts {
		if t.After(since) {
			out = append(out, t)
		}
	}
	return out
}

// openRecovery stores d as the identity's recovery in progress, applying
// the per-identity limits. It returns an apiError (with next steps) when a
// limit stops it.
func (s *Server) openRecovery(ctx context.Context, d recoveryDoc) (*limitError, error) {
	l := s.lockout
	l.mu.Lock()
	defer l.mu.Unlock()
	h, err := l.history(ctx, d.Commitment)
	if err != nil {
		return nil, err
	}
	if h.Active != "" {
		if cur, found, err := l.recovery(ctx, h.Active); err != nil {
			return nil, err
		} else if found && cur.Status == RecoveryPending {
			return &limitError{409, "recovery_pending", "a recovery of this identity is already in progress", map[string]any{"executes_at": cur.ExecutesAt}, nil}, nil
		}
	}
	window := d.CreatedAt.Add(-s.cfg.Lockout.RecoveryCooldown)
	h.Completed, h.Cancelled = pruneSince(h.Completed, window), pruneSince(h.Cancelled, window)
	if d.Factors[0] != FactorOperatorReview {
		if len(h.Completed) > 0 {
			return &limitError{429, "recovery_cooldown", "this identity was recovered recently; another recovery so soon needs a person to review it", map[string]any{"retry_after": h.Completed[len(h.Completed)-1].Add(s.cfg.Lockout.RecoveryCooldown)}, s.reviewStep("recovery")}, nil
		}
		if len(h.Cancelled) >= s.cfg.Lockout.MaxCancelledRecoveries {
			return &limitError{403, "recovery_needs_review", "several recoveries of this identity were cancelled; the next one needs a person to review it", nil, s.reviewStep("recovery")}, nil
		}
	}
	h.Active = d.ID
	if err := l.setJSON(ctx, nsRecoveries, d.ID, d); err != nil {
		return nil, err
	}
	if err := l.setJSON(ctx, nsRecoveryHistory, sha256Hex(d.Commitment), h); err != nil {
		return nil, err
	}
	for _, k := range []types.DID{d.OldHolder, d.NewHolder} {
		if err := l.setJSON(ctx, nsRecoveryByKey, sha256Hex(string(k)), recoveryPointer{ID: d.ID}); err != nil {
			return nil, err
		}
	}
	return nil, nil
}

// closeRecovery moves a pending recovery to status and updates history.
func (s *Server) closeRecovery(ctx context.Context, id, status, by string) (recoveryDoc, error) {
	l := s.lockout
	l.mu.Lock()
	defer l.mu.Unlock()
	d, found, err := l.recovery(ctx, id)
	if err != nil {
		return d, err
	}
	if !found {
		return d, errRecoveryNotFound
	}
	if d.Status != RecoveryPending {
		return d, errRecoveryClosed
	}
	now := s.nowFunc()
	d.Status, d.ClosedAt, d.ClosedBy = status, now, by
	h, err := l.history(ctx, d.Commitment)
	if err != nil {
		return d, err
	}
	if h.Active == id {
		h.Active = ""
	}
	if status == RecoveryCompleted {
		h.Completed = append(h.Completed, now)
	} else {
		h.Cancelled = append(h.Cancelled, now)
	}
	if err := l.setJSON(ctx, nsRecoveries, id, d); err != nil {
		return d, err
	}
	return d, l.setJSON(ctx, nsRecoveryHistory, sha256Hex(d.Commitment), h)
}

var (
	errRecoveryNotFound = errors.New("recovery not found")
	errRecoveryClosed   = errors.New("recovery is no longer pending")
)

// limitError is a refusal with a status, extra fields and next steps.
type limitError struct {
	status  int
	code    string
	message string
	extra   map[string]any
	next    []nextStep
}

func (e *limitError) write(w http.ResponseWriter) {
	writeErrorNext(w, e.status, e.code, e.message, e.next, e.extra)
}

func (s *Server) reviewStep(kind string) []nextStep {
	if !s.reviewsEnabled() {
		return []nextStep{{Action: "contact_operator", Description: "Contact the issuer's operator; this issuer has no online review queue."}}
	}
	return []nextStep{{Action: "manual_review", Endpoint: "/v1/reviews", Description: "Ask a person at the issuer to review your case (kind \"" + kind + "\")."}}
}

// recoveryFactors returns the factors sess proves for the face identity
// whose biometric nullifier commitment is bioNB and whose current holder is
// old.
func (s *Server) recoveryFactors(ctx context.Context, sess SessionView, bioNB string, old types.DID) ([]string, error) {
	var factors []string
	links, err := s.lockout.identityLinks(ctx, bioNB)
	if err != nil {
		return nil, err
	}
	if s.identifiers != nil {
		for _, key := range sess.IdentifierKeys {
			seed, found, err := s.identifiers.Lookup(ctx, key)
			if err != nil {
				return nil, err
			}
			if found && links[identityKeyNullifier(NullifierBindingForIdentifierSeed(seed).Commitment)] {
				factors = append(factors, FactorIdentifier)
				break
			}
		}
	}
	if s.inPerson != nil {
		now, err := s.inPerson.AnchorVouchers(ctx, string(sess.HolderDID))
		if err != nil {
			return nil, err
		}
		before, err := s.inPerson.VoucherDIDsFor(ctx, string(old))
		if err != nil {
			return nil, err
		}
		was := map[string]bool{}
		for _, v := range before {
			was[v] = true
		}
		n := 0
		for _, v := range now {
			if was[v] {
				n++
			}
		}
		if n >= s.cfg.Lockout.RecoveryVouches {
			factors = append(factors, FactorVouchers)
		}
	}
	for _, vm := range sess.VerifiedMethods {
		if contains(s.cfg.Lockout.RecoveryDocumentMethods, vm.MethodID) && vm.AttestationDigest != "" &&
			links[identityKeyAttestation(vm.MethodID, vm.AttestationDigest)] && !contains(factors, FactorDocument) {
			factors = append(factors, FactorDocument)
		}
	}
	return factors, nil
}

func contains(xs []string, x string) bool {
	for _, y := range xs {
		if y == x {
			return true
		}
	}
	return false
}

func (s *Server) factorSteps() []nextStep {
	steps := []nextStep{{
		Action:      "verify_identifier",
		Endpoint:    "/v1/methods/email/begin",
		Methods:     []string{"email", "sms"},
		Description: "Verify the email address or phone number you enrolled with, in this same session, then start the recovery again.",
	}}
	if s.inPerson != nil {
		steps = append(steps, nextStep{
			Action:      "vouchers",
			Endpoint:    "/v1/methods/in-person-vouch/accept",
			Description: fmt.Sprintf("Meet %d of the people who vouched for you before; each vouches in person for this new phone. Then start the recovery again.", s.cfg.Lockout.RecoveryVouches),
		})
	}
	if len(s.cfg.Lockout.RecoveryDocumentMethods) > 0 {
		steps = append(steps, nextStep{
			Action:      "document",
			Methods:     s.cfg.Lockout.RecoveryDocumentMethods,
			Description: "Scan the same identity document you enrolled with, in this session, then start the recovery again.",
		})
	}
	return append(steps, s.reviewStep("recovery")...)
}

// recoveryView is the public shape of a recovery: no DIDs, no commitment.
type recoveryView struct {
	ID         string    `json:"recovery_id"`
	Status     string    `json:"status"`
	Factors    []string  `json:"factors"`
	CreatedAt  time.Time `json:"created_at"`
	ExecutesAt time.Time `json:"executes_at"`
	ClosedAt   time.Time `json:"closed_at,omitempty"`
}

func viewOf(d recoveryDoc) recoveryView {
	return recoveryView{ID: d.ID, Status: d.Status, Factors: d.Factors, CreatedAt: d.CreatedAt, ExecutesAt: d.ExecutesAt, ClosedAt: d.ClosedAt}
}

func newRecoveryID() (string, error) {
	b := make([]byte, 16)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return hex.EncodeToString(b), nil
}

type recoveryStartRequest struct {
	SessionID string `json:"session_id"`
}

// handleRecoveryStart is POST /v1/recovery/start.
func (s *Server) handleRecoveryStart(w http.ResponseWriter, r *http.Request) {
	var req recoveryStartRequest
	if err := decodeJSON(r, &req); err != nil {
		writeError(w, http.StatusBadRequest, "invalid_request", err.Error())
		return
	}
	ctx := r.Context()
	sess, err := s.sessions.Get(req.SessionID)
	if err != nil {
		writeError(w, http.StatusNotFound, "session_not_found", err.Error())
		return
	}
	if sess.IssuedCredentialID != "" {
		writeError(w, http.StatusConflict, "already_issued", "this session already issued a credential; start a new session")
		return
	}
	if !strings.HasPrefix(string(sess.HolderDID), "did:key:") {
		writeError(w, http.StatusBadRequest, "holder_key_required", "recovery moves an identity to a holder key; start the session with holder_public_key_b64")
		return
	}
	fm, found, err := s.lockout.faceMatch(ctx, sess.ID)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "store_failed", err.Error())
		return
	}
	if !found {
		writeErrorNext(w, http.StatusConflict, "no_face_match", "start a recovery from a session whose selfie matched your enrolled face", []nextStep{{Action: "selfie", Endpoint: "/v1/methods/" + fuzzyextractorselfie.MethodID + "/begin", Description: "Take the selfie check in this session first."}}, nil)
		return
	}
	if fm.Declined {
		writeError(w, http.StatusConflict, "face_match_declined", "this session said the matched face is not yours; start a new session to recover instead")
		return
	}
	nb := NullifierBindingForBiometricCommitment(fm.Commitment).Commitment
	old, known, err := s.lockout.holderOf(ctx, identityKeyNullifier(nb))
	if err != nil {
		writeError(w, http.StatusInternalServerError, "store_failed", err.Error())
		return
	}
	if !known {
		writeErrorNext(w, http.StatusNotFound, "recovery_identity_unknown", "the issuer has no record of which key holds this identity (it was issued before recovery was turned on)", s.reviewStep("recovery"), nil)
		return
	}
	if old == sess.HolderDID {
		writeError(w, http.StatusConflict, "already_yours", "this holder key already holds this identity; complete the selfie again to re-issue")
		return
	}
	if banned, err := s.holders.Banned(ctx, BanKindNullifier, nb); err != nil {
		writeError(w, http.StatusInternalServerError, "ban_check_failed", err.Error())
		return
	} else if banned {
		writeErrorNext(w, http.StatusForbidden, "nullifier_revoked", "this identity was revoked; recovering it would not help. "+appealHint, s.appealStep(), nil)
		return
	}
	if recs, err := s.holders.Issuances(ctx, sess.HolderDID); err != nil {
		writeError(w, http.StatusInternalServerError, "store_failed", err.Error())
		return
	} else if len(recs) > 0 {
		writeError(w, http.StatusConflict, "holder_has_credential", "this holder key already holds a different identity; recover onto a fresh key")
		return
	}
	factors, err := s.recoveryFactors(ctx, sess, nb, old)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "factor_check_failed", err.Error())
		return
	}
	if len(factors) == 0 {
		writeErrorNext(w, http.StatusForbidden, "recovery_factor_missing",
			"a face match alone cannot move an identity (a look-alike could steal it); prove one more thing", s.factorSteps(), nil)
		return
	}
	s.startRecovery(w, ctx, old, sess.HolderDID, fm.Commitment, factors)
}

// startRecovery opens the recovery and answers with its view.
func (s *Server) startRecovery(w http.ResponseWriter, ctx context.Context, old, newHolder types.DID, commitment string, factors []string) {
	id, err := newRecoveryID()
	if err != nil {
		writeError(w, http.StatusInternalServerError, "recovery_failed", err.Error())
		return
	}
	now := s.nowFunc()
	d := recoveryDoc{ID: id, OldHolder: old, NewHolder: newHolder, Commitment: commitment, Factors: factors,
		Status: RecoveryPending, CreatedAt: now, ExecutesAt: now.Add(s.cfg.Lockout.RecoveryDelay)}
	if lerr, err := s.openRecovery(ctx, d); err != nil {
		writeError(w, http.StatusInternalServerError, "recovery_failed", err.Error())
		return
	} else if lerr != nil {
		lerr.write(w)
		return
	}
	s.notifyRecovery("recovery_started", d)
	writeJSON(w, http.StatusOK, viewOf(d))
}

// handleRecoveryGet is GET /v1/recovery/{id}.
func (s *Server) handleRecoveryGet(w http.ResponseWriter, r *http.Request) {
	d, found, err := s.lockout.recovery(r.Context(), chi.URLParam(r, "id"))
	if err != nil {
		writeError(w, http.StatusInternalServerError, "store_failed", err.Error())
		return
	}
	if !found {
		writeError(w, http.StatusNotFound, "recovery_not_found", "no such recovery")
		return
	}
	writeJSON(w, http.StatusOK, viewOf(d))
}

// handleRecoveryPending is GET /v1/recovery/pending?holder_did=: the old
// key's wallet polls it to learn that someone is moving its identity.
func (s *Server) handleRecoveryPending(w http.ResponseWriter, r *http.Request) {
	holder := types.DID(strings.TrimSpace(r.URL.Query().Get("holder_did")))
	if !strings.HasPrefix(string(holder), "did:") {
		writeError(w, http.StatusBadRequest, "invalid_request", "holder_did is required")
		return
	}
	id, err := s.activeRecoveryFor(r.Context(), holder)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "store_failed", err.Error())
		return
	}
	out := map[string]any{"pending": []recoveryView{}}
	if id != "" {
		d, _, err := s.lockout.recovery(r.Context(), id)
		if err != nil {
			writeError(w, http.StatusInternalServerError, "store_failed", err.Error())
			return
		}
		role := "new_key"
		if d.OldHolder == holder {
			role = "old_key"
		}
		out["pending"] = []recoveryView{viewOf(d)}
		out["role"] = role
		out["cancel_message"] = RecoveryCancelMessage(s.issuerDID, d.ID)
	}
	writeJSON(w, http.StatusOK, out)
}

type recoveryCancelRequest struct {
	HolderDID    string `json:"holder_did"`
	SignatureB64 string `json:"signature_b64"`
}

// handleRecoveryCancel is POST /v1/recovery/{id}/cancel, signed by the old
// or the new key.
func (s *Server) handleRecoveryCancel(w http.ResponseWriter, r *http.Request) {
	id := chi.URLParam(r, "id")
	var req recoveryCancelRequest
	if err := decodeJSON(r, &req); err != nil {
		writeError(w, http.StatusBadRequest, "invalid_request", err.Error())
		return
	}
	ctx := r.Context()
	d, found, err := s.lockout.recovery(ctx, id)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "store_failed", err.Error())
		return
	}
	if !found {
		writeError(w, http.StatusNotFound, "recovery_not_found", "no such recovery")
		return
	}
	holder := types.DID(req.HolderDID)
	by := ""
	switch holder {
	case d.OldHolder:
		by = "old_key"
	case d.NewHolder:
		by = "new_key"
	default:
		writeError(w, http.StatusForbidden, "not_a_party", "only the old or the new holder key can cancel this recovery")
		return
	}
	if !verifyDIDSignature(holder, RecoveryCancelMessage(s.issuerDID, id), req.SignatureB64) {
		writeError(w, http.StatusForbidden, "bad_signature", "signature_b64 must sign cancel_message with the holder key")
		return
	}
	d, err = s.closeRecovery(ctx, id, RecoveryCancelled, by)
	if errors.Is(err, errRecoveryClosed) {
		writeError(w, http.StatusConflict, "recovery_closed", "this recovery is already "+d.Status)
		return
	}
	if err != nil {
		writeError(w, http.StatusInternalServerError, "store_failed", err.Error())
		return
	}
	log.Printf(`{"severity":"NOTICE","message":"recovery cancelled","recovery":%q,"by":%q}`, id, by)
	s.notifyRecovery("recovery_cancelled", d)
	writeJSON(w, http.StatusOK, viewOf(d))
}

type recoveryCompleteRequest struct {
	SessionID string `json:"session_id"`
}

// handleRecoveryComplete is POST /v1/recovery/{id}/complete: after the
// delay, in a session of the new key, the old key's credentials are
// revoked, the old key is barred, and the session is credited with the
// identity's face so issuance gives it the same nullifierBinding.
func (s *Server) handleRecoveryComplete(w http.ResponseWriter, r *http.Request) {
	id := chi.URLParam(r, "id")
	var req recoveryCompleteRequest
	if err := decodeJSON(r, &req); err != nil {
		writeError(w, http.StatusBadRequest, "invalid_request", err.Error())
		return
	}
	ctx := r.Context()
	d, found, err := s.lockout.recovery(ctx, id)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "store_failed", err.Error())
		return
	}
	if !found {
		writeError(w, http.StatusNotFound, "recovery_not_found", "no such recovery")
		return
	}
	sess, err := s.sessions.Get(req.SessionID)
	if err != nil {
		writeError(w, http.StatusNotFound, "session_not_found", err.Error())
		return
	}
	if sess.HolderDID != d.NewHolder || sess.IssuedCredentialID != "" {
		writeError(w, http.StatusForbidden, "wrong_session", "complete the recovery from a new, unissued session of the key that started it")
		return
	}
	// A completed recovery may be completed again by the same new key: that
	// is a retry after a failure part-way, and every step below is
	// idempotent.
	retry := d.Status == RecoveryCompleted
	if d.Status != RecoveryPending && !retry {
		writeError(w, http.StatusConflict, "recovery_closed", "this recovery is already "+d.Status)
		return
	}
	if now := s.nowFunc(); now.Before(d.ExecutesAt) {
		writeErrorNext(w, http.StatusTooEarly, "recovery_not_ready", "the cancel window is still open", nil, map[string]any{"executes_at": d.ExecutesAt})
		return
	}
	nb := NullifierBindingForBiometricCommitment(d.Commitment).Commitment
	if banned, err := s.holders.Banned(ctx, BanKindNullifier, nb); err != nil {
		writeError(w, http.StatusInternalServerError, "ban_check_failed", err.Error())
		return
	} else if banned {
		writeErrorNext(w, http.StatusForbidden, "nullifier_revoked", "this identity was revoked during the recovery window. "+appealHint, s.appealStep(), nil)
		return
	}
	selfie, ok := s.registry.Get(fuzzyextractorselfie.MethodID)
	if !ok {
		writeError(w, http.StatusInternalServerError, "selfie_unavailable", "the selfie method is no longer registered")
		return
	}
	// Close the window first, atomically: a cancel that lands at the same
	// moment either wins (and we stop here) or loses.
	if !retry {
		if d, err = s.closeRecovery(ctx, id, RecoveryCompleted, "new_key"); errors.Is(err, errRecoveryClosed) {
			writeError(w, http.StatusConflict, "recovery_closed", "this recovery is already "+d.Status)
			return
		} else if err != nil {
			writeError(w, http.StatusInternalServerError, "store_failed", err.Error())
			return
		}
	}
	revoked, err := s.retireRecoveredHolder(ctx, d.OldHolder)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "revoke_failed", err.Error())
		return
	}
	res := types.MethodResult{Success: true, MethodID: fuzzyextractorselfie.MethodID, VerifiedAt: s.nowFunc(), AttestationDigest: d.Commitment}
	if err := s.sessions.RecordMethodResult(sess.ID, res, selfie.Metadata()); err != nil {
		writeError(w, http.StatusInternalServerError, "record_failed", err.Error())
		return
	}
	if !retry {
		s.notifyRecovery("recovery_completed", d)
	}
	view, _ := s.sessions.Get(sess.ID)
	writeJSON(w, http.StatusOK, map[string]any{"recovery": viewOf(d), "revoked_credentials": revoked, "session": view})
}

// retireRecoveredHolder revokes every credential issued to the old key and
// bars the key from new ones. Its nullifiers stay valid: the identity lives
// on under the new key.
func (s *Server) retireRecoveredHolder(ctx context.Context, old types.DID) (int, error) {
	if _, err := s.holders.Ban(ctx, BanKindHolder, string(old), BanRecord{Reason: "recovered: identity moved to a new holder key", At: s.nowFunc()}); err != nil {
		return 0, err
	}
	recs, err := s.holders.Issuances(ctx, old)
	if err != nil {
		return 0, err
	}
	n := 0
	for _, r := range recs {
		_, already, err := s.revocations.Revoke(ctx, r.CredentialID)
		switch {
		case errors.Is(err, ErrCredentialNotFound):
		case err != nil:
			return n, err
		case !already:
			n++
		}
	}
	return n, nil
}

// notifyRecovery tells the configured webhook, in the background.
func (s *Server) notifyRecovery(event string, d recoveryDoc) {
	log.Printf(`{"severity":"NOTICE","message":%q,"recovery":%q,"executes_at":%q}`, event, d.ID, d.ExecutesAt.Format(time.RFC3339))
	url := s.cfg.Lockout.NotifyWebhook
	if url == "" {
		return
	}
	body := mustMarshal(map[string]any{
		"event": event, "recovery_id": d.ID, "old_holder_did": d.OldHolder,
		"status": d.Status, "executes_at": d.ExecutesAt,
		"cancel_message": RecoveryCancelMessage(s.issuerDID, d.ID),
	})
	go func() {
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		req, err := http.NewRequestWithContext(ctx, http.MethodPost, url, bytes.NewReader(body))
		if err != nil {
			return
		}
		req.Header.Set("Content-Type", "application/json")
		resp, err := http.DefaultClient.Do(req)
		if err != nil {
			log.Printf("recovery webhook: %v", err)
			return
		}
		resp.Body.Close()
	}()
}

// verifyDIDSignature checks an Ed25519 signature by a did:key holder.
func verifyDIDSignature(holder types.DID, message, sigB64 string) bool {
	pub, err := Ed25519FromDIDKey(holder)
	if err != nil {
		return false
	}
	sig, err := base64.StdEncoding.DecodeString(strings.TrimSpace(sigB64))
	if err != nil {
		if sig, err = decodeB64Tolerant(sigB64); err != nil {
			return false
		}
	}
	return len(sig) == ed25519.SignatureSize && ed25519.Verify(pub, []byte(message), sig)
}

func mustMarshal(v any) []byte {
	b, err := json.Marshal(v)
	if err != nil {
		panic(fmt.Sprintf("marshal: %v", err))
	}
	return b
}
