package server

// Manual review, appeals and reinstatement (NO_FALSE_LOCKOUT + ADMIN_TOKEN).
//
// Every automatic refusal that an honest person could hit ends in a person
// at the issuer looking at the case:
//
//	POST /v1/reviews     {session_id, kind, message}       a live session asks for review
//	POST /v1/appeals     {holder_did, message, signature_b64?}  a banned key appeals
//	GET  /v1/reviews/{id}                                    status, for the person who asked
//	GET  /v1/admin/reviews                                   open cases (operator)
//	POST /v1/admin/reviews/{id}/decide {approve, note, old_holder_did?}
//	POST /v1/admin/reinstate {holder_did, reason}           lift a ban directly
//
// What approving does, by kind:
//
//	face_match, no_selfie, other: the holder key may complete the
//	    operator-review anchor (strength 50, the floor), so it gets a
//	    credential without the selfie dedupe. Its nullifier comes from its
//	    email/phone seed or its holder key, never from a matched face.
//	recovery: a recovery is opened with factor operator_review; the usual
//	    cancel window still applies.
//	appeal: the holder is reinstated (see reinstate).
//
// The operator's judgement is the evidence, so the anchor is only as good
// as the operator's process (docs/08-no-false-lockout.md).

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"net/http"
	"strings"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/sagearbor/personhood/pkg/types"
)

// Review kinds.
const (
	ReviewFaceMatch = "face_match"
	ReviewRecovery  = "recovery"
	ReviewNoSelfie  = "no_selfie"
	ReviewOther     = "other"
	ReviewAppeal    = "appeal"
)

// Review states.
const (
	ReviewOpen     = "open"
	ReviewApproved = "approved"
	ReviewDenied   = "denied"
)

// maxOpenReviews bounds the queue so it cannot be flooded.
const maxOpenReviews = 5000

// reviewApprovalLifetime: an approval for the operator-review anchor must be
// used within this long.
const reviewApprovalLifetime = 30 * 24 * time.Hour

type reviewDoc struct {
	ID         string    `json:"id"`
	Kind       string    `json:"kind"`
	HolderDID  types.DID `json:"holder_did"`
	Message    string    `json:"message,omitempty"`
	Signed     bool      `json:"signed"`
	Commitment string    `json:"commitment,omitempty"` // matched face, server-side only
	// BanReason is the ban an appeal is about, copied for the operator.
	BanReason string    `json:"ban_reason,omitempty"`
	Status    string    `json:"status"`
	CreatedAt time.Time `json:"created_at"`
	DecidedAt time.Time `json:"decided_at,omitempty"`
	Note      string    `json:"note,omitempty"`
}

type reviewIndex struct {
	IDs []string `json:"ids"`
}

type reviewApproval struct {
	ReviewID string    `json:"review_id"`
	Kind     string    `json:"kind"`
	At       time.Time `json:"at"`
}

func (s *Server) reviewsEnabled() bool { return s.lockout != nil && s.cfg.AdminToken != "" }

// appealStepIfLockout is appealStep when NO_FALSE_LOCKOUT is on, else nil
// (the refusal stays exactly as before).
func (s *Server) appealStepIfLockout() []nextStep {
	if s.lockout == nil {
		return nil
	}
	return s.appealStep()
}

func (s *Server) appealStep() []nextStep {
	if !s.reviewsEnabled() {
		return []nextStep{{Action: "contact_operator", Description: "Contact the issuer's operator to appeal."}}
	}
	return []nextStep{{Action: "appeal", Endpoint: "/v1/appeals", Description: "Appeal: a person at the issuer reviews it and can reinstate you."}}
}

// openReview stores d unless the holder already has an open review of that
// kind (whose id is returned) or the queue is full.
func (s *Server) openReview(ctx context.Context, d reviewDoc) (existing string, full bool, err error) {
	l := s.lockout
	l.mu.Lock()
	defer l.mu.Unlock()
	key := sha256Hex(d.Kind + "\x00" + string(d.HolderDID))
	var ptr recoveryPointer
	if found, err := l.getJSON(ctx, nsReviewOpen, key, &ptr); err != nil {
		return "", false, err
	} else if found && ptr.ID != "" {
		var cur reviewDoc
		if ok, err := l.getJSON(ctx, nsReviews, ptr.ID, &cur); err != nil {
			return "", false, err
		} else if ok && cur.Status == ReviewOpen {
			return cur.ID, false, nil
		}
	}
	var idx reviewIndex
	if _, err := l.getJSON(ctx, nsReviews, "_open", &idx); err != nil {
		return "", false, err
	}
	if len(idx.IDs) >= maxOpenReviews {
		return "", true, nil
	}
	idx.IDs = append(idx.IDs, d.ID)
	if err := l.setJSON(ctx, nsReviews, d.ID, d); err != nil {
		return "", false, err
	}
	if err := l.setJSON(ctx, nsReviewOpen, key, recoveryPointer{ID: d.ID}); err != nil {
		return "", false, err
	}
	return "", false, l.setJSON(ctx, nsReviews, "_open", idx)
}

func (s *Server) writeReviewOpened(w http.ResponseWriter, ctx context.Context, d reviewDoc) {
	existing, full, err := s.openReview(ctx, d)
	switch {
	case err != nil:
		writeError(w, http.StatusInternalServerError, "store_failed", err.Error())
	case full:
		writeError(w, http.StatusServiceUnavailable, "review_queue_full", "the review queue is full; please try again in a few days")
	case existing != "":
		writeErrorNext(w, http.StatusConflict, "review_open", "you already have an open review of this kind", nil, map[string]any{"review_id": existing})
	default:
		writeJSON(w, http.StatusOK, map[string]any{"review_id": d.ID, "status": d.Status})
	}
}

type reviewRequest struct {
	SessionID string `json:"session_id"`
	Kind      string `json:"kind"`
	Message   string `json:"message"`
}

// handleReviewRequest is POST /v1/reviews.
func (s *Server) handleReviewRequest(w http.ResponseWriter, r *http.Request) {
	var req reviewRequest
	if err := decodeJSON(r, &req); err != nil {
		writeError(w, http.StatusBadRequest, "invalid_request", err.Error())
		return
	}
	switch req.Kind {
	case ReviewFaceMatch, ReviewRecovery, ReviewNoSelfie, ReviewOther:
	default:
		writeError(w, http.StatusBadRequest, "invalid_request", "kind must be face_match, recovery, no_selfie or other")
		return
	}
	if len(req.Message) > 1000 {
		writeError(w, http.StatusBadRequest, "invalid_request", "message is limited to 1000 characters")
		return
	}
	ctx := r.Context()
	sess, err := s.sessions.Get(req.SessionID)
	if err != nil {
		writeError(w, http.StatusNotFound, "session_not_found", err.Error())
		return
	}
	if !strings.HasPrefix(string(sess.HolderDID), "did:key:") {
		writeError(w, http.StatusBadRequest, "holder_key_required", "a review is decided for a holder key; start the session with holder_public_key_b64")
		return
	}
	d := reviewDoc{Kind: req.Kind, HolderDID: sess.HolderDID, Message: strings.TrimSpace(req.Message), Status: ReviewOpen, CreatedAt: s.nowFunc()}
	if req.Kind == ReviewFaceMatch || req.Kind == ReviewRecovery {
		fm, found, err := s.lockout.faceMatch(ctx, sess.ID)
		if err != nil {
			writeError(w, http.StatusInternalServerError, "store_failed", err.Error())
			return
		}
		if !found {
			writeError(w, http.StatusConflict, "no_face_match", "this kind of review needs a session whose selfie matched an enrolled face")
			return
		}
		d.Commitment = fm.Commitment
	}
	if d.ID, err = newRecoveryID(); err != nil {
		writeError(w, http.StatusInternalServerError, "store_failed", err.Error())
		return
	}
	s.writeReviewOpened(w, ctx, d)
}

// AppealMessage is what a holder key signs to appeal its ban; message is
// the appeal text exactly as sent.
func AppealMessage(issuerDID, holder types.DID, message string) string {
	return "personhood-appeal/v1\n" + string(issuerDID) + "\n" + string(holder) + "\n" + message
}

type appealRequest struct {
	HolderDID    string `json:"holder_did"`
	Message      string `json:"message"`
	SignatureB64 string `json:"signature_b64,omitempty"`
}

// handleAppeal is POST /v1/appeals. A signature by the banned key marks the
// appeal as coming from the key's holder; an unsigned appeal (the key was
// lost) is accepted too, and the operator weighs it accordingly.
func (s *Server) handleAppeal(w http.ResponseWriter, r *http.Request) {
	var req appealRequest
	if err := decodeJSON(r, &req); err != nil {
		writeError(w, http.StatusBadRequest, "invalid_request", err.Error())
		return
	}
	holder := types.DID(strings.TrimSpace(req.HolderDID))
	if !strings.HasPrefix(string(holder), "did:") || len(req.Message) > 1000 {
		writeError(w, http.StatusBadRequest, "invalid_request", "holder_did (a DID) and a message of at most 1000 characters are required")
		return
	}
	ctx := r.Context()
	ban, banned, err := s.holders.BanInfo(ctx, BanKindHolder, string(holder))
	if err != nil {
		writeError(w, http.StatusInternalServerError, "store_failed", err.Error())
		return
	}
	if !banned {
		writeError(w, http.StatusConflict, "not_banned", "this holder is not banned; there is nothing to appeal")
		return
	}
	d := reviewDoc{Kind: ReviewAppeal, HolderDID: holder, Message: strings.TrimSpace(req.Message), BanReason: ban.Reason, Status: ReviewOpen, CreatedAt: s.nowFunc()}
	if req.SignatureB64 != "" {
		if !verifyDIDSignature(holder, AppealMessage(s.issuerDID, holder, req.Message), req.SignatureB64) {
			writeError(w, http.StatusForbidden, "bad_signature", "signature_b64 must sign the appeal message with the holder key (or leave it out)")
			return
		}
		d.Signed = true
	}
	if d.ID, err = newRecoveryID(); err != nil {
		writeError(w, http.StatusInternalServerError, "store_failed", err.Error())
		return
	}
	s.writeReviewOpened(w, ctx, d)
}

// handleReviewGet is GET /v1/reviews/{id}: status only.
func (s *Server) handleReviewGet(w http.ResponseWriter, r *http.Request) {
	var d reviewDoc
	id := chi.URLParam(r, "id")
	found, err := s.lockout.getJSON(r.Context(), nsReviews, id, &d)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "store_failed", err.Error())
		return
	}
	if !found || id == "_open" {
		writeError(w, http.StatusNotFound, "review_not_found", "no such review")
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"review_id": d.ID, "kind": d.Kind, "status": d.Status, "decided_at": d.DecidedAt, "note": d.Note})
}

// handleAdminReviews is GET /v1/admin/reviews: the open queue.
func (s *Server) handleAdminReviews(w http.ResponseWriter, r *http.Request) {
	if !s.adminAuthorized(r) {
		writeError(w, http.StatusUnauthorized, "unauthorized", "a valid admin bearer token is required")
		return
	}
	ctx := r.Context()
	var idx reviewIndex
	if _, err := s.lockout.getJSON(ctx, nsReviews, "_open", &idx); err != nil {
		writeError(w, http.StatusInternalServerError, "store_failed", err.Error())
		return
	}
	out := make([]reviewDoc, 0, len(idx.IDs))
	for _, id := range idx.IDs {
		var d reviewDoc
		if found, err := s.lockout.getJSON(ctx, nsReviews, id, &d); err != nil {
			writeError(w, http.StatusInternalServerError, "store_failed", err.Error())
			return
		} else if found {
			d.Commitment = "" // the operator decides on the person, not the template
			out = append(out, d)
		}
	}
	writeJSON(w, http.StatusOK, map[string]any{"reviews": out})
}

type decideRequest struct {
	Approve      bool   `json:"approve"`
	Note         string `json:"note"`
	OldHolderDID string `json:"old_holder_did,omitempty"`
}

// handleAdminDecide is POST /v1/admin/reviews/{id}/decide.
func (s *Server) handleAdminDecide(w http.ResponseWriter, r *http.Request) {
	if !s.adminAuthorized(r) {
		writeError(w, http.StatusUnauthorized, "unauthorized", "a valid admin bearer token is required")
		return
	}
	var req decideRequest
	if err := decodeJSON(r, &req); err != nil {
		writeError(w, http.StatusBadRequest, "invalid_request", err.Error())
		return
	}
	req.Note = strings.TrimSpace(req.Note)
	if req.Note == "" || len(req.Note) > 500 {
		writeError(w, http.StatusBadRequest, "invalid_request", "note (1..500 characters) is required: say what you checked")
		return
	}
	ctx := r.Context()
	id := chi.URLParam(r, "id")
	var d reviewDoc
	if found, err := s.lockout.getJSON(ctx, nsReviews, id, &d); err != nil {
		writeError(w, http.StatusInternalServerError, "store_failed", err.Error())
		return
	} else if !found || id == "_open" {
		writeError(w, http.StatusNotFound, "review_not_found", "no such review")
		return
	}
	if d.Status != ReviewOpen {
		writeError(w, http.StatusConflict, "review_closed", "this review was already "+d.Status)
		return
	}
	out := map[string]any{}
	if req.Approve {
		switch d.Kind {
		case ReviewAppeal:
			rep, err := s.reinstate(ctx, d.HolderDID)
			if errors.Is(err, errRetiredByRecovery) {
				writeError(w, http.StatusConflict, "retired_by_recovery", err.Error())
				return
			}
			if err != nil {
				writeError(w, http.StatusInternalServerError, "reinstate_failed", err.Error())
				return
			}
			out["reinstated"] = rep
		case ReviewRecovery:
			old := types.DID(strings.TrimSpace(req.OldHolderDID))
			if old == "" {
				h, known, err := s.lockout.holderOf(ctx, identityKeyNullifier(NullifierBindingForBiometricCommitment(d.Commitment).Commitment))
				if err != nil {
					writeError(w, http.StatusInternalServerError, "store_failed", err.Error())
					return
				}
				if !known {
					writeError(w, http.StatusBadRequest, "old_holder_unknown", "the issuer does not know which key holds this identity; pass old_holder_did")
					return
				}
				old = h
			}
			rec := &recordingWriter{header: http.Header{}}
			s.startRecovery(rec, ctx, old, d.HolderDID, d.Commitment, []string{FactorOperatorReview})
			if rec.status != http.StatusOK {
				w.Header().Set("Content-Type", "application/json")
				w.WriteHeader(rec.status)
				_, _ = w.Write(rec.body)
				return
			}
			var view recoveryView
			_ = json.Unmarshal(rec.body, &view)
			out["recovery"] = view
		default:
			if err := s.lockout.setJSON(ctx, nsReviewApprovals, sha256Hex(string(d.HolderDID)), reviewApproval{ReviewID: d.ID, Kind: d.Kind, At: s.nowFunc()}); err != nil {
				writeError(w, http.StatusInternalServerError, "store_failed", err.Error())
				return
			}
			out["operator_review_anchor"] = OperatorReviewMethodID
		}
	}
	d.Status, d.DecidedAt, d.Note = ReviewDenied, s.nowFunc(), req.Note
	if req.Approve {
		d.Status = ReviewApproved
	}
	if err := s.closeReview(ctx, d); err != nil {
		writeError(w, http.StatusInternalServerError, "store_failed", err.Error())
		return
	}
	out["review_id"], out["status"] = d.ID, d.Status
	writeJSON(w, http.StatusOK, out)
}

func (s *Server) closeReview(ctx context.Context, d reviewDoc) error {
	l := s.lockout
	l.mu.Lock()
	defer l.mu.Unlock()
	if err := l.setJSON(ctx, nsReviews, d.ID, d); err != nil {
		return err
	}
	var idx reviewIndex
	if _, err := l.getJSON(ctx, nsReviews, "_open", &idx); err != nil {
		return err
	}
	kept := idx.IDs[:0]
	for _, id := range idx.IDs {
		if id != d.ID {
			kept = append(kept, id)
		}
	}
	idx.IDs = kept
	return l.setJSON(ctx, nsReviews, "_open", idx)
}

type reinstateRequest struct {
	HolderDID string `json:"holder_did"`
	Reason    string `json:"reason"`
}

// handleAdminReinstate is POST /v1/admin/reinstate.
func (s *Server) handleAdminReinstate(w http.ResponseWriter, r *http.Request) {
	if !s.adminAuthorized(r) {
		writeError(w, http.StatusUnauthorized, "unauthorized", "a valid admin bearer token is required")
		return
	}
	var req reinstateRequest
	if err := decodeJSON(r, &req); err != nil {
		writeError(w, http.StatusBadRequest, "invalid_request", err.Error())
		return
	}
	req.HolderDID, req.Reason = strings.TrimSpace(req.HolderDID), strings.TrimSpace(req.Reason)
	if !strings.HasPrefix(req.HolderDID, "did:") || req.Reason == "" || len(req.Reason) > 200 {
		writeError(w, http.StatusBadRequest, "invalid_request", "holder_did (a DID) and reason (1..200 characters) are required")
		return
	}
	rep, err := s.reinstate(r.Context(), types.DID(req.HolderDID))
	if errors.Is(err, errRetiredByRecovery) {
		writeError(w, http.StatusConflict, "retired_by_recovery", err.Error())
		return
	}
	if err != nil {
		writeError(w, http.StatusInternalServerError, "reinstate_failed", err.Error())
		return
	}
	writeJSON(w, http.StatusOK, rep)
}

// errRetiredByRecovery: the key's identity was moved to a new key.
var errRetiredByRecovery = errors.New("this holder key was retired by a completed recovery; its identity now lives under the new key")

type reinstateReport struct {
	HolderDID          types.DID `json:"holder_did"`
	WasBanned          bool      `json:"was_banned"`
	NullifiersUnbanned int       `json:"nullifiers_unbanned"`
	VouchersRestored   int       `json:"vouchers_restored"`
	EvidencePardoned   bool      `json:"evidence_pardoned"`
}

// reinstate undoes revokeHolder after review: the holder ban and the bans
// on every nullifier its issuances touched are lifted, the equivocation
// proof that caused it (if any) is pardoned so re-posting it does nothing,
// and the strikes its revocation gave its vouchers are taken back. Revoked
// credentials stay revoked: the person enrolls again and, on the same
// seed, gets the same nullifierBinding back.
//
// A key retired by a completed recovery is not reinstated this way: its
// identity now lives under the new key.
func (s *Server) reinstate(ctx context.Context, holder types.DID) (reinstateReport, error) {
	rep := reinstateReport{HolderDID: holder}
	ban, banned, err := s.holders.BanInfo(ctx, BanKindHolder, string(holder))
	if err != nil {
		return rep, err
	}
	rep.WasBanned = banned
	if banned && strings.HasPrefix(ban.Reason, "recovered:") {
		return rep, errRetiredByRecovery
	}
	if ban.EvidenceDigest != "" {
		if _, err := s.holders.Ban(ctx, BanKindPardon, ban.EvidenceDigest, BanRecord{Reason: "pardoned after review of " + string(holder), At: s.nowFunc()}); err != nil {
			return rep, err
		}
		rep.EvidencePardoned = true
	}
	nullifiers := map[string]bool{}
	if pub, err := Ed25519FromDIDKey(holder); err == nil {
		nullifiers[NullifierBindingForHolder(pub).Commitment] = true
	}
	recs, err := s.holders.Issuances(ctx, holder)
	if err != nil {
		return rep, err
	}
	for _, r := range recs {
		for _, c := range r.NullifierCommitments {
			nullifiers[c] = true
		}
	}
	for c := range nullifiers {
		was, err := s.holders.Banned(ctx, BanKindNullifier, c)
		if err != nil {
			return rep, err
		}
		if was {
			if err := s.holders.Unban(ctx, BanKindNullifier, c); err != nil {
				return rep, err
			}
			rep.NullifiersUnbanned++
		}
	}
	if err := s.holders.Unban(ctx, BanKindHolder, string(holder)); err != nil {
		return rep, err
	}
	if s.inPerson != nil {
		pr, err := s.inPerson.Reinstate(ctx, string(holder))
		if err != nil {
			return rep, err
		}
		rep.VouchersRestored = len(pr.Vouchers)
	}
	return rep, nil
}

// ----------------------------------------------------------------------------
// operator-review anchor
// ----------------------------------------------------------------------------

// OperatorReviewMethodID is the anchor an approved manual review grants.
const OperatorReviewMethodID = "operator-review"

// OperatorReviewStrength is the anchor floor: a person at the issuer looked
// at the case. It is as strong as that person's process, no stronger.
const OperatorReviewStrength = 50

type operatorReviewMethod struct{ s *Server }

func (m operatorReviewMethod) Metadata() types.MethodMetadata {
	return types.MethodMetadata{
		ID:                OperatorReviewMethodID,
		Type:              types.MethodTypeAnchor,
		Strength:          OperatorReviewStrength,
		UXFriction:        types.FrictionHigh,
		FreshnessLifetime: 180 * 24 * time.Hour,
		Version:           "0.1.0",
	}
}

func (m operatorReviewMethod) IsAvailableForUser(types.UserContext) (bool, string) { return true, "" }
func (m operatorReviewMethod) HealthCheck(context.Context) error                   { return nil }

func (m operatorReviewMethod) BeginCeremony(_ context.Context, cc types.CeremonyContext) (types.ChallengeData, error) {
	return types.ChallengeData{Type: "operator-review", Payload: map[string]any{
		"reviews_endpoint": "/v1/reviews",
		"instructions":     "Ask for a review with POST /v1/reviews. Once an operator approves it, complete this method from any session of the same holder key.",
	}}, nil
}

func (m operatorReviewMethod) CompleteCeremony(ctx context.Context, cc types.CeremonyContext, _ types.ResponseData) (types.MethodResult, error) {
	fail := func(reason string) (types.MethodResult, error) {
		return types.MethodResult{Success: false, MethodID: OperatorReviewMethodID, ErrorReason: reason}, nil
	}
	var a reviewApproval
	found, err := m.s.lockout.getJSON(ctx, nsReviewApprovals, sha256Hex(string(cc.HolderDID)), &a)
	if err != nil {
		return types.MethodResult{}, err
	}
	now := m.s.nowFunc()
	if !found || now.Sub(a.At) > reviewApprovalLifetime {
		return fail("review_not_approved")
	}
	sum := sha256.Sum256([]byte(OperatorReviewMethodID + "\x00" + a.ReviewID))
	return types.MethodResult{Success: true, MethodID: OperatorReviewMethodID, VerifiedAt: now, AttestationDigest: hex.EncodeToString(sum[:])}, nil
}

// recordingWriter captures a handler's response so another handler can
// reuse it (handleAdminDecide calling startRecovery).
type recordingWriter struct {
	header http.Header
	status int
	body   []byte
}

func (r *recordingWriter) Header() http.Header { return r.header }
func (r *recordingWriter) Write(b []byte) (int, error) {
	if r.status == 0 {
		r.status = http.StatusOK
	}
	r.body = append(r.body, b...)
	return len(b), nil
}
func (r *recordingWriter) WriteHeader(code int) { r.status = code }
