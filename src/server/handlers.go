package server

import (
	"context"
	"crypto/ed25519"
	"encoding/json"
	"errors"
	"fmt"
	"html/template"
	"net/http"
	"strings"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/sagearbor/personhood/pkg/types"
	"github.com/sagearbor/personhood/src/credential"
)

// startEnrollmentRequest is the JSON body of POST /enrollment/start.
//
// Both fields are optional. holder_public_key_b64, when supplied, is a
// 32-byte Ed25519 public key the client generated; it is mixed into the
// holder DID derivation so the same key always maps to the same DID. user
// agent / platform / etc. flow through to methods that care.
type startEnrollmentRequest struct {
	HolderPublicKeyB64 string `json:"holder_public_key_b64,omitempty"`
	UserAgent          string `json:"user_agent,omitempty"`
	Platform           string `json:"platform,omitempty"`
	CountryCode        string `json:"country_code,omitempty"`
}

// startEnrollmentResponse is returned by POST /enrollment/start.
type startEnrollmentResponse struct {
	SessionID        string                 `json:"session_id"`
	HolderDID        types.DID              `json:"holder_did"`
	IssuerDID        types.DID              `json:"issuer_did"`
	ExpiresAt        time.Time              `json:"expires_at"`
	AvailableMethods []methodSummary        `json:"available_methods"`
}

// methodSummary is the projection of MethodMetadata returned to clients on
// the enrollment-start and list-methods endpoints. Same shape as the
// underlying type — kept as a named alias so the wire contract is explicit.
type methodSummary struct {
	ID                string `json:"id"`
	Type              string `json:"type"`
	Strength          int    `json:"strength"`
	UXFriction        string `json:"ux_friction"`
	CostUSD           float64 `json:"cost_usd"`
	Version           string `json:"version"`
}

// beginMethodRequest is the JSON body of POST /v1/methods/{methodId}/begin.
//
// user_input carries the email / phone number / etc. that the method needs to
// start its ceremony. The server threads it onto CeremonyContext.UserID — a
// v0.1 convention documented in src/methods/email/email.go.
type beginMethodRequest struct {
	SessionID string `json:"session_id"`
	UserInput string `json:"user_input"`
}

type beginMethodResponse struct {
	Challenge types.ChallengeData `json:"challenge"`
}

// completeMethodRequest is the JSON body of POST /v1/methods/{methodId}/complete.
type completeMethodRequest struct {
	SessionID string             `json:"session_id"`
	Response  types.ResponseData `json:"response"`
}

type completeMethodResponse struct {
	Result        types.MethodResult `json:"result"`
	Session       SessionView        `json:"session"`
}

// issueCredentialRequest is the JSON body of POST /v1/credentials/issue.
type issueCredentialRequest struct {
	SessionID string `json:"session_id"`
}

type issueCredentialResponse struct {
	Credential types.PersonhoodCredential `json:"credential"`
}

// ----------------------------------------------------------------------------
// Handlers
// ----------------------------------------------------------------------------

func (s *Server) handleHealth(w http.ResponseWriter, _ *http.Request) {
	writeJSON(w, http.StatusOK, map[string]any{"status": "ok"})
}

func (s *Server) handleListMethods(w http.ResponseWriter, _ *http.Request) {
	writeJSON(w, http.StatusOK, map[string]any{
		"methods": s.methodSummaries(),
	})
}

func (s *Server) handleStartEnrollment(w http.ResponseWriter, r *http.Request) {
	var req startEnrollmentRequest
	if err := decodeJSON(r, &req); err != nil {
		writeError(w, http.StatusBadRequest, "invalid_request", err.Error())
		return
	}

	var holderPub ed25519.PublicKey
	if strings.TrimSpace(req.HolderPublicKeyB64) != "" {
		raw, err := decodeB64Tolerant(req.HolderPublicKeyB64)
		if err != nil {
			writeError(w, http.StatusBadRequest, "invalid_holder_key", err.Error())
			return
		}
		if len(raw) != ed25519.PublicKeySize {
			writeError(w, http.StatusBadRequest, "invalid_holder_key",
				fmt.Sprintf("public key must be %d bytes, got %d", ed25519.PublicKeySize, len(raw)))
			return
		}
		holderPub = raw
	}

	// Generate a placeholder session ID to derive the holder DID; the store
	// will ultimately regenerate one — but because the DID depends on the
	// session ID, derive once and reuse. We do this in two steps to avoid
	// exposing randomSessionID outside session.go.
	sess, err := s.sessions.Create("", s.nowFunc())
	if err != nil {
		writeError(w, http.StatusInternalServerError, "session_create_failed", err.Error())
		return
	}
	holderDID := HolderDIDForSession(sess.ID, holderPub)
	sess.HolderDID = holderDID

	writeJSON(w, http.StatusOK, startEnrollmentResponse{
		SessionID:        sess.ID,
		HolderDID:        holderDID,
		IssuerDID:        s.issuerDID,
		ExpiresAt:        sess.ExpiresAt,
		AvailableMethods: s.methodSummaries(),
	})
}

func (s *Server) handleBeginMethod(w http.ResponseWriter, r *http.Request) {
	methodID := chi.URLParam(r, "methodId")
	method, ok := s.registry.Get(methodID)
	if !ok {
		writeError(w, http.StatusNotFound, "method_not_found",
			fmt.Sprintf("no method with id %q is registered", methodID))
		return
	}

	var req beginMethodRequest
	if err := decodeJSON(r, &req); err != nil {
		writeError(w, http.StatusBadRequest, "invalid_request", err.Error())
		return
	}
	sess, err := s.sessions.Get(req.SessionID)
	if err != nil {
		writeError(w, http.StatusNotFound, "session_not_found", err.Error())
		return
	}

	cc := types.CeremonyContext{
		SessionID:  sess.ID,
		UserID:     req.UserInput, // v0.1 hand-off — see email.go / sms.go
		MethodID:   methodID,
		IssuerDID:  s.issuerDID,
		StartedAt:  s.nowFunc(),
	}

	ctx, cancel := context.WithTimeout(r.Context(), 30*time.Second)
	defer cancel()
	challenge, err := method.BeginCeremony(ctx, cc)
	if err != nil {
		writeError(w, http.StatusBadRequest, "begin_failed", err.Error())
		return
	}
	writeJSON(w, http.StatusOK, beginMethodResponse{Challenge: challenge})
}

func (s *Server) handleCompleteMethod(w http.ResponseWriter, r *http.Request) {
	methodID := chi.URLParam(r, "methodId")
	method, ok := s.registry.Get(methodID)
	if !ok {
		writeError(w, http.StatusNotFound, "method_not_found",
			fmt.Sprintf("no method with id %q is registered", methodID))
		return
	}

	var req completeMethodRequest
	if err := decodeJSON(r, &req); err != nil {
		writeError(w, http.StatusBadRequest, "invalid_request", err.Error())
		return
	}
	sess, err := s.sessions.Get(req.SessionID)
	if err != nil {
		writeError(w, http.StatusNotFound, "session_not_found", err.Error())
		return
	}

	cc := types.CeremonyContext{
		SessionID:  sess.ID,
		MethodID:   methodID,
		IssuerDID:  s.issuerDID,
		StartedAt:  sess.CreatedAt,
	}

	ctx, cancel := context.WithTimeout(r.Context(), 30*time.Second)
	defer cancel()
	result, err := method.CompleteCeremony(ctx, cc, req.Response)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "complete_failed", err.Error())
		return
	}
	if result.Success {
		if recErr := s.sessions.RecordMethodResult(sess.ID, result, method.Metadata()); recErr != nil {
			writeError(w, http.StatusInternalServerError, "record_failed", recErr.Error())
			return
		}
	}
	view, _ := s.sessions.Snapshot(sess.ID)
	writeJSON(w, http.StatusOK, completeMethodResponse{Result: result, Session: view})
}

// handleEmailMagicLink is the GET /v1/methods/email/verify endpoint the email
// method's magic link points at. It calls the email method's CompleteCeremony
// internally (so issuing a separate POST is not required) and renders a small
// HTML page so the user knows the click succeeded.
//
// Query parameters: session=<sessionID>, token=<magic-link-token>.
func (s *Server) handleEmailMagicLink(w http.ResponseWriter, r *http.Request) {
	sessionID := r.URL.Query().Get("session")
	token := r.URL.Query().Get("token")
	if sessionID == "" || token == "" {
		writeError(w, http.StatusBadRequest, "missing_params", "session and token query parameters are required")
		return
	}
	method, ok := s.registry.Get("email")
	if !ok {
		writeError(w, http.StatusNotFound, "method_not_found", "email method is not registered")
		return
	}
	sess, err := s.sessions.Get(sessionID)
	if err != nil {
		writeError(w, http.StatusNotFound, "session_not_found", err.Error())
		return
	}

	cc := types.CeremonyContext{
		SessionID: sess.ID,
		MethodID:  "email",
		IssuerDID: s.issuerDID,
		StartedAt: sess.CreatedAt,
	}
	resp := types.ResponseData{
		Type:    "magic-link-click",
		Payload: map[string]any{"token": token},
	}
	ctx, cancel := context.WithTimeout(r.Context(), 30*time.Second)
	defer cancel()
	result, err := method.CompleteCeremony(ctx, cc, resp)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "complete_failed", err.Error())
		return
	}
	if result.Success {
		if recErr := s.sessions.RecordMethodResult(sess.ID, result, method.Metadata()); recErr != nil {
			writeError(w, http.StatusInternalServerError, "record_failed", recErr.Error())
			return
		}
	}

	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.WriteHeader(http.StatusOK)
	if result.Success {
		_ = magicLinkSuccessTmpl.Execute(w, nil)
	} else {
		_ = magicLinkFailureTmpl.Execute(w, struct{ Reason string }{Reason: result.ErrorReason})
	}
}

func (s *Server) handleIssueCredential(w http.ResponseWriter, r *http.Request) {
	var req issueCredentialRequest
	if err := decodeJSON(r, &req); err != nil {
		writeError(w, http.StatusBadRequest, "invalid_request", err.Error())
		return
	}
	view, err := s.sessions.Snapshot(req.SessionID)
	if err != nil {
		writeError(w, http.StatusNotFound, "session_not_found", err.Error())
		return
	}
	if view.IssuedCredentialID != "" {
		writeError(w, http.StatusConflict, "already_issued",
			"this session already issued a credential; start a new session to reissue")
		return
	}
	if len(view.VerifiedMethods) == 0 {
		writeError(w, http.StatusUnprocessableEntity, "no_methods_completed",
			"complete at least one method ceremony before requesting issuance")
		return
	}

	issuedAt := s.nowFunc()
	expiresAt := issuedAt.Add(s.credentialLifetime)
	cred, err := s.issuer.Issue(view.HolderDID, view.VerifiedMethods, view.AnchorMethodID, nil, issuedAt, expiresAt, nil)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "issue_failed", err.Error())
		return
	}
	if err := s.sessions.MarkIssued(req.SessionID, cred.ID); err != nil {
		// Already-issued races are reported as 409; everything else as 500.
		status := http.StatusInternalServerError
		if errors.Is(err, ErrSessionAlreadyIssued) {
			status = http.StatusConflict
		}
		writeError(w, status, "mark_issued_failed", err.Error())
		return
	}
	writeJSON(w, http.StatusOK, issueCredentialResponse{Credential: cred})
}

func (s *Server) handleStatusList(w http.ResponseWriter, r *http.Request) {
	// v0.1: the server publishes an empty (no revocations) Status List 2021
	// credential. Revocation issuance is deferred to v0.2.
	listID := chi.URLParam(r, "listId")
	if listID == "" {
		listID = "default"
	}
	bits := credential.NewBitString(131_072) // W3C-recommended minimum size
	encoded, err := bits.Encode()
	if err != nil {
		writeError(w, http.StatusInternalServerError, "encode_failed", err.Error())
		return
	}
	now := s.nowFunc()
	out := map[string]any{
		"@context": []string{
			"https://www.w3.org/2018/credentials/v1",
			"https://w3id.org/vc/status-list/2021/v1",
		},
		"id":           s.statusListURL,
		"type":         []string{"VerifiableCredential", "StatusList2021Credential"},
		"issuer":       s.issuerDID,
		"issuanceDate": now.Format(time.RFC3339),
		"credentialSubject": map[string]any{
			"id":            s.statusListURL + "#list",
			"type":          "StatusList2021",
			"statusPurpose": "revocation",
			"encodedList":   encoded,
		},
		"_note": fmt.Sprintf("v0.1 placeholder list %q: no revocations issued. v0.2 will sign this credential.", listID),
	}
	writeJSON(w, http.StatusOK, out)
}

func (s *Server) handleDIDDocument(w http.ResponseWriter, _ *http.Request) {
	doc, err := BuildDIDDocument(s.issuerDID, "key-1", s.issuerPublicKey)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "did_build_failed", err.Error())
		return
	}
	w.Header().Set("Content-Type", "application/did+json")
	if err := json.NewEncoder(w).Encode(doc); err != nil {
		// can't change status mid-response; just abort
		return
	}
}

// ----------------------------------------------------------------------------
// Helpers
// ----------------------------------------------------------------------------

func (s *Server) methodSummaries() []methodSummary {
	methods := s.registry.List()
	out := make([]methodSummary, 0, len(methods))
	for _, m := range methods {
		md := m.Metadata()
		out = append(out, methodSummary{
			ID:         md.ID,
			Type:       string(md.Type),
			Strength:   md.Strength,
			UXFriction: string(md.UXFriction),
			CostUSD:    md.CostUSD,
			Version:    md.Version,
		})
	}
	return out
}

func decodeJSON(r *http.Request, dst any) error {
	if r.Body == nil {
		return errors.New("request body is empty")
	}
	dec := json.NewDecoder(r.Body)
	dec.DisallowUnknownFields()
	if err := dec.Decode(dst); err != nil {
		return fmt.Errorf("decode body: %w", err)
	}
	return nil
}

func writeJSON(w http.ResponseWriter, status int, body any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(body)
}

func writeError(w http.ResponseWriter, status int, code, message string) {
	writeJSON(w, status, map[string]any{
		"error": map[string]any{
			"code":    code,
			"message": message,
		},
	})
}

// magicLinkSuccessTmpl / magicLinkFailureTmpl render the magic-link landing
// page. html/template auto-escapes any interpolated values, blocking XSS
// even if a method ever surfaces user-controlled text through ErrorReason.
var (
	magicLinkSuccessTmpl = template.Must(template.New("ok").Parse(`<!doctype html>
<html lang="en"><head>
<meta charset="utf-8"><title>Email verified</title>
<meta name="viewport" content="width=device-width,initial-scale=1">
<style>body{font:16px/1.5 system-ui,-apple-system,sans-serif;max-width:480px;margin:48px auto;padding:0 16px;color:#0f1115;background:#fafbfc}h1{font-size:20px;margin:0 0 12px}.ok{padding:16px;border:1px solid #86efac;background:#f0fdf4;border-radius:8px}.muted{color:#6b7280;font-size:14px;margin-top:24px}</style>
</head><body>
<div class="ok"><h1>Email verified</h1><p>You can return to the Personhood enrollment app and continue. This tab can be closed.</p></div>
<p class="muted">Personhood — proof-of-personhood reference issuer</p>
</body></html>`))

	magicLinkFailureTmpl = template.Must(template.New("bad").Parse(`<!doctype html>
<html lang="en"><head>
<meta charset="utf-8"><title>Email verification failed</title>
<meta name="viewport" content="width=device-width,initial-scale=1">
<style>body{font:16px/1.5 system-ui,-apple-system,sans-serif;max-width:480px;margin:48px auto;padding:0 16px;color:#0f1115;background:#fafbfc}h1{font-size:20px;margin:0 0 12px}.bad{padding:16px;border:1px solid #fca5a5;background:#fef2f2;border-radius:8px}.muted{color:#6b7280;font-size:14px;margin-top:24px}code{font-family:ui-monospace,monospace;background:#fff;padding:2px 6px;border-radius:4px;border:1px solid #e5e7eb}</style>
</head><body>
<div class="bad"><h1>Email verification failed</h1><p>Reason: <code>{{.Reason}}</code></p><p>Open a fresh magic link or restart the ceremony from the enrollment app.</p></div>
<p class="muted">Personhood — proof-of-personhood reference issuer</p>
</body></html>`))
)
