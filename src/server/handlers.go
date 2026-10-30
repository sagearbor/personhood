package server

import (
	"context"
	"crypto/ed25519"
	"crypto/subtle"
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
	fuzzyextractorselfie "github.com/sagearbor/personhood/src/methods/fuzzy-extractor-selfie"
	ipasnmethod "github.com/sagearbor/personhood/src/methods/ip-asn-reputation"
)

// startEnrollmentRequest is the JSON body of POST /enrollment/start.
//
// Every field is optional. holder_public_key_b64, when supplied, is a
// 32-byte Ed25519 public key the client generated; it is mixed into the
// holder DID derivation so the same key always maps to the same DID. user
// agent / platform / etc. flow through to methods that care.
//
// invite_code is required only when the server was configured with
// Config.EnrollmentInviteCode (env ENROLLMENT_INVITE_CODE); clients discover
// whether they must ask the user for one from GET /v1/config.
type startEnrollmentRequest struct {
	HolderPublicKeyB64 string `json:"holder_public_key_b64,omitempty"`
	UserAgent          string `json:"user_agent,omitempty"`
	Platform           string `json:"platform,omitempty"`
	CountryCode        string `json:"country_code,omitempty"`
	InviteCode         string `json:"invite_code,omitempty"`
}

// startEnrollmentResponse is returned by POST /enrollment/start.
type startEnrollmentResponse struct {
	SessionID        string          `json:"session_id"`
	HolderDID        types.DID       `json:"holder_did"`
	IssuerDID        types.DID       `json:"issuer_did"`
	ExpiresAt        time.Time       `json:"expires_at"`
	AvailableMethods []methodSummary `json:"available_methods"`
	// HolderProofMessage is set when the request declared a holder key: the
	// exact UTF-8 string the client signs with that key and sends back as
	// holder_proof_b64 at issuance (see holderpop.go).
	HolderProofMessage string `json:"holder_proof_message,omitempty"`
}

// methodSummary is the projection of MethodMetadata returned to clients on
// the enrollment-start and list-methods endpoints. Same shape as the
// underlying type — kept as a named alias so the wire contract is explicit.
type methodSummary struct {
	ID         string  `json:"id"`
	Type       string  `json:"type"`
	Strength   int     `json:"strength"`
	UXFriction string  `json:"ux_friction"`
	CostUSD    float64 `json:"cost_usd"`
	Version    string  `json:"version"`
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
	Result  types.MethodResult `json:"result"`
	Session SessionView        `json:"session"`
}

// serverConfigResponse is the JSON body of GET /v1/config — the public,
// unauthenticated description of how this deployment is configured.
//
// It deliberately carries no secrets: only whether a gate exists, not the
// code that opens it. A client uses it to decide whether to prompt for an
// invite code before calling /enrollment/start, and to warn the user when
// magic links are being handed back over the wire instead of emailed.
type serverConfigResponse struct {
	// InviteCodeRequired reports whether POST /enrollment/start demands an
	// invite_code field.
	InviteCodeRequired bool `json:"invite_code_required"`

	// ChallengeSecretsExposed reports whether POST /v1/methods/{id}/begin
	// returns secret-bearing challenge fields (the email magic_link_url) to
	// the caller. True means this deployment is in dev/preview mode and the
	// email method proves nothing about address ownership.
	ChallengeSecretsExposed bool `json:"challenge_secrets_exposed"`

	// EmailDelivery names the email backend the server selected at startup:
	// "log", "smtp", "sendgrid", or "unknown" (a custom/injected Sender).
	EmailDelivery string `json:"email_delivery"`

	// SMSDelivery is the same for SMS: "log" (codes go only to the server
	// log — a phone number entered here receives nothing), "twilio", or
	// "unknown". The web app hides the SMS step when it is "log".
	SMSDelivery string `json:"sms_delivery"`

	// IdentifierDedup reports whether per-identifier nullifier seeds are on
	// (IDENTIFIER_HMAC_KEY set): a second enrollment by the same email or
	// phone gets the same nullifierBinding back instead of a new one.
	IdentifierDedup bool `json:"identifier_dedup"`

	// HolderPoPRequired reports whether issuance needs holder_proof_b64
	// from sessions that declared a holder key (REQUIRE_HOLDER_POP).
	HolderPoPRequired bool `json:"holder_pop_required"`
}

// issueCredentialRequest is the JSON body of POST /v1/credentials/issue.
type issueCredentialRequest struct {
	SessionID string `json:"session_id"`
	// HolderProofB64 is an Ed25519 signature, by the session's holder key,
	// over the session's holder_proof_message. Required when the server
	// runs with RequireHolderPoP and the session declared a holder key;
	// verified whenever present.
	HolderProofB64 string `json:"holder_proof_b64,omitempty"`
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

func (s *Server) handleConfig(w http.ResponseWriter, _ *http.Request) {
	writeJSON(w, http.StatusOK, serverConfigResponse{
		InviteCodeRequired:      s.cfg.EnrollmentInviteCode != "",
		ChallengeSecretsExposed: s.cfg.ExposeChallengeSecrets,
		EmailDelivery:           s.emailDelivery,
		SMSDelivery:             s.smsDelivery,
		IdentifierDedup:         s.identifierKeys != nil,
		HolderPoPRequired:       s.cfg.RequireHolderPoP,
	})
}

func (s *Server) handleStartEnrollment(w http.ResponseWriter, r *http.Request) {
	var req startEnrollmentRequest
	if err := decodeJSON(r, &req); err != nil {
		writeError(w, http.StatusBadRequest, "invalid_request", err.Error())
		return
	}

	// Invite gate, before any session is allocated. Never log req.InviteCode.
	if err := s.checkInviteCode(req.InviteCode); err != nil {
		writeError(w, http.StatusForbidden, err.code, err.message)
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

	view, err := s.sessions.Create(holderPub, s.nowFunc())
	if err != nil {
		writeError(w, http.StatusInternalServerError, "session_create_failed", err.Error())
		return
	}

	resp := startEnrollmentResponse{
		SessionID:        view.ID,
		HolderDID:        view.HolderDID,
		IssuerDID:        s.issuerDID,
		ExpiresAt:        view.ExpiresAt,
		AvailableMethods: s.methodSummaries(),
	}
	if holderPub != nil {
		resp.HolderProofMessage = HolderPoPMessage(s.issuerDID, view.ID)
	}
	writeJSON(w, http.StatusOK, resp)
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

	// With per-identifier seeds on, an identifier that has no single
	// canonical form (a phone number without its country code) is refused
	// before anything is sent: it could be enrolled again under another
	// spelling as a different person.
	if kind := identifierKindForMethod(methodID); kind != "" && s.identifierKeys != nil {
		if _, err := normalizeIdentifier(kind, req.UserInput); err != nil {
			writeError(w, http.StatusBadRequest, "invalid_identifier", err.Error())
			return
		}
	}

	cc := types.CeremonyContext{
		SessionID: sess.ID,
		HolderDID: sess.HolderDID,
		UserID:    req.UserInput, // v0.1 hand-off — see email.go / sms.go
		MethodID:  methodID,
		IssuerDID: s.issuerDID,
		StartedAt: s.nowFunc(),
	}

	ctx, cancel := context.WithTimeout(r.Context(), 30*time.Second)
	defer cancel()
	challenge, err := method.BeginCeremony(ctx, cc)
	if err != nil {
		writeError(w, http.StatusBadRequest, "begin_failed", err.Error())
		return
	}
	writeJSON(w, http.StatusOK, beginMethodResponse{Challenge: s.redactChallenge(challenge)})
}

// challengeSecretKeys lists ChallengeData payload keys that must never reach
// the client in a real deployment. A method may include them for the benefit
// of its Sender / logs, but handing them to the browser would let the client
// complete the ceremony without the out-of-band step the method exists to
// prove (e.g. the email magic link proves inbox control only if the link is
// delivered to the inbox — not to whoever called /begin).
var challengeSecretKeys = []string{"magic_link_url"}

// redactChallenge returns a copy of ch with challengeSecretKeys removed from
// the payload, unless Config.ExposeChallengeSecrets is set (dev/test only).
func (s *Server) redactChallenge(ch types.ChallengeData) types.ChallengeData {
	if s.cfg.ExposeChallengeSecrets || len(ch.Payload) == 0 {
		return ch
	}
	out := types.ChallengeData{Type: ch.Type, Payload: make(map[string]any, len(ch.Payload))}
	for k, v := range ch.Payload {
		out.Payload[k] = v
	}
	for _, k := range challengeSecretKeys {
		delete(out.Payload, k)
	}
	return out
}

// handleGetSession is GET /v1/sessions/{sessionId}. It returns the same
// SessionView that /complete returns, so a client can poll for progress made
// out of band — most importantly whether the email magic link has been
// clicked (in another tab, or on another device) — instead of guessing.
//
// The session ID is a 32-byte random bearer token, exactly as it is for
// /credentials/issue, so knowing it is the authorization.
func (s *Server) handleGetSession(w http.ResponseWriter, r *http.Request) {
	sessionID := chi.URLParam(r, "sessionId")
	view, err := s.sessions.Get(sessionID)
	if err != nil {
		writeError(w, http.StatusNotFound, "session_not_found", err.Error())
		return
	}
	writeJSON(w, http.StatusOK, view)
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
		SessionID: sess.ID,
		HolderDID: sess.HolderDID,
		MethodID:  methodID,
		IssuerDID: s.issuerDID,
		StartedAt: sess.CreatedAt,
	}

	// ip-asn-reputation judges the caller's own address, so the server fills
	// it in; a client-supplied "ip" would let anyone pick a clean one.
	if methodID == ipasnmethod.MethodID {
		payload := map[string]any{}
		for k, v := range req.Response.Payload {
			payload[k] = v
		}
		payload["ip"] = clientIP(r, s.cfg.RateLimit.TrustedProxyHops)
		req.Response.Payload = payload
	}

	ctx, cancel := context.WithTimeout(r.Context(), 30*time.Second)
	defer cancel()
	result, err := method.CompleteCeremony(ctx, cc, req.Response)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "complete_failed", err.Error())
		return
	}
	if result.Success {
		if recErr := s.recordVerified(sess.ID, methodID, result, method.Metadata()); recErr != nil {
			writeError(w, http.StatusInternalServerError, "record_failed", recErr.Error())
			return
		}
	}
	view, _ := s.sessions.Get(sess.ID)
	writeJSON(w, http.StatusOK, completeMethodResponse{Result: result, Session: view})
}

// handleEmailMagicLink is the GET /v1/methods/email/verify endpoint every
// magic-link email points at — both the plain "email" method and the
// strength-22 "email-tier" upgrade (checklist #8) share this single landing
// route so there is one base URL to expose publicly. It calls the target
// method's CompleteCeremony internally (so issuing a separate POST is not
// required) and renders a small HTML page so the user knows the click
// succeeded.
//
// Query parameters: session=<sessionID>, token=<magic-link-token>,
// method=<methodID> (optional, defaults to "email" so links minted before
// this parameter existed keep working).
func (s *Server) handleEmailMagicLink(w http.ResponseWriter, r *http.Request) {
	sessionID := r.URL.Query().Get("session")
	token := r.URL.Query().Get("token")
	if sessionID == "" || token == "" {
		writeError(w, http.StatusBadRequest, "missing_params", "session and token query parameters are required")
		return
	}
	methodID := r.URL.Query().Get("method")
	if methodID == "" {
		methodID = "email"
	}
	method, ok := s.registry.Get(methodID)
	if !ok {
		writeError(w, http.StatusNotFound, "method_not_found", fmt.Sprintf("%s method is not registered", methodID))
		return
	}
	sess, err := s.sessions.Get(sessionID)
	if err != nil {
		writeError(w, http.StatusNotFound, "session_not_found", err.Error())
		return
	}

	cc := types.CeremonyContext{
		SessionID: sess.ID,
		HolderDID: sess.HolderDID,
		MethodID:  methodID,
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
		if recErr := s.recordVerified(sess.ID, methodID, result, method.Metadata()); recErr != nil {
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
	view, err := s.sessions.Get(req.SessionID)
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
	if err := s.checkHolderPoP(view, req.HolderProofB64); err != nil {
		writeError(w, http.StatusForbidden, err.code, err.message)
		return
	}

	issuedAt := s.nowFunc()
	expiresAt := issuedAt.Add(s.credentialLifetime)
	// NullifierBindingForHolder returns nil when the session has no
	// client-supplied holder public key (e.g. the round-1 email-only flow),
	// so such credentials are issued without a nullifierBinding and fail
	// closed against any policy with nullifier_required: true.
	nullifierBinding := NullifierBindingForHolder(view.HolderPublicKey)
	// When the session's verified methods include a successful
	// fuzzy-extractor-selfie anchor (checklist #10a), prefer deriving the
	// nullifierBinding from ITS biometric commitment instead: a device
	// keypair can be regenerated at will, but the biometric commitment is
	// stable per-person (enforced by the method's Accumulator dedup check)
	// and unique across people. See NullifierBindingForBiometricCommitment's
	// doc comment for why this matters for OpenLine's airdrop-test UBI/vote
	// use cases.
	//
	// Between the two: when per-identifier seeds are on and the session
	// verified an email or phone, the binding comes from that identifier's
	// seed, so the same inbox always gets the same binding no matter how
	// many device keys it enrolls with (identifier.go).
	bio := biometricCommitmentFromVerifiedMethods(view.VerifiedMethods, fuzzyextractorselfie.MethodID)
	if bio == "" && s.identifierKeys != nil {
		for _, vm := range view.VerifiedMethods {
			if kind := identifierKindForMethod(vm.MethodID); kind != "" && view.IdentifierKeys[kind] == "" {
				// Verified before this issuer keyed identifiers (an
				// in-flight session across the deploy). Issuing would
				// hand out an unbound, repeatable credential.
				writeError(w, http.StatusConflict, "reverify_required",
					"this session's "+kind+" was verified before identifier binding was on; start a new enrollment")
				return
			}
		}
		if len(view.IdentifierKeys) > 0 {
			seed, err := resolveIdentifierSeed(r.Context(), s.identifiers, view.IdentifierKeys)
			if err != nil {
				writeError(w, http.StatusInternalServerError, "identifier_seed_failed", err.Error())
				return
			}
			nullifierBinding = NullifierBindingForIdentifierSeed(seed)
		}
	}
	if bio != "" {
		nullifierBinding = NullifierBindingForBiometricCommitment(bio)
	}
	// Every credential gets a random slot in the status list so it can be
	// revoked later (see RevocationStore). A slot claimed for a request
	// that then fails stays unused, which is harmless.
	statusIndex, err := s.revocations.Allocate(r.Context())
	if err != nil {
		writeError(w, http.StatusInternalServerError, "status_slot_failed", err.Error())
		return
	}
	cred, err := s.issuer.Issue(view.HolderDID, view.VerifiedMethods, view.AnchorMethodID, nullifierBinding, issuedAt, expiresAt, &statusIndex)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "issue_failed", err.Error())
		return
	}
	if err := s.revocations.Bind(r.Context(), statusIndex, cred.ID); err != nil {
		writeError(w, http.StatusInternalServerError, "status_slot_failed", err.Error())
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
	// The issuer publishes one list, "default". Credentials reference it by
	// absolute URL, so any other id is unknown.
	if chi.URLParam(r, "listId") != "default" {
		writeError(w, http.StatusNotFound, "status_list_not_found", "this issuer publishes only the \"default\" status list")
		return
	}
	revoked, err := s.revocations.Revoked(r.Context())
	if err != nil {
		writeError(w, http.StatusInternalServerError, "status_list_failed", err.Error())
		return
	}
	bits := credential.NewBitString(statusListSize)
	for _, idx := range revoked {
		if err := bits.Set(idx); err != nil {
			writeError(w, http.StatusInternalServerError, "status_list_failed", err.Error())
			return
		}
	}
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
		"_note": "v0.1: this status list credential is not signed yet; fetch it over HTTPS from the issuer's own host.",
	}
	// Short cache: verifiers may reuse the list briefly, and a revocation
	// shows up within a minute (the store itself caches for 30s).
	w.Header().Set("Cache-Control", "public, max-age=30")
	writeJSON(w, http.StatusOK, out)
}

type adminRevokeRequest struct {
	CredentialID string `json:"credential_id"`
}

type adminRevokeResponse struct {
	CredentialID    string `json:"credential_id"`
	StatusListIndex int    `json:"status_list_index"`
	AlreadyRevoked  bool   `json:"already_revoked"`
}

// handleAdminRevoke sets a credential's revocation bit. Mounted only when
// Config.AdminToken is set; the caller must send it as a Bearer token.
func (s *Server) handleAdminRevoke(w http.ResponseWriter, r *http.Request) {
	const prefix = "Bearer "
	got := r.Header.Get("Authorization")
	if !strings.HasPrefix(got, prefix) ||
		subtle.ConstantTimeCompare([]byte(strings.TrimPrefix(got, prefix)), []byte(s.cfg.AdminToken)) != 1 {
		writeError(w, http.StatusUnauthorized, "unauthorized", "a valid admin bearer token is required")
		return
	}
	var req adminRevokeRequest
	if err := decodeJSON(r, &req); err != nil {
		writeError(w, http.StatusBadRequest, "invalid_request", err.Error())
		return
	}
	if strings.TrimSpace(req.CredentialID) == "" {
		writeError(w, http.StatusBadRequest, "invalid_request", "credential_id is required")
		return
	}
	idx, already, err := s.revocations.Revoke(r.Context(), req.CredentialID)
	if errors.Is(err, ErrCredentialNotFound) {
		writeError(w, http.StatusNotFound, "credential_not_found", err.Error())
		return
	}
	if err != nil {
		writeError(w, http.StatusInternalServerError, "revoke_failed", err.Error())
		return
	}
	writeJSON(w, http.StatusOK, adminRevokeResponse{CredentialID: req.CredentialID, StatusListIndex: idx, AlreadyRevoked: already})
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

// apiError is a machine-readable code plus a human message, in the shape
// writeError renders. checkInviteCode returns one so the gate's decision can
// be unit-tested without an http.ResponseWriter.
type apiError struct {
	code    string
	message string
}

var (
	errInviteCodeRequired = &apiError{"invite_code_required", "this issuer requires an invite code; pass invite_code in the request body"}
	errInviteCodeInvalid  = &apiError{"invite_code_invalid", "invite code is not valid"}
)

// checkInviteCode enforces Config.EnrollmentInviteCode against the supplied
// code. It returns nil when the server has no gate configured, or when the
// supplied code matches.
//
// The comparison is constant-time so a caller cannot recover the code one
// byte at a time from response latency. Neither the configured code nor the
// supplied one is ever written to a log or to the error message.
func (s *Server) checkInviteCode(supplied string) *apiError {
	want := s.cfg.EnrollmentInviteCode
	if want == "" {
		return nil
	}
	got := strings.TrimSpace(supplied)
	if got == "" {
		return errInviteCodeRequired
	}
	if subtle.ConstantTimeCompare([]byte(got), []byte(want)) != 1 {
		return errInviteCodeInvalid
	}
	return nil
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

// recordVerified stores a successful method result on the session. When
// per-identifier seeds are on and the method verified an email or phone, it
// first records the identifier's keyed hash (never the identifier itself),
// so issuance can bind the credential to it. The key is written before the
// method result: if the second write fails the client retries the
// ceremony, and a key without its method is never used on its own.
func (s *Server) recordVerified(sessionID, methodID string, result types.MethodResult, meta types.MethodMetadata) error {
	raw := result.VerifiedIdentifier
	result.VerifiedIdentifier = ""
	if kind := identifierKindForMethod(methodID); kind != "" && s.identifierKeys != nil {
		if raw == "" {
			return fmt.Errorf("method %q verified no identifier; cannot bind the credential to it", methodID)
		}
		normalized, err := normalizeIdentifier(kind, raw)
		if err != nil {
			return err
		}
		if err := s.sessions.SetIdentifierKey(sessionID, kind, s.identifierKeys.Key(kind, normalized)); err != nil {
			return err
		}
	}
	return s.sessions.RecordMethodResult(sessionID, result, meta)
}
