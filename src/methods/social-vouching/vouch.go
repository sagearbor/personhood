package socialvouching

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"net/http"
	"sort"
	"time"
)

// VouchMaxBodyBytes caps the vouch submission body.
const VouchMaxBodyBytes = 1 << 16 // 64 KiB, generous for a JSON object of a few strings

// vouchRequest is the JSON body an existing member POSTs to
// /v1/methods/social-vouching-graph/vouch to vouch for a candidate.
type vouchRequest struct {
	CandidateID string `json:"candidate_id"`
	VoucherID   string `json:"voucher_id"`
	Proof       string `json:"proof"`
}

type vouchResponse struct {
	Recorded     bool    `json:"recorded"`
	VoucherTrust float64 `json:"voucher_trust,omitempty"`
	Error        string  `json:"error,omitempty"`
}

// VouchHandler returns the HTTP handler for the out-of-band vouch
// submission route: an existing, already-vouched member asserts they vouch
// for a candidate. It is wired into the server via a methodRoute (see
// src/server/server.go's BuildDependencies), the same mechanism every other
// method's webhook uses (e.g. plaid-bank-link.WebhookHandler) — a vouch
// submission is conceptually the same shape as a webhook: an out-of-band
// signal about a session that isn't the ceremony-completing client itself.
//
// now, if nil, defaults to time.Now.
func (m *Method) VouchHandler(now func() time.Time) http.HandlerFunc {
	if now == nil {
		now = time.Now
	}
	return func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			writeVouchError(w, http.StatusMethodNotAllowed, "method_not_allowed")
			return
		}
		r.Body = http.MaxBytesReader(w, r.Body, VouchMaxBodyBytes)
		var req vouchRequest
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			writeVouchError(w, http.StatusBadRequest, "invalid_request")
			return
		}
		if req.CandidateID == "" || req.VoucherID == "" || req.Proof == "" {
			writeVouchError(w, http.StatusBadRequest, "missing_fields")
			return
		}

		ctx := r.Context()
		if err := m.auth.Authenticate(ctx, req.VoucherID, req.CandidateID, req.Proof); err != nil {
			writeVouchError(w, http.StatusUnauthorized, "proof_invalid")
			return
		}

		trust, known, err := m.store.TrustOf(ctx, req.VoucherID)
		if err != nil {
			writeVouchError(w, http.StatusInternalServerError, "store_error")
			return
		}
		if !known {
			writeVouchError(w, http.StatusForbidden, "unknown_voucher")
			return
		}
		if req.VoucherID == req.CandidateID {
			writeVouchError(w, http.StatusBadRequest, "self_vouch_not_allowed")
			return
		}

		if err := m.store.RecordVouch(ctx, req.CandidateID, Vouch{
			VoucherID: req.VoucherID,
			Weight:    trust,
			At:        now().UTC(),
		}); err != nil {
			writeVouchError(w, http.StatusInternalServerError, "store_error")
			return
		}

		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		_ = json.NewEncoder(w).Encode(vouchResponse{Recorded: true, VoucherTrust: trust})
	}
}

func writeVouchError(w http.ResponseWriter, status int, code string) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(vouchResponse{Recorded: false, Error: code})
}

// vouchDigest is a SHA-256 digest over the candidate id and the sorted set
// of (voucherID, weight) pairs backing a successful ceremony — the audit
// trail this method's AttestationDigest carries, mirroring every other
// method's "digest over the evidence, never the evidence itself" pattern.
func vouchDigest(candidateID string, vouches []Vouch) string {
	sorted := make([]Vouch, len(vouches))
	copy(sorted, vouches)
	sort.Slice(sorted, func(i, j int) bool { return sorted[i].VoucherID < sorted[j].VoucherID })

	h := sha256.New()
	h.Write([]byte(candidateID))
	for _, v := range sorted {
		h.Write([]byte{0})
		h.Write([]byte(v.VoucherID))
	}
	return hex.EncodeToString(h.Sum(nil))
}
