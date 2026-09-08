package socialvouching

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/sagearbor/personhood/pkg/types"
)

func postVouch(t *testing.T, m *Method, body vouchRequest) (*httptest.ResponseRecorder, vouchResponse) {
	t.Helper()
	b, err := json.Marshal(body)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	req := httptest.NewRequest(http.MethodPost, "/v1/methods/"+MethodID+"/vouch", bytes.NewReader(b))
	rec := httptest.NewRecorder()
	m.VouchHandler(nil).ServeHTTP(rec, req)
	var resp vouchResponse
	if rec.Body.Len() > 0 {
		if err := json.Unmarshal(rec.Body.Bytes(), &resp); err != nil {
			t.Fatalf("unmarshal response: %v (body: %s)", err, rec.Body.String())
		}
	}
	return rec, resp
}

func TestVouchHandler_Success(t *testing.T) {
	t.Parallel()
	m := newTestMethod(map[string]float64{"seed-1": 1.0})
	proof := SignVouchForTesting(testSecret, "seed-1", "candidate-1")

	rec, resp := postVouch(t, m, vouchRequest{CandidateID: "candidate-1", VoucherID: "seed-1", Proof: proof})
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200 (body: %s)", rec.Code, rec.Body.String())
	}
	if !resp.Recorded {
		t.Fatalf("Recorded = false, want true (error: %s)", resp.Error)
	}
	if resp.VoucherTrust != 1.0 {
		t.Fatalf("VoucherTrust = %v, want 1.0", resp.VoucherTrust)
	}

	vouches, err := m.store.VouchesFor(context.Background(), "candidate-1")
	if err != nil {
		t.Fatalf("VouchesFor: %v", err)
	}
	if len(vouches) != 1 || vouches[0].VoucherID != "seed-1" {
		t.Fatalf("VouchesFor = %+v, want one vouch from seed-1", vouches)
	}
}

func TestVouchHandler_BadProofRejected(t *testing.T) {
	t.Parallel()
	m := newTestMethod(map[string]float64{"seed-1": 1.0})
	rec, resp := postVouch(t, m, vouchRequest{CandidateID: "candidate-1", VoucherID: "seed-1", Proof: "wrong-proof"})
	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("status = %d, want 401", rec.Code)
	}
	if resp.Recorded {
		t.Fatal("Recorded = true for a bad proof")
	}
}

func TestVouchHandler_UnknownVoucherRejected(t *testing.T) {
	t.Parallel()
	m := newTestMethod(nil) // no seeds at all
	proof := SignVouchForTesting(testSecret, "nobody", "candidate-1")
	rec, resp := postVouch(t, m, vouchRequest{CandidateID: "candidate-1", VoucherID: "nobody", Proof: proof})
	if rec.Code != http.StatusForbidden {
		t.Fatalf("status = %d, want 403", rec.Code)
	}
	if resp.Recorded {
		t.Fatal("Recorded = true for an unknown voucher")
	}
}

func TestVouchHandler_SelfVouchRejected(t *testing.T) {
	t.Parallel()
	m := newTestMethod(map[string]float64{"seed-1": 1.0})
	proof := SignVouchForTesting(testSecret, "seed-1", "seed-1")
	rec, resp := postVouch(t, m, vouchRequest{CandidateID: "seed-1", VoucherID: "seed-1", Proof: proof})
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("status = %d, want 400", rec.Code)
	}
	if resp.Recorded {
		t.Fatal("Recorded = true for a self-vouch")
	}
}

func TestVouchHandler_MissingFields(t *testing.T) {
	t.Parallel()
	m := newTestMethod(map[string]float64{"seed-1": 1.0})
	rec, resp := postVouch(t, m, vouchRequest{CandidateID: "candidate-1"})
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("status = %d, want 400", rec.Code)
	}
	if resp.Recorded {
		t.Fatal("Recorded = true with missing fields")
	}
}

func TestVouchHandler_WrongHTTPMethod(t *testing.T) {
	t.Parallel()
	m := newTestMethod(nil)
	req := httptest.NewRequest(http.MethodGet, "/v1/methods/"+MethodID+"/vouch", nil)
	rec := httptest.NewRecorder()
	m.VouchHandler(nil).ServeHTTP(rec, req)
	if rec.Code != http.StatusMethodNotAllowed {
		t.Fatalf("status = %d, want 405", rec.Code)
	}
}

func TestVouchHandler_MalformedJSON(t *testing.T) {
	t.Parallel()
	m := newTestMethod(nil)
	req := httptest.NewRequest(http.MethodPost, "/v1/methods/"+MethodID+"/vouch", strings.NewReader("{not json"))
	rec := httptest.NewRecorder()
	m.VouchHandler(nil).ServeHTTP(rec, req)
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("status = %d, want 400", rec.Code)
	}
}

// TestVouchHandler_EndToEndThroughCompleteCeremony proves the HTTP vouch
// route and CompleteCeremony agree: enough real HTTP vouches make the
// ceremony succeed.
func TestVouchHandler_EndToEndThroughCompleteCeremony(t *testing.T) {
	t.Parallel()
	m := newTestMethod(map[string]float64{"seed-1": 1.0, "seed-2": 1.0, "seed-3": 1.0})
	for _, voucher := range []string{"seed-1", "seed-2", "seed-3"} {
		proof := SignVouchForTesting(testSecret, voucher, "candidate-1")
		rec, resp := postVouch(t, m, vouchRequest{CandidateID: "candidate-1", VoucherID: voucher, Proof: proof})
		if rec.Code != http.StatusOK || !resp.Recorded {
			t.Fatalf("vouch from %s: status=%d recorded=%v error=%s", voucher, rec.Code, resp.Recorded, resp.Error)
		}
	}

	result, err := m.CompleteCeremony(context.Background(), types.CeremonyContext{SessionID: "candidate-1"}, types.ResponseData{})
	if err != nil {
		t.Fatalf("CompleteCeremony: %v", err)
	}
	if !result.Success {
		t.Fatalf("CompleteCeremony after 3 real HTTP vouches: Success = false, ErrorReason = %q", result.ErrorReason)
	}
}
