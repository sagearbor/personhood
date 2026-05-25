package credential

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/sagearbor/personhood/pkg/types"
)

func TestBitString_RoundTrip(t *testing.T) {
	t.Parallel()
	b := NewBitString(1024)
	for _, i := range []int{0, 1, 7, 8, 9, 42, 100, 1023} {
		if err := b.Set(i); err != nil {
			t.Fatalf("Set(%d): %v", i, err)
		}
	}
	encoded, err := b.Encode()
	if err != nil {
		t.Fatalf("Encode: %v", err)
	}
	decoded, err := DecodeBitString(encoded)
	if err != nil {
		t.Fatalf("DecodeBitString: %v", err)
	}
	for _, i := range []int{0, 1, 7, 8, 9, 42, 100, 1023} {
		if !decoded.Get(i) {
			t.Errorf("expected bit %d set after roundtrip", i)
		}
	}
	for _, i := range []int{2, 3, 4, 5, 6, 10, 41, 43, 99, 1022} {
		if decoded.Get(i) {
			t.Errorf("expected bit %d clear after roundtrip", i)
		}
	}
}

func TestBitString_GetOutOfRange(t *testing.T) {
	t.Parallel()
	b := NewBitString(16)
	if b.Get(-1) {
		t.Error("negative index should return false")
	}
	if b.Get(16) {
		t.Error("index past length should return false")
	}
	if b.Get(99999) {
		t.Error("very large index should return false")
	}
}

func TestBitString_SetOutOfRange(t *testing.T) {
	t.Parallel()
	b := NewBitString(8)
	if err := b.Set(-1); err == nil {
		t.Error("expected error setting negative bit")
	}
	if err := b.Set(8); err == nil {
		t.Error("expected error setting bit past length")
	}
}

func TestIsRevoked_NilStatus(t *testing.T) {
	t.Parallel()
	cred := types.PersonhoodCredential{}
	revoked, err := IsRevoked(context.Background(), nil, cred)
	if err != nil {
		t.Fatalf("IsRevoked: %v", err)
	}
	if revoked {
		t.Error("expected not revoked when CredentialStatus is nil")
	}
}

// statusListServer spins up an httptest.Server that responds to the configured
// path with a W3C Status List 2021 credential containing the supplied encoded
// bitstring.
func statusListServer(t *testing.T, encodedList string) *httptest.Server {
	t.Helper()
	mux := http.NewServeMux()
	mux.HandleFunc("/status/1", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		body := map[string]any{
			"@context": []string{"https://www.w3.org/2018/credentials/v1"},
			"id":       "https://example.test/status/1",
			"type":     []string{"VerifiableCredential", "StatusList2021Credential"},
			"credentialSubject": map[string]any{
				"id":            "https://example.test/status/1#list",
				"type":          "StatusList2021",
				"statusPurpose": "revocation",
				"encodedList":   encodedList,
			},
		}
		_ = json.NewEncoder(w).Encode(body)
	})
	return httptest.NewServer(mux)
}

func TestIsRevoked_BitSet(t *testing.T) {
	t.Parallel()
	bits := NewBitString(1024)
	if err := bits.Set(42); err != nil {
		t.Fatalf("Set: %v", err)
	}
	encoded, err := bits.Encode()
	if err != nil {
		t.Fatalf("Encode: %v", err)
	}
	srv := statusListServer(t, encoded)
	defer srv.Close()

	cred := types.PersonhoodCredential{
		CredentialStatus: &types.CredentialStatus{
			ID:                   srv.URL + "/status/1#42",
			Type:                 StatusList2021EntryType,
			StatusPurpose:        "revocation",
			StatusListIndex:      42,
			StatusListCredential: srv.URL + "/status/1",
		},
	}
	revoked, err := IsRevoked(context.Background(), srv.Client(), cred)
	if err != nil {
		t.Fatalf("IsRevoked: %v", err)
	}
	if !revoked {
		t.Error("expected revoked=true for bit 42")
	}
}

func TestIsRevoked_BitClear(t *testing.T) {
	t.Parallel()
	bits := NewBitString(1024)
	if err := bits.Set(7); err != nil {
		t.Fatalf("Set: %v", err)
	}
	encoded, err := bits.Encode()
	if err != nil {
		t.Fatalf("Encode: %v", err)
	}
	srv := statusListServer(t, encoded)
	defer srv.Close()

	cred := types.PersonhoodCredential{
		CredentialStatus: &types.CredentialStatus{
			ID:                   srv.URL + "/status/1#100",
			Type:                 StatusList2021EntryType,
			StatusPurpose:        "revocation",
			StatusListIndex:      100,
			StatusListCredential: srv.URL + "/status/1",
		},
	}
	revoked, err := IsRevoked(context.Background(), srv.Client(), cred)
	if err != nil {
		t.Fatalf("IsRevoked: %v", err)
	}
	if revoked {
		t.Error("expected revoked=false for clear bit 100")
	}
}

func TestIsRevoked_EmptyBitString(t *testing.T) {
	t.Parallel()
	bits := NewBitString(1024) // all clear
	encoded, err := bits.Encode()
	if err != nil {
		t.Fatalf("Encode: %v", err)
	}
	srv := statusListServer(t, encoded)
	defer srv.Close()

	for _, i := range []int{0, 1, 100, 1023} {
		cred := types.PersonhoodCredential{
			CredentialStatus: &types.CredentialStatus{
				ID:                   fmt.Sprintf("%s/status/1#%d", srv.URL, i),
				Type:                 StatusList2021EntryType,
				StatusPurpose:        "revocation",
				StatusListIndex:      i,
				StatusListCredential: srv.URL + "/status/1",
			},
		}
		revoked, err := IsRevoked(context.Background(), srv.Client(), cred)
		if err != nil {
			t.Fatalf("IsRevoked(idx=%d): %v", i, err)
		}
		if revoked {
			t.Errorf("expected revoked=false for empty bitstring at idx %d", i)
		}
	}
}

func TestIsRevoked_UnsupportedType(t *testing.T) {
	t.Parallel()
	cred := types.PersonhoodCredential{
		CredentialStatus: &types.CredentialStatus{
			Type: "RevocationList2020Status",
		},
	}
	if _, err := IsRevoked(context.Background(), nil, cred); err == nil {
		t.Error("expected error for unsupported status type")
	}
}

func TestIsRevoked_NegativeIndex(t *testing.T) {
	t.Parallel()
	cred := types.PersonhoodCredential{
		CredentialStatus: &types.CredentialStatus{
			Type:                 StatusList2021EntryType,
			StatusListIndex:      -1,
			StatusListCredential: "http://unused",
		},
	}
	if _, err := IsRevoked(context.Background(), nil, cred); err == nil {
		t.Error("expected error for negative status index")
	}
}

func TestFetchStatusList_BadStatusCode(t *testing.T) {
	t.Parallel()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusNotFound)
	}))
	defer srv.Close()
	if _, err := FetchStatusList(context.Background(), srv.Client(), srv.URL+"/missing"); err == nil {
		t.Error("expected error for 404")
	}
}

func TestFetchStatusList_EmptyURL(t *testing.T) {
	t.Parallel()
	if _, err := FetchStatusList(context.Background(), nil, ""); err == nil {
		t.Error("expected error for empty URL")
	}
}

func TestFetchStatusList_MissingEncodedList(t *testing.T) {
	t.Parallel()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"credentialSubject":{}}`))
	}))
	defer srv.Close()
	if _, err := FetchStatusList(context.Background(), srv.Client(), srv.URL); err == nil {
		t.Error("expected error for missing encodedList")
	}
}

func TestFetchStatusList_RealFixture(t *testing.T) {
	// Ensure FetchStatusList interoperates with statusListServer end-to-end.
	t.Parallel()
	bits := NewBitString(64)
	if err := bits.Set(3); err != nil {
		t.Fatalf("Set: %v", err)
	}
	encoded, err := bits.Encode()
	if err != nil {
		t.Fatalf("Encode: %v", err)
	}
	srv := statusListServer(t, encoded)
	defer srv.Close()
	got, err := FetchStatusList(context.Background(), srv.Client(), srv.URL+"/status/1")
	if err != nil {
		t.Fatalf("FetchStatusList: %v", err)
	}
	if !got.Get(3) {
		t.Error("expected bit 3 set after fetch")
	}
}

func TestFetchStatusList_RespectsContext(t *testing.T) {
	t.Parallel()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		time.Sleep(50 * time.Millisecond)
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()
	ctx, cancel := context.WithCancel(context.Background())
	cancel() // cancel immediately
	_, err := FetchStatusList(ctx, srv.Client(), srv.URL)
	if err == nil {
		t.Error("expected error from cancelled context")
	}
}
