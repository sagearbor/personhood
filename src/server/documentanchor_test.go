package server

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"net/http"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/sagearbor/personhood/pkg/types"
	documentchip "github.com/sagearbor/personhood/src/methods/document-chip"
)

const docVectors = "../methods/document-chip/icao/testdata"

func setDocumentEnv(t *testing.T) {
	t.Setenv("DOCUMENT_CHIP_ANCHOR", "1")
	t.Setenv(IdentifierKeyEnv, base64.StdEncoding.EncodeToString(make([]byte, 32)))
	t.Setenv("DOCUMENT_CHIP_CSCA_PEM", filepath.Join(docVectors, "p256", "csca.pem"))
	t.Setenv("DOCUMENT_CHIP_ALLOW_PASSIVE_ONLY", "1")
	t.Setenv("FIRESTORE_PROJECT_ID", "")
	t.Setenv("REDIS_URL", "")
}

func TestBuildDependencies_DocumentAnchorOff(t *testing.T) {
	t.Setenv("DOCUMENT_CHIP_ANCHOR", "")
	deps, err := BuildDependencies("http://example.invalid/v1/methods/email/verify", "")
	if err != nil {
		t.Fatal(err)
	}
	if _, ok := deps.Registry.Get(documentchip.ChipMethodID); ok {
		t.Fatal("document-chip registered without DOCUMENT_CHIP_ANCHOR=1")
	}
}

func TestBuildDependencies_DocumentAnchorNeedsIdentifierKey(t *testing.T) {
	setDocumentEnv(t)
	t.Setenv(IdentifierKeyEnv, "")
	if _, err := BuildDependencies("http://example.invalid/v1/methods/email/verify", ""); err == nil {
		t.Fatal("DOCUMENT_CHIP_ANCHOR=1 without IDENTIFIER_HMAC_KEY must fail at startup")
	}
}

// TestIntegration_DocumentChip_OneDocumentOneIdentity enrolls the same
// (specimen) passport twice through the HTTP API and requires the same
// nullifier commitment both times: re-enrolling is a re-issue, not a new
// person.
func TestIntegration_DocumentChip_OneDocumentOneIdentity(t *testing.T) {
	setDocumentEnv(t)
	deps, err := BuildDependencies("http://example.invalid/v1/methods/email/verify", "")
	if err != nil {
		t.Fatal(err)
	}
	for _, id := range []string{documentchip.ChipMethodID, documentchip.QRMethodID} {
		m, ok := deps.Registry.Get(id)
		if !ok || m.Metadata().Type != types.MethodTypeAnchor {
			t.Fatalf("%s not registered as an anchor", id)
		}
	}
	listener, err := newLocalListener()
	if err != nil {
		t.Fatal(err)
	}
	_, priv, _ := ed25519.GenerateKey(rand.Reader)
	key := make([]byte, 32)
	srv, err := NewServer(Config{
		Addr:              listener.Addr().String(),
		PublicURL:         "http://" + listener.Addr().String(),
		IssuerPrivateKey:  priv,
		SessionTTL:        10 * time.Minute,
		IdentifierHMACKey: key,
	}, deps)
	if err != nil {
		t.Fatal(err)
	}
	httpServer := &http.Server{Handler: srv.Router()}
	go func() { _ = httpServer.Serve(listener) }()
	defer httpServer.Close()
	base := "http://" + listener.Addr().String()

	read := func(name string) string {
		b, err := os.ReadFile(filepath.Join(docVectors, "p256", name))
		if err != nil {
			t.Fatal(err)
		}
		return base64.StdEncoding.EncodeToString(b)
	}
	enroll := func() string {
		var start startEnrollmentResponse
		mustPOST(t, base+"/enrollment/start", mustJSON(t, map[string]any{}), &start)
		var begin beginMethodResponse
		mustPOST(t, base+"/v1/methods/document-chip/begin", mustJSON(t, map[string]any{"session_id": start.SessionID, "user_input": ""}), &begin)
		if begin.Challenge.Payload["aa_challenge_hex"] == nil {
			t.Fatalf("begin payload %+v", begin.Challenge.Payload)
		}
		var complete completeMethodResponse
		mustPOST(t, base+"/v1/methods/document-chip/complete", mustJSON(t, map[string]any{
			"session_id": start.SessionID,
			"response": types.ResponseData{Type: "document-chip", Payload: map[string]any{
				"sod_b64":   read("EF.SOD"),
				"dg1_b64":   read("EF.DG1"),
				"face_bind": map[string]any{"match": true, "liveness": true},
			}},
		}), &complete)
		if !complete.Result.Success {
			t.Fatalf("complete: %+v", complete.Result)
		}
		var issued issueCredentialResponse
		mustPOST(t, base+"/v1/credentials/issue", mustJSON(t, map[string]any{"session_id": start.SessionID}), &issued)
		subj := issued.Credential.CredentialSubject
		if subj.AnchorMethodID == nil || *subj.AnchorMethodID != documentchip.ChipMethodID {
			t.Fatalf("anchor = %v", subj.AnchorMethodID)
		}
		if subj.NullifierBinding == nil {
			t.Fatal("no nullifier binding")
		}
		return subj.NullifierBinding.Commitment
	}
	first, second := enroll(), enroll()
	if first != second {
		t.Fatalf("same document, different commitments: %s vs %s", first, second)
	}
}
