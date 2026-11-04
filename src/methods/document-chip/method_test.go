package documentchip

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha1" //nolint:gosec
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"encoding/pem"
	"math/big"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"testing/fstest"
	"time"

	"github.com/sagearbor/personhood/pkg/types"
	"github.com/sagearbor/personhood/src/methods/document-chip/icao"
	"github.com/sagearbor/personhood/src/methods/document-chip/signedqr"
	fes "github.com/sagearbor/personhood/src/methods/fuzzy-extractor-selfie"
)

var testNow = time.Date(2026, 11, 4, 12, 0, 0, 0, time.UTC)

func vec(t *testing.T, name, file string) []byte {
	t.Helper()
	b, err := os.ReadFile(filepath.Join("icao", "testdata", name, file))
	if err != nil {
		t.Fatal(err)
	}
	return b
}

func b64(b []byte) string { return base64.StdEncoding.EncodeToString(b) }

func trustOf(t *testing.T, names ...string) *icao.TrustStore {
	ts := icao.NewTrustStore()
	for _, n := range names {
		ts.AddPEM(vec(t, n, "csca.pem"))
	}
	return ts
}

// aaSign answers INTERNAL AUTHENTICATE as the rsa-pss vector's chip would
// (ISO 9796-2 scheme 1, SHA-1).
func aaSign(t *testing.T, challenge []byte) []byte {
	t.Helper()
	blk, _ := pem.Decode(vec(t, "rsa-pss", "aa.key"))
	k, err := x509.ParsePKCS8PrivateKey(blk.Bytes)
	if err != nil {
		t.Fatal(err)
	}
	key := k.(*rsa.PrivateKey)
	kLen := (key.N.BitLen() + 7) / 8
	m1 := make([]byte, kLen-2-sha1.Size)
	_, _ = rand.Read(m1)
	h := sha1.Sum(append(append([]byte(nil), m1...), challenge...)) //nolint:gosec
	j := append(append(append([]byte{0x6A}, m1...), h[:]...), 0xBC)
	return new(big.Int).Exp(new(big.Int).SetBytes(j), key.D, key.N).FillBytes(make([]byte, kLen))
}

func template(seed byte) []byte {
	b := bytes.Repeat([]byte{seed}, fes.TemplateBytes)
	return b
}

type ceremony struct {
	m       *ChipMethod
	session string
}

func newChip(t *testing.T, cfg Config) *ceremony {
	if cfg.Trust == nil {
		cfg.Trust = trustOf(t, "rsa-pss", "bp256", "p256", "expired")
	}
	cfg.Now = func() time.Time { return testNow }
	return &ceremony{m: NewChipMethod(cfg, nil), session: "sess-" + t.Name()}
}

// run begins and completes; mutate edits the payload before completion.
func (c *ceremony) run(t *testing.T, vector string, mutate func(p map[string]any, challenge []byte)) types.MethodResult {
	t.Helper()
	cc := types.CeremonyContext{SessionID: c.session}
	ch, err := c.m.BeginCeremony(context.Background(), cc)
	if err != nil {
		t.Fatal(err)
	}
	challenge, _ := hex.DecodeString(ch.Payload["aa_challenge_hex"].(string))
	p := map[string]any{
		"sod_b64":   b64(vec(t, vector, "EF.SOD")),
		"dg1_b64":   b64(vec(t, vector, "EF.DG1")),
		"face_bind": map[string]any{"match": true, "liveness": true, "engine": "test"},
	}
	if vector == "rsa-pss" {
		p["dg15_b64"] = b64(vec(t, vector, "EF.DG15"))
		p["aa_signature_b64"] = b64(aaSign(t, challenge))
	}
	if mutate != nil {
		mutate(p, challenge)
	}
	res, err := c.m.CompleteCeremony(context.Background(), cc, types.ResponseData{Payload: p})
	if err != nil {
		t.Fatal(err)
	}
	return res
}

func TestChipWithActiveAuth(t *testing.T) {
	c := newChip(t, Config{})
	res := c.run(t, "rsa-pss", nil)
	if !res.Success {
		t.Fatalf("%+v", res)
	}
	want := ChipIdentifier("UT", "L898902C3")
	if res.VerifiedIdentifier != want || !IsDocumentIdentifier(want) {
		t.Fatalf("identifier %q", res.VerifiedIdentifier)
	}
	if strings.Contains(want, "L898902C3") {
		t.Fatal("identifier carries the raw document number")
	}
	if c.m.Metadata().Strength != ChipStrength || c.m.Metadata().Type != types.MethodTypeAnchor {
		t.Fatalf("metadata %+v", c.m.Metadata())
	}
	// The challenge was consumed: completing again without begin fails.
	res, _ = c.m.CompleteCeremony(context.Background(), types.CeremonyContext{SessionID: c.session}, types.ResponseData{Payload: map[string]any{}})
	if res.ErrorReason != "no_challenge_issued" {
		t.Fatalf("second completion: %+v", res)
	}
}

func TestChipFailures(t *testing.T) {
	cases := []struct {
		name, vector, reason string
		cfg                  Config
		mutate               func(p map[string]any, ch []byte)
	}{
		{"tampered DG1", "rsa-pss", "dg_hash_mismatch", Config{}, func(p map[string]any, _ []byte) {
			dg1 := vec(t, "rsa-pss", "EF.DG1")
			dg1[20] ^= 1
			p["dg1_b64"] = b64(dg1)
		}},
		{"wrong CSCA", "rogue-csca", "csca_untrusted", Config{AllowPassiveOnly: true}, nil},
		{"no trust for state", "bp256", "csca_untrusted", Config{Trust: trustOf(t, "p256"), AllowPassiveOnly: true}, nil},
		{"expired document", "expired", "document_expired", Config{AllowPassiveOnly: true}, nil},
		{"no AA, AA required", "p256", "active_auth_unavailable", Config{}, nil},
		{"DG15 listed but omitted", "rsa-pss", "active_auth_missing", Config{}, func(p map[string]any, _ []byte) {
			delete(p, "dg15_b64")
			delete(p, "aa_signature_b64")
		}},
		{"AA over another challenge (replay)", "rsa-pss", "active_auth_failed", Config{}, func(p map[string]any, _ []byte) {
			p["aa_signature_b64"] = b64(aaSign(t, []byte("oldchal!")))
		}},
		{"face does not match", "rsa-pss", "face_bind_failed", Config{}, func(p map[string]any, _ []byte) {
			p["face_bind"] = map[string]any{"match": false, "liveness": true}
		}},
		{"no liveness", "rsa-pss", "face_bind_failed", Config{}, func(p map[string]any, _ []byte) {
			p["face_bind"] = map[string]any{"match": true, "liveness": false}
		}},
		{"no face bind", "rsa-pss", "face_bind_missing", Config{}, func(p map[string]any, _ []byte) {
			delete(p, "face_bind")
		}},
		{"garbage SOD", "rsa-pss", "sod_invalid", Config{}, func(p map[string]any, _ []byte) {
			p["sod_b64"] = b64([]byte{0x77, 0x02, 0x30, 0x00})
		}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			res := newChip(t, tc.cfg).run(t, tc.vector, tc.mutate)
			if res.Success || res.ErrorReason != tc.reason {
				t.Fatalf("got %+v, want %s", res, tc.reason)
			}
		})
	}
}

func TestChipPassiveOnlyAllowed(t *testing.T) {
	c := newChip(t, Config{AllowPassiveOnly: true})
	for _, v := range []string{"p256"} {
		if res := c.run(t, v, nil); !res.Success {
			t.Fatalf("%s: %+v", v, res)
		}
	}
	if c.m.Metadata().Strength != ChipPassiveOnlyStrength {
		t.Fatal("passive-only must lower the strength")
	}
}

func TestDualDocumentFlagged(t *testing.T) {
	q := &InMemoryReviewQueue{}
	known := map[string]bool{}
	var flagged []ReviewCase
	cfg := Config{
		AllowPassiveOnly: true,
		Faces:            fes.NewInMemoryAccumulator(),
		Reviews:          q,
		KnownIdentifier: func(_ context.Context, id string) (bool, error) {
			return known[id], nil
		},
	}
	c := newChip(t, cfg)
	c.m.logFlag = func(rc ReviewCase) { flagged = append(flagged, rc) }
	face := func(p map[string]any, _ []byte) { p["face_template_b64"] = b64(template(0xA5)) }

	first := c.run(t, "p256", face)
	if !first.Success {
		t.Fatalf("%+v", first)
	}
	known[first.VerifiedIdentifier] = true

	// Same document, same face: a re-enrollment, not flagged.
	if res := c.run(t, "p256", face); !res.Success {
		t.Fatalf("%+v", res)
	}
	if cases, _ := q.List(context.Background()); len(cases) != 0 {
		t.Fatalf("re-enrollment flagged: %+v", cases)
	}

	// Same face, a document this issuer has not seen (here: the same
	// specimen number, reported unknown, standing in for a second
	// passport). Not refused: issued and queued for review.
	delete(known, first.VerifiedIdentifier)
	res := c.run(t, "rsa-pss", face)
	if !res.Success {
		t.Fatalf("dual document refused: %+v", res)
	}
	cases, _ := q.List(context.Background())
	if len(cases) != 1 || len(flagged) != 1 || cases[0].DocumentCountry != "UT" || cases[0].MatchedFaceID == "" {
		t.Fatalf("review cases %+v", cases)
	}

	// A different face is not flagged.
	if res := c.run(t, "rsa-pss", func(p map[string]any, _ []byte) { p["face_template_b64"] = b64(template(0x0F)) }); !res.Success {
		t.Fatal(res)
	}
	if cases, _ := q.List(context.Background()); len(cases) != 1 {
		t.Fatalf("different face flagged: %+v", cases)
	}
}

func TestDefaultTrustLoads(t *testing.T) {
	ts, infos, err := DefaultTrust()
	if err != nil {
		t.Fatal(err)
	}
	if len(infos) == 0 || ts.Len() < 400 {
		t.Fatalf("%d certs", ts.Len())
	}
}

func qrRegistry(t *testing.T) *signedqr.Registry {
	t.Helper()
	spec, err := os.ReadFile("signedqr/formats/in-aadhaar-secure-qr.json")
	if err != nil {
		t.Fatal(err)
	}
	spec = bytes.ReplaceAll(spec, []byte(`["uidai-2021-02-26.pem", "uidai-2024-02-21.pem"]`), []byte(`["test.pem"]`))
	cert, _ := os.ReadFile("signedqr/testdata/anon-aadhaar-test-cert.pem")
	r := &signedqr.Registry{}
	if err := r.LoadFS(fstest.MapFS{"a.json": {Data: spec}, "test.pem": {Data: cert}}); err != nil {
		t.Fatal(err)
	}
	return r
}

func TestSignedQR(t *testing.T) {
	qr, _ := os.ReadFile("signedqr/testdata/anon-aadhaar-test-qr.txt")
	m := NewQRMethod(Config{QRFormats: qrRegistry(t)}, nil)
	cc := types.CeremonyContext{SessionID: "s"}
	if _, err := m.BeginCeremony(context.Background(), cc); err != nil {
		t.Fatal(err)
	}
	ok := map[string]any{"qr_text": string(qr), "face_bind": map[string]any{"match": true, "liveness": true}}
	res, err := m.CompleteCeremony(context.Background(), cc, types.ResponseData{Payload: ok})
	if err != nil || !res.Success || !IsDocumentIdentifier(res.VerifiedIdentifier) || !strings.HasPrefix(res.VerifiedIdentifier, "qr:IN-aadhaar:") {
		t.Fatalf("%+v %v", res, err)
	}

	builtin, err := signedqr.Builtin()
	if err != nil {
		t.Fatal(err)
	}
	prod := NewQRMethod(Config{QRFormats: builtin}, nil)
	res, _ = prod.CompleteCeremony(context.Background(), cc, types.ResponseData{Payload: ok})
	if res.ErrorReason != "qr_signature_invalid" {
		t.Fatalf("test QR against UIDAI keys: %+v", res)
	}
	res, _ = m.CompleteCeremony(context.Background(), cc, types.ResponseData{Payload: map[string]any{
		"qr_text": "hello", "face_bind": map[string]any{"match": true, "liveness": true},
	}})
	if res.ErrorReason != "qr_format_unknown" {
		t.Fatalf("%+v", res)
	}
	res, _ = m.CompleteCeremony(context.Background(), cc, types.ResponseData{Payload: map[string]any{"qr_text": string(qr)}})
	if res.ErrorReason != "face_bind_missing" {
		t.Fatalf("%+v", res)
	}
}
