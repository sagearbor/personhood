package signedqr

import (
	"bytes"
	"compress/zlib"
	"errors"
	"io"
	"math/big"
	"os"
	"strings"
	"testing"
	"testing/fstest"
)

// The test QR is anon-aadhaar's (MIT) packages/circuits/assets/test.json:
// a real-format Aadhaar Secure QR V2 payload with fictitious data, signed
// with anon-aadhaar's test key (testdata/anon-aadhaar-test-cert.pem), not
// UIDAI's: a QR signed by UIDAI would carry a real person's data.

func testQR(t *testing.T) string {
	t.Helper()
	b, err := os.ReadFile("testdata/anon-aadhaar-test-qr.txt")
	if err != nil {
		t.Fatal(err)
	}
	return strings.TrimSpace(string(b))
}

// testRegistry is the built-in Aadhaar format with the test key instead of
// UIDAI's: the format description is shared, only the trust differs.
func testRegistry(t *testing.T) *Registry {
	t.Helper()
	spec, err := builtin.ReadFile("formats/in-aadhaar-secure-qr.json")
	if err != nil {
		t.Fatal(err)
	}
	spec = bytes.ReplaceAll(spec, []byte(`["uidai-2021-02-26.pem", "uidai-2024-02-21.pem"]`), []byte(`["test.pem"]`))
	cert, err := os.ReadFile("testdata/anon-aadhaar-test-cert.pem")
	if err != nil {
		t.Fatal(err)
	}
	r := &Registry{}
	if err := r.LoadFS(fstest.MapFS{
		"aadhaar.json": {Data: spec},
		"test.pem":     {Data: cert},
	}); err != nil {
		t.Fatal(err)
	}
	return r
}

func TestAadhaarV2Verifies(t *testing.T) {
	r := testRegistry(t)
	res, err := r.Verify(testQR(t), "")
	if err != nil {
		t.Fatal(err)
	}
	if res.FormatID != "in-aadhaar-secure-qr-v2" || res.Country != "IN" {
		t.Fatalf("%+v", res)
	}
	if !strings.HasPrefix(res.UniqueKey, "IN-aadhaar:") || len(res.UniqueKey) != len("IN-aadhaar:")+64 {
		t.Fatalf("unique key %q", res.UniqueKey)
	}
	if strings.Contains(res.UniqueKey, "Sumit") || strings.Contains(res.UniqueKey, "1984") {
		t.Fatal("unique key leaks personal data")
	}
	if res.SignedAt.Year() != 2024 || res.SignedAt.Month() != 4 {
		t.Fatalf("signed at %v", res.SignedAt)
	}
	again, _ := r.Verify(testQR(t), "in-aadhaar-secure-qr-v2")
	if again == nil || again.UniqueKey != res.UniqueKey {
		t.Fatal("unique key not stable")
	}
}

func TestAadhaarWrongKey(t *testing.T) {
	// The shipped registry trusts only UIDAI's keys.
	r, err := Builtin()
	if err != nil {
		t.Fatal(err)
	}
	if got := r.IDs(); len(got) != 2 {
		t.Fatalf("builtin formats %v", got)
	}
	if _, err := r.Verify(testQR(t), ""); !errors.Is(err, ErrSignatureInvalid) {
		t.Fatalf("test-key QR against UIDAI keys: %v", err)
	}
}

func TestAadhaarTampered(t *testing.T) {
	n, _ := new(big.Int).SetString(testQR(t), 10)
	zr, err := zlib.NewReader(bytes.NewReader(n.Bytes()))
	if err != nil {
		t.Fatal(err)
	}
	data, _ := io.ReadAll(zr)
	// Change the birth date 01-01-1984 -> 01-01-1985, keep the signature.
	i := bytes.Index(data, []byte("01-01-1984"))
	if i < 0 {
		t.Fatal("dob not found")
	}
	data[i+9] = '5'
	var buf bytes.Buffer
	zw := zlib.NewWriter(&buf)
	_, _ = zw.Write(data)
	_ = zw.Close()
	tampered := new(big.Int).SetBytes(buf.Bytes()).String()
	if _, err := testRegistry(t).Verify(tampered, ""); !errors.Is(err, ErrSignatureInvalid) {
		t.Fatalf("tampered QR: %v", err)
	}
}

func TestNotAKnownQR(t *testing.T) {
	r := testRegistry(t)
	for _, qr := range []string{"https://example.org", "12345", ""} {
		if _, err := r.Verify(qr, ""); err == nil {
			t.Fatalf("%q accepted", qr)
		}
	}
}
