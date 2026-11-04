package icao

import (
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"encoding/pem"
	"errors"
	"math/big"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// GermanCSCASHA256 is the SHA-256 fingerprint BSI publishes for the
// csca-germany certificate that signs the German master list's signer
// (bsi.bund.de, "The German Country Signing Certificate Authority",
// certificate 10/24). Duplicated from the method package to keep this
// package's tests self-contained.
const germanCSCASHA256 = "2084aed7a991b3158e63ad750d3dc38bc6c9dcf5958f28d1162f49884e91ada8"

func readFile(t *testing.T, parts ...string) []byte {
	t.Helper()
	b, err := os.ReadFile(filepath.Join(parts...))
	if err != nil {
		t.Fatal(err)
	}
	return b
}

func trustWith(t *testing.T, dirs ...string) *TrustStore {
	t.Helper()
	ts := NewTrustStore()
	for _, d := range dirs {
		if added, skipped := ts.AddPEM(readFile(t, "testdata", d, "csca.pem")); added != 1 || skipped != 0 {
			t.Fatalf("%s: added %d skipped %d", d, added, skipped)
		}
	}
	return ts
}

func passive(t *testing.T, vec string, ts *TrustStore) (*SOD, *PassiveResult, error) {
	t.Helper()
	sod, err := ParseSOD(readFile(t, "testdata", vec, "EF.SOD"))
	if err != nil {
		t.Fatalf("%s: ParseSOD: %v", vec, err)
	}
	res, err := sod.VerifySignature(ts)
	return sod, res, err
}

func TestPassiveAuthentication(t *testing.T) {
	ts := trustWith(t, "rsa-pss", "bp256", "p256")
	for _, vec := range []string{"rsa-pss", "bp256", "p256"} {
		t.Run(vec, func(t *testing.T) {
			sod, res, err := passive(t, vec, ts)
			if err != nil {
				t.Fatalf("VerifySignature: %v", err)
			}
			if res.Country != "UT" {
				t.Fatalf("country %q", res.Country)
			}
			for _, n := range []int{1, 2} {
				if err := sod.CheckDataGroup(n, readFile(t, "testdata", vec, "EF.DG"+string(rune('0'+n)))); err != nil {
					t.Fatalf("DG%d: %v", n, err)
				}
			}
			mrz, err := ParseDG1(readFile(t, "testdata", vec, "EF.DG1"))
			if err != nil {
				t.Fatal(err)
			}
			if mrz.DocumentNumber != "L898902C3" || mrz.IssuingState != "UTO" || mrz.DateOfBirth != "740812" {
				t.Fatalf("mrz %+v", mrz)
			}
			if exp, _ := mrz.Expired(time.Date(2026, 11, 4, 0, 0, 0, 0, time.UTC)); exp {
				t.Fatal("valid vector reported expired")
			}
		})
	}
}

func TestTamperedDataGroup(t *testing.T) {
	ts := trustWith(t, "p256")
	sod, _, err := passive(t, "p256", ts)
	if err != nil {
		t.Fatal(err)
	}
	dg1 := readFile(t, "testdata", "p256", "EF.DG1")
	dg1[len(dg1)-5] ^= 0x01
	if err := sod.CheckDataGroup(1, dg1); !errors.Is(err, ErrHashMismatch) {
		t.Fatalf("tampered DG1: %v", err)
	}
	if err := sod.CheckDataGroup(15, []byte{0x6f, 0}); !errors.Is(err, ErrHashMismatch) {
		t.Fatalf("unlisted DG15: %v", err)
	}
}

func TestTamperedSOD(t *testing.T) {
	ts := trustWith(t, "bp256")
	raw := readFile(t, "testdata", "bp256", "EF.SOD")
	// Flip a byte inside the LDSSecurityObject's DG1 hash: the
	// messageDigest attribute no longer matches.
	lds := strings.Index(string(raw), "\x02\x01\x01\x04\x20") // DataGroupHash{1, OCTET STRING(32)}
	if lds < 0 {
		t.Fatal("DG1 hash not found in SOD")
	}
	raw[lds+6] ^= 0xff
	sod, err := ParseSOD(raw)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := sod.VerifySignature(ts); !errors.Is(err, ErrSOD) {
		t.Fatalf("tampered SOD: %v", err)
	}
}

func TestWrongCSCA(t *testing.T) {
	// The rogue vector's CSCA has the same name as p256's but a different
	// key; only p256's CSCA is trusted.
	ts := trustWith(t, "p256", "rsa-pss")
	if _, _, err := passive(t, "rogue-csca", ts); !errors.Is(err, ErrUntrusted) {
		t.Fatalf("rogue CSCA: %v", err)
	}
	if _, _, err := passive(t, "bp256", NewTrustStore()); !errors.Is(err, ErrUntrusted) {
		t.Fatalf("empty trust: %v", err)
	}
}

func TestExpiredSpecimen(t *testing.T) {
	ts := trustWith(t, "expired")
	sod, _, err := passive(t, "expired", ts)
	if err != nil {
		t.Fatal(err)
	}
	dg1 := readFile(t, "testdata", "expired", "EF.DG1")
	if err := sod.CheckDataGroup(1, dg1); err != nil {
		t.Fatal(err)
	}
	mrz, err := ParseDG1(dg1)
	if err != nil {
		t.Fatal(err)
	}
	exp, err := mrz.Expired(time.Date(2026, 11, 4, 0, 0, 0, 0, time.UTC))
	if err != nil || !exp {
		t.Fatalf("specimen expiry 2012-04-15 not expired: %v %v", exp, err)
	}
	if exp, _ := mrz.Expired(time.Date(2012, 4, 15, 23, 0, 0, 0, time.UTC)); exp {
		t.Fatal("document must be valid through its expiry day")
	}
}

// ICAO 9303 Part 4 / Part 5 specimens.
func TestMRZSpecimens(t *testing.T) {
	td3 := "P<UTOERIKSSON<<ANNA<MARIA<<<<<<<<<<<<<<<<<<<" +
		"L898902C36UTO7408122F1204159ZE184226B<<<<<10"
	m, err := ParseMRZ(td3)
	if err != nil || m.DocumentNumber != "L898902C3" || m.DateOfExpiry != "120415" {
		t.Fatalf("TD3: %+v %v", m, err)
	}
	td1 := "I<UTOD231458907<<<<<<<<<<<<<<<" +
		"7408122F1204159UTO<<<<<<<<<<<6" +
		"ERIKSSON<<ANNA<MARIA<<<<<<<<<<"
	m, err = ParseMRZ(td1)
	if err != nil || m.DocumentNumber != "D23145890" || m.DocumentCode != "I" {
		t.Fatalf("TD1: %+v %v", m, err)
	}
	bad := strings.Replace(td3, "L898902C36", "L898902C37", 1)
	if _, err := ParseMRZ(bad); !errors.Is(err, ErrMRZ) {
		t.Fatalf("bad check digit: %v", err)
	}
	if d, _ := CheckDigit("L898902C3"); d != '6' {
		t.Fatalf("check digit %c", d)
	}
}

// --- Active Authentication ---

func loadPKCS8(t *testing.T, path string) []byte {
	t.Helper()
	b, _ := pem.Decode(readFile(t, path))
	if b == nil {
		t.Fatal("no PEM")
	}
	return b.Bytes
}

// signAARSA makes an ISO 9796-2 scheme 1 signature as a chip would.
func signAARSA(t *testing.T, k *rsa.PrivateKey, challenge []byte) []byte {
	kLen := (k.N.BitLen() + 7) / 8
	h := crypto.SHA1
	m1Len := kLen - 2 - h.Size()
	m1 := make([]byte, m1Len)
	_, _ = rand.Read(m1)
	j := append([]byte{0x6A}, m1...)
	j = append(j, digest(h, append(append([]byte(nil), m1...), challenge...))...)
	j = append(j, 0xBC)
	s := new(big.Int).Exp(new(big.Int).SetBytes(j), k.D, k.N)
	return s.FillBytes(make([]byte, kLen))
}

func TestActiveAuthRSA(t *testing.T) {
	key, err := x509.ParsePKCS8PrivateKey(loadPKCS8(t, "testdata/rsa-pss/aa.key"))
	if err != nil {
		t.Fatal(err)
	}
	dg15 := readFile(t, "testdata", "rsa-pss", "EF.DG15")
	challenge := []byte{1, 2, 3, 4, 5, 6, 7, 8}
	sig := signAARSA(t, key.(*rsa.PrivateKey), challenge)
	if err := VerifyActiveAuth(dg15, nil, challenge, sig); err != nil {
		t.Fatalf("valid AA: %v", err)
	}
	if err := VerifyActiveAuth(dg15, nil, []byte{9, 9, 9, 9, 9, 9, 9, 9}, sig); !errors.Is(err, ErrAA) {
		t.Fatalf("replayed AA with another challenge: %v", err)
	}
	sig[10] ^= 1
	if err := VerifyActiveAuth(dg15, nil, challenge, sig); !errors.Is(err, ErrAA) {
		t.Fatalf("tampered AA: %v", err)
	}
}

type pkcs8 struct {
	Version int
	Algo    pkix.AlgorithmIdentifier
	Key     []byte
}

type ecPrivateKey struct {
	Version int
	D       []byte
	Params  asn1.RawValue  `asn1:"optional,explicit,tag:0"`
	Public  asn1.BitString `asn1:"optional,explicit,tag:1"`
}

// signECDSA is a test-only signer on an arbitrary curve.
func signECDSA(c *Curve, d *big.Int, digestBytes []byte) []byte {
	e := hashToInt(digestBytes, c.N)
	for {
		k, _ := rand.Int(rand.Reader, c.N)
		if k.Sign() == 0 {
			continue
		}
		p := c.mul(point{x: c.Gx, y: c.Gy}, k)
		r := new(big.Int).Mod(p.x, c.N)
		if r.Sign() == 0 {
			continue
		}
		s := new(big.Int).Mul(r, d)
		s.Add(s, e)
		s.Mul(s, new(big.Int).ModInverse(k, c.N))
		s.Mod(s, c.N)
		if s.Sign() == 0 {
			continue
		}
		n := c.byteLen()
		return append(r.FillBytes(make([]byte, n)), s.FillBytes(make([]byte, n))...)
	}
}

func TestActiveAuthECBrainpoolExplicit(t *testing.T) {
	var p8 pkcs8
	if _, err := asn1.Unmarshal(loadPKCS8(t, "testdata/bp256/aa.key"), &p8); err != nil {
		t.Fatal(err)
	}
	curve, err := parseECParams(p8.Algo.Parameters.FullBytes)
	if err != nil || curve == nil {
		t.Fatalf("curve: %v", err)
	}
	var ek ecPrivateKey
	if _, err := asn1.Unmarshal(p8.Key, &ek); err != nil {
		t.Fatal(err)
	}
	d := new(big.Int).SetBytes(ek.D)
	dg15 := readFile(t, "testdata", "bp256", "EF.DG15")
	challenge := []byte("8bytes!!")
	sig := signECDSA(curve, d, digest(crypto.SHA256, challenge))
	if err := VerifyActiveAuth(dg15, nil, challenge, sig); err != nil {
		t.Fatalf("valid EC AA: %v", err)
	}
	if err := VerifyActiveAuth(dg15, nil, []byte("other!!!"), sig); !errors.Is(err, ErrAA) {
		t.Fatalf("EC AA other challenge: %v", err)
	}
}

// --- Real data ---

func TestGermanMasterList(t *testing.T) {
	matches, _ := filepath.Glob("../trust/DE_ML_*.ml")
	if len(matches) == 0 {
		t.Skip("no master list in ../trust")
	}
	der := readFile(t, matches[len(matches)-1])
	ts := NewTrustStore()
	info, err := ts.AddMasterList(der, []string{germanCSCASHA256})
	if err != nil {
		t.Fatal(err)
	}
	if info.Signer != "DE" || info.Certificates < 400 {
		t.Fatalf("info %+v", info)
	}
	t.Logf("master list: %d certificates (%d unparsed), %d countries", info.Certificates, info.Skipped, len(ts.Countries()))
	have := map[string]bool{}
	for _, c := range ts.Countries() {
		have[c] = true
	}
	for _, c := range []string{"US", "DE", "IN", "FR", "GB"} {
		if !have[c] {
			t.Errorf("master list has no %s CSCA", c)
		}
	}
	// Every CSCA and link certificate must verify against some issuer in
	// the list (itself, or the previous key for a link certificate). This
	// exercises RSA, RSA-PSS and explicit-parameter EC on real
	// certificates. A handful of entries in national lists are known to
	// be link certificates from keys that are not in the list (checked with
	// openssl for GB); allow a few percent.
	var failed int
	for _, c := range ts.certs {
		if _, err := ts.Chain(c); err != nil {
			failed++
			t.Logf("unchained: %s serial %s: %v", c.Country, c.SerialNumber, err)
		}
	}
	if failed > len(ts.certs)/30 {
		t.Errorf("%d of %d master list certificates do not chain", failed, len(ts.certs))
	}

	// A wrong pin must refuse the whole list.
	if _, err := NewTrustStore().AddMasterList(der, []string{strings.Repeat("00", 32)}); err == nil {
		t.Fatal("master list accepted without a pinned anchor")
	}
	// A tampered list must be refused.
	bad := append([]byte(nil), der...)
	bad[len(bad)/2] ^= 0xff
	if _, err := NewTrustStore().AddMasterList(bad, []string{germanCSCASHA256}); err == nil {
		t.Fatal("tampered master list accepted")
	}
}
