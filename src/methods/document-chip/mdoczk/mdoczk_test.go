package mdoczk

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"math/big"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"testing"
	"time"

	"github.com/sagearbor/personhood/src/methods/document-chip/zkproof"
)

func findBB(t *testing.T) string {
	t.Helper()
	if p := os.Getenv("BB"); p != "" {
		return p
	}
	if p, err := exec.LookPath("bb"); err == nil {
		return p
	}
	arch := map[string]string{"arm64": "arm64", "amd64": "amd64"}[runtime.GOARCH]
	osn := map[string]string{"darwin": "macos", "linux": "linux"}[runtime.GOOS]
	p, _ := filepath.Abs(filepath.Join("..", "..", "..", "..", "tools", "zk-circuits", "node_modules", "@aztec", "bb.js", "build", arch+"-"+osn, "bb"))
	if _, err := os.Stat(p); err == nil {
		return p
	}
	t.Skip("bb not found: set BB or npm ci in tools/zk-circuits")
	return ""
}

func TestCBORRoundTrip(t *testing.T) {
	v := Map{{"a", int64(1)}, {int64(-2), []byte{1, 2}}, {"t", Tag{24, Encode([]any{"x", Null, true})}}, {"big", int64(70000)}}
	got, err := Decode(Encode(v))
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(Encode(got), Encode(v)) {
		t.Fatalf("round trip differs: %x vs %x", Encode(got), Encode(v))
	}
	for _, bad := range [][]byte{{0x5f}, {0x82, 0x01}, {0x59, 0xff}, {0x01, 0x02}, {0xf9, 0, 0}} {
		if _, err := Decode(bad); err == nil {
			t.Fatalf("accepted %x", bad)
		}
	}
}

func TestEncryptionInfo(t *testing.T) {
	n := Nonce([32]byte{7}, "did:key:x")
	k := Map{{int64(1), int64(2)}}
	good := base64.RawURLEncoding.EncodeToString(EncryptionInfo(n, k))
	if err := CheckEncryptionInfo(good, n); err != nil {
		t.Fatal(err)
	}
	for name, b64 := range map[string]string{
		"other nonce":  base64.RawURLEncoding.EncodeToString(EncryptionInfo(Nonce([32]byte{8}, "did:key:x"), k)),
		"other holder": base64.RawURLEncoding.EncodeToString(EncryptionInfo(Nonce([32]byte{7}, "did:key:y"), k)),
		"no key":       base64.RawURLEncoding.EncodeToString(Encode([]any{"dcapi", Map{{"nonce", n[:]}}})),
		"not dcapi":    base64.RawURLEncoding.EncodeToString(Encode([]any{"x", Map{{"nonce", n[:]}, {"recipientPublicKey", k}}})),
		"not base64":   "!!",
		"empty":        "",
	} {
		if err := CheckEncryptionInfo(b64, n); err == nil {
			t.Errorf("%s accepted", name)
		}
	}
}

func TestOrigin(t *testing.T) {
	if CheckOrigin("android:apk-key-hash:abc", nil) != nil || CheckOrigin("", nil) == nil || CheckOrigin("a\nb", nil) == nil {
		t.Fatal("origin checks")
	}
	if CheckOrigin("android:apk-key-hash:abc", []string{"android:apk-key-hash:def"}) == nil {
		t.Fatal("unlisted origin accepted")
	}
}

// The scope is pinned: changing it re-keys every licence.
func TestServiceScopePinned(t *testing.T) {
	s := ServiceScope()
	vec := loadVector(t, "specimen")
	if "0x"+hex.EncodeToString(s[:]) != vec.Scope {
		t.Fatalf("scope %x, fixture %s", s, vec.Scope)
	}
}

func p384Cert(t *testing.T) *x509.Certificate {
	k, _ := ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
	tmpl := &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{Country: []string{"US"}, Province: []string{"ZZ"}},
		NotBefore: time.Now(), NotAfter: time.Now().Add(time.Hour), IsCA: true, BasicConstraintsValid: true}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &k.PublicKey, k)
	if err != nil {
		t.Fatal(err)
	}
	c, _ := x509.ParseCertificate(der)
	return c
}

func TestRegistry(t *testing.T) {
	a, _ := NewTestIssuer("US", "CA", time.Now())
	b, _ := NewTestIssuer("US", "AZ", time.Now())
	ca, _ := x509.ParseCertificate(a.IACACert)
	az, _ := x509.ParseCertificate(b.IACACert)
	if Jurisdiction(ca, nil) != "US-CA" || Jurisdiction(az, nil) != "US-AZ" {
		t.Fatal(Jurisdiction(ca, nil), Jurisdiction(az, nil))
	}
	sum := sha256.Sum256(ca.Raw)
	if Jurisdiction(ca, map[string]string{hex.EncodeToString(sum[:]): "US-XX"}) != "US-XX" {
		t.Fatal("override ignored")
	}
	reg, err := BuildRegistry([]*x509.Certificate{ca, az, p384Cert(t), ca}, nil)
	if err != nil {
		t.Fatal(err)
	}
	if len(reg.Entries) != 2 || reg.Skipped != 1 || reg.Entries[0].Jurisdiction != "US-AZ" {
		t.Fatalf("%+v", reg)
	}
	// Order does not change the root.
	reg2, _ := BuildRegistry([]*x509.Certificate{az, ca}, nil)
	if reg2.Root != reg.Root {
		t.Fatal("root depends on input order")
	}
	// Each path leads to the root.
	for i, e := range reg.Entries {
		leaf, _ := new(big.Int).SetString(e.Leaf[2:], 16)
		var path []*big.Int
		for _, p := range reg.Path(i) {
			x, _ := new(big.Int).SetString(p[2:], 16)
			path = append(path, x)
		}
		if zkproof.FieldHex(zkproof.MerkleRootFromPath(leaf, uint64(i), path)) != reg.Root {
			t.Fatalf("path %d", i)
		}
	}
}

type vector struct {
	Scope    string   `json:"scope"`
	Expected string   `json:"expected_nullifier"`
	Circuit  string   `json:"circuit"`
	Now      string   `json:"now"`
	Registry Registry `json:"registry"`
	Trans    string   `json:"transcript_hash"`
	proof    []byte
	pubs     []byte
}

func loadVector(t *testing.T, dir string) *vector {
	t.Helper()
	raw, err := os.ReadFile(filepath.Join("testdata", dir, "vector.json"))
	if err != nil {
		t.Fatal(err)
	}
	var v vector
	if err := json.Unmarshal(raw, &v); err != nil {
		t.Fatal(err)
	}
	v.proof, _ = os.ReadFile(filepath.Join("testdata", dir, "proof"))
	v.pubs, _ = os.ReadFile(filepath.Join("testdata", dir, "public_inputs"))
	return &v
}

func verifierFor(t *testing.T, v *vector) (*Verifier, [32]byte) {
	vk, err := VK(v.Circuit)
	if err != nil {
		t.Fatal(err)
	}
	root, _ := new(big.Int).SetString(v.Registry.Root[2:], 16)
	now, _ := time.Parse("2006-01-02T15:04:05Z", v.Now)
	var th [32]byte
	b, _ := hex.DecodeString(v.Trans)
	copy(th[:], b)
	return &Verifier{
		BB: findBB(t), VKs: map[string][]byte{v.Circuit: vk},
		Roots: map[[zkproof.FieldSize]byte]bool{zkproof.FieldBytes(root): true},
		Scope: ServiceScope(), Now: func() time.Time { return now },
	}, th
}

func TestVerifyFixture(t *testing.T) {
	v := loadVector(t, "specimen")
	ver, th := verifierFor(t, v)
	res, err := ver.Verify(context.Background(), Proof{Circuit: v.Circuit, Proof: v.proof, PublicInputs: v.pubs}, th)
	if err != nil {
		t.Fatal(err)
	}
	want, _ := new(big.Int).SetString(v.Expected[2:], 16)
	if res.Nullifier != zkproof.FieldBytes(want) || res.DocType != DocTypeMDL {
		t.Fatalf("%+v", res)
	}
	// The nullifier is Poseidon2(scope, "UT", "UT1234567", 9), recomputed here.
	if zkproof.FieldHex(ExpectedNullifier(ServiceScope(), "UT", "UT1234567")) != zkproof.FieldHex(want) {
		t.Fatal("nullifier formula differs from the circuit")
	}
}

func TestVerifyRefusesCompanySignedBeforeProving(t *testing.T) {
	v := loadVector(t, "specimen")
	ver, th := verifierFor(t, v)
	pubs := append([]byte(nil), v.pubs...)
	dt := PackText("org.iso.23220.photoid.1")
	copy(pubs[2*32:3*32], dt[:])
	_, err := ver.Verify(context.Background(), Proof{Circuit: v.Circuit, Proof: v.proof, PublicInputs: pubs}, th)
	if !errors.Is(err, ErrCompanySigned) {
		t.Fatalf("got %v", err)
	}
}

// A test wallet's DeviceResponse carries what the circuit needs, and the
// device signature verifies over DeviceSigStructure.
func TestTestIssuerPresentation(t *testing.T) {
	now := time.Now()
	iss, err := NewTestIssuer("UT", "", now)
	if err != nil {
		t.Fatal(err)
	}
	dk, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	m, err := iss.Issue(TestCredential{DocType: DocTypeMDL, Elements: SpecimenElements("UT1", []byte{1}), DeviceKey: dk,
		Signed: now, ValidFrom: now, ValidUntil: now.Add(time.Hour)})
	if err != nil {
		t.Fatal(err)
	}
	tr := SessionTranscript("abc", "android:apk-key-hash:x")
	resp, err := m.Present(tr, map[string][]string{NameSpaceMDL: {"document_number"}})
	if err != nil {
		t.Fatal(err)
	}
	root, err := Decode(resp)
	if err != nil {
		t.Fatal(err)
	}
	docs, _ := root.(Map).Get("documents")
	doc := docs.([]any)[0].(Map)
	ds, _ := doc.Get("deviceSigned")
	da, _ := ds.(Map).Get("deviceAuth")
	sigArr, _ := da.(Map).Get("deviceSignature")
	sig := sigArr.([]any)[3].([]byte)
	h := sha256.Sum256(DeviceSigStructure(tr, DocTypeMDL))
	if !ecdsa.Verify(&dk.PublicKey, h[:], new(big.Int).SetBytes(sig[:32]), new(big.Int).SetBytes(sig[32:])) {
		t.Fatal("device signature does not verify")
	}
}
