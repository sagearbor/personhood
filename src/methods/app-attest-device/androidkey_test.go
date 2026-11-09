package appattestdevice

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"math/big"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/sagearbor/personhood/pkg/types"
)

// ---------------------------------------------------------------------------
// Real chains. testdata/android/*.pem are attestation chains captured from
// real phones, published by Google in github.com/android/keyattestation
// (Apache-2.0; see testdata/android/NOTICE). The .json next to each is
// Google's own decoding of the leaf, which these tests read the expected
// challenge, package and signer from.
// ---------------------------------------------------------------------------

type sample struct {
	chain     []*x509.Certificate
	challenge []byte
	pkg       string
	signer    []byte
}

func loadSample(t *testing.T, name string) sample {
	t.Helper()
	pemBytes, err := os.ReadFile("testdata/android/" + name + ".pem")
	if err != nil {
		t.Fatal(err)
	}
	chain, err := ParsePEMCertificates(pemBytes)
	if err != nil {
		t.Fatalf("%s: %v", name, err)
	}
	s := sample{chain: chain}
	js, err := os.ReadFile("testdata/android/" + name + ".json")
	if err != nil {
		return s // no decoding published for this one
	}
	var d struct {
		AttestationChallenge string `json:"attestationChallenge"`
		SoftwareEnforced     struct {
			AttestationApplicationID struct {
				Packages []struct {
					Name string `json:"name"`
				} `json:"packages"`
				Signatures []string `json:"signatures"`
			} `json:"attestationApplicationId"`
		} `json:"softwareEnforced"`
	}
	if err := json.Unmarshal(js, &d); err != nil {
		t.Fatalf("%s.json: %v", name, err)
	}
	s.challenge, _ = base64.StdEncoding.DecodeString(d.AttestationChallenge)
	s.pkg = d.SoftwareEnforced.AttestationApplicationID.Packages[0].Name
	s.signer, _ = base64.StdEncoding.DecodeString(d.SoftwareEnforced.AttestationApplicationID.Signatures[0])
	return s
}

func at(s string) func() time.Time {
	tm, err := time.Parse(time.RFC3339, s)
	if err != nil {
		panic(err)
	}
	return func() time.Time { return tm }
}

func reasonOf(err error) string {
	var ve *VerifyError
	if errors.As(err, &ve) {
		return ve.Reason
	}
	if err == nil {
		return ""
	}
	return "untyped: " + err.Error()
}

// Each RKP chain is only valid for the ~10 days its attestation key lives,
// so every test pins the clock inside that window.
var realGood = []struct {
	name, now, level string
}{
	{"caiman_sdk36_SB_EC_RKP", "2025-09-30T00:00:00Z", "strongbox"},     // Pixel 9 Pro, StrongBox, RSA root
	{"caiman_sdk36_TEE_EC_RKP", "2025-09-30T00:00:00Z", "tee"},          // Pixel 9 Pro, TEE, RSA root
	{"tegu_sdk36_SB_EC_2026_ROOT", "2026-02-25T00:00:00Z", "strongbox"}, // Pixel 9a, new ECDSA root
}

func TestRealChains_Pass(t *testing.T) {
	for _, tc := range realGood {
		t.Run(tc.name, func(t *testing.T) {
			s := loadSample(t, tc.name)
			v := NewAndroidKeyVerifier(AndroidKeyConfig{
				PackageName:   s.pkg,
				SignerDigests: [][]byte{s.signer},
				Now:           at(tc.now),
			})
			ev, err := v.VerifyChain(context.Background(), s.chain, s.challenge)
			if err != nil {
				t.Fatalf("expected pass, got %v", err)
			}
			if ev.SecurityLevel != tc.level {
				t.Errorf("security level %q, want %q", ev.SecurityLevel, tc.level)
			}
			if len(ev.DeviceHint) != 64 {
				t.Errorf("RKP chain should give a device hint, got %q", ev.DeviceHint)
			}
		})
	}
}

func TestRealChain_TokenRoundTrip(t *testing.T) {
	s := loadSample(t, "caiman_sdk36_SB_EC_RKP")
	parts := make([]string, len(s.chain))
	for i, c := range s.chain {
		parts[i] = base64.StdEncoding.EncodeToString(c.Raw)
	}
	v := NewAndroidKeyVerifier(AndroidKeyConfig{PackageName: s.pkg, Now: at("2025-09-30T00:00:00Z")})
	_, err := v.Verify(context.Background(), AttestationInput{
		Platform: PlatformAndroid,
		Nonce:    hex.EncodeToString(s.challenge),
		Token:    strings.Join(parts, ","),
	})
	if err != nil {
		t.Fatalf("token form: %v", err)
	}
}

func TestRealChains_Rejected(t *testing.T) {
	caiman := loadSample(t, "caiman_sdk36_SB_EC_RKP")
	tegu := loadSample(t, "tegu_sdk36_SB_EC_2026_ROOT")
	roots := GoogleRootCertificates()
	var rsaRoot, ecRoot []*x509.Certificate
	for _, r := range roots {
		if r.PublicKeyAlgorithm == x509.RSA {
			rsaRoot = append(rsaRoot, r)
		} else {
			ecRoot = append(ecRoot, r)
		}
	}
	if len(rsaRoot) != 1 || len(ecRoot) != 1 {
		t.Fatalf("expected one RSA and one ECDSA pinned root, got %d/%d", len(rsaRoot), len(ecRoot))
	}
	otherSigner := sha256.Sum256([]byte("someone else's signing cert"))

	cases := []struct {
		name   string
		s      sample
		cfg    AndroidKeyConfig
		chal   []byte
		reason string
	}{
		{"wrong challenge", caiman, AndroidKeyConfig{PackageName: caiman.pkg, Now: at("2025-09-30T00:00:00Z")},
			[]byte("a different session's nonce"), "attestation_challenge_mismatch"},
		{"wrong package", caiman, AndroidKeyConfig{PackageName: "org.openline.wallet", Now: at("2025-09-30T00:00:00Z")},
			caiman.challenge, "attestation_wrong_app"},
		{"wrong signer", caiman, AndroidKeyConfig{PackageName: caiman.pkg, SignerDigests: [][]byte{otherSigner[:]}, Now: at("2025-09-30T00:00:00Z")},
			caiman.challenge, "attestation_wrong_app"},
		{"expired attestation key", caiman, AndroidKeyConfig{PackageName: caiman.pkg, Now: at("2026-11-03T00:00:00Z")},
			caiman.challenge, "attestation_chain_invalid"},
		{"untrusted root (RSA root not pinned)", caiman, AndroidKeyConfig{PackageName: caiman.pkg, Roots: ecRoot, Now: at("2025-09-30T00:00:00Z")},
			caiman.challenge, "attestation_untrusted_root"},
		{"untrusted root (new root not pinned)", tegu, AndroidKeyConfig{PackageName: tegu.pkg, Roots: rsaRoot, Now: at("2026-02-25T00:00:00Z")},
			tegu.challenge, "attestation_untrusted_root"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			_, err := NewAndroidKeyVerifier(tc.cfg).VerifyChain(context.Background(), tc.s.chain, tc.chal)
			if got := reasonOf(err); got != tc.reason {
				t.Fatalf("reason %q, want %q (err %v)", got, tc.reason, err)
			}
		})
	}
}

// Real phones with an unlocked bootloader (Google's collector fleet):
// verifiedBootState UNVERIFIED, deviceLocked false.
func TestRealChains_UnlockedBootloader(t *testing.T) {
	for _, tc := range []struct{ name, now string }{
		{"akita_sdk34_TEE_EC_NONE", "2024-09-20T00:00:00Z"},    // Pixel 8a, RKP
		{"blueline_sdk28_TEE_EC_NONE", "2020-01-01T00:00:00Z"}, // Pixel 3, factory batch key
	} {
		t.Run(tc.name, func(t *testing.T) {
			s := loadSample(t, tc.name)
			v := NewAndroidKeyVerifier(AndroidKeyConfig{
				PackageName: "com.google.wireless.android.security.attestationverifier.collector",
				Now:         at(tc.now),
			})
			_, err := v.VerifyChain(context.Background(), s.chain, []byte("challenge"))
			if got := reasonOf(err); got != "attestation_boot_not_verified" {
				t.Fatalf("reason %q, want attestation_boot_not_verified (err %v)", got, err)
			}
		})
	}
}

// A factory-provisioned batch key is shared by many phones, so no hint.
func TestDeviceHint_NoneForFactoryBatchKeys(t *testing.T) {
	s := loadSample(t, "blueline_sdk28_TEE_EC_NONE")
	if h := rkpDeviceHint(s.chain); h != "" {
		t.Fatalf("factory batch chain must not yield a hint, got %q", h)
	}
	a := loadSample(t, "caiman_sdk36_SB_EC_RKP")
	b := loadSample(t, "caiman_sdk36_TEE_EC_RKP")
	if rkpDeviceHint(a.chain) == rkpDeviceHint(b.chain) {
		t.Fatal("different attestation keys must give different hints")
	}
}

// A real chain whose RootOfTrust encodes deviceLocked as a non-DER
// boolean (Google's "invalid" corpus).
func TestRealChain_MalformedRootOfTrust(t *testing.T) {
	pemBytes, err := os.ReadFile("testdata/android/invalid_malformed_rot_device_locked.pem")
	if err != nil {
		t.Fatal(err)
	}
	chain, err := ParsePEMCertificates(pemBytes)
	if err != nil {
		t.Fatal(err)
	}
	v := NewAndroidKeyVerifier(AndroidKeyConfig{PackageName: "x", Now: at("2025-01-01T00:00:00Z")})
	_, err = v.VerifyChain(context.Background(), chain, []byte("challenge"))
	if got := reasonOf(err); got != "attestation_malformed" {
		t.Fatalf("reason %q, want attestation_malformed (err %v)", got, err)
	}
}

func TestRealChain_Revocation(t *testing.T) {
	s := loadSample(t, "caiman_sdk36_SB_EC_RKP")
	attestKeySerial := strings.ToLower(s.chain[1].SerialNumber.Text(16))

	var hits atomic.Int32
	var fail atomic.Bool
	var listed atomic.Bool
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		hits.Add(1)
		if fail.Load() {
			http.Error(w, "down", http.StatusServiceUnavailable)
			return
		}
		entries := `"1f": {"status": "REVOKED", "reason": "KEY_COMPROMISE"}`
		if listed.Load() {
			entries += `, "` + strings.ToUpper(attestKeySerial) + `": {"status": "SUSPENDED", "reason": "SOFTWARE_FLAW"}`
		}
		_, _ = w.Write([]byte(`{"entries": {` + entries + `}}`))
	}))
	defer srv.Close()

	clock := time.Date(2025, 9, 30, 0, 0, 0, 0, time.UTC)
	now := func() time.Time { return clock }
	newV := func(mode RevocationMode) *AndroidKeyVerifier {
		return NewAndroidKeyVerifier(AndroidKeyConfig{
			PackageName: s.pkg,
			Now:         now,
			Revocation:  NewStatusList(StatusListConfig{URL: srv.URL, Mode: mode, Now: now}),
		})
	}
	ctx := context.Background()

	// Not listed: passes, and the list is fetched once then cached.
	v := newV(RevocationFailClosed)
	for i := 0; i < 3; i++ {
		if _, err := v.VerifyChain(ctx, s.chain, s.challenge); err != nil {
			t.Fatalf("unlisted chain: %v", err)
		}
	}
	if hits.Load() != 1 {
		t.Fatalf("expected 1 fetch (cached), got %d", hits.Load())
	}

	// Listed (SUSPENDED counts too), after the cache expires.
	listed.Store(true)
	clock = clock.Add(2 * time.Hour)
	if _, err := v.VerifyChain(ctx, s.chain, s.challenge); reasonOf(err) != "attestation_revoked" {
		t.Fatalf("listed chain: got %v, want attestation_revoked", err)
	}

	// The list goes unreachable: the stale cached list is still used.
	fail.Store(true)
	clock = clock.Add(2 * time.Hour)
	if _, err := v.VerifyChain(ctx, s.chain, s.challenge); reasonOf(err) != "attestation_revoked" {
		t.Fatalf("stale list must still apply, got %v", err)
	}

	// Never fetched + unreachable: fail-closed rejects, fail-open accepts.
	if _, err := newV(RevocationFailClosed).VerifyChain(ctx, s.chain, s.challenge); reasonOf(err) != "attestation_revocation_unavailable" {
		t.Fatalf("fail-closed: got %v", err)
	}
	if _, err := newV(RevocationFailOpen).VerifyChain(ctx, s.chain, s.challenge); err != nil {
		t.Fatalf("fail-open: got %v", err)
	}
}

func TestParseRevocationMode(t *testing.T) {
	for in, want := range map[string]RevocationMode{"": RevocationFailOpen, "OFF": RevocationOff, "fail-open": RevocationFailOpen, " fail-closed ": RevocationFailClosed} {
		got, err := ParseRevocationMode(in)
		if err != nil || got != want {
			t.Errorf("%q: got %q, %v", in, got, err)
		}
	}
	if _, err := ParseRevocationMode("strict"); err == nil {
		t.Error("expected error for unknown mode")
	}
}

func TestParseSignerDigests(t *testing.T) {
	d := sha256.Sum256([]byte("x"))
	h := hex.EncodeToString(d[:])
	colon := strings.ToUpper(h[:2]) + ":" + strings.ToUpper(h[2:4]) + ":" + h[4:]
	got, err := ParseSignerDigests(h + ", " + colon)
	if err != nil || len(got) != 2 || string(got[0]) != string(d[:]) || string(got[1]) != string(d[:]) {
		t.Fatalf("got %x, %v", got, err)
	}
	if _, err := ParseSignerDigests("abcd"); err == nil {
		t.Error("short digest must fail")
	}
}

// ---------------------------------------------------------------------------
// Synthetic chains: same structure as a real RKP chain (root -> "Droid CA"
// -> per-device attestation key -> leaf with the KeyMint extension), signed
// by a test root, so each field can be varied on its own.
// ---------------------------------------------------------------------------

type leafOpts struct {
	attestLevel, keyMintLevel SecurityLevel
	challenge                 []byte
	noRootOfTrust             bool
	locked                    bool
	bootState                 VerifiedBootState
	origin                    int
	pkg                       string
	signer                    []byte
	rotInSoftwareList         bool
}

func goodOpts(challenge []byte) leafOpts {
	return leafOpts{
		attestLevel: SecurityLevelTrustedEnvironment, keyMintLevel: SecurityLevelTrustedEnvironment,
		challenge: challenge, locked: true, bootState: BootVerified, origin: KeyOriginGenerated,
		pkg: "org.openline.wallet", signer: testSigner[:],
	}
}

var testSigner = sha256.Sum256([]byte("openline sideload signing cert"))

func explicit(tag int, v any) asn1.RawValue {
	inner, err := asn1.Marshal(v)
	if err != nil {
		panic(err)
	}
	return asn1.RawValue{Class: asn1.ClassContextSpecific, Tag: tag, IsCompound: true, Bytes: inner}
}

func authList(els ...asn1.RawValue) asn1.RawValue {
	var body []byte
	for _, e := range els {
		b, err := asn1.Marshal(e)
		if err != nil {
			panic(err)
		}
		body = append(body, b...)
	}
	return asn1.RawValue{Class: asn1.ClassUniversal, Tag: asn1.TagSequence, IsCompound: true, Bytes: body}
}

func keyDescriptionDER(o leafOpts) []byte {
	appID, err := asn1.Marshal(asn1AttestationApplicationID{
		PackageInfos:     []asn1PackageInfo{{PackageName: []byte(o.pkg), Version: 11}},
		SignatureDigests: [][]byte{o.signer},
	})
	if err != nil {
		panic(err)
	}
	rot := explicit(tagRootOfTrust, asn1RootOfTrust{
		VerifiedBootKey: make([]byte, 32), DeviceLocked: o.locked,
		VerifiedBootState: asn1.Enumerated(o.bootState), VerifiedBootHash: make([]byte, 32),
	})
	sw := []asn1.RawValue{explicit(tagAttestationApplicationID, appID)}
	hw := []asn1.RawValue{explicit(tagOrigin, o.origin)}
	if !o.noRootOfTrust {
		if o.rotInSoftwareList {
			sw = append([]asn1.RawValue{rot}, sw...)
		} else {
			hw = append(hw, rot)
		}
	}
	hw = append(hw, explicit(tagOSPatchLevel, 202610), explicit(tagAttestationIDModel, []byte("Pixel 10")))
	der, err := asn1.Marshal(asn1KeyDescription{
		AttestationVersion: 400, AttestationSecurityLevel: asn1.Enumerated(o.attestLevel),
		KeyMintVersion: 400, KeyMintSecurityLevel: asn1.Enumerated(o.keyMintLevel),
		AttestationChallenge: o.challenge, UniqueID: []byte{},
		SoftwareEnforced: authList(sw...), HardwareEnforced: authList(hw...),
	})
	if err != nil {
		panic(err)
	}
	return der
}

type testPKI struct {
	root, droidCA, attestKey      *x509.Certificate
	rootKey, droidKey, attestPriv *ecdsa.PrivateKey
}

var serialCounter atomic.Int64

func mkCert(t *testing.T, tmpl *x509.Certificate, parent *x509.Certificate, pub any, signer *ecdsa.PrivateKey) *x509.Certificate {
	t.Helper()
	tmpl.SerialNumber = big.NewInt(1000 + serialCounter.Add(1))
	if parent == nil {
		parent = tmpl
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, parent, pub, signer)
	if err != nil {
		t.Fatal(err)
	}
	c, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatal(err)
	}
	return c
}

func newKey(t *testing.T) *ecdsa.PrivateKey {
	t.Helper()
	k, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	return k
}

var (
	pkiNow    = time.Date(2026, 11, 3, 12, 0, 0, 0, time.UTC)
	pkiBefore = pkiNow.Add(-24 * time.Hour)
	pkiAfter  = pkiNow.Add(10 * 24 * time.Hour)
)

func newTestPKI(t *testing.T) *testPKI {
	t.Helper()
	p := &testPKI{rootKey: newKey(t), droidKey: newKey(t), attestPriv: newKey(t)}
	ca := func(name pkix.Name) *x509.Certificate {
		return &x509.Certificate{Subject: name, NotBefore: pkiBefore, NotAfter: pkiAfter.Add(365 * 24 * time.Hour),
			IsCA: true, BasicConstraintsValid: true, KeyUsage: x509.KeyUsageCertSign}
	}
	p.root = mkCert(t, ca(pkix.Name{SerialNumber: "test-root"}), nil, &p.rootKey.PublicKey, p.rootKey)
	p.droidCA = mkCert(t, ca(pkix.Name{Organization: []string{"Google LLC"}, CommonName: "Droid CA3"}), p.root, &p.droidKey.PublicKey, p.rootKey)
	ak := ca(pkix.Name{Organization: []string{"TEE"}, CommonName: "0123456789abcdef0123456789abcdef"})
	ak.NotAfter = pkiAfter
	p.attestKey = mkCert(t, ak, p.droidCA, &p.attestPriv.PublicKey, p.droidKey)
	return p
}

// leaf builds the leaf certificate for a fresh app key, as KeyMint would.
func (p *testPKI) leaf(t *testing.T, o leafOpts) *x509.Certificate {
	t.Helper()
	appKey := newKey(t)
	tmpl := &x509.Certificate{
		Subject:   pkix.Name{CommonName: "Android Keystore Key"},
		NotBefore: time.Unix(0, 0).UTC(), NotAfter: time.Date(2048, 1, 1, 0, 0, 0, 0, time.UTC),
		ExtraExtensions: []pkix.Extension{{Id: OIDAndroidKeyAttestation, Value: keyDescriptionDER(o)}},
		KeyUsage:        x509.KeyUsageDigitalSignature,
	}
	return mkCert(t, tmpl, p.attestKey, &appKey.PublicKey, p.attestPriv)
}

func (p *testPKI) chain(t *testing.T, o leafOpts) []*x509.Certificate {
	return []*x509.Certificate{p.leaf(t, o), p.attestKey, p.droidCA, p.root}
}

func (p *testPKI) verifier() *AndroidKeyVerifier {
	return NewAndroidKeyVerifier(AndroidKeyConfig{
		PackageName: "org.openline.wallet", SignerDigests: [][]byte{testSigner[:]},
		Roots: []*x509.Certificate{p.root}, Now: func() time.Time { return pkiNow },
	})
}

func TestSynthetic_GoodChainPasses(t *testing.T) {
	p := newTestPKI(t)
	chal := []byte("0123456789abcdef0123456789abcdef")
	ev, err := p.verifier().VerifyChain(context.Background(), p.chain(t, goodOpts(chal)), chal)
	if err != nil {
		t.Fatalf("good chain: %v", err)
	}
	sum := sha256.Sum256(p.attestKey.RawSubjectPublicKeyInfo)
	if ev.DeviceHint != hex.EncodeToString(sum[:]) || ev.SecurityLevel != "tee" {
		t.Fatalf("evidence %+v", ev)
	}
	// The client may leave the root off; the top cert is then checked
	// against the pinned root's key.
	if _, err := p.verifier().VerifyChain(context.Background(), p.chain(t, goodOpts(chal))[:3], chal); err != nil {
		t.Fatalf("chain without root: %v", err)
	}
}

func TestSynthetic_Rejections(t *testing.T) {
	p := newTestPKI(t)
	chal := []byte("session-nonce-bytes-32-long-xxxxx")
	mod := func(f func(*leafOpts)) leafOpts { o := goodOpts(chal); f(&o); return o }
	cases := []struct {
		name   string
		o      leafOpts
		reason string
	}{
		{"software-backed key", mod(func(o *leafOpts) { o.attestLevel, o.keyMintLevel = SecurityLevelSoftware, SecurityLevelSoftware }), "attestation_not_hardware"},
		{"software keymint under TEE attestation", mod(func(o *leafOpts) { o.keyMintLevel = SecurityLevelSoftware }), "attestation_not_hardware"},
		{"no root of trust", mod(func(o *leafOpts) { o.noRootOfTrust = true }), "attestation_not_hardware"},
		{"root of trust only software-enforced", mod(func(o *leafOpts) { o.rotInSoftwareList = true }), "attestation_not_hardware"},
		{"unlocked bootloader", mod(func(o *leafOpts) { o.locked = false; o.bootState = BootUnverified }), "attestation_boot_not_verified"},
		{"custom ROM, relocked", mod(func(o *leafOpts) { o.bootState = BootSelfSigned }), "attestation_boot_not_verified"},
		{"verified but unlocked", mod(func(o *leafOpts) { o.locked = false }), "attestation_device_unlocked"},
		{"imported key", mod(func(o *leafOpts) { o.origin = 2 }), "attestation_key_not_generated"},
		{"wrong challenge", mod(func(o *leafOpts) { o.challenge = []byte("replayed from another session") }), "attestation_challenge_mismatch"},
		{"another app", mod(func(o *leafOpts) { o.pkg = "com.evil.farm" }), "attestation_wrong_app"},
		{"repackaged app", mod(func(o *leafOpts) { o.signer = make([]byte, 32) }), "attestation_wrong_app"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			_, err := p.verifier().VerifyChain(context.Background(), p.chain(t, tc.o), chal)
			if got := reasonOf(err); got != tc.reason {
				t.Fatalf("reason %q, want %q (err %v)", got, tc.reason, err)
			}
		})
	}
}

func TestSynthetic_UntrustedRoot(t *testing.T) {
	p := newTestPKI(t)
	other := newTestPKI(t)
	chal := []byte("nonce")
	// Chain from `other`, verifier pinning p's root.
	_, err := p.verifier().VerifyChain(context.Background(), other.chain(t, goodOpts(chal)), chal)
	if got := reasonOf(err); got != "attestation_untrusted_root" {
		t.Fatalf("reason %q (err %v)", got, err)
	}
	// And the real Google roots don't accept a test chain either.
	g := NewAndroidKeyVerifier(AndroidKeyConfig{PackageName: "org.openline.wallet", Now: func() time.Time { return pkiNow }})
	if _, err := g.VerifyChain(context.Background(), p.chain(t, goodOpts(chal)), chal); reasonOf(err) != "attestation_untrusted_root" {
		t.Fatalf("google roots accepted a test chain: %v", err)
	}
}

func TestSynthetic_TamperedLeaf(t *testing.T) {
	p := newTestPKI(t)
	chal := []byte("nonce-A")
	chain := p.chain(t, goodOpts(chal))
	raw := append([]byte(nil), chain[0].Raw...)
	i := strings.Index(string(raw), "nonce-A")
	raw[i+6] = 'B' // the challenge now says nonce-B, signature unchanged
	forged, err := x509.ParseCertificate(raw)
	if err != nil {
		t.Fatal(err)
	}
	chain[0] = forged
	_, err = p.verifier().VerifyChain(context.Background(), chain, []byte("nonce-B"))
	if got := reasonOf(err); got != "attestation_chain_invalid" {
		t.Fatalf("reason %q (err %v)", got, err)
	}
}

// The attack the "extension only in the leaf" rule stops: an app key that
// was itself attested (its cert carries the extension) is used to sign a
// hand-made "leaf" claiming whatever the attacker likes.
func TestSynthetic_AttestedAppKeyAsIssuer(t *testing.T) {
	p := newTestPKI(t)
	chal := []byte("victim session nonce")
	appKey := newKey(t)
	appCert := mkCert(t, &x509.Certificate{
		Subject:   pkix.Name{CommonName: "Android Keystore Key"},
		NotBefore: pkiBefore, NotAfter: pkiAfter,
		ExtraExtensions: []pkix.Extension{{Id: OIDAndroidKeyAttestation, Value: keyDescriptionDER(goodOpts([]byte("whatever")))}},
		IsCA:            true, BasicConstraintsValid: true,
	}, p.attestKey, &appKey.PublicKey, p.attestPriv)
	fake := mkCert(t, &x509.Certificate{
		Subject:   pkix.Name{CommonName: "Android Keystore Key"},
		NotBefore: pkiBefore, NotAfter: pkiAfter,
		ExtraExtensions: []pkix.Extension{{Id: OIDAndroidKeyAttestation, Value: keyDescriptionDER(goodOpts(chal))}},
	}, appCert, &newKey(t).PublicKey, appKey)
	chain := []*x509.Certificate{fake, appCert, p.attestKey, p.droidCA, p.root}
	_, err := p.verifier().VerifyChain(context.Background(), chain, chal)
	if got := reasonOf(err); got != "attestation_chain_invalid" {
		t.Fatalf("reason %q (err %v)", got, err)
	}
}

func TestSynthetic_MalformedInputs(t *testing.T) {
	p := newTestPKI(t)
	v := p.verifier()
	ctx := context.Background()
	if _, err := v.VerifyChain(ctx, []*x509.Certificate{p.leaf(t, goodOpts([]byte("n")))}, []byte("n")); reasonOf(err) != "attestation_malformed" {
		t.Errorf("single cert: %v", err)
	}
	// Leaf without the extension (a plain key, never attested).
	plain := mkCert(t, &x509.Certificate{Subject: pkix.Name{CommonName: "x"}, NotBefore: pkiBefore, NotAfter: pkiAfter},
		p.attestKey, &newKey(t).PublicKey, p.attestPriv)
	if _, err := v.VerifyChain(ctx, []*x509.Certificate{plain, p.attestKey, p.droidCA, p.root}, []byte("n")); reasonOf(err) != "attestation_malformed" {
		t.Errorf("no extension: %v", err)
	}
	for _, tok := range []string{"", "not base64!", base64.StdEncoding.EncodeToString([]byte("not a cert"))} {
		_, err := v.Verify(ctx, AttestationInput{Platform: PlatformAndroid, Nonce: "abcd", Token: tok})
		if reasonOf(err) != "attestation_malformed" {
			t.Errorf("token %q: %v", tok, err)
		}
	}
}

func TestParseKeyDescription_DuplicateTagRejected(t *testing.T) {
	der, err := asn1.Marshal(asn1KeyDescription{
		AttestationVersion: 400, AttestationSecurityLevel: 1, KeyMintVersion: 400, KeyMintSecurityLevel: 1,
		AttestationChallenge: []byte("c"), UniqueID: []byte{},
		SoftwareEnforced: authList(),
		HardwareEnforced: authList(explicit(tagOrigin, 0), explicit(tagOrigin, 2)),
	})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := ParseKeyDescription(der); err == nil {
		t.Fatal("duplicate tag must be rejected")
	}
}

// ---------------------------------------------------------------------------
// Through the Method: begin -> Android chain -> complete.
// ---------------------------------------------------------------------------

func androidMethod(t *testing.T, p *testPKI, limiter DeviceHintLimiter) (*Method, *InMemoryStore) {
	t.Helper()
	store := NewInMemoryStore()
	m := NewMethod(Config{
		Verifier:    PlatformRouter{PlatformAndroid: p.verifier()},
		Store:       store,
		HintLimiter: limiter,
	})
	return m, store
}

func completeAndroid(t *testing.T, m *Method, p *testPKI, session string, mutate func(*leafOpts)) types.MethodResult {
	t.Helper()
	ctx := context.Background()
	cc := types.CeremonyContext{SessionID: session, MethodID: MethodID}
	ch, err := m.BeginCeremony(ctx, cc)
	if err != nil {
		t.Fatal(err)
	}
	if ch.Payload["nonce_encoding"] != "hex" {
		t.Fatalf("begin payload %v", ch.Payload)
	}
	nonce, _ := hex.DecodeString(ch.Payload["nonce"].(string))
	o := goodOpts(nonce)
	if mutate != nil {
		mutate(&o)
	}
	var arr []any
	for _, c := range p.chain(t, o) {
		arr = append(arr, base64.StdEncoding.EncodeToString(c.Raw))
	}
	res, err := m.CompleteCeremony(ctx, cc, types.ResponseData{Payload: map[string]any{
		"platform": "android", "certificate_chain": arr,
	}})
	if err != nil {
		t.Fatal(err)
	}
	return res
}

func TestMethod_AndroidHappyPathAndReasons(t *testing.T) {
	p := newTestPKI(t)
	m, _ := androidMethod(t, p, nil)
	if res := completeAndroid(t, m, p, "s1", nil); !res.Success || res.AttestationDigest == "" {
		t.Fatalf("happy path: %+v", res)
	}
	if res := completeAndroid(t, m, p, "s2", func(o *leafOpts) { o.locked = false; o.bootState = BootUnverified }); res.Success || res.ErrorReason != "attestation_boot_not_verified" {
		t.Fatalf("unlocked: %+v", res)
	}
	// iOS is not routed when only Android is configured.
	ctx := context.Background()
	cc := types.CeremonyContext{SessionID: "s3", MethodID: MethodID}
	if _, err := m.BeginCeremony(ctx, cc); err != nil {
		t.Fatal(err)
	}
	res, _ := m.CompleteCeremony(ctx, cc, types.ResponseData{Payload: map[string]any{"platform": "ios", "token": "x"}})
	if res.Success || res.ErrorReason != "platform_unsupported" {
		t.Fatalf("ios: %+v", res)
	}
}

func TestMethod_DeviceHintLimit(t *testing.T) {
	p := newTestPKI(t)
	m, _ := androidMethod(t, p, NewInMemoryHintLimiter(2, 0))
	for _, s := range []string{"a", "b", "a"} { // repeating a counted session is fine
		if res := completeAndroid(t, m, p, s, nil); !res.Success {
			t.Fatalf("session %s: %+v", s, res)
		}
	}
	if res := completeAndroid(t, m, p, "c", nil); res.Success || res.ErrorReason != "device_enrollment_limit" {
		t.Fatalf("third session on the same attestation key: %+v", res)
	}
	// A different phone (different attestation key) is unaffected.
	if res := completeAndroid(t, m, newTestPKIWithRoot(t, p), "d", nil); !res.Success {
		t.Fatalf("other device: %+v", res)
	}
}

// newTestPKIWithRoot gives a second "phone" (its own attestation key) under
// the same root and Droid CA as p.
func newTestPKIWithRoot(t *testing.T, p *testPKI) *testPKI {
	t.Helper()
	q := *p
	q.attestPriv = newKey(t)
	q.attestKey = mkCert(t, &x509.Certificate{
		Subject:   pkix.Name{Organization: []string{"TEE"}, CommonName: "fedcba9876543210fedcba9876543210"},
		NotBefore: pkiBefore, NotAfter: pkiAfter, IsCA: true, BasicConstraintsValid: true, KeyUsage: x509.KeyUsageCertSign,
	}, p.droidCA, &q.attestPriv.PublicKey, p.droidKey)
	return &q
}

func TestGoogleRootCertificates(t *testing.T) {
	roots := GoogleRootCertificates()
	if len(roots) != 2 {
		t.Fatalf("expected 2 pinned roots, got %d", len(roots))
	}
	want := map[string]bool{
		// SHA-256 of each root's SubjectPublicKeyInfo.
		"feb2ea7551ee316ed4bb443c8293b884dbfdea40b603ee3e4f4a897e4580fbae": false, // RSA root (serialNumber=f92009e853b6b045)
		"3ee44512a1af2beb39c889490c60ea3f82e43f5d5a5532f5ab9419f676cd07ec": false, // Key Attestation CA1 (ECDSA P-384)
	}
	for _, r := range roots {
		sum := sha256.Sum256(r.RawSubjectPublicKeyInfo)
		h := hex.EncodeToString(sum[:])
		if _, ok := want[h]; !ok {
			t.Errorf("unexpected root key %s (%s)", h, r.Subject)
		}
		want[h] = true
	}
	for h, seen := range want {
		if !seen {
			t.Errorf("missing pinned root key %s", h)
		}
	}
}
