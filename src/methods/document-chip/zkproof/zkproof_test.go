package zkproof

import (
	"context"
	"encoding/hex"
	"encoding/json"
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"
)

// The fixtures in testdata/<vector>/ were made by spikes/zk-passport
// (run.sh, then bind-fixtures.mjs) from the personhood ICAO test vectors in
// ../icao/testdata (p256 and rsa-pss): four sub-proofs (dsc, id, integrity,
// bind), their public inputs, and the verification keys. The bind proof
// commits to BindData(testChallenge, testHolderDID).

// Must match spikes/zk-passport/bind-fixtures.mjs.
var testChallenge = [32]byte{0x5a, 0x5a, 0x5a, 0x5a, 0x5a, 0x5a, 0x5a, 0x5a, 0x5a, 0x5a, 0x5a, 0x5a, 0x5a, 0x5a, 0x5a, 0x5a,
	0x5a, 0x5a, 0x5a, 0x5a, 0x5a, 0x5a, 0x5a, 0x5a, 0x5a, 0x5a, 0x5a, 0x5a, 0x5a, 0x5a, 0x5a, 0x5a}

const testHolderDID = "did:key:z6MkhaXgBZDvotDkL5257faiztiGiC2QtKLGpbnnEGta2doK"

var testBind = BindData(testChallenge, testHolderDID)

// The aa fixtures (spikes/zk-passport/aa-fixtures.mjs) answer this challenge.
var testAA = AAChallenge(testChallenge)

//
// The tests need the bb binary. They look for it in $BB, then on PATH as
// "bb", then in spikes/zk-passport/node_modules (npm install there). Without
// it they skip.

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
	p, _ := filepath.Abs(filepath.Join("..", "..", "..", "..", "spikes", "zk-passport", "node_modules", "@aztec", "bb.js", "build", arch+"-"+osn, "bb"))
	if _, err := os.Stat(p); err == nil {
		return p
	}
	t.Skip("bb not found: set BB or run npm install in spikes/zk-passport")
	return ""
}

type manifest struct {
	Circuits     map[string]string `json:"circuits"`
	RegistryRoot string            `json:"registry_root"`
	Scope        string            `json:"scope"`
	CurrentDate  int64             `json:"current_date"`
}

func field(t *testing.T, h string) (f [FieldSize]byte) {
	t.Helper()
	b, err := hex.DecodeString(strings.TrimPrefix(h, "0x"))
	if err != nil || len(b) > FieldSize {
		t.Fatalf("bad field %q", h)
	}
	copy(f[FieldSize-len(b):], b)
	return f
}

func load(t *testing.T, vector string) (*Verifier, Bundle) {
	t.Helper()
	dir := filepath.Join("testdata", vector)
	raw, err := os.ReadFile(filepath.Join(dir, "manifest.json"))
	if err != nil {
		t.Fatal(err)
	}
	var m manifest
	if err := json.Unmarshal(raw, &m); err != nil {
		t.Fatal(err)
	}
	read := func(stage, f string) []byte {
		b, err := os.ReadFile(filepath.Join(dir, stage, f))
		if err != nil {
			t.Fatal(err)
		}
		return b
	}
	v := &Verifier{
		BB:    findBB(t),
		VKs:   map[string][]byte{},
		Roots: map[[FieldSize]byte]bool{field(t, m.RegistryRoot): true},
		Scope: field(t, m.Scope),
	}
	sp := map[string]SubProof{}
	for _, st := range Stages {
		v.VKs[m.Circuits[st]] = read(st, "vk")
		sp[st] = SubProof{Circuit: m.Circuits[st], Proof: read(st, "proof"), PublicInputs: read(st, "public_inputs")}
	}
	b := Bundle{DSC: sp["dsc"], ID: sp["id"], Integrity: sp["integrity"], Bind: sp["bind"], AA: sp["aa"]}
	// The proof states the date it was made; pin the clock to it.
	date, _ := small(([FieldSize]byte)(b.Bind.PublicInputs[FieldSize : 2*FieldSize]))
	v.Now = func() time.Time { return time.Unix(date, 0).Add(time.Hour) }
	return v, b
}

func TestVerifyVectors(t *testing.T) {
	for _, vec := range []string{"p256", "rsa-pss"} {
		t.Run(vec, func(t *testing.T) {
			v, b := load(t, vec)
			start := time.Now()
			res, err := v.Verify(context.Background(), b, testBind, testAA)
			if err != nil {
				t.Fatalf("Verify: %v", err)
			}
			// rsa-pss lists DG15 (RSA-1024 AA key); p256 has none.
			if want := vec == "rsa-pss"; res.ActiveAuth != want {
				t.Errorf("ActiveAuth = %v, want %v", res.ActiveAuth, want)
			}
			t.Logf("verified 5 sub-proofs in %v; identifier %s", time.Since(start), res.Identifier())
			if res.NullifierType != NullifierNonSalted {
				t.Errorf("nullifier type %d", res.NullifierType)
			}
			if !strings.HasPrefix(res.Identifier(), "chip:ZK:") || len(res.Identifier()) != len("chip:ZK:")+64 {
				t.Errorf("identifier shape %q", res.Identifier())
			}
		})
	}
}

func flip(b []byte, i int) []byte {
	c := append([]byte(nil), b...)
	c[i] ^= 1
	return c
}

func TestVerifyRejects(t *testing.T) {
	ctx := context.Background()
	cases := []struct {
		name string
		mut  func(v *Verifier, b *Bundle)
		want error
		bind *[BindDataSize]byte
		vec  string
	}{
		{"tampered nullifier", func(_ *Verifier, b *Bundle) {
			b.Bind.PublicInputs = flip(b.Bind.PublicInputs, 6*FieldSize+31)
		}, ErrProofInvalid, nil, ""},
		{"tampered param commitment", func(_ *Verifier, b *Bundle) {
			b.Bind.PublicInputs = flip(b.Bind.PublicInputs, 4*FieldSize+31)
		}, ErrBindMismatch, nil, ""},
		{"tampered proof", func(_ *Verifier, b *Bundle) { b.ID.Proof = flip(b.ID.Proof, 1000) }, ErrProofInvalid, nil, ""},
		{"registry root not published", func(v *Verifier, _ *Bundle) { v.Roots = map[[FieldSize]byte]bool{} }, ErrRegistryUnknown, nil, ""},
		{"other scope", func(v *Verifier, _ *Bundle) { v.Scope[31] ^= 1 }, ErrScope, nil, ""},
		{"stale date", func(v *Verifier, _ *Bundle) {
			v.Now = func() time.Time { return time.Now().Add(72 * time.Hour) }
		}, ErrStaleDate, nil, ""},
		{"untrusted vk", func(v *Verifier, b *Bundle) { delete(v.VKs, b.DSC.Circuit) }, ErrUnknownCircuit, nil, ""},
		{"bind vk used for dsc", func(v *Verifier, b *Bundle) { b.DSC.Circuit = BindCircuit }, ErrUnknownCircuit, nil, ""},
		{"stage swap", func(_ *Verifier, b *Bundle) { b.ID, b.Integrity = b.Integrity, b.ID }, ErrChainBroken, nil, ""},
		{"other session challenge", func(*Verifier, *Bundle) {}, ErrBindMismatch, func() *[BindDataSize]byte {
			c := testChallenge
			c[0] ^= 1
			d := BindData(c, testHolderDID)
			return &d
		}(), ""},
		{"other holder DID", func(*Verifier, *Bundle) {}, ErrBindMismatch, func() *[BindDataSize]byte {
			d := BindData(testChallenge, testHolderDID+"x")
			return &d
		}(), ""},
		// Active Authentication
		{"aa missing (a clone leaving DG15 out)", func(_ *Verifier, b *Bundle) { b.AA = SubProof{} }, ErrAAMissing, nil, "rsa-pss"},
		{"aa answers another challenge (old session)", func(v *Verifier, b *Bundle) {
			b.AA = loadStage(t, "rsa-pss", "aa-wrong-challenge", b.AA.Circuit)
		}, ErrAAChallenge, nil, "rsa-pss"},
		{"old-session aa with its challenge rewritten to this one", func(_ *Verifier, b *Bundle) {
			b.AA = loadStage(t, "rsa-pss", "aa-wrong-challenge", b.AA.Circuit)
			copy(b.AA.PublicInputs[2*FieldSize-AAChallengeSize:], testAA[:])
		}, ErrProofInvalid, nil, "rsa-pss"},
		{"aa proof tampered", func(_ *Verifier, b *Bundle) { b.AA.Proof = flip(b.AA.Proof, 2000) }, ErrProofInvalid, nil, "rsa-pss"},
		{"aa of another passport", func(_ *Verifier, b *Bundle) {
			_, other := load(t, "p256")
			b.AA = other.AA
		}, ErrChainBroken, nil, "rsa-pss"},
		{"aa vk not pinned", func(v *Verifier, b *Bundle) { delete(v.VKs, b.AA.Circuit) }, ErrUnknownCircuit, nil, "rsa-pss"},
		{"aa proof under another stage's name", func(_ *Verifier, b *Bundle) { b.AA.Circuit = BindCircuit }, ErrUnknownCircuit, nil, "rsa-pss"},
		{"aa_absent name on a DG15 proof", func(v *Verifier, b *Bundle) {
			// The vk decides: the absent circuit's key does not verify an AA proof.
			_, other := load(t, "p256")
			v.VKs[AAAbsentCircuit] = mustVK(t, "p256", "aa")
			b.AA.Circuit = other.AA.Circuit
		}, ErrProofInvalid, nil, "rsa-pss"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			vec := tc.vec
			if vec == "" {
				vec = "p256"
			}
			v, b := load(t, vec)
			tc.mut(v, &b)
			bind := testBind
			if tc.bind != nil {
				bind = *tc.bind
			}
			_, err := v.Verify(ctx, b, bind, testAA)
			if tc.want == nil {
				if err == nil {
					t.Fatal("accepted")
				}
				return
			}
			if !errors.Is(err, tc.want) {
				t.Fatalf("got %v, want %v", err, tc.want)
			}
		})
	}

	// Sub-proofs from two different passports do not chain.
	t.Run("mixed passports", func(t *testing.T) {
		v, b := load(t, "p256")
		_, other := load(t, "rsa-pss")
		b.Bind = other.Bind
		if _, err := v.Verify(ctx, b, testBind, testAA); !errors.Is(err, ErrChainBroken) {
			t.Fatalf("got %v", err)
		}
	})
}

func TestServiceScopeIsStable(t *testing.T) {
	// The scope is part of every nullifier this issuer has stored: changing
	// it would give every passport a new identity.
	s := ServiceScope()
	if got := hex.EncodeToString(s[:]); got != wantScopeHex {
		t.Fatalf("ServiceScope() = %s; changing it re-keys every enrolled passport", got)
	}
}

const wantScopeHex = "28a6676ad15b10f2b78fb5f1e25cd20c68e5d4611ecf6b364df8427d0c69edfe"

func loadStage(t *testing.T, vector, dir, circuit string) SubProof {
	t.Helper()
	read := func(f string) []byte {
		b, err := os.ReadFile(filepath.Join("testdata", vector, dir, f))
		if err != nil {
			t.Fatal(err)
		}
		return b
	}
	return SubProof{Circuit: circuit, Proof: read("proof"), PublicInputs: read("public_inputs")}
}

func mustVK(t *testing.T, vector, stage string) []byte {
	t.Helper()
	b, err := os.ReadFile(filepath.Join("testdata", vector, stage, "vk"))
	if err != nil {
		t.Fatal(err)
	}
	return b
}

func TestAAChallengeIsStable(t *testing.T) {
	// The wallet hands this to the chip; it must not drift between issuer
	// and fixtures (spikes/zk-passport/aa-fixtures.mjs).
	got := AAChallenge(testChallenge)
	raw, err := os.ReadFile(filepath.Join("testdata", "rsa-pss", "manifest.json"))
	if err != nil {
		t.Fatal(err)
	}
	var m struct {
		AAChallenge string `json:"aa_challenge"`
	}
	if err := json.Unmarshal(raw, &m); err != nil {
		t.Fatal(err)
	}
	if "0x"+hex.EncodeToString(got[:]) != m.AAChallenge {
		t.Fatalf("AAChallenge = %x, fixtures used %s", got, m.AAChallenge)
	}
}

// testChainID is the OpenLine chain the link fixtures were proved for
// (spikes/zk-passport/link-fixtures.mjs); OpenLine's passport tests use the
// same chain id and pin the same scope.
const testChainID = "passport-e2e"

func TestChainScope(t *testing.T) {
	s := ChainScope(testChainID)
	t.Logf("ChainScope(%q) = 0x%x", testChainID, s)
	if got := hex.EncodeToString(s[:]); got != "0728a2109c6a24d69012ccf09e50c212ffce27b662a93775063bc5dab6edea12" {
		t.Fatalf("chain scope %s (OpenLine's PassportScope vector differs)", got)
	}
}

func loadLink(t *testing.T, vector string) SubProof {
	t.Helper()
	read := func(f string) []byte {
		b, err := os.ReadFile(filepath.Join("testdata", vector, "link", f))
		if err != nil {
			t.Fatal(err)
		}
		return b
	}
	return SubProof{Circuit: BindCircuit, Proof: read("proof"), PublicInputs: read("public_inputs")}
}

// The link: a second bind proof of the same passport for a chain's scope.
func TestVerifyLink(t *testing.T) {
	ctx := context.Background()
	for _, vec := range []string{"p256", "rsa-pss"} {
		t.Run(vec, func(t *testing.T) {
			v, b := load(t, vec)
			res, err := v.Verify(ctx, b, testBind, testAA)
			if err != nil {
				t.Fatal(err)
			}
			link := loadLink(t, vec)
			n, err := v.VerifyLink(ctx, b, link, ChainScope(testChainID), testBind)
			if err != nil {
				t.Fatalf("VerifyLink: %v", err)
			}
			if n == res.Nullifier || n == ([FieldSize]byte{}) {
				t.Fatalf("chain nullifier %x must differ from the issuer's %x", n, res.Nullifier)
			}
			t.Logf("chain nullifier %x", n)
			bad := map[string]func() (Bundle, SubProof, [FieldSize]byte, [BindDataSize]byte){
				"other chain": func() (Bundle, SubProof, [FieldSize]byte, [BindDataSize]byte) {
					return b, link, ChainScope("other-chain"), testBind
				},
				"issuer scope": func() (Bundle, SubProof, [FieldSize]byte, [BindDataSize]byte) {
					return b, link, v.Scope, testBind
				},
				"other session": func() (Bundle, SubProof, [FieldSize]byte, [BindDataSize]byte) {
					return b, link, ChainScope(testChainID), BindData(testChallenge, "did:key:other")
				},
				"other passport's link": func() (Bundle, SubProof, [FieldSize]byte, [BindDataSize]byte) {
					other := map[string]string{"p256": "rsa-pss", "rsa-pss": "p256"}[vec]
					return b, loadLink(t, other), ChainScope(testChainID), testBind
				},
				"tampered proof": func() (Bundle, SubProof, [FieldSize]byte, [BindDataSize]byte) {
					l := link
					l.Proof = flip(l.Proof, 5000)
					return b, l, ChainScope(testChainID), testBind
				},
				"main bind as link": func() (Bundle, SubProof, [FieldSize]byte, [BindDataSize]byte) {
					return b, b.Bind, ChainScope(testChainID), testBind
				},
			}
			for name, mk := range bad {
				bb, l, sc, bd := mk()
				if _, err := v.VerifyLink(ctx, bb, l, sc, bd); !errors.Is(err, ErrLink) {
					t.Fatalf("%s: %v", name, err)
				}
			}
		})
	}
}
