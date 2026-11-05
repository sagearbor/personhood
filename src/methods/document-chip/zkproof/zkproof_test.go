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

// The fixtures in testdata/<vector>/ were made by spikes/zk-passport from the
// personhood ICAO test vectors in ../icao/testdata (p256 and rsa-pss): four
// sub-proofs, their public inputs, and the verification keys.
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
	b := Bundle{DSC: sp["dsc"], ID: sp["id"], Integrity: sp["integrity"], Expiry: sp["expiry"]}
	// The proof states the date it was made; pin the clock to it.
	date, _ := small(([FieldSize]byte)(b.Expiry.PublicInputs[FieldSize : 2*FieldSize]))
	v.Now = func() time.Time { return time.Unix(date, 0).Add(time.Hour) }
	return v, b
}

func TestVerifyVectors(t *testing.T) {
	for _, vec := range []string{"p256", "rsa-pss"} {
		t.Run(vec, func(t *testing.T) {
			v, b := load(t, vec)
			start := time.Now()
			res, err := v.Verify(context.Background(), b)
			if err != nil {
				t.Fatalf("Verify: %v", err)
			}
			t.Logf("verified 4 sub-proofs in %v; identifier %s", time.Since(start), res.Identifier())
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
	}{
		{"tampered nullifier", func(_ *Verifier, b *Bundle) {
			b.Expiry.PublicInputs = flip(b.Expiry.PublicInputs, 6*FieldSize+31)
		}, ErrProofInvalid},
		{"tampered proof", func(_ *Verifier, b *Bundle) { b.ID.Proof = flip(b.ID.Proof, 1000) }, ErrProofInvalid},
		{"registry root not published", func(v *Verifier, _ *Bundle) { v.Roots = map[[FieldSize]byte]bool{} }, ErrRegistryUnknown},
		{"other scope", func(v *Verifier, _ *Bundle) { v.Scope[31] ^= 1 }, ErrScope},
		{"stale date", func(v *Verifier, _ *Bundle) {
			v.Now = func() time.Time { return time.Now().Add(72 * time.Hour) }
		}, ErrStaleDate},
		{"untrusted vk", func(v *Verifier, b *Bundle) { delete(v.VKs, b.DSC.Circuit) }, ErrUnknownCircuit},
		{"stage swap", func(_ *Verifier, b *Bundle) { b.ID, b.Integrity = b.Integrity, b.ID }, ErrChainBroken},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			v, b := load(t, "p256")
			tc.mut(v, &b)
			if _, err := v.Verify(ctx, b); !errors.Is(err, tc.want) {
				t.Fatalf("got %v, want %v", err, tc.want)
			}
		})
	}

	// Sub-proofs from two different passports do not chain.
	t.Run("mixed passports", func(t *testing.T) {
		v, b := load(t, "p256")
		_, other := load(t, "rsa-pss")
		b.Expiry = other.Expiry
		if _, err := v.Verify(ctx, b); !errors.Is(err, ErrChainBroken) {
			t.Fatalf("got %v", err)
		}
	})
}
