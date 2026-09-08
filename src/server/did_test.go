package server

import (
	"crypto/ed25519"
	"crypto/rand"
	"strings"
	"testing"

	"github.com/sagearbor/personhood/pkg/types"
)

func TestBase58_RoundTrip(t *testing.T) {
	cases := [][]byte{
		{},
		{0x00},
		{0x00, 0x00, 0x01},
		{0xed, 0x01},
		[]byte("hello world"),
	}
	// Add a real Ed25519 public key and a few random 34-byte payloads.
	pub, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	cases = append(cases, append(append([]byte{}, ed25519MulticodecPrefix...), pub...))
	for i := 0; i < 20; i++ {
		buf := make([]byte, 34)
		if _, err := rand.Read(buf); err != nil {
			t.Fatal(err)
		}
		cases = append(cases, buf)
	}

	for _, c := range cases {
		enc := base58Encode(c)
		dec, err := base58Decode(enc)
		if err != nil {
			t.Fatalf("base58Decode(%q) after encoding %x: %v", enc, c, err)
		}
		if len(c) == 0 {
			if len(dec) != 0 {
				t.Errorf("round trip of empty input produced %x", dec)
			}
			continue
		}
		if string(dec) != string(c) {
			t.Errorf("round trip mismatch: in=%x out=%x (encoded=%q)", c, dec, enc)
		}
	}
}

func TestBase58Decode_RejectsInvalidCharacters(t *testing.T) {
	// '0', 'O', 'I', 'l' are deliberately excluded from base58btc.
	for _, bad := range []string{"0", "O", "I", "l", "z6Mk0", "not-base58!"} {
		if _, err := base58Decode(bad); err == nil {
			t.Errorf("base58Decode(%q) should have failed", bad)
		}
	}
}

func TestDIDKeyFromEd25519_RoundTrip(t *testing.T) {
	pub, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	did, err := DIDKeyFromEd25519(pub)
	if err != nil {
		t.Fatalf("DIDKeyFromEd25519: %v", err)
	}
	if !strings.HasPrefix(string(did), "did:key:z") {
		t.Fatalf("unexpected did:key shape: %q", did)
	}

	got, err := Ed25519FromDIDKey(did)
	if err != nil {
		t.Fatalf("Ed25519FromDIDKey: %v", err)
	}
	if !got.Equal(pub) {
		t.Errorf("round trip mismatch: got %x want %x", got, pub)
	}
}

func TestDIDKeyFromEd25519_DeterministicSameKeySameDID(t *testing.T) {
	pub, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	d1, err := DIDKeyFromEd25519(pub)
	if err != nil {
		t.Fatal(err)
	}
	d2, err := DIDKeyFromEd25519(pub)
	if err != nil {
		t.Fatal(err)
	}
	if d1 != d2 {
		t.Errorf("same public key produced different DIDs: %q vs %q", d1, d2)
	}

	pub2, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	d3, err := DIDKeyFromEd25519(pub2)
	if err != nil {
		t.Fatal(err)
	}
	if d1 == d3 {
		t.Errorf("different public keys produced the same DID: %q", d1)
	}
}

func TestDIDKeyFromEd25519_RejectsWrongLength(t *testing.T) {
	if _, err := DIDKeyFromEd25519([]byte{1, 2, 3}); err == nil {
		t.Error("expected an error for a short public key")
	}
}

func TestEd25519FromDIDKey_RejectsNonDIDKey(t *testing.T) {
	cases := []types.DID{
		"did:web:example.com",
		"did:personhood:holder:deadbeef",
		"did:key:znotbase58!!!",
	}
	for _, did := range cases {
		if _, err := Ed25519FromDIDKey(did); err == nil {
			t.Errorf("Ed25519FromDIDKey(%q) should have failed", did)
		}
	}
}

func TestHolderDIDForSession_WithClientKeyProducesDIDKey(t *testing.T) {
	pub, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	did := HolderDIDForSession("session-123", pub)
	if !strings.HasPrefix(string(did), "did:key:z") {
		t.Errorf("expected a did:key DID, got %q", did)
	}
	want, err := DIDKeyFromEd25519(pub)
	if err != nil {
		t.Fatal(err)
	}
	if did != want {
		t.Errorf("HolderDIDForSession did:key mismatch: got %q want %q", did, want)
	}

	// Same key, different session -> same DID (did:key is a pure function of
	// the key, not the session).
	did2 := HolderDIDForSession("session-456", pub)
	if did2 != did {
		t.Errorf("did:key drifted across sessions for the same key: %q vs %q", did2, did)
	}
}

func TestHolderDIDForSession_WithoutClientKeyFallsBackToPlaceholder(t *testing.T) {
	did := HolderDIDForSession("session-123", nil)
	if !strings.HasPrefix(string(did), "did:personhood:holder:") {
		t.Errorf("expected the v0.1 placeholder DID, got %q", did)
	}
}

func TestNullifierBindingForHolder_NilWithoutKey(t *testing.T) {
	if b := NullifierBindingForHolder(nil); b != nil {
		t.Errorf("expected nil binding for a nil key, got %+v", b)
	}
	if b := NullifierBindingForHolder([]byte{1, 2, 3}); b != nil {
		t.Errorf("expected nil binding for a short key, got %+v", b)
	}
}

func TestNullifierBindingForHolder_DeterministicAndDistinct(t *testing.T) {
	pub1, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	pub2, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}

	b1a := NullifierBindingForHolder(pub1)
	b1b := NullifierBindingForHolder(pub1)
	b2 := NullifierBindingForHolder(pub2)

	if b1a == nil || b1b == nil || b2 == nil {
		t.Fatal("expected non-nil bindings for valid keys")
	}
	if b1a.Commitment != b1b.Commitment {
		t.Errorf("same holder key produced different commitments: %q vs %q", b1a.Commitment, b1b.Commitment)
	}
	if b1a.Commitment == b2.Commitment {
		t.Errorf("different holder keys produced the same commitment: %q", b1a.Commitment)
	}
	if b1a.Curve != "bn254" || b1a.Scheme != "pedersen-v1" {
		t.Errorf("unexpected curve/scheme: %+v", b1a)
	}
	if b1a.Commitment == "" {
		t.Error("commitment should not be empty")
	}
}
