package credential

import (
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"strings"
	"testing"
)

func newProof(t *testing.T, priv ed25519.PrivateKey, a, b string) EquivocationProof {
	t.Helper()
	da, db := sha256.Sum256([]byte(a)), sha256.Sum256([]byte(b))
	sa, err := SignSlotStatement(priv, "openline/test-chain/spend", "acct1:7", da[:])
	if err != nil {
		t.Fatal(err)
	}
	sb, err := SignSlotStatement(priv, "openline/test-chain/spend", "acct1:7", db[:])
	if err != nil {
		t.Fatal(err)
	}
	return EquivocationProof{
		Scheme:             SlotStatementScheme,
		HolderPublicKeyB64: base64.StdEncoding.EncodeToString(priv.Public().(ed25519.PublicKey)),
		Context:            "openline/test-chain/spend",
		Slot:               "acct1:7",
		Statements:         [2]SlotStatement{sa, sb},
	}
}

func TestEquivocationProof_Valid(t *testing.T) {
	pub, priv, _ := ed25519.GenerateKey(rand.Reader)
	p := newProof(t, priv, "pay alice 5", "pay bob 5")
	got, err := p.Verify()
	if err != nil {
		t.Fatalf("Verify: %v", err)
	}
	if !got.Equal(pub) {
		t.Fatal("Verify returned the wrong key")
	}
}

func TestSlotStatementMessage_Format(t *testing.T) {
	d := sha256.Sum256([]byte("x"))
	msg, err := SlotStatementMessage("ctx", "slot", d[:])
	if err != nil {
		t.Fatal(err)
	}
	want := "personhood-slot/v1\nctx\nslot\n" + "2d711642b726b04401627ca9fbac32f5c8530fb1903cc4db02258717921a4881"
	if msg != want {
		t.Fatalf("message = %q, want %q", msg, want)
	}
}

func TestEquivocationProof_Rejects(t *testing.T) {
	_, priv, _ := ed25519.GenerateKey(rand.Reader)
	_, other, _ := ed25519.GenerateKey(rand.Reader)

	cases := map[string]func(p *EquivocationProof){
		"same payload twice": func(p *EquivocationProof) { p.Statements[1] = p.Statements[0] },
		"wrong scheme":       func(p *EquivocationProof) { p.Scheme = "personhood-slot/v2" },
		"different slot": func(p *EquivocationProof) {
			// statement 0 was signed for slot acct1:7; the proof now claims acct1:8.
			p.Slot = "acct1:8"
		},
		"signature by another key": func(p *EquivocationProof) {
			d := sha256.Sum256([]byte("pay bob 5"))
			st, _ := SignSlotStatement(other, p.Context, p.Slot, d[:])
			p.Statements[1] = st
		},
		"bad public key":     func(p *EquivocationProof) { p.HolderPublicKeyB64 = "AAAA" },
		"upper-case digest":  func(p *EquivocationProof) { p.Statements[0].PayloadDigestHex = strings.ToUpper(p.Statements[0].PayloadDigestHex) },
		"newline in context": func(p *EquivocationProof) { p.Context = "a\nb" },
		"empty slot":         func(p *EquivocationProof) { p.Slot = "" },
		"garbage signature":  func(p *EquivocationProof) { p.Statements[0].SignatureB64 = "!!" },
	}
	for name, mutate := range cases {
		t.Run(name, func(t *testing.T) {
			p := newProof(t, priv, "pay alice 5", "pay bob 5")
			mutate(&p)
			if _, err := p.Verify(); !errors.Is(err, ErrEquivocationInvalid) {
				t.Fatalf("Verify = %v, want ErrEquivocationInvalid", err)
			}
		})
	}
}
