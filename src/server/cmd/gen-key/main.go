// Command gen-key prints a freshly generated Ed25519 private-key seed in the
// base64url (no padding) form ISSUER_ED25519_SK_B64 expects.
//
// Usage:
//
//	go run ./src/server/cmd/gen-key
//	# copy the printed value into .env.local under ISSUER_ED25519_SK_B64=...
//
// The seed is the 32-byte input ed25519.NewKeyFromSeed expands into a full
// 64-byte private key; both forms are accepted by the server at load time.
package main

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"fmt"
	"io"
	"os"
)

func main() {
	seed := make([]byte, ed25519.SeedSize)
	if _, err := io.ReadFull(rand.Reader, seed); err != nil {
		fmt.Fprintf(os.Stderr, "gen-key: %v\n", err)
		os.Exit(1)
	}
	priv := ed25519.NewKeyFromSeed(seed)
	pub := priv.Public().(ed25519.PublicKey)

	fmt.Fprintln(os.Stderr, "-- Personhood issuer key --")
	fmt.Fprintln(os.Stderr, "Add the line below to .env.local (gitignored):")
	fmt.Fprintln(os.Stderr)
	fmt.Printf("ISSUER_ED25519_SK_B64=%s\n", base64.RawURLEncoding.EncodeToString(seed))
	fmt.Fprintln(os.Stderr)
	fmt.Fprintf(os.Stderr, "Public key (base64url): %s\n", base64.RawURLEncoding.EncodeToString(pub))
}
