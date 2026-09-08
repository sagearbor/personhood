package fuzzyextractorselfie

import "crypto/rand"

// RandomTemplateForTesting returns TemplateBytes of cryptographically random
// data, standing in for a client's on-device face-embedding output. Real
// clients derive this from an ML model; tests (in this package, and in
// tests/ against the real running server) use random bytes as a stand-in
// "person" — mirroring SignDeviceTokenForTesting in app-attest-device and
// SignWebhookForTesting in plaid-bank-link, the repo's established pattern
// for giving other packages' tests a way to drive a method end to end
// without the real (here: on-device ML) counterpart.
func RandomTemplateForTesting() []byte {
	b := make([]byte, TemplateBytes)
	if _, err := rand.Read(b); err != nil {
		panic("fuzzy-extractor-selfie: RandomTemplateForTesting: " + err.Error())
	}
	return b
}

// NoisyTemplateForTesting returns a copy of base with exactly flipBits bits
// flipped (spread one-per-block across the first min(flipBits, numBlocks)
// repetition-code blocks, so each flipped bit is a minority vote within its
// block and Rep still corrects it) — simulating a second, genuine-but-noisy
// reading of the "same person" within Gen/Rep's error-correction tolerance.
// Panics if len(base) != TemplateBytes.
func NoisyTemplateForTesting(base []byte, flipBits int) []byte {
	if len(base) != TemplateBytes {
		panic("fuzzy-extractor-selfie: NoisyTemplateForTesting: base must be TemplateBytes long")
	}
	out := make([]byte, len(base))
	copy(out, base)
	for block := 0; block < flipBits && block < numBlocks; block++ {
		bitPos := block * BlockBits // first bit of this block
		byteIdx, bitIdx := bitPos/8, 7-(bitPos%8)
		out[byteIdx] ^= 1 << uint(bitIdx)
	}
	return out
}
