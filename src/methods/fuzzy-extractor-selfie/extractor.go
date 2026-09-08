// Package fuzzyextractorselfie implements the fuzzy-extractor cryptographic
// primitive this method is built on: a Juels-Wattenberg-style "fuzzy
// commitment" scheme over a fixed-length binarized biometric template.
//
// A fuzzy extractor solves a specific problem: two readings of the same
// person's face (or iris, fingerprint, etc.) are never bit-identical — the
// raw template is *noisy* — yet we want a STABLE secret that only a genuine
// re-reading of the same person's face can reproduce, without ever storing
// the raw template (or anything that trivially reverses to it) on the
// server. That's what makes this method "no central biometric DB": the
// server only ever sees XOR-masked helper data and one-way hashes.
//
// Construction (Gen / Rep), following Juels & Wattenberg (1999) "A Fuzzy
// Commitment Scheme":
//
//	Gen(w):
//	  seed  := random NumSeedBits bits
//	  c     := repeat each seed bit BlockBits times      (the "codeword")
//	  helper:= w XOR c                                   (public, safe to store)
//	  key   := SHA-256(domainTag || seed)                (the derived secret)
//	  return helper, key
//
//	Rep(w', helper):
//	  x        := w' XOR helper                          (= c XOR (w XOR w'))
//	  seed'    := per-block MAJORITY VOTE decode of x     (corrects bit noise)
//	  c'       := repeat each seed' bit BlockBits times
//	  residual := HammingDistance(x, c')
//	  if residual > MaxResidualBits: FAIL ("not a match")
//	  key'     := SHA-256(domainTag || seed')
//	  return key', true
//
// If w' is a noisy-but-genuine re-reading of the SAME w (few bits differ),
// each BlockBits-wide block still has a majority of un-flipped bits, so
// seed' decodes to exactly seed and key' == key: a perfect, stable match.
// If w' comes from an unrelated person's biometric (~50% of bits differ from
// any given w), the per-block majority vote is close to a coin flip, seed'
// is unrelated to seed, and — critically — the residual Hamming distance
// between x and its "nearest" codeword stays far above MaxResidualBits, so
// Rep correctly reports no match instead of quietly returning a wrong key.
//
// v0.1 scope note: a simple repetition code is used instead of a proper
// linear/Reed-Solomon code. A repetition code's correction capability is
// vulnerable to adversarial *clustering* of errors within one block (the
// residual-distance check below still catches this, at the cost of some
// legitimate near-matches with clustered sensor noise being rejected). This
// mirrors the project's existing "v0.1 stub crypto, real construction, not
// production-hardened" convention (see src/policy/nullifier.go and
// src/server/did.go's NullifierBindingForHolder for the same disclosure
// pattern elsewhere in this repo). A production version should swap in a
// BCH/Reed-Solomon secure sketch behind the same Gen/Rep call shape.
package fuzzyextractorselfie

import (
	"crypto/rand"
	"crypto/sha256"
	"errors"
	"fmt"
)

const (
	// TemplateBytes is the fixed length of the binarized biometric feature
	// vector this method accepts, e.g. a sign-thresholded face embedding
	// computed on-device. 256 bits is a common binarized-embedding size.
	TemplateBytes = 32
	templateBits  = TemplateBytes * 8 // 256

	// BlockBits is the repetition-code block size. Odd, so per-block
	// majority vote never ties. Correction capacity per block is
	// (BlockBits-1)/2 = 7 flipped bits.
	BlockBits = 15

	// numBlocks*BlockBits must be <= templateBits; the remaining bits are
	// ignored (dropped) rather than complicating the code with a partial
	// final block.
	numBlocks = templateBits / BlockBits // 17
	usedBits  = numBlocks * BlockBits    // 255 of 256 template bits used

	// seedBytes is ceil(numBlocks/8) bytes — enough to hold one bit per
	// block.
	seedBytes = (numBlocks + 7) / 8

	// MaxResidualBits is the total Hamming-distance budget, between the
	// masked input and its nearest codeword, that Rep still accepts as a
	// match. Set to 25% of usedBits: generous enough to absorb realistic
	// sensor/lighting noise between two genuine readings of the same person,
	// while (per the package doc) staying far below the ~50% distance an
	// unrelated person's biometric produces.
	MaxResidualBits = usedBits / 4

	// domainTag namespaces the derived key so it can never collide with a
	// hash of the same seed computed for an unrelated purpose elsewhere in
	// the codebase.
	domainTag = "personhood-fuzzy-extractor-v1"
)

// ErrBadTemplateLength is returned when a template is not exactly
// TemplateBytes long.
var ErrBadTemplateLength = fmt.Errorf("fuzzy-extractor-selfie: template must be exactly %d bytes", TemplateBytes)

// Commitment is a derived, one-way, non-reversible identity commitment: the
// output of SHA-256(domainTag || seed). Equal Commitments mean Gen/Rep
// recovered the same underlying seed, which — by construction — only happens
// for a genuine re-reading of the same biometric (see package doc).
type Commitment [sha256.Size]byte

// Hex returns the lowercase hex encoding of c, the form stored on the
// credential's AttestationDigest and in the accumulator.
func (c Commitment) Hex() string {
	return fmt.Sprintf("%x", c[:])
}

// Gen runs the fuzzy-extractor generation step over a fresh biometric
// template. It returns public helper data (safe to store; XOR-masked, not
// the raw template) and the derived Commitment. Every call picks fresh
// randomness, so calling Gen twice on the identical template yields two
// unrelated helper/commitment pairs — recovering a stable, repeatable
// Commitment for the "same person" requires Rep against previously stored
// helper data (see Accumulator.FindDuplicate).
func Gen(template []byte) (helper []byte, commitment Commitment, err error) {
	if len(template) != TemplateBytes {
		return nil, Commitment{}, ErrBadTemplateLength
	}
	seed := make([]byte, seedBytes)
	if _, err := rand.Read(seed); err != nil {
		return nil, Commitment{}, fmt.Errorf("fuzzy-extractor-selfie: generate seed: %w", err)
	}
	// seedBytes*8 may exceed numBlocks (one bit is stored per block; the
	// buffer is byte-aligned). majorityDecode only ever sets bits
	// [0, numBlocks) and leaves the rest at zero, so the padding bits here
	// MUST also be zeroed — otherwise a genuine Rep on the identical
	// template would decode a seed whose meaningful bits match but whose
	// random padding bits don't, producing a different SHA-256 commitment
	// than Gen computed and breaking the entire fuzzy-match property.
	clearPaddingBits(seed)
	codeword := expandSeed(seed)
	helper = xorBytes(template[:usedBits/8+boolToInt(usedBits%8 != 0)], codeword)
	return helper, commitmentFromSeed(seed), nil
}

// Rep runs the fuzzy-extractor reproduction step: given a new (possibly
// noisy) template and previously stored helper data, it attempts to recover
// the same Commitment Gen produced for the original template. ok is false
// (with a zero Commitment) when the residual Hamming distance exceeds
// MaxResidualBits — i.e. template is not a close-enough match to whatever
// biometric produced helper.
func Rep(template []byte, helper []byte) (commitment Commitment, ok bool, err error) {
	if len(template) != TemplateBytes {
		return Commitment{}, false, ErrBadTemplateLength
	}
	usedByteLen := usedBits/8 + boolToInt(usedBits%8 != 0)
	if len(helper) != usedByteLen {
		return Commitment{}, false, fmt.Errorf("fuzzy-extractor-selfie: helper data must be %d bytes, got %d", usedByteLen, len(helper))
	}
	x := xorBytes(template[:usedByteLen], helper)
	seedGuess := majorityDecode(x)
	codewordGuess := expandSeed(seedGuess)
	residual := hammingDistance(x, codewordGuess)
	if residual > MaxResidualBits {
		return Commitment{}, false, nil
	}
	return commitmentFromSeed(seedGuess), true, nil
}

func commitmentFromSeed(seed []byte) Commitment {
	h := sha256.New()
	h.Write([]byte(domainTag))
	h.Write(seed)
	var c Commitment
	copy(c[:], h.Sum(nil))
	return c
}

// expandSeed repeats each of the numBlocks bits in seed BlockBits times,
// producing a usedBits-bit (packed into bytes, MSB-first per byte) codeword.
func expandSeed(seed []byte) []byte {
	out := make([]byte, usedBits/8+boolToInt(usedBits%8 != 0))
	bitPos := 0
	for block := 0; block < numBlocks; block++ {
		bit := getBit(seed, block)
		for i := 0; i < BlockBits; i++ {
			setBit(out, bitPos, bit)
			bitPos++
		}
	}
	return out
}

// majorityDecode reads x (usedBits bits) BlockBits at a time and returns the
// numBlocks-bit majority-vote decode, one bit per block. BlockBits is odd so
// there is never a tie.
func majorityDecode(x []byte) []byte {
	seed := make([]byte, seedBytes)
	bitPos := 0
	for block := 0; block < numBlocks; block++ {
		ones := 0
		for i := 0; i < BlockBits; i++ {
			if getBit(x, bitPos) == 1 {
				ones++
			}
			bitPos++
		}
		if ones*2 > BlockBits {
			setBit(seed, block, 1)
		}
	}
	return seed
}

// clearPaddingBits zeroes seed's bit positions [numBlocks, seedBytes*8),
// the padding beyond the numBlocks bits expandSeed/majorityDecode actually
// use. See the comment at Gen's call site for why this matters.
func clearPaddingBits(seed []byte) {
	for i := numBlocks; i < seedBytes*8; i++ {
		setBit(seed, i, 0)
	}
}

func getBit(b []byte, i int) byte {
	byteIdx, bitIdx := i/8, 7-(i%8)
	if byteIdx >= len(b) {
		return 0
	}
	return (b[byteIdx] >> uint(bitIdx)) & 1
}

func setBit(b []byte, i int, v byte) {
	byteIdx, bitIdx := i/8, 7-(i%8)
	if byteIdx >= len(b) {
		return
	}
	if v == 1 {
		b[byteIdx] |= 1 << uint(bitIdx)
	} else {
		b[byteIdx] &^= 1 << uint(bitIdx)
	}
}

func xorBytes(a, b []byte) []byte {
	n := len(a)
	if len(b) < n {
		n = len(b)
	}
	out := make([]byte, n)
	for i := 0; i < n; i++ {
		out[i] = a[i] ^ b[i]
	}
	return out
}

func hammingDistance(a, b []byte) int {
	x := xorBytes(a, b)
	dist := 0
	for _, by := range x {
		for by != 0 {
			dist++
			by &= by - 1
		}
	}
	return dist
}

func boolToInt(v bool) int {
	if v {
		return 1
	}
	return 0
}

// ErrNoMatch is a sentinel some callers may find convenient; Rep itself
// signals "no match" via ok=false rather than this error (see doc comment),
// so this exists only for callers that prefer an error-returning wrapper.
var ErrNoMatch = errors.New("fuzzy-extractor-selfie: template does not match helper data within tolerance")
