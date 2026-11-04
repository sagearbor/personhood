package icao

import (
	"bytes"
	"crypto"
	"crypto/rsa"
	"encoding/asn1"
	"errors"
	"fmt"
	"math/big"
)

// Active Authentication (ICAO 9303 Part 11, 6.1). The chip holds a private
// key that cannot be read out; its public key is EF.DG15, whose hash is in
// the signed EF.SOD. The issuer sends a fresh random challenge, the phone
// passes it to the chip (INTERNAL AUTHENTICATE), and the chip signs it.
// A copy of the chip's files cannot answer, so this is what stops a cloned
// chip. Chips without DG15 do not support it.
//
// Chip Authentication (EAC, DG14) also stops clones, but only toward the
// terminal that runs it (the phone): it yields session keys, not a
// signature, so a remote issuer cannot check it after the fact. This
// package therefore relies on Active Authentication for clone resistance.

var (
	ErrAA             = errors.New("icao: active authentication failed")
	oidActiveAuthInfo = asn1.ObjectIdentifier{2, 23, 136, 1, 1, 5}
)

// ParseDG15 reads EF.DG15 (tag 0x6F around a SubjectPublicKeyInfo).
func ParseDG15(dg15 []byte) (any, error) {
	var outer asn1.RawValue
	if _, err := asn1.Unmarshal(dg15, &outer); err != nil || outer.Class != asn1.ClassApplication || outer.Tag != 15 {
		return nil, fmt.Errorf("%w: EF.DG15 is not tag 0x6F", ErrAA)
	}
	return ParsePublicKeyInfo(outer.Bytes)
}

type securityInfo struct {
	Protocol asn1.ObjectIdentifier
	Rest     asn1.RawContent
}

type activeAuthInfo struct {
	Protocol           asn1.ObjectIdentifier
	Version            int
	SignatureAlgorithm asn1.ObjectIdentifier `asn1:"optional"`
}

// aaSignatureAlgorithm returns the ECDSA AA signature algorithm declared in
// EF.DG14 (tag 0x6E around SecurityInfos), or nil if DG14 is absent or does
// not declare one.
func aaSignatureAlgorithm(dg14 []byte) asn1.ObjectIdentifier {
	if len(dg14) == 0 {
		return nil
	}
	var outer asn1.RawValue
	if _, err := asn1.Unmarshal(dg14, &outer); err != nil || outer.Class != asn1.ClassApplication || outer.Tag != 14 {
		return nil
	}
	var set asn1.RawValue
	if _, err := asn1.Unmarshal(outer.Bytes, &set); err != nil {
		return nil
	}
	rest := set.Bytes
	for len(rest) > 0 {
		var raw asn1.RawValue
		var err error
		if rest, err = asn1.Unmarshal(rest, &raw); err != nil {
			return nil
		}
		var si securityInfo
		if _, err := asn1.Unmarshal(raw.FullBytes, &si); err != nil || !si.Protocol.Equal(oidActiveAuthInfo) {
			continue
		}
		var aai activeAuthInfo
		if _, err := asn1.Unmarshal(raw.FullBytes, &aai); err == nil {
			return aai.SignatureAlgorithm
		}
	}
	return nil
}

// VerifyActiveAuth checks the chip's response to challenge with the DG15
// key. dg14 may be nil.
func VerifyActiveAuth(dg15, dg14, challenge, response []byte) error {
	pub, err := ParseDG15(dg15)
	if err != nil {
		return err
	}
	switch k := pub.(type) {
	case *rsa.PublicKey:
		return verifyAARSA(k, challenge, response)
	case *ECPublicKey:
		return verifyAAEC(k, aaSignatureAlgorithm(dg14), challenge, response)
	}
	return fmt.Errorf("%w: unsupported DG15 key", ErrAA)
}

// verifyAARSA checks an ISO/IEC 9796-2 digital signature scheme 1
// (partial message recovery) signature: J = 0x6A || M1 || H(M1||M2) || T,
// where M2 is the challenge and T is 0xBC (SHA-1) or (hash id, 0xCC).
func verifyAARSA(k *rsa.PublicKey, challenge, sig []byte) error {
	n := k.N
	kLen := (n.BitLen() + 7) / 8
	s := new(big.Int).SetBytes(sig)
	if s.Sign() <= 0 || s.Cmp(n) >= 0 {
		return fmt.Errorf("%w: signature out of range", ErrAA)
	}
	j := new(big.Int).Exp(s, big.NewInt(int64(k.E)), n)
	// The signer may have sent min(J^d, n - J^d); J ends in nibble 0xC.
	if j.Bit(0) != 0 || j.Bit(1) != 0 || j.Bit(2) != 1 || j.Bit(3) != 1 {
		j.Sub(n, j)
	}
	jb := j.FillBytes(make([]byte, kLen))
	// A modulus whose top byte is small leaves a leading zero byte.
	for len(jb) > 0 && jb[0] == 0 {
		jb = jb[1:]
	}
	if len(jb) < 2 || jb[0] != 0x6A {
		return fmt.Errorf("%w: bad 9796-2 header", ErrAA)
	}
	var h crypto.Hash
	var tLen int
	switch {
	case jb[len(jb)-1] == 0xBC:
		h, tLen = crypto.SHA1, 1
	case jb[len(jb)-1] == 0xCC:
		tLen = 2
		switch jb[len(jb)-2] {
		case 0x33:
			h = crypto.SHA1
		case 0x34:
			h = crypto.SHA256
		case 0x35:
			h = crypto.SHA512
		case 0x36:
			h = crypto.SHA384
		case 0x38:
			h = crypto.SHA224
		default:
			return fmt.Errorf("%w: unknown 9796-2 hash id", ErrAA)
		}
	default:
		return fmt.Errorf("%w: bad 9796-2 trailer", ErrAA)
	}
	hLen := h.Size()
	if len(jb) < 1+hLen+tLen {
		return fmt.Errorf("%w: short 9796-2 block", ErrAA)
	}
	m1 := jb[1 : len(jb)-hLen-tLen]
	got := jb[len(jb)-hLen-tLen : len(jb)-tLen]
	want := digest(h, append(append([]byte(nil), m1...), challenge...))
	if !bytes.Equal(got, want) {
		return fmt.Errorf("%w: signature does not cover the challenge", ErrAA)
	}
	return nil
}

// verifyAAEC checks an ECDSA AA signature. DG14 names the hash; when it
// does not, the common hashes are tried (trying several cannot make a
// signature by another key verify).
func verifyAAEC(k *ECPublicKey, sigAlg asn1.ObjectIdentifier, challenge, sig []byte) error {
	r, s, err := parseECDSASignature(sig)
	if err != nil {
		return fmt.Errorf("%w: %v", ErrAA, err)
	}
	hashes := []crypto.Hash{crypto.SHA1, crypto.SHA224, crypto.SHA256, crypto.SHA384, crypto.SHA512}
	if sigAlg != nil {
		switch {
		case sigAlg.Equal(oidECDSAPlainSHA1), sigAlg.Equal(oidECDSAWithSHA1):
			hashes = []crypto.Hash{crypto.SHA1}
		case sigAlg.Equal(oidECDSAPlainSHA224), sigAlg.Equal(oidECDSAWithSHA224):
			hashes = []crypto.Hash{crypto.SHA224}
		case sigAlg.Equal(oidECDSAPlainSHA256), sigAlg.Equal(oidECDSAWithSHA256):
			hashes = []crypto.Hash{crypto.SHA256}
		case sigAlg.Equal(oidECDSAPlainSHA384), sigAlg.Equal(oidECDSAWithSHA384):
			hashes = []crypto.Hash{crypto.SHA384}
		case sigAlg.Equal(oidECDSAPlainSHA512), sigAlg.Equal(oidECDSAWithSHA512):
			hashes = []crypto.Hash{crypto.SHA512}
		}
	}
	for _, h := range hashes {
		if verifyECDSA(k, digest(h, challenge), r, s) {
			return nil
		}
	}
	return fmt.Errorf("%w: ECDSA signature invalid", ErrAA)
}
