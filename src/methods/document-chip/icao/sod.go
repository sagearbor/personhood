package icao

import (
	"bytes"
	"crypto"
	"crypto/x509/pkix"
	"encoding/asn1"
	"errors"
	"fmt"
)

// Passive authentication (ICAO 9303 Part 11, 5.1): EF.SOD is a CMS
// SignedData over an LDSSecurityObject listing the hash of every data group.
// The document signer certificate inside it must chain to a trusted CSCA,
// and the data groups the reader presents must hash to the listed values.
//
// What it proves: the data groups were written by a state that holds that
// CSCA's key. What it does NOT prove: that they were read from the original
// chip. A copy of the files (a "dump") passes passive authentication; only
// Active Authentication or Chip Authentication stops a cloned chip.

var oidLDSSecurityObject = asn1.ObjectIdentifier{2, 23, 136, 1, 1, 1}

type ldsSecurityObject struct {
	Version  int
	HashAlg  pkix.AlgorithmIdentifier
	DGHashes []dataGroupHash
	Rest     asn1.RawContent `asn1:"optional"`
}

type dataGroupHash struct {
	Number int
	Hash   []byte
}

// Failure kinds, for mapping to error reasons.
var (
	ErrSOD          = errors.New("icao: invalid EF.SOD")
	ErrHashMismatch = errors.New("icao: data group hash does not match EF.SOD")
)

// SOD is a parsed EF.SOD.
type SOD struct {
	msg      *SignedMessage
	hashAlg  crypto.Hash
	dgHashes map[int][]byte
}

// ParseSOD reads EF.SOD (tag 0x77 around a ContentInfo).
func ParseSOD(sod []byte) (*SOD, error) {
	var outer asn1.RawValue
	if _, err := asn1.Unmarshal(sod, &outer); err != nil {
		return nil, fmt.Errorf("%w: %v", ErrSOD, err)
	}
	if outer.Class != asn1.ClassApplication || outer.Tag != 23 {
		return nil, fmt.Errorf("%w: not tag 0x77", ErrSOD)
	}
	msg, err := ParseSignedData(outer.Bytes)
	if err != nil {
		return nil, fmt.Errorf("%w: %v", ErrSOD, err)
	}
	if !msg.EContentType.Equal(oidLDSSecurityObject) {
		return nil, fmt.Errorf("%w: content type %s", ErrSOD, msg.EContentType)
	}
	var lds ldsSecurityObject
	if _, err := asn1.Unmarshal(msg.EContent, &lds); err != nil {
		return nil, fmt.Errorf("%w: LDSSecurityObject: %v", ErrSOD, err)
	}
	h, err := HashForOID(lds.HashAlg.Algorithm)
	if err != nil {
		return nil, err
	}
	s := &SOD{msg: msg, hashAlg: h, dgHashes: map[int][]byte{}}
	for _, dg := range lds.DGHashes {
		if dg.Number < 1 || dg.Number > 16 {
			return nil, fmt.Errorf("%w: data group number %d", ErrSOD, dg.Number)
		}
		s.dgHashes[dg.Number] = dg.Hash
	}
	return s, nil
}

// HasDataGroup reports whether the SOD lists data group n.
func (s *SOD) HasDataGroup(n int) bool { _, ok := s.dgHashes[n]; return ok }

// CheckDataGroup checks that the presented EF.DGn file hashes to the value
// the SOD lists for it.
func (s *SOD) CheckDataGroup(n int, file []byte) error {
	want, ok := s.dgHashes[n]
	if !ok {
		return fmt.Errorf("%w: DG%d is not listed", ErrHashMismatch, n)
	}
	if !bytes.Equal(digest(s.hashAlg, file), want) {
		return fmt.Errorf("%w: DG%d", ErrHashMismatch, n)
	}
	return nil
}

// PassiveResult is what a successful signature check established.
type PassiveResult struct {
	// Country is the trusted CSCA's country (ISO 3166-1 alpha-2). It, not
	// the DG1 issuing state, namespaces the document number: a state can
	// only ever mint document keys inside its own namespace.
	Country string
	DSC     *Certificate
	CSCA    *Certificate
}

// VerifySignature checks the SOD signature and the signer's chain to trust.
func (s *SOD) VerifySignature(trust *TrustStore) (*PassiveResult, error) {
	dsc, err := s.msg.SignerCertificate()
	if err != nil {
		return nil, fmt.Errorf("%w: %v", ErrSOD, err)
	}
	csca, err := trust.Chain(dsc)
	if err != nil {
		return nil, err
	}
	if err := s.msg.VerifySigner(dsc); err != nil {
		if errors.Is(err, ErrUnsupportedAlgorithm) {
			return nil, err
		}
		return nil, fmt.Errorf("%w: signature: %v", ErrSOD, err)
	}
	country := csca.Country
	if country == "" {
		country = dsc.Country
	}
	if country == "" {
		return nil, fmt.Errorf("%w: CSCA has no country", ErrUntrusted)
	}
	return &PassiveResult{Country: country, DSC: dsc, CSCA: csca}, nil
}
