package icao

import (
	"bytes"
	"crypto/x509/pkix"
	"encoding/asn1"
	"errors"
	"fmt"
	"math/big"
)

// The slice of CMS (RFC 5652) SignedData that EF.SOD and CSCA master lists
// use: one signer, the signer's certificate embedded, signed attributes.

var (
	oidSignedData       = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 7, 2}
	oidAttrContentType  = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 9, 3}
	oidAttrMessageDigst = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 9, 4}
)

type contentInfo struct {
	ContentType asn1.ObjectIdentifier
	Content     asn1.RawValue `asn1:"explicit,tag:0"`
}

type signedData struct {
	Version          int
	DigestAlgorithms asn1.RawValue
	EncapContentInfo encapContentInfo
	Certificates     asn1.RawValue `asn1:"optional,tag:0"`
	CRLs             asn1.RawValue `asn1:"optional,tag:1"`
	SignerInfos      []signerInfo  `asn1:"set"`
}

type encapContentInfo struct {
	EContentType asn1.ObjectIdentifier
	EContent     asn1.RawValue `asn1:"explicit,optional,tag:0"`
}

type signerInfo struct {
	Version            int
	SID                asn1.RawValue
	DigestAlgorithm    pkix.AlgorithmIdentifier
	SignedAttrs        asn1.RawValue `asn1:"optional,tag:0"`
	SignatureAlgorithm pkix.AlgorithmIdentifier
	Signature          []byte
	UnsignedAttrs      asn1.RawValue `asn1:"optional,tag:1"`
}

type attribute struct {
	Type   asn1.ObjectIdentifier
	Values asn1.RawValue `asn1:"set"`
}

type issuerAndSerial struct {
	Issuer asn1.RawValue
	Serial *big.Int
}

// SignedMessage is a verified-structure (not yet verified-signature) CMS
// SignedData with exactly one signer.
type SignedMessage struct {
	EContentType asn1.ObjectIdentifier
	EContent     []byte
	Certificates []*Certificate
	signer       signerInfo
}

// ParseSignedData reads a DER ContentInfo holding SignedData.
func ParseSignedData(der []byte) (*SignedMessage, error) {
	var ci contentInfo
	if _, err := asn1.Unmarshal(der, &ci); err != nil {
		return nil, fmt.Errorf("icao: CMS ContentInfo: %w", err)
	}
	if !ci.ContentType.Equal(oidSignedData) {
		return nil, fmt.Errorf("icao: CMS content type %s is not SignedData", ci.ContentType)
	}
	var sd signedData
	if _, err := asn1.Unmarshal(ci.Content.Bytes, &sd); err != nil {
		return nil, fmt.Errorf("icao: CMS SignedData: %w", err)
	}
	if len(sd.SignerInfos) != 1 {
		return nil, fmt.Errorf("icao: CMS SignedData has %d signers, want 1", len(sd.SignerInfos))
	}
	// eContent is an OCTET STRING inside [0].
	var econtent []byte
	if _, err := asn1.Unmarshal(sd.EncapContentInfo.EContent.Bytes, &econtent); err != nil {
		return nil, fmt.Errorf("icao: CMS eContent: %w", err)
	}
	msg := &SignedMessage{
		EContentType: sd.EncapContentInfo.EContentType,
		EContent:     econtent,
		signer:       sd.SignerInfos[0],
	}
	rest := sd.Certificates.Bytes
	for len(rest) > 0 {
		var raw asn1.RawValue
		var err error
		rest, err = asn1.Unmarshal(rest, &raw)
		if err != nil {
			return nil, fmt.Errorf("icao: CMS certificates: %w", err)
		}
		c, err := ParseCertificate(raw.FullBytes)
		if err != nil {
			return nil, err
		}
		msg.Certificates = append(msg.Certificates, c)
	}
	return msg, nil
}

// SignerCertificate returns the embedded certificate that the signer
// identifier names.
func (m *SignedMessage) SignerCertificate() (*Certificate, error) {
	sid := m.signer.SID
	for _, c := range m.Certificates {
		switch {
		case sid.Class == asn1.ClassUniversal && sid.Tag == asn1.TagSequence:
			var ias issuerAndSerial
			if _, err := asn1.Unmarshal(sid.FullBytes, &ias); err != nil {
				return nil, fmt.Errorf("icao: CMS signer id: %w", err)
			}
			if ias.Serial != nil && ias.Serial.Cmp(c.SerialNumber) == 0 && sameName(ias.Issuer.FullBytes, c.RawIssuer) {
				return c, nil
			}
		case sid.Class == asn1.ClassContextSpecific && sid.Tag == 0:
			if len(c.SubjectKeyID) > 0 && bytes.Equal(sid.Bytes, c.SubjectKeyID) {
				return c, nil
			}
		}
	}
	return nil, errors.New("icao: signer certificate not embedded")
}

// VerifySigner checks the signer's signature with signerCert's key,
// including the messageDigest and contentType signed attributes.
func (m *SignedMessage) VerifySigner(signerCert *Certificate) error {
	si := m.signer
	if len(si.SignedAttrs.FullBytes) == 0 {
		return VerifySignature(si.SignatureAlgorithm, si.DigestAlgorithm, signerCert.PublicKey, m.EContent, si.Signature)
	}
	h, err := HashForOID(si.DigestAlgorithm.Algorithm)
	if err != nil {
		return err
	}
	var gotDigest []byte
	var gotType asn1.ObjectIdentifier
	rest := si.SignedAttrs.Bytes
	for len(rest) > 0 {
		var a attribute
		if rest, err = asn1.Unmarshal(rest, &a); err != nil {
			return fmt.Errorf("icao: CMS signed attributes: %w", err)
		}
		switch {
		case a.Type.Equal(oidAttrMessageDigst):
			if _, err := asn1.Unmarshal(a.Values.Bytes, &gotDigest); err != nil {
				return fmt.Errorf("icao: CMS messageDigest: %w", err)
			}
		case a.Type.Equal(oidAttrContentType):
			if _, err := asn1.Unmarshal(a.Values.Bytes, &gotType); err != nil {
				return fmt.Errorf("icao: CMS contentType: %w", err)
			}
		}
	}
	if gotDigest == nil || !bytes.Equal(gotDigest, digest(h, m.EContent)) {
		return errors.New("icao: CMS messageDigest does not match the content")
	}
	if gotType != nil && !gotType.Equal(m.EContentType) {
		return errors.New("icao: CMS contentType attribute does not match the content")
	}
	// The signature covers the attributes DER-encoded as a SET OF (tag
	// 0x31), not with the [0] IMPLICIT tag they carry in SignerInfo.
	signed := append([]byte(nil), si.SignedAttrs.FullBytes...)
	signed[0] = 0x31
	return VerifySignature(si.SignatureAlgorithm, si.DigestAlgorithm, signerCert.PublicKey, signed, si.Signature)
}
