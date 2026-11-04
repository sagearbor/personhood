package icao

import (
	"bytes"
	"crypto"
	"crypto/rsa"
	"crypto/sha1" //nolint:gosec // ICAO 9303 still allows SHA-1 in older documents
	"crypto/sha256"
	"crypto/sha512"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"errors"
	"fmt"
	"hash"
	"math/big"
	"strings"
	"time"
)

// A minimal X.509 reader for the ePassport PKI.
//
// crypto/x509 refuses certificates whose EC key uses explicit curve
// parameters or a brainpool curve, which is a large share of CSCA and
// document signer certificates. This reader keeps only what passive
// authentication needs: the raw TBS bytes and signature, names, key ids,
// validity and the public key (RSA, or EC on any prime curve).

// ErrUnsupportedAlgorithm is wrapped by errors for algorithms this package
// does not implement. The caller reports it as "signature_unsupported", which
// sends the person to another path rather than calling the document fake.
var ErrUnsupportedAlgorithm = errors.New("icao: unsupported algorithm")

// Certificate is a parsed X.509 certificate.
type Certificate struct {
	Raw          []byte
	RawTBS       []byte
	RawSubject   []byte
	RawIssuer    []byte
	SerialNumber *big.Int
	SigAlg       pkix.AlgorithmIdentifier
	Signature    []byte
	NotBefore    time.Time
	NotAfter     time.Time
	SubjectKeyID []byte
	AuthKeyID    []byte
	// Country is the subject's countryName (ISO 3166-1 alpha-2, upper case),
	// or "" if absent.
	Country string
	// PublicKey is *rsa.PublicKey or *ECPublicKey. For an EC key whose
	// parameters are inherited from the issuer it is an *ECPublicKey with a
	// nil Curve until resolveInherited fills it.
	PublicKey any
	rawPoint  []byte
}

type rawCertificate struct {
	TBS    asn1.RawValue
	SigAlg pkix.AlgorithmIdentifier
	Sig    asn1.BitString
}

type rawTBS struct {
	Raw        asn1.RawContent
	Version    int `asn1:"optional,explicit,default:0,tag:0"`
	Serial     *big.Int
	SigAlg     pkix.AlgorithmIdentifier
	Issuer     asn1.RawValue
	Validity   rawValidity
	Subject    asn1.RawValue
	SPKI       rawSPKI
	IssuerUID  asn1.BitString   `asn1:"optional,tag:1"`
	SubjectUID asn1.BitString   `asn1:"optional,tag:2"`
	Extensions []pkix.Extension `asn1:"optional,explicit,tag:3"`
}

type rawValidity struct {
	NotBefore, NotAfter time.Time
}

type rawSPKI struct {
	Raw       asn1.RawContent
	Algorithm pkix.AlgorithmIdentifier
	Key       asn1.BitString
}

var (
	oidRSAEncryption = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 1, 1}
	oidRSAPSS        = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 1, 10}
	oidECPublicKey   = asn1.ObjectIdentifier{1, 2, 840, 10045, 2, 1}
	oidCountryName   = asn1.ObjectIdentifier{2, 5, 4, 6}
	oidExtSKI        = asn1.ObjectIdentifier{2, 5, 29, 14}
	oidExtAKI        = asn1.ObjectIdentifier{2, 5, 29, 35}
)

// ParseCertificate reads one DER certificate.
func ParseCertificate(der []byte) (*Certificate, error) {
	var rc rawCertificate
	rest, err := asn1.Unmarshal(der, &rc)
	if err != nil {
		return nil, fmt.Errorf("icao: certificate: %w", err)
	}
	if len(rest) != 0 {
		return nil, errors.New("icao: certificate: trailing data")
	}
	var tbs rawTBS
	if _, err := asn1.Unmarshal(rc.TBS.FullBytes, &tbs); err != nil {
		return nil, fmt.Errorf("icao: certificate TBS: %w", err)
	}
	c := &Certificate{
		Raw:          der[:len(der)-len(rest)],
		RawTBS:       rc.TBS.FullBytes,
		RawSubject:   tbs.Subject.FullBytes,
		RawIssuer:    tbs.Issuer.FullBytes,
		SerialNumber: tbs.Serial,
		SigAlg:       rc.SigAlg,
		Signature:    rc.Sig.RightAlign(),
		NotBefore:    tbs.Validity.NotBefore,
		NotAfter:     tbs.Validity.NotAfter,
		Country:      countryOf(tbs.Subject.FullBytes),
	}
	for _, e := range tbs.Extensions {
		switch {
		case e.Id.Equal(oidExtSKI):
			var ski []byte
			if _, err := asn1.Unmarshal(e.Value, &ski); err == nil {
				c.SubjectKeyID = ski
			}
		case e.Id.Equal(oidExtAKI):
			var aki struct {
				KeyID []byte `asn1:"optional,tag:0"`
			}
			if _, err := asn1.Unmarshal(e.Value, &aki); err == nil {
				c.AuthKeyID = aki.KeyID
			}
		}
	}
	pub, point, err := parsePublicKey(tbs.SPKI)
	if err != nil {
		return nil, err
	}
	c.PublicKey, c.rawPoint = pub, point
	return c, nil
}

// ParsePublicKeyInfo reads a DER SubjectPublicKeyInfo (EF.DG15's content).
func ParsePublicKeyInfo(der []byte) (any, error) {
	var spki rawSPKI
	if _, err := asn1.Unmarshal(der, &spki); err != nil {
		return nil, fmt.Errorf("icao: public key info: %w", err)
	}
	pub, _, err := parsePublicKey(spki)
	if err != nil {
		return nil, err
	}
	if ec, ok := pub.(*ECPublicKey); ok && ec.Curve == nil {
		return nil, errors.New("icao: EC public key without curve parameters")
	}
	return pub, nil
}

func parsePublicKey(spki rawSPKI) (any, []byte, error) {
	alg := spki.Algorithm.Algorithm
	switch {
	case alg.Equal(oidRSAEncryption), alg.Equal(oidRSAPSS):
		k, err := x509.ParsePKCS1PublicKey(spki.Key.RightAlign())
		if err != nil {
			return nil, nil, fmt.Errorf("icao: RSA public key: %w", err)
		}
		return k, nil, nil
	case alg.Equal(oidECPublicKey):
		curve, err := parseECParams(spki.Algorithm.Parameters.FullBytes)
		if err != nil {
			return nil, nil, err
		}
		pt := spki.Key.RightAlign()
		if curve == nil {
			return &ECPublicKey{}, pt, nil
		}
		x, y, err := curve.decodePoint(pt)
		if err != nil {
			return nil, nil, fmt.Errorf("icao: EC public key: %w", err)
		}
		return &ECPublicKey{Curve: curve, X: x, Y: y}, nil, nil
	default:
		return nil, nil, fmt.Errorf("%w: public key algorithm %s", ErrUnsupportedAlgorithm, alg)
	}
}

// resolveInherited fills an EC key whose parameters are inherited from the
// issuer's key (implicitCA).
func (c *Certificate) resolveInherited(issuer *Certificate) error {
	ec, ok := c.PublicKey.(*ECPublicKey)
	if !ok || ec.Curve != nil {
		return nil
	}
	iec, ok := issuer.PublicKey.(*ECPublicKey)
	if !ok || iec.Curve == nil {
		return errors.New("icao: EC key inherits parameters from a non-EC issuer")
	}
	x, y, err := iec.Curve.decodePoint(c.rawPoint)
	if err != nil {
		return fmt.Errorf("icao: EC public key: %w", err)
	}
	c.PublicKey = &ECPublicKey{Curve: iec.Curve, X: x, Y: y}
	return nil
}

func countryOf(rawName []byte) string {
	var rdns pkix.RDNSequence
	if _, err := asn1.Unmarshal(rawName, &rdns); err != nil {
		return ""
	}
	for _, set := range rdns {
		for _, atv := range set {
			if atv.Type.Equal(oidCountryName) {
				if s, ok := atv.Value.(string); ok {
					return strings.ToUpper(strings.TrimSpace(s))
				}
			}
		}
	}
	return ""
}

// normalizedName is a loose, comparable form of a Name, for matching an
// issuer to a subject whose string types differ (PrintableString vs
// UTF8String) between the two certificates, which happens in the wild.
func normalizedName(rawName []byte) string {
	var rdns pkix.RDNSequence
	if _, err := asn1.Unmarshal(rawName, &rdns); err != nil {
		return ""
	}
	var b strings.Builder
	for _, set := range rdns {
		for _, atv := range set {
			b.WriteString(atv.Type.String())
			b.WriteByte('=')
			b.WriteString(strings.ToLower(strings.TrimSpace(fmt.Sprint(atv.Value))))
			b.WriteByte(';')
		}
	}
	return b.String()
}

// sameName reports whether two encoded Names denote the same entity.
func sameName(a, b []byte) bool {
	if bytes.Equal(a, b) {
		return true
	}
	na := normalizedName(a)
	return na != "" && na == normalizedName(b)
}

// CheckSignatureFrom verifies that issuer signed c.
func (c *Certificate) CheckSignatureFrom(issuer *Certificate) error {
	if err := c.resolveInherited(issuer); err != nil {
		return err
	}
	return VerifySignature(c.SigAlg, pkix.AlgorithmIdentifier{}, issuer.PublicKey, c.RawTBS, c.Signature)
}

// Signature algorithm OIDs seen in ICAO 9303 documents.
var (
	oidSHA1WithRSA   = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 1, 5}
	oidSHA224WithRSA = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 1, 14}
	oidSHA256WithRSA = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 1, 11}
	oidSHA384WithRSA = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 1, 12}
	oidSHA512WithRSA = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 1, 13}

	oidECDSAWithSHA1   = asn1.ObjectIdentifier{1, 2, 840, 10045, 4, 1}
	oidECDSAWithSHA224 = asn1.ObjectIdentifier{1, 2, 840, 10045, 4, 3, 1}
	oidECDSAWithSHA256 = asn1.ObjectIdentifier{1, 2, 840, 10045, 4, 3, 2}
	oidECDSAWithSHA384 = asn1.ObjectIdentifier{1, 2, 840, 10045, 4, 3, 3}
	oidECDSAWithSHA512 = asn1.ObjectIdentifier{1, 2, 840, 10045, 4, 3, 4}

	// BSI TR-03111 "ecdsa-plain-signatures": r||s, not DER.
	oidECDSAPlainSHA1   = asn1.ObjectIdentifier{0, 4, 0, 127, 0, 7, 1, 1, 4, 1, 1}
	oidECDSAPlainSHA224 = asn1.ObjectIdentifier{0, 4, 0, 127, 0, 7, 1, 1, 4, 1, 2}
	oidECDSAPlainSHA256 = asn1.ObjectIdentifier{0, 4, 0, 127, 0, 7, 1, 1, 4, 1, 3}
	oidECDSAPlainSHA384 = asn1.ObjectIdentifier{0, 4, 0, 127, 0, 7, 1, 1, 4, 1, 4}
	oidECDSAPlainSHA512 = asn1.ObjectIdentifier{0, 4, 0, 127, 0, 7, 1, 1, 4, 1, 5}

	oidSHA1   = asn1.ObjectIdentifier{1, 3, 14, 3, 2, 26}
	oidSHA224 = asn1.ObjectIdentifier{2, 16, 840, 1, 101, 3, 4, 2, 4}
	oidSHA256 = asn1.ObjectIdentifier{2, 16, 840, 1, 101, 3, 4, 2, 1}
	oidSHA384 = asn1.ObjectIdentifier{2, 16, 840, 1, 101, 3, 4, 2, 2}
	oidSHA512 = asn1.ObjectIdentifier{2, 16, 840, 1, 101, 3, 4, 2, 3}

	oidMGF1 = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 1, 8}
)

// HashForOID maps a digest algorithm OID to a crypto.Hash.
func HashForOID(oid asn1.ObjectIdentifier) (crypto.Hash, error) {
	switch {
	case oid.Equal(oidSHA1):
		return crypto.SHA1, nil
	case oid.Equal(oidSHA224):
		return crypto.SHA224, nil
	case oid.Equal(oidSHA256):
		return crypto.SHA256, nil
	case oid.Equal(oidSHA384):
		return crypto.SHA384, nil
	case oid.Equal(oidSHA512):
		return crypto.SHA512, nil
	}
	return 0, fmt.Errorf("%w: digest %s", ErrUnsupportedAlgorithm, oid)
}

func newHash(h crypto.Hash) hash.Hash {
	switch h {
	case crypto.SHA1:
		return sha1.New() //nolint:gosec
	case crypto.SHA224:
		return sha256.New224()
	case crypto.SHA256:
		return sha256.New()
	case crypto.SHA384:
		return sha512.New384()
	case crypto.SHA512:
		return sha512.New()
	}
	return nil
}

func digest(h crypto.Hash, msg []byte) []byte {
	d := newHash(h)
	d.Write(msg)
	return d.Sum(nil)
}

type pssParams struct {
	Hash         pkix.AlgorithmIdentifier `asn1:"optional,explicit,tag:0"`
	MGF          pkix.AlgorithmIdentifier `asn1:"optional,explicit,tag:1"`
	SaltLength   int                      `asn1:"optional,explicit,tag:2,default:20"`
	TrailerField int                      `asn1:"optional,explicit,tag:3,default:1"`
}

// VerifySignature checks sig over msg with pub. sigAlg is the signature
// algorithm; digestAlg is used when sigAlg names only the key type (CMS
// SignerInfos may say rsaEncryption or id-ecPublicKey and put the hash in
// digestAlgorithm).
func VerifySignature(sigAlg, digestAlg pkix.AlgorithmIdentifier, pub any, msg, sig []byte) error {
	alg := sigAlg.Algorithm
	var (
		h     crypto.Hash
		kind  string // "rsa" | "pss" | "ecdsa" | "ecdsa-plain"
		pssSL int
	)
	fromDigest := func() error {
		var err error
		h, err = HashForOID(digestAlg.Algorithm)
		return err
	}
	switch {
	case alg.Equal(oidSHA1WithRSA):
		h, kind = crypto.SHA1, "rsa"
	case alg.Equal(oidSHA224WithRSA):
		h, kind = crypto.SHA224, "rsa"
	case alg.Equal(oidSHA256WithRSA):
		h, kind = crypto.SHA256, "rsa"
	case alg.Equal(oidSHA384WithRSA):
		h, kind = crypto.SHA384, "rsa"
	case alg.Equal(oidSHA512WithRSA):
		h, kind = crypto.SHA512, "rsa"
	case alg.Equal(oidRSAEncryption):
		kind = "rsa"
		if err := fromDigest(); err != nil {
			return err
		}
	case alg.Equal(oidRSAPSS):
		kind = "pss"
		p := pssParams{SaltLength: 20, Hash: pkix.AlgorithmIdentifier{Algorithm: oidSHA1}}
		if len(sigAlg.Parameters.FullBytes) > 0 {
			if _, err := asn1.Unmarshal(sigAlg.Parameters.FullBytes, &p); err != nil {
				return fmt.Errorf("icao: RSASSA-PSS parameters: %w", err)
			}
		}
		if len(p.Hash.Algorithm) == 0 {
			p.Hash.Algorithm = oidSHA1
		}
		var err error
		if h, err = HashForOID(p.Hash.Algorithm); err != nil {
			return err
		}
		if len(p.MGF.Algorithm) > 0 {
			if !p.MGF.Algorithm.Equal(oidMGF1) {
				return fmt.Errorf("%w: PSS mask generation %s", ErrUnsupportedAlgorithm, p.MGF.Algorithm)
			}
			var mgfHash pkix.AlgorithmIdentifier
			if _, err := asn1.Unmarshal(p.MGF.Parameters.FullBytes, &mgfHash); err == nil {
				if mh, err := HashForOID(mgfHash.Algorithm); err != nil || mh != h {
					return fmt.Errorf("%w: PSS with an MGF1 hash different from the message hash", ErrUnsupportedAlgorithm)
				}
			}
		}
		pssSL = p.SaltLength
	case alg.Equal(oidECDSAWithSHA1):
		h, kind = crypto.SHA1, "ecdsa"
	case alg.Equal(oidECDSAWithSHA224):
		h, kind = crypto.SHA224, "ecdsa"
	case alg.Equal(oidECDSAWithSHA256):
		h, kind = crypto.SHA256, "ecdsa"
	case alg.Equal(oidECDSAWithSHA384):
		h, kind = crypto.SHA384, "ecdsa"
	case alg.Equal(oidECDSAWithSHA512):
		h, kind = crypto.SHA512, "ecdsa"
	case alg.Equal(oidECPublicKey):
		kind = "ecdsa"
		if err := fromDigest(); err != nil {
			return err
		}
	case alg.Equal(oidECDSAPlainSHA1):
		h, kind = crypto.SHA1, "ecdsa-plain"
	case alg.Equal(oidECDSAPlainSHA224):
		h, kind = crypto.SHA224, "ecdsa-plain"
	case alg.Equal(oidECDSAPlainSHA256):
		h, kind = crypto.SHA256, "ecdsa-plain"
	case alg.Equal(oidECDSAPlainSHA384):
		h, kind = crypto.SHA384, "ecdsa-plain"
	case alg.Equal(oidECDSAPlainSHA512):
		h, kind = crypto.SHA512, "ecdsa-plain"
	default:
		return fmt.Errorf("%w: signature algorithm %s", ErrUnsupportedAlgorithm, alg)
	}

	d := digest(h, msg)
	switch kind {
	case "rsa", "pss":
		rk, ok := pub.(*rsa.PublicKey)
		if !ok {
			return errors.New("icao: RSA signature with a non-RSA key")
		}
		if kind == "pss" {
			return rsa.VerifyPSS(rk, h, d, sig, &rsa.PSSOptions{SaltLength: pssSL, Hash: h})
		}
		return rsa.VerifyPKCS1v15(rk, h, d, sig)
	default:
		ek, ok := pub.(*ECPublicKey)
		if !ok || ek.Curve == nil {
			return errors.New("icao: ECDSA signature with a non-EC key")
		}
		// Both encodings are accepted under either OID: some documents put
		// a plain r||s signature under ecdsa-with-SHAx. Reading a signature
		// two ways cannot make a forgery verify.
		r, s, err := parseECDSASignature(sig)
		if err != nil {
			return err
		}
		if !verifyECDSA(ek, d, r, s) {
			return errors.New("icao: ECDSA signature invalid")
		}
		return nil
	}
}
