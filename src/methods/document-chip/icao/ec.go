package icao

import (
	"crypto/elliptic"
	"encoding/asn1"
	"encoding/hex"
	"errors"
	"fmt"
	"math/big"
)

// Generic short-Weierstrass ECDSA verification over a prime field, with the
// curve given by its parameters.
//
// Why not crypto/ecdsa: about a quarter of the CSCA certificates in the
// German master list carry EXPLICIT curve parameters (mostly brainpool), and
// many document signers use brainpool curves, which Go's standard library
// does not implement and crypto/x509 refuses to parse. Verification uses no
// secret, so plain math/big arithmetic (not constant time) is fine here.
// Nothing in this file signs.

// Curve is y^2 = x^3 + a*x + b over GF(p), with base point G of order N.
type Curve struct {
	P, A, B, Gx, Gy, N *big.Int
	Name               string
}

// ECPublicKey is a point on Curve.
type ECPublicKey struct {
	Curve *Curve
	X, Y  *big.Int
}

var (
	oidNamedP224  = asn1.ObjectIdentifier{1, 3, 132, 0, 33}
	oidNamedP256  = asn1.ObjectIdentifier{1, 2, 840, 10045, 3, 1, 7}
	oidNamedP384  = asn1.ObjectIdentifier{1, 3, 132, 0, 34}
	oidNamedP521  = asn1.ObjectIdentifier{1, 3, 132, 0, 35}
	oidPrimeField = asn1.ObjectIdentifier{1, 2, 840, 10045, 1, 1}
)

// namedCurve returns the curve for a named-curve OID.
func namedCurve(oid asn1.ObjectIdentifier) (*Curve, error) {
	var std elliptic.Curve
	switch {
	case oid.Equal(oidNamedP224):
		std = elliptic.P224()
	case oid.Equal(oidNamedP256):
		std = elliptic.P256()
	case oid.Equal(oidNamedP384):
		std = elliptic.P384()
	case oid.Equal(oidNamedP521):
		std = elliptic.P521()
	}
	if std != nil {
		p := std.Params()
		return &Curve{
			P: p.P, A: new(big.Int).Sub(p.P, big.NewInt(3)), B: p.B,
			Gx: p.Gx, Gy: p.Gy, N: p.N, Name: p.Name,
		}, nil
	}
	if h, ok := brainpoolExplicitDER[oid.String()]; ok {
		der, _ := hex.DecodeString(h)
		c, err := parseExplicitCurve(der)
		if err != nil {
			return nil, err
		}
		c.Name = oid.String()
		return c, nil
	}
	return nil, fmt.Errorf("%w: named curve %s", ErrUnsupportedAlgorithm, oid)
}

// ecParameters is SEC 1 / X9.62 ECParameters (explicit form).
type ecParameters struct {
	Version  int
	FieldID  fieldID
	Curve    curveAB
	Base     []byte
	Order    *big.Int
	Cofactor *big.Int `asn1:"optional"`
}

type fieldID struct {
	FieldType asn1.ObjectIdentifier
	Prime     *big.Int
}

type curveAB struct {
	A    []byte
	B    []byte
	Seed asn1.BitString `asn1:"optional"`
}

// parseExplicitCurve reads explicit ECParameters.
func parseExplicitCurve(der []byte) (*Curve, error) {
	var ep ecParameters
	rest, err := asn1.Unmarshal(der, &ep)
	if err != nil || len(rest) != 0 {
		return nil, fmt.Errorf("icao: explicit EC parameters: %v", err)
	}
	if !ep.FieldID.FieldType.Equal(oidPrimeField) {
		return nil, fmt.Errorf("%w: characteristic-two EC field", ErrUnsupportedAlgorithm)
	}
	c := &Curve{
		P: ep.FieldID.Prime,
		A: new(big.Int).SetBytes(ep.Curve.A),
		B: new(big.Int).SetBytes(ep.Curve.B),
		N: ep.Order,
	}
	if c.P.Sign() <= 0 || c.N.Sign() <= 0 {
		return nil, errors.New("icao: explicit EC parameters: bad prime or order")
	}
	gx, gy, err := c.decodePoint(ep.Base)
	if err != nil {
		return nil, fmt.Errorf("icao: explicit EC base point: %w", err)
	}
	c.Gx, c.Gy = gx, gy
	return c, nil
}

// parseECParams reads the AlgorithmIdentifier parameters of an EC key:
// a named curve OID or explicit parameters. Empty or NULL parameters return
// (nil, nil): the curve is inherited from the issuer (RFC 3279 implicitCA).
func parseECParams(raw []byte) (*Curve, error) {
	if len(raw) == 0 || (len(raw) == 2 && raw[0] == 0x05 && raw[1] == 0x00) {
		return nil, nil
	}
	if raw[0] == 0x06 {
		var oid asn1.ObjectIdentifier
		if _, err := asn1.Unmarshal(raw, &oid); err != nil {
			return nil, err
		}
		return namedCurve(oid)
	}
	return parseExplicitCurve(raw)
}

func (c *Curve) byteLen() int { return (c.P.BitLen() + 7) / 8 }

// isOnCurve reports y^2 == x^3 + ax + b (mod p) for 0 <= x,y < p.
func (c *Curve) isOnCurve(x, y *big.Int) bool {
	if x.Sign() < 0 || x.Cmp(c.P) >= 0 || y.Sign() < 0 || y.Cmp(c.P) >= 0 {
		return false
	}
	lhs := new(big.Int).Mul(y, y)
	lhs.Mod(lhs, c.P)
	return lhs.Cmp(c.rhs(x)) == 0
}

func (c *Curve) rhs(x *big.Int) *big.Int {
	r := new(big.Int).Mul(x, x)
	r.Mul(r, x)
	ax := new(big.Int).Mul(c.A, x)
	r.Add(r, ax)
	r.Add(r, c.B)
	return r.Mod(r, c.P)
}

// decodePoint reads an uncompressed (04) or compressed (02/03) point.
func (c *Curve) decodePoint(b []byte) (*big.Int, *big.Int, error) {
	n := c.byteLen()
	switch {
	case len(b) == 1+2*n && b[0] == 4:
		x := new(big.Int).SetBytes(b[1 : 1+n])
		y := new(big.Int).SetBytes(b[1+n:])
		if !c.isOnCurve(x, y) {
			return nil, nil, errors.New("point not on curve")
		}
		return x, y, nil
	case len(b) == 1+n && (b[0] == 2 || b[0] == 3):
		x := new(big.Int).SetBytes(b[1:])
		if x.Cmp(c.P) >= 0 {
			return nil, nil, errors.New("point x out of range")
		}
		y := new(big.Int).ModSqrt(c.rhs(x), c.P)
		if y == nil {
			return nil, nil, errors.New("point not on curve")
		}
		if y.Bit(0) != uint(b[0]&1) {
			y.Sub(c.P, y)
		}
		return x, y, nil
	default:
		return nil, nil, errors.New("malformed EC point")
	}
}

// point is an affine point; inf marks the point at infinity.
type point struct {
	x, y *big.Int
	inf  bool
}

func (c *Curve) add(p, q point) point {
	if p.inf {
		return q
	}
	if q.inf {
		return p
	}
	if p.x.Cmp(q.x) == 0 {
		sum := new(big.Int).Add(p.y, q.y)
		if sum.Mod(sum, c.P).Sign() == 0 {
			return point{inf: true}
		}
		return c.double(p)
	}
	// lambda = (qy - py) / (qx - px)
	num := new(big.Int).Sub(q.y, p.y)
	den := new(big.Int).Sub(q.x, p.x)
	den.Mod(den, c.P)
	den.ModInverse(den, c.P)
	l := num.Mul(num, den)
	l.Mod(l, c.P)
	return c.finish(l, p, q.x)
}

func (c *Curve) double(p point) point {
	if p.inf || p.y.Sign() == 0 {
		return point{inf: true}
	}
	// lambda = (3x^2 + a) / 2y
	num := new(big.Int).Mul(p.x, p.x)
	num.Mul(num, big.NewInt(3))
	num.Add(num, c.A)
	den := new(big.Int).Lsh(p.y, 1)
	den.Mod(den, c.P)
	den.ModInverse(den, c.P)
	l := num.Mul(num, den)
	l.Mod(l, c.P)
	return c.finish(l, p, p.x)
}

// finish computes x3 = l^2 - px - qx, y3 = l(px - x3) - py.
func (c *Curve) finish(l *big.Int, p point, qx *big.Int) point {
	x3 := new(big.Int).Mul(l, l)
	x3.Sub(x3, p.x)
	x3.Sub(x3, qx)
	x3.Mod(x3, c.P)
	y3 := new(big.Int).Sub(p.x, x3)
	y3.Mul(y3, l)
	y3.Sub(y3, p.y)
	y3.Mod(y3, c.P)
	return point{x: x3, y: y3}
}

func (c *Curve) mul(p point, k *big.Int) point {
	r := point{inf: true}
	for i := k.BitLen() - 1; i >= 0; i-- {
		r = c.double(r)
		if k.Bit(i) == 1 {
			r = c.add(r, p)
		}
	}
	return r
}

// hashToInt converts a digest to an integer per SEC 1 4.1.4 step 5: the
// leftmost bitlen(N) bits.
func hashToInt(digest []byte, n *big.Int) *big.Int {
	orderBits := n.BitLen()
	orderBytes := (orderBits + 7) / 8
	if len(digest) > orderBytes {
		digest = digest[:orderBytes]
	}
	e := new(big.Int).SetBytes(digest)
	if excess := len(digest)*8 - orderBits; excess > 0 {
		e.Rsh(e, uint(excess))
	}
	return e
}

// verifyECDSA checks (r, s) over digest.
func verifyECDSA(pub *ECPublicKey, digest []byte, r, s *big.Int) bool {
	c := pub.Curve
	if r.Sign() <= 0 || s.Sign() <= 0 || r.Cmp(c.N) >= 0 || s.Cmp(c.N) >= 0 {
		return false
	}
	if !c.isOnCurve(pub.X, pub.Y) {
		return false
	}
	e := hashToInt(digest, c.N)
	w := new(big.Int).ModInverse(s, c.N)
	if w == nil {
		return false
	}
	u1 := new(big.Int).Mul(e, w)
	u1.Mod(u1, c.N)
	u2 := new(big.Int).Mul(r, w)
	u2.Mod(u2, c.N)
	g := point{x: c.Gx, y: c.Gy}
	q := point{x: pub.X, y: pub.Y}
	x := c.add(c.mul(g, u1), c.mul(q, u2))
	if x.inf {
		return false
	}
	v := new(big.Int).Mod(x.x, c.N)
	return v.Cmp(r) == 0
}

// ecdsaSig is the DER form of an ECDSA signature.
type ecdsaSig struct {
	R, S *big.Int
}

// parseECDSASignature accepts DER (SEQUENCE{r,s}) or plain r||s (BSI TR-03111).
func parseECDSASignature(sig []byte) (*big.Int, *big.Int, error) {
	var es ecdsaSig
	if rest, err := asn1.Unmarshal(sig, &es); err == nil && len(rest) == 0 && es.R != nil && es.S != nil {
		return es.R, es.S, nil
	}
	if len(sig)%2 == 0 && len(sig) > 0 {
		h := len(sig) / 2
		return new(big.Int).SetBytes(sig[:h]), new(big.Int).SetBytes(sig[h:]), nil
	}
	return nil, nil, errors.New("malformed ECDSA signature")
}
