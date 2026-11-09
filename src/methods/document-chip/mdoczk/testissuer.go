package mdoczk

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"fmt"
	"io"
	"math/big"
	mrand "math/rand"
	"time"
)

// A test mdoc issuer, for fixtures and tests only: it mints ISO/IEC 18013-5
// mobile driving licences for the specimen jurisdiction "Utopia" (UT) under
// a self-made IACA, the way a state DMV does, and lets a test "wallet"
// present them with a device signature over a session transcript. Nothing
// here is real personal data, and no real issuer trusts these keys.

// TestIssuer is an IACA (root) and one document signer under it.
type TestIssuer struct {
	IACAKey  *ecdsa.PrivateKey
	IACACert []byte // DER
	DSKey    *ecdsa.PrivateKey
	DSCert   []byte // DER
}

// NewTestIssuer makes a P-256 IACA for country (and optional state), and a
// P-256 document signer certificate it signs with ecdsa-with-SHA256, both
// valid around now.
func NewTestIssuer(country, state string, now time.Time) (*TestIssuer, error) {
	iacaKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, err
	}
	dsKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, err
	}
	name := pkix.Name{Country: []string{country}, CommonName: "Utopia Test IACA"}
	if state != "" {
		name.Province = []string{state}
	}
	iacaTmpl := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               name,
		NotBefore:             now.Add(-365 * 24 * time.Hour),
		NotAfter:              now.Add(9 * 365 * 24 * time.Hour),
		IsCA:                  true,
		BasicConstraintsValid: true,
		MaxPathLen:            0,
		MaxPathLenZero:        true,
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
	}
	iacaDER, err := x509.CreateCertificate(rand.Reader, iacaTmpl, iacaTmpl, &iacaKey.PublicKey, iacaKey)
	if err != nil {
		return nil, err
	}
	iaca, _ := x509.ParseCertificate(iacaDER)
	dsName := name
	dsName.CommonName = "Utopia Test Document Signer"
	dsTmpl := &x509.Certificate{
		SerialNumber: big.NewInt(2),
		Subject:      dsName,
		NotBefore:    now.Add(-30 * 24 * time.Hour),
		NotAfter:     now.Add(3 * 365 * 24 * time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature,
		// id-mdl-kp-mdlDS (ISO/IEC 18013-5 Annex B).
		UnknownExtKeyUsage: []asn1.ObjectIdentifier{{1, 0, 18013, 5, 1, 2}},
	}
	dsDER, err := x509.CreateCertificate(rand.Reader, dsTmpl, iaca, &dsKey.PublicKey, iacaKey)
	if err != nil {
		return nil, err
	}
	return &TestIssuer{IACAKey: iacaKey, IACACert: iacaDER, DSKey: dsKey, DSCert: dsDER}, nil
}

// TestElement is one data element.
type TestElement struct {
	NameSpace  string
	Identifier string
	Value      any
}

// TestCredential describes the licence to mint.
type TestCredential struct {
	DocType    string
	Elements   []TestElement
	DeviceKey  *ecdsa.PrivateKey
	Signed     time.Time
	ValidFrom  time.Time
	ValidUntil time.Time
	// Shuffle, when non-nil, shuffles digest IDs (as real issuers do).
	Shuffle *mrand.Rand
}

// IssuedMDoc is the issuer-signed part of a credential as a wallet holds it.
type IssuedMDoc struct {
	DocType   string
	DeviceKey *ecdsa.PrivateKey
	// Items maps namespace -> element id -> IssuerSignedItemBytes
	// (#6.24(bstr .cbor IssuerSignedItem)).
	Items map[string]map[string][]byte
	// Order keeps each namespace's element order.
	Order      map[string][]string
	NSOrder    []string
	IssuerAuth []any // COSE_Sign1
	MSO        []byte
}

// SpecimenElements is a Utopia specimen licence. Every value is invented.
func SpecimenElements(documentNumber string, portrait []byte) []TestElement {
	const ns = NameSpaceMDL
	return []TestElement{
		{ns, "family_name", "SPECIMEN"},
		{ns, "given_name", "TEST"},
		{ns, "birth_date", Tag{1004, "1990-01-01"}},
		{ns, "issue_date", Tag{1004, "2024-01-15"}},
		{ns, "expiry_date", Tag{1004, "2032-01-15"}},
		{ns, "issuing_country", "UT"},
		{ns, "issuing_authority", "Utopia Department of Motor Vehicles"},
		{ns, "document_number", documentNumber},
		{ns, "portrait", portrait},
		{ns, "driving_privileges", []any{Map{{"vehicle_category_code", "C"}}}},
		{ns, "un_distinguishing_sign", "UTO"},
		{ns, "age_over_18", true},
		{ns, "age_over_21", true},
		{ns, "sex", int64(9)},
		{ns, "height", int64(170)},
		{ns, "resident_address", "1 Specimen Street"},
		{ns, "resident_city", "Utopia City"},
		{ns, "issuing_jurisdiction", "UT"},
		{"org.iso.18013.5.1.aamva", "DHS_compliance", "F"},
		{"org.iso.18013.5.1.aamva", "EDL_credential", int64(1)},
		{"org.iso.18013.5.1.aamva", "sex", int64(9)},
	}
}

func ecdsaRaw(key *ecdsa.PrivateKey, msg []byte) ([]byte, error) {
	h := sha256.Sum256(msg)
	r, s, err := ecdsa.Sign(rand.Reader, key, h[:])
	if err != nil {
		return nil, err
	}
	out := make([]byte, 64)
	r.FillBytes(out[:32])
	s.FillBytes(out[32:])
	return out, nil
}

// COSEKey is the COSE_Key of a P-256 public key as ISO/IEC 18013-5 writes
// it: {1: 2, -1: 1, -2: x, -3: y}.
func COSEKey(pub *ecdsa.PublicKey) Map {
	x := make([]byte, 32)
	y := make([]byte, 32)
	pub.X.FillBytes(x)
	pub.Y.FillBytes(y)
	return Map{{int64(1), int64(2)}, {int64(-1), int64(1)}, {int64(-2), x}, {int64(-3), y}}
}

func tdate(t time.Time) Tag { return Tag{0, t.UTC().Format("2006-01-02T15:04:05Z")} }

// sigStructure is COSE's Sig_structure for COSE_Sign1 with empty
// external_aad.
func sigStructure(protected, payload []byte) []byte {
	return Encode([]any{"Signature1", protected, []byte{}, payload})
}

// protectedES256 is the protected header {1: -7} (alg ES256).
var protectedES256 = Encode(Map{{int64(1), int64(-7)}})

// Issue mints the credential: random salts, the MSO, and the issuer
// signature (COSE_Sign1 with the DS certificate in x5chain).
func (ti *TestIssuer) Issue(c TestCredential) (*IssuedMDoc, error) {
	out := &IssuedMDoc{DocType: c.DocType, DeviceKey: c.DeviceKey, Items: map[string]map[string][]byte{}, Order: map[string][]string{}}
	digests := map[string]Map{}
	ids := make([]int, len(c.Elements))
	for i := range ids {
		ids[i] = i
	}
	if c.Shuffle != nil {
		c.Shuffle.Shuffle(len(ids), func(i, j int) { ids[i], ids[j] = ids[j], ids[i] })
	}
	for i, e := range c.Elements {
		salt := make([]byte, 32)
		if _, err := io.ReadFull(rand.Reader, salt); err != nil {
			return nil, err
		}
		item := Map{{"digestID", int64(ids[i])}, {"random", salt}, {"elementIdentifier", e.Identifier}, {"elementValue", e.Value}}
		itemBytes := Embedded(item)
		d := sha256.Sum256(itemBytes)
		if out.Items[e.NameSpace] == nil {
			out.Items[e.NameSpace] = map[string][]byte{}
			out.NSOrder = append(out.NSOrder, e.NameSpace)
		}
		out.Items[e.NameSpace][e.Identifier] = itemBytes
		out.Order[e.NameSpace] = append(out.Order[e.NameSpace], e.Identifier)
		digests[e.NameSpace] = append(digests[e.NameSpace], Pair{int64(ids[i]), d[:]})
	}
	var vd Map
	for _, ns := range out.NSOrder {
		vd = append(vd, Pair{ns, digests[ns]})
	}
	mso := Map{
		{"version", "1.0"},
		{"digestAlgorithm", "SHA-256"},
		{"valueDigests", vd},
		{"deviceKeyInfo", Map{{"deviceKey", COSEKey(&c.DeviceKey.PublicKey)}}},
		{"docType", c.DocType},
		{"validityInfo", Map{{"signed", tdate(c.Signed)}, {"validFrom", tdate(c.ValidFrom)}, {"validUntil", tdate(c.ValidUntil)}}},
	}
	out.MSO = Encode(mso)
	payload := Encode(Tag{24, out.MSO}) // MobileSecurityObjectBytes
	sig, err := ecdsaRaw(ti.DSKey, sigStructure(protectedES256, payload))
	if err != nil {
		return nil, err
	}
	out.IssuerAuth = []any{protectedES256, Map{{int64(33), ti.DSCert}}, payload, sig}
	return out, nil
}

// Present is a test wallet answering a request for elements of NameSpaceMDL
// (or any namespace, as "ns/element"): the DeviceResponse CBOR, with the
// device signature over DeviceAuthentication for sessionTranscript.
func (m *IssuedMDoc) Present(sessionTranscript []byte, elements map[string][]string) ([]byte, error) {
	var nss Map
	for _, ns := range m.NSOrder {
		want := elements[ns]
		if len(want) == 0 {
			continue
		}
		var items []any
		for _, id := range m.Order[ns] {
			for _, w := range want {
				if w == id {
					items = append(items, CBOR(m.Items[ns][id]))
				}
			}
		}
		nss = append(nss, Pair{ns, items})
	}
	deviceNameSpacesBytes := Embedded(Map{})
	da := []any{"DeviceAuthentication", CBOR(sessionTranscript), m.DocType, CBOR(deviceNameSpacesBytes)}
	daBytes := Embedded(da) // DeviceAuthenticationBytes
	sig, err := ecdsaRaw(m.DeviceKey, sigStructure(protectedES256, daBytes))
	if err != nil {
		return nil, err
	}
	doc := Map{
		{"docType", m.DocType},
		{"issuerSigned", Map{{"nameSpaces", nss}, {"issuerAuth", m.IssuerAuth}}},
		{"deviceSigned", Map{
			{"nameSpaces", CBOR(deviceNameSpacesBytes)},
			{"deviceAuth", Map{{"deviceSignature", []any{protectedES256, Map{}, Null, sig}}}},
		}},
	}
	return Encode(Map{{"version", "1.0"}, {"documents", []any{doc}}, {"status", int64(0)}}), nil
}

// DeviceSigStructure returns the bytes the device key signs for
// sessionTranscript (exported for tests).
func DeviceSigStructure(sessionTranscript []byte, docType string) []byte {
	da := []any{"DeviceAuthentication", CBOR(sessionTranscript), docType, CBOR(Embedded(Map{}))}
	return sigStructure(protectedES256, Embedded(da))
}

// String is for debugging.
func (m *IssuedMDoc) String() string {
	return fmt.Sprintf("mdoc %s (%d bytes MSO)", m.DocType, len(m.MSO))
}
