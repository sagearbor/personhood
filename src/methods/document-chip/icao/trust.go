package icao

import (
	"bytes"
	"crypto/sha256"
	"encoding/asn1"
	"encoding/hex"
	"encoding/pem"
	"errors"
	"fmt"
	"sort"
	"strings"
)

// TrustStore holds Country Signing CA (CSCA) certificates: the roots that
// document signer certificates must chain to.
type TrustStore struct {
	certs []*Certificate
	seen  map[[32]byte]bool
}

// NewTrustStore returns an empty store.
func NewTrustStore() *TrustStore {
	return &TrustStore{seen: map[[32]byte]bool{}}
}

// Add adds a CSCA certificate (duplicates are ignored).
func (t *TrustStore) Add(c *Certificate) {
	fp := sha256.Sum256(c.Raw)
	if t.seen[fp] {
		return
	}
	t.seen[fp] = true
	t.certs = append(t.certs, c)
}

// Len returns the number of certificates.
func (t *TrustStore) Len() int { return len(t.certs) }

// Countries returns the distinct subject countries, sorted.
func (t *TrustStore) Countries() []string {
	m := map[string]bool{}
	for _, c := range t.certs {
		if c.Country != "" {
			m[c.Country] = true
		}
	}
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}

// AddPEM adds every CERTIFICATE block in pemData. Certificates this package
// cannot parse are skipped and counted.
func (t *TrustStore) AddPEM(pemData []byte) (added, skipped int) {
	for {
		var b *pem.Block
		b, pemData = pem.Decode(pemData)
		if b == nil {
			return added, skipped
		}
		if b.Type != "CERTIFICATE" {
			continue
		}
		c, err := ParseCertificate(b.Bytes)
		if err != nil {
			skipped++
			continue
		}
		t.Add(c)
		added++
	}
}

// issuersOf returns the CSCAs that may have issued c: same name, and the
// same key id when both sides carry one.
func (t *TrustStore) issuersOf(c *Certificate) []*Certificate {
	var out []*Certificate
	for _, ca := range t.certs {
		if !sameName(ca.RawSubject, c.RawIssuer) {
			continue
		}
		if len(c.AuthKeyID) > 0 && len(ca.SubjectKeyID) > 0 && !bytes.Equal(c.AuthKeyID, ca.SubjectKeyID) {
			continue
		}
		out = append(out, ca)
	}
	return out
}

// ErrUntrusted means no CSCA in the store vouches for a certificate.
var ErrUntrusted = errors.New("icao: no trusted CSCA issued this certificate")

// Chain verifies that dsc was issued by a CSCA in the store and returns
// that CSCA.
//
// Validity periods are deliberately not enforced on the chain: a document
// signer key signs passports for a few months and its certificate may then
// expire, while the passports it signed stay valid for ten years (ICAO 9303
// Part 12). The document's own expiry date (from DG1) is what is checked.
func (t *TrustStore) Chain(dsc *Certificate) (*Certificate, error) {
	var lastErr error
	for _, ca := range t.issuersOf(dsc) {
		if err := dsc.CheckSignatureFrom(ca); err != nil {
			lastErr = err
			continue
		}
		return ca, nil
	}
	if lastErr != nil && errors.Is(lastErr, ErrUnsupportedAlgorithm) {
		return nil, lastErr
	}
	return nil, ErrUntrusted
}

var oidCSCAMasterList = asn1.ObjectIdentifier{2, 23, 136, 1, 1, 2}

type cscaMasterList struct {
	Version  int
	CertList []asn1.RawValue `asn1:"set"`
}

// MasterListInfo describes a loaded master list.
type MasterListInfo struct {
	Signer       string // master list signer's subject country
	Certificates int    // certificates added
	Skipped      int    // certificates this package could not parse
}

// AddMasterList verifies a CSCA master list (ICAO 9303 Part 12: CMS
// SignedData over a CscaMasterList) and adds its certificates.
//
// The list is only trusted if its signer certificate chains to one of the
// pinned anchors: SHA-256 fingerprints (hex) of the publishing state's CSCA.
// The anchor itself may come from inside the list; what makes it an anchor
// is that its fingerprint was pinned out of band (see
// docs/document-chip-anchor.md for where the pinned value comes from).
func (t *TrustStore) AddMasterList(der []byte, pinnedAnchorSHA256 []string) (MasterListInfo, error) {
	msg, err := ParseSignedData(der)
	if err != nil {
		return MasterListInfo{}, err
	}
	if !msg.EContentType.Equal(oidCSCAMasterList) {
		return MasterListInfo{}, fmt.Errorf("icao: content type %s is not a CSCA master list", msg.EContentType)
	}
	var ml cscaMasterList
	if _, err := asn1.Unmarshal(msg.EContent, &ml); err != nil {
		return MasterListInfo{}, fmt.Errorf("icao: CscaMasterList: %w", err)
	}
	var listed []*Certificate
	skipped := 0
	for _, raw := range ml.CertList {
		c, err := ParseCertificate(raw.FullBytes)
		if err != nil {
			skipped++
			continue
		}
		listed = append(listed, c)
	}

	pins := map[string]bool{}
	for _, p := range pinnedAnchorSHA256 {
		p = strings.ToLower(strings.ReplaceAll(strings.TrimSpace(p), ":", ""))
		if p != "" {
			pins[p] = true
		}
	}
	anchors := NewTrustStore()
	for _, c := range append(append([]*Certificate(nil), msg.Certificates...), listed...) {
		fp := sha256.Sum256(c.Raw)
		if pins[hex.EncodeToString(fp[:])] {
			anchors.Add(c)
		}
	}
	if anchors.Len() == 0 {
		return MasterListInfo{}, errors.New("icao: master list: no pinned anchor certificate found")
	}
	signer, err := msg.SignerCertificate()
	if err != nil {
		return MasterListInfo{}, fmt.Errorf("icao: master list: %w", err)
	}
	if _, err := anchors.Chain(signer); err != nil {
		return MasterListInfo{}, fmt.Errorf("icao: master list signer does not chain to a pinned anchor: %w", err)
	}
	if err := msg.VerifySigner(signer); err != nil {
		return MasterListInfo{}, fmt.Errorf("icao: master list signature: %w", err)
	}
	for _, c := range listed {
		t.Add(c)
	}
	return MasterListInfo{Signer: signer.Country, Certificates: len(listed), Skipped: skipped}, nil
}
