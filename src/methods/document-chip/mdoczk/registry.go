package mdoczk

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/sha256"
	"crypto/x509"
	"encoding/hex"
	"encoding/pem"
	"fmt"
	"math/big"
	"sort"
	"strings"

	"github.com/sagearbor/personhood/src/methods/document-chip/zkproof"
)

// The IACA registry: a Poseidon2 Merkle tree (depth 16, the same tree code
// as the passport registry, zkproof.CertificateTree) whose leaves are the
// issuing authorities' root keys this issuer trusts, each with its
// jurisdiction:
//
//	leaf = Poseidon2(LeafTag, pack_be(jurisdiction), pack_be(x || y))
//
// The circuit shows that the licence's document signer was signed by the key
// of some leaf, without saying which. The jurisdiction in the leaf goes into
// the nullifier, so document numbers are scoped per jurisdiction (two states
// can issue the same number) while an IACA key rotation in one jurisdiction
// keeps every licence's nullifier.

// LeafTag is "mdoc-iaca" packed big-endian (the circuit's LEAF_TAG).
var LeafTag = new(big.Int).SetBytes([]byte("mdoc-iaca"))

// RegistryEntry is one trusted IACA.
type RegistryEntry struct {
	Jurisdiction string `json:"jurisdiction"`
	X            string `json:"x"` // hex, 32 bytes
	Y            string `json:"y"`
	Leaf         string `json:"leaf"`        // 0x field
	CertSHA256   string `json:"cert_sha256"` // of the IACA certificate DER
	Subject      string `json:"subject"`
}

// Registry is what GET /v1/methods/mobile-id-zk/registry serves. Phones
// download all of it and build their Merkle path locally, so the issuer
// does not learn which jurisdiction a phone used.
type Registry struct {
	Root    string          `json:"root"`
	Depth   int             `json:"depth"`
	Entries []RegistryEntry `json:"entries"`
	// Skipped counts certificates no circuit takes (not P-256) or without a
	// jurisdiction.
	Skipped int `json:"skipped"`
	tree    *zkproof.CertificateTree
}

// Jurisdiction is the IACA's jurisdiction code: its subject's country, plus
// "-" and the stateOrProvinceName when present (ISO/IEC 18013-5 Annex B:
// when present it must match issuing_jurisdiction), e.g. "US-CA", "JP".
// override (from MOBILE_ID_IACA_JURISDICTIONS) maps a certificate's SHA-256
// hex to a code, for IACAs whose subject does not say.
func Jurisdiction(c *x509.Certificate, override map[string]string) string {
	sum := sha256.Sum256(c.Raw)
	if j, ok := override[hex.EncodeToString(sum[:])]; ok {
		return j
	}
	if len(c.Subject.Country) != 1 || len(c.Subject.Country[0]) != 2 {
		return ""
	}
	j := strings.ToUpper(c.Subject.Country[0])
	if len(c.Subject.Province) == 1 {
		st := strings.ToUpper(strings.TrimSpace(c.Subject.Province[0]))
		if st == "" || len(st) > 24 {
			return ""
		}
		j += "-" + st
	}
	return j
}

// ParsePEMCertificates reads every CERTIFICATE block in pemData.
func ParsePEMCertificates(pemData []byte) ([]*x509.Certificate, int) {
	var out []*x509.Certificate
	bad := 0
	for {
		var b *pem.Block
		b, pemData = pem.Decode(pemData)
		if b == nil {
			return out, bad
		}
		if b.Type != "CERTIFICATE" {
			continue
		}
		c, err := x509.ParseCertificate(b.Bytes)
		if err != nil {
			bad++
			continue
		}
		out = append(out, c)
	}
}

// BuildRegistry makes the registry from IACA certificates. Certificates
// whose key no circuit takes (anything but P-256), or without a
// jurisdiction, are skipped and counted. Leaves are sorted by (jurisdiction,
// certificate hash), so the root is deterministic.
//
// A jurisdiction whose IACA subject has a country but no state while
// another IACA of that country names one is still accepted; the operator
// must make sure two issuers never share a code (two states issuing the
// same document number under one code would make two people one identity).
// BuildRegistry refuses duplicate keys.
func BuildRegistry(certs []*x509.Certificate, override map[string]string) (*Registry, error) {
	r := &Registry{Depth: zkproof.RegistryDepth}
	seen := map[string]bool{}
	for _, c := range certs {
		pub, ok := c.PublicKey.(*ecdsa.PublicKey)
		j := Jurisdiction(c, override)
		if !ok || pub.Curve != elliptic.P256() || j == "" || len(j) > 31 {
			r.Skipped++
			continue
		}
		x, y := make([]byte, 32), make([]byte, 32)
		pub.X.FillBytes(x)
		pub.Y.FillBytes(y)
		key := hex.EncodeToString(x) + hex.EncodeToString(y)
		if seen[key] {
			continue
		}
		seen[key] = true
		sum := sha256.Sum256(c.Raw)
		r.Entries = append(r.Entries, RegistryEntry{
			Jurisdiction: j, X: hex.EncodeToString(x), Y: hex.EncodeToString(y),
			Leaf:       zkproof.FieldHex(LeafHash(j, x, y)),
			CertSHA256: hex.EncodeToString(sum[:]), Subject: c.Subject.String(),
		})
	}
	sort.Slice(r.Entries, func(a, b int) bool {
		if r.Entries[a].Jurisdiction != r.Entries[b].Jurisdiction {
			return r.Entries[a].Jurisdiction < r.Entries[b].Jurisdiction
		}
		return r.Entries[a].CertSHA256 < r.Entries[b].CertSHA256
	})
	leaves := make([]*big.Int, len(r.Entries))
	for i, e := range r.Entries {
		leaves[i], _ = new(big.Int).SetString(e.Leaf[2:], 16)
	}
	if len(leaves) > 1<<zkproof.RegistryDepth {
		return nil, fmt.Errorf("mdoczk: %d IACAs is more than the tree holds", len(leaves))
	}
	r.tree = zkproof.NewCertificateTree(leaves)
	r.Root = zkproof.FieldHex(r.tree.Root())
	return r, nil
}

// LeafHash is the registry leaf of one IACA key.
func LeafHash(jurisdiction string, x, y []byte) *big.Int {
	in := []*big.Int{LeafTag, new(big.Int).SetBytes([]byte(jurisdiction))}
	in = append(in, zkproof.PackBEBytesIntoFields(append(append([]byte{}, x...), y...))...)
	return zkproof.Poseidon2Hash(in)
}

// RootBytes is the root as a 32-byte field.
func (r *Registry) RootBytes() [zkproof.FieldSize]byte {
	return zkproof.FieldBytes(r.tree.Root())
}

// Path is the Merkle path of entry i (tests and fixtures; phones compute
// their own).
func (r *Registry) Path(i int) []string {
	p := r.tree.Path(i)
	out := make([]string, len(p))
	for j, x := range p {
		out[j] = zkproof.FieldHex(x)
	}
	return out
}
