package documentchip

import (
	"bytes"
	"crypto/rsa"
	"crypto/sha256"
	_ "embed"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"math"
	"math/big"
	"sort"
	"strings"
	"time"

	"github.com/sagearbor/personhood/src/methods/document-chip/icao"
	"github.com/sagearbor/personhood/src/methods/document-chip/zkproof"
)

// The CSCA registry for document-chip-zk (docs/zk-passport.md, "The CSCA
// registry root"): every CSCA this issuer trusts, as a leaf of a Poseidon2
// Merkle tree in zkPassport's v1 layout. The phone downloads the whole file
// and builds its Merkle path locally, so the issuer does not learn which
// state's CSCA a phone used. The issuer builds it at start-up from the same
// trust store document-chip uses, so the two methods trust exactly the same
// certificates.

// ZKRegistrySchemaVersion is the registry schema the dsc circuits expect.
const ZKRegistrySchemaVersion = 1

// ZKRegistry is the published registry file.
type ZKRegistry struct {
	Version             int              `json:"version"`
	SchemaVersion       int              `json:"schema_version"`
	Timestamp           uint32           `json:"timestamp"`
	Depth               int              `json:"depth"`
	Root                string           `json:"root"`
	CertificateTreeRoot string           `json:"certificate_tree_root"`
	RevocationTreeRoot  string           `json:"revocation_tree_root"`
	MasterlistTreeRoot  string           `json:"masterlist_tree_root"`
	Certificates        []ZKRegistryCert `json:"certificates"`
	// Skipped counts trusted CSCAs that cannot be a leaf (a key type no
	// circuit takes). Passports under them use document-chip.
	Skipped int `json:"skipped"`

	root [zkproof.FieldSize]byte
}

// ZKRegistryCert is one leaf.
type ZKRegistryCert struct {
	Index          int         `json:"index"`
	Country        string      `json:"country"`
	Tags           [3]string   `json:"tags"`
	Expiry         uint32      `json:"expiry"`
	Fingerprint    string      `json:"fingerprint"`
	Leaf           string      `json:"leaf"`
	SubjectKeyID   string      `json:"subject_key_id"`
	SubjectCountry string      `json:"subject_country"`
	PublicKey      ZKPublicKey `json:"public_key"`
}

// ZKPublicKey is a leaf's key in the form the wallet needs to pick the
// right circuit and fill its inputs.
type ZKPublicKey struct {
	Type     string `json:"type"` // "RSA" or "EC"
	KeySize  int    `json:"key_size"`
	Modulus  string `json:"modulus,omitempty"`
	Exponent int    `json:"exponent,omitempty"`
	Curve    string `json:"curve,omitempty"`
	X        string `json:"x,omitempty"`
	Y        string `json:"y,omitempty"`
}

// RootBytes is the registry root as a field element.
func (r *ZKRegistry) RootBytes() [zkproof.FieldSize]byte { return r.root }

// icaoCountryOverrides are the issuing-state codes passports write in DG1
// that are not ISO 3166 alpha-3 (ICAO 9303 Part 3), keyed by the alpha-2
// code CSCA certificates carry.
var icaoCountryOverrides = map[string]string{
	"DE": "D<<", // Germany
	"XK": "RKS", // Kosovo (ISO user-assigned)
	"KS": "RKS", // Kosovo, as its CSCA writes it
	"UN": "UNO", // United Nations
	"EU": "EUE", // European Union laissez-passer
}

// DG1Country maps a certificate's alpha-2 country to the 3-character
// issuing-state code in the passports it signs, or "" if unknown.
func DG1Country(alpha2 string) string {
	a := strings.ToUpper(strings.TrimSpace(alpha2))
	if c, ok := icaoCountryOverrides[a]; ok {
		return c
	}
	if len(a) == 3 { // a few test CAs write the alpha-3 code
		return a
	}
	if a == "UT" { // ICAO specimen state Utopia (test documents only)
		return "UTO"
	}
	return iso3166Alpha3[a]
}

var rsaLeafSizes = []int{1024, 2048, 3072, 4096, 6144}

// zkLeafKey returns the key bytes as the circuits take them, or an error
// for a key no circuit takes.
func zkLeafKey(c *icao.Certificate) ([]byte, ZKPublicKey, error) {
	switch k := c.PublicKey.(type) {
	case *rsa.PublicKey:
		bits := k.N.BitLen()
		size := 0
		for _, s := range rsaLeafSizes {
			if bits <= s && bits > s-8 {
				size = s
				break
			}
		}
		if size == 0 {
			return nil, ZKPublicKey{}, fmt.Errorf("RSA-%d", bits)
		}
		mod := k.N.FillBytes(make([]byte, size/8))
		return mod, ZKPublicKey{Type: "RSA", KeySize: size, Modulus: "0x" + hex.EncodeToString(mod), Exponent: k.E}, nil
	case *icao.ECPublicKey:
		name := k.Curve.StandardName()
		if name == "" || name == "brainpoolP320r1" { // no circuit for brainpool-320
			return nil, ZKPublicKey{}, errors.New("EC curve without a circuit")
		}
		n := k.Curve.ByteLen()
		x, y := k.X.FillBytes(make([]byte, n)), k.Y.FillBytes(make([]byte, n))
		return append(append([]byte{}, x...), y...), ZKPublicKey{
			Type: "EC", KeySize: k.Curve.P.BitLen(), Curve: name,
			X: "0x" + hex.EncodeToString(x), Y: "0x" + hex.EncodeToString(y),
		}, nil
	default:
		return nil, ZKPublicKey{}, errors.New("key type")
	}
}

// BuildZKRegistry builds the registry from a CSCA trust store. Leaves are
// sorted by (DG1 country, SHA-256 of the certificate), so the same trust
// store always gives the same root. A zero timestamp means "the newest
// notBefore among the leaves", which is also deterministic.
func BuildZKRegistry(ts *icao.TrustStore, timestamp time.Time) (*ZKRegistry, error) {
	type leaf struct {
		cert *icao.Certificate
		key  []byte
		pk   ZKPublicKey
		cc   string
		fp   [32]byte
	}
	var leaves []leaf
	skipped := 0
	for _, c := range ts.Certificates() {
		cc := DG1Country(c.Country)
		key, pk, err := zkLeafKey(c)
		if cc == "" || err != nil {
			skipped++
			continue
		}
		leaves = append(leaves, leaf{cert: c, key: key, pk: pk, cc: cc, fp: sha256.Sum256(c.Raw)})
	}
	if len(leaves) == 0 {
		return nil, errors.New("document-chip-zk: no CSCA can be a registry leaf")
	}
	sort.Slice(leaves, func(i, j int) bool {
		if leaves[i].cc != leaves[j].cc {
			return leaves[i].cc < leaves[j].cc
		}
		return bytes.Compare(leaves[i].fp[:], leaves[j].fp[:]) < 0
	})
	if timestamp.IsZero() {
		for _, l := range leaves {
			if l.cert.NotBefore.After(timestamp) {
				timestamp = l.cert.NotBefore
			}
		}
	}
	ts32 := timestamp.Unix()
	if ts32 < 0 || ts32 > math.MaxUint32 {
		return nil, errors.New("document-chip-zk: registry timestamp out of range")
	}
	reg := &ZKRegistry{
		Version: 1, SchemaVersion: ZKRegistrySchemaVersion, Timestamp: uint32(ts32),
		Depth: zkproof.RegistryDepth, Skipped: skipped,
	}
	hashes := make([]*big.Int, len(leaves))
	for i, l := range leaves {
		exp := l.cert.NotAfter.Unix()
		if exp < 0 {
			exp = 0
		} else if exp > math.MaxUint32 {
			exp = math.MaxUint32
		}
		cl := zkproof.CertificateLeaf{
			Country: l.cc, Expiry: uint32(exp),
			Fingerprint: zkproof.Fingerprint(l.cert.Raw), PublicKey: l.key,
		}
		hashes[i] = cl.Hash()
		reg.Certificates = append(reg.Certificates, ZKRegistryCert{
			Index: i, Country: l.cc, Tags: [3]string{"0x0", "0x0", "0x0"}, Expiry: cl.Expiry,
			Fingerprint: zkproof.FieldHex(cl.Fingerprint), Leaf: zkproof.FieldHex(hashes[i]),
			SubjectKeyID: hex.EncodeToString(l.cert.SubjectKeyID), SubjectCountry: l.cert.Country,
			PublicKey: l.pk,
		})
	}
	tree := zkproof.NewCertificateTree(hashes)
	zero := new(big.Int)
	root := zkproof.RegistryRoot(ZKRegistrySchemaVersion, reg.Timestamp, tree.Root(), zero, zero)
	reg.Root = zkproof.FieldHex(root)
	reg.CertificateTreeRoot = zkproof.FieldHex(tree.Root())
	reg.RevocationTreeRoot = zkproof.FieldHex(zero)
	reg.MasterlistTreeRoot = zkproof.FieldHex(zero)
	reg.root = zkproof.FieldBytes(root)
	return reg, nil
}

// ---------------------------------------------------------------- roots

// zkAcceptedRootsJSON lists registry roots this issuer published before
// the current one, with the day each was replaced. Phones cache the
// registry file, so a root stays accepted for ZKRootGrace after it was
// replaced. When the master list (or DOCUMENT_CHIP_CSCA_PEM) changes, add
// the old root here (docs/zk-passport.md, "Updating the registry").
//
//go:embed zk/accepted_roots.json
var zkAcceptedRootsJSON []byte

// ZKRootGrace is how long a replaced registry root stays accepted.
const ZKRootGrace = 60 * 24 * time.Hour

type zkRetiredRoot struct {
	Root    string `json:"root"`
	Retired string `json:"retired"` // YYYY-MM-DD
	Note    string `json:"note,omitempty"`
}

// ZKAcceptedRoots returns the current root plus every retired root still
// inside its grace period at now, plus extra (operator-supplied, e.g. a
// root published by another instance during a rollout).
func ZKAcceptedRoots(current [zkproof.FieldSize]byte, now time.Time, extra ...string) (map[[zkproof.FieldSize]byte]bool, error) {
	out := map[[zkproof.FieldSize]byte]bool{current: true}
	var retired []zkRetiredRoot
	if err := json.Unmarshal(zkAcceptedRootsJSON, &retired); err != nil {
		return nil, fmt.Errorf("document-chip-zk: accepted roots: %w", err)
	}
	add := func(s string) error {
		v, ok := new(big.Int).SetString(strings.TrimSpace(s), 0)
		if !ok || v.Sign() < 0 || v.Cmp(zkproof.Modulus) >= 0 {
			return fmt.Errorf("document-chip-zk: bad registry root %q", s)
		}
		out[zkproof.FieldBytes(v)] = true
		return nil
	}
	for _, r := range retired {
		day, err := time.Parse("2006-01-02", r.Retired)
		if err != nil {
			return nil, fmt.Errorf("document-chip-zk: accepted roots: %q: %w", r.Retired, err)
		}
		if now.Before(day.Add(ZKRootGrace)) {
			if err := add(r.Root); err != nil {
				return nil, err
			}
		}
	}
	for _, s := range extra {
		if strings.TrimSpace(s) == "" {
			continue
		}
		if err := add(s); err != nil {
			return nil, err
		}
	}
	return out, nil
}
