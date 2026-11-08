package zkproof

import "math/big"

// The certificate registry, in zkPassport's v1 layout (circuits
// lib/commitment/common): a binary Poseidon2 Merkle tree of depth
// RegistryDepth whose leaves are CSCA certificates, folded into one
// registry root together with a schema version, a timestamp and two more
// tree roots (revocation, master list) that the circuits bind but do not
// check. The dsc sub-proof shows that the CSCA which signed the passport's
// document signer is a leaf under a root this issuer publishes.

// RegistryDepth is the certificate tree depth the dsc circuits take
// (certificate_tree_hash_path: [Field; 16]): up to 65,536 certificates.
const RegistryDepth = 16

// CSCCertType is the leaf type for a CSCA (zkPassport CSC_CERT_TYPE).
const CSCCertType = 1

// CertificateLeaf is one CSCA in the registry.
type CertificateLeaf struct {
	// Tags are zkPassport's tag bit flags; this issuer sets none.
	Tags [3]*big.Int
	// Country is the 3-character code the passport's DG1 uses for the
	// issuing state (ICAO 9303 Part 3: ISO alpha-3, except "D<<" for
	// Germany and a few ICAO-only codes). The id circuit ties the DSC to
	// this country, so it must be exactly what the state's passports carry.
	Country string
	// Expiry is the certificate's notAfter as Unix seconds.
	Expiry uint32
	// Fingerprint identifies the certificate (Poseidon2 over its DER bytes
	// packed little-endian; opaque to the circuits).
	Fingerprint *big.Int
	// PublicKey is the key as the circuits take it: the RSA modulus,
	// big-endian, key-size bytes; or the EC point x || y, each the curve's
	// byte length.
	PublicKey []byte
}

// Hash is calculate_certificate_registry_leaf_v1.
func (l CertificateLeaf) Hash() *big.Int {
	meta := []byte{CSCCertType, 0, 0, 0, byte(l.Expiry >> 24), byte(l.Expiry >> 16), byte(l.Expiry >> 8), byte(l.Expiry)}
	copy(meta[1:4], []byte(l.Country))
	in := make([]*big.Int, 0, 5+len(l.PublicKey)/31+1)
	for _, t := range l.Tags {
		if t == nil {
			t = new(big.Int)
		}
		in = append(in, t)
	}
	in = append(in, new(big.Int).SetBytes(meta), l.Fingerprint)
	in = append(in, PackBEBytesIntoFields(l.PublicKey)...)
	return Poseidon2Hash(in)
}

// Fingerprint is the leaf fingerprint for a DER certificate.
func Fingerprint(der []byte) *big.Int {
	return Poseidon2Hash(PackLEBytesIntoFields(der))
}

func hash2(a, b *big.Int) *big.Int { return Poseidon2Hash([]*big.Int{a, b}) }

// MerkleRootFromPath is compute_merkle_root: walk up from leaf, the index's
// bits (least significant first) saying whether the node is a right child.
func MerkleRootFromPath(leaf *big.Int, index uint64, path []*big.Int) *big.Int {
	cur := leaf
	for i, sib := range path {
		if index>>uint(i)&1 == 1 {
			cur = hash2(sib, cur)
		} else {
			cur = hash2(cur, sib)
		}
	}
	return cur
}

// RegistryRoot is calculate_certificate_root_v1.
func RegistryRoot(schemaVersion uint16, timestamp uint32, certRoot, revocationRoot, masterlistRoot *big.Int) *big.Int {
	meta := []byte{byte(schemaVersion >> 8), byte(schemaVersion), byte(timestamp >> 24), byte(timestamp >> 16), byte(timestamp >> 8), byte(timestamp)}
	state := Poseidon2Hash([]*big.Int{certRoot, revocationRoot, masterlistRoot})
	return hash2(new(big.Int).SetBytes(meta), state)
}

// CertificateTree is a depth-RegistryDepth tree over leaves, padded with
// zero leaves. Only the non-empty part is stored; empty subtrees use
// precomputed zero hashes.
type CertificateTree struct {
	levels [][]*big.Int // levels[0] = leaves
	zeros  []*big.Int   // zeros[i] = root of an empty subtree of height i
}

// NewCertificateTree builds the tree. It panics on more than 2^16 leaves.
func NewCertificateTree(leaves []*big.Int) *CertificateTree {
	if len(leaves) > 1<<RegistryDepth {
		panic("zkproof: too many registry leaves")
	}
	t := &CertificateTree{zeros: make([]*big.Int, RegistryDepth+1)}
	t.zeros[0] = new(big.Int)
	for i := 1; i <= RegistryDepth; i++ {
		t.zeros[i] = hash2(t.zeros[i-1], t.zeros[i-1])
	}
	level := append([]*big.Int(nil), leaves...)
	t.levels = append(t.levels, level)
	for h := 0; h < RegistryDepth; h++ {
		next := make([]*big.Int, (len(level)+1)/2)
		for i := range next {
			l := level[2*i]
			r := t.zeros[h]
			if 2*i+1 < len(level) {
				r = level[2*i+1]
			}
			next[i] = hash2(l, r)
		}
		level = next
		t.levels = append(t.levels, level)
	}
	return t
}

// Root is the certificate tree root.
func (t *CertificateTree) Root() *big.Int {
	if top := t.levels[RegistryDepth]; len(top) == 1 {
		return top[0]
	}
	return t.zeros[RegistryDepth]
}

// Path returns the sibling hashes for leaf index i, bottom first.
func (t *CertificateTree) Path(i int) []*big.Int {
	out := make([]*big.Int, RegistryDepth)
	for h := 0; h < RegistryDepth; h++ {
		sib := i ^ 1
		if sib < len(t.levels[h]) {
			out[h] = t.levels[h][sib]
		} else {
			out[h] = t.zeros[h]
		}
		i >>= 1
	}
	return out
}
