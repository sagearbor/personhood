package zkproof

import (
	"encoding/json"
	"math/big"
	"os"
	"testing"
)

func hexInt(t *testing.T, s string) *big.Int {
	t.Helper()
	v, ok := new(big.Int).SetString(s, 0)
	if !ok {
		t.Fatalf("bad number %q", s)
	}
	return v
}

// Barretenberg / Noir smoke vector: permutation of [0, 0, 0, 0].
func TestPoseidon2PermutationVector(t *testing.T) {
	z := [4]*big.Int{new(big.Int), new(big.Int), new(big.Int), new(big.Int)}
	got := Poseidon2Permutation(z)
	want := []string{
		"0x18DFB8DC9B82229CFF974EFEFC8DF78B1CE96D9D844236B496785C698BC6732E",
		"0x095C230D1D37A246E8D2D5A63B165FE0FADE040D442F61E25F0590E5FB76F839",
		"0x0BB9545846E1AFA4FA3C97414A60A20FC4949F537A68CCECA34C5CE71E28AA59",
		"0x18A4F34C9C6F99335FF7638B82AEED9018026618358873C982BBDDE265B2ED6D",
	}
	for i := range want {
		if got[i].Cmp(hexInt(t, want[i])) != 0 {
			t.Fatalf("state[%d] = %x, want %s", i, got[i], want[i])
		}
	}
}

func TestPackBytes(t *testing.T) {
	b := make([]byte, 33)
	for i := range b {
		b[i] = byte(i + 1)
	}
	be := PackBEBytesIntoFields(b)
	if len(be) != 2 || be[1].Cmp(big.NewInt(0x0102)) != 0 || be[0].Cmp(new(big.Int).SetBytes(b[2:])) != 0 {
		t.Fatalf("BE packing wrong: %x", be)
	}
	le := PackLEBytesIntoFields(b)
	if len(le) != 2 || le[1].Cmp(big.NewInt(0x2120)) != 0 {
		t.Fatalf("LE packing wrong: %x", le)
	}
}

// spikeDSCInputs are the dsc sub-circuit inputs the phase-1 spike built with
// zkPassport's own tooling for the p256 test vector, and whose proof
// verified. Recomputing the registry root and the dsc commitment from them
// checks Poseidon2, the packing and the leaf layout against the circuit.
type spikeDSCInputs struct {
	Root          string   `json:"certificate_registry_root"`
	SchemaVersion int      `json:"schema_version"`
	Timestamp     uint32   `json:"timestamp"`
	Index         uint64   `json:"certificate_tree_index"`
	Path          []string `json:"certificate_tree_hash_path"`
	Tags          []string `json:"certificate_tags"`
	Country       string   `json:"country"`
	Expiry        uint32   `json:"csc_expiry"`
	Fingerprint   string   `json:"csc_fingerprint"`
	Revocation    string   `json:"revocation_tree_root"`
	Masterlist    string   `json:"masterlist_tree_root"`
	Salt          string   `json:"salt"`
	PubX          []byte   `json:"-"`
	RawX          []int    `json:"csc_pubkey_x"`
	RawY          []int    `json:"csc_pubkey_y"`
	TBS           []int    `json:"tbs_certificate"`
}

func ints(v []int) []byte {
	b := make([]byte, len(v))
	for i, x := range v {
		b[i] = byte(x)
	}
	return b
}

func TestRegistryAndCommitmentMatchSpike(t *testing.T) {
	raw, err := os.ReadFile("testdata/p256/dsc.inputs.json")
	if err != nil {
		t.Fatal(err)
	}
	var in spikeDSCInputs
	if err := json.Unmarshal(raw, &in); err != nil {
		t.Fatal(err)
	}
	leaf := CertificateLeaf{
		Country:     in.Country,
		Expiry:      in.Expiry,
		Fingerprint: hexInt(t, in.Fingerprint),
		PublicKey:   append(ints(in.RawX), ints(in.RawY)...),
	}
	path := make([]*big.Int, len(in.Path))
	for i, p := range in.Path {
		path[i] = hexInt(t, p)
	}
	certRoot := MerkleRootFromPath(leaf.Hash(), in.Index, path)
	root := RegistryRoot(uint16(in.SchemaVersion), in.Timestamp, certRoot, hexInt(t, in.Revocation), hexInt(t, in.Masterlist))
	if root.Cmp(hexInt(t, in.Root)) != 0 {
		t.Fatalf("registry root %s, spike circuit accepted %s", FieldHex(root), in.Root)
	}
	// The same leaf in a tree we build ourselves (index 0, empty siblings)
	// must give the same certificate tree root as the spike's path.
	tree := NewCertificateTree([]*big.Int{leaf.Hash()})
	if tree.Root().Cmp(certRoot) != 0 {
		t.Fatalf("our tree root %s, spike path root %s", FieldHex(tree.Root()), FieldHex(certRoot))
	}
	for i, sib := range tree.Path(0) {
		if sib.Cmp(path[i]) != 0 {
			t.Fatalf("path[%d] = %s, spike has %s", i, FieldHex(sib), in.Path[i])
		}
	}

	// dsc's output commitment, hash_salt_country_tbs(salt, country, tbs),
	// as the circuit returned it in the spike (and the id circuit took it).
	const dscCommitment = "0x0b6ff21d576ba23600f6b314894a7db89c578d094f354b3dfbfd9528f9770608"
	inputs := []*big.Int{hexInt(t, in.Salt)}
	inputs = append(inputs, PackBEBytesIntoFields([]byte(in.Country))...)
	inputs = append(inputs, PackBEBytesIntoFields(ints(in.TBS))...)
	if got := Poseidon2Hash(inputs); got.Cmp(hexInt(t, dscCommitment)) != 0 {
		t.Fatalf("dsc commitment %s, circuit returned %s", FieldHex(got), dscCommitment)
	}
}
