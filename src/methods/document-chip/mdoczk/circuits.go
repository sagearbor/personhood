package mdoczk

import "embed"

// The pinned circuit set: circuits/circuits.json (manifest) and
// circuits/vks/<name>.vk, written by tools/zk-circuits/mdoc/build.sh. The
// issuer accepts only proofs under these verification keys.
//
//go:embed circuits/circuits.json circuits/vks
var circuitsFS embed.FS

// CircuitsJSON is the embedded manifest.
func CircuitsJSON() []byte {
	b, _ := circuitsFS.ReadFile("circuits/circuits.json")
	return b
}

// VK is the embedded verification key of a circuit.
func VK(name string) ([]byte, error) { return circuitsFS.ReadFile("circuits/vks/" + name + ".vk") }
