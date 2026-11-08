package zkproof

import (
	_ "embed"
	"encoding/json"
	"fmt"
	"math/big"
)

// Poseidon2 over the BN254 scalar field with Barretenberg's parameters
// (t = 4, 8 full rounds, 56 partial rounds, x^5 S-box), and the sponge
// Noir's poseidon library uses (rate 3, IV = message length << 64). This is
// the hash every zkPassport commitment, registry leaf and the bind circuit's
// parameter commitment use; the issuer needs it to build the certificate
// registry and to check the session binding.
//
// poseidon2_bn254.json holds the constants exactly as Noir v1.0.0-beta.22
// ships them (acvm-repo/bn254_blackbox_solver/src/poseidon2_constants.rs,
// Apache-2.0), which are Barretenberg's. The wallet's TypeScript port reads
// the same file. Plain math/big: nothing hashed here is secret.

//go:embed poseidon2_bn254.json
var poseidon2JSON []byte

// Modulus is the BN254 scalar field modulus (the field Noir's Field lives in).
var Modulus, _ = new(big.Int).SetString("21888242871839275222246405745257275088548364400416034343698204186575808495617", 10)

type poseidon2Params struct {
	diag   [4]*big.Int
	rc     [64][4]*big.Int
	roundF int
	roundP int
}

var p2 = mustLoadPoseidon2()

func mustLoadPoseidon2() *poseidon2Params {
	var raw struct {
		T              int         `json:"t"`
		RoundsF        int         `json:"rounds_f"`
		RoundsP        int         `json:"rounds_p"`
		Diag           []string    `json:"internal_matrix_diagonal"`
		RoundConstants [][4]string `json:"round_constants"`
	}
	if err := json.Unmarshal(poseidon2JSON, &raw); err != nil {
		panic(fmt.Sprintf("zkproof: poseidon2 constants: %v", err))
	}
	if raw.T != 4 || len(raw.Diag) != 4 || len(raw.RoundConstants) != raw.RoundsF+raw.RoundsP || raw.RoundsF+raw.RoundsP != 64 {
		panic("zkproof: poseidon2 constants have the wrong shape")
	}
	p := &poseidon2Params{roundF: raw.RoundsF, roundP: raw.RoundsP}
	parse := func(s string) *big.Int {
		v, ok := new(big.Int).SetString(s, 0)
		if !ok || v.Cmp(Modulus) >= 0 {
			panic("zkproof: bad poseidon2 constant " + s)
		}
		return v
	}
	for i, s := range raw.Diag {
		p.diag[i] = parse(s)
	}
	for r, row := range raw.RoundConstants {
		for i, s := range row {
			p.rc[r][i] = parse(s)
		}
	}
	return p
}

func fmod(x *big.Int) *big.Int { return x.Mod(x, Modulus) }

func sbox(x *big.Int) *big.Int {
	s := new(big.Int).Mul(x, x)
	fmod(s)
	s.Mul(s, s)
	fmod(s)
	s.Mul(s, x)
	return fmod(s)
}

// external linear layer (Barretenberg's 4x4 MDS-like matrix)
func mat4(s *[4]*big.Int) {
	add := func(a, b *big.Int) *big.Int { return fmod(new(big.Int).Add(a, b)) }
	t0 := add(s[0], s[1])
	t1 := add(s[2], s[3])
	t2 := add(add(s[1], s[1]), t1)
	t3 := add(add(s[3], s[3]), t0)
	t4 := add(t1, t1)
	t4 = add(add(t4, t4), t3)
	t5 := add(t0, t0)
	t5 = add(add(t5, t5), t2)
	t6 := add(t3, t5)
	t7 := add(t2, t4)
	s[0], s[1], s[2], s[3] = t6, t5, t7, t4
}

func internalM(s *[4]*big.Int) {
	sum := new(big.Int)
	for _, v := range s {
		sum.Add(sum, v)
	}
	fmod(sum)
	for i := range s {
		v := new(big.Int).Mul(s[i], p2.diag[i])
		v.Add(v, sum)
		s[i] = fmod(v)
	}
}

// Poseidon2Permutation applies the permutation to a 4-element state.
func Poseidon2Permutation(in [4]*big.Int) [4]*big.Int {
	var s [4]*big.Int
	for i := range in {
		s[i] = fmod(new(big.Int).Set(in[i]))
	}
	mat4(&s)
	half := p2.roundF / 2
	for r := 0; r < half; r++ {
		for i := range s {
			s[i] = sbox(fmod(s[i].Add(s[i], p2.rc[r][i])))
		}
		mat4(&s)
	}
	for r := half; r < half+p2.roundP; r++ {
		s[0] = sbox(fmod(s[0].Add(s[0], p2.rc[r][0])))
		internalM(&s)
	}
	for r := half + p2.roundP; r < p2.roundF+p2.roundP; r++ {
		for i := range s {
			s[i] = sbox(fmod(s[i].Add(s[i], p2.rc[r][i])))
		}
		mat4(&s)
	}
	return s
}

// Poseidon2Hash is Noir's Poseidon2::hash(input, input.len()).
func Poseidon2Hash(input []*big.Int) *big.Int {
	const rate = 3
	iv := new(big.Int).Lsh(big.NewInt(int64(len(input))), 64)
	state := [4]*big.Int{new(big.Int), new(big.Int), new(big.Int), iv}
	n := len(input)
	for c := 0; c < n/rate; c++ {
		for i := 0; i < rate; i++ {
			state[i] = fmod(new(big.Int).Add(state[i], input[c*rate+i]))
		}
		state = Poseidon2Permutation(state)
	}
	if rem := n % rate; rem != 0 || n == 0 {
		for j := 0; j < rem; j++ {
			state[j] = fmod(new(big.Int).Add(state[j], input[n-rem+j]))
		}
		state = Poseidon2Permutation(state)
	}
	return state[0]
}

// PackBEBytesIntoFields is zkPassport's utils::pack_be_bytes_into_fields with
// 31-byte limbs: the bytes are read as one big-endian number and cut into
// 31-byte limbs from the least significant end, so out[0] holds the last 31
// bytes and out[len-1] the (possibly shorter) leading chunk.
func PackBEBytesIntoFields(b []byte) []*big.Int {
	const limb = 31
	n := (len(b) + limb - 1) / limb
	out := make([]*big.Int, n)
	end := len(b)
	for i := 0; i < n; i++ {
		start := end - limb
		if start < 0 {
			start = 0
		}
		out[i] = new(big.Int).SetBytes(b[start:end])
		end = start
	}
	return out
}

// PackLEBytesIntoFields is zkPassport's utils::pack_le_bytes_into_fields with
// 31-byte limbs: consecutive 31-byte chunks from the front, each read as a
// little-endian number.
func PackLEBytesIntoFields(b []byte) []*big.Int {
	const limb = 31
	n := (len(b) + limb - 1) / limb
	out := make([]*big.Int, n)
	for i := 0; i < n; i++ {
		start := i * limb
		end := start + limb
		if end > len(b) {
			end = len(b)
		}
		chunk := make([]byte, end-start)
		for j := range chunk {
			chunk[j] = b[end-1-j]
		}
		out[i] = new(big.Int).SetBytes(chunk)
	}
	return out
}

// FieldBytes returns x as a 32-byte big-endian field element.
func FieldBytes(x *big.Int) (f [FieldSize]byte) {
	x.FillBytes(f[:])
	return f
}

// FieldHex returns x as "0x" + 64 hex digits.
func FieldHex(x *big.Int) string { return fmt.Sprintf("0x%064x", x) }
