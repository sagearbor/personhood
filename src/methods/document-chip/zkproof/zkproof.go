// Package zkproof verifies a zero-knowledge ePassport proof: four chained
// UltraHonk sub-proofs, made on the phone with zkPassport's Noir circuits
// (Apache-2.0, github.com/zkpassport/circuits), that together show
//
//  1. dsc:       a CSCA in the issuer's published certificate registry
//     (a Poseidon2 Merkle root) signed the document signer certificate;
//  2. id:        that DSC signed the passport's EF.SOD;
//  3. integrity: EF.SOD's hashes cover DG1 (name, number, birth date) and DG2;
//  4. expiry:    the document has not expired on the public current_date, and
//     the scoped nullifier is Poseidon2(private nullifier, scope, subscope),
//     where the private nullifier is Poseidon2(DG1, eContent, SOD signature).
//
// The sub-proofs are linked by salted commitments: each one's output
// commitment is the next one's public input. None of DG1, the document
// number, the photo or the signatures appears in any public input.
//
// This is the phase-1 spike (docs/zk-passport.md). It is not wired into any
// method yet. Verification shells out to Barretenberg's `bb verify`; there is
// no native Go UltraHonk verifier.
package zkproof

import (
	"bytes"
	"context"
	"encoding/hex"
	"errors"
	"fmt"
	"math/big"
	"os"
	"os/exec"
	"path/filepath"
	"time"
)

// FieldSize is the byte length of one BN254 field element in a public-inputs
// file.
const FieldSize = 32

// ProofSize is the byte length of every UltraHonk ZK proof bb 5.0.0 writes
// for target noir-recursive, whatever the circuit size.
const ProofSize = 14656

// VerifierTarget is the bb verifier target the wallet proves with.
const VerifierTarget = "noir-recursive"

// Nullifier types the expiry circuit outputs (zkPassport utils/constants.nr).
const (
	NullifierNonSalted     = 0
	NullifierSalted        = 1
	NullifierNonSaltedMock = 2
	NullifierSaltedMock    = 3
	NullifierNone          = 4
)

// Stage names, in chain order.
var Stages = []string{"dsc", "id", "integrity", "expiry"}

// SubProof is one stage's proof and its public inputs, exactly as bb writes
// them (proof bytes; public inputs as concatenated 32-byte big-endian fields).
type SubProof struct {
	Circuit      string // circuit variant name, e.g. sig_check_dsc_tbs_700_ecdsa_nist_p256_sha256
	Proof        []byte
	PublicInputs []byte
}

// Bundle is what the wallet sends: one sub-proof per stage.
type Bundle struct {
	DSC, ID, Integrity, Expiry SubProof
}

// Result is what a verified bundle establishes.
type Result struct {
	// RegistryRoot is the certificate registry root the DSC proof used.
	RegistryRoot [FieldSize]byte
	// Nullifier is the scoped nullifier. Same passport + same scope gives
	// the same value; it says nothing else about the passport.
	Nullifier [FieldSize]byte
	// NullifierType: NullifierNonSalted for real documents,
	// NullifierNonSaltedMock for zkPassport's mock state "ZKR".
	NullifierType int64
	// CurrentDate is the date (unix seconds) the proof says the document was
	// still valid on.
	CurrentDate int64
}

// Identifier is the uniqueness identifier the issuer keys with
// IDENTIFIER_HMAC_KEY, in the same "chip:CC:<64 hex>" shape as
// documentchip.ChipIdentifier. The country is not known (it stays on the
// phone), so the namespace is "ZK".
func (r Result) Identifier() string {
	return "chip:ZK:" + hex.EncodeToString(r.Nullifier[:])
}

// Errors. Each maps to a refusal reason with a next step (docs/zk-passport.md).
var (
	ErrMalformed       = errors.New("zkproof: malformed bundle")
	ErrUnknownCircuit  = errors.New("zkproof: circuit not in the trusted set")
	ErrProofInvalid    = errors.New("zkproof: proof does not verify")
	ErrChainBroken     = errors.New("zkproof: sub-proof commitments do not chain")
	ErrRegistryUnknown = errors.New("zkproof: certificate registry root not published by this issuer")
	ErrScope           = errors.New("zkproof: proof is for another scope")
	ErrStaleDate       = errors.New("zkproof: proof's current_date is not today")
	ErrMockDocument    = errors.New("zkproof: mock (test) document")
)

// Verifier checks bundles.
type Verifier struct {
	// BB is the path to the Barretenberg CLI (pinned version, see
	// spikes/zk-passport/package.json).
	BB string
	// VKs maps circuit variant name -> verification key bytes. Only circuits
	// listed here are accepted: a proof is only as good as the circuit its
	// vk describes, so the vk must come from the issuer, never the phone.
	VKs map[string][]byte
	// Roots are the certificate registry roots this issuer has published
	// (current and recent; see "CSCA registry" in docs/zk-passport.md).
	Roots map[[FieldSize]byte]bool
	// Scope and Subscope must match the proof's service scope.
	Scope, Subscope [FieldSize]byte
	// AllowMock accepts zkPassport mock documents (state "ZKR"). Tests only.
	AllowMock bool
	// MaxDateSkew bounds |current_date - now|. Default 36h (time zones and
	// a proof made just before midnight).
	MaxDateSkew time.Duration
	// Now is the clock; nil means time.Now.
	Now func() time.Time
}

// public input counts per stage
var wantInputs = map[string]int{"dsc": 2, "id": 2, "integrity": 2, "expiry": 8}

func fields(sp SubProof, stage string) ([][FieldSize]byte, error) {
	n := wantInputs[stage]
	if len(sp.PublicInputs) != n*FieldSize {
		return nil, fmt.Errorf("%w: %s has %d public-input bytes, want %d", ErrMalformed, stage, len(sp.PublicInputs), n*FieldSize)
	}
	if len(sp.Proof) != ProofSize {
		return nil, fmt.Errorf("%w: %s proof is %d bytes, want %d", ErrMalformed, stage, len(sp.Proof), ProofSize)
	}
	out := make([][FieldSize]byte, n)
	for i := range out {
		copy(out[i][:], sp.PublicInputs[i*FieldSize:])
	}
	return out, nil
}

func small(f [FieldSize]byte) (int64, bool) {
	v := new(big.Int).SetBytes(f[:])
	return v.Int64(), v.IsInt64()
}

// Verify checks all four sub-proofs and the links between them.
func (v *Verifier) Verify(ctx context.Context, b Bundle) (Result, error) {
	var res Result
	sps := []SubProof{b.DSC, b.ID, b.Integrity, b.Expiry}
	pub := make([][][FieldSize]byte, len(sps))
	for i, sp := range sps {
		f, err := fields(sp, Stages[i])
		if err != nil {
			return res, err
		}
		pub[i] = f
	}
	dsc, id, integ, exp := pub[0], pub[1], pub[2], pub[3]

	// Cheap checks first, before running bb.
	// dsc:       [certificate_registry_root, comm_out]
	// id:        [comm_in, comm_out]
	// integrity: [comm_in, comm_out]
	// expiry:    [comm_in, current_date, service_scope, service_subscope,
	//             param_commitment, nullifier_type, nullifier, oprf_pk_hash]
	if dsc[1] != id[0] || id[1] != integ[0] || integ[1] != exp[0] {
		return res, ErrChainBroken
	}
	if !v.Roots[dsc[0]] {
		return res, ErrRegistryUnknown
	}
	if exp[2] != v.Scope || exp[3] != v.Subscope {
		return res, ErrScope
	}
	date, ok := small(exp[1])
	now := time.Now
	if v.Now != nil {
		now = v.Now
	}
	skew := v.MaxDateSkew
	if skew == 0 {
		skew = 36 * time.Hour
	}
	if d := time.Duration(now().Unix()-date) * time.Second; !ok || d > skew || d < -skew {
		return res, ErrStaleDate
	}
	nt, ok := small(exp[5])
	switch {
	case ok && nt == NullifierNonSalted:
	case ok && nt == NullifierNonSaltedMock && v.AllowMock:
	case ok && (nt == NullifierNonSaltedMock || nt == NullifierSaltedMock):
		return res, ErrMockDocument
	default:
		// Salted (OPRF) and hidden nullifiers are phase 3; refuse for now.
		return res, fmt.Errorf("%w: nullifier type %x", ErrMalformed, exp[5])
	}
	if exp[6] == ([FieldSize]byte{}) {
		return res, fmt.Errorf("%w: empty nullifier", ErrMalformed)
	}

	for i, sp := range sps {
		vk, ok := v.VKs[sp.Circuit]
		if !ok {
			return res, fmt.Errorf("%w: %q", ErrUnknownCircuit, sp.Circuit)
		}
		if !circuitMatchesStage(sp.Circuit, Stages[i]) {
			return res, fmt.Errorf("%w: %q used for stage %s", ErrUnknownCircuit, sp.Circuit, Stages[i])
		}
		if err := v.bbVerify(ctx, vk, sp); err != nil {
			return res, fmt.Errorf("%s: %w", Stages[i], err)
		}
	}

	res.RegistryRoot = dsc[0]
	res.Nullifier = exp[6]
	res.NullifierType = nt
	res.CurrentDate = date
	return res, nil
}

// circuitMatchesStage stops a valid proof of one stage being passed off as
// another (their public-input shapes partly coincide).
func circuitMatchesStage(name, stage string) bool {
	prefix := map[string]string{
		"dsc":       "sig_check_dsc_",
		"id":        "sig_check_id_data_",
		"integrity": "data_check_integrity_",
		"expiry":    "compare_expiry",
	}[stage]
	return len(name) >= len(prefix) && name[:len(prefix)] == prefix
}

func (v *Verifier) bbVerify(ctx context.Context, vk []byte, sp SubProof) error {
	dir, err := os.MkdirTemp("", "zkproof-")
	if err != nil {
		return err
	}
	defer os.RemoveAll(dir)
	for name, data := range map[string][]byte{"vk": vk, "proof": sp.Proof, "public_inputs": sp.PublicInputs} {
		if err := os.WriteFile(filepath.Join(dir, name), data, 0o600); err != nil {
			return err
		}
	}
	ctx, cancel := context.WithTimeout(ctx, 30*time.Second)
	defer cancel()
	cmd := exec.CommandContext(ctx, v.BB, "verify", "-t", VerifierTarget,
		"-k", filepath.Join(dir, "vk"), "-p", filepath.Join(dir, "proof"), "-i", filepath.Join(dir, "public_inputs"))
	var stderr bytes.Buffer
	cmd.Stderr = &stderr
	if err := cmd.Run(); err != nil {
		var ee *exec.ExitError
		if errors.As(err, &ee) {
			return ErrProofInvalid
		}
		return fmt.Errorf("zkproof: running bb: %w", err)
	}
	return nil
}
