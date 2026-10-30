package server

import (
	"crypto/ed25519"

	"github.com/sagearbor/personhood/pkg/types"
)

// Holder proof-of-possession.
//
// A client declares a holder public key at POST /enrollment/start, and the
// credential is bound to it (did:key holder DID, nullifierBinding). Without
// a proof, anyone could declare someone else's public key and get a
// credential bound to a key they don't hold. So the start response carries
// holder_proof_message, the client signs it with the private key, and sends
// the signature as holder_proof_b64 at POST /v1/credentials/issue.
//
// The message names this issuer and the session, and the session id is a
// 256-bit random value the server chose, so a signature can't be replayed
// into another session or at another issuer.

const (
	errCodeHolderProofRequired = "holder_proof_required"
	errCodeHolderProofInvalid  = "holder_proof_invalid"
)

// HolderPoPMessage is the exact string a holder signs to prove it holds the
// key it declared for sessionID at the issuer issuerDID.
func HolderPoPMessage(issuerDID types.DID, sessionID string) string {
	return "personhood-holder-pop:v1:" + string(issuerDID) + ":" + sessionID
}

// checkHolderPoP verifies proofB64 against the session's holder key. A
// session without a holder key has nothing to prove. A missing proof is
// refused only under Config.RequireHolderPoP; a proof that is present but
// wrong is always refused.
func (s *Server) checkHolderPoP(view SessionView, proofB64 string) *apiError {
	if len(view.HolderPublicKey) != ed25519.PublicKeySize {
		return nil
	}
	if proofB64 == "" {
		if s.cfg.RequireHolderPoP {
			return &apiError{errCodeHolderProofRequired,
				"sign holder_proof_message from /enrollment/start with the holder key and send it as holder_proof_b64"}
		}
		return nil
	}
	sig, err := decodeB64Tolerant(proofB64)
	if err != nil || len(sig) != ed25519.SignatureSize ||
		!ed25519.Verify(view.HolderPublicKey, []byte(HolderPoPMessage(s.issuerDID, view.ID)), sig) {
		return &apiError{errCodeHolderProofInvalid, "holder_proof_b64 is not a valid signature over holder_proof_message by the declared holder key"}
	}
	return nil
}
