package server

import (
	"context"
	"crypto"
	"errors"
	"fmt"
	"strings"

	appattestmethod "github.com/sagearbor/personhood/src/methods/app-attest-device"
	fuzzyextractorselfie "github.com/sagearbor/personhood/src/methods/fuzzy-extractor-selfie"
)

// selfieNativeFromEnv builds the native selfie ceremony on top of the
// SELFIE_ANCHOR web method. The device key is checked with the same
// Android Key Attestation verifier and settings as app-attest-device
// (ANDROID_KEY_ATTESTATION_PACKAGE, _SIGNER_SHA256, _REVOCATION, ...).
func selfieNativeFromEnv(web *fuzzyextractorselfie.Method) (*fuzzyextractorselfie.NativeMethod, error) {
	akv, err := androidKeyVerifierFromEnv()
	if err != nil {
		return nil, err
	}
	if akv == nil {
		return nil, fmt.Errorf("SELFIE_NATIVE=1 needs ANDROID_KEY_ATTESTATION_PACKAGE (the wallet's application id)")
	}
	return fuzzyextractorselfie.NewNativeMethod(fuzzyextractorselfie.NativeConfig{
		Web:      web,
		Attester: androidKeyAttester{v: akv},
	}), nil
}

// androidKeyAttester adapts app-attest-device's verifier to the selfie
// method's KeyAttester: verify the chain for the challenge, return the
// leaf's public key.
type androidKeyAttester struct {
	v *appattestmethod.AndroidKeyVerifier
}

func (a androidKeyAttester) VerifyAttestedKey(ctx context.Context, chain []string, challenge []byte) (crypto.PublicKey, error) {
	certs, err := appattestmethod.DecodeCertificateChain(strings.Join(chain, ","))
	if err != nil {
		return nil, &fuzzyextractorselfie.AttestationError{Reason: "attestation_malformed"}
	}
	if _, err := a.v.VerifyChain(ctx, certs, challenge); err != nil {
		var ve *appattestmethod.VerifyError
		if errors.As(err, &ve) && ve.Reason != "" {
			return nil, &fuzzyextractorselfie.AttestationError{Reason: ve.Reason}
		}
		return nil, &fuzzyextractorselfie.AttestationError{Reason: "attestation_invalid"}
	}
	return certs[0].PublicKey, nil
}
