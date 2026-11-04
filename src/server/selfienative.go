package server

import (
	"context"
	"crypto"
	"errors"
	"fmt"
	"os"
	"strings"

	"github.com/sagearbor/personhood/pkg/types"

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
		// Test issuers only: raw traces for threshold calibration.
		LogTraces: os.Getenv("SELFIE_NATIVE_LOG_TRACES") == "1",
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

// selfieCommitment is the face commitment from either selfie ceremony (web
// or native): both enroll into one accumulator, so they are one identity.
func selfieCommitment(verifiedMethods []types.VerifiedMethod) string {
	if c := biometricCommitmentFromVerifiedMethods(verifiedMethods, fuzzyextractorselfie.MethodID); c != "" {
		return c
	}
	return biometricCommitmentFromVerifiedMethods(verifiedMethods, fuzzyextractorselfie.NativeMethodID)
}

// isSelfieMethod reports whether id is the web or the native selfie method.
func isSelfieMethod(id string) bool {
	return id == fuzzyextractorselfie.MethodID || id == fuzzyextractorselfie.NativeMethodID
}
