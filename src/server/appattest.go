package server

import (
	"fmt"
	"os"
	"strconv"
	"strings"

	appattestmethod "github.com/sagearbor/personhood/src/methods/app-attest-device"
)

// appAttestFromEnv builds the app-attest-device method from the
// environment, or returns nil when neither verifier is configured (the
// default: the method is not registered).
//
//	ANDROID_KEY_ATTESTATION_PACKAGE     Android application id whose keys are
//	                                    accepted (e.g. org.openline.wallet).
//	                                    Setting it turns Android Key
//	                                    Attestation on for platform "android".
//	ANDROID_KEY_ATTESTATION_SIGNER_SHA256
//	                                    comma-separated SHA-256 digests of the
//	                                    APK signing certificate(s). Optional;
//	                                    without it any app using that package
//	                                    name passes (still only on a real,
//	                                    locked phone).
//	ANDROID_KEY_ATTESTATION_REVOCATION  off | fail-open (default) | fail-closed
//	ANDROID_KEY_ATTESTATION_STATUS_URL  status list URL (default Google's)
//	ANDROID_KEY_ATTESTATION_MAX_PER_DEVICE
//	                                    sessions allowed per short-lived device
//	                                    hint (0 or unset: no limit)
//	APP_ATTEST_SECRET                   HMAC dev stand-in; serves platform
//	                                    "ios" (and "android" too when the
//	                                    package above is unset)
func appAttestFromEnv() (*appattestmethod.Method, error) {
	pkg := strings.TrimSpace(os.Getenv("ANDROID_KEY_ATTESTATION_PACKAGE"))
	secret := os.Getenv("APP_ATTEST_SECRET")
	if pkg == "" && secret == "" {
		return nil, nil
	}

	cfg := appattestmethod.Config{Store: appattestmethod.NewInMemoryStore()}
	if pkg == "" {
		// Unchanged pre-Android-attestation behaviour.
		cfg.Verifier = appattestmethod.NewHMACDevVerifier(secret)
		return appattestmethod.NewMethod(cfg), nil
	}

	signers, err := appattestmethod.ParseSignerDigests(os.Getenv("ANDROID_KEY_ATTESTATION_SIGNER_SHA256"))
	if err != nil {
		return nil, fmt.Errorf("ANDROID_KEY_ATTESTATION_SIGNER_SHA256: %w", err)
	}
	mode, err := appattestmethod.ParseRevocationMode(os.Getenv("ANDROID_KEY_ATTESTATION_REVOCATION"))
	if err != nil {
		return nil, fmt.Errorf("ANDROID_KEY_ATTESTATION_REVOCATION: %w", err)
	}
	akc := appattestmethod.AndroidKeyConfig{PackageName: pkg, SignerDigests: signers}
	if mode != appattestmethod.RevocationOff {
		akc.Revocation = appattestmethod.NewStatusList(appattestmethod.StatusListConfig{
			URL:  strings.TrimSpace(os.Getenv("ANDROID_KEY_ATTESTATION_STATUS_URL")),
			Mode: mode,
		})
	}
	router := appattestmethod.PlatformRouter{
		appattestmethod.PlatformAndroid: appattestmethod.NewAndroidKeyVerifier(akc),
	}
	if secret != "" {
		router[appattestmethod.PlatformIOS] = appattestmethod.NewHMACDevVerifier(secret)
	}
	cfg.Verifier = router

	if v := strings.TrimSpace(os.Getenv("ANDROID_KEY_ATTESTATION_MAX_PER_DEVICE")); v != "" {
		n, err := strconv.Atoi(v)
		if err != nil || n < 0 {
			return nil, fmt.Errorf("ANDROID_KEY_ATTESTATION_MAX_PER_DEVICE: %q is not a non-negative integer", v)
		}
		if n > 0 {
			cfg.HintLimiter = appattestmethod.NewInMemoryHintLimiter(n, 0)
		}
	}
	return appattestmethod.NewMethod(cfg), nil
}
