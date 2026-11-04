package server

import (
	"context"
	"testing"

	"github.com/sagearbor/personhood/pkg/types"
	appattestmethod "github.com/sagearbor/personhood/src/methods/app-attest-device"
)

func clearAppAttestEnv(t *testing.T) {
	for _, k := range []string{"ANDROID_KEY_ATTESTATION_PACKAGE", "ANDROID_KEY_ATTESTATION_SIGNER_SHA256",
		"ANDROID_KEY_ATTESTATION_REVOCATION", "ANDROID_KEY_ATTESTATION_STATUS_URL",
		"ANDROID_KEY_ATTESTATION_MAX_PER_DEVICE", "APP_ATTEST_SECRET"} {
		t.Setenv(k, "")
	}
}

func TestAppAttestFromEnv_OffByDefault(t *testing.T) {
	clearAppAttestEnv(t)
	m, err := appAttestFromEnv()
	if err != nil || m != nil {
		t.Fatalf("expected nothing registered, got %v, %v", m, err)
	}
}

func TestAppAttestFromEnv_DevSecretUnchanged(t *testing.T) {
	clearAppAttestEnv(t)
	t.Setenv("APP_ATTEST_SECRET", "s3cret")
	m, err := appAttestFromEnv()
	if err != nil || m == nil {
		t.Fatalf("got %v, %v", m, err)
	}
	ctx := context.Background()
	cc := types.CeremonyContext{SessionID: "sess", MethodID: appattestmethod.MethodID}
	ch, _ := m.BeginCeremony(ctx, cc)
	nonce := ch.Payload["nonce"].(string)
	tok := appattestmethod.SignDeviceTokenForTesting("s3cret", appattestmethod.PlatformAndroid, nonce, "k")
	res, _ := m.CompleteCeremony(ctx, cc, types.ResponseData{Payload: map[string]any{"platform": "android", "token": tok, "key_id": "k"}})
	if !res.Success {
		t.Fatalf("dev HMAC path must still work with only APP_ATTEST_SECRET: %+v", res)
	}
}

func TestAppAttestFromEnv_AndroidKeyAttestation(t *testing.T) {
	clearAppAttestEnv(t)
	t.Setenv("ANDROID_KEY_ATTESTATION_PACKAGE", "org.openline.wallet")
	t.Setenv("ANDROID_KEY_ATTESTATION_REVOCATION", "off")
	t.Setenv("APP_ATTEST_SECRET", "s3cret")
	m, err := appAttestFromEnv()
	if err != nil || m == nil {
		t.Fatalf("got %v, %v", m, err)
	}
	ctx := context.Background()
	cc := types.CeremonyContext{SessionID: "sess", MethodID: appattestmethod.MethodID}
	ch, _ := m.BeginCeremony(ctx, cc)
	nonce := ch.Payload["nonce"].(string)
	// With real attestation on, the dev HMAC no longer passes for Android.
	tok := appattestmethod.SignDeviceTokenForTesting("s3cret", appattestmethod.PlatformAndroid, nonce, "k")
	res, _ := m.CompleteCeremony(ctx, cc, types.ResponseData{Payload: map[string]any{"platform": "android", "token": tok}})
	if res.Success || res.ErrorReason != "attestation_malformed" {
		t.Fatalf("HMAC token must not pass Android attestation: %+v", res)
	}
}

func TestAppAttestFromEnv_BadConfig(t *testing.T) {
	for k, v := range map[string]string{
		"ANDROID_KEY_ATTESTATION_SIGNER_SHA256":  "nothex",
		"ANDROID_KEY_ATTESTATION_REVOCATION":     "maybe",
		"ANDROID_KEY_ATTESTATION_MAX_PER_DEVICE": "-1",
	} {
		clearAppAttestEnv(t)
		t.Setenv("ANDROID_KEY_ATTESTATION_PACKAGE", "org.openline.wallet")
		t.Setenv(k, v)
		if _, err := appAttestFromEnv(); err == nil {
			t.Errorf("%s=%q should be rejected", k, v)
		}
	}
}
