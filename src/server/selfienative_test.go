package server

import (
	"context"
	"errors"
	"testing"

	"github.com/sagearbor/personhood/pkg/types"
	fuzzyextractorselfie "github.com/sagearbor/personhood/src/methods/fuzzy-extractor-selfie"
)

func TestBuildDependencies_SelfieNative(t *testing.T) {
	t.Setenv("SELFIE_ANCHOR", "1")
	t.Setenv("SELFIE_NATIVE", "1")
	t.Setenv("FIRESTORE_PROJECT_ID", "")
	t.Setenv("REDIS_URL", "")
	t.Setenv("ANDROID_KEY_ATTESTATION_PACKAGE", "org.openline.wallet")
	t.Setenv("ANDROID_KEY_ATTESTATION_REVOCATION", "off")
	deps, err := BuildDependencies("http://example.invalid/v1/methods/email/verify", "")
	if err != nil {
		t.Fatalf("BuildDependencies: %v", err)
	}
	web, ok1 := deps.Registry.Get(fuzzyextractorselfie.MethodID)
	native, ok2 := deps.Registry.Get(fuzzyextractorselfie.NativeMethodID)
	if !ok1 || !ok2 {
		t.Fatal("SELFIE_NATIVE=1 must register both the web and the native ceremony")
	}
	if native.Metadata().Strength <= web.Metadata().Strength || native.Metadata().Type != types.MethodTypeAnchor {
		t.Fatalf("native %+v vs web %+v", native.Metadata(), web.Metadata())
	}
	ch, err := native.BeginCeremony(context.Background(), types.CeremonyContext{SessionID: "s"})
	if err != nil || ch.Payload["attestation_challenge"] == nil || ch.Payload["fallback_method"] != fuzzyextractorselfie.MethodID {
		t.Fatalf("begin: %v %+v", err, ch.Payload)
	}
}

func TestBuildDependencies_SelfieNativeNeedsAnchorAndAttestation(t *testing.T) {
	t.Setenv("FIRESTORE_PROJECT_ID", "")
	t.Setenv("REDIS_URL", "")
	t.Setenv("SELFIE_NATIVE", "1")
	t.Setenv("ANDROID_KEY_ATTESTATION_PACKAGE", "org.openline.wallet")
	if _, err := BuildDependencies("http://example.invalid/v1/methods/email/verify", ""); err == nil {
		t.Fatal("SELFIE_NATIVE without SELFIE_ANCHOR: want error")
	}
	t.Setenv("SELFIE_ANCHOR", "1")
	t.Setenv("ANDROID_KEY_ATTESTATION_PACKAGE", "")
	if _, err := BuildDependencies("http://example.invalid/v1/methods/email/verify", ""); err == nil {
		t.Fatal("SELFIE_NATIVE without ANDROID_KEY_ATTESTATION_PACKAGE: want error")
	}
}

func TestBuildDependencies_SelfieNativeOffByDefault(t *testing.T) {
	t.Setenv("SELFIE_ANCHOR", "1")
	t.Setenv("FIRESTORE_PROJECT_ID", "")
	t.Setenv("REDIS_URL", "")
	t.Setenv("ANDROID_KEY_ATTESTATION_PACKAGE", "org.openline.wallet")
	deps, err := BuildDependencies("http://example.invalid/v1/methods/email/verify", "")
	if err != nil {
		t.Fatal(err)
	}
	if _, ok := deps.Registry.Get(fuzzyextractorselfie.NativeMethodID); ok {
		t.Fatal("native selfie registered without SELFIE_NATIVE=1")
	}
}

func TestAndroidKeyAttester_RefusesGarbage(t *testing.T) {
	t.Setenv("ANDROID_KEY_ATTESTATION_PACKAGE", "org.openline.wallet")
	t.Setenv("ANDROID_KEY_ATTESTATION_REVOCATION", "off")
	akv, err := androidKeyVerifierFromEnv()
	if err != nil || akv == nil {
		t.Fatal(err)
	}
	_, err = androidKeyAttester{v: akv}.VerifyAttestedKey(context.Background(), []string{"bm90IGEgY2VydA=="}, make([]byte, 32))
	var ae *fuzzyextractorselfie.AttestationError
	if !errors.As(err, &ae) || !fuzzyextractorselfie.IsNativeFallbackReason(ae.Reason) {
		t.Fatalf("garbage chain: %v", err)
	}
}
