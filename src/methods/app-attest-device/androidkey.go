package appattestdevice

import (
	"bytes"
	"context"
	"crypto/sha256"
	"crypto/x509"
	"embed"
	"encoding/base64"
	"encoding/hex"
	"encoding/pem"
	"errors"
	"fmt"
	"strings"
	"time"
)

// Android Key Attestation verifier.
//
// What it proves: the key in the leaf certificate was generated inside the
// secure hardware (TEE or StrongBox) of a real Android phone whose
// bootloader is locked and which booted its manufacturer's signed system,
// for the app named in the certificate, in answer to this session's nonce.
// Emulators, VMs, rooted phones with an unlocked bootloader, and software
// keystores all fail.
//
// What it does NOT prove: that a unique human holds the phone. One person
// with ten phones passes ten times, and a farm of real phones passes. It
// stays a supplementary signal.
//
// Everything is checked offline against Google's pinned root keys: no call
// to Google per verification (unlike Play Integrity). The only optional
// network use is the revocation status list, fetched and cached.

//go:embed roots/*.pem
var googleRootsFS embed.FS

// GoogleRootCertificates returns Google's published hardware attestation
// roots (https://android.googleapis.com/attestation/root): the RSA root
// used since 2016 (same key, reissued with later dates) and the ECDSA P-384
// "Key Attestation CA1" root that Remote Key Provisioning chains move to
// from 2026. Pinning is by public key, so every reissue of a root is
// accepted.
func GoogleRootCertificates() []*x509.Certificate {
	entries, err := googleRootsFS.ReadDir("roots")
	if err != nil {
		panic("app-attest-device: embedded roots: " + err.Error())
	}
	var out []*x509.Certificate
	for _, e := range entries {
		b, err := googleRootsFS.ReadFile("roots/" + e.Name())
		if err != nil {
			panic("app-attest-device: embedded roots: " + err.Error())
		}
		certs, err := ParsePEMCertificates(b)
		if err != nil {
			panic("app-attest-device: embedded root " + e.Name() + ": " + err.Error())
		}
		out = append(out, certs...)
	}
	return out
}

// ParsePEMCertificates parses every CERTIFICATE block in b, in order.
func ParsePEMCertificates(b []byte) ([]*x509.Certificate, error) {
	var out []*x509.Certificate
	for {
		var block *pem.Block
		block, b = pem.Decode(b)
		if block == nil {
			break
		}
		if block.Type != "CERTIFICATE" {
			continue
		}
		c, err := x509.ParseCertificate(block.Bytes)
		if err != nil {
			return nil, err
		}
		out = append(out, c)
	}
	if len(out) == 0 {
		return nil, errors.New("no certificates")
	}
	return out, nil
}

// AndroidKeyConfig configures AndroidKeyVerifier.
type AndroidKeyConfig struct {
	// PackageName is the Android application id the key must belong to
	// (e.g. "org.openline.wallet"). Required.
	PackageName string

	// SignerDigests are SHA-256 digests of the APK signing certificate(s)
	// the app must be signed with (what `apksigner verify --print-certs`
	// prints as "certificate SHA-256 digest"). Optional but strongly
	// recommended: without it any app that calls itself PackageName passes
	// (still only on a real, locked phone).
	SignerDigests [][]byte

	// Roots overrides the pinned root certificates. Nil means
	// GoogleRootCertificates(). Tests use their own.
	Roots []*x509.Certificate

	// Revocation, when non-nil, checks every certificate in the chain
	// against Google's attestation status list.
	Revocation *StatusList

	// Now overrides the clock (tests). Nil means time.Now.
	Now func() time.Time
}

// AndroidKeyVerifier verifies Android Key Attestation certificate chains.
// Safe for concurrent use.
type AndroidKeyVerifier struct {
	pkg        string
	signers    [][]byte
	rootSPKIs  [][]byte
	roots      []*x509.Certificate
	revocation *StatusList
	now        func() time.Time
}

var _ Verifier = (*AndroidKeyVerifier)(nil)

// NewAndroidKeyVerifier builds the verifier. An empty PackageName is a
// programmer error and panics.
func NewAndroidKeyVerifier(cfg AndroidKeyConfig) *AndroidKeyVerifier {
	if strings.TrimSpace(cfg.PackageName) == "" {
		panic("app-attest-device.NewAndroidKeyVerifier: PackageName must not be empty")
	}
	roots := cfg.Roots
	if roots == nil {
		roots = GoogleRootCertificates()
	}
	v := &AndroidKeyVerifier{
		pkg:        strings.TrimSpace(cfg.PackageName),
		signers:    cfg.SignerDigests,
		roots:      roots,
		revocation: cfg.Revocation,
		now:        cfg.Now,
	}
	for _, r := range roots {
		v.rootSPKIs = append(v.rootSPKIs, r.RawSubjectPublicKeyInfo)
	}
	if v.now == nil {
		v.now = time.Now
	}
	return v
}

// ParseSignerDigests parses a comma-separated list of hex SHA-256 digests;
// colons and spaces inside a digest are ignored, so apksigner/keytool output
// can be pasted as is.
func ParseSignerDigests(s string) ([][]byte, error) {
	var out [][]byte
	for _, part := range strings.Split(s, ",") {
		h := strings.NewReplacer(":", "", " ", "").Replace(strings.TrimSpace(part))
		if h == "" {
			continue
		}
		b, err := hex.DecodeString(h)
		if err != nil || len(b) != sha256.Size {
			return nil, fmt.Errorf("signer digest %q is not 32 bytes of hex", part)
		}
		out = append(out, b)
	}
	return out, nil
}

// DecodeCertificateChain parses an Android attestation token: base64 (std
// or URL alphabet, padded or not) DER certificates, leaf first, joined
// with ",".
func DecodeCertificateChain(token string) ([]*x509.Certificate, error) {
	var out []*x509.Certificate
	for i, part := range strings.Split(token, ",") {
		part = strings.TrimSpace(part)
		der, err := decodeB64(part)
		if err != nil {
			return nil, fmt.Errorf("certificate %d: %w", i, err)
		}
		c, err := x509.ParseCertificate(der)
		if err != nil {
			return nil, fmt.Errorf("certificate %d: %w", i, err)
		}
		out = append(out, c)
	}
	return out, nil
}

func decodeB64(s string) ([]byte, error) {
	s = strings.TrimRight(s, "=")
	if strings.ContainsAny(s, "-_") {
		return base64.RawURLEncoding.DecodeString(s)
	}
	return base64.RawStdEncoding.DecodeString(s)
}

// Verify implements Verifier for Platform "android".
func (v *AndroidKeyVerifier) Verify(ctx context.Context, in AttestationInput) (Evidence, error) {
	challenge, err := hex.DecodeString(in.Nonce)
	if err != nil || len(challenge) == 0 {
		// The nonce comes from our own store, so this is a server bug.
		return Evidence{}, fmt.Errorf("app-attest-device: stored nonce is not hex: %w", err)
	}
	chain, err := DecodeCertificateChain(in.Token)
	if err != nil {
		return Evidence{}, reject("attestation_malformed", "%w", err)
	}
	return v.VerifyChain(ctx, chain, challenge)
}

// VerifyChain checks a parsed chain (leaf first) against the expected
// attestation challenge. Exposed for tests and tools.
func (v *AndroidKeyVerifier) VerifyChain(ctx context.Context, chain []*x509.Certificate, challenge []byte) (Evidence, error) {
	if len(chain) < 2 {
		return Evidence{}, reject("attestation_malformed", "chain has %d certificate(s); need the leaf and its issuers", len(chain))
	}
	if len(chain) > 10 {
		return Evidence{}, reject("attestation_malformed", "chain too long (%d)", len(chain))
	}
	if err := v.verifyChainSignatures(chain); err != nil {
		return Evidence{}, err
	}

	// The extension must be in the leaf and nowhere else. An app can ask
	// KeyMint to sign arbitrary bytes with an attested app key; if a
	// certificate with the extension were accepted as an issuer, an
	// attacker could hand-craft a "leaf" with any extension contents and
	// sign it with such a key.
	var ext []byte
	for i, c := range chain {
		for _, e := range c.Extensions {
			if !e.Id.Equal(OIDAndroidKeyAttestation) {
				continue
			}
			if i != 0 {
				return Evidence{}, reject("attestation_chain_invalid", "attestation extension in certificate %d, not only the leaf", i)
			}
			if ext != nil {
				return Evidence{}, reject("attestation_malformed", "leaf has two attestation extensions")
			}
			ext = e.Value
		}
	}
	if ext == nil {
		return Evidence{}, reject("attestation_malformed", "leaf has no key attestation extension")
	}
	kd, err := ParseKeyDescription(ext)
	if err != nil {
		return Evidence{}, reject("attestation_malformed", "%w", err)
	}

	if !bytes.Equal(kd.Challenge, challenge) {
		return Evidence{}, reject("attestation_challenge_mismatch", "challenge does not match this session's nonce")
	}
	if !hardware(kd.AttestationSecurityLevel) || !hardware(kd.KeyMintSecurityLevel) {
		return Evidence{}, reject("attestation_not_hardware", "security level %s/%s", kd.AttestationSecurityLevel, kd.KeyMintSecurityLevel)
	}
	if kd.RootOfTrust == nil {
		return Evidence{}, reject("attestation_not_hardware", "no hardware-enforced root of trust")
	}
	if kd.RootOfTrust.VerifiedBootState != BootVerified {
		return Evidence{}, reject("attestation_boot_not_verified", "verified boot state %d", kd.RootOfTrust.VerifiedBootState)
	}
	if !kd.RootOfTrust.DeviceLocked {
		return Evidence{}, reject("attestation_device_unlocked", "bootloader is unlocked")
	}
	if kd.Origin != KeyOriginGenerated {
		return Evidence{}, reject("attestation_key_not_generated", "key origin %d (imported or missing)", kd.Origin)
	}
	if err := v.checkApp(kd.ApplicationID); err != nil {
		return Evidence{}, err
	}

	if v.revocation != nil {
		if err := v.revocation.Check(ctx, chain); err != nil {
			return Evidence{}, err
		}
	}

	return Evidence{
		SecurityLevel: kd.AttestationSecurityLevel.String(),
		DeviceHint:    rkpDeviceHint(chain),
	}, nil
}

func hardware(s SecurityLevel) bool {
	return s == SecurityLevelTrustedEnvironment || s == SecurityLevelStrongBox
}

// verifyChainSignatures checks that each certificate is signed by the next,
// that every certificate is within its validity period, and that the chain
// ends at (or is signed by) a pinned Google root key.
//
// It deliberately does not use x509.Certificate.Verify: Android chains
// carry odd names and constraints on some devices, and Google's own
// guidance is to check signatures link by link and pin the root's public
// key rather than the root certificate (the RSA root has been reissued
// several times with the same key).
func (v *AndroidKeyVerifier) verifyChainSignatures(chain []*x509.Certificate) error {
	now := v.now()
	top := chain[len(chain)-1]
	topPinned := v.pinned(top)
	for i, c := range chain {
		if i == len(chain)-1 && topPinned {
			break // a pinned trust anchor: its key is what we trust, not its dates
		}
		if now.Before(c.NotBefore) || now.After(c.NotAfter) {
			return reject("attestation_chain_invalid", "certificate %d is outside its validity period (%s to %s)",
				i, c.NotBefore.Format(time.RFC3339), c.NotAfter.Format(time.RFC3339))
		}
		if i == len(chain)-1 {
			break
		}
		parent := chain[i+1]
		if !bytes.Equal(c.RawIssuer, parent.RawSubject) {
			return reject("attestation_chain_invalid", "certificate %d's issuer is not certificate %d", i, i+1)
		}
		if err := parent.CheckSignature(c.SignatureAlgorithm, c.RawTBSCertificate, c.Signature); err != nil {
			return reject("attestation_chain_invalid", "certificate %d signature: %w", i, err)
		}
	}
	if topPinned {
		return nil
	}
	for _, r := range v.roots {
		if bytes.Equal(top.RawIssuer, r.RawSubject) &&
			r.CheckSignature(top.SignatureAlgorithm, top.RawTBSCertificate, top.Signature) == nil {
			return nil
		}
	}
	return reject("attestation_untrusted_root", "chain does not end at a pinned Google attestation root")
}

func (v *AndroidKeyVerifier) pinned(c *x509.Certificate) bool {
	for _, spki := range v.rootSPKIs {
		if bytes.Equal(c.RawSubjectPublicKeyInfo, spki) {
			return true
		}
	}
	return false
}

func (v *AndroidKeyVerifier) checkApp(id *AttestationApplicationID) error {
	if id == nil {
		return reject("attestation_wrong_app", "no attestationApplicationId")
	}
	found := false
	for _, p := range id.PackageNames {
		if p == v.pkg {
			found = true
		}
	}
	if !found {
		return reject("attestation_wrong_app", "key belongs to %v, not %s", id.PackageNames, v.pkg)
	}
	if len(v.signers) == 0 {
		return nil
	}
	// Apps sharing a UID list several packages and signers; every signer
	// present must be one we accept, so a stranger's app can't ride along.
	if len(id.SignatureDigests) == 0 {
		return reject("attestation_wrong_app", "no signing certificate digest")
	}
	for _, d := range id.SignatureDigests {
		ok := false
		for _, want := range v.signers {
			if bytes.Equal(d, want) {
				ok = true
			}
		}
		if !ok {
			return reject("attestation_wrong_app", "app signed by an unexpected certificate %x", d)
		}
	}
	return nil
}

// rkpDeviceHint returns a short-lived per-device hint, or "" when there is
// no honest one.
//
// The certificate that signs the leaf is the device's attestation key.
// Under Remote Key Provisioning (Android 12+; required for devices
// launching with Android 13+, so every Pixel 10) Google issues each device
// its own short-lived attestation keys, so the same phone shows the same
// key until it rotates (days to weeks), and it is not shared with other
// phones. On older factory-provisioned phones the same "batch" key is
// shared by many thousands of devices, so there it means nothing and no
// hint is returned.
//
// RKP is recognised by the issuer of that certificate being Google's
// "Droid CA" provisioning CA. The hint is SHA-256 of its public key.
func rkpDeviceHint(chain []*x509.Certificate) string {
	if len(chain) < 3 {
		return ""
	}
	attestKey := chain[1]
	issuer := attestKey.Issuer
	google := false
	for _, o := range issuer.Organization {
		if o == "Google LLC" {
			google = true
		}
	}
	if !google || !strings.HasPrefix(issuer.CommonName, "Droid CA") {
		return ""
	}
	sum := sha256.Sum256(attestKey.RawSubjectPublicKeyInfo)
	return hex.EncodeToString(sum[:])
}
