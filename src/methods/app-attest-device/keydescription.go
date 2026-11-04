package appattestdevice

import (
	"encoding/asn1"
	"errors"
	"fmt"
)

// OIDAndroidKeyAttestation is the X.509 extension Android KeyMint/Keymaster
// writes into the leaf certificate of an attested key (KeyDescription).
var OIDAndroidKeyAttestation = asn1.ObjectIdentifier{1, 3, 6, 1, 4, 1, 11129, 2, 1, 17}

// SecurityLevel is where the attested key lives (KeyDescription
// attestationSecurityLevel / keyMintSecurityLevel).
type SecurityLevel int

const (
	SecurityLevelSoftware           SecurityLevel = 0
	SecurityLevelTrustedEnvironment SecurityLevel = 1
	SecurityLevelStrongBox          SecurityLevel = 2
)

func (s SecurityLevel) String() string {
	switch s {
	case SecurityLevelSoftware:
		return "software"
	case SecurityLevelTrustedEnvironment:
		return "tee"
	case SecurityLevelStrongBox:
		return "strongbox"
	default:
		return fmt.Sprintf("unknown(%d)", int(s))
	}
}

// VerifiedBootState is RootOfTrust.verifiedBootState.
type VerifiedBootState int

const (
	BootVerified   VerifiedBootState = 0 // locked, booting the OEM's signed image
	BootSelfSigned VerifiedBootState = 1 // locked with a user-installed key (custom ROM)
	BootUnverified VerifiedBootState = 2 // bootloader unlocked
	BootFailed     VerifiedBootState = 3
)

// KeyOriginGenerated is the KeyMint origin value for a key generated inside
// the secure hardware (as opposed to imported, which proves nothing).
const KeyOriginGenerated = 0

// AuthorizationList tags this verifier reads (see the KeyMint
// KeyDescription schema). All others are ignored.
const (
	tagOrigin                   = 702
	tagRootOfTrust              = 704
	tagOSPatchLevel             = 706
	tagAttestationApplicationID = 709
	tagAttestationIDModel       = 717
)

// KeyDescription is the parsed attestation extension: only the fields this
// package checks.
type KeyDescription struct {
	AttestationVersion       int
	AttestationSecurityLevel SecurityLevel
	KeyMintVersion           int
	KeyMintSecurityLevel     SecurityLevel
	Challenge                []byte

	// From the hardware-enforced list. RootOfTrust is nil when the TEE did
	// not put one there (software-only keystores).
	RootOfTrust *RootOfTrust
	// Origin is -1 when the hardware list has no origin tag.
	Origin       int
	OSPatchLevel int
	// Model is set only when the app asked for device properties
	// (setDevicePropertiesAttestationIncluded, Android 12+). Not unique.
	Model string

	// From the software-enforced list: keystore (Android itself) fills
	// these in, which is fine because Android's own integrity is what the
	// root of trust vouches for.
	ApplicationID *AttestationApplicationID
}

// RootOfTrust is the device's boot state as the TEE saw it.
type RootOfTrust struct {
	VerifiedBootKey   []byte
	DeviceLocked      bool
	VerifiedBootState VerifiedBootState
}

// AttestationApplicationID names the app(s) that own the key: package names
// and the SHA-256 digests of their APK signing certificates.
type AttestationApplicationID struct {
	PackageNames     []string
	SignatureDigests [][]byte
}

type asn1KeyDescription struct {
	AttestationVersion       int
	AttestationSecurityLevel asn1.Enumerated
	KeyMintVersion           int
	KeyMintSecurityLevel     asn1.Enumerated
	AttestationChallenge     []byte
	UniqueID                 []byte
	SoftwareEnforced         asn1.RawValue
	HardwareEnforced         asn1.RawValue
}

type asn1RootOfTrust struct {
	VerifiedBootKey   []byte
	DeviceLocked      bool
	VerifiedBootState asn1.Enumerated
	VerifiedBootHash  []byte `asn1:"optional"`
}

type asn1PackageInfo struct {
	PackageName []byte
	Version     int64
}

type asn1AttestationApplicationID struct {
	PackageInfos     []asn1PackageInfo `asn1:"set"`
	SignatureDigests [][]byte          `asn1:"set"`
}

// ParseKeyDescription decodes the DER value of the attestation extension.
// It is strict: trailing bytes, duplicate tags, or a malformed field are
// errors, because a lenient parser is how two verifiers end up disagreeing
// about what a certificate says.
func ParseKeyDescription(der []byte) (*KeyDescription, error) {
	var raw asn1KeyDescription
	rest, err := asn1.Unmarshal(der, &raw)
	if err != nil {
		return nil, fmt.Errorf("key description: %w", err)
	}
	if len(rest) != 0 {
		return nil, errors.New("key description: trailing data")
	}
	kd := &KeyDescription{
		AttestationVersion:       raw.AttestationVersion,
		AttestationSecurityLevel: SecurityLevel(raw.AttestationSecurityLevel),
		KeyMintVersion:           raw.KeyMintVersion,
		KeyMintSecurityLevel:     SecurityLevel(raw.KeyMintSecurityLevel),
		Challenge:                raw.AttestationChallenge,
		Origin:                   -1,
	}

	sw, err := authorizationList(raw.SoftwareEnforced)
	if err != nil {
		return nil, fmt.Errorf("softwareEnforced: %w", err)
	}
	hw, err := authorizationList(raw.HardwareEnforced)
	if err != nil {
		return nil, fmt.Errorf("hardwareEnforced: %w", err)
	}

	if el, ok := hw[tagRootOfTrust]; ok {
		var rot asn1RootOfTrust
		if err := unmarshalExact(el.Bytes, &rot); err != nil {
			return nil, fmt.Errorf("rootOfTrust: %w", err)
		}
		kd.RootOfTrust = &RootOfTrust{
			VerifiedBootKey:   rot.VerifiedBootKey,
			DeviceLocked:      rot.DeviceLocked,
			VerifiedBootState: VerifiedBootState(rot.VerifiedBootState),
		}
	}
	if el, ok := hw[tagOrigin]; ok {
		if err := unmarshalExact(el.Bytes, &kd.Origin); err != nil {
			return nil, fmt.Errorf("origin: %w", err)
		}
	}
	if el, ok := hw[tagOSPatchLevel]; ok {
		if err := unmarshalExact(el.Bytes, &kd.OSPatchLevel); err != nil {
			return nil, fmt.Errorf("osPatchLevel: %w", err)
		}
	}
	if el, ok := hw[tagAttestationIDModel]; ok {
		var model []byte
		if err := unmarshalExact(el.Bytes, &model); err != nil {
			return nil, fmt.Errorf("attestationIdModel: %w", err)
		}
		kd.Model = string(model)
	}
	if el, ok := sw[tagAttestationApplicationID]; ok {
		var wrapped []byte // the value is an OCTET STRING holding DER
		if err := unmarshalExact(el.Bytes, &wrapped); err != nil {
			return nil, fmt.Errorf("attestationApplicationId: %w", err)
		}
		var app asn1AttestationApplicationID
		if err := unmarshalExact(wrapped, &app); err != nil {
			return nil, fmt.Errorf("attestationApplicationId: %w", err)
		}
		id := &AttestationApplicationID{SignatureDigests: app.SignatureDigests}
		for _, p := range app.PackageInfos {
			id.PackageNames = append(id.PackageNames, string(p.PackageName))
		}
		kd.ApplicationID = id
	}
	return kd, nil
}

// authorizationList splits an AuthorizationList SEQUENCE into its
// explicitly-tagged elements, keyed by tag number.
func authorizationList(seq asn1.RawValue) (map[int]asn1.RawValue, error) {
	if seq.Class != asn1.ClassUniversal || seq.Tag != asn1.TagSequence || !seq.IsCompound {
		return nil, errors.New("not a SEQUENCE")
	}
	out := map[int]asn1.RawValue{}
	rest := seq.Bytes
	for len(rest) > 0 {
		var el asn1.RawValue
		var err error
		rest, err = asn1.Unmarshal(rest, &el)
		if err != nil {
			return nil, err
		}
		if el.Class != asn1.ClassContextSpecific || !el.IsCompound {
			return nil, fmt.Errorf("element with tag %d is not an explicit context tag", el.Tag)
		}
		if _, dup := out[el.Tag]; dup {
			return nil, fmt.Errorf("duplicate tag %d", el.Tag)
		}
		out[el.Tag] = el
	}
	return out, nil
}

func unmarshalExact(der []byte, v any) error {
	rest, err := asn1.Unmarshal(der, v)
	if err != nil {
		return err
	}
	if len(rest) != 0 {
		return errors.New("trailing data")
	}
	return nil
}
