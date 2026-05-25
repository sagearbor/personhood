package credential

import (
	"bytes"
	"compress/gzip"
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"

	"github.com/sagearbor/personhood/pkg/types"
)

// BitString wraps the decoded bytes of a W3C Status List 2021 bitstring.
// Bits are addressed least-significant-bit-first within each byte, matching
// the W3C Status List 2021 spec (https://www.w3.org/TR/vc-status-list/).
//
// Bit 0 lives in byte[0] & 0x01; bit 7 lives in byte[0] & 0x80; bit 8 lives
// in byte[1] & 0x01; and so on.
type BitString struct {
	bytes []byte
}

// NewBitString constructs a BitString of the given length (in bits), with all
// bits cleared. The underlying byte slice is rounded up to the nearest byte.
func NewBitString(bits int) BitString {
	if bits < 0 {
		bits = 0
	}
	n := (bits + 7) / 8
	return BitString{bytes: make([]byte, n)}
}

// FromBytes wraps an existing byte slice (e.g. the decoded contents of a W3C
// Status List 2021 encodedList field). The slice is not copied; callers that
// need isolation should clone it themselves.
func FromBytes(b []byte) BitString {
	return BitString{bytes: b}
}

// Bytes returns the underlying byte slice. Mutating the slice mutates the
// BitString. Callers that need a copy should clone it.
func (b BitString) Bytes() []byte { return b.bytes }

// BitLen reports the addressable bit length (always a multiple of 8).
func (b BitString) BitLen() int { return len(b.bytes) * 8 }

// Get reports whether bit i is set. Returns false for out-of-range indices
// (matching the W3C spec's "unset bit means not revoked" semantics for any
// index past the published list length).
func (b BitString) Get(i int) bool {
	if i < 0 {
		return false
	}
	byteIdx := i / 8
	if byteIdx >= len(b.bytes) {
		return false
	}
	bitIdx := uint(i % 8)
	return (b.bytes[byteIdx]>>bitIdx)&0x01 == 1
}

// Set sets bit i. Returns an error if i is out of range.
func (b *BitString) Set(i int) error {
	if i < 0 {
		return fmt.Errorf("BitString.Set: negative index %d", i)
	}
	byteIdx := i / 8
	if byteIdx >= len(b.bytes) {
		return fmt.Errorf("BitString.Set: index %d out of range (len %d bits)", i, b.BitLen())
	}
	bitIdx := uint(i % 8)
	b.bytes[byteIdx] |= 1 << bitIdx
	return nil
}

// Encode returns the base64url-encoded gzip-compressed bitstring, matching
// the format of the encodedList field in a W3C Status List 2021 credential.
func (b BitString) Encode() (string, error) {
	var buf bytes.Buffer
	gz := gzip.NewWriter(&buf)
	if _, err := gz.Write(b.bytes); err != nil {
		return "", fmt.Errorf("BitString.Encode: gzip write: %w", err)
	}
	if err := gz.Close(); err != nil {
		return "", fmt.Errorf("BitString.Encode: gzip close: %w", err)
	}
	return base64.RawURLEncoding.EncodeToString(buf.Bytes()), nil
}

// DecodeBitString reverses Encode: base64url-decode then gunzip. The W3C
// spec uses unpadded base64url, but we tolerate padded form as well.
func DecodeBitString(encoded string) (BitString, error) {
	if encoded == "" {
		return BitString{}, errors.New("DecodeBitString: empty input")
	}
	var raw []byte
	var err error
	if raw, err = base64.RawURLEncoding.DecodeString(encoded); err != nil {
		if raw, err = base64.URLEncoding.DecodeString(encoded); err != nil {
			return BitString{}, fmt.Errorf("DecodeBitString: base64url decode: %w", err)
		}
	}
	gz, err := gzip.NewReader(bytes.NewReader(raw))
	if err != nil {
		return BitString{}, fmt.Errorf("DecodeBitString: gzip reader: %w", err)
	}
	defer gz.Close()
	out, err := io.ReadAll(gz)
	if err != nil {
		return BitString{}, fmt.Errorf("DecodeBitString: gunzip: %w", err)
	}
	return FromBytes(out), nil
}

// statusListCredentialEnvelope is a minimal subset of a W3C Status List 2021
// VC sufficient to extract the encoded bitstring.
type statusListCredentialEnvelope struct {
	CredentialSubject struct {
		Type          string `json:"type,omitempty"`
		StatusPurpose string `json:"statusPurpose,omitempty"`
		EncodedList   string `json:"encodedList"`
	} `json:"credentialSubject"`
}

// FetchStatusList retrieves a Status List 2021 credential from url and
// returns its decoded bitstring. The HTTP client must be non-nil; pass
// http.DefaultClient (or a custom client with appropriate timeouts) when in
// doubt.
func FetchStatusList(ctx context.Context, hc *http.Client, url string) (BitString, error) {
	if hc == nil {
		hc = http.DefaultClient
	}
	if url == "" {
		return BitString{}, errors.New("FetchStatusList: empty url")
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return BitString{}, fmt.Errorf("FetchStatusList: build request: %w", err)
	}
	req.Header.Set("Accept", "application/json,application/ld+json")
	resp, err := hc.Do(req)
	if err != nil {
		return BitString{}, fmt.Errorf("FetchStatusList: %s: %w", url, err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return BitString{}, fmt.Errorf("FetchStatusList: %s returned status %d", url, resp.StatusCode)
	}
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return BitString{}, fmt.Errorf("FetchStatusList: read body: %w", err)
	}
	var env statusListCredentialEnvelope
	if err := json.Unmarshal(body, &env); err != nil {
		return BitString{}, fmt.Errorf("FetchStatusList: parse credential: %w", err)
	}
	if env.CredentialSubject.EncodedList == "" {
		return BitString{}, fmt.Errorf("FetchStatusList: %s missing credentialSubject.encodedList", url)
	}
	return DecodeBitString(env.CredentialSubject.EncodedList)
}

// IsRevoked reports whether cred is revoked according to its referenced W3C
// Status List 2021 credential.
//
// If cred.CredentialStatus is nil, IsRevoked returns (false, nil) — no
// revocation is tracked for this credential. Otherwise it fetches
// cred.CredentialStatus.StatusListCredential and checks the bit at
// cred.CredentialStatus.StatusListIndex.
//
// IsRevoked does NOT verify cred's signature; callers typically run
// Verifier.Verify first, then IsRevoked.
func IsRevoked(ctx context.Context, hc *http.Client, cred types.PersonhoodCredential) (bool, error) {
	if cred.CredentialStatus == nil {
		return false, nil
	}
	if cred.CredentialStatus.Type != StatusList2021EntryType {
		return false, fmt.Errorf("IsRevoked: unsupported credentialStatus.type %q", cred.CredentialStatus.Type)
	}
	if cred.CredentialStatus.StatusListIndex < 0 {
		return false, fmt.Errorf("IsRevoked: negative statusListIndex %d", cred.CredentialStatus.StatusListIndex)
	}
	bits, err := FetchStatusList(ctx, hc, cred.CredentialStatus.StatusListCredential)
	if err != nil {
		return false, err
	}
	return bits.Get(cred.CredentialStatus.StatusListIndex), nil
}
