// Package signedqr verifies government ID cards that carry a QR code signed
// by the issuing authority, readable by any phone camera (no NFC).
//
// Formats are data: a JSON file describes how to decode a family of QR
// payloads (encoding, compression, where the signature is, which field is
// which) and names the authority's certificates. Adding a country whose QR
// fits an existing family is a JSON file plus a certificate, no code. A new
// family (for example a CBOR/COSE payload) needs a new decoder here.
//
// What a valid QR proves: the authority issued these fields and this photo.
// What it does NOT prove: that the person scanning it is that person, or
// holds the card. A QR is a static blob: a photocopy, or a photo of someone
// else's card, scans just as well. The caller must bind the card's photo to
// a live face on the device, and must key uniqueness so one leaked card can
// make at most one identity.
package signedqr

import (
	"bytes"
	"compress/gzip"
	"compress/zlib"
	"crypto"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"embed"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"math/big"
	"path"
	"strings"
	"time"
)

//go:embed formats/*.json formats/*.pem
var builtin embed.FS

// Errors, for mapping to error reasons.
var (
	ErrFormatUnknown    = errors.New("signedqr: no known format matches this QR")
	ErrInvalid          = errors.New("signedqr: QR payload is malformed")
	ErrSignatureInvalid = errors.New("signedqr: signature does not verify with any trusted key")
)

// maxQRDigits bounds the decimal input (a dense QR holds ~7000 digits).
const maxQRDigits = 8000

// maxInflated bounds decompression.
const maxInflated = 64 << 10

type sliceSpec struct {
	Field       string `json:"field,omitempty"`
	From        int    `json:"from,omitempty"`
	To          int    `json:"to,omitempty"`
	PhotoSHA256 bool   `json:"photo_sha256,omitempty"`
	Layout      string `json:"layout,omitempty"`
}

// Format is one QR layout.
type Format struct {
	ID          string `json:"id"`
	Country     string `json:"country"`
	Document    string `json:"document"`
	Encoding    string `json:"encoding"`
	Compression string `json:"compression"`
	Signature   struct {
		Placement string `json:"placement"`
		Length    int    `json:"length"`
		Algorithm string `json:"algorithm"`
	} `json:"signature"`
	Delimiter int `json:"delimiter"`
	Detect    struct {
		Field int      `json:"field"`
		OneOf []string `json:"one_of"`
	} `json:"detect"`
	Fields               map[string]int `json:"fields"`
	PhotoAfterDelimiters int            `json:"photo_after_delimiters"`
	TrailingHashes       struct {
		IndicatorField string         `json:"indicator_field"`
		Bytes          map[string]int `json:"bytes"`
	} `json:"trailing_hashes"`
	SigningTime *sliceSpec  `json:"signing_time"`
	Uniqueness  []sliceSpec `json:"uniqueness"`
	Keys        []string    `json:"keys"`

	certs []*x509.Certificate
}

type formatFile struct {
	Formats []*Format `json:"formats"`
}

// Registry holds the known formats, tried in order.
type Registry struct {
	formats []*Format
}

// Builtin returns the formats shipped with this package.
func Builtin() (*Registry, error) {
	sub, err := fs.Sub(builtin, "formats")
	if err != nil {
		return nil, err
	}
	r := &Registry{}
	if err := r.LoadFS(sub); err != nil {
		return nil, err
	}
	return r, nil
}

// LoadFS adds every *.json format file in fsys; key files are resolved
// relative to the JSON file.
func (r *Registry) LoadFS(fsys fs.FS) error {
	names, err := fs.Glob(fsys, "*.json")
	if err != nil {
		return err
	}
	for _, name := range names {
		raw, err := fs.ReadFile(fsys, name)
		if err != nil {
			return err
		}
		var ff formatFile
		if err := json.Unmarshal(raw, &ff); err != nil {
			return fmt.Errorf("signedqr: %s: %w", name, err)
		}
		for _, f := range ff.Formats {
			if err := f.validate(); err != nil {
				return fmt.Errorf("signedqr: %s: %w", name, err)
			}
			for _, k := range f.Keys {
				pemData, err := fs.ReadFile(fsys, path.Join(path.Dir(name), k))
				if err != nil {
					return fmt.Errorf("signedqr: %s: key %s: %w", f.ID, k, err)
				}
				certs, err := parseCerts(pemData)
				if err != nil {
					return fmt.Errorf("signedqr: %s: key %s: %w", f.ID, k, err)
				}
				f.certs = append(f.certs, certs...)
			}
			if len(f.certs) == 0 {
				return fmt.Errorf("signedqr: %s: no keys", f.ID)
			}
			r.formats = append(r.formats, f)
		}
	}
	return nil
}

// IDs lists the loaded format ids.
func (r *Registry) IDs() []string {
	out := make([]string, 0, len(r.formats))
	for _, f := range r.formats {
		out = append(out, f.ID)
	}
	return out
}

func (f *Format) validate() error {
	switch {
	case f.ID == "" || f.Country == "" || f.Document == "":
		return errors.New("format needs id, country and document")
	case f.Encoding != "decimal-bigint":
		return fmt.Errorf("%s: unsupported encoding %q", f.ID, f.Encoding)
	case f.Compression != "zlib-or-gzip" && f.Compression != "none":
		return fmt.Errorf("%s: unsupported compression %q", f.ID, f.Compression)
	case f.Signature.Placement != "trailing" || f.Signature.Length <= 0:
		return fmt.Errorf("%s: unsupported signature placement", f.ID)
	case f.Signature.Algorithm != "rsa-pkcs1v15-sha256":
		return fmt.Errorf("%s: unsupported signature algorithm %q", f.ID, f.Signature.Algorithm)
	case f.Delimiter < 0 || f.Delimiter > 255:
		return fmt.Errorf("%s: delimiter must be a byte", f.ID)
	case len(f.Uniqueness) == 0:
		return fmt.Errorf("%s: a format must say what makes a card unique", f.ID)
	}
	for _, u := range append(append([]sliceSpec(nil), f.Uniqueness...), derefSlice(f.SigningTime)...) {
		if u.Field != "" {
			if _, ok := f.Fields[u.Field]; !ok {
				return fmt.Errorf("%s: unknown field %q", f.ID, u.Field)
			}
		}
	}
	return nil
}

func derefSlice(s *sliceSpec) []sliceSpec {
	if s == nil {
		return nil
	}
	return []sliceSpec{*s}
}

func parseCerts(pemData []byte) ([]*x509.Certificate, error) {
	var out []*x509.Certificate
	for {
		var b *pem.Block
		b, pemData = pem.Decode(pemData)
		if b == nil {
			break
		}
		if b.Type != "CERTIFICATE" {
			continue
		}
		c, err := x509.ParseCertificate(b.Bytes)
		if err != nil {
			return nil, err
		}
		if _, ok := c.PublicKey.(*rsa.PublicKey); !ok {
			return nil, errors.New("only RSA keys are supported")
		}
		out = append(out, c)
	}
	if len(out) == 0 {
		return nil, errors.New("no certificate")
	}
	return out, nil
}

// Result is a verified card. It holds no personal data: UniqueKey is a
// SHA-256 over the uniqueness fields, namespaced by country and document.
type Result struct {
	FormatID  string
	Country   string
	Document  string
	UniqueKey string    // "<COUNTRY>-<document>:<hex sha256>"
	SignedAt  time.Time // zero if the format has no signing time
	// Photo is the card's embedded photo bytes, for an on-device face
	// match. The issuer does not need it and must not keep it.
	Photo []byte
}

// Verify decodes qr, finds its format (or uses formatID if given), checks
// the signature and returns the card's uniqueness key.
func (r *Registry) Verify(qr, formatID string) (*Result, error) {
	payload, err := decodeDecimal(qr)
	if err != nil {
		return nil, err
	}
	var lastErr error = ErrFormatUnknown
	for _, f := range r.formats {
		if formatID != "" && f.ID != formatID {
			continue
		}
		data, err := f.decompress(payload)
		if err != nil {
			continue
		}
		fields := bytes.Split(data, []byte{byte(f.Delimiter)})
		if !f.detects(fields) {
			continue
		}
		res, err := f.verify(data)
		if err == nil {
			return res, nil
		}
		lastErr = err
	}
	return nil, lastErr
}

func decodeDecimal(qr string) ([]byte, error) {
	qr = strings.TrimSpace(qr)
	if qr == "" || len(qr) > maxQRDigits {
		return nil, fmt.Errorf("%w: length", ErrInvalid)
	}
	for _, c := range qr {
		if c < '0' || c > '9' {
			return nil, ErrFormatUnknown
		}
	}
	n, ok := new(big.Int).SetString(qr, 10)
	if !ok {
		return nil, ErrInvalid
	}
	return n.Bytes(), nil
}

func (f *Format) decompress(b []byte) ([]byte, error) {
	if f.Compression == "none" {
		return b, nil
	}
	var rd io.Reader
	if len(b) > 2 && b[0] == 0x1f && b[1] == 0x8b {
		g, err := gzip.NewReader(bytes.NewReader(b))
		if err != nil {
			return nil, err
		}
		rd = g
	} else {
		z, err := zlib.NewReader(bytes.NewReader(b))
		if err != nil {
			return nil, err
		}
		rd = z
	}
	out, err := io.ReadAll(io.LimitReader(rd, maxInflated+1))
	if err != nil {
		return nil, err
	}
	if len(out) > maxInflated {
		return nil, fmt.Errorf("%w: too large", ErrInvalid)
	}
	return out, nil
}

func (f *Format) detects(fields [][]byte) bool {
	if f.Detect.Field >= len(fields) {
		return false
	}
	v := string(fields[f.Detect.Field])
	for _, want := range f.Detect.OneOf {
		if v == want {
			return true
		}
	}
	return false
}

func (f *Format) verify(data []byte) (*Result, error) {
	sigLen := f.Signature.Length
	if len(data) <= sigLen {
		return nil, fmt.Errorf("%w: shorter than its signature", ErrInvalid)
	}
	signed, sig := data[:len(data)-sigLen], data[len(data)-sigLen:]

	// Fields are read from the signed part only. The photo can contain the
	// delimiter byte, so fields are taken up to photo_after_delimiters.
	fields, photoStart, err := splitFields(signed, byte(f.Delimiter), f.PhotoAfterDelimiters)
	if err != nil {
		return nil, err
	}
	field := func(name string) (string, error) {
		i, ok := f.Fields[name]
		if !ok || i >= len(fields) {
			return "", fmt.Errorf("%w: field %s missing", ErrInvalid, name)
		}
		return string(fields[i]), nil
	}

	var signedAt time.Time
	if st := f.SigningTime; st != nil {
		v, err := field(st.Field)
		if err != nil {
			return nil, err
		}
		v, err = cut(v, st.From, st.To)
		if err != nil {
			return nil, err
		}
		if signedAt, err = time.Parse(st.Layout, v); err != nil {
			return nil, fmt.Errorf("%w: signing time", ErrInvalid)
		}
	}

	digest := sha256.Sum256(signed)
	var verified bool
	for _, c := range f.certs {
		// The key must have been valid when the card's QR was signed. The
		// certificate may have expired since; the card is still genuine.
		if !signedAt.IsZero() && (signedAt.Before(c.NotBefore.Add(-24*time.Hour)) || signedAt.After(c.NotAfter.Add(24*time.Hour))) {
			continue
		}
		if rsa.VerifyPKCS1v15(c.PublicKey.(*rsa.PublicKey), crypto.SHA256, digest[:], sig) == nil {
			verified = true
			break
		}
	}
	if !verified {
		return nil, ErrSignatureInvalid
	}

	// Photo: from photoStart up to the trailing identifier hashes.
	tail := 0
	if th := f.TrailingHashes; th.IndicatorField != "" {
		ind, err := field(th.IndicatorField)
		if err != nil {
			return nil, err
		}
		n, ok := th.Bytes[ind]
		if !ok {
			return nil, fmt.Errorf("%w: indicator %q", ErrInvalid, ind)
		}
		tail = n
	}
	if photoStart > len(signed)-tail {
		return nil, fmt.Errorf("%w: no photo", ErrInvalid)
	}
	photo := signed[photoStart : len(signed)-tail]

	h := sha256.New()
	h.Write([]byte("personhood/signedqr-unique/v1"))
	for _, u := range f.Uniqueness {
		var part []byte
		if u.PhotoSHA256 {
			if len(photo) == 0 {
				return nil, fmt.Errorf("%w: empty photo", ErrInvalid)
			}
			ph := sha256.Sum256(photo)
			part = ph[:]
		} else {
			v, err := field(u.Field)
			if err != nil {
				return nil, err
			}
			if u.To > 0 {
				if v, err = cut(v, u.From, u.To); err != nil {
					return nil, err
				}
			}
			part = []byte(strings.ToUpper(strings.TrimSpace(v)))
		}
		h.Write([]byte{0})
		h.Write(part)
	}
	return &Result{
		FormatID:  f.ID,
		Country:   f.Country,
		Document:  f.Document,
		UniqueKey: f.Country + "-" + f.Document + ":" + hex.EncodeToString(h.Sum(nil)),
		SignedAt:  signedAt,
		Photo:     append([]byte(nil), photo...),
	}, nil
}

// splitFields returns the first n delimiter-separated fields and the offset
// just after the n-th delimiter.
func splitFields(b []byte, delim byte, n int) ([][]byte, int, error) {
	var fields [][]byte
	start := 0
	for i := 0; i < len(b) && len(fields) < n; i++ {
		if b[i] == delim {
			fields = append(fields, b[start:i])
			start = i + 1
		}
	}
	if len(fields) < n {
		return nil, 0, fmt.Errorf("%w: %d fields, want %d", ErrInvalid, len(fields), n)
	}
	return fields, start, nil
}

func cut(s string, from, to int) (string, error) {
	if from < 0 || to > len(s) || from >= to {
		return "", fmt.Errorf("%w: field too short", ErrInvalid)
	}
	return s[from:to], nil
}
