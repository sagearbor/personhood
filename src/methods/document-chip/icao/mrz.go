package icao

import (
	"encoding/asn1"
	"errors"
	"fmt"
	"strings"
	"time"
)

// MRZ is the part of a machine readable zone the issuer needs. It holds
// personal data only in memory: callers must not store or log it.
type MRZ struct {
	DocumentCode   string // "P", "I", "ID", "AC", ...
	IssuingState   string // ICAO alpha-3 ("USA", "D", "UTO")
	DocumentNumber string // without filler '<'
	DateOfBirth    string // YYMMDD as printed
	DateOfExpiry   string // YYMMDD as printed
}

// ErrMRZ is wrapped by MRZ parsing and check digit failures.
var ErrMRZ = errors.New("icao: invalid MRZ")

// CheckDigit computes the ICAO 9303 Part 3 check digit (weights 7,3,1).
func CheckDigit(s string) (byte, error) {
	weights := [3]int{7, 3, 1}
	sum := 0
	for i := 0; i < len(s); i++ {
		c := s[i]
		var v int
		switch {
		case c >= '0' && c <= '9':
			v = int(c - '0')
		case c >= 'A' && c <= 'Z':
			v = int(c-'A') + 10
		case c == '<':
			v = 0
		default:
			return 0, fmt.Errorf("%w: character %q", ErrMRZ, c)
		}
		sum += v * weights[i%3]
	}
	return byte('0' + sum%10), nil
}

func checkField(field string, digit byte) error {
	want, err := CheckDigit(field)
	if err != nil {
		return err
	}
	// '<' as a check digit stands for 0 on some documents.
	if digit == '<' {
		digit = '0'
	}
	if digit != want {
		return fmt.Errorf("%w: check digit for %q", ErrMRZ, field)
	}
	return nil
}

// ParseMRZ parses a TD1 (3x30), TD2 (2x36) or TD3 (2x44) MRZ, given as the
// concatenated lines, and verifies its check digits.
func ParseMRZ(mrz string) (*MRZ, error) {
	mrz = strings.ToUpper(strings.NewReplacer("\n", "", "\r", "", " ", "").Replace(mrz))
	switch len(mrz) {
	case 90:
		return parseTD1(mrz)
	case 72:
		return parseTD23(mrz, 36)
	case 88:
		return parseTD23(mrz, 44)
	}
	return nil, fmt.Errorf("%w: length %d", ErrMRZ, len(mrz))
}

func trimFiller(s string) string { return strings.TrimRight(s, "<") }

// parseTD23 handles TD2 and TD3: line 2 = number(9) cd nat(3) dob(6) cd sex
// exp(6) cd optional cd? composite.
func parseTD23(mrz string, lineLen int) (*MRZ, error) {
	l1, l2 := mrz[:lineLen], mrz[lineLen:]
	m := &MRZ{
		DocumentCode: trimFiller(l1[0:2]),
		IssuingState: trimFiller(l1[2:5]),
		DateOfBirth:  l2[13:19],
		DateOfExpiry: l2[21:27],
	}
	num := l2[0:9]
	numCD := l2[9]
	optional := l2[28 : lineLen-1]
	if lineLen == 44 {
		optional = l2[28:42]
	}
	if numCD == '<' && lineLen == 36 {
		// TD2 long document number: continues in the optional data, its
		// check digit is the last character before the filler.
		ext := trimFiller(optional)
		if len(ext) < 1 {
			return nil, fmt.Errorf("%w: long document number", ErrMRZ)
		}
		num += ext[:len(ext)-1]
		numCD = ext[len(ext)-1]
	}
	if err := checkField(num, numCD); err != nil {
		return nil, err
	}
	if err := checkField(m.DateOfBirth, l2[19]); err != nil {
		return nil, err
	}
	if err := checkField(m.DateOfExpiry, l2[27]); err != nil {
		return nil, err
	}
	var composite string
	if lineLen == 44 {
		if err := checkField(l2[28:42], l2[42]); err != nil {
			return nil, err
		}
		composite = l2[0:10] + l2[13:20] + l2[21:43]
	} else {
		composite = l2[0:10] + l2[13:20] + l2[21:35]
	}
	if err := checkField(composite, l2[lineLen-1]); err != nil {
		return nil, err
	}
	m.DocumentNumber = trimFiller(num)
	return m, nil
}

// parseTD1: line 1 = code(2) state(3) number(9) cd optional(15); line 2 =
// dob(6) cd sex exp(6) cd nat(3) optional(11) composite.
func parseTD1(mrz string) (*MRZ, error) {
	l1, l2 := mrz[0:30], mrz[30:60]
	m := &MRZ{
		DocumentCode: trimFiller(l1[0:2]),
		IssuingState: trimFiller(l1[2:5]),
		DateOfBirth:  l2[0:6],
		DateOfExpiry: l2[8:14],
	}
	num := l1[5:14]
	numCD := l1[14]
	if numCD == '<' {
		ext := trimFiller(l1[15:30])
		if len(ext) < 1 {
			return nil, fmt.Errorf("%w: long document number", ErrMRZ)
		}
		num += ext[:len(ext)-1]
		numCD = ext[len(ext)-1]
	}
	if err := checkField(num, numCD); err != nil {
		return nil, err
	}
	if err := checkField(m.DateOfBirth, l2[6]); err != nil {
		return nil, err
	}
	if err := checkField(m.DateOfExpiry, l2[14]); err != nil {
		return nil, err
	}
	composite := l1[5:30] + l2[0:7] + l2[8:15] + l2[18:29]
	if err := checkField(composite, l2[29]); err != nil {
		return nil, err
	}
	m.DocumentNumber = trimFiller(num)
	return m, nil
}

// ParseDG1 reads EF.DG1 (tag 0x61 holding tag 0x5F1F, the MRZ).
func ParseDG1(dg1 []byte) (*MRZ, error) {
	var outer asn1.RawValue
	if _, err := asn1.Unmarshal(dg1, &outer); err != nil || outer.Class != asn1.ClassApplication || outer.Tag != 1 {
		return nil, fmt.Errorf("%w: EF.DG1 is not tag 0x61", ErrMRZ)
	}
	var inner asn1.RawValue
	if _, err := asn1.Unmarshal(outer.Bytes, &inner); err != nil || inner.Class != asn1.ClassApplication || inner.Tag != 0x1F {
		return nil, fmt.Errorf("%w: EF.DG1 has no MRZ (tag 0x5F1F)", ErrMRZ)
	}
	return ParseMRZ(string(inner.Bytes))
}

// ExpiryDate returns the expiry date. Two-digit years are 20YY: documents
// are valid for at most ten years, so expiry dates are never in the 1900s
// for a document that is still in circulation.
func (m *MRZ) ExpiryDate() (time.Time, error) {
	t, err := time.Parse("060102", m.DateOfExpiry)
	if err != nil {
		return time.Time{}, fmt.Errorf("%w: expiry date %q", ErrMRZ, m.DateOfExpiry)
	}
	return time.Date(2000+t.Year()%100, t.Month(), t.Day(), 0, 0, 0, 0, time.UTC), nil
}

// Expired reports whether the document has expired as of now. A document is
// valid through the whole of its expiry day.
func (m *MRZ) Expired(now time.Time) (bool, error) {
	exp, err := m.ExpiryDate()
	if err != nil {
		return false, err
	}
	return now.UTC().After(exp.Add(24 * time.Hour)), nil
}
