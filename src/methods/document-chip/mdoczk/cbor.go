package mdoczk

import (
	"errors"
	"fmt"
	"math"
)

// A minimal CBOR (RFC 8949) encoder and decoder: enough for ISO/IEC 18013-5
// structures (maps, arrays, byte and text strings, tags, small integers,
// null, booleans). No floats, no indefinite lengths. The issuer only needs
// it to rebuild the session transcript and, in tests, to mint test mdocs;
// the phone parses the real DeviceResponse.

// CBOR is an already-encoded data item, written as is.
type CBOR []byte

// Tag is a tagged data item (e.g. Tag{24, CBOR(...)} for embedded CBOR,
// Tag{0, "2026-01-01T00:00:00Z"} for a tdate).
type Tag struct {
	Number uint64
	Value  any
}

// Pair is one map entry; maps are encoded in the order given, which is how
// real issuers' MSOs look (the order is not canonicalised).
type Pair struct {
	Key   any
	Value any
}

// Map is an ordered CBOR map.
type Map []Pair

// Null encodes as CBOR null.
type nullT struct{}

// Null is the CBOR null value.
var Null = nullT{}

func head(major byte, n uint64) []byte {
	m := major << 5
	switch {
	case n < 24:
		return []byte{m | byte(n)}
	case n <= math.MaxUint8:
		return []byte{m | 24, byte(n)}
	case n <= math.MaxUint16:
		return []byte{m | 25, byte(n >> 8), byte(n)}
	case n <= math.MaxUint32:
		return []byte{m | 26, byte(n >> 24), byte(n >> 16), byte(n >> 8), byte(n)}
	default:
		return []byte{m | 27, byte(n >> 56), byte(n >> 48), byte(n >> 40), byte(n >> 32), byte(n >> 24), byte(n >> 16), byte(n >> 8), byte(n)}
	}
}

// Encode encodes v. Supported: CBOR, Tag, Map, []any, []byte, string, int,
// int64, uint64, bool, nil/Null.
func Encode(v any) []byte {
	switch x := v.(type) {
	case CBOR:
		return append([]byte(nil), x...)
	case nil, nullT:
		return []byte{0xf6}
	case bool:
		if x {
			return []byte{0xf5}
		}
		return []byte{0xf4}
	case int:
		return Encode(int64(x))
	case int64:
		if x >= 0 {
			return head(0, uint64(x))
		}
		return head(1, uint64(-1-x))
	case uint64:
		return head(0, x)
	case []byte:
		return append(head(2, uint64(len(x))), x...)
	case string:
		return append(head(3, uint64(len(x))), x...)
	case []any:
		out := head(4, uint64(len(x)))
		for _, e := range x {
			out = append(out, Encode(e)...)
		}
		return out
	case Map:
		out := head(5, uint64(len(x)))
		for _, p := range x {
			out = append(out, Encode(p.Key)...)
			out = append(out, Encode(p.Value)...)
		}
		return out
	case Tag:
		return append(head(6, x.Number), Encode(x.Value)...)
	default:
		panic(fmt.Sprintf("mdoczk: cannot CBOR-encode %T", v))
	}
}

// Embedded is #6.24(bstr .cbor v): v encoded, wrapped in a byte string,
// tagged 24.
func Embedded(v any) []byte {
	return Encode(Tag{24, Encode(v)})
}

// ErrCBOR is returned for malformed or unsupported CBOR.
var ErrCBOR = errors.New("mdoczk: malformed CBOR")

// Decode decodes exactly one data item filling b. Maps decode to Map (in
// wire order), arrays to []any, integers to int64, tags to Tag.
func Decode(b []byte) (any, error) {
	v, n, err := decodeAt(b, 0, 0)
	if err != nil {
		return nil, err
	}
	if n != len(b) {
		return nil, fmt.Errorf("%w: %d trailing bytes", ErrCBOR, len(b)-n)
	}
	return v, nil
}

func decodeAt(b []byte, pos, depth int) (any, int, error) {
	if depth > 16 || pos >= len(b) {
		return nil, 0, ErrCBOR
	}
	major, info := b[pos]>>5, b[pos]&0x1f
	pos++
	var n uint64
	switch {
	case info < 24:
		n = uint64(info)
	case info <= 27:
		size := 1 << (info - 24)
		if pos+size > len(b) {
			return nil, 0, ErrCBOR
		}
		for i := 0; i < size; i++ {
			n = n<<8 | uint64(b[pos+i])
		}
		pos += size
	default:
		return nil, 0, fmt.Errorf("%w: indefinite or reserved length", ErrCBOR)
	}
	switch major {
	case 0:
		if n > math.MaxInt64 {
			return nil, 0, ErrCBOR
		}
		return int64(n), pos, nil
	case 1:
		if n > math.MaxInt64 {
			return nil, 0, ErrCBOR
		}
		return -1 - int64(n), pos, nil
	case 2, 3:
		if n > uint64(len(b)-pos) {
			return nil, 0, ErrCBOR
		}
		s := b[pos : pos+int(n)]
		if major == 2 {
			return append([]byte(nil), s...), pos + int(n), nil
		}
		return string(s), pos + int(n), nil
	case 4:
		if n > uint64(len(b)) {
			return nil, 0, ErrCBOR
		}
		out := make([]any, 0, n)
		for i := uint64(0); i < n; i++ {
			v, next, err := decodeAt(b, pos, depth+1)
			if err != nil {
				return nil, 0, err
			}
			out = append(out, v)
			pos = next
		}
		return out, pos, nil
	case 5:
		if n > uint64(len(b)) {
			return nil, 0, ErrCBOR
		}
		out := make(Map, 0, n)
		for i := uint64(0); i < n; i++ {
			k, next, err := decodeAt(b, pos, depth+1)
			if err != nil {
				return nil, 0, err
			}
			v, next2, err := decodeAt(b, next, depth+1)
			if err != nil {
				return nil, 0, err
			}
			out = append(out, Pair{k, v})
			pos = next2
		}
		return out, pos, nil
	case 6:
		v, next, err := decodeAt(b, pos, depth+1)
		if err != nil {
			return nil, 0, err
		}
		return Tag{n, v}, next, nil
	default: // 7
		switch info {
		case 20:
			return false, pos, nil
		case 21:
			return true, pos, nil
		case 22:
			return Null, pos, nil
		}
		return nil, 0, fmt.Errorf("%w: unsupported simple value or float", ErrCBOR)
	}
}

// Get returns the value for a text key in m.
func (m Map) Get(key any) (any, bool) {
	for _, p := range m {
		if p.Key == key {
			return p.Value, true
		}
	}
	return nil, false
}
