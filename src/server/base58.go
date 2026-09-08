package server

import "fmt"

// base58Alphabet is the Bitcoin/IPFS "base58btc" alphabet: base64's alphabet
// minus the characters that are easy to confuse in print (0, O, I, l) and
// minus "+"/"/". This is the alphabet the multibase "z" prefix denotes.
//
// Hand-rolled deliberately: every other vendor integration in this repo
// (SendGrid, Twilio, Persona, Plaid, Stripe) is a dependency-free net/http
// client, and src/credential/issue.go's doc comment already notes v0.1
// avoided a base58 dependency for the same reason. did:key needs base58btc
// to encode a multicodec-prefixed Ed25519 public key, so we implement the
// ~30-line standard algorithm here instead of importing a module.
const base58Alphabet = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"

// base58Encode implements the standard (Bitcoin-style) base58 encoding:
// leading zero bytes become leading '1' characters, and the remaining bytes
// are treated as a big-endian unsigned integer converted to base 58.
func base58Encode(input []byte) string {
	if len(input) == 0 {
		return ""
	}

	zeros := 0
	for zeros < len(input) && input[zeros] == 0 {
		zeros++
	}

	// log(256)/log(58) ~= 1.3657; +1 rounds up for integer division slack.
	size := (len(input)-zeros)*138/100 + 1
	b58 := make([]byte, size)
	length := 0
	for _, c := range input[zeros:] {
		carry := int(c)
		i := 0
		for j := size - 1; (carry != 0 || i < length) && j >= 0; j-- {
			carry += 256 * int(b58[j])
			b58[j] = byte(carry % 58)
			carry /= 58
			i++
		}
		length = i
	}

	idx := size - length
	for idx < size && b58[idx] == 0 {
		idx++
	}

	out := make([]byte, 0, zeros+(size-idx))
	for i := 0; i < zeros; i++ {
		out = append(out, '1')
	}
	for ; idx < size; idx++ {
		out = append(out, base58Alphabet[b58[idx]])
	}
	return string(out)
}

// base58Decode is the inverse of base58Encode. It returns an error if any
// input byte is outside the base58btc alphabet.
func base58Decode(s string) ([]byte, error) {
	if s == "" {
		return nil, nil
	}

	var alphabetIdx [256]int8
	for i := range alphabetIdx {
		alphabetIdx[i] = -1
	}
	for i, c := range base58Alphabet {
		alphabetIdx[byte(c)] = int8(i)
	}

	zeros := 0
	for zeros < len(s) && s[zeros] == '1' {
		zeros++
	}

	// log(58)/log(256) ~= 0.7325; +1 rounds up for integer division slack.
	size := (len(s)-zeros)*733/1000 + 1
	b256 := make([]byte, size)
	length := 0
	for i := 0; i < len(s); i++ {
		v := alphabetIdx[s[i]]
		if v < 0 {
			return nil, fmt.Errorf("base58Decode: invalid character %q at offset %d", s[i], i)
		}
		carry := int(v)
		j := 0
		for k := size - 1; (carry != 0 || j < length) && k >= 0; k-- {
			carry += 58 * int(b256[k])
			b256[k] = byte(carry % 256)
			carry /= 256
			j++
		}
		length = j
	}

	idx := size - length
	for idx < size && b256[idx] == 0 {
		idx++
	}

	out := make([]byte, 0, zeros+(size-idx))
	for i := 0; i < zeros; i++ {
		out = append(out, 0)
	}
	out = append(out, b256[idx:]...)
	return out, nil
}
