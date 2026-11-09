package auth

import (
	"crypto/rand"
	"encoding/base64"
	"encoding/hex"
	"io"
	"math"
	"strconv"
	"strings"
	"unicode/utf8"
)

// Helpers in this file reproduce the JavaScript primitives the TypeScript
// auth code relies on (String.prototype.trim, UTF-16 length, Number#toString,
// decodeURIComponent, URLSearchParams serialization). Every helper exists
// because a byte-level or decision-level difference would make the two
// backends disagree on the same request.

// isJSWhitespace matches the ECMAScript WhiteSpace + LineTerminator set used
// by trim() and the \s regex class.
func isJSWhitespace(r rune) bool {
	switch r {
	case '\t', '\n', '\v', '\f', '\r', ' ',
		'\u00a0', '\u1680', '\u2028', '\u2029', '\u202f', '\u205f', '\u3000', '\ufeff':
		return true
	}
	return r >= '\u2000' && r <= '\u200a'
}

// jsTrim mirrors String.prototype.trim (Go's TrimSpace uses a different set:
// it trims U+0085 and does not trim U+FEFF).
func jsTrim(value string) string {
	return strings.TrimFunc(value, isJSWhitespace)
}

// jsLength mirrors String.prototype.length: UTF-16 code units. Invalid UTF-8
// bytes count as one unit each, like the U+FFFD a JS decoder would produce.
func jsLength(value string) int {
	n := 0
	for _, r := range value {
		if r > 0xFFFF {
			n += 2
		} else {
			n++
		}
	}
	return n
}

// jsLowerCase mirrors String.prototype.toLowerCase for decisions made against
// ASCII literals. U+0130 is the only unconditional SpecialCasing lowercase
// mapping: JS yields "i" + U+0307 while Go's simple mapping yields plain "i",
// which would let a non-ASCII path compare equal to an ASCII allowlist entry.
func jsLowerCase(value string) string {
	return strings.ToLower(strings.ReplaceAll(value, "\u0130", "i\u0307"))
}

// jsNumberString formats a float64 like Number#toString / JSON.stringify.
func jsNumberString(value float64) string {
	if math.IsNaN(value) || math.IsInf(value, 0) {
		return "null"
	}
	if value == 0 {
		return "0" // also normalizes -0, as JSON.stringify does
	}
	abs := math.Abs(value)
	if abs >= 1e-7 && abs < 1e21 {
		return strconv.FormatFloat(value, 'f', -1, 64)
	}
	formatted := strconv.FormatFloat(value, 'e', -1, 64)
	mantissa, exponent, _ := strings.Cut(formatted, "e")
	sign := exponent[:1]
	digits := strings.TrimLeft(exponent[1:], "0")
	if digits == "" {
		digits = "0"
	}
	return mantissa + "e" + sign + digits
}

func appendBoolJSONField(dst []byte, name string, value bool, first *bool) []byte {
	dst = appendFieldName(dst, name, first)
	return strconv.AppendBool(dst, value)
}

func appendNumberJSONField(dst []byte, name string, value float64, first *bool) []byte {
	dst = appendFieldName(dst, name, first)
	return append(dst, jsNumberString(value)...)
}

// decodeBase64URLLoose accepts both base64 alphabets with or without padding,
// as Buffer.from(value, 'base64url') does for every well-formed input.
func decodeBase64URLLoose(value string) ([]byte, error) {
	value = strings.TrimRight(value, "=")
	value = strings.NewReplacer("+", "-", "/", "_").Replace(value)
	return base64.RawURLEncoding.DecodeString(value)
}

func randomBytesFrom(random io.Reader, n int) []byte {
	buf := make([]byte, n)
	if _, err := io.ReadFull(random, buf); err != nil {
		panic("auth: random source failed: " + err.Error())
	}
	return buf
}

func randomBase64URLFrom(random io.Reader, n int) string {
	return base64.RawURLEncoding.EncodeToString(randomBytesFrom(random, n))
}

func randomHexFrom(random io.Reader, n int) string {
	return hex.EncodeToString(randomBytesFrom(random, n))
}

var defaultRandom io.Reader = rand.Reader

// decodeURIComponentJS mirrors decodeURIComponent, including its URIError
// cases (malformed escapes and invalid UTF-8 sequences such as %ff), which
// url.PathUnescape would silently accept.
func decodeURIComponentJS(value string) (string, bool) {
	if !strings.Contains(value, "%") {
		return value, true
	}
	out := make([]byte, 0, len(value))
	for i := 0; i < len(value); {
		if value[i] != '%' {
			out = append(out, value[i])
			i++
			continue
		}
		lead, ok := percentByteAt(value, i)
		if !ok {
			return "", false
		}
		i += 3
		if lead < 0x80 {
			out = append(out, lead)
			continue
		}
		var width int
		switch {
		case lead&0xE0 == 0xC0:
			width = 2
		case lead&0xF0 == 0xE0:
			width = 3
		case lead&0xF8 == 0xF0:
			width = 4
		default:
			return "", false
		}
		seq := []byte{lead}
		for k := 1; k < width; k++ {
			next, ok := percentByteAt(value, i)
			if !ok || next&0xC0 != 0x80 {
				return "", false
			}
			seq = append(seq, next)
			i += 3
		}
		r, size := utf8.DecodeRune(seq)
		if size != width || (r == utf8.RuneError && size == 1) {
			return "", false // overlong, surrogate or out-of-range code point
		}
		out = append(out, seq...)
	}
	return string(out), true
}

func percentByteAt(value string, i int) (byte, bool) {
	if i+2 >= len(value) || value[i] != '%' {
		return 0, false
	}
	hi, ok1 := fromHexDigit(value[i+1])
	lo, ok2 := fromHexDigit(value[i+2])
	if !ok1 || !ok2 {
		return 0, false
	}
	return hi<<4 | lo, true
}

func fromHexDigit(c byte) (byte, bool) {
	switch {
	case c >= '0' && c <= '9':
		return c - '0', true
	case c >= 'a' && c <= 'f':
		return c - 'a' + 10, true
	case c >= 'A' && c <= 'F':
		return c - 'A' + 10, true
	}
	return 0, false
}

// formPair is one entry of an application/x-www-form-urlencoded list.
type formPair struct{ name, value string }

// parseFormURLEncoded follows the WHATWG urlencoded parser (URLSearchParams):
// keep order and duplicates, '+' is a space, malformed escapes stay literal and
// invalid UTF-8 becomes U+FFFD.
func parseFormURLEncoded(input string) []formPair {
	var pairs []formPair
	for _, part := range strings.Split(input, "&") {
		if part == "" {
			continue
		}
		name, value, _ := strings.Cut(part, "=")
		pairs = append(pairs, formPair{name: formDecode(name), value: formDecode(value)})
	}
	return pairs
}

func formDecode(value string) string {
	value = strings.ReplaceAll(value, "+", " ")
	out := make([]byte, 0, len(value))
	for i := 0; i < len(value); i++ {
		if value[i] == '%' {
			if b, ok := percentByteAt(value, i); ok {
				out = append(out, b)
				i += 2
				continue
			}
		}
		out = append(out, value[i])
	}
	return replaceInvalidUTF8(string(out))
}

// replaceInvalidUTF8 substitutes U+FFFD per invalid byte, close to the WHATWG
// decoder (strings.ToValidUTF8 would collapse a whole run into one).
func replaceInvalidUTF8(value string) string {
	if utf8.ValidString(value) {
		return value
	}
	var b strings.Builder
	for i := 0; i < len(value); {
		r, size := utf8.DecodeRuneInString(value[i:])
		if r == utf8.RuneError && size == 1 {
			b.WriteRune(utf8.RuneError)
		} else {
			b.WriteString(value[i : i+size])
		}
		i += size
	}
	return b.String()
}

// formURLEncode is the WHATWG application/x-www-form-urlencoded byte
// serializer used by URLSearchParams#toString (differs from url.QueryEscape on
// '~' and on which punctuation stays literal).
func formURLEncode(value string) string {
	const upperHex = "0123456789ABCDEF"
	var b strings.Builder
	for i := 0; i < len(value); i++ {
		c := value[i]
		switch {
		case c == ' ':
			b.WriteByte('+')
		case c == '*' || c == '-' || c == '.' || c == '_' ||
			(c >= '0' && c <= '9') || (c >= 'A' && c <= 'Z') || (c >= 'a' && c <= 'z'):
			b.WriteByte(c)
		default:
			b.WriteByte('%')
			b.WriteByte(upperHex[c>>4])
			b.WriteByte(upperHex[c&0xF])
		}
	}
	return b.String()
}

func serializeFormURLEncoded(pairs []formPair) string {
	parts := make([]string, 0, len(pairs))
	for _, pair := range pairs {
		parts = append(parts, formURLEncode(pair.name)+"="+formURLEncode(pair.value))
	}
	return strings.Join(parts, "&")
}
