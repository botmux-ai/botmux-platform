package server

import (
	"net/http"
	"strings"
	"unicode/utf8"
)

// WHATWG URL primitives the TypeScript handlers get from `new URL(req.url,
// base)` / URLSearchParams. Go's net/url differs in ways that change routing
// or the bytes forwarded to a daemon (dot segments are kept, ';' splits
// queries, malformed escapes drop a pair, '~' and '*' are escaped
// differently), so the B4 handlers use these instead.

// urlFormPair is one application/x-www-form-urlencoded entry.
type urlFormPair struct{ name, value string }

// parseURLSearchParams follows the WHATWG urlencoded parser: keep order and
// duplicates, split on '&' only, '+' is a space, malformed escapes stay
// literal and invalid UTF-8 becomes U+FFFD.
func parseURLSearchParams(query string) []urlFormPair {
	var pairs []urlFormPair
	for _, part := range strings.Split(query, "&") {
		if part == "" {
			continue
		}
		name, value, _ := strings.Cut(part, "=")
		pairs = append(pairs, urlFormPair{name: urlFormDecode(name), value: urlFormDecode(value)})
	}
	return pairs
}

// searchParamGet is URLSearchParams#get: the first value for name.
func searchParamGet(pairs []urlFormPair, name string) (string, bool) {
	for _, pair := range pairs {
		if pair.name == name {
			return pair.value, true
		}
	}
	return "", false
}

// serializeURLSearchParams is URLSearchParams#toString.
func serializeURLSearchParams(pairs []urlFormPair) string {
	parts := make([]string, 0, len(pairs))
	for _, pair := range pairs {
		parts = append(parts, urlFormEncode(pair.name)+"="+urlFormEncode(pair.value))
	}
	return strings.Join(parts, "&")
}

func urlFormDecode(value string) string {
	value = strings.ReplaceAll(value, "+", " ")
	out := make([]byte, 0, len(value))
	for i := 0; i < len(value); i++ {
		if value[i] == '%' && i+2 < len(value) {
			hi, ok1 := urlHexDigit(value[i+1])
			lo, ok2 := urlHexDigit(value[i+2])
			if ok1 && ok2 {
				out = append(out, hi<<4|lo)
				i += 2
				continue
			}
		}
		out = append(out, value[i])
	}
	if utf8.Valid(out) {
		return string(out)
	}
	var b strings.Builder
	for i := 0; i < len(out); {
		r, size := utf8.DecodeRune(out[i:])
		if r == utf8.RuneError && size == 1 {
			b.WriteRune(utf8.RuneError)
		} else {
			b.Write(out[i : i+size])
		}
		i += size
	}
	return b.String()
}

func urlHexDigit(c byte) (byte, bool) {
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

const urlUpperHex = "0123456789ABCDEF"

// urlFormEncode is the urlencoded byte serializer: space -> '+', only
// *-._ and alphanumerics stay literal.
func urlFormEncode(value string) string {
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
			b.WriteByte(urlUpperHex[c>>4])
			b.WriteByte(urlUpperHex[c&0xF])
		}
	}
	return b.String()
}

// requestPathname is url.pathname of `new URL(req.url, base)`.
func requestPathname(r *http.Request) string {
	return whatwgPathname(r.URL.EscapedPath())
}

// requestSearchParams is `new URL(req.url, base).searchParams`.
func requestSearchParams(r *http.Request) []urlFormPair {
	return parseURLSearchParams(r.URL.RawQuery)
}

// uriComponentDecode mirrors decodeURIComponent, including its URIError
// cases (malformed escapes and invalid UTF-8 such as %ff), which
// url.PathUnescape would silently accept.
func uriComponentDecode(value string) (string, bool) {
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
		lead, ok := percentByte(value, i)
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
			next, ok := percentByte(value, i)
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
