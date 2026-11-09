package server

import (
	"strings"
	"unicode/utf8"

	"github.com/botmux-ai/botmux-platform/internal/proxy"
)

// WHATWG URL helpers for the machine subdomain handler. machine.ts derives
// every authorization decision from `new URL(req.url, base)`: pathname keeps
// percent-escapes but resolves dot segments, and searchParams re-serializes
// the query with the urlencoded serializer. Deciding on a different spelling
// of the path than Node would let `/s/../api/x` (terminal, anonymous guest in
// Go) reach a path Node treats as the authenticated dashboard.

// whatwgPathname is proxy.WHATWGPathname (shared with the proxy layer's
// webhook decision).
func whatwgPathname(escaped string) string {
	return proxy.WHATWGPathname(escaped)
}

// jsEncodeURIComponent percent-encodes everything outside
// A-Z a-z 0-9 - _ . ! ~ * ' ( ) (url.QueryEscape differs on space, '~', '!',
// '*', '\”, '(' and ')').
func jsEncodeURIComponent(value string) string {
	const upperHex = "0123456789ABCDEF"
	value = strings.ToValidUTF8(value, string(utf8.RuneError))
	var b strings.Builder
	for i := 0; i < len(value); i++ {
		c := value[i]
		if (c >= 'A' && c <= 'Z') || (c >= 'a' && c <= 'z') || (c >= '0' && c <= '9') ||
			strings.IndexByte("-_.!~*'()", c) >= 0 {
			b.WriteByte(c)
			continue
		}
		b.WriteByte('%')
		b.WriteByte(upperHex[c>>4])
		b.WriteByte(upperHex[c&0xF])
	}
	return b.String()
}

// searchParam is one URLSearchParams entry (order and duplicates kept).
type searchParam struct{ name, value string }

func parseSearchParams(rawQuery string) []searchParam {
	var params []searchParam
	for _, part := range strings.Split(rawQuery, "&") {
		if part == "" {
			continue
		}
		name, value, _ := strings.Cut(part, "=")
		params = append(params, searchParam{name: formDecodeComponent(name), value: formDecodeComponent(value)})
	}
	return params
}

func hasSearchParam(params []searchParam, name string) bool {
	for _, param := range params {
		if param.name == name {
			return true
		}
	}
	return false
}

// setSearchParam is URLSearchParams#set: replace the first entry with name,
// drop the others, append when absent.
func setSearchParam(params []searchParam, name, value string) []searchParam {
	out := make([]searchParam, 0, len(params)+1)
	found := false
	for _, param := range params {
		if param.name != name {
			out = append(out, param)
			continue
		}
		if !found {
			out = append(out, searchParam{name: name, value: value})
			found = true
		}
	}
	if !found {
		out = append(out, searchParam{name: name, value: value})
	}
	return out
}

func deleteSearchParam(params []searchParam, name string) []searchParam {
	out := make([]searchParam, 0, len(params))
	for _, param := range params {
		if param.name != name {
			out = append(out, param)
		}
	}
	return out
}

// serializeSearch renders URL#search after a searchParams mutation: "" for an
// empty list, otherwise "?" + the urlencoded serialization.
func serializeSearch(params []searchParam) string {
	if len(params) == 0 {
		return ""
	}
	parts := make([]string, 0, len(params))
	for _, param := range params {
		parts = append(parts, formEncodeComponent(param.name)+"="+formEncodeComponent(param.value))
	}
	return "?" + strings.Join(parts, "&")
}

func formDecodeComponent(value string) string {
	value = strings.ReplaceAll(value, "+", " ")
	out := make([]byte, 0, len(value))
	for i := 0; i < len(value); i++ {
		if value[i] == '%' && i+2 < len(value) {
			hi, ok1 := hexValue(value[i+1])
			lo, ok2 := hexValue(value[i+2])
			if ok1 && ok2 {
				out = append(out, hi<<4|lo)
				i += 2
				continue
			}
		}
		out = append(out, value[i])
	}
	return strings.ToValidUTF8(string(out), string(utf8.RuneError))
}

func formEncodeComponent(value string) string {
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

func hexValue(c byte) (byte, bool) {
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
