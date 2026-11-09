package proxy

import (
	"net/http"
	"strings"
)

// RequestTarget returns the origin-form request target as the client sent it
// (Node's req.url). Hertz's net/http adaptor builds r.URL from its normalized
// URI (dot segments resolved, duplicate slashes merged, escapes rewritten)
// and keeps the request-line bytes in r.RequestURI. The machine subdomain
// decides on the WHATWG spelling of the raw target and forwards the raw
// target upstream, like the Node platform. Callers that rewrite a request
// (OpenAPI WebSocket, Desktop auth-query stripping) set both r.URL and
// r.RequestURI.
func RequestTarget(r *http.Request) string {
	if strings.HasPrefix(r.RequestURI, "/") {
		return r.RequestURI
	}
	if r.URL == nil {
		return "/"
	}
	return r.URL.RequestURI()
}

// SplitRequestTarget splits RequestTarget into the escaped path and the raw
// query (without "?"); a fragment in the request line is dropped like WHATWG.
func SplitRequestTarget(r *http.Request) (string, string) {
	target := RequestTarget(r)
	if i := strings.IndexByte(target, '#'); i >= 0 {
		target = target[:i]
	}
	path, query, _ := strings.Cut(target, "?")
	return path, query
}

// WHATWGPathname resolves dot segments of an escaped request path the way the
// WHATWG URL parser does for special schemes (`new URL(req.url, base)
// .pathname`): "\" separates segments, "." and "%2e" (any case) are
// single-dot segments, ".." / ".%2e" / "%2e." / "%2e%2e" pop the previous
// segment, and a trailing dot segment leaves a trailing "/". Percent-escapes
// are kept. Deciding on a different spelling than Node would let
// `/s/../api/x` (anonymous terminal guest) reach what Node treats as the
// authenticated dashboard.
func WHATWGPathname(escaped string) string {
	var segments []string
	var buf strings.Builder
	flush := func(atEnd bool) {
		segment := buf.String()
		buf.Reset()
		switch {
		case isDoubleDotSegment(segment):
			if len(segments) > 0 {
				segments = segments[:len(segments)-1]
			}
			if atEnd {
				segments = append(segments, "")
			}
		case isSingleDotSegment(segment):
			if atEnd {
				segments = append(segments, "")
			}
		default:
			segments = append(segments, segment)
		}
	}
	isSeparator := func(c byte) bool { return c == '/' || c == '\\' }
	// `new URL("//host/path", base)` is scheme-relative: the first segment
	// is an authority, not part of the path.
	if len(escaped) >= 2 && isSeparator(escaped[0]) && isSeparator(escaped[1]) {
		rest := escaped[2:]
		end := strings.IndexAny(rest, "/\\")
		if end < 0 {
			return "/"
		}
		escaped = rest[end:]
	}
	// The path-start state consumes one leading separator.
	if escaped != "" && isSeparator(escaped[0]) {
		escaped = escaped[1:]
	}
	const upperHex = "0123456789ABCDEF"
	for i := 0; i < len(escaped); i++ {
		c := escaped[i]
		if isSeparator(c) {
			flush(false)
			continue
		}
		// Bytes in the WHATWG path percent-encode set (raw non-ASCII from the
		// request line included) are escaped; existing escapes stay verbatim.
		if c <= 0x20 || c >= 0x7F || c == '"' || c == '<' || c == '>' || c == '`' || c == '{' || c == '}' {
			buf.WriteByte('%')
			buf.WriteByte(upperHex[c>>4])
			buf.WriteByte(upperHex[c&0xF])
			continue
		}
		buf.WriteByte(c)
	}
	flush(true)
	return "/" + strings.Join(segments, "/")
}

func isSingleDotSegment(segment string) bool {
	return segment == "." || strings.EqualFold(segment, "%2e")
}

func isDoubleDotSegment(segment string) bool {
	switch strings.ToLower(segment) {
	case "..", ".%2e", "%2e.", "%2e%2e":
		return true
	}
	return false
}
