package auth

import (
	"strings"
	"unicode/utf8"
)

// SafeProxyNextPath validates a redirect target as a same-origin absolute
// path and returns it unchanged, or ok=false.
//
// WHATWG URLs treat backslashes as slashes for special schemes, so a check
// like /^\/(?!\/)/ alone would accept `/\evil.example` as cross-origin.
// Up to three percent-decoding layers are checked as defence in depth: each
// layer must start with "/", must not start with "//", and must not contain
// a backslash or a C0/DEL control character; a malformed escape rejects.
//
// The TypeScript version finally resolves the value against a placeholder
// origin and compares origins. For any value that passed the first-layer
// checks that resolution is always same-origin without credentials (a
// path-absolute reference), so it is not repeated here. Unlike JavaScript
// strings, Go strings can carry invalid UTF-8; such values are rejected.
func SafeProxyNextPath(value string) (string, bool) {
	if value == "" || !utf8.ValidString(value) || jsLength(value) > 4096 {
		return "", false
	}
	probe := value
	for i := 0; i < 3; i++ {
		if !strings.HasPrefix(probe, "/") || strings.HasPrefix(probe, "//") || strings.ContainsRune(probe, '\\') || hasControl(probe) {
			return "", false
		}
		decoded, ok := decodeURIComponentJS(probe)
		if !ok {
			return "", false
		}
		if decoded == probe {
			break
		}
		probe = decoded
	}
	return value, true
}

func hasControl(value string) bool {
	for i := 0; i < len(value); i++ {
		if value[i] < 0x20 || value[i] == 0x7f {
			return true
		}
	}
	return false
}
