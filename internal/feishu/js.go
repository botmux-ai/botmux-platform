package feishu

import (
	"bytes"
	"encoding/json"
	"math"
	"regexp"
	"strconv"
	"strings"
)

// Helpers that reproduce the JavaScript semantics the TypeScript Feishu client
// relies on (truthiness, Number()/String() coercion, encodeURIComponent,
// JSON.stringify key order), so request URLs, bodies and error texts match.

// encodeURIComponent percent-encodes everything outside A-Z a-z 0-9 - _ . ! ~ * ' ( ).
func encodeURIComponent(s string) string {
	const hex = "0123456789ABCDEF"
	var b strings.Builder
	for i := 0; i < len(s); i++ {
		c := s[i]
		if 'A' <= c && c <= 'Z' || 'a' <= c && c <= 'z' || '0' <= c && c <= '9' || strings.IndexByte("-_.!~*'()", c) >= 0 {
			b.WriteByte(c)
			continue
		}
		b.WriteByte('%')
		b.WriteByte(hex[c>>4])
		b.WriteByte(hex[c&15])
	}
	return b.String()
}

func isJSWhitespace(r rune) bool {
	switch r {
	case '\t', '\n', '\v', '\f', '\r', ' ', '\u00a0', '\u1680', '\u2028', '\u2029', '\u202f', '\u205f', '\u3000', '\ufeff':
		return true
	}
	return r >= '\u2000' && r <= '\u200a'
}

// jsTrim is String.prototype.trim.
func jsTrim(s string) string { return strings.TrimFunc(s, isJSWhitespace) }

// jsLowerCase approximates String.prototype.toLowerCase (U+0130 expands to
// "i" + combining dot above, unlike Go's single-rune mapping).
func jsLowerCase(s string) string {
	return strings.ToLower(strings.ReplaceAll(s, "\u0130", "i\u0307"))
}

// sliceUTF16 is String.prototype.slice(0, n): n counts UTF-16 code units. A
// surrogate pair cut in half becomes U+FFFD once re-encoded as UTF-8.
func sliceUTF16(s string, n int) string {
	units := 0
	for i, r := range s {
		width := 1
		if r >= 0x10000 {
			width = 2
		}
		if units+width > n {
			if units < n {
				return s[:i] + "\uFFFD"
			}
			return s[:i]
		}
		units += width
	}
	return s
}

// truthy is JavaScript truthiness of a decoded JSON value (missing = undefined).
func truthy(raw json.RawMessage) bool {
	raw = bytes.TrimSpace(raw)
	if len(raw) == 0 {
		return false
	}
	switch raw[0] {
	case 'n', 'f':
		return false
	case 't', '{', '[':
		return true
	case '"':
		return string(raw) != `""`
	}
	var f float64
	if json.Unmarshal(raw, &f) != nil {
		return false
	}
	return f != 0 && !math.IsNaN(f)
}

// nullish reports a missing or null value (the `??` operator's test).
func nullish(raw json.RawMessage) bool {
	raw = bytes.TrimSpace(raw)
	return len(raw) == 0 || string(raw) == "null"
}

// objectFields returns the members of a JSON object; anything else yields nil.
func objectFields(raw json.RawMessage) map[string]json.RawMessage {
	var out map[string]json.RawMessage
	raw = bytes.TrimSpace(raw)
	if len(raw) == 0 || raw[0] != '{' || json.Unmarshal(raw, &out) != nil {
		return nil
	}
	return out
}

// arrayItems returns the elements when raw is a JSON array (Array.isArray).
func arrayItems(raw json.RawMessage) ([]json.RawMessage, bool) {
	var out []json.RawMessage
	raw = bytes.TrimSpace(raw)
	if len(raw) == 0 || raw[0] != '[' || json.Unmarshal(raw, &out) != nil {
		return nil, false
	}
	return out, true
}

// stringValue returns the value when raw is a JSON string (typeof === 'string').
func stringValue(raw json.RawMessage) (string, bool) {
	raw = bytes.TrimSpace(raw)
	if len(raw) == 0 || raw[0] != '"' {
		return "", false
	}
	var s string
	if json.Unmarshal(raw, &s) != nil {
		return "", false
	}
	return s, true
}

// str returns a string member or "" (callers only ever compare against strings).
func str(fields map[string]json.RawMessage, name string) string {
	s, _ := stringValue(fields[name])
	return s
}

// numberValue returns the value when raw is a JSON number (typeof === 'number').
func numberValue(raw json.RawMessage) (float64, bool) {
	raw = bytes.TrimSpace(raw)
	if len(raw) == 0 || !(raw[0] == '-' || ('0' <= raw[0] && raw[0] <= '9')) {
		return 0, false
	}
	var f float64
	if json.Unmarshal(raw, &f) != nil {
		return 0, false
	}
	return f, true
}

var jsDecimalNumber = regexp.MustCompile(`^[+-]?(?:[0-9]+\.?[0-9]*|\.[0-9]+)(?:[eE][+-]?[0-9]+)?$`)

// jsNumber is Number(value) for a decoded JSON value (NaN when not coercible).
func jsNumber(raw json.RawMessage) float64 {
	raw = bytes.TrimSpace(raw)
	if len(raw) == 0 {
		return math.NaN()
	}
	switch raw[0] {
	case 'n', 'f':
		return 0
	case 't':
		return 1
	case '{':
		return math.NaN()
	case '[':
		// Number([]) is 0 and Number([x]) is Number(String(x)); longer arrays are NaN.
		items, _ := arrayItems(raw)
		switch {
		case len(items) == 0:
			return 0
		case len(items) == 1 && nullish(items[0]):
			return 0
		case len(items) == 1:
			return jsStringToNumber(jsString(items[0]))
		}
		return math.NaN()
	case '"':
		s, _ := stringValue(raw)
		return jsStringToNumber(s)
	}
	f, _ := numberValue(raw)
	return f
}

func jsStringToNumber(s string) float64 {
	s = jsTrim(s)
	switch s {
	case "":
		return 0
	case "Infinity", "+Infinity":
		return math.Inf(1)
	case "-Infinity":
		return math.Inf(-1)
	}
	if len(s) > 2 && s[0] == '0' {
		base := 0
		switch s[1] {
		case 'x', 'X':
			base = 16
		case 'o', 'O':
			base = 8
		case 'b', 'B':
			base = 2
		}
		if base != 0 {
			n, err := strconv.ParseUint(s[2:], base, 64)
			if err != nil {
				return math.NaN()
			}
			return float64(n)
		}
	}
	if !jsDecimalNumber.MatchString(s) {
		return math.NaN()
	}
	f, err := strconv.ParseFloat(s, 64)
	if err != nil && !math.IsInf(f, 0) {
		return math.NaN()
	}
	return f
}

// jsNumberString formats a float like Number.prototype.toString().
func jsNumberString(f float64) string {
	switch {
	case math.IsNaN(f):
		return "NaN"
	case math.IsInf(f, 1):
		return "Infinity"
	case math.IsInf(f, -1):
		return "-Infinity"
	case f == 0:
		return "0"
	}
	abs := math.Abs(f)
	if abs >= 1e-6 && abs < 1e21 {
		return strconv.FormatFloat(f, 'f', -1, 64)
	}
	s := strconv.FormatFloat(f, 'e', -1, 64)
	mantissa, exp, _ := strings.Cut(s, "e")
	sign := exp[0]
	exp = strings.TrimLeft(exp[1:], "0")
	return mantissa + "e" + string(sign) + exp
}

// jsString is String(value) for a decoded JSON value (missing = "undefined").
func jsString(raw json.RawMessage) string {
	raw = bytes.TrimSpace(raw)
	if len(raw) == 0 {
		return "undefined"
	}
	switch raw[0] {
	case '"':
		s, _ := stringValue(raw)
		return s
	case '{':
		return "[object Object]"
	case '[':
		items, _ := arrayItems(raw)
		parts := make([]string, len(items))
		for i, item := range items {
			if !nullish(item) {
				parts[i] = jsString(item)
			}
		}
		return strings.Join(parts, ",")
	case 't', 'f', 'n':
		return string(raw)
	}
	f, ok := numberValue(raw)
	if !ok {
		return string(raw)
	}
	return jsNumberString(f)
}

// jsOrEmpty is the template `${value || ""}` (empty string when falsy).
func jsOrEmpty(raw json.RawMessage) string {
	if !truthy(raw) {
		return ""
	}
	return jsString(raw)
}

// jsNullishEmpty is the template `${value ?? ""}` (empty when null/undefined).
func jsNullishEmpty(raw json.RawMessage) string {
	if nullish(raw) {
		return ""
	}
	return jsString(raw)
}

// jsObj is a JSON object that keeps insertion order like JSON.stringify of an
// object literal. Values are encoded without HTML escaping.
type jsObj []jsField

type jsField struct {
	key   string
	value any
}

func (o jsObj) MarshalJSON() ([]byte, error) {
	buf := []byte{'{'}
	for i, field := range o {
		if i > 0 {
			buf = append(buf, ',')
		}
		key, err := marshalJS(field.key)
		if err != nil {
			return nil, err
		}
		value, err := marshalJS(field.value)
		if err != nil {
			return nil, err
		}
		buf = append(append(append(buf, key...), ':'), value...)
	}
	return append(buf, '}'), nil
}

// marshalJS encodes like JSON.stringify for the values this package sends:
// no HTML escaping. (encoding/json still escapes U+2028/U+2029, which decodes
// to the same string.)
func marshalJS(v any) ([]byte, error) {
	var buf bytes.Buffer
	enc := json.NewEncoder(&buf)
	enc.SetEscapeHTML(false)
	if err := enc.Encode(v); err != nil {
		return nil, err
	}
	return bytes.TrimSuffix(buf.Bytes(), []byte{'\n'}), nil
}

// stringifyJS returns JSON.stringify(v) as a string (for message `content`).
func stringifyJS(v any) string {
	b, err := marshalJS(v)
	if err != nil {
		// Only static card shapes are stringified here; this cannot fail.
		panic(err)
	}
	return string(b)
}
