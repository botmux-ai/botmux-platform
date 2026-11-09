package store

import (
	"encoding/json"
	"math"
	"strconv"
	"strings"
)

// The helpers below reproduce the JavaScript coercions the TypeScript store
// applies to untrusted JSON input (String(v), String.prototype.trim, slice on
// UTF-16 code units, truthiness). Values are expected to come from
// encoding/json decoding into `any` (map[string]any, []any, string, float64,
// bool, nil); json.Number and Go integer kinds are accepted as numbers.

// jsString mirrors String(v ?? ""): nil becomes "", arrays join their
// elements with "," (nil elements become ""), and objects become
// "[object Object]".
func jsString(v any) string {
	switch value := v.(type) {
	case nil:
		return ""
	case string:
		return value
	case bool:
		if value {
			return "true"
		}
		return "false"
	case float64:
		return jsNumberString(value)
	case float32:
		return jsNumberString(float64(value))
	case json.Number:
		f, err := value.Float64()
		if err != nil {
			return value.String()
		}
		return jsNumberString(f)
	case int:
		return strconv.FormatInt(int64(value), 10)
	case int32:
		return strconv.FormatInt(int64(value), 10)
	case int64:
		return jsNumberString(float64(value))
	case []any:
		parts := make([]string, len(value))
		for i, item := range value {
			parts[i] = jsString(item)
		}
		return strings.Join(parts, ",")
	case []string:
		return strings.Join(value, ",")
	default:
		return "[object Object]"
	}
}

// jsNumberString implements ECMAScript Number::toString(10).
func jsNumberString(x float64) string {
	switch {
	case math.IsNaN(x):
		return "NaN"
	case math.IsInf(x, 1):
		return "Infinity"
	case math.IsInf(x, -1):
		return "-Infinity"
	case x == 0:
		return "0"
	}
	sign := ""
	if x < 0 {
		sign = "-"
		x = -x
	}
	// Shortest round-trip digits: d.ddddde±XX.
	formatted := strconv.FormatFloat(x, 'e', -1, 64)
	mantissa, expPart, _ := strings.Cut(formatted, "e")
	digits := strings.Replace(mantissa, ".", "", 1)
	exp, _ := strconv.Atoi(expPart)
	k := len(digits)
	n := exp + 1 // position of the decimal point relative to the digits
	switch {
	case k <= n && n <= 21:
		return sign + digits + strings.Repeat("0", n-k)
	case 0 < n && n <= 21:
		return sign + digits[:n] + "." + digits[n:]
	case -6 < n && n <= 0:
		return sign + "0." + strings.Repeat("0", -n) + digits
	}
	expSign := "+"
	if n-1 < 0 {
		expSign = "-"
	}
	e := n - 1
	if e < 0 {
		e = -e
	}
	if k == 1 {
		return sign + digits + "e" + expSign + strconv.Itoa(e)
	}
	return sign + digits[:1] + "." + digits[1:] + "e" + expSign + strconv.Itoa(e)
}

// isJSWhitespace (issues_support.go) is the WhiteSpace + LineTerminator set
// that String.prototype.trim removes.
func jsTrim(value string) string { return strings.TrimFunc(value, isJSWhitespace) }

// jsTrimStr mirrors the TS helper String(v ?? "").trim().slice(0, max).
// Truncation is truncateUTF16 (issues_support.go): UTF-16 code units, with a
// split surrogate pair persisted as U+FFFD like the Node driver does.
func jsTrimStr(v any, max int) string { return truncateUTF16(jsTrim(jsString(v)), max) }

// jsLower mirrors String.prototype.toLowerCase for the cases where Go's simple
// case mapping disagrees with JavaScript's full mapping in a way that matters
// for ASCII identifier validation (U+0130 lowers to "i̇", not "i").
func jsLower(value string) string {
	if strings.ContainsRune(value, 0x0130) {
		value = strings.ReplaceAll(value, "İ", "i̇")
	}
	return strings.ToLower(value)
}

// jsTruthy mirrors JavaScript truthiness for JSON-decoded values.
func jsTruthy(v any) bool {
	switch value := v.(type) {
	case nil:
		return false
	case bool:
		return value
	case string:
		return value != ""
	case float64:
		return value != 0 && !math.IsNaN(value)
	case float32:
		return value != 0 && !math.IsNaN(float64(value))
	case json.Number:
		f, err := value.Float64()
		return err != nil || (f != 0 && !math.IsNaN(f))
	case int:
		return value != 0
	case int32:
		return value != 0
	case int64:
		return value != 0
	default:
		return true
	}
}

// jsObject reports whether v is a non-null JavaScript object (`v && typeof v
// === 'object'`) and returns its own enumerable properties. Arrays are objects
// without named properties.
func jsObject(v any) (map[string]any, bool) {
	switch value := v.(type) {
	case map[string]any:
		return value, true
	case Document:
		return map[string]any(value), true
	case []any, []string:
		return map[string]any{}, true
	}
	return nil, false
}

// jsArray reports whether v is a JavaScript array (Array.isArray).
func jsArray(v any) ([]any, bool) {
	switch value := v.(type) {
	case []any:
		return value, true
	case []string:
		out := make([]any, len(value))
		for i, s := range value {
			out[i] = s
		}
		return out, true
	}
	return nil, false
}
