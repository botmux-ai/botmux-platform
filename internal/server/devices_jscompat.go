package server

import (
	"encoding/json"
	"io"
	"math"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"unicode/utf8"
)

// Request coercions shared by the device protocol and Desktop Cloud handlers
// (B1). The TypeScript handlers read bodies with readJson — JSON.parse of the
// raw body, null on any failure — and coerce fields with
// String(body?.x || ""), .trim() and .slice(). A typed Go decode would reject
// `{"deviceName": 123}` that Node accepts as "123", or turn a wrong-typed
// field into a 400 where Node answers with the field-specific error, so these
// handlers read bodies through deviceBody instead of readJSON.

// deviceBodyLimit is readBody's 64 KiB limit: a larger body makes readJson
// return null.
const deviceBodyLimit = 64 << 10

// deviceBody is the parsed request body. Only a JSON object has fields;
// null, arrays and primitives behave like `body?.x === undefined`.
type deviceBody struct {
	fields map[string]any
}

func readDeviceBody(r *http.Request) deviceBody {
	if r.Body == nil {
		return deviceBody{}
	}
	defer r.Body.Close()
	raw, err := io.ReadAll(io.LimitReader(r.Body, deviceBodyLimit+1))
	if err != nil || len(raw) == 0 || len(raw) > deviceBodyLimit {
		return deviceBody{}
	}
	var parsed any
	if err := json.Unmarshal(raw, &parsed); err != nil {
		return deviceBody{}
	}
	fields, _ := parsed.(map[string]any)
	return deviceBody{fields: fields}
}

// value returns body?.[key] and whether the key is present (a JSON null is
// present, unlike an absent key — `body.scope === undefined` tells them apart).
func (b deviceBody) value(key string) (any, bool) {
	v, ok := b.fields[key]
	return v, ok
}

// str is String(body?.[key] || "").
func (b deviceBody) str(key string) string {
	v, _ := b.value(key)
	if !deviceJSTruthy(v) {
		return ""
	}
	return deviceJSString(v)
}

// trimmed is String(body?.[key] || "").trim().
func (b deviceBody) trimmed(key string) string { return deviceJSTrim(b.str(key)) }

// deviceJSTruthy is JavaScript truthiness for a JSON-decoded value.
func deviceJSTruthy(v any) bool {
	switch value := v.(type) {
	case nil:
		return false
	case bool:
		return value
	case string:
		return value != ""
	case float64:
		return value != 0 && !math.IsNaN(value)
	default:
		return true
	}
}

// deviceJSString is String(v) for a JSON-decoded value: arrays join their
// elements with "," (null elements become ""), objects are "[object Object]".
func deviceJSString(v any) string {
	switch value := v.(type) {
	case nil:
		return ""
	case string:
		return value
	case bool:
		return strconv.FormatBool(value)
	case float64:
		return deviceJSNumberString(value)
	case []any:
		parts := make([]string, len(value))
		for i, item := range value {
			parts[i] = deviceJSString(item)
		}
		return strings.Join(parts, ",")
	default:
		return "[object Object]"
	}
}

// deviceJSNumberString implements Number.prototype.toString() for the finite
// values JSON.parse can produce.
func deviceJSNumberString(x float64) string {
	if x == 0 {
		return "0"
	}
	sign := ""
	if x < 0 {
		sign, x = "-", -x
	}
	mantissa, expPart, _ := strings.Cut(strconv.FormatFloat(x, 'e', -1, 64), "e")
	digits := strings.Replace(mantissa, ".", "", 1)
	exp, _ := strconv.Atoi(expPart)
	k, n := len(digits), exp+1
	switch {
	case k <= n && n <= 21:
		return sign + digits + strings.Repeat("0", n-k)
	case 0 < n && n <= 21:
		return sign + digits[:n] + "." + digits[n:]
	case -6 < n && n <= 0:
		return sign + "0." + strings.Repeat("0", -n) + digits
	}
	e := n - 1
	expSign := "+"
	if e < 0 {
		expSign, e = "-", -e
	}
	if k == 1 {
		return sign + digits + "e" + expSign + strconv.Itoa(e)
	}
	return sign + digits[:1] + "." + digits[1:] + "e" + expSign + strconv.Itoa(e)
}

// deviceJSTrim is String.prototype.trim (WhiteSpace + LineTerminator, which
// is not Go's unicode.IsSpace: U+FEFF is trimmed, U+0085 is not).
func deviceJSTrim(value string) string {
	return strings.TrimFunc(value, func(r rune) bool {
		switch r {
		case '\t', '\n', '\v', '\f', '\r', ' ', 0x00A0, 0x1680, 0x2028, 0x2029, 0x202F, 0x205F, 0x3000, 0xFEFF:
			return true
		}
		return r >= 0x2000 && r <= 0x200A
	})
}

// deviceJSLength is String.prototype.length (UTF-16 code units).
func deviceJSLength(value string) int {
	n := 0
	for _, r := range value {
		n++
		if r >= 0x10000 {
			n++
		}
	}
	return n
}

// deviceJSSlice is value.slice(0, limit) over UTF-16 code units. A surrogate
// pair split by the limit leaves a lone high surrogate in JavaScript, which
// both the Node BSON serializer and Buffer.from(…, 'utf8') persist as U+FFFD;
// the Go string carries that U+FFFD directly.
func deviceJSSlice(value string, limit int) string {
	units := 0
	for i, r := range value {
		width := 1
		if r >= 0x10000 {
			width = 2
		}
		if units+width > limit {
			if width == 2 && units+1 == limit {
				return value[:i] + "\uFFFD"
			}
			return value[:i]
		}
		units += width
	}
	return value
}

// deviceNodeHeader is String(req.headers[name] || "") for an ordinary header:
// Node joins repeated fields with ", " and decodes header bytes as latin1, so
// a non-ASCII byte becomes the code point of the same value (and hashes as
// its UTF-8 encoding, like crypto's update(string)).
func deviceNodeHeader(r *http.Request, name string) string {
	joined := strings.Join(r.Header.Values(name), ", ")
	ascii := true
	for i := 0; i < len(joined); i++ {
		if joined[i] >= utf8.RuneSelf {
			ascii = false
			break
		}
	}
	if ascii {
		return joined
	}
	var b strings.Builder
	for i := 0; i < len(joined); i++ {
		b.WriteRune(rune(joined[i]))
	}
	return b.String()
}

// deviceWebOrigin is new URL(base).origin for an http(s) base URL: lower-case
// scheme and host, default port omitted, port in canonical decimal.
func deviceWebOrigin(base string) string {
	u, err := url.Parse(base)
	if err != nil || u.Host == "" {
		return "null"
	}
	scheme := strings.ToLower(u.Scheme)
	if scheme != "http" && scheme != "https" {
		return "null"
	}
	host := strings.ToLower(u.Hostname())
	if strings.Contains(host, ":") {
		host = "[" + host + "]"
	}
	if raw := u.Port(); raw != "" {
		port, err := strconv.Atoi(raw)
		if err != nil {
			return "null"
		}
		if !(scheme == "http" && port == 80) && !(scheme == "https" && port == 443) {
			host += ":" + strconv.Itoa(port)
		}
	}
	return scheme + "://" + host
}

// deviceSameOrigin is the CSRF gate of the browser-facing device endpoints:
// String(req.headers.origin || "") === new URL(publicBaseUrl).origin. A
// browser POST always carries Origin, so a missing one is rejected too.
func (a *Apex) deviceSameOrigin(r *http.Request) bool {
	return deviceNodeHeader(r, "Origin") == deviceWebOrigin(a.Config.PublicBaseURL)
}
