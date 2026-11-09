package server

import (
	"bytes"
	"encoding/json"
	"errors"
	"io"
	"math"
	"math/big"
	"net/http"
	"regexp"
	"sort"
	"strconv"
	"strings"

	"github.com/botmux-ai/botmux-platform/internal/store"
	"go.mongodb.org/mongo-driver/bson"
)

// The issue handlers reproduce TS expressions on `await readJson(req)`:
// truthiness checks (`!body?.claimId`), `typeof x === 'number'`, String(x),
// own-property spreads, and values persisted verbatim (claim agent /
// repoLabel). That needs the JSON.parse value itself — JS types, null versus
// absent, and JS property order — rather than a Go struct decode.

// issueJSONObject is a JSON.parse object: own properties in JS order
// (array-index keys ascending, then insertion order; a repeated key keeps its
// first position and takes the last value).
type issueJSONObject struct {
	keys   []string
	values map[string]any
}

func (o *issueJSONObject) get(key string) (any, bool) {
	if o == nil {
		return nil, false
	}
	value, ok := o.values[key]
	return value, ok
}

// issueJS is a property read: defined=false is JS undefined.
type issueJS struct {
	value   any
	defined bool
}

// prop is `v?.key` for a parsed body. Only objects have the properties the
// handlers read; arrays, strings, numbers and null yield undefined.
func issuesProp(v any, key string) issueJS {
	obj, ok := v.(*issueJSONObject)
	if !ok {
		return issueJS{}
	}
	value, defined := obj.get(key)
	return issueJS{value: value, defined: defined}
}

func (j issueJS) truthy() bool { return j.defined && issuesTruthy(j.value) }

// number is `typeof x === 'number'`.
func (j issueJS) number() (float64, bool) {
	f, ok := j.value.(float64)
	return f, j.defined && ok
}

// str is `typeof x === 'string'`.
func (j issueJS) str() (string, bool) {
	s, ok := j.value.(string)
	return s, j.defined && ok
}

// issuesReadJSON is TS readJson: a body over 64 KiB, an empty body or invalid
// JSON is null; any JSON value is accepted.
func issuesReadJSON(r *http.Request) any {
	if r.Body == nil {
		return nil
	}
	defer r.Body.Close()
	data, err := io.ReadAll(io.LimitReader(r.Body, maxJSONBody+1))
	if err != nil || len(data) == 0 || len(data) > maxJSONBody {
		return nil
	}
	value, ok := issuesParseJSON(data)
	if !ok {
		return nil
	}
	return value
}

// issuesParseJSON is JSON.parse: nil, bool, float64 (overflow is ±Infinity),
// string, *issueJSONObject or []any.
func issuesParseJSON(data []byte) (any, bool) {
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.UseNumber()
	value, err := issuesParseValue(decoder)
	if err != nil {
		return nil, false
	}
	if _, err := decoder.Token(); !errors.Is(err, io.EOF) {
		return nil, false
	}
	return value, true
}

var errIssueJSONSyntax = errors.New("issues: invalid JSON")

func issuesParseValue(decoder *json.Decoder) (any, error) {
	token, err := decoder.Token()
	if err != nil {
		return nil, err
	}
	switch t := token.(type) {
	case json.Delim:
		switch t {
		case '{':
			obj := &issueJSONObject{values: map[string]any{}}
			for decoder.More() {
				keyToken, err := decoder.Token()
				if err != nil {
					return nil, err
				}
				key, ok := keyToken.(string)
				if !ok {
					return nil, errIssueJSONSyntax
				}
				value, err := issuesParseValue(decoder)
				if err != nil {
					return nil, err
				}
				if _, seen := obj.values[key]; !seen {
					obj.keys = append(obj.keys, key)
				}
				obj.values[key] = value
			}
			if _, err := decoder.Token(); err != nil {
				return nil, err
			}
			sort.SliceStable(obj.keys, func(i, j int) bool {
				ai, aok := store.JSArrayIndex(obj.keys[i])
				bi, bok := store.JSArrayIndex(obj.keys[j])
				if aok && bok {
					return ai < bi
				}
				return aok && !bok
			})
			return obj, nil
		case '[':
			list := []any{}
			for decoder.More() {
				value, err := issuesParseValue(decoder)
				if err != nil {
					return nil, err
				}
				list = append(list, value)
			}
			if _, err := decoder.Token(); err != nil {
				return nil, err
			}
			return list, nil
		}
		return nil, errIssueJSONSyntax
	case json.Number:
		f, err := strconv.ParseFloat(string(t), 64)
		if err != nil && !errors.Is(err, strconv.ErrRange) {
			return nil, err
		}
		return f, nil // ErrRange: ±Inf on overflow, like JSON.parse
	case string, bool, nil:
		return t, nil
	}
	return nil, errIssueJSONSyntax
}

// issuesTruthy is JavaScript ToBoolean for a parsed JSON value.
func issuesTruthy(v any) bool {
	switch value := v.(type) {
	case nil:
		return false
	case bool:
		return value
	case float64:
		return value != 0 && !math.IsNaN(value)
	case string:
		return value != ""
	default:
		return true
	}
}

// issuesJSString is String(v) for a parsed JSON value (String(null) is
// "null"; array elements that are null become "").
func issuesJSString(v any) string {
	switch value := v.(type) {
	case nil:
		return "null"
	case bool:
		if value {
			return "true"
		}
		return "false"
	case float64:
		return store.JSNumberToString(value)
	case string:
		return value
	case []any:
		parts := make([]string, len(value))
		for i, item := range value {
			if item != nil {
				parts[i] = issuesJSString(item)
			}
		}
		return strings.Join(parts, ",")
	default:
		return "[object Object]"
	}
}

// issuesPlain converts a parsed value to the encoding/json `any` shapes
// (map[string]any, []any, float64, string, bool, nil) the store's form and
// settings normalizers consume.
func issuesPlain(v any) any {
	switch value := v.(type) {
	case *issueJSONObject:
		out := make(map[string]any, len(value.keys))
		for _, key := range value.keys {
			out[key] = issuesPlain(value.values[key])
		}
		return out
	case []any:
		out := make([]any, len(value))
		for i, item := range value {
			out[i] = issuesPlain(item)
		}
		return out
	default:
		return v
	}
}

// issuesBSONValue shapes a parsed value the way js-bson 1.x serializes it:
// objects keep JS property order, integral numbers in int32 range (including
// -0) are Int32 and every other number is a Double.
func issuesBSONValue(v any) any {
	switch value := v.(type) {
	case *issueJSONObject:
		out := make(bson.D, 0, len(value.keys))
		for _, key := range value.keys {
			out = append(out, bson.E{Key: key, Value: issuesBSONValue(value.values[key])})
		}
		return out
	case []any:
		out := make(bson.A, len(value))
		for i, item := range value {
			out[i] = issuesBSONValue(item)
		}
		return out
	case float64:
		if value == math.Trunc(value) && value >= math.MinInt32 && value <= math.MaxInt32 {
			return int32(value)
		}
		return value
	default:
		return v
	}
}

var issuesDecimalLiteral = regexp.MustCompile(`^[+-]?(?:(?:[0-9]+\.?[0-9]*|\.[0-9]+)(?:[eE][+-]?[0-9]+)?|Infinity)$`)

// issuesJSNumber is Number(s) for a string (StringToNumber): JS whitespace is
// trimmed, "" is 0, 0x/0o/0b prefixes (unsigned) are integers, anything else
// that is not a StrDecimalLiteral is NaN.
func issuesJSNumber(s string) float64 {
	s = store.JSTrim(s)
	if s == "" {
		return 0
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
			n, ok := new(big.Int).SetString(s[2:], base)
			if !ok || strings.ContainsAny(s[2:], "+-_") {
				return math.NaN()
			}
			f, _ := new(big.Float).SetInt(n).Float64()
			return f
		}
	}
	if !issuesDecimalLiteral.MatchString(s) {
		return math.NaN()
	}
	switch strings.TrimLeft(s, "+-") {
	case "Infinity":
		if s[0] == '-' {
			return math.Inf(-1)
		}
		return math.Inf(1)
	}
	f, err := strconv.ParseFloat(s, 64)
	if err != nil && !errors.Is(err, strconv.ErrRange) {
		return math.NaN()
	}
	return f
}
