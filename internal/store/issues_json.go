package store

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"math"
	"sort"
	"strconv"
	"time"
	"unicode/utf8"

	"go.mongodb.org/mongo-driver/bson"
	"go.mongodb.org/mongo-driver/bson/bsontype"
)

// The TS service answers issue reads with the raw driver result: js-bson
// deserializes the stored document and JSON.stringify writes it in physical
// field order. Mongo appends fields first added by a later $set (claim,
// attention*, archivedAt, patched labels/repo/assignee) after the creation
// literal, in an order that depends on the document's history, so no struct
// field order can reproduce it. IssueDoc, IssueClaim and IssueEventDoc
// therefore keep the BSON they were decoded from and render JSON from it.
// Documents built in memory (Create's return value) have no raw form and use
// their struct order, which is the TS insert literal.

// jsJSONFromBSON renders a BSON document as JSON.stringify(js-bson
// deserialize(doc)).
func jsJSONFromBSON(raw bson.Raw) ([]byte, error) {
	var out bytes.Buffer
	if err := appendJSDocument(&out, raw, false); err != nil {
		return nil, err
	}
	return out.Bytes(), nil
}

type jsBSONProperty struct {
	key   string
	value bson.RawValue
}

// jsObjectOrder applies the JavaScript property order js-bson's
// `object[name] = value` produces: a repeated key keeps its first position
// with the last value, and integer-like keys (array indices) come first in
// ascending numeric order.
func jsObjectOrder(elements []bson.RawElement) []jsBSONProperty {
	props := make([]jsBSONProperty, 0, len(elements))
	index := make(map[string]int, len(elements))
	for _, element := range elements {
		key := element.Key()
		if i, ok := index[key]; ok {
			props[i].value = element.Value()
			continue
		}
		index[key] = len(props)
		props = append(props, jsBSONProperty{key: key, value: element.Value()})
	}
	sort.SliceStable(props, func(i, j int) bool {
		ai, aok := JSArrayIndex(props[i].key)
		bi, bok := JSArrayIndex(props[j].key)
		if aok && bok {
			return ai < bi
		}
		return aok && !bok
	})
	return props
}

// JSArrayIndex reports whether key is a canonical array index ("0".."4294967294"
// without leading zeros), the property keys JavaScript orders before all
// others in an ordinary object.
func JSArrayIndex(key string) (uint32, bool) {
	if key == "" || len(key) > 10 || (len(key) > 1 && key[0] == '0') {
		return 0, false
	}
	var n uint64
	for i := 0; i < len(key); i++ {
		c := key[i]
		if c < '0' || c > '9' {
			return 0, false
		}
		n = n*10 + uint64(c-'0')
	}
	if n >= math.MaxUint32 {
		return 0, false
	}
	return uint32(n), true
}

func appendJSDocument(out *bytes.Buffer, raw bson.Raw, array bool) error {
	elements, err := raw.Elements()
	if err != nil {
		return err
	}
	if array {
		out.WriteByte('[')
		for i, element := range elements {
			if i > 0 {
				out.WriteByte(',')
			}
			defined, err := appendJSValue(out, element.Value())
			if err != nil {
				return err
			}
			if !defined {
				out.WriteString("null")
			}
		}
		out.WriteByte(']')
		return nil
	}
	out.WriteByte('{')
	first := true
	for _, prop := range jsObjectOrder(elements) {
		if prop.value.Type == bsontype.Undefined {
			continue // JSON.stringify omits undefined properties
		}
		if !first {
			out.WriteByte(',')
		}
		first = false
		AppendJSString(out, prop.key)
		out.WriteByte(':')
		if _, err := appendJSValue(out, prop.value); err != nil {
			return err
		}
	}
	out.WriteByte('}')
	return nil
}

// appendJSValue writes one deserialized BSON value; defined=false means JS
// undefined (nothing written).
func appendJSValue(out *bytes.Buffer, value bson.RawValue) (bool, error) {
	switch value.Type {
	case bsontype.Double:
		f, _ := value.DoubleOK()
		AppendJSNumber(out, f)
	case bsontype.Int32:
		i, _ := value.Int32OK()
		out.WriteString(strconv.FormatInt(int64(i), 10))
	case bsontype.Int64:
		i, _ := value.Int64OK()
		// promoteLongs: safe integers become numbers, others stay Long whose
		// toJSON is its decimal string.
		if i <= 1<<53 && i >= -(1<<53) {
			AppendJSNumber(out, float64(i))
		} else {
			AppendJSString(out, strconv.FormatInt(i, 10))
		}
	case bsontype.String:
		s, _ := value.StringValueOK()
		AppendJSString(out, s)
	case bsontype.Symbol:
		s, _ := value.SymbolOK()
		AppendJSString(out, s)
	case bsontype.Boolean:
		b, _ := value.BooleanOK()
		if b {
			out.WriteString("true")
		} else {
			out.WriteString("false")
		}
	case bsontype.Null:
		out.WriteString("null")
	case bsontype.Undefined:
		return false, nil
	case bsontype.EmbeddedDocument:
		doc, _ := value.DocumentOK()
		if err := appendJSDocument(out, doc, false); err != nil {
			return false, err
		}
	case bsontype.Array:
		arr, _ := value.ArrayOK()
		if err := appendJSDocument(out, arr, true); err != nil {
			return false, err
		}
	case bsontype.DateTime:
		ms, _ := value.DateTimeOK()
		if iso, ok := jsDateISO(ms); ok {
			AppendJSString(out, iso)
		} else {
			out.WriteString("null")
		}
	case bsontype.ObjectID:
		oid, _ := value.ObjectIDOK()
		AppendJSString(out, oid.Hex())
	case bsontype.Binary:
		_, data, _ := value.BinaryOK()
		AppendJSString(out, base64.StdEncoding.EncodeToString(data))
	case bsontype.Decimal128:
		d, _ := value.Decimal128OK()
		out.WriteString(`{"$numberDecimal":`)
		AppendJSString(out, d.String())
		out.WriteByte('}')
	case bsontype.Timestamp:
		t, i, _ := value.TimestampOK()
		AppendJSString(out, strconv.FormatUint(uint64(t)<<32|uint64(i), 10))
	case bsontype.JavaScript:
		code, _ := value.JavaScriptOK()
		out.WriteString(`{"code":`)
		AppendJSString(out, code)
		out.WriteByte('}')
	case bsontype.Regex:
		out.WriteString("{}") // a RegExp has no enumerable own properties
	default:
		// MinKey / MaxKey / DBPointer / CodeWithScope never occur in issue
		// documents; JS would render the wrapper object, null is the closest
		// lossless-enough stand-in.
		out.WriteString("null")
	}
	return true, nil
}

// AppendJSNumber writes a number like JSON.stringify: non-finite values are
// null and finite ones use Number::toString (so -0 is "0").
func AppendJSNumber(out *bytes.Buffer, f float64) {
	if math.IsNaN(f) || math.IsInf(f, 0) {
		out.WriteString("null")
		return
	}
	out.WriteString(jsNumberString(f))
}

// AppendJSString writes s quoted like JSON.stringify (QuoteJSONString): the
// short escapes \b \t \n \f \r \" \\, \u00xx for the remaining C0 controls,
// and everything else (including U+2028/U+2029 and '<' '>' '&') verbatim.
// Invalid UTF-8 becomes U+FFFD, as Buffer#toString('utf8') decodes it.
func AppendJSString(out *bytes.Buffer, s string) {
	const hex = "0123456789abcdef"
	out.WriteByte('"')
	for i := 0; i < len(s); {
		c := s[i]
		if c < utf8.RuneSelf {
			switch c {
			case '"':
				out.WriteString(`\"`)
			case '\\':
				out.WriteString(`\\`)
			case '\b':
				out.WriteString(`\b`)
			case '\f':
				out.WriteString(`\f`)
			case '\n':
				out.WriteString(`\n`)
			case '\r':
				out.WriteString(`\r`)
			case '\t':
				out.WriteString(`\t`)
			default:
				if c < 0x20 {
					out.WriteString(`\u00`)
					out.WriteByte(hex[c>>4])
					out.WriteByte(hex[c&0xf])
				} else {
					out.WriteByte(c)
				}
			}
			i++
			continue
		}
		r, size := utf8.DecodeRuneInString(s[i:])
		if r == utf8.RuneError && size == 1 {
			out.WriteString("\uFFFD")
		} else {
			out.WriteString(s[i : i+size])
		}
		i += size
	}
	out.WriteByte('"')
}

// jsDateISO is Date.prototype.toJSON: toISOString for valid dates (extended
// six-digit years outside 0000-9999), null beyond the ±8.64e15 ms range.
func jsDateISO(ms int64) (string, bool) {
	const limit = 8_640_000_000_000_000
	if ms > limit || ms < -limit {
		return "", false
	}
	t := time.UnixMilli(ms).UTC()
	year := t.Year()
	var y string
	switch {
	case year >= 0 && year <= 9999:
		y = fmt.Sprintf("%04d", year)
	case year < 0:
		y = fmt.Sprintf("-%06d", -year)
	default:
		y = fmt.Sprintf("+%06d", year)
	}
	return y + t.Format("-01-02T15:04:05.000Z"), true
}

// marshalJSONNoEscape is json.Marshal without HTML escaping, so the bytes
// stay identical to JSON.stringify when writeJSON embeds them.
func marshalJSONNoEscape(v any) ([]byte, error) {
	var out bytes.Buffer
	encoder := json.NewEncoder(&out)
	encoder.SetEscapeHTML(false)
	if err := encoder.Encode(v); err != nil {
		return nil, err
	}
	return bytes.TrimSuffix(out.Bytes(), []byte{'\n'}), nil
}

// unmarshalLenient decodes data into dst (a pointer to a struct without its
// own UnmarshalBSON). Fields whose stored type does not fit the Go field —
// e.g. a label array of numbers that TS persisted verbatim from a client —
// are skipped instead of failing the whole read: TS readers never fail on
// such documents, and the raw-backed JSON still shows the stored value.
func unmarshalLenient[T any](data []byte, dst *T) error {
	if err := bson.Unmarshal(data, dst); err == nil {
		return nil
	}
	elements, err := bson.Raw(data).Elements()
	if err != nil {
		return err
	}
	kept := make(bson.D, 0, len(elements))
	for _, element := range elements {
		single, err := bson.Marshal(bson.D{{Key: element.Key(), Value: element.Value()}})
		if err != nil {
			continue
		}
		var probe T
		if bson.Unmarshal(single, &probe) == nil {
			kept = append(kept, bson.E{Key: element.Key(), Value: element.Value()})
		}
	}
	filtered, err := bson.Marshal(kept)
	if err != nil {
		return err
	}
	var fresh T
	if err := bson.Unmarshal(filtered, &fresh); err != nil {
		return err
	}
	*dst = fresh
	return nil
}

// JS string/number coercions shared with the issue HTTP layer, which has to
// reproduce the same TS expressions on request input.

// JSTrim is String.prototype.trim.
func JSTrim(s string) string { return jsTrim(s) }

// JSSliceUTF16 is String.prototype.slice(0, max) on UTF-16 code units; a
// surrogate pair cut in half becomes U+FFFD, which is what the Node driver
// persists for the lone surrogate.
func JSSliceUTF16(s string, max int) string { return truncateUTF16(s, max) }

// JSNumberToString is Number::toString(10) (String(n) for a number).
func JSNumberToString(f float64) string { return jsNumberString(f) }
