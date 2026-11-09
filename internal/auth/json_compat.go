package auth

import (
	"strconv"
	"unicode/utf8"
)

// appendJSONString matches JSON.stringify for valid Go strings: HTML
// characters and U+2028/U+2029 remain literal, while JSON controls are escaped.
func appendJSONString(dst []byte, value string) []byte {
	dst = append(dst, '"')
	for len(value) > 0 {
		r, size := utf8.DecodeRuneInString(value)
		if r == utf8.RuneError && size == 1 {
			r = '\uFFFD'
		}
		value = value[size:]
		switch r {
		case '"', '\\':
			dst = append(dst, '\\', byte(r))
		case '\b':
			dst = append(dst, `\b`...)
		case '\f':
			dst = append(dst, `\f`...)
		case '\n':
			dst = append(dst, `\n`...)
		case '\r':
			dst = append(dst, `\r`...)
		case '\t':
			dst = append(dst, `\t`...)
		default:
			if r < 0x20 {
				const hex = "0123456789abcdef"
				dst = append(dst, '\\', 'u', '0', '0', hex[byte(r)>>4], hex[byte(r)&0xf])
			} else {
				dst = utf8.AppendRune(dst, r)
			}
		}
	}
	return append(dst, '"')
}

func appendFieldName(dst []byte, name string, first *bool) []byte {
	if !*first {
		dst = append(dst, ',')
	}
	*first = false
	dst = appendJSONString(dst, name)
	return append(dst, ':')
}

func appendStringField(dst []byte, name, value string, first *bool) []byte {
	dst = appendFieldName(dst, name, first)
	return appendJSONString(dst, value)
}

func appendInt64Field(dst []byte, name string, value int64, first *bool) []byte {
	dst = appendFieldName(dst, name, first)
	return strconv.AppendInt(dst, value, 10)
}
