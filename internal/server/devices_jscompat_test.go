package server

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

// Reference values come from Node (String(x), trim, slice, new URL().origin).

func TestDeviceJSNumberString(t *testing.T) {
	for _, tc := range []struct {
		in   float64
		want string
	}{
		{0, "0"}, {1, "1"}, {-1, "-1"}, {1.5, "1.5"}, {123456789012345680000, "123456789012345680000"},
		{1e21, "1e+21"}, {1.234e-7, "1.234e-7"}, {0.000001, "0.000001"}, {1e-7, "1e-7"}, {5e-324, "5e-324"},
		{1.7976931348623157e308, "1.7976931348623157e+308"}, {100, "100"}, {0.1, "0.1"}, {-2.5e-10, "-2.5e-10"}, {123e20, "1.23e+22"},
	} {
		if got := deviceJSNumberString(tc.in); got != tc.want {
			t.Errorf("String(%v) = %q, want %q", tc.in, got, tc.want)
		}
	}
}

func TestDeviceBodyCoercions(t *testing.T) {
	body := func(raw string) deviceBody {
		return readDeviceBody(httptest.NewRequest(http.MethodPost, "/", strings.NewReader(raw)))
	}
	b := body(`{"s":"  x ","n":12.50,"z":0,"f":false,"t":true,"a":["a",null,1],"o":{},"e":"","nul":null}`)
	for key, want := range map[string]string{"s": "  x ", "n": "12.5", "z": "", "f": "", "t": "true", "a": "a,,1", "o": "[object Object]", "e": "", "nul": "", "missing": ""} {
		if got := b.str(key); got != want {
			t.Errorf("String(body.%s || '') = %q, want %q", key, got, want)
		}
	}
	if b.trimmed("s") != "x" {
		t.Errorf("trimmed = %q", b.trimmed("s"))
	}
	if v, present := b.value("nul"); !present || v != nil {
		t.Errorf("null must be present: %v %v", v, present)
	}
	if _, present := b.value("missing"); present {
		t.Error("missing key reported present")
	}
	// Non-objects, invalid JSON, empty and oversized bodies read as no fields.
	for _, raw := range []string{"", "null", "[1]", `"str"`, "7", "{", strings.Repeat(" ", deviceBodyLimit) + "{}"} {
		if got := body(raw); got.fields != nil {
			t.Errorf("body %.10q has fields %v", raw, got.fields)
		}
	}
	if got := body(strings.Repeat(" ", deviceBodyLimit-2) + "{}"); got.fields == nil {
		t.Error("a body at the limit must parse")
	}
}

func TestDeviceJSTrimSliceLength(t *testing.T) {
	if got := deviceJSTrim("\ufeff \u3000\u2028x\u00a0\u205f\t"); got != "x" {
		t.Errorf("trim = %q", got)
	}
	// U+0085 and U+180E are not JS whitespace.
	if got := deviceJSTrim("\u0085x\u180e"); got != "\u0085x\u180e" {
		t.Errorf("trim = %q", got)
	}
	if deviceJSLength("a\U0001F600") != 3 {
		t.Errorf("length = %d", deviceJSLength("a\U0001F600"))
	}
	for _, tc := range []struct {
		in    string
		limit int
		want  string
	}{
		{"abc", 2, "ab"},
		{"a\U0001F600b", 2, "a\uFFFD"}, // the split pair leaves a lone surrogate, stored as U+FFFD
		{"a\U0001F600b", 3, "a\U0001F600"},
		{"\U0001F600\U0001F600", 4, "\U0001F600\U0001F600"},
		{"", 64, ""},
	} {
		if got := deviceJSSlice(tc.in, tc.limit); got != tc.want {
			t.Errorf("slice(%q, %d) = %q, want %q", tc.in, tc.limit, got, tc.want)
		}
	}
}

func TestDeviceNodeHeaderAndOrigin(t *testing.T) {
	r := httptest.NewRequest(http.MethodPost, "/", nil)
	r.Header.Add("Idempotency-Key", "a")
	r.Header.Add("Idempotency-Key", "b\xe9")
	if got := deviceNodeHeader(r, "Idempotency-Key"); got != "a, bé" {
		t.Errorf("header = %q", got)
	}
	if deviceNodeHeader(r, "Origin") != "" {
		t.Error("missing header must be empty")
	}
	for base, want := range map[string]string{
		"HTTPS://Botmux.Example:443/x": "https://botmux.example",
		"http://localhost:8080":        "http://localhost:8080",
		"http://[::1]:080/":            "http://[::1]",
		"https://a.b:8443":             "https://a.b:8443",
		"":                             "null",
	} {
		if got := deviceWebOrigin(base); got != want {
			t.Errorf("origin(%q) = %q, want %q", base, got, want)
		}
	}
	a := &Apex{}
	a.Config.PublicBaseURL = "https://botmux.example"
	r.Header.Set("Origin", "https://botmux.example")
	if !a.deviceSameOrigin(r) {
		t.Error("same origin rejected")
	}
	r.Header.Add("Origin", "https://botmux.example")
	if a.deviceSameOrigin(r) {
		t.Error("a repeated Origin header joins with \", \" and must not match")
	}
}
