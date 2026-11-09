package server

import (
	"testing"
)

// Expected values are what Node 22's `new URL(...)` / URLSearchParams /
// decodeURIComponent produce.

func TestWhatwgPathname(t *testing.T) {
	cases := map[string]string{
		"":                       "/",
		"/":                      "/",
		"/a/./b/../c":            "/a/c",
		"/a/%2e/b/%2E%2e/c":      "/a/c",
		"/a/..":                  "/",
		"/a/b/.":                 "/a/b/",
		"/a\\b":                  "/a/b",
		"/a b\"<>`{}":            "/a%20b%22%3C%3E%60%7B%7D",
		"/a^|[]~":                "/a^|[]~",
		"/x/%2F/y":               "/x/%2F/y",
		"/openapi/machines/../x": "/openapi/x",
		"//double":               "/",
		"//openapi/machines":     "/machines",
		"/\\host\\a/b":           "/a/b",
		"/caf\xc3\xa9":           "/caf%C3%A9",
	}
	for in, want := range cases {
		if got := whatwgPathname(in); got != want {
			t.Fatalf("whatwgPathname(%q) = %q, want %q", in, got, want)
		}
	}
}

func TestURLSearchParams(t *testing.T) {
	pairs := parseURLSearchParams("a=1&&b=x+y&c=%zz&d=%E4%B8%AD&e&=f&a=2&g=%ff")
	want := []urlFormPair{{"a", "1"}, {"b", "x y"}, {"c", "%zz"}, {"d", "中"}, {"e", ""}, {"", "f"}, {"a", "2"}, {"g", "�"}}
	if len(pairs) != len(want) {
		t.Fatalf("pairs = %q", pairs)
	}
	for i := range want {
		if pairs[i] != want[i] {
			t.Fatalf("pair %d = %q, want %q", i, pairs[i], want[i])
		}
	}
	if v, ok := searchParamGet(pairs, "a"); !ok || v != "1" {
		t.Fatalf("get a = %q %v", v, ok)
	}
	if _, ok := searchParamGet(pairs, "zz"); ok {
		t.Fatal("get zz found")
	}
	if got := serializeURLSearchParams([]urlFormPair{{"a b", "c&d=e"}, {"~*", "中"}}); got != "a+b=c%26d%3De&%7E*=%E4%B8%AD" {
		t.Fatalf("serialize = %q", got)
	}
}

func TestURIComponentDecode(t *testing.T) {
	ok := map[string]string{"oc_1": "oc_1", "a%20b": "a b", "%E4%B8%AD": "中", "%2F": "/", "%F0%9F%98%80": "😀"}
	for in, want := range ok {
		if got, valid := uriComponentDecode(in); !valid || got != want {
			t.Fatalf("decode(%q) = %q %v", in, got, valid)
		}
	}
	for _, bad := range []string{"%", "%z1", "%ff", "%E4%B8", "%C0%AF", "%ED%A0%80"} {
		if _, valid := uriComponentDecode(bad); valid {
			t.Fatalf("decode(%q) accepted", bad)
		}
	}
}
