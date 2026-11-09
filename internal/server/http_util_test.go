package server

import (
	"net/http/httptest"
	"strings"
	"testing"
)

func TestWriteJSONMatchesJSONStringifyLineSeparators(t *testing.T) {
	for _, tc := range []struct {
		in   string
		want string
	}{
		// JSON.stringify({name:"a\u2028b\u2029c"}) keeps both separators raw.
		{"a\u2028b\u2029c", "{\"name\":\"a\u2028b\u2029c\"}"},
		// A literal backslash followed by "u2028" text stays escaped.
		{"x\\u2028", `{"name":"x\\u2028"}`},
		{"<&>", `{"name":"<&>"}`},
	} {
		recorder := httptest.NewRecorder()
		writeJSON(recorder, 200, map[string]string{"name": tc.in})
		if got := recorder.Body.String(); got != tc.want {
			t.Errorf("writeJSON(%q) = %q, want %q", tc.in, got, tc.want)
		}
	}
}

func TestTruncateCountsUTF16LikeSlice(t *testing.T) {
	// "😀".repeat(40).slice(0, 64) keeps 32 emoji in Node.
	in := strings.Repeat("😀", 40)
	if got := truncate(in, 64); got != strings.Repeat("😀", 32) {
		t.Fatalf("truncate = %d runes, want 32", len([]rune(got)))
	}
	// An odd cut splits a surrogate pair; Node stores U+FFFD for the lone half.
	if got := truncate("a😀", 2); got != "a�" {
		t.Fatalf("truncate(a😀, 2) = %q", got)
	}
	if got := truncate("héllo", 64); got != "héllo" {
		t.Fatalf("truncate kept %q", got)
	}
}
