package proxy

import "testing"

// Expected values are new URL(path, "http://x").pathname from Node.
func TestWHATWGPathnameMatchesNode(t *testing.T) {
	for _, tc := range []struct{ in, want string }{
		{"/", "/"},
		{"", "/"},
		{"/a/b", "/a/b"},
		{"/a/./b", "/a/b"},
		{"/a/../b", "/b"},
		{"/a/%2e%2E/b", "/b"},
		{"/a\\b", "/a/b"},
		{"/a/b/..", "/a/"},
		{"/a/b/.", "/a/b/"},
		{"/a b", "/a%20b"},
		{"/é", "/%C3%A9"},
		{"/a\"b<c>", "/a%22b%3Cc%3E"},
		{"/`{}", "/%60%7B%7D"},
		{"/a|b", "/a|b"},
		{"/%", "/%"},
		{"/a/..%2f", "/a/..%2f"},
		{"/../x", "/x"},
		{"/s/%2e%2e/api", "/api"},
		{"//host/p", "/p"},
		{"//host", "/"},
	} {
		if got := WHATWGPathname(tc.in); got != tc.want {
			t.Errorf("WHATWGPathname(%q) = %q, want %q", tc.in, got, tc.want)
		}
	}
}
