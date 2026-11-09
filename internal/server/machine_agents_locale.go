package server

import (
	"golang.org/x/text/collate"
	"golang.org/x/text/language"
)

// localeCollator reproduces String.prototype.localeCompare without explicit
// locales: ICU collation for the process default locale, which is the CLDR
// root order for the en-US / POSIX locales the service runs under (case- and
// accent-insensitive at the primary level, lower case before upper case on
// ties, punctuation ordered before digits before letters). A Collator keeps
// internal buffers and is not safe for concurrent use: create one per sort.
type localeCollator struct{ c *collate.Collator }

func newLocaleCollator() localeCollator {
	return localeCollator{c: collate.New(language.Und)}
}

// compare returns <0, 0 or >0 like a.localeCompare(b).
func (l localeCollator) compare(a, b string) int {
	return l.c.CompareString(a, b)
}

// jsSlice mirrors String.prototype.slice(0, n): the first n UTF-16 code
// units. A surrogate pair split by the cut leaves a lone surrogate in JS; Go
// strings cannot hold one, so it becomes U+FFFD (what a UTF-8 encoder emits).
func jsSlice(value string, n int) string {
	units := 0
	for i, r := range value {
		width := 1
		if r > 0xFFFF {
			width = 2
		}
		if units+width > n {
			if units < n {
				return value[:i] + "\uFFFD"
			}
			return value[:i]
		}
		units += width
	}
	return value
}
