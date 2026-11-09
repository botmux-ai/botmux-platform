package server

import (
	"net/http"
	"net/netip"
	"strconv"
	"strings"
	"unicode/utf8"

	"golang.org/x/net/idna"

	"github.com/botmux-ai/botmux-platform/internal/config"
	"github.com/botmux-ai/botmux-platform/internal/store"
)

// WHATWG URL pieces the issue handlers need from `new URL(...)`: the request
// pathname and searchParams, the configured origin, and the https-only
// sanitizer for the bind deep link (sanitizeLocalTaskUrl).

const (
	issueLocalTaskLabelMax = 120
	issueLocalTaskURLMax   = 2048
)

// issuesSanitizeLocalTaskLabel is sanitizeLocalTaskLabel: control characters
// (including newlines) become spaces, then trim, then slice(0, 120).
func issuesSanitizeLocalTaskLabel(v string) (string, bool) {
	cleaned := strings.Map(func(r rune) rune {
		if r <= 0x1f || r == 0x7f {
			return ' '
		}
		return r
	}, v)
	cleaned = store.JSTrim(cleaned)
	if cleaned == "" {
		return "", false
	}
	return store.JSSliceUTF16(cleaned, issueLocalTaskLabelMax), true
}

// issuesSanitizeLocalTaskURL is sanitizeLocalTaskUrl: trim, at most 2048
// UTF-16 units, must parse as an absolute URL whose scheme is https, and the
// stored value is the parser's serialization (href).
func issuesSanitizeLocalTaskURL(v string) (string, bool) {
	raw := store.JSTrim(v)
	if raw == "" || issuesUTF16Len(raw) > issueLocalTaskURLMax {
		return "", false
	}
	return issuesParseHTTPSURL(raw)
}

func issuesUTF16Len(s string) int {
	n := 0
	for _, r := range s {
		if r >= 0x10000 {
			n += 2
		} else {
			n++
		}
	}
	return n
}

// issuesOriginOK is originOk: the Origin header must equal
// new URL(cfg.publicBaseUrl).origin exactly (a missing header fails).
// Node joins repeated Origin headers with ", ", which never matches.
func issuesOriginOK(cfg config.Config, r *http.Request) bool {
	origin := strings.Join(r.Header.Values("Origin"), ", ")
	want, ok := issuesURLOrigin(cfg.PublicBaseURL)
	return ok && origin == want
}

// issuesURLOrigin is new URL(base).origin for the http(s) base URL the
// platform is configured with: lowercase scheme and host, default port
// dropped.
func issuesURLOrigin(base string) (string, bool) {
	s := strings.TrimFunc(base, func(r rune) bool { return r <= 0x20 })
	s = issuesRemoveTabNewline(s)
	colon := strings.IndexByte(s, ':')
	if colon <= 0 {
		return "", false
	}
	scheme := strings.ToLower(s[:colon])
	defaultPort := map[string]string{"http": "80", "https": "443"}[scheme]
	if defaultPort == "" {
		return "", false
	}
	_, _, host, port, _, ok := issuesParseSpecialAuthority(s[colon+1:], defaultPort)
	if !ok {
		return "", false
	}
	origin := scheme + "://" + host
	if port != "" {
		origin += ":" + port
	}
	return origin, true
}

func issuesRemoveTabNewline(s string) string {
	if !strings.ContainsAny(s, "\t\n\r") {
		return s
	}
	return strings.Map(func(r rune) rune {
		if r == '\t' || r == '\n' || r == '\r' {
			return -1
		}
		return r
	}, s)
}

// issuesParseHTTPSURL runs the WHATWG basic URL parser (no base) and returns
// the href when the result's scheme is https. Internationalized hosts go
// through golang.org/x/net/idna (Unicode 15.0 tables), which can differ from
// Node's ada in edge cases; such a difference only decides whether the deep
// link is kept.
func issuesParseHTTPSURL(input string) (string, bool) {
	s := strings.TrimFunc(input, func(r rune) bool { return r <= 0x20 })
	s = issuesRemoveTabNewline(s)
	if s == "" || !issuesASCIIAlpha(s[0]) {
		return "", false
	}
	i := 1
	for i < len(s) && (issuesASCIIAlpha(s[i]) || (s[i] >= '0' && s[i] <= '9') || s[i] == '+' || s[i] == '-' || s[i] == '.') {
		i++
	}
	if i >= len(s) || s[i] != ':' || strings.ToLower(s[:i]) != "https" {
		return "", false
	}
	userinfo, rest, host, port, hasCredentials, ok := issuesParseSpecialAuthority(s[i+1:], "443")
	if !ok {
		return "", false
	}
	var href strings.Builder
	href.WriteString("https://")
	if hasCredentials {
		href.WriteString(userinfo)
		href.WriteByte('@')
	}
	href.WriteString(host)
	if port != "" {
		href.WriteByte(':')
		href.WriteString(port)
	}
	href.WriteString(issuesSerializePathQueryFragment(rest))
	return href.String(), true
}

func issuesASCIIAlpha(c byte) bool { return (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') }

// issuesParseSpecialAuthority handles "special authority (ignore) slashes",
// authority, host and port states for a special scheme. It returns the
// serialized userinfo ("user" or "user:pass", meaningful when hasCredentials),
// the remaining input (starting at the path), the serialized host and the
// port ("" when absent or default).
func issuesParseSpecialAuthority(s, defaultPort string) (userinfo, rest, host, port string, hasCredentials, ok bool) {
	s = strings.TrimLeft(s, `/\`)
	end := strings.IndexAny(s, `/\?#`)
	if end < 0 {
		end = len(s)
	}
	authority, rest := s[:end], s[end:]
	if at := strings.LastIndexByte(authority, '@'); at >= 0 {
		user, pass, _ := strings.Cut(authority[:at], ":")
		user = issuesPercentEncode(user, issuesUserinfoSet)
		pass = issuesPercentEncode(pass, issuesUserinfoSet)
		authority = authority[at+1:]
		if authority == "" {
			return "", "", "", "", false, false
		}
		if user != "" || pass != "" {
			hasCredentials = true
			userinfo = user
			if pass != "" {
				userinfo += ":" + pass
			}
		}
	}
	hostPart, portPart, hasPort := authority, "", false
	inBrackets := false
	for i := 0; i < len(authority); i++ {
		switch authority[i] {
		case '[':
			inBrackets = true
		case ']':
			inBrackets = false
		case ':':
			if !inBrackets {
				hostPart, portPart, hasPort = authority[:i], authority[i+1:], true
				i = len(authority)
			}
		}
	}
	if hostPart == "" {
		return "", "", "", "", false, false
	}
	host, ok = issuesParseHost(hostPart)
	if !ok {
		return "", "", "", "", false, false
	}
	if hasPort && portPart != "" {
		for i := 0; i < len(portPart); i++ {
			if portPart[i] < '0' || portPart[i] > '9' {
				return "", "", "", "", false, false
			}
		}
		digits := strings.TrimLeft(portPart, "0")
		if len(digits) > 5 {
			return "", "", "", "", false, false
		}
		n := 0
		if digits != "" {
			n, _ = strconv.Atoi(digits)
		}
		if n > 65535 {
			return "", "", "", "", false, false
		}
		port = strconv.Itoa(n)
		if port == defaultPort {
			port = ""
		}
	}
	return userinfo, rest, host, port, hasCredentials, true
}

// issuesParseHost is the host parser for a special, non-opaque host.
func issuesParseHost(input string) (string, bool) {
	if strings.HasPrefix(input, "[") {
		if !strings.HasSuffix(input, "]") || len(input) < 2 {
			return "", false
		}
		return issuesParseIPv6(input[1 : len(input)-1])
	}
	domain, ok := issuesDomainToASCII(issuesPercentDecode(input))
	if !ok || domain == "" {
		return "", false
	}
	for i := 0; i < len(domain); i++ {
		c := domain[i]
		if c <= 0x20 || c == 0x7f || strings.IndexByte(`#%/:<>?@[\]^|`, c) >= 0 {
			return "", false
		}
	}
	if issuesEndsInNumber(domain) {
		return issuesParseIPv4(domain)
	}
	return domain, true
}

// issuesIDNA is the UTS #46 ToASCII profile of WHATWG "domain to ASCII"
// (beStrict=false): CheckHyphens=false, CheckBidi=true, CheckJoiners=true,
// UseSTD3ASCIIRules=false, Transitional_Processing=false,
// VerifyDnsLength=false.
var issuesIDNA = idna.New(
	idna.MapForLookup(),
	idna.BidiRule(),
	idna.CheckHyphens(false),
	idna.CheckJoiners(true),
	idna.StrictDomainName(false),
	idna.Transitional(false),
	idna.VerifyDNSLength(false),
)

// issuesDomainToASCII is WHATWG "domain to ASCII" with beStrict=false: an
// ASCII domain without an "xn--" label is just lowercased; anything else
// goes through UTS #46 ToASCII, and any error is a host-parsing failure.
func issuesDomainToASCII(domain string) (string, bool) {
	needsIDNA := !issuesIsASCII(domain)
	if !needsIDNA {
		for _, label := range strings.Split(domain, ".") {
			if len(label) >= 4 && strings.EqualFold(label[:4], "xn--") {
				needsIDNA = true
				break
			}
		}
	}
	if !needsIDNA {
		return strings.ToLower(domain), true
	}
	if !utf8.ValidString(domain) {
		return "", false
	}
	ascii, err := issuesIDNA.ToASCII(domain)
	if err != nil {
		return "", false
	}
	// x/net/idna re-encodes a decoded "xn--" label, so one whose Punycode
	// decodes to ASCII ("xn--abc-") comes back as "abc" and "xn--" as an empty
	// label. Node's ada keeps such a label as written (lowercased) and rejects
	// an empty decode; restore that when the labels line up.
	in := strings.Split(issuesLabelSeparators.Replace(domain), ".")
	out := strings.Split(ascii, ".")
	if len(in) == len(out) {
		for i, label := range in {
			if len(label) < 4 || !strings.EqualFold(label[:4], "xn--") || !issuesIsASCII(label) {
				continue
			}
			if out[i] == "" {
				return "", false
			}
			out[i] = strings.ToLower(label)
		}
		ascii = strings.Join(out, ".")
	}
	return ascii, true
}

// issuesLabelSeparators maps the code points UTS #46 turns into '.'.
var issuesLabelSeparators = strings.NewReplacer("\u3002", ".", "\uff0e", ".", "\uff61", ".")

func issuesIsASCII(s string) bool {
	for i := 0; i < len(s); i++ {
		if s[i] >= 0x80 {
			return false
		}
	}
	return true
}

func issuesEndsInNumber(domain string) bool {
	parts := strings.Split(domain, ".")
	if parts[len(parts)-1] == "" {
		if len(parts) == 1 {
			return false
		}
		parts = parts[:len(parts)-1]
	}
	last := parts[len(parts)-1]
	if last != "" && strings.Trim(last, "0123456789") == "" {
		return true
	}
	_, ok := issuesParseIPv4Number(last)
	return ok
}

// issuesParseIPv4Number accepts decimal, 0x hex and leading-zero octal; the
// result saturates above 2^32 (callers reject it anyway).
func issuesParseIPv4Number(input string) (uint64, bool) {
	if input == "" {
		return 0, false
	}
	radix := uint64(10)
	switch {
	case len(input) >= 2 && (input[:2] == "0x" || input[:2] == "0X"):
		radix, input = 16, input[2:]
	case len(input) >= 2 && input[0] == '0':
		radix, input = 8, input[1:]
	}
	var n uint64
	for i := 0; i < len(input); i++ {
		c := input[i]
		var d uint64
		switch {
		case c >= '0' && c <= '9':
			d = uint64(c - '0')
		case c >= 'a' && c <= 'f':
			d = uint64(c-'a') + 10
		case c >= 'A' && c <= 'F':
			d = uint64(c-'A') + 10
		default:
			return 0, false
		}
		if d >= radix {
			return 0, false
		}
		if n < 1<<40 {
			n = n*radix + d
		}
	}
	return n, true
}

func issuesParseIPv4(input string) (string, bool) {
	parts := strings.Split(input, ".")
	if parts[len(parts)-1] == "" && len(parts) > 1 {
		parts = parts[:len(parts)-1]
	}
	if len(parts) > 4 {
		return "", false
	}
	numbers := make([]uint64, len(parts))
	for i, part := range parts {
		n, ok := issuesParseIPv4Number(part)
		if !ok {
			return "", false
		}
		numbers[i] = n
	}
	for _, n := range numbers[:len(numbers)-1] {
		if n > 255 {
			return "", false
		}
	}
	last := numbers[len(numbers)-1]
	if last >= uint64(1)<<(8*(5-len(numbers))) {
		return "", false
	}
	ipv4 := last
	for i, n := range numbers[:len(numbers)-1] {
		ipv4 += n << (8 * (3 - i))
	}
	return strconv.FormatUint(ipv4>>24, 10) + "." + strconv.FormatUint(ipv4>>16&0xff, 10) + "." +
		strconv.FormatUint(ipv4>>8&0xff, 10) + "." + strconv.FormatUint(ipv4&0xff, 10), true
}

// issuesParseIPv6 accepts what the WHATWG IPv6 parser accepts (no zone ids,
// embedded IPv4 only as four strict decimals) and serializes it the WHATWG
// way: lowercase, first longest run of 2+ zero pieces compressed, embedded
// IPv4 written as hex pieces.
func issuesParseIPv6(input string) (string, bool) {
	if strings.ContainsAny(input, "%") {
		return "", false
	}
	addr, err := netip.ParseAddr(input)
	if err != nil || !addr.Is6() {
		return "", false
	}
	bytes16 := addr.As16()
	var pieces [8]uint16
	for i := range pieces {
		pieces[i] = uint16(bytes16[2*i])<<8 | uint16(bytes16[2*i+1])
	}
	compress, best := -1, 1
	for i := 0; i < 8; {
		if pieces[i] != 0 {
			i++
			continue
		}
		j := i
		for j < 8 && pieces[j] == 0 {
			j++
		}
		if j-i > best {
			compress, best = i, j-i
		}
		i = j
	}
	var out strings.Builder
	out.WriteByte('[')
	for i := 0; i < 8; i++ {
		if compress >= 0 && i >= compress && i < compress+best {
			if i == compress {
				if i == 0 {
					out.WriteString("::")
				} else {
					out.WriteByte(':')
				}
			}
			continue
		}
		out.WriteString(strconv.FormatUint(uint64(pieces[i]), 16))
		if i != 7 {
			out.WriteByte(':')
		}
	}
	out.WriteByte(']')
	return out.String(), true
}

// issuesSerializePathQueryFragment runs the path / query / fragment states for
// a special URL on the input after the authority and returns the serialized
// "/path?query#fragment".
func issuesSerializePathQueryFragment(rest string) string {
	pathPart, query, fragment := rest, "", ""
	hasQuery, hasFragment := false, false
	if i := strings.IndexByte(pathPart, '#'); i >= 0 {
		pathPart, fragment, hasFragment = pathPart[:i], pathPart[i+1:], true
	}
	if i := strings.IndexByte(pathPart, '?'); i >= 0 {
		pathPart, query, hasQuery = pathPart[:i], pathPart[i+1:], true
	}
	out := issuesNormalizePath(pathPart)
	if hasQuery {
		out += "?" + issuesPercentEncode(query, issuesSpecialQuerySet)
	}
	if hasFragment {
		out += "#" + issuesPercentEncode(fragment, issuesFragmentSet)
	}
	return out
}

// issuesNormalizePath is the path start + path states of a special URL:
// '\' is a separator, "." / ".." segments (including %2e forms) are
// resolved, and code points outside the path set are percent-encoded. The
// result always starts with "/".
func issuesNormalizePath(path string) string {
	if strings.HasPrefix(path, "/") || strings.HasPrefix(path, `\`) {
		path = path[1:]
	}
	var segments []string
	for {
		end := strings.IndexAny(path, `/\`)
		last := end < 0
		segment := path
		if !last {
			segment = path[:end]
		}
		buffer := issuesPercentEncode(segment, issuesPathSet)
		switch {
		case issuesDoubleDotSegment(buffer):
			if len(segments) > 0 {
				segments = segments[:len(segments)-1]
			}
			if last {
				segments = append(segments, "")
			}
		case issuesSingleDotSegment(buffer):
			if last {
				segments = append(segments, "")
			}
		default:
			segments = append(segments, buffer)
		}
		if last {
			break
		}
		path = path[end+1:]
	}
	return "/" + strings.Join(segments, "/")
}

func issuesSingleDotSegment(s string) bool { return s == "." || strings.EqualFold(s, "%2e") }

func issuesDoubleDotSegment(s string) bool {
	switch strings.ToLower(s) {
	case "..", ".%2e", "%2e.", "%2e%2e":
		return true
	}
	return false
}

type issuesEncodeSet func(c byte) bool

func issuesC0ControlSet(c byte) bool { return c < 0x20 || c > 0x7e }

func issuesFragmentSet(c byte) bool {
	return issuesC0ControlSet(c) || c == ' ' || c == '"' || c == '<' || c == '>' || c == '`'
}

func issuesQuerySet(c byte) bool {
	return issuesC0ControlSet(c) || c == ' ' || c == '"' || c == '#' || c == '<' || c == '>'
}

func issuesSpecialQuerySet(c byte) bool { return issuesQuerySet(c) || c == '\'' }

func issuesPathSet(c byte) bool {
	return issuesQuerySet(c) || c == '?' || c == '`' || c == '{' || c == '}'
}

func issuesUserinfoSet(c byte) bool {
	return issuesPathSet(c) || strings.IndexByte(`/:;=@[\]^|`, c) >= 0
}

// issuesPercentEncode UTF-8 percent-encodes s byte-wise with the given set
// ('%' itself is never encoded). Invalid UTF-8 is first replaced by U+FFFD,
// matching a JS string built from the same bytes.
func issuesPercentEncode(s string, set issuesEncodeSet) string {
	if !utf8.ValidString(s) {
		s = strings.ToValidUTF8(s, "\uFFFD")
	}
	const hex = "0123456789ABCDEF"
	var out strings.Builder
	for i := 0; i < len(s); i++ {
		c := s[i]
		if set(c) {
			out.WriteByte('%')
			out.WriteByte(hex[c>>4])
			out.WriteByte(hex[c&0xf])
		} else {
			out.WriteByte(c)
		}
	}
	return out.String()
}

func issuesUnhex(c byte) (byte, bool) {
	switch {
	case c >= '0' && c <= '9':
		return c - '0', true
	case c >= 'a' && c <= 'f':
		return c - 'a' + 10, true
	case c >= 'A' && c <= 'F':
		return c - 'A' + 10, true
	}
	return 0, false
}

// issuesPercentDecode decodes valid %XX escapes and leaves everything else.
func issuesPercentDecode(s string) string {
	if !strings.Contains(s, "%") {
		return s
	}
	out := make([]byte, 0, len(s))
	for i := 0; i < len(s); i++ {
		if s[i] == '%' && i+2 < len(s) {
			hi, ok1 := issuesUnhex(s[i+1])
			lo, ok2 := issuesUnhex(s[i+2])
			if ok1 && ok2 {
				out = append(out, hi<<4|lo)
				i += 2
				continue
			}
		}
		out = append(out, s[i])
	}
	return string(out)
}

// issuesRequestTarget splits the raw request-target into the WHATWG pathname
// (new URL(req.url, base).pathname) and the raw query. Origin-form targets go
// through the path state (dot segments, '\', percent-encoding); anything else
// falls back to Go's parsed URL.
func issuesRequestTarget(r *http.Request) (pathname, rawQuery string) {
	target := r.RequestURI
	if !strings.HasPrefix(target, "/") || strings.HasPrefix(target, "//") || strings.HasPrefix(target, `/\`) {
		return r.URL.EscapedPath(), r.URL.RawQuery
	}
	target = issuesRemoveTabNewline(target)
	if i := strings.IndexByte(target, '#'); i >= 0 {
		target = target[:i]
	}
	pathPart, query, _ := strings.Cut(target, "?")
	return issuesNormalizePath(pathPart), query
}

// issuesSearchParam is url.searchParams.get(name): the first pair whose
// decoded name matches ('+' is a space, invalid escapes stay literal).
func issuesSearchParam(rawQuery, name string) (string, bool) {
	for _, pair := range strings.Split(rawQuery, "&") {
		if pair == "" {
			continue
		}
		key, value, _ := strings.Cut(pair, "=")
		if issuesFormDecode(key) == name {
			return issuesFormDecode(value), true
		}
	}
	return "", false
}

func issuesFormDecode(s string) string {
	decoded := issuesPercentDecode(strings.ReplaceAll(s, "+", " "))
	if !utf8.ValidString(decoded) {
		decoded = strings.ToValidUTF8(decoded, "\uFFFD")
	}
	return decoded
}
