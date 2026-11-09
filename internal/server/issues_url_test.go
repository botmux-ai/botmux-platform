package server

import (
	"math"
	"net/http/httptest"
	"testing"
)

// The vectors below were produced by Node 22 (the TS runtime): `new URL(...)`
// for sanitizeLocalTaskUrl and request targets, URLSearchParams.get, Number()
// and the sanitizeLocalTaskLabel expression.

func TestIssuesSanitizeLocalTaskURLMatchesNode(t *testing.T) {
	cases := []struct{ in, want string }{
		{"https://example.com", "https://example.com/"},
		{"https://example.com/", "https://example.com/"},
		{"HTTPS://EXAMPLE.COM/A/B", "https://example.com/A/B"},
		{"https://example.com:443/x", "https://example.com/x"},
		{"https://example.com:8443/x", "https://example.com:8443/x"},
		{"https://example.com:0443/x", "https://example.com/x"},
		{"https://example.com:/x", "https://example.com/x"},
		{"https://user:pass@example.com/x", "https://user:pass@example.com/x"},
		{"https://user@example.com", "https://user@example.com/"},
		{"https://@example.com", "https://example.com/"},
		{"https://:@example.com", "https://example.com/"},
		{"https://us er:p@ss@example.com/", "https://us%20er:p%40ss@example.com/"},
		{"https://u%40x:p@h/", "https://u%40x:p@h/"},
		{"https:example.com/x", "https://example.com/x"},
		{"https:/example.com/x", "https://example.com/x"},
		{"https:\\\\example.com\\a\\b", "https://example.com/a/b"},
		{"https:///example.com", "https://example.com/"},
		{"https://\\example.com", "https://example.com/"},
		{"https://a/b/../c/./d", "https://a/c/d"},
		{"https://a/b/%2e%2E/c", "https://a/c"},
		{"https://a/b/.%2e/c", "https://a/c"},
		{"https://a/..", "https://a/"},
		{"https://a/./", "https://a/"},
		{"https://a/b/..?q", "https://a/?q"},
		{"https://a/b/.#f", "https://a/b/#f"},
		{"https://a/p q?r s#t u", "https://a/p%20q?r%20s#t%20u"},
		{"https://a/\"<>`{}^|?\"<>'`{}^|#\"<>`{}^|", "https://a/%22%3C%3E%60%7B%7D^|?%22%3C%3E%27`{}^|#%22%3C%3E%60{}^|"},
		{"https://a/\u00e9?\u00e9#\u00e9", "https://a/%C3%A9?%C3%A9#%C3%A9"},
		{"https://a/%zz%2g%41", "https://a/%zz%2g%41"},
		{"https://127.0.0.1/", "https://127.0.0.1/"},
		{"https://0x7f.1/", "https://127.0.0.1/"},
		{"https://0177.0.0.1/", "https://127.0.0.1/"},
		{"https://2130706433/", "https://127.0.0.1/"},
		{"https://127.1/", "https://127.0.0.1/"},
		{"https://1.2.3.4.5/", ""},
		{"https://256.0.0.1/", ""},
		{"https://1.2.3.256/", ""},
		{"https://1.2.3.0x100/", ""},
		{"https://4294967295/", "https://255.255.255.255/"},
		{"https://4294967296/", ""},
		{"https://0x/", "https://0.0.0.0/"},
		{"https://1.2.3.4./", "https://1.2.3.4/"},
		{"https://1.2.3.4../", "https://1.2.3.4../"},
		{"https://09/", ""},
		{"https://foo.09/", ""},
		{"https://foo.0x10/", ""},
		{"https://foo.1e1/", "https://foo.1e1/"},
		{"https://[::1]/", "https://[::1]/"},
		{"https://[0:0:0:0:0:0:0:1]/", "https://[::1]/"},
		{"https://[::ffff:127.0.0.1]/", "https://[::ffff:7f00:1]/"},
		{"https://[2001:db8:0:0:1:0:0:1]/", "https://[2001:db8::1:0:0:1]/"},
		{"https://[2001:DB8::]/", "https://[2001:db8::]/"},
		{"https://[1:0:0:2:0:0:0:3]/", "https://[1:0:0:2::3]/"},
		{"https://[::]/", "https://[::]/"},
		{"https://[fe80::1%25eth0]/", ""},
		{"https://[::1/", ""},
		{"https://[1::2::3]/", ""},
		{"https://[0:0:0:0:0:0:0:0:1]/", ""},
		{"https://[::1.2.3]/", ""},
		{"https://[1:2:3:4:5:6:7::]/", "https://[1:2:3:4:5:6:7:0]/"},
		{"https://ex%41mple.com/", "https://example.com/"},
		{"https://exa mple.com/", ""},
		{"https://ex<ample.com/", ""},
		{"https://ex^ample.com/", ""},
		{"https://ex%00ample.com/", ""},
		{"https://ex|ample.com/", ""},
		{"https://ex*ample.com/", "https://ex*ample.com/"},
		{"https://ex_ample.com/", "https://ex_ample.com/"},
		{"https://EX$ample.com/", "https://ex$ample.com/"},
		{"https://xn--nxasmq6b.com/", "https://xn--nxasmq6b.com/"},
		{"https://\u00fcber.de/", "https://xn--ber-goa.de/"},
		{"https://\u4f8b\u3048.jp/", "https://xn--r8jz45g.jp/"},
		{"https://ex%C3%BCample.com/", "https://xn--example-o2a.com/"},
		{"https://a.b.c.d/", "https://a.b.c.d/"},
		{"https://-a-.com/", "https://-a-.com/"},
		{"https:// a.com/", ""},
		{"https://a.com:65535/", "https://a.com:65535/"},
		{"https://a.com:65536/", ""},
		{"https://a.com:1a/", ""},
		{"https://a.com:+1/", ""},
		{"https://a.com?x=1&y=2", "https://a.com/?x=1&y=2"},
		{"https://a.com#frag", "https://a.com/#frag"},
		{"https://a.com/?", "https://a.com/?"},
		{"https://a.com/#", "https://a.com/#"},
		{"https://a.com/a?b#c?d#e", "https://a.com/a?b#c?d#e"},
		{"https://a.com/\x09\x0a\x0dx", "https://a.com/x"},
		{"  https://a.com/x  ", "https://a.com/x"},
		{"https://a.com/\x01", "https://a.com/"},
		{"http://a.com/", ""},
		{"javascript:alert(1)", ""},
		{"data:text/html,x", ""},
		{"file:///etc/passwd", ""},
		{"ftp://a.com/", ""},
		{"https", ""},
		{"https:", ""},
		{"https:/", ""},
		{"https://", ""},
		{"https:///", ""},
		{"https://?x", ""},
		{"https://#x", ""},
		{"https://a.com:443", "https://a.com/"},
		{"https://applink.feishu.cn/client/chat/open?openChatId=oc_123&x=%E4%B8%AD", "https://applink.feishu.cn/client/chat/open?openChatId=oc_123&x=%E4%B8%AD"},
		{"https://a/%2e", "https://a/"},
		{"https://a/%2e%2e", "https://a/"},
		{"https://a/b/c/%2e%2e/%2e%2e/%2e%2e/d", "https://a/d"},
		{"https://a/C:/../x", "https://a/x"},
		{"https://a/;x/..", "https://a/"},
		{"https://a.com/x/..\\y", "https://a.com/y"},
		{"https://user:pa:ss@a.com/", "https://user:pa%3Ass@a.com/"},
		{"https://us/er@a.com/", "https://us/er@a.com/"},
		{"https://a@b@c/", "https://a%40b@c/"},
		{"https://a%zzb@c/", "https://a%zzb@c/"},
		{"https://[::1]:8080/", "https://[::1]:8080/"},
		{"https://[::1]:443/", "https://[::1]/"},
		{"https://a.com.:443/", "https://a.com./"},
		{"https://A.COM./", "https://a.com./"},
		{"https://a..com/", "https://a..com/"},
		{"https://.a.com/", "https://.a.com/"},
		{"https://0.0.0.0/", "https://0.0.0.0/"},
		{"https://0/", "https://0.0.0.0/"},
		{"https://0x7fffffff/", "https://127.255.255.255/"},
		{"https://1.0x/", "https://1.0.0.0/"},
		{"https://08.1/", ""},
		{"https://1.08/", ""},
		{"https://a/b?c=d e&f=\"g\"&h='i'", "https://a/b?c=d%20e&f=%22g%22&h=%27i%27"},
		{"https://xn--nxasmq6b.com/p", "https://xn--nxasmq6b.com/p"},
		{"https://XN--NXASMQ6B.COM/p", "https://xn--nxasmq6b.com/p"},
		{"https://\u00fcber.de/p", "https://xn--ber-goa.de/p"},
		{"https://\u00dcBER.de/p", "https://xn--ber-goa.de/p"},
		{"https://\u4f8b\u3048.jp/p", "https://xn--r8jz45g.jp/p"},
		{"https://ex%C3%BCample.com/p", "https://xn--example-o2a.com/p"},
		{"https://fa\u00df.de/p", "https://xn--fa-hia.de/p"},
		{"https://xn--zca.de/p", "https://xn--zca.de/p"},
		{"https://xn--a.com/p", ""},
		{"https://xn--.com/p", ""},
		{"https://xn--abc-.com/p", "https://xn--abc-.com/p"},
		{"https://a\u200db.com/p", ""},
		{"https://\u0627\u0644\u0639\u0631\u0628\u064a\u0629.com/p", "https://xn--mgbcd4a2b0d2b.com/p"},
		{"https://a.\u0627b.com/p", ""},
		{"https://\u05d0\u05d1.com/p", "https://xn--4dbc.com/p"},
		{"https://\u0301a.com/p", ""},
		{"https://\uff45\uff58\uff41\uff4d\uff50\uff4c\uff45.com/p", "https://example.com/p"},
		{"https://a\u3002b.com/p", "https://a.b.com/p"},
		{"https://a\uff0eb/p", "https://a.b/p"},
		{"https://xn--55qx5d.cn/p", "https://xn--55qx5d.cn/p"},
		{"https://\u4e2d\u56fd.cn/p", "https://xn--fiqs8s.cn/p"},
		{"https://-\u00fcber-.de/p", "https://xn---ber--kva.de/p"},
		{"https://\u00fcber--x.de/p", "https://xn--ber--x-2ya.de/p"},
		{"https://ab--c.com/p", "https://ab--c.com/p"},
		{"https://\u00ad.com/p", "https://.com/p"},
		{"https://a\u00adb.com/p", "https://ab.com/p"},
		{"https://\u2665.com/p", "https://xn--g6h.com/p"},
		{"https://\U0001f600.com/p", "https://xn--e28h.com/p"},
		{"https://xn--ls8h.la/p", "https://xn--ls8h.la/p"},
		{"https://\U0001f4a9.la/p", "https://xn--ls8h.la/p"},
		{"https://a%ff.com/p", ""},
		{"https://%e4%b8%ad.cn/p", "https://xn--fiq.cn/p"},
		{"https://xn--ber-goa.de/p", "https://xn--ber-goa.de/p"},
		{"https://xn--BER-GOA.de/p", "https://xn--ber-goa.de/p"},
		{"https://xn--u-ccb.com/p", ""},
		{"https://stra\u00dfe.de/p", "https://xn--strae-oqa.de/p"},
		{"https://\u03c2.gr/p", "https://xn--3xa.gr/p"},
		{"https://a.b.xn--c/p", ""},
		{"https://1.xn--2/p", ""},
		{"https://xn--1.com/p", ""},
		{"https://a..\u00fcber/p", "https://a..xn--ber-goa/p"},
		{"https://.\u00fcber.de/p", "https://.xn--ber-goa.de/p"},
		{"https://\u00fcber.de./p", "https://xn--ber-goa.de./p"},
		{"https://\u210c.com/p", "https://h.com/p"},
		{"https://\u2028.com/p", ""},
		{"https://\u200b.com/p", "https://.com/p"},
		{"https://\ufeffa.com/p", "https://a.com/p"},
		{"https://\u00df/p", "https://xn--zca/p"},
		{"https://r3---sn-apo3qvuoxuxbt-j5pe.googlevideo.com/p", "https://r3---sn-apo3qvuoxuxbt-j5pe.googlevideo.com/p"},
		{"https://xn--r3---sn-apo3qvuoxuxbt-j5pe.com/p", ""},
		{"https://I\u0307.com/p", "https://xn--i-9bb.com/p"},
		{"https://\u0130.com/p", "https://xn--i-9bb.com/p"},
		{"https://\u01c5.com/p", "https://xn--d-toa.com/p"},
		{"https://a\u0308.com/p", "https://xn--4ca.com/p"},
		{"https://a^b:c^d@h/", "https://a%5Eb:c%5Ed@h/"},
		{"https://a{b}:c|d@h/", "https://a%7Bb%7D:c%7Cd@h/"},
		{"https://a`b@h/", "https://a%60b@h/"},
		{"https://a\"b@h/", "https://a%22b@h/"},
		{"https://a b@h/", "https://a%20b@h/"},
		{"https://%61@h/", "https://%61@h/"},
		{"https://a\u00e9@h/", "https://a%C3%A9@h/"},
		{"https://h/a^b", "https://h/a^b"},
		{"https://xn--/q", ""},
		{"https://xn---/q", ""},
		{"https://xn--a-/q", "https://xn--a-/q"},
		{"https://xn--ab-/q", "https://xn--ab-/q"},
		{"https://xn--1-/q", "https://xn--1-/q"},
		{"https://xn--Ab-/q", "https://xn--ab-/q"},
		{"https://XN--ab-/q", "https://xn--ab-/q"},
		{"https://xn--ab-.xn--ber-goa/q", "https://xn--ab-.xn--ber-goa/q"},
		{"https://\u00fcber.xn--abc-/q", "https://xn--ber-goa.xn--abc-/q"},
		{"https://xn--abc-\u3002com/q", "https://xn--abc-.com/q"},
		{"https://xn--ab-c/q", ""},
		{"https://xn--abc-/q", "https://xn--abc-/q"},
		{"https://xn--a-b-/q", "https://xn--a-b-/q"},
		{"https://xn--ab--/q", "https://xn--ab--/q"},
		{"https://xn--\u00fc/q", ""},
		{"https://xn--ber-goa/q", "https://xn--ber-goa/q"},
		{"https://xn--zca/q", "https://xn--zca/q"},
		{"https://xn--ss-/q", "https://xn--ss-/q"},
		{"https://xn--.xn--/q", ""},
		{"https://a.xn--/q", ""},
		{"https://xn--abc-./q", "https://xn--abc-./q"},
		{"https://xn--abc-../q", "https://xn--abc-../q"},
		{"https://..xn--abc-/q", "https://..xn--abc-/q"},
		{"https://xn--abc-\uff0ecom/q", "https://xn--abc-.com/q"},
		{"https://Xn--abc-.\u00fcber/q", "https://xn--abc-.xn--ber-goa/q"},
		{"https://xn--abc-.1/q", ""},
		{"https://xn--abc-.0x10/q", ""},
		{"https://xn--abc-.09/q", ""},
		{"https://\u00fcber.1/q", ""},
		{"https://\u00fcber.0x7f.1/q", ""},
		{"https://\uff11\uff12\uff17.0.0.1/q", "https://127.0.0.1/q"},
		{"https://\uff10\uff58\uff17\uff46.1/q", "https://127.0.0.1/q"},
		{"https://a.b.c.\u24d0/q", "https://a.b.c.a/q"},
		{"https://xn--9n2bp8q/q", "https://xn--9n2bp8q/q"},
		{"https://xn--ls8h/q", "https://xn--ls8h/q"},
		{"https://xn--abc-\u24d0.com/q", ""},
		{"https://%78n--abc-.com/q", "https://xn--abc-.com/q"},
	}
	for _, tc := range cases {
		got, ok := issuesSanitizeLocalTaskURL(tc.in)
		if ok != (tc.want != "") || got != tc.want {
			t.Errorf("issuesSanitizeLocalTaskURL(%q) = (%q, %v), want %q", tc.in, got, ok, tc.want)
		}
	}
}

func TestIssuesSanitizeLocalTaskURLLengthLimit(t *testing.T) {
	prefix := "https://a.example/"
	fits := prefix + repeatString("x", issueLocalTaskURLMax-len(prefix))
	if got, ok := issuesSanitizeLocalTaskURL("  " + fits + "  "); !ok || got != fits {
		t.Fatalf("2048 units after trim should pass, got (%q, %v)", got, ok)
	}
	if _, ok := issuesSanitizeLocalTaskURL(fits + "x"); ok {
		t.Fatal("2049 units should be dropped")
	}
	// Length is counted in UTF-16 units: an astral code point counts twice.
	astral := prefix + repeatString("\U0001F600", (issueLocalTaskURLMax-len(prefix))/2+1)
	if _, ok := issuesSanitizeLocalTaskURL(astral); ok {
		t.Fatal("over-long astral URL should be dropped")
	}
}

func repeatString(s string, n int) string {
	out := make([]byte, 0, len(s)*n)
	for i := 0; i < n; i++ {
		out = append(out, s...)
	}
	return string(out)
}

func TestIssuesSanitizeLocalTaskLabelMatchesNode(t *testing.T) {
	cases := []struct {
		in, want string
		ok       bool
	}{
		{"Task 1", "Task 1", true},
		{"  padded  ", "padded", true},
		{"a\x0ab\x09c\x0dd", "a b c d", true},
		{"\x00\x1f\x7f", "", false},
		{"\u00a0\ufeff x \u2028\u3000", "x", true},
		{"\u0085next", "\u0085next", true},
		{"xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx", "xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx", true},
		{"\u00e9\u00e9\u00e9\u00e9\u00e9\u00e9\u00e9\u00e9\u00e9\u00e9\u00e9\u00e9\u00e9\u00e9\u00e9\u00e9\u00e9\u00e9\u00e9\u00e9\u00e9\u00e9\u00e9\u00e9\u00e9\u00e9\u00e9\u00e9\u00e9\u00e9\u00e9\u00e9\u00e9\u00e9\u00e9\u00e9\u00e9\u00e9\u00e9\u00e9\u00e9\u00e9\u00e9\u00e9\u00e9\u00e9\u00e9\u00e9\u00e9\u00e9\u00e9\u00e9\u00e9\u00e9\u00e9\u00e9\u00e9\u00e9\u00e9\u00e9\u00e9\u00e9\u00e9\u00e9\u00e9\u00e9\u00e9\u00e9\u00e9\u00e9\u00e9\u00e9\u00e9\u00e9\u00e9\u00e9\u00e9\u00e9\u00e9\u00e9\u00e9\u00e9\u00e9\u00e9\u00e9\u00e9\u00e9\u00e9\u00e9\u00e9\u00e9\u00e9\u00e9\u00e9\u00e9\u00e9\u00e9\u00e9\u00e9\u00e9\u00e9\u00e9\u00e9\u00e9\u00e9\u00e9\u00e9\u00e9\u00e9\u00e9\u00e9\u00e9\u00e9\u00e9\u00e9\u00e9\u00e9\u00e9\u00e9\u00e9\u00e9", "\u00e9\u00e9\u00e9\u00e9\u00e9\u00e9\u00e9\u00e9\u00e9\u00e9\u00e9\u00e9\u00e9\u00e9\u00e9\u00e9\u00e9\u00e9\u00e9\u00e9\u00e9\u00e9\u00e9\u00e9\u00e9\u00e9\u00e9\u00e9\u00e9\u00e9\u00e9\u00e9\u00e9\u00e9\u00e9\u00e9\u00e9\u00e9\u00e9\u00e9\u00e9\u00e9\u00e9\u00e9\u00e9\u00e9\u00e9\u00e9\u00e9\u00e9\u00e9\u00e9\u00e9\u00e9\u00e9\u00e9\u00e9\u00e9\u00e9\u00e9\u00e9\u00e9\u00e9\u00e9\u00e9\u00e9\u00e9\u00e9\u00e9\u00e9\u00e9\u00e9\u00e9\u00e9\u00e9\u00e9\u00e9\u00e9\u00e9\u00e9\u00e9\u00e9\u00e9\u00e9\u00e9\u00e9\u00e9\u00e9\u00e9\u00e9\u00e9\u00e9\u00e9\u00e9\u00e9\u00e9\u00e9\u00e9\u00e9\u00e9\u00e9\u00e9\u00e9\u00e9\u00e9\u00e9\u00e9\u00e9\u00e9\u00e9\u00e9\u00e9\u00e9\u00e9\u00e9\u00e9\u00e9\u00e9\u00e9\u00e9", true},
		{"a\U0001f600\U0001f600\U0001f600\U0001f600\U0001f600\U0001f600\U0001f600\U0001f600\U0001f600\U0001f600\U0001f600\U0001f600\U0001f600\U0001f600\U0001f600\U0001f600\U0001f600\U0001f600\U0001f600\U0001f600\U0001f600\U0001f600\U0001f600\U0001f600\U0001f600\U0001f600\U0001f600\U0001f600\U0001f600\U0001f600\U0001f600\U0001f600\U0001f600\U0001f600\U0001f600\U0001f600\U0001f600\U0001f600\U0001f600\U0001f600\U0001f600\U0001f600\U0001f600\U0001f600\U0001f600\U0001f600\U0001f600\U0001f600\U0001f600\U0001f600\U0001f600\U0001f600\U0001f600\U0001f600\U0001f600\U0001f600\U0001f600\U0001f600\U0001f600\U0001f600", "a\U0001f600\U0001f600\U0001f600\U0001f600\U0001f600\U0001f600\U0001f600\U0001f600\U0001f600\U0001f600\U0001f600\U0001f600\U0001f600\U0001f600\U0001f600\U0001f600\U0001f600\U0001f600\U0001f600\U0001f600\U0001f600\U0001f600\U0001f600\U0001f600\U0001f600\U0001f600\U0001f600\U0001f600\U0001f600\U0001f600\U0001f600\U0001f600\U0001f600\U0001f600\U0001f600\U0001f600\U0001f600\U0001f600\U0001f600\U0001f600\U0001f600\U0001f600\U0001f600\U0001f600\U0001f600\U0001f600\U0001f600\U0001f600\U0001f600\U0001f600\U0001f600\U0001f600\U0001f600\U0001f600\U0001f600\U0001f600\U0001f600\U0001f600\U0001f600\ufffd", true},
		{"\U0001f600\U0001f600\U0001f600\U0001f600\U0001f600\U0001f600\U0001f600\U0001f600\U0001f600\U0001f600\U0001f600\U0001f600\U0001f600\U0001f600\U0001f600\U0001f600\U0001f600\U0001f600\U0001f600\U0001f600\U0001f600\U0001f600\U0001f600\U0001f600\U0001f600\U0001f600\U0001f600\U0001f600\U0001f600\U0001f600\U0001f600\U0001f600\U0001f600\U0001f600\U0001f600\U0001f600\U0001f600\U0001f600\U0001f600\U0001f600\U0001f600\U0001f600\U0001f600\U0001f600\U0001f600\U0001f600\U0001f600\U0001f600\U0001f600\U0001f600\U0001f600\U0001f600\U0001f600\U0001f600\U0001f600\U0001f600\U0001f600\U0001f600\U0001f600\U0001f600\U0001f600", "\U0001f600\U0001f600\U0001f600\U0001f600\U0001f600\U0001f600\U0001f600\U0001f600\U0001f600\U0001f600\U0001f600\U0001f600\U0001f600\U0001f600\U0001f600\U0001f600\U0001f600\U0001f600\U0001f600\U0001f600\U0001f600\U0001f600\U0001f600\U0001f600\U0001f600\U0001f600\U0001f600\U0001f600\U0001f600\U0001f600\U0001f600\U0001f600\U0001f600\U0001f600\U0001f600\U0001f600\U0001f600\U0001f600\U0001f600\U0001f600\U0001f600\U0001f600\U0001f600\U0001f600\U0001f600\U0001f600\U0001f600\U0001f600\U0001f600\U0001f600\U0001f600\U0001f600\U0001f600\U0001f600\U0001f600\U0001f600\U0001f600\U0001f600\U0001f600\U0001f600", true},
		{"   ", "", false},
		{"\u200b", "\u200b", true},
		{"\u7fa4\u540d #a1b2c3d4", "\u7fa4\u540d #a1b2c3d4", true},
	}
	for _, tc := range cases {
		got, ok := issuesSanitizeLocalTaskLabel(tc.in)
		if ok != tc.ok || got != tc.want {
			t.Errorf("issuesSanitizeLocalTaskLabel(%q) = (%q, %v), want (%q, %v)", tc.in, got, ok, tc.want, tc.ok)
		}
	}
}

func TestIssuesJSNumberMatchesNode(t *testing.T) {
	cases := []struct {
		in   string
		want float64
	}{
		{"", 0},
		{"0", 0},
		{" 12 ", 12},
		{"0x10", 16},
		{"0X1f", 31},
		{"1e3", 1000},
		{"abc", math.NaN()},
		{"Infinity", math.Inf(1)},
		{"-Infinity", math.Inf(-1)},
		{"+Infinity", math.Inf(1)},
		{"-0", math.Copysign(0, -1)},
		{"+5", 5},
		{"0b101", 5},
		{"0o17", 15},
		{"1_000", math.NaN()},
		{".5", 0.5},
		{"5.", 5},
		{"0x", math.NaN()},
		{"1e", math.NaN()},
		{"1e400", math.Inf(1)},
		{"-1e400", math.Inf(-1)},
		{"\u00a012\ufeff", 12},
		{"0x-1", math.NaN()},
		{"00012", 12},
		{"1.5e-3", 0.0015},
		{"infinity", math.NaN()},
		{"NaN", math.NaN()},
		{"- 1", math.NaN()},
		{"2.", 2},
		{"0.0000001", 1e-7},
		{"123456789012345678901234567890", 1.2345678901234568e+29},
		{"0b", math.NaN()},
		{"0o8", math.NaN()},
		{"\x0a7\x0a", 7},
	}
	for _, tc := range cases {
		got := issuesJSNumber(tc.in)
		same := got == tc.want && math.Signbit(got) == math.Signbit(tc.want)
		if math.IsNaN(tc.want) {
			same = math.IsNaN(got)
		}
		if !same {
			t.Errorf("issuesJSNumber(%q) = %v, want %v", tc.in, got, tc.want)
		}
	}
}

func TestIssuesSearchParamMatchesNode(t *testing.T) {
	cases := []struct {
		query, name, want string
		ok                bool
	}{
		{"teamId=abc", "teamId", "abc", true},
		{"teamId=a&teamId=b", "teamId", "a", true},
		{"team%49d=x", "teamId", "x", true},
		{"teamId=a+b%20c", "teamId", "a b c", true},
		{"teamId=%zz%4", "teamId", "%zz%4", true},
		{"teamId=%E4%B8%AD", "teamId", "\u4e2d", true},
		{"teamId", "teamId", "", true},
		{"=x&teamId=", "teamId", "", true},
		{"&&teamId=y&", "teamId", "y", true},
		{"teamId=a=b", "teamId", "a=b", true},
		{"teamid=x", "teamId", "", false},
		{"after=2", "after", "2", true},
		{"", "after", "", false},
		{"after=%ff", "after", "\ufffd", true},
	}
	for _, tc := range cases {
		got, ok := issuesSearchParam(tc.query, tc.name)
		if ok != tc.ok || got != tc.want {
			t.Errorf("issuesSearchParam(%q, %q) = (%q, %v), want (%q, %v)", tc.query, tc.name, got, ok, tc.want, tc.ok)
		}
	}
}

func TestIssuesRequestTargetMatchesNode(t *testing.T) {
	cases := []struct{ target, pathname, query string }{
		{"/api/issues", "/api/issues", ""},
		{"/api/issues/", "/api/issues/", ""},
		{"/api/issues/iss_1/../iss_2/events", "/api/issues/iss_2/events", ""},
		{"/api/issues/./iss_1", "/api/issues/iss_1", ""},
		{"/api/issues/%2e%2e/x", "/api/x", ""},
		{"/api/x\\y", "/api/x/y", ""},
		{"/api/issues?teamId=a#frag", "/api/issues", "teamId=a"},
		{"/api/issues/a%20b", "/api/issues/a%20b", ""},
		{"/api/issues/a b", "/api/issues/a%20b", ""},
		{"/api/is%73ues", "/api/is%73ues", ""},
		{"/api/issues/{x}", "/api/issues/%7Bx%7D", ""},
		{"/api/issues/a^b", "/api/issues/a^b", ""},
		{"/api/issues/\"q\"", "/api/issues/%22q%22", ""},
		{"/api/issues/..", "/api/", ""},
		{"/api/issues/.%2E/", "/api/", ""},
		{"/a/b/c/../../..", "/", ""},
		{"/a/b/c/../../../..", "/", ""},
	}
	for _, tc := range cases {
		r := httptest.NewRequest("GET", "/", nil)
		r.RequestURI = tc.target
		pathname, query := issuesRequestTarget(r)
		if pathname != tc.pathname || query != tc.query {
			t.Errorf("issuesRequestTarget(%q) = (%q, %q), want (%q, %q)", tc.target, pathname, query, tc.pathname, tc.query)
		}
	}
}
