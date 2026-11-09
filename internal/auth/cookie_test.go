package auth

import (
	"testing"
	"time"

	"github.com/botmux-ai/botmux-platform/internal/config"
)

func TestCookieHeadersMatchTypeScript(t *testing.T) {
	cfg := config.Config{SessionTTL: 7 * 24 * time.Hour, CookieSecure: true, CookieDomain: ".botmux.example"}

	if got, want := SessionCookieHeader(cfg, "TOKEN"), "botmux_platform_session=TOKEN; Path=/; HttpOnly; Max-Age=604800; SameSite=None; Domain=.botmux.example; Secure"; got != want {
		t.Fatalf("session cookie\n got: %s\nwant: %s", got, want)
	}
	if got, want := ClearSessionCookieHeader(cfg), "botmux_platform_session=; Path=/; HttpOnly; SameSite=Lax; Max-Age=0; Domain=.botmux.example; Secure"; got != want {
		t.Fatalf("clear cookie\n got: %s\nwant: %s", got, want)
	}
	if got, want := ProxySessionCookieHeader(cfg, "PROXY"), "botmux_proxy_session=PROXY; Path=/; HttpOnly; SameSite=Lax; Max-Age=604800; Secure"; got != want {
		t.Fatalf("proxy cookie\n got: %s\nwant: %s", got, want)
	}
}

func TestParseCookieCompatibility(t *testing.T) {
	got := ParseCookie(" first=one; encoded=a%2Bb%3Dc; raw=a+b; duplicate=old; duplicate=new; flag")
	want := map[string]string{"first": "one", "encoded": "a+b=c", "raw": "a+b", "duplicate": "new"}
	if len(got) != len(want) {
		t.Fatalf("cookies = %#v", got)
	}
	for key, value := range want {
		if got[key] != value {
			t.Errorf("cookie %q = %q, want %q", key, got[key], value)
		}
	}
}
