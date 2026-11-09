package proxy

import (
	"net/http"
	"net/url"
	"testing"
)

func TestRequestTargetPrefersRawRequestLine(t *testing.T) {
	// Hertz's adaptor: r.URL is the normalized URI, r.RequestURI the raw line.
	normalized, _ := url.ParseRequestURI("/api/sessions?x=1")
	r := &http.Request{URL: normalized, RequestURI: "/s/%2e%2e/api/sessions?x=1#frag"}
	if got := RequestTarget(r); got != "/s/%2e%2e/api/sessions?x=1#frag" {
		t.Fatalf("RequestTarget = %q", got)
	}
	if path, query := SplitRequestTarget(r); path != "/s/%2e%2e/api/sessions" || query != "x=1" {
		t.Fatalf("split = %q %q", path, query)
	}
	// Client-side / synthetic requests without a request line use r.URL.
	if got := RequestTarget(&http.Request{URL: normalized}); got != "/api/sessions?x=1" {
		t.Fatalf("fallback = %q", got)
	}
}

func TestWebhookDecisionUsesWHATWGPathnameOfRawTarget(t *testing.T) {
	for target, want := range map[string]bool{
		"/webhook/a/b":        true,
		"/x/../webhook/a":     true,
		"/x/%2e%2e/webhook/a": true,
		"/webhook/../api/x":   false,
		`/webhook\a`:          true,
		"/webhooks/a":         false,
		"/webhook":            false,
	} {
		r := &http.Request{URL: &url.URL{Path: "/"}, RequestURI: target}
		if got := isWebhookPath(r); got != want {
			t.Fatalf("isWebhookPath(%q) = %v", target, got)
		}
	}
}
