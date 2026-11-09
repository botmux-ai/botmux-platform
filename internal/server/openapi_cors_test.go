package server

import (
	"net/http"
	"net/http/httptest"
	"reflect"
	"strings"
	"testing"

	"github.com/botmux-ai/botmux-platform/internal/config"
)

const corsAllowedOrigin = "https://tools.example.com"

func corsHarness(t *testing.T, origins string) *openAPIHarness {
	t.Helper()
	h := newOpenAPIHarness(t)
	h.apex.Config.OpenAPICORSOrigins = config.ParseCORSOrigins(origins)
	return h
}

func preflight(origin, method string) map[string]string {
	return map[string]string{"Origin": origin, "Access-Control-Request-Method": method, "Access-Control-Request-Headers": "authorization"}
}

func TestParseCORSOriginsKeepsOnlyExactOrigins(t *testing.T) {
	got := config.ParseCORSOrigins(" https://A.example.com/ ,http://localhost:3000, *, https://x.com/path, ftp://x.com, https://user@x.com, , https://a.example.com")
	want := []string{"https://a.example.com", "http://localhost:3000", "*"}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("origins = %q, want %q", got, want)
	}
	if got := config.ParseCORSOrigins(""); len(got) != 0 {
		t.Fatalf("empty env must disable CORS, got %q", got)
	}
}

func TestOpenAPICORSDisabledByDefaultKeepsBehavior(t *testing.T) {
	h := newOpenAPIHarness(t)
	list := h.do(http.MethodOptions, "/openapi/machines", preflight(corsAllowedOrigin, "GET"), "")
	proxy := h.do(http.MethodOptions, "/openapi/machines/"+openAPIMIDAlice+"/proxy/api/x", preflight(corsAllowedOrigin, "POST"), "")
	if list.status != http.StatusMethodNotAllowed || proxy.status != http.StatusUnauthorized {
		t.Fatalf("disabled preflight = %d / %d", list.status, proxy.status)
	}
	for _, res := range []openAPIResult{list, proxy} {
		if res.header.Get("Access-Control-Allow-Origin") != "" || res.header.Get("Vary") != "" {
			t.Fatalf("CORS headers without config: %v", res.header)
		}
	}
}

func TestOpenAPICORSPreflightForAllowedOrigin(t *testing.T) {
	h := corsHarness(t, corsAllowedOrigin)
	for _, tc := range []struct {
		path, methods string
	}{
		{"/openapi/machines", "GET, HEAD, OPTIONS"},
		{"/openapi/machines/" + openAPIMIDAlice + "/proxy/api/sessions", "GET, HEAD, POST, PUT, PATCH, DELETE, OPTIONS"},
	} {
		res := h.do(http.MethodOptions, tc.path, preflight(corsAllowedOrigin, "GET"), "")
		if res.status != http.StatusNoContent || res.text != "" {
			t.Fatalf("%s preflight = %d %q", tc.path, res.status, res.text)
		}
		if res.header.Get("Access-Control-Allow-Origin") != corsAllowedOrigin ||
			res.header.Get("Access-Control-Allow-Methods") != tc.methods ||
			!strings.Contains(res.header.Get("Access-Control-Allow-Headers"), "Authorization") ||
			res.header.Get("Access-Control-Max-Age") != "600" ||
			res.header.Get("Access-Control-Allow-Credentials") != "" ||
			!strings.Contains(strings.Join(res.header.Values("Vary"), ","), "Origin") {
			t.Fatalf("%s preflight headers = %v", tc.path, res.header)
		}
	}
	if calls := h.proxyCalls(); len(calls) != 0 {
		t.Fatalf("preflight reached the daemon: %+v", calls)
	}
}

func TestOpenAPICORSRejectsOtherOrigins(t *testing.T) {
	h := corsHarness(t, corsAllowedOrigin)
	for _, origin := range []string{"https://evil.example.com", "https://tools.example.com.evil.com", "null", "http://tools.example.com"} {
		res := h.do(http.MethodOptions, "/openapi/machines", preflight(origin, "GET"), "")
		if res.status == http.StatusNoContent || res.header.Get("Access-Control-Allow-Origin") != "" {
			t.Fatalf("origin %q preflight = %d %v", origin, res.status, res.header)
		}
		if !strings.Contains(strings.Join(res.header.Values("Vary"), ","), "Origin") {
			t.Fatalf("origin %q: Vary: Origin missing", origin)
		}
	}
}

func TestOpenAPICORSWildcardNeverAllowsCredentials(t *testing.T) {
	h := corsHarness(t, "*")
	res := h.do(http.MethodOptions, "/openapi/machines", preflight("https://any.example.com", "GET"), "")
	if res.status != http.StatusNoContent || res.header.Get("Access-Control-Allow-Origin") != "*" || res.header.Get("Access-Control-Allow-Credentials") != "" {
		t.Fatalf("wildcard preflight = %d %v", res.status, res.header)
	}
	// "null" (sandboxed iframes, file://) is never echoed, even with "*".
	if res := h.do(http.MethodGet, "/openapi/machines", map[string]string{"Origin": "null"}, ""); res.header.Get("Access-Control-Allow-Origin") != "" {
		t.Fatalf("null origin got ACAO: %v", res.header)
	}
}

func TestOpenAPICORSHeadersOnErrorAndSuccessResponses(t *testing.T) {
	h := corsHarness(t, corsAllowedOrigin)
	h.seedAlice()
	// 401 without a JWT still carries ACAO so the page can read the error.
	unauth := h.do(http.MethodGet, "/openapi/machines", map[string]string{"Origin": corsAllowedOrigin}, "")
	if unauth.status != http.StatusUnauthorized || unauth.header.Get("Access-Control-Allow-Origin") != corsAllowedOrigin {
		t.Fatalf("401 = %d %v", unauth.status, unauth.header)
	}
	ok := h.do(http.MethodGet, "/openapi/machines", map[string]string{"Origin": corsAllowedOrigin, "Authorization": "Bearer tok"}, "")
	if ok.status != http.StatusOK || ok.header.Get("Access-Control-Allow-Origin") != corsAllowedOrigin || ok.header.Get("Access-Control-Allow-Credentials") != "" {
		t.Fatalf("200 = %d %v", ok.status, ok.header)
	}
}

func TestOpenAPICORSReplacesDaemonCORSHeaders(t *testing.T) {
	h := corsHarness(t, corsAllowedOrigin)
	h.seedAlice()
	daemonHeaders := http.Header{"Content-Type": {"application/json"}, "Access-Control-Allow-Origin": {"null"}, "Access-Control-Allow-Credentials": {"true"}, "Vary": {"Accept-Encoding"}}
	h.apex.OpenAPI.ProxyFetch = h.recordingFetch(http.StatusOK, daemonHeaders, `{"ok":true}`)
	path := "/openapi/machines/" + openAPIMIDAlice + "/proxy/api/sessions"
	res := h.do(http.MethodGet, path, map[string]string{"Origin": corsAllowedOrigin, "Authorization": "Bearer tok"}, "")
	if res.status != http.StatusOK || !reflect.DeepEqual(res.header.Values("Access-Control-Allow-Origin"), []string{corsAllowedOrigin}) ||
		res.header.Get("Access-Control-Allow-Credentials") != "" {
		t.Fatalf("CORS on: %d %v", res.status, res.header)
	}
	if vary := strings.Join(res.header.Values("Vary"), ","); !strings.Contains(vary, "Origin") || !strings.Contains(vary, "Accept-Encoding") {
		t.Fatalf("Vary must keep Origin and the daemon's value: %q", vary)
	}
	// Without a platform CORS decision the daemon's headers pass through as before.
	h.apex.Config.OpenAPICORSOrigins = nil
	res = h.do(http.MethodGet, path, map[string]string{"Origin": corsAllowedOrigin, "Authorization": "Bearer tok"}, "")
	if res.status != http.StatusOK || res.header.Get("Access-Control-Allow-Origin") != "null" || res.header.Get("Access-Control-Allow-Credentials") != "true" {
		t.Fatalf("CORS off must not touch daemon headers: %d %v", res.status, res.header)
	}
}

func TestOpenAPICORSDoesNotTouchSessionSurfaces(t *testing.T) {
	cfg := openAPITestConfig()
	cfg.OpenAPICORSOrigins = []string{"*"}
	a := &Apex{Config: cfg, Repository: newMemoryRepository()}
	for _, path := range []string{"/api/me", "/api/credentials", "/credentials", "/v1/machine/credential-grant"} {
		for _, method := range []string{http.MethodOptions, http.MethodGet} {
			request := httptest.NewRequest(method, "http://localhost"+path, nil)
			request.Header.Set("Origin", "https://any.example.com")
			request.Header.Set("Access-Control-Request-Method", "GET")
			recorder := httptest.NewRecorder()
			a.ServeHTTP(recorder, request)
			if recorder.Header().Get("Access-Control-Allow-Origin") != "" || recorder.Code == http.StatusNoContent {
				t.Fatalf("%s %s got CORS: %d %v", method, path, recorder.Code, recorder.Header())
			}
		}
	}
}
