package server

import (
	"net/http"
	"strings"

	"github.com/botmux-ai/botmux-platform/internal/config"
)

// CORS for the external OpenAPI (/openapi/machines and
// /openapi/machines/:id/proxy/*) only. The OpenAPI authenticates with a
// token in a request header and never reads cookies, so responses
// never carry Access-Control-Allow-Credentials: a "*" allow-list therefore
// never combines with credentials, and pages on other origins cannot ride the
// SSO session. Cookie-authenticated surfaces (/api/*, /credentials, /v1/*,
// machine subdomains) keep their strict same-origin checks and get no CORS
// headers. With OPENAPI_CORS_ORIGINS unset nothing here changes behavior.

const (
	openAPICORSAllowHeaders = "Authorization, Content-Type, X-Jwt-Token, X-Requested-With"
	openAPICORSMaxAge       = "600"
)

var openAPICORSHeaderPrefix = "access-control-"

// openAPICORSOrigin returns the Access-Control-Allow-Origin value for r, or
// "" when CORS is off or the request's Origin is not allowed.
func openAPICORSOrigin(cfg config.Config, r *http.Request) string {
	if len(cfg.OpenAPICORSOrigins) == 0 {
		return ""
	}
	raw := r.Header.Get("Origin")
	if raw == "" {
		return ""
	}
	origin, ok := config.NormalizeCORSOrigin(raw)
	if !ok || origin == "*" {
		return ""
	}
	for _, allowed := range cfg.OpenAPICORSOrigins {
		if allowed == "*" {
			return "*"
		}
		if allowed == origin {
			return raw
		}
	}
	return ""
}

// applyOpenAPICORS writes the CORS headers for an allowed origin and answers
// a preflight itself (true = response written). Disallowed origins and
// non-preflight requests fall through to the normal handler unchanged.
func (a *Apex) applyOpenAPICORS(w http.ResponseWriter, r *http.Request, isList bool) bool {
	if len(a.Config.OpenAPICORSOrigins) == 0 {
		return false
	}
	header := w.Header()
	if r.Header.Get("Origin") != "" {
		header.Add("Vary", "Origin")
	}
	allowOrigin := openAPICORSOrigin(a.Config, r)
	if allowOrigin == "" {
		return false
	}
	header.Set("Access-Control-Allow-Origin", allowOrigin)
	if r.Method != http.MethodOptions || r.Header.Get("Access-Control-Request-Method") == "" {
		return false
	}
	methods := "GET, HEAD, OPTIONS"
	if !isList {
		methods = "GET, HEAD, POST, PUT, PATCH, DELETE, OPTIONS"
	}
	header.Set("Access-Control-Allow-Methods", methods)
	header.Set("Access-Control-Allow-Headers", openAPICORSAllowHeaders)
	header.Set("Access-Control-Max-Age", openAPICORSMaxAge)
	header.Add("Vary", "Access-Control-Request-Method")
	header.Add("Vary", "Access-Control-Request-Headers")
	header.Set("Cache-Control", "no-store")
	w.WriteHeader(http.StatusNoContent)
	return true
}

// isOpenAPICORSResponseHeader reports daemon-sent CORS headers, which are
// dropped when the platform answers CORS itself so the two never conflict.
func isOpenAPICORSResponseHeader(name string) bool {
	return strings.HasPrefix(strings.ToLower(name), openAPICORSHeaderPrefix)
}
