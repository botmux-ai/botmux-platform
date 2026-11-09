package server

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"net/url"
	"regexp"
	"strings"
	"time"

	"github.com/botmux-ai/botmux-platform/internal/auth"
	"github.com/botmux-ai/botmux-platform/internal/config"
	"github.com/botmux-ai/botmux-platform/internal/proxy"
	"github.com/botmux-ai/botmux-platform/internal/store"
)

// External OpenAPI (src/server/openapi-http.ts), HTTP and the
// /openapi/machines/:id/proxy/* WebSocket upgrade. Owned by Phase 2 agent B4.
//
// A third-party platform presents a personal token; the edition's verifier
// checks it, the email is mapped to a Feishu union_id, and then only the
// machines that person owns or co-manages are exposed
// (auth.ResolveMachineAccess is the single gate, so no caller allowlist is
// needed). Daemon calls go through the same chain the platform UI uses:
// machine subdomain + owner proxy cookie + reverse tunnel. Everything fails
// closed and is no-store.

const (
	openAPIListPath     = "/openapi/machines"
	openAPIProxyTimeout = 6 * time.Second
	openAPIBodyLimit    = 1 << 20
)

var openAPIProxyPath = regexp.MustCompile(`^/openapi/machines/([a-f0-9]{8,64})/proxy(/.*)?$`)

// Hop-by-hop headers are not forwarded, and the platform injects the daemon
// credentials itself: the caller's own credentials (authorization, cookie,
// the JWT) and the platform-authoritative x-botmux-* headers a daemon trusts
// are always stripped.
var openAPIStrippedRequestHeaders = map[string]bool{
	"host": true, "connection": true, "keep-alive": true, "transfer-encoding": true, "upgrade": true,
	"proxy-authorization": true, "proxy-connection": true, "te": true, "trailer": true,
	"authorization": true, "cookie": true, "x-jwt-token": true, "content-length": true,
	"x-botmux-role": true, "x-botmux-actor": true, "x-botmux-scopes": true,
	"x-botmux-login-url": true, "x-botmux-forwarded": true,
}

var openAPIStrippedResponseHeaders = map[string]bool{
	"connection": true, "keep-alive": true, "transfer-encoding": true, "upgrade": true,
	"proxy-authenticate": true, "set-cookie": true, "content-length": true, "content-encoding": true,
}

// nodeSingleValueHeaders are the request headers Node's IncomingMessage keeps
// only the first occurrence of; every other repeated header is joined.
var nodeSingleValueHeaders = map[string]bool{
	"age": true, "authorization": true, "content-length": true, "content-type": true, "etag": true,
	"expires": true, "from": true, "host": true, "if-modified-since": true, "if-unmodified-since": true,
	"last-modified": true, "location": true, "max-forwards": true, "proxy-authorization": true,
	"referer": true, "retry-after": true, "server": true, "user-agent": true,
}

// OpenAPIProxyRequest is one forwarded daemon call. Body is nil for GET/HEAD.
type OpenAPIProxyRequest struct {
	Method string
	URL    string
	Header http.Header
	Body   []byte
}

// OpenAPIProxyResponse is the daemon answer relayed to the caller.
type OpenAPIProxyResponse struct {
	Status int
	Header http.Header
	Body   []byte
}

// OpenAPIIdentity is the caller a verified OpenAPI token speaks for.
type OpenAPIIdentity struct {
	// Email is mapped to the caller's Feishu union_id.
	Email string
	// Person is false for service accounts, which the OpenAPI refuses.
	Person bool
}

// OpenAPIVerifier checks the token of an OpenAPI request; a failure's error
// text is the `reason` of 401 invalid_jwt.
type OpenAPIVerifier func(ctx context.Context, token string) (*OpenAPIIdentity, error)

// OpenAPIDeps holds OpenAPI seams (token verifier, identity resolver, proxy).
// Nil fields use the production defaults, except VerifyJWT.
type OpenAPIDeps struct {
	// VerifyJWT checks the caller's token; nil leaves /openapi/* unserved
	// (404).
	VerifyJWT OpenAPIVerifier
	// ResolveUnionID maps the JWT email to a Feishu union_id; "" means
	// unmapped or unavailable (both 403 identity_unmapped, fail closed).
	ResolveUnionID func(ctx context.Context, email string) string
	// ProxyFetch performs the daemon call (machine subdomain + owner cookie).
	// It must not follow redirects; ctx carries the 6s budget.
	ProxyFetch func(ctx context.Context, request OpenAPIProxyRequest) (OpenAPIProxyResponse, error)
	// MachineWS serves a rewritten WebSocket upgrade exactly like the machine
	// subdomain would (surface is "dashboard" or "terminal").
	MachineWS func(w http.ResponseWriter, r *http.Request, machineID, surface string)
	// Now is the clock of the `online` flag.
	Now func() time.Time
}

type openAPIBot struct {
	AppID  string  `json:"appId"`
	Name   string  `json:"name"`
	OpenID *string `json:"openId"`
}

// openAPIMachine is machineView in TS key order.
type openAPIMachine struct {
	MachineID     string       `json:"machineId"`
	Name          string       `json:"name"`
	BotmuxVersion string       `json:"botmuxVersion"`
	Online        bool         `json:"online"`
	LastSeen      int64        `json:"lastSeen"`
	Role          *string      `json:"role"`
	OwnerName     *string      `json:"ownerName"`
	Scopes        []string     `json:"scopes"`
	Bots          []openAPIBot `json:"bots"`
}

type openAPIMachineList struct {
	UnionID  string           `json:"unionId"`
	Machines []openAPIMachine `json:"machines"`
}

func openAPIMachineView(doc store.MachineDoc, staleAfter time.Duration, access auth.MachineAccess, now time.Time) openAPIMachine {
	name := doc.DisplayName
	if name == "" {
		name = doc.Name
	}
	if name == "" {
		name = jsSlice(doc.ID, 8)
	}
	view := openAPIMachine{
		MachineID:     doc.ID,
		Name:          name,
		BotmuxVersion: doc.BotmuxVersion,
		Online:        now.UnixMilli()-doc.LastSeen <= staleAfter.Milliseconds(),
		LastSeen:      doc.LastSeen,
		Scopes:        []string{},
		Bots:          make([]openAPIBot, 0, len(doc.Bots)),
	}
	if access.OK {
		role := string(access.Role)
		view.Role = &role
		view.Scopes = append(view.Scopes, access.Scopes...)
		// Only a co-managed machine says whose it is.
		if access.Role == auth.MachineRoleCoManager {
			owner := doc.OwnerName
			view.OwnerName = &owner
		}
	}
	for _, bot := range doc.Bots {
		view.Bots = append(view.Bots, openAPIBot{AppID: bot.AppID, Name: bot.Name, OpenID: bot.OpenID})
	}
	return view
}

type openAPIAuthFailure struct {
	status int
	code   string
	reason string
}

func jsTrimString(value string) string { return strings.TrimFunc(value, isECMAWhitespace) }

// openAPIExtractJWT reads Authorization: Bearer, then X-Jwt-Token. ?jwt= is
// honoured only on a WebSocket upgrade (browsers cannot set WS headers), so
// HTTP tokens never reach daemon access logs or Referer headers.
func openAPIExtractJWT(r *http.Request, params []urlFormPair) string {
	if m := machineBearerPattern.FindStringSubmatch(r.Header.Get("Authorization")); m != nil {
		if token := jsTrimString(m[1]); token != "" {
			return token
		}
	}
	if token := jsTrimString(nodeJoinedHeader(r.Header, "X-Jwt-Token")); token != "" {
		return token
	}
	if strings.Contains(strings.ToLower(nodeJoinedHeader(r.Header, "Upgrade")), "websocket") {
		value, _ := searchParamGet(params, "jwt")
		return jsTrimString(value)
	}
	return ""
}

// nodeJoinedHeader is req.headers[name] for a header Node joins with ", ".
func nodeJoinedHeader(header http.Header, name string) string {
	return strings.Join(header.Values(name), ", ")
}

// openAPIAuthenticate verifies the JWT, requires a person account and maps
// the email to a union_id.
func (a *Apex) openAPIAuthenticate(r *http.Request, params []urlFormPair) (string, *openAPIAuthFailure) {
	token := openAPIExtractJWT(r, params)
	if token == "" {
		return "", &openAPIAuthFailure{status: http.StatusUnauthorized, code: "missing_jwt"}
	}
	identity, err := a.OpenAPI.VerifyJWT(r.Context(), token)
	if err != nil || identity == nil {
		reason := "malformed"
		if err != nil {
			reason = err.Error()
		}
		return "", &openAPIAuthFailure{status: http.StatusUnauthorized, code: "invalid_jwt", reason: reason}
	}
	if !identity.Person {
		return "", &openAPIAuthFailure{status: http.StatusForbidden, code: "not_person_account"}
	}
	unionID := a.openAPIResolveUnionID(r.Context(), identity.Email)
	if unionID == "" {
		return "", &openAPIAuthFailure{status: http.StatusForbidden, code: "identity_unmapped"}
	}
	return unionID, nil
}

func (a *Apex) openAPIResolveUnionID(ctx context.Context, email string) string {
	if a.OpenAPI.ResolveUnionID != nil {
		return a.OpenAPI.ResolveUnionID(ctx, email)
	}
	if a.Feishu == nil {
		return ""
	}
	// Tenant-token failures and directory misses both map to "" (403):
	// fail closed, as in TS.
	token, err := a.Feishu.TenantAccessTokenCached(ctx)
	if err != nil {
		slog.Warn("OpenAPI: tenant token failed", "error", err)
		return ""
	}
	unionID, err := a.Feishu.ResolveUnionIDByEmail(ctx, token, email)
	if err != nil {
		return ""
	}
	return unionID
}

func (a *Apex) openAPINow() time.Time {
	if a.OpenAPI.Now != nil {
		return a.OpenAPI.Now()
	}
	return time.Now()
}

// isNodeUpgrade is Node's 'upgrade' classification: an Upgrade header plus a
// Connection: upgrade token. Such requests never reach the HTTP handler.
func isNodeUpgrade(r *http.Request) bool {
	if len(r.Header.Values("Upgrade")) == 0 {
		return false
	}
	for _, value := range r.Header.Values("Connection") {
		for _, token := range strings.Split(value, ",") {
			if strings.EqualFold(strings.TrimSpace(token), "upgrade") {
				return true
			}
		}
	}
	return false
}

// handleOpenAPI serves /openapi/machines and /openapi/machines/*.
func (a *Apex) handleOpenAPI(w http.ResponseWriter, r *http.Request) bool {
	if isNodeUpgrade(r) {
		// Node routes upgrades to handleOpenApiWs; anything it does not claim
		// has its socket destroyed.
		if !a.handleOpenAPIWS(w, r) {
			destroyConnection(w)
		}
		return true
	}
	pathname := requestPathname(r)
	isList := pathname == openAPIListPath
	match := openAPIProxyPath.FindStringSubmatch(pathname)
	if !isList && match == nil {
		return false
	}
	// Without a token verifier the whole surface does not exist.
	if a.OpenAPI.VerifyJWT == nil {
		writeJSONNoStore(w, http.StatusNotFound, map[string]any{"error": "not_found"})
		return true
	}
	// CORS headers are set before any handler writes, so error responses
	// (401, 403, 502 ...) carry them too; an allowed preflight is answered
	// here, before authentication (browsers never send credentials on it).
	if a.applyOpenAPICORS(w, r, isList) {
		return true
	}
	params := requestSearchParams(r)
	if isList {
		a.openAPIList(w, r, params)
		return true
	}
	a.openAPIProxy(w, r, params, match[1], openAPIProxyTail(match))
	return true
}

func openAPIProxyTail(match []string) string {
	if match[2] == "" {
		return "/"
	}
	return match[2]
}

// writeOpenAPIAuthFailure sends {error} or {error, reason} (in that order).
func writeOpenAPIAuthFailure(w http.ResponseWriter, failure *openAPIAuthFailure) {
	writeJSONNoStore(w, failure.status, struct {
		Error  string `json:"error"`
		Reason string `json:"reason,omitempty"`
	}{failure.code, failure.reason})
}

// openAPIList is GET /openapi/machines: owned machines plus machines the
// caller co-manages.
func (a *Apex) openAPIList(w http.ResponseWriter, r *http.Request, params []urlFormPair) {
	if r.Method != http.MethodGet {
		writeJSONNoStore(w, http.StatusMethodNotAllowed, map[string]any{"error": "method_not_allowed"})
		return
	}
	unionID, failure := a.openAPIAuthenticate(r, params)
	if failure != nil {
		writeOpenAPIAuthFailure(w, failure)
		return
	}
	// Both reads fail closed: half a list would look like a revoked machine.
	owned, ownedErr := a.Repository.ListMachinesForUsers(r.Context(), []string{unionID})
	coManaged, coErr := a.Repository.ListMachinesCoManagedBy(r.Context(), unionID)
	if ownedErr != nil || coErr != nil {
		writeJSONNoStore(w, http.StatusServiceUnavailable, map[string]any{"error": "store_unavailable"})
		return
	}
	now := a.openAPINow()
	machines := make([]openAPIMachine, 0, len(owned)+len(coManaged))
	seen := make(map[string]bool, len(owned)+len(coManaged))
	for i := range owned {
		seen[owned[i].ID] = true
		machines = append(machines, openAPIMachineView(owned[i], a.Config.StaleAfter, auth.ResolveMachineAccess(&owned[i], unionID), now))
	}
	for i := range coManaged {
		// Owner wins over a co-manager entry for the same machine.
		if seen[coManaged[i].ID] {
			continue
		}
		access := auth.ResolveMachineAccess(&coManaged[i], unionID)
		if !access.OK {
			continue // listed but no grantable scope left: no access
		}
		// The OpenAPI dispatches work into a machine; a read-only viewer can
		// do nothing there (no sessions:open), so the machine is not listed.
		if auth.IsViewer(access) {
			continue
		}
		seen[coManaged[i].ID] = true
		machines = append(machines, openAPIMachineView(coManaged[i], a.Config.StaleAfter, access, now))
	}
	writeJSONNoStore(w, http.StatusOK, openAPIMachineList{UnionID: unionID, Machines: machines})
}

// openAPILookupAccess is the shared access gate: the owner, or a co-manager
// holding sessions:open. ok=false with err=nil means denied.
func (a *Apex) openAPILookupAccess(ctx context.Context, machineID, unionID string) (bool, error) {
	doc, err := a.Repository.LookupMachine(ctx, machineID, store.AuthorityCacheOptions{})
	if errors.Is(err, store.ErrNotFound) {
		return false, nil
	}
	if err != nil {
		return false, err
	}
	return auth.AccessCanUseDaemonAPI(auth.ResolveMachineAccess(&doc, unionID)), nil
}

// openAPIQuery is the caller's query without our own jwt parameter, in
// URLSearchParams serialization ("" when nothing is left).
func openAPIQuery(params []urlFormPair) string {
	kept := make([]urlFormPair, 0, len(params))
	for _, pair := range params {
		if pair.name != "jwt" {
			kept = append(kept, pair)
		}
	}
	return serializeURLSearchParams(kept)
}

// openAPIProxy is ANY /openapi/machines/:id/proxy/*: a generic daemon API
// pass-through.
func (a *Apex) openAPIProxy(w http.ResponseWriter, r *http.Request, params []urlFormPair, machineID, tail string) {
	unionID, failure := a.openAPIAuthenticate(r, params)
	if failure != nil {
		writeOpenAPIAuthFailure(w, failure)
		return
	}
	allowed, err := a.openAPILookupAccess(r.Context(), machineID, unionID)
	if err != nil {
		writeJSONNoStore(w, http.StatusServiceUnavailable, map[string]any{"error": "store_unavailable"})
		return
	}
	if !allowed {
		// Missing, retired or not yours all look the same.
		writeJSONNoStore(w, http.StatusForbidden, map[string]any{"error": "machine_not_owned"})
		return
	}

	target := MachineBaseURL(a.Config, machineID) + tail
	if query := openAPIQuery(params); query != "" {
		target += "?" + query
	}
	header := http.Header{}
	for name, values := range r.Header {
		lower := strings.ToLower(name)
		if openAPIStrippedRequestHeaders[lower] || len(values) == 0 {
			continue
		}
		// Go decompresses for us only when it negotiates the encoding itself;
		// fetch always hands back a decoded body.
		if lower == "accept-encoding" {
			continue
		}
		if nodeSingleValueHeaders[lower] {
			header.Set(name, values[0])
		} else {
			header.Set(name, strings.Join(values, ", "))
		}
	}
	header.Set("Cookie", auth.ProxySessionRequestCookie(a.Config, auth.ProxyIdentity{UnionID: unionID, MachineID: machineID}))

	method := r.Method
	var body []byte
	if method != http.MethodGet && method != http.MethodHead {
		body, err = readOpenAPIBody(r)
		if err != nil {
			// The body was not drained; close so keep-alive cannot desync.
			w.Header().Set("Connection", "close")
			writeJSONNoStore(w, http.StatusRequestEntityTooLarge, map[string]any{"error": "body_too_large"})
			return
		}
		if body == nil {
			body = []byte{}
		}
	}

	ctx, cancel := context.WithTimeout(r.Context(), openAPIProxyTimeout)
	defer cancel()
	fetch := a.OpenAPI.ProxyFetch
	if fetch == nil {
		fetch = defaultOpenAPIProxyFetch
	}
	upstream, err := fetch(ctx, OpenAPIProxyRequest{Method: method, URL: target, Header: header, Body: body})
	if err != nil {
		slog.Warn("OpenAPI proxy failed", "machineId", machineID, "error", err)
		writeJSONNoStore(w, http.StatusBadGateway, map[string]any{"error": "machine_unreachable"})
		return
	}
	out := w.Header()
	platformCORS := out.Get("Access-Control-Allow-Origin") != ""
	for name, values := range upstream.Header {
		if openAPIStrippedResponseHeaders[strings.ToLower(name)] || len(values) == 0 {
			continue
		}
		if platformCORS && isOpenAPICORSResponseHeader(name) {
			continue
		}
		if platformCORS && strings.EqualFold(name, "Vary") {
			// Keep the platform's Vary: Origin next to whatever the daemon varies on.
			out["Vary"] = append(out["Vary"], strings.Join(values, ", "))
			continue
		}
		out[http.CanonicalHeaderKey(name)] = []string{strings.Join(values, ", ")}
	}
	// Forced last: owner-private data must never become cacheable.
	out.Set("Cache-Control", "no-store")
	// The daemon's status, relayed: not a platform failure for the metric.
	proxy.MarkRelayedStatus(r.Context(), upstream.Status)
	w.WriteHeader(upstream.Status)
	_, _ = w.Write(upstream.Body)
}

// readOpenAPIBody reads at most 1 MiB; anything larger (or a read error) is
// answered 413 by the caller.
func readOpenAPIBody(r *http.Request) ([]byte, error) {
	if r.Body == nil {
		return nil, nil
	}
	body, err := io.ReadAll(io.LimitReader(r.Body, openAPIBodyLimit+1))
	if err != nil {
		return nil, err
	}
	if len(body) > openAPIBodyLimit {
		return nil, errors.New("body too large")
	}
	return body, nil
}

var openAPIProxyClient = func() *http.Client {
	// Like MachineAPI: no process proxy (the call re-enters this service via
	// the machine subdomain with a signed cookie) and no redirect following.
	transport := http.DefaultTransport.(*http.Transport).Clone()
	transport.Proxy = nil
	return &http.Client{Transport: transport, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
}()

// fetchForbiddenMethods are the methods fetch() rejects with a TypeError,
// which the TS handler reports as 502.
var fetchForbiddenMethods = map[string]bool{"CONNECT": true, "TRACE": true, "TRACK": true}

func defaultOpenAPIProxyFetch(ctx context.Context, request OpenAPIProxyRequest) (OpenAPIProxyResponse, error) {
	if fetchForbiddenMethods[strings.ToUpper(request.Method)] {
		return OpenAPIProxyResponse{}, fmt.Errorf("fetch: %s is a forbidden method", request.Method)
	}
	var body io.Reader
	if request.Body != nil {
		body = bytes.NewReader(request.Body)
	}
	outgoing, err := http.NewRequestWithContext(ctx, request.Method, request.URL, body)
	if err != nil {
		return OpenAPIProxyResponse{}, err
	}
	pinRequestTarget(outgoing.URL, request.URL)
	for name, values := range request.Header {
		outgoing.Header[name] = append([]string(nil), values...)
	}
	response, err := openAPIProxyClient.Do(outgoing)
	if err != nil {
		return OpenAPIProxyResponse{}, err
	}
	defer response.Body.Close()
	payload, err := io.ReadAll(response.Body)
	if err != nil {
		return OpenAPIProxyResponse{}, err
	}
	return OpenAPIProxyResponse{Status: response.StatusCode, Header: response.Header, Body: payload}, nil
}

// pinRequestTarget sends target's path and query byte-for-byte: net/url would
// otherwise re-escape characters WHATWG leaves alone (for example '^').
func pinRequestTarget(u *url.URL, target string) {
	rest := target
	if i := strings.Index(rest, "://"); i >= 0 {
		rest = rest[i+3:]
	}
	slash := strings.IndexByte(rest, '/')
	if slash < 0 {
		return
	}
	pathAndQuery := rest[slash:]
	path, query, _ := strings.Cut(pathAndQuery, "?")
	if strings.HasPrefix(path, "//") {
		u.Opaque = "//" + u.Host + path
	} else {
		u.Opaque = path
	}
	u.RawQuery = query
}

// machineSurfaceHost is new URL(machineBaseUrl(cfg, id, surface)).host.
func machineSurfaceHost(cfg config.Config, machineID, surface string) string {
	prefix := cfg.MachineSubdomainPrefix
	if surface == "terminal" {
		prefix = cfg.TerminalSubdomainPrefix
		if prefix == "" {
			prefix = "t-"
		}
	}
	host := prefix + machineID + "." + cfg.RootHost
	base, err := url.Parse(cfg.PublicBaseURL)
	if err != nil {
		return host
	}
	port := base.Port()
	if port == "" || (port == "80" && (base.Scheme == "http" || base.Scheme == "ws")) ||
		(port == "443" && (base.Scheme == "https" || base.Scheme == "wss")) {
		return host
	}
	return net.JoinHostPort(host, port)
}

// handleOpenAPIWS is handleOpenApiWs: the WebSocket upgrade of
// /openapi/machines/:id/proxy/*. It reports false for any other path (the
// caller destroys the socket). Failures are a bare HTTP status line on the
// raw connection; success rewrites the request into the machine-subdomain
// form and delegates to the machine WebSocket handler, which already does
// the tunnel bridging, cross-pod forwarding and role injection.
func (a *Apex) handleOpenAPIWS(w http.ResponseWriter, r *http.Request) bool {
	match := openAPIProxyPath.FindStringSubmatch(requestPathname(r))
	if match == nil {
		return false
	}
	if a.OpenAPI.VerifyJWT == nil {
		wsFail(w, http.StatusNotFound, "Not Found")
		return true
	}
	params := requestSearchParams(r)
	unionID, failure := a.openAPIAuthenticate(r, params)
	if failure != nil {
		wsFail(w, failure.status, failure.code)
		return true
	}
	machineID, tail := match[1], openAPIProxyTail(match)
	allowed, err := a.openAPILookupAccess(r.Context(), machineID, unionID)
	if err != nil {
		wsFail(w, http.StatusServiceUnavailable, "store_unavailable")
		return true
	}
	if !allowed {
		wsFail(w, http.StatusForbidden, "machine_not_owned")
		return true
	}

	// Daemon path plus the caller's query minus jwt (never leaked to the daemon).
	requestURI := tail
	if query := openAPIQuery(params); query != "" {
		requestURI += "?" + query
	}
	rewritten, err := url.ParseRequestURI(requestURI)
	if err != nil {
		wsFail(w, http.StatusBadRequest, "Bad Request")
		return true
	}
	// The daemon terminal lives under /s/*; dashboard and terminal surfaces
	// validate paths oppositely and have separate origins.
	surface := "dashboard"
	if tail == "/s" || strings.HasPrefix(tail, "/s/") {
		surface = "terminal"
	}
	host := machineSurfaceHost(a.Config, machineID, surface)
	r.URL = rewritten
	r.RequestURI = requestURI
	r.Host = host
	if r.Header.Get("Host") != "" {
		r.Header.Set("Host", host)
	}
	for _, name := range []string{"Authorization", "X-Jwt-Token", "X-Botmux-Role", "X-Botmux-Actor", "X-Botmux-Scopes", "X-Botmux-Login-Url", "X-Botmux-Forwarded"} {
		r.Header.Del(name)
	}
	r.Header.Set("Cookie", auth.ProxySessionRequestCookie(a.Config, auth.ProxyIdentity{UnionID: unionID, MachineID: machineID}))

	if a.OpenAPI.MachineWS == nil {
		slog.Warn("OpenAPI WS proxy has no machine handler", "machineId", machineID)
		destroyConnection(w)
		return true
	}
	a.OpenAPI.MachineWS(w, r, machineID, surface)
	return true
}

// wsFail answers an upgrade that has not been accepted with a bare status
// line and closes the connection.
func wsFail(w http.ResponseWriter, status int, reason string) {
	conn := hijackConnection(w)
	if conn == nil {
		w.Header().Set("Connection", "close")
		w.WriteHeader(status)
		return
	}
	defer conn.Close()
	_ = conn.SetWriteDeadline(time.Now().Add(5 * time.Second))
	_, _ = fmt.Fprintf(conn, "HTTP/1.1 %d %s\r\nconnection: close\r\n\r\n", status, reason)
}

// destroyConnection is socket.destroy() for an upgrade nobody claimed.
func destroyConnection(w http.ResponseWriter) {
	if conn := hijackConnection(w); conn != nil {
		_ = conn.Close()
		return
	}
	w.Header().Set("Connection", "close")
	w.WriteHeader(http.StatusBadRequest)
}

func hijackConnection(w http.ResponseWriter) net.Conn {
	hijacker, ok := w.(http.Hijacker)
	if !ok {
		return nil
	}
	conn, _, err := hijacker.Hijack()
	if err != nil {
		return nil
	}
	return conn
}
