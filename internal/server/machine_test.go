package server

import (
	"bufio"
	"encoding/json"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/botmux-ai/botmux-platform/internal/auth"
	"github.com/botmux-ai/botmux-platform/internal/config"
	"github.com/botmux-ai/botmux-platform/internal/proxy"
	"github.com/botmux-ai/botmux-platform/internal/store"
	"github.com/botmux-ai/botmux-platform/internal/tunnel"
	"github.com/botmux-ai/botmux-platform/internal/tunnel/tunneltest"
)

// Shared harness for the machine subdomain tests (ports of
// test/server-device-proxy.test.ts machine parts, server-machine-*.test.ts
// and the handler-level cache tests).

const testMID = "feedfacefeedface"

type machineProxyCall struct {
	Header   http.Header
	URI      string
	Platform proxy.PlatformHeaders
	WS       bool
}

// fakeMachineProxy stands in for proxy.Dashboard: it records what the
// handler hands to the proxy layer (request headers and the separate
// platform decision) and answers like patchProxyHttpAsRoleEcho / AsSse.
type fakeMachineProxy struct {
	mu    sync.Mutex
	calls []machineProxyCall
	sse   bool
}

func (f *fakeMachineProxy) record(r *http.Request, platform proxy.PlatformHeaders, ws bool) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.calls = append(f.calls, machineProxyCall{Header: r.Header.Clone(), URI: r.URL.RequestURI(), Platform: platform, WS: ws})
}

func (f *fakeMachineProxy) Calls() []machineProxyCall {
	f.mu.Lock()
	defer f.mu.Unlock()
	return append([]machineProxyCall(nil), f.calls...)
}

func (f *fakeMachineProxy) ProxyHTTP(w http.ResponseWriter, r *http.Request, _ tunnel.MachineConn, platform proxy.PlatformHeaders) {
	f.record(r, platform, false)
	f.mu.Lock()
	sse := f.sse
	f.mu.Unlock()
	if sse {
		w.Header().Set("Content-Type", "text/event-stream")
		w.Header().Set("Cache-Control", "no-store")
		w.WriteHeader(http.StatusOK)
		_, _ = io.WriteString(w, "data: hello\n\n")
		w.(http.Flusher).Flush()
		// The real proxy aborts the browser connection when the request
		// context is cancelled (revocation, lease, client gone).
		<-r.Context().Done()
		abortMachineClient(w)
		return
	}
	writeJSON(w, http.StatusOK, struct {
		Role string `json:"role,omitempty"`
	}{platform.Role})
}

func (f *fakeMachineProxy) ProxyWebSocket(w http.ResponseWriter, r *http.Request, _ tunnel.MachineConn, platform proxy.PlatformHeaders) error {
	f.record(r, platform, true)
	if hijacker, ok := w.(http.Hijacker); ok {
		if conn, buffered, err := hijacker.Hijack(); err == nil {
			_, _ = buffered.WriteString("HTTP/1.1 101 Switching Protocols\r\n\r\n")
			_ = buffered.Flush()
			_ = conn.Close()
		}
	}
	return nil
}

type machineTestEnv struct {
	cfg     config.Config
	repo    *store.DocumentRepository
	devices *fakeDeviceReader
	states  *auth.DeviceStateCache
	watcher *DeviceSocketWatcher
	proxy   *fakeMachineProxy
	daemon  *tunneltest.Daemon
	online  *MachineHandler
	offline *MachineHandler
}

func machineTestConfig() config.Config {
	return config.Config{
		PublicBaseURL:           "http://localhost",
		RootHost:                "localhost",
		MachineSubdomainPrefix:  "m-",
		TerminalSubdomainPrefix: "t-",
		SigningSecret:           "test-secret",
		SessionTTL:              7 * 24 * time.Hour,
		StaleAfter:              time.Minute,
	}
}

func newMachineTestEnv(t *testing.T) *machineTestEnv {
	t.Helper()
	return newMachineTestEnvVersion(t, "")
}

// newMachineTestEnvVersion is newMachineTestEnv with the botmux version the
// fake daemon reports in its tunnel registration ("" = tunneltest default).
func newMachineTestEnvVersion(t *testing.T, botmuxVersion string) *machineTestEnv {
	t.Helper()
	cfg := machineTestConfig()
	repo := newMemoryRepository()
	if err := seedMachine(repo, store.RegisterMachine{MachineID: testMID, UnionID: "u-alice", OwnerName: "Alice", Name: "alice-macbook"}); err != nil {
		t.Fatal(err)
	}
	devices := &fakeDeviceReader{doc: activeDevice(1)}
	states := auth.NewDeviceStateCache(devices)
	watcher := NewDeviceSocketWatcher(states)
	watcher.interval = time.Hour
	fake := &fakeMachineProxy{}
	daemon := tunneltest.Start(t, "127.0.0.1:1", tunneltest.Options{MachineID: testMID, UnionID: "u-alice", OwnerName: "Alice", BotmuxVersion: botmuxVersion})
	build := func(registry *tunnel.Registry) *MachineHandler {
		return &MachineHandler{
			Config: cfg, Registry: registry, Dashboard: fake,
			Machines: repo, DesktopSessions: repo, DeviceStates: states, DeviceSockets: watcher,
		}
	}
	empty := tunnel.NewRegistry(time.Minute, "", nil)
	t.Cleanup(func() { _ = empty.Close() })
	return &machineTestEnv{
		cfg: cfg, repo: repo, devices: devices, states: states, watcher: watcher, proxy: fake, daemon: daemon,
		online: build(daemon.Registry), offline: build(empty),
	}
}

// serve exposes one handler on one surface (machineServer / terminal...).
func serveMachine(t *testing.T, h *MachineHandler, surface proxy.MachineSurface) string {
	t.Helper()
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		h.ServeMachineSurface(w, r, testMID, surface)
	}))
	t.Cleanup(server.Close)
	return server.URL
}

type subdomainResponse struct {
	Status     int
	Header     http.Header
	Body       string
	SetCookies []string
}

func machineDo(t *testing.T, method, target string, headers map[string]string) subdomainResponse {
	t.Helper()
	request, err := http.NewRequest(method, target, nil)
	if err != nil {
		t.Fatal(err)
	}
	for name, value := range headers {
		if strings.EqualFold(name, "Host") {
			request.Host = value
			continue
		}
		request.Header.Set(name, value)
	}
	client := &http.Client{CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
	response, err := client.Do(request)
	if err != nil {
		t.Fatal(err)
	}
	defer response.Body.Close()
	body, _ := io.ReadAll(response.Body)
	return subdomainResponse{Status: response.StatusCode, Header: response.Header, Body: string(body), SetCookies: response.Header.Values("Set-Cookie")}
}

func machineGet(t *testing.T, target string, cookies ...string) subdomainResponse {
	t.Helper()
	headers := map[string]string{}
	if len(cookies) > 0 {
		headers["Cookie"] = strings.Join(cookies, "; ")
	}
	return machineDo(t, http.MethodGet, target, headers)
}

func deviceClaims(purpose auth.DeviceProxyPurpose, scopes []string) auth.DeviceProxyClaims {
	now := time.Now().Unix()
	return auth.DeviceProxyClaims{
		UnionID: "u-alice", MachineID: testMID, DeviceID: "dev-1", CredentialVersion: 1,
		EffectiveScopes: scopes, SID: "sid-1", SessionMaxExp: now + 3600, AuthExp: now + 600, Purpose: purpose,
	}
}

func dashboardDeviceCookie(cfg config.Config, claims auth.DeviceProxyClaims) string {
	return "botmux_device_proxy_session=" + auth.MintDeviceProxySession(cfg, claims)
}

func terminalDeviceCookie(cfg config.Config, claims auth.DeviceProxyClaims) string {
	return "botmux_device_terminal_session=" + auth.MintDeviceProxySession(cfg, claims)
}

func ownerCookie(cfg config.Config, unionID string) string {
	return auth.ProxySessionRequestCookie(cfg, auth.ProxyIdentity{UnionID: unionID, MachineID: testMID})
}

func cookieValue(setCookies []string, name string) string {
	for _, cookie := range setCookies {
		if strings.HasPrefix(cookie, name+"=") {
			first, _, _ := strings.Cut(cookie, ";")
			return strings.TrimPrefix(first, name+"=")
		}
	}
	return ""
}

func (e *machineTestEnv) revokeDevice() {
	e.devices.set(&store.DeviceDoc{ID: "dev-1", Status: store.DeviceStatusRevoked, CredentialVersion: 1}, nil)
	e.states.Invalidate("dev-1")
}

func (e *machineTestEnv) registeredStreams() int {
	return len(e.watcher.snapshot("dev-1"))
}

// rawUpgrade sends a WebSocket upgrade over a raw connection and returns
// everything the server wrote before closing.
func rawUpgrade(t *testing.T, base, path string, headers map[string]string) string {
	t.Helper()
	conn, err := net.Dial("tcp", strings.TrimPrefix(base, "http://"))
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	var b strings.Builder
	b.WriteString("GET " + path + " HTTP/1.1\r\nHost: x\r\nConnection: Upgrade\r\nUpgrade: websocket\r\n")
	b.WriteString("Sec-WebSocket-Version: 13\r\nSec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\n")
	for name, value := range headers {
		b.WriteString(name + ": " + value + "\r\n")
	}
	b.WriteString("\r\n")
	if _, err := io.WriteString(conn, b.String()); err != nil {
		t.Fatal(err)
	}
	_ = conn.SetReadDeadline(time.Now().Add(3 * time.Second))
	raw, _ := io.ReadAll(bufio.NewReader(conn))
	return string(raw)
}

func TestReconnectPageMatchesNode(t *testing.T) {
	recorder := httptest.NewRecorder()
	reconnect(recorder)
	if recorder.Code != http.StatusServiceUnavailable ||
		recorder.Header().Get("Content-Type") != "text/html; charset=utf-8" ||
		recorder.Header().Get("Retry-After") != "2" ||
		recorder.Header().Get("Cache-Control") != "no-store" {
		t.Fatalf("reconnect = %d %v", recorder.Code, recorder.Header())
	}
	if !strings.Contains(recorder.Body.String(), "正在重连") || !strings.HasSuffix(recorder.Body.String(), "</body></html>") {
		t.Fatalf("reconnect body = %q", recorder.Body.String())
	}
}

func TestMachineSubdomainMatchesBothSurfaces(t *testing.T) {
	cfg := machineTestConfig()
	for host, want := range map[string]string{
		"m-" + testMID + ".localhost:8080": testMID,
		"t-" + testMID + ".localhost":      testMID,
	} {
		if got, ok := MatchMachineSubdomain(cfg, host); !ok || got != want {
			t.Fatalf("%s => %q %v", host, got, ok)
		}
	}
	if _, ok := MatchMachineSubdomain(cfg, "x-"+testMID+".localhost"); ok {
		t.Fatal("unknown prefix matched")
	}
	if got := MachineBaseURL(cfg, testMID); got != "http://m-"+testMID+".localhost" {
		t.Fatalf("MachineBaseURL = %q", got)
	}

	// ServeMachine derives the surface from the same Host.
	env := newMachineTestEnv(t)
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		env.online.ServeMachine(w, r, testMID)
	}))
	defer server.Close()
	terminal := machineDo(t, http.MethodGet, server.URL+"/api/sessions", map[string]string{"Host": "t-" + testMID + ".localhost"})
	if terminal.Status != http.StatusForbidden || terminal.Body != `{"error":"terminal_surface_path_forbidden"}` {
		t.Fatalf("terminal host = %d %s", terminal.Status, terminal.Body)
	}
	guest := machineDo(t, http.MethodGet, server.URL+"/s/x", map[string]string{"Host": "t-" + testMID + ".localhost"})
	if guest.Status != http.StatusOK || guest.Body != `{"role":"guest"}` {
		t.Fatalf("terminal guest = %d %s", guest.Status, guest.Body)
	}
}

func TestWhatwgPathnameAndSearchHelpers(t *testing.T) {
	for in, want := range map[string]string{
		"":                "/",
		"/s/../api/x":     "/api/x",
		"/s/%2e%2E/api":   "/api",
		"/a/./b/.":        "/a/b/",
		`/a\b`:            "/a/b",
		"/a/%2e":          "/a/",
		"/../..":          "/",
		"/webhook/a%2Fb/": "/webhook/a%2Fb/",
	} {
		if got := whatwgPathname(in); got != want {
			t.Fatalf("whatwgPathname(%q) = %q, want %q", in, got, want)
		}
	}
	if got := jsEncodeURIComponent("/foo/bar?x=1&__bmx_sso=1 é~!*'()"); got != "%2Ffoo%2Fbar%3Fx%3D1%26__bmx_sso%3D1%20%C3%A9~!*'()" {
		t.Fatalf("encodeURIComponent = %q", got)
	}
	params := parseSearchParams("x=1&__bmx_sso=1&y=a+b&x=2")
	if got := serializeSearch(setSearchParam(params, "x", "3")); got != "?x=3&__bmx_sso=1&y=a+b" {
		t.Fatalf("set = %q", got)
	}
	if got := serializeSearch(deleteSearchParam(params, ssoBounceParam)); got != "?x=1&y=a+b&x=2" {
		t.Fatalf("delete = %q", got)
	}
	if got := serializeSearch(deleteSearchParam(parseSearchParams("__bmx_sso=1"), ssoBounceParam)); got != "" {
		t.Fatalf("empty = %q", got)
	}
}

// decodeJSONBody is a small helper for exact-key assertions.
func decodeJSONBody(t *testing.T, body string) map[string]any {
	t.Helper()
	var out map[string]any
	if err := json.Unmarshal([]byte(body), &out); err != nil {
		t.Fatalf("body %q: %v", body, err)
	}
	return out
}

func parseLocation(t *testing.T, location string) *url.URL {
	t.Helper()
	parsed, err := url.Parse(location)
	if err != nil {
		t.Fatal(err)
	}
	return parsed
}
