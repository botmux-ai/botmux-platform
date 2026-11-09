package server

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/botmux-ai/botmux-platform/internal/auth"
	"github.com/botmux-ai/botmux-platform/internal/proxy"
	"github.com/botmux-ai/botmux-platform/internal/store"
	"github.com/botmux-ai/botmux-platform/internal/tunnel/tunneltest"
	"github.com/gorilla/websocket"
)

// Ports of test/server-machine-comanager-owner-parity.test.ts, the handler
// half of server-machine-header-strip.test.ts, server-machine-webhook-auth
// .test.ts, plus the machine.ts Desktop Bearer, peer-forward and WebSocket
// gates.

type failingMachineLookup struct{}

func (failingMachineLookup) LookupMachine(context.Context, string, store.AuthorityCacheOptions) (store.MachineDoc, error) {
	return store.MachineDoc{}, store.ErrUnavailable
}

func setCoManager(t *testing.T, env *machineTestEnv, unionID string, scopes ...string) {
	t.Helper()
	err := env.repo.SetMachineCoManagers(context.Background(), testMID, "u-alice", []store.MachineCoManager{{
		UnionID: unionID, Name: "Co", Scopes: scopes, GrantedAt: time.Now().UnixMilli(), GrantedBy: "u-alice",
	}})
	if err != nil {
		t.Fatal(err)
	}
}

func TestCoManagerOwnerParityPlatformHeaders(t *testing.T) {
	env := newMachineTestEnv(t)
	dashboard := serveMachine(t, env.online, proxy.SurfaceDashboard)

	owner := machineGet(t, dashboard+"/api/settings", ownerCookie(env.cfg, "u-alice"))
	if owner.Status != http.StatusOK || owner.Body != `{}` {
		t.Fatalf("owner = %d %s", owner.Status, owner.Body)
	}
	calls := env.proxy.Calls()
	if calls[0].Platform != (proxy.PlatformHeaders{Actor: "u-alice", Scopes: "machines:read,sessions:open,terminal:control,dashboard:manage"}) {
		t.Fatalf("owner platform = %+v", calls[0].Platform)
	}

	for _, tc := range []struct {
		scopes []string
		want   string
	}{
		{auth.ComanagerDefaultScopes(), "machines:read,sessions:open,terminal:control"},
		{[]string{"machines:read", "sessions:open"}, "machines:read,sessions:open"},
		{auth.ComanagerGrantableScopes(), "machines:read,sessions:open,terminal:control,dashboard:manage"},
	} {
		setCoManager(t, env, "u-co", tc.scopes...)
		before := len(env.proxy.Calls())
		got := machineGet(t, dashboard+"/api/settings", ownerCookie(env.cfg, "u-co"))
		calls := env.proxy.Calls()
		if got.Status != http.StatusOK || len(calls) != before+1 {
			t.Fatalf("co-manager %v = %d", tc.scopes, got.Status)
		}
		if calls[before].Platform != (proxy.PlatformHeaders{Actor: "u-co", Scopes: tc.want}) {
			t.Fatalf("co-manager %v platform = %+v", tc.scopes, calls[before].Platform)
		}
	}

	before := len(env.proxy.Calls())
	outsider := machineGet(t, dashboard+"/api/settings", ownerCookie(env.cfg, "u-outsider"))
	if outsider.Status != http.StatusForbidden || outsider.Body != "无权访问该机器" || len(env.proxy.Calls()) != before {
		t.Fatalf("outsider = %d %q", outsider.Status, outsider.Body)
	}

	env.online.Machines = failingMachineLookup{}
	unavailable := machineGet(t, dashboard+"/api/settings", ownerCookie(env.cfg, "u-co"))
	if unavailable.Status != http.StatusServiceUnavailable || unavailable.Body != "机器归属状态暂不可用，请稍后重试" {
		t.Fatalf("unavailable = %d %q", unavailable.Status, unavailable.Body)
	}
	// The owner is decided from the live tunnel and needs no store read.
	if got := machineGet(t, dashboard+"/api/settings", ownerCookie(env.cfg, "u-alice")); got.Status != http.StatusOK {
		t.Fatalf("owner during outage = %d", got.Status)
	}
}

func TestTerminalRoleForCoManagers(t *testing.T) {
	env := newMachineTestEnv(t)
	terminal := serveMachine(t, env.online, proxy.SurfaceTerminal)
	setCoManager(t, env, "u-co", auth.ComanagerDefaultScopes()...)
	if got := machineGet(t, terminal+"/s/x", ownerCookie(env.cfg, "u-co")); got.Body != `{"role":"owner"}` {
		t.Fatalf("co-manager with terminal:control = %s", got.Body)
	}
	setCoManager(t, env, "u-co", "machines:read")
	if got := machineGet(t, terminal+"/s/x", ownerCookie(env.cfg, "u-co")); got.Body != `{"role":"guest"}` {
		t.Fatalf("co-manager without terminal:control = %s", got.Body)
	}
	// Anonymous read-only stays available when the authority is degraded.
	env.online.Machines = failingMachineLookup{}
	if got := machineGet(t, terminal+"/s/x", ownerCookie(env.cfg, "u-co")); got.Status != http.StatusOK || got.Body != `{"role":"guest"}` {
		t.Fatalf("degraded = %d %s", got.Status, got.Body)
	}
	// Degraded, the person cannot be told apart from a read-only viewer, so
	// no actor is attached (no wake proof): anonymous guest.
	calls := env.proxy.Calls()
	if last := calls[len(calls)-1].Platform; last.Actor != "" || last.Role != "guest" {
		t.Fatalf("degraded platform = %+v", last)
	}
	// A grant that is gone but whose proxy cookie is still held: same.
	env.online.Machines = env.repo
	if err := env.repo.SetMachineCoManagers(context.Background(), testMID, "u-alice", nil); err != nil {
		t.Fatal(err)
	}
	if got := machineGet(t, terminal+"/s/x", ownerCookie(env.cfg, "u-co")); got.Body != `{"role":"guest"}` {
		t.Fatalf("revoked = %s", got.Body)
	}
	calls = env.proxy.Calls()
	if last := calls[len(calls)-1].Platform; last.Actor != "" {
		t.Fatalf("revoked platform = %+v", last)
	}
}

var forgedPlatformHeaders = map[string]string{
	"X-Botmux-Role":   "owner",
	"X-Botmux-Actor":  "ou_attacker",
	"X-Botmux-Scopes": "dashboard:manage",
}

func withHeaders(base map[string]string, extra map[string]string) map[string]string {
	out := map[string]string{}
	for k, v := range base {
		out[k] = v
	}
	for k, v := range extra {
		out[k] = v
	}
	return out
}

func TestEntryStripsForgedHeadersOnWebhookPaths(t *testing.T) {
	env := newMachineTestEnv(t)
	dashboard := serveMachine(t, env.online, proxy.SurfaceDashboard)
	for _, path := range []string{"/webhook/connector-1/tok", "/webhook/a/b/c", "/webhook/abc/tok/"} {
		before := len(env.proxy.Calls())
		got := machineDo(t, http.MethodGet, dashboard+path, withHeaders(forgedPlatformHeaders, map[string]string{"X-Botmux-Login-Url": "https://evil.example/phish"}))
		calls := env.proxy.Calls()
		if got.Status != http.StatusOK || len(calls) != before+1 {
			t.Fatalf("%s = %d", path, got.Status)
		}
		header := calls[before].Header
		for _, name := range []string{"X-Botmux-Role", "X-Botmux-Actor", "X-Botmux-Scopes", "X-Botmux-Login-Url"} {
			if header.Get(name) != "" {
				t.Fatalf("%s leaked %s", path, name)
			}
		}
		if calls[before].Platform != (proxy.PlatformHeaders{}) {
			t.Fatalf("%s platform = %+v", path, calls[before].Platform)
		}
	}

	got := machineDo(t, http.MethodGet, dashboard+"/webhook/connector-1/tok", withHeaders(forgedPlatformHeaders, map[string]string{
		"X-Botmux-Chat-Id": "oc_target_chat", "X-Botmux-Idempotency-Key": "idem-1", "X-Botmux-Signature": "sig",
		"X-Botmux-Terminal-Control": "forged-grant", "X-Botmux-Daemon-Sig": "forged", "X-Botmux-Cli-Auth": "forged",
	}))
	calls := env.proxy.Calls()
	header := calls[len(calls)-1].Header
	if got.Status != http.StatusOK || header.Get("X-Botmux-Role") != "" ||
		header.Get("X-Botmux-Chat-Id") != "oc_target_chat" || header.Get("X-Botmux-Idempotency-Key") != "idem-1" || header.Get("X-Botmux-Signature") != "sig" ||
		header.Get("X-Botmux-Terminal-Control") != "" || header.Get("X-Botmux-Daemon-Sig") != "" || header.Get("X-Botmux-Cli-Auth") != "" {
		t.Fatalf("webhook headers = %v", header)
	}
}

func TestEntryStripsForgedHeadersOnAuthenticatedAndTerminalPaths(t *testing.T) {
	env := newMachineTestEnv(t)
	dashboard := serveMachine(t, env.online, proxy.SurfaceDashboard)
	terminal := serveMachine(t, env.online, proxy.SurfaceTerminal)
	// Unauthenticated: never reaches the tunnel at all.
	if got := machineDo(t, http.MethodGet, dashboard+"/api/settings", withHeaders(forgedPlatformHeaders, map[string]string{"Accept": "application/json"})); got.Status != http.StatusUnauthorized || len(env.proxy.Calls()) != 0 {
		t.Fatalf("unauthenticated = %d", got.Status)
	}
	// Anonymous terminal: forged headers gone, the platform decides guest.
	machineDo(t, http.MethodGet, terminal+"/s/some-session", forgedPlatformHeaders)
	// Authenticated owner: forged headers gone, platform decision separate.
	machineDo(t, http.MethodGet, dashboard+"/api/settings", withHeaders(forgedPlatformHeaders, map[string]string{"Cookie": ownerCookie(env.cfg, "u-alice")}))
	calls := env.proxy.Calls()
	if len(calls) != 2 {
		t.Fatalf("calls = %d", len(calls))
	}
	for _, call := range calls {
		if call.Header.Get("X-Botmux-Role") != "" || call.Header.Get("X-Botmux-Actor") != "" || call.Header.Get("X-Botmux-Scopes") != "" {
			t.Fatalf("forged header reached the proxy: %v", call.Header)
		}
	}
	if calls[0].Platform.Role != "guest" || calls[1].Platform.Actor != "u-alice" {
		t.Fatalf("platform = %+v / %+v", calls[0].Platform, calls[1].Platform)
	}
}

// realProxyEnv runs the machine handler against the real proxy.Dashboard and
// a fake daemon whose dashboard is upstream.
func realProxyEnv(t *testing.T, upstream http.Handler) (*machineTestEnv, string, string) {
	t.Helper()
	t.Setenv("DASHBOARD_DIRECT", "0")
	env := newMachineTestEnv(t)
	server := httptest.NewServer(upstream)
	t.Cleanup(server.Close)
	daemon := tunneltest.Start(t, strings.TrimPrefix(server.URL, "http://"), tunneltest.Options{MachineID: testMID, UnionID: "u-alice", OwnerName: "Alice"})
	dashboard := proxy.NewDashboard(daemon.Registry)
	t.Cleanup(func() { _ = dashboard.Close() })
	env.online.Registry, env.online.Dashboard = daemon.Registry, dashboard
	return env, serveMachine(t, env.online, proxy.SurfaceDashboard), serveMachine(t, env.online, proxy.SurfaceTerminal)
}

func echoHeaders(w http.ResponseWriter, r *http.Request) {
	headers := map[string]string{}
	for name := range r.Header {
		headers[strings.ToLower(name)] = r.Header.Get(name)
	}
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(headers)
}

func TestWebhookKeepsThirdPartyAuthorizationEndToEnd(t *testing.T) {
	env, dashboard, _ := realProxyEnv(t, http.HandlerFunc(echoHeaders))
	webhook := machineDo(t, http.MethodGet, dashboard+"/webhook/secret", map[string]string{
		"Authorization":       "Bearer third-party-secret",
		"Proxy-Authorization": "Basic dGhpcmQtcGFydHk=",
		"X-Botmux-Role":       "owner",
		"X-Botmux-Chat-Id":    "oc_target",
	})
	headers := map[string]string{}
	if err := json.Unmarshal([]byte(webhook.Body), &headers); err != nil || webhook.Status != http.StatusOK {
		t.Fatalf("webhook = %d %q %v", webhook.Status, webhook.Body, err)
	}
	if headers["authorization"] != "Bearer third-party-secret" || headers["proxy-authorization"] != "Basic dGhpcmQtcGFydHk=" ||
		headers["x-botmux-role"] != "" || headers["x-botmux-chat-id"] != "oc_target" || headers["cookie"] != "botmux_dashboard_token=tok-123" {
		t.Fatalf("upstream saw %v", headers)
	}

	// Other dashboard paths strip credentials in the proxy layer.
	front := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		machine, _ := env.online.Registry.Get(testMID)
		env.online.Dashboard.ProxyHTTP(w, r, machine, proxy.PlatformHeaders{})
	}))
	defer front.Close()
	direct := machineDo(t, http.MethodGet, front.URL+"/api/sessions", map[string]string{
		"Authorization": "Bearer platform-dashboard-secret", "Proxy-Authorization": "Basic cGxhdGZvcm0=",
	})
	headers = map[string]string{}
	_ = json.Unmarshal([]byte(direct.Body), &headers)
	if direct.Status != http.StatusOK || headers["authorization"] != "" || headers["proxy-authorization"] != "" {
		t.Fatalf("direct = %d %v", direct.Status, headers)
	}
}

// wsEcho upgrades and echoes, recording the upgrade request headers.
type wsEcho struct {
	mu      sync.Mutex
	headers []http.Header
}

func (e *wsEcho) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	e.mu.Lock()
	e.headers = append(e.headers, r.Header.Clone())
	e.mu.Unlock()
	upgrader := websocket.Upgrader{CheckOrigin: func(*http.Request) bool { return true }}
	conn, err := upgrader.Upgrade(w, r, nil)
	if err != nil {
		return
	}
	defer conn.Close()
	for {
		kind, data, err := conn.ReadMessage()
		if err != nil {
			return
		}
		if conn.WriteMessage(kind, data) != nil {
			return
		}
	}
}

func (e *wsEcho) seen() []http.Header {
	e.mu.Lock()
	defer e.mu.Unlock()
	return append([]http.Header(nil), e.headers...)
}

func dialMachineWS(t *testing.T, base, path, cookie string) *websocket.Conn {
	t.Helper()
	header := http.Header{}
	if cookie != "" {
		header.Set("Cookie", cookie)
	}
	conn, response, err := websocket.DefaultDialer.Dial("ws"+strings.TrimPrefix(base, "http")+path, header)
	if err != nil {
		status := 0
		if response != nil {
			status = response.StatusCode
		}
		t.Fatalf("dial %s: %v (%d)", path, err, status)
	}
	t.Cleanup(func() { _ = conn.Close() })
	if err := conn.WriteMessage(websocket.TextMessage, []byte("ping")); err != nil {
		t.Fatal(err)
	}
	_ = conn.SetReadDeadline(time.Now().Add(3 * time.Second))
	if _, data, err := conn.ReadMessage(); err != nil || string(data) != "ping" {
		t.Fatalf("echo = %q %v", data, err)
	}
	_ = conn.SetReadDeadline(time.Time{})
	return conn
}

func waitClosed(t *testing.T, conn *websocket.Conn, within time.Duration) {
	t.Helper()
	_ = conn.SetReadDeadline(time.Now().Add(within))
	for {
		if _, _, err := conn.ReadMessage(); err != nil {
			if netErr, ok := err.(interface{ Timeout() bool }); ok && netErr.Timeout() {
				t.Fatal("device WebSocket outlived its revocation")
			}
			return
		}
	}
}

func TestDeviceTerminalWebSocketIsRevokedEndToEnd(t *testing.T) {
	echo := &wsEcho{}
	env, _, terminal := realProxyEnv(t, echo)
	conn := dialMachineWS(t, terminal, "/s/ws", terminalDeviceCookie(env.cfg, deviceClaims(auth.DeviceProxyPurposeTerminal, store.MobileDeviceScopes())))
	upgrade := echo.seen()[0]
	if upgrade.Get("X-Botmux-Role") != "owner" || upgrade.Get("X-Botmux-Actor") != "u-alice" || upgrade.Get("X-Botmux-Login-Url") != "" ||
		upgrade.Get("X-Botmux-Scopes") != "" || upgrade.Get("Cookie") != "botmux_dashboard_token=tok-123" {
		t.Fatalf("upgrade headers = %v", upgrade)
	}
	if got := env.registeredStreams(); got != 1 {
		t.Fatalf("registered = %d", got)
	}
	if closed := env.watcher.CloseDevice("dev-1", "owner_revoked"); closed != 1 {
		t.Fatalf("CloseDevice = %d", closed)
	}
	waitClosed(t, conn, 2*time.Second)
	eventuallyTrue(t, func() bool { return env.registeredStreams() == 0 })
}

func TestDeviceTerminalWebSocketEndsAtAuthExp(t *testing.T) {
	env, _, terminal := realProxyEnv(t, &wsEcho{})
	claims := deviceClaims(auth.DeviceProxyPurposeTerminal, store.MobileDeviceScopes())
	claims.AuthExp = time.Now().Unix() + 2
	conn := dialMachineWS(t, terminal, "/s/ws", terminalDeviceCookie(env.cfg, claims))
	waitClosed(t, conn, 4*time.Second)
}

func TestOwnerAndGuestWebSocketsThroughRealProxy(t *testing.T) {
	echo := &wsEcho{}
	env, dashboard, terminal := realProxyEnv(t, echo)
	dialMachineWS(t, terminal, "/s/ws", "")
	dialMachineWS(t, dashboard, "/api/ws", ownerCookie(env.cfg, "u-alice"))
	seen := echo.seen()
	if seen[0].Get("X-Botmux-Role") != "guest" || seen[0].Get("X-Botmux-Actor") != "" {
		t.Fatalf("guest upgrade = %v", seen[0])
	}
	if seen[1].Get("X-Botmux-Role") != "" || seen[1].Get("X-Botmux-Actor") != "u-alice" ||
		seen[1].Get("X-Botmux-Scopes") != "machines:read,sessions:open,terminal:control,dashboard:manage" {
		t.Fatalf("owner upgrade = %v", seen[1])
	}
	if env.registeredStreams() != 0 {
		t.Fatal("non-device streams must not be registered")
	}
}

func TestWebSocketUpgradeRejections(t *testing.T) {
	env := newMachineTestEnv(t)
	dashboard := serveMachine(t, env.online, proxy.SurfaceDashboard)
	terminal := serveMachine(t, env.online, proxy.SurfaceTerminal)
	offline := serveMachine(t, env.offline, proxy.SurfaceDashboard)
	dashboardCookie := dashboardDeviceCookie(env.cfg, deviceClaims(auth.DeviceProxyPurposeDashboardMobile, store.MobileDeviceScopes()))
	terminalCookie := terminalDeviceCookie(env.cfg, deviceClaims(auth.DeviceProxyPurposeTerminal, store.MobileDeviceScopes()))
	forbidden := "HTTP/1.1 403 Forbidden\r\n\r\n"
	for name, tc := range map[string]struct {
		base, path, cookie, want string
	}{
		"m- /s cannot migrate origin":      {dashboard, "/s/x", "", forbidden},
		"t- non-terminal path":             {terminal, "/api/ws", "", forbidden},
		"both device purposes":             {terminal, "/s/x", dashboardCookie + "; " + terminalCookie, forbidden},
		"dashboard device on dashboard ws": {dashboard, "/api/ws", dashboardCookie, forbidden},
		"dashboard device on terminal":     {terminal, "/s/x", dashboardCookie, forbidden},
		"no session":                       {dashboard, "/api/ws", "", "HTTP/1.1 401 Unauthorized\r\n\r\n"},
		"offline":                          {offline, "/api/ws", ownerCookie(env.cfg, "u-alice"), "HTTP/1.1 502 Bad Gateway\r\n\r\n"},
		"outsider":                         {dashboard, "/api/ws", ownerCookie(env.cfg, "u-outsider"), forbidden},
		"garbage terminal device cookie":   {terminal, "/s/x", "botmux_device_terminal_session=garbage", "HTTP/1.1 401 Unauthorized\r\n\r\n"},
		"terminal device without control":  {terminal, "/s/x", terminalDeviceCookie(env.cfg, deviceClaims(auth.DeviceProxyPurposeTerminal, []string{store.DeviceScopeMachinesRead})), forbidden},
	} {
		headers := map[string]string{}
		if tc.cookie != "" {
			headers["Cookie"] = tc.cookie
		}
		if got := rawUpgrade(t, tc.base, tc.path, headers); got != tc.want {
			t.Fatalf("%s = %q", name, got)
		}
	}
	env.online.Machines = failingMachineLookup{}
	if got := rawUpgrade(t, dashboard, "/api/ws", map[string]string{"Cookie": ownerCookie(env.cfg, "u-co")}); got != "HTTP/1.1 503 Service Unavailable\r\n\r\n" {
		t.Fatalf("unavailable = %q", got)
	}
	env.devices.set(nil, store.ErrUnavailable)
	env.states.Invalidate("dev-1")
	if got := rawUpgrade(t, terminal, "/s/x", map[string]string{"Cookie": terminalCookie}); got != "HTTP/1.1 503 Service Unavailable\r\n\r\n" {
		t.Fatalf("device unavailable = %q", got)
	}
	if len(env.proxy.Calls()) != 0 {
		t.Fatalf("rejected upgrades reached the proxy: %+v", env.proxy.Calls())
	}
}

type fakeRoutes struct {
	mu    sync.Mutex
	owner string
	err   error
	opts  []store.RouteCacheOptions
}

func (f *fakeRoutes) GetMachineRouteCached(_ context.Context, _ string, opts store.RouteCacheOptions) (string, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.opts = append(f.opts, opts)
	return f.owner, f.err
}

type forwardRecord struct {
	owner  string
	ws     bool
	header http.Header
	uri    string
}

func installForwarders(h *MachineHandler) *[]forwardRecord {
	var mu sync.Mutex
	records := &[]forwardRecord{}
	record := func(ws bool) func(string, http.ResponseWriter, *http.Request) error {
		return func(owner string, w http.ResponseWriter, r *http.Request) error {
			mu.Lock()
			*records = append(*records, forwardRecord{owner: owner, ws: ws, header: r.Header.Clone(), uri: r.URL.RequestURI()})
			mu.Unlock()
			if ws {
				rejectUpgrade(w, http.StatusTeapot)
				return nil
			}
			w.WriteHeader(299)
			_, _ = io.WriteString(w, "forwarded")
			return nil
		}
	}
	h.ForwardHTTP, h.ForwardRawWS = record(false), record(true)
	return records
}

func TestOfflineMachineForwardsToOwnerPod(t *testing.T) {
	env := newMachineTestEnv(t)
	routes := &fakeRoutes{owner: "10.0.0.2:8080"}
	env.offline.Routes = routes
	env.offline.Config.SelfPodAddr = "10.0.0.1:8080"
	records := installForwarders(env.offline)
	dashboard := serveMachine(t, env.offline, proxy.SurfaceDashboard)
	terminal := serveMachine(t, env.offline, proxy.SurfaceTerminal)
	owner := ownerCookie(env.cfg, "u-alice")

	if got := machineDo(t, http.MethodGet, dashboard+"/api/sessions", withHeaders(forgedPlatformHeaders, map[string]string{"Cookie": owner})); got.Status != 299 {
		t.Fatalf("forward = %d", got.Status)
	}
	if got := machineGet(t, dashboard+"/webhook/a/b"); got.Status != 299 {
		t.Fatalf("webhook forward = %d", got.Status)
	}
	if got := machineGet(t, terminal+"/s/x"); got.Status != 299 {
		t.Fatalf("terminal forward = %d", got.Status)
	}
	if got := rawUpgrade(t, dashboard, "/api/ws", map[string]string{"Cookie": owner}); got != "HTTP/1.1 418 I'm a teapot\r\n\r\n" {
		t.Fatalf("ws forward = %q", got)
	}
	if len(*records) != 4 || !(*records)[3].ws {
		t.Fatalf("records = %+v", *records)
	}
	for _, record := range *records {
		if record.owner != "10.0.0.2:8080" || record.header.Get("X-Botmux-Role") != "" {
			t.Fatalf("record = %+v", record)
		}
	}
	for _, opts := range routes.opts {
		if opts.PositiveTTL != store.MachineRouteCacheTTL {
			t.Fatalf("route read opts = %+v", opts)
		}
	}

	// The loop guard keeps a forwarded request on this pod.
	if got := machineDo(t, http.MethodGet, dashboard+"/api/sessions", map[string]string{"Cookie": owner, proxy.ForwardHeader: "1"}); got.Status != http.StatusServiceUnavailable {
		t.Fatalf("loop guard = %d", got.Status)
	}
	if got := machineDo(t, http.MethodGet, dashboard+"/webhook/a/b", map[string]string{proxy.ForwardHeader: "1"}); got.Status != http.StatusBadGateway || got.Body != "机器当前不在线" {
		t.Fatalf("webhook loop guard = %d %q", got.Status, got.Body)
	}
	// A route to this very pod, or a failed route read, is "no route".
	routes.owner = "10.0.0.1:8080"
	if got := machineGet(t, dashboard+"/api/sessions", owner); got.Status != http.StatusServiceUnavailable {
		t.Fatalf("self route = %d", got.Status)
	}
	routes.owner, routes.err = "10.0.0.2:8080", store.ErrUnavailable
	if got := rawUpgrade(t, dashboard, "/api/ws", map[string]string{"Cookie": owner}); got != "HTTP/1.1 502 Bad Gateway\r\n\r\n" {
		t.Fatalf("route error ws = %q", got)
	}
	if len(*records) != 4 {
		t.Fatalf("unexpected forwards: %+v", *records)
	}
}

type spyDesktopAuthority struct {
	store.DesktopSessionRepository
	machines  auth.MachineLookup
	mu        sync.Mutex
	family    []store.AuthorityCacheOptions
	lookups   []store.AuthorityCacheOptions
	familyErr error
}

func (s *spyDesktopAuthority) GetDesktopSessionFamilyStatus(ctx context.Context, sid string, opts store.AuthorityCacheOptions) (store.DesktopFamilyStatus, error) {
	s.mu.Lock()
	s.family = append(s.family, opts)
	err := s.familyErr
	s.mu.Unlock()
	if err != nil {
		return "", err
	}
	return s.DesktopSessionRepository.GetDesktopSessionFamilyStatus(ctx, sid, opts)
}

func (s *spyDesktopAuthority) LookupMachine(ctx context.Context, id string, opts store.AuthorityCacheOptions) (store.MachineDoc, error) {
	s.mu.Lock()
	s.lookups = append(s.lookups, opts)
	s.mu.Unlock()
	return s.machines.LookupMachine(ctx, id, opts)
}

func desktopBearer(env *machineTestEnv, unionID, machineID string, scope auth.DesktopDashboardScope) string {
	access := &auth.DesktopAccessPayload{
		Kind: "desktop-access", SID: "family-0000000001", UnionID: unionID, CloudProfileID: "cp-1", Exp: time.Now().Unix() + 3600,
	}
	return "Bearer " + auth.MintDesktopDashboardAccessToken(env.cfg, access, machineID, scope).AccessToken
}

func TestDesktopBearerOnMachineDashboard(t *testing.T) {
	env := newMachineTestEnv(t)
	spy := &spyDesktopAuthority{DesktopSessionRepository: env.repo, machines: env.repo}
	env.online.DesktopSessions, env.online.Machines = spy, spy
	dashboard := serveMachine(t, env.online, proxy.SurfaceDashboard)
	terminal := serveMachine(t, env.online, proxy.SurfaceTerminal)
	observe := desktopBearer(env, "u-alice", testMID, auth.DesktopDashboardObserve)
	call := func(base, method, path, bearer string) subdomainResponse {
		return machineDo(t, method, base+path, map[string]string{"Authorization": bearer, "Cookie": ownerCookie(env.cfg, "u-alice")})
	}
	expectJSON := func(name string, got subdomainResponse, status int, body string) {
		t.Helper()
		if got.Status != status || got.Body != body || got.Header.Get("Cache-Control") != "no-store" {
			t.Fatalf("%s = %d %v %s", name, got.Status, got.Header, got.Body)
		}
	}

	expectJSON("invalid", call(dashboard, http.MethodGet, "/api/bots", "Bearer garbage"), http.StatusUnauthorized, `{"error":"invalid_dashboard_access"}`)
	// A terminal path on the terminal surface is decided as Bearer first.
	expectJSON("terminal surface", call(terminal, http.MethodGet, "/s/x", observe), http.StatusForbidden, `{"error":"dashboard_surface_mismatch"}`)
	expectJSON("other machine", call(dashboard, http.MethodGet, "/api/bots", desktopBearer(env, "u-alice", "deadbeefdeadbeef", auth.DesktopDashboardObserve)), http.StatusForbidden, `{"error":"machine_mismatch"}`)
	expectJSON("update/run", call(dashboard, http.MethodPost, "/api/update/run", desktopBearer(env, "u-alice", testMID, auth.DesktopDashboardManage)), http.StatusForbidden, `{"error":"path_not_allowed"}`)
	expectJSON("observe write", call(dashboard, http.MethodPost, "/api/bots", observe), http.StatusForbidden, `{"error":"insufficient_scope"}`)
	expectJSON("co-manager is not an owner", call(dashboard, http.MethodGet, "/api/bots", desktopBearer(env, "u-co", testMID, auth.DesktopDashboardObserve)), http.StatusForbidden, `{"error":"machine_owner_mismatch"}`)
	if len(env.proxy.Calls()) != 0 {
		t.Fatal("rejected Bearer reached the proxy")
	}

	ok := call(dashboard, http.MethodGet, "/api/bots?token=leak&x=1&ticket=t", observe)
	calls := env.proxy.Calls()
	if ok.Status != http.StatusOK || len(calls) != 1 || calls[0].URI != "/api/bots?x=1" ||
		calls[0].Header.Get("Authorization") != "" || calls[0].Platform != (proxy.PlatformHeaders{}) {
		t.Fatalf("authorized = %d %+v", ok.Status, calls)
	}
	// The SSO cookie riding along does not change the decision either.
	if calls[0].Header.Get("Cookie") == "" {
		t.Fatal("cookie header unexpectedly dropped before the proxy layer")
	}
	spy.mu.Lock()
	for _, opts := range append(append([]store.AuthorityCacheOptions(nil), spy.family...), spy.lookups...) {
		if opts.PositiveTTL != store.DesktopDashboardAuthCacheTTL {
			t.Fatalf("desktop authority opts = %+v", opts)
		}
	}
	spy.mu.Unlock()

	spy.familyErr = store.ErrUnavailable
	expectJSON("family unavailable", call(dashboard, http.MethodGet, "/api/bots", observe), http.StatusServiceUnavailable, `{"error":"store_unavailable"}`)
	spy.familyErr = nil
	if err := env.repo.RevokeDesktopSessionFamily(context.Background(), "family-0000000001", time.Now().Add(time.Hour).UnixMilli()); err != nil {
		t.Fatal(err)
	}
	expectJSON("revoked family", call(dashboard, http.MethodGet, "/api/bots", observe), http.StatusUnauthorized, `{"error":"session_revoked"}`)
}

func TestDesktopBearerRejectsRetiredOrUnavailableMachine(t *testing.T) {
	env := newMachineTestEnv(t)
	dashboard := serveMachine(t, env.online, proxy.SurfaceDashboard)
	observe := desktopBearer(env, "u-alice", testMID, auth.DesktopDashboardObserve)
	env.online.Machines = failingMachineLookup{}
	if got := machineDo(t, http.MethodGet, dashboard+"/api/bots", map[string]string{"Authorization": observe}); got.Status != http.StatusServiceUnavailable || got.Body != `{"error":"store_unavailable"}` {
		t.Fatalf("unavailable = %d %s", got.Status, got.Body)
	}
	env.online.Machines = env.repo
	if err := env.repo.RetireMachine(context.Background(), testMID); err != nil {
		t.Fatal(err)
	}
	if got := machineDo(t, http.MethodGet, dashboard+"/api/bots", map[string]string{"Authorization": observe}); got.Status != http.StatusForbidden || got.Body != `{"error":"machine_owner_mismatch"}` {
		t.Fatalf("retired = %d %s", got.Status, got.Body)
	}
	// Offline with no peer: the owner gets the reconnect page, not a 403.
	fresh := newMachineTestEnv(t)
	offline := serveMachine(t, fresh.offline, proxy.SurfaceDashboard)
	if got := machineDo(t, http.MethodGet, offline+"/api/bots", map[string]string{"Authorization": desktopBearer(fresh, "u-alice", testMID, auth.DesktopDashboardObserve)}); got.Status != http.StatusServiceUnavailable || !strings.Contains(got.Body, "正在重连") {
		t.Fatalf("offline = %d %q", got.Status, got.Body)
	}
	// Webhook paths keep their Bearer for the third party.
	if got := machineDo(t, http.MethodGet, dashboard+"/webhook/a/b", map[string]string{"Authorization": "Bearer third-party"}); got.Status != http.StatusOK {
		t.Fatalf("webhook bearer = %d %s", got.Status, got.Body)
	}
	calls := env.proxy.Calls()
	if len(calls) != 1 || calls[0].Header.Get("Authorization") != "Bearer third-party" {
		t.Fatalf("webhook call = %+v", calls)
	}
}

func TestDesktopBearerSSEEndsAtTicketExpiry(t *testing.T) {
	env := newMachineTestEnv(t)
	env.proxy.sse = true
	dashboard := serveMachine(t, env.online, proxy.SurfaceDashboard)
	access := &auth.DesktopAccessPayload{Kind: "desktop-access", SID: "family-0000000002", UnionID: "u-alice", CloudProfileID: "cp-1", Exp: time.Now().Unix() + 2}
	bearer := "Bearer " + auth.MintDesktopDashboardAccessToken(env.cfg, access, testMID, auth.DesktopDashboardObserve).AccessToken
	request, _ := http.NewRequest(http.MethodGet, dashboard+"/events", nil)
	request.Header.Set("Authorization", bearer)
	client := &http.Client{Transport: &http.Transport{DisableKeepAlives: true}}
	response, err := client.Do(request)
	if err != nil {
		t.Fatal(err)
	}
	defer response.Body.Close()
	done := make(chan error, 1)
	go func() {
		_, err := io.ReadAll(response.Body)
		done <- err
	}()
	select {
	case err := <-done:
		if err == nil {
			t.Fatal("expired desktop stream ended cleanly")
		}
	case <-time.After(5 * time.Second):
		t.Fatal("desktop stream outlived the ticket")
	}
}
