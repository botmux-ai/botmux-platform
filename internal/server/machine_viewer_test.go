package server

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/botmux-ai/botmux-platform/internal/auth"
	"github.com/botmux-ai/botmux-platform/internal/proxy"
	"github.com/botmux-ai/botmux-platform/internal/store"
	"github.com/botmux-ai/botmux-platform/internal/tunnel/tunneltest"
)

// Read-only machine viewer on the m-<id> / t-<id> reverse proxy: the
// platform allowlist is the authority, the daemon sees a guest.

const viewerTestVersion = "3.57.1"

func setViewer(t *testing.T, env *machineTestEnv, unionID string) {
	t.Helper()
	err := env.repo.SetMachineCoManagers(context.Background(), testMID, "u-alice", []store.MachineCoManager{{
		UnionID: unionID, Name: "Viewer", Role: store.CoManagerRoleViewer, Scopes: auth.ViewerScopes(),
		GrantedAt: time.Now().UnixMilli(), GrantedBy: "u-alice",
	}})
	if err != nil {
		t.Fatal(err)
	}
}

var viewerPlatform = proxy.PlatformHeaders{Role: "guest", Actor: "u-view", Scopes: "machines:read"}

func TestViewerDashboardReadsReachDaemonAsGuest(t *testing.T) {
	env := newMachineTestEnvVersion(t, viewerTestVersion)
	dashboard := serveMachine(t, env.online, proxy.SurfaceDashboard)
	setViewer(t, env, "u-view")
	cookie := ownerCookie(env.cfg, "u-view")
	for _, path := range []string{
		"/", "/assets/index.js", "/api/sessions", "/api/workbench/capabilities",
		"/api/sessions/s-1/view-link", "/api/sessions/s-1/control",
	} {
		before := len(env.proxy.Calls())
		// Forged authority headers must not survive into the decision.
		got := machineDo(t, http.MethodGet, dashboard+path, withHeaders(forgedPlatformHeaders, map[string]string{"Cookie": cookie}))
		calls := env.proxy.Calls()
		if got.Status != http.StatusOK || len(calls) != before+1 {
			t.Fatalf("GET %s = %d %s", path, got.Status, got.Body)
		}
		if calls[before].Platform != viewerPlatform {
			t.Fatalf("GET %s platform = %+v", path, calls[before].Platform)
		}
		for _, name := range []string{"X-Botmux-Role", "X-Botmux-Actor", "X-Botmux-Scopes"} {
			if calls[before].Header.Get(name) != "" {
				t.Fatalf("GET %s forwarded forged %s", path, name)
			}
		}
	}
}

func TestViewerWriteAndPrivateRequestsRefusedAtPlatform(t *testing.T) {
	env := newMachineTestEnvVersion(t, viewerTestVersion)
	dashboard := serveMachine(t, env.online, proxy.SurfaceDashboard)
	setViewer(t, env, "u-view")
	cookie := ownerCookie(env.cfg, "u-view")
	for _, tc := range []struct{ kind, method, path string }{
		// configuration
		{"config", http.MethodGet, "/api/settings"},
		{"config", http.MethodPut, "/api/settings"},
		{"config", http.MethodPost, "/api/schedules"},
		{"config", http.MethodDelete, "/api/schedules/sch-1"},
		{"config", http.MethodPatch, "/api/bots/cli_a"},
		{"config", http.MethodPut, "/api/bots/cli_a/env"},
		{"config", http.MethodPut, "/api/bots/cli_a/startup-commands"},
		{"config", http.MethodPost, "/api/groups"},
		{"config", http.MethodPost, "/api/plugins/install"},
		// session operations
		{"session", http.MethodPost, "/api/sessions"},
		{"session", http.MethodDelete, "/api/sessions/s-1"},
		{"session", http.MethodPost, "/api/sessions/s-1/close"},
		{"session", http.MethodPost, "/api/sessions/s-1/restart"},
		{"session", http.MethodPost, "/api/sessions/s-1/locate"},
		{"session", http.MethodPost, "/api/sessions/s-1/control/takeover"},
		{"session", http.MethodPost, "/api/sessions/s-1/preview-interaction/unlock"},
		{"session", http.MethodPost, "/api/sessions/s-1/view-link"},
		// credentials / host takeover
		{"credential", http.MethodGet, "/api/sessions/s-1/write-link"},
		{"credential", http.MethodGet, "/api/sessions/s-1/spawn-command"},
		{"credential", http.MethodGet, "/api/debug-terminal"},
		{"credential", http.MethodGet, "/api/webhook-secrets"},
		// dot segments are resolved before the allowlist, like the daemon does
		{"normalized", http.MethodGet, "/api/sessions/../settings"},
		{"normalized", http.MethodGet, "/api/sessions/s-1/view-link/../write-link"},
		{"normalized", http.MethodGet, "/assets/../api/settings"},
		{"encoded", http.MethodGet, "/api/sessions/x%2F..%2F..%2Fsettings/view-link"},
	} {
		before := len(env.proxy.Calls())
		got := machineDo(t, tc.method, dashboard+tc.path, withHeaders(forgedPlatformHeaders, map[string]string{"Cookie": cookie}))
		wantStatus := http.StatusForbidden
		if tc.method == http.MethodGet {
			wantStatus = http.StatusUnauthorized
		}
		if got.Status != wantStatus || !strings.Contains(got.Body, `"viewer_read_only"`) ||
			got.Header.Get("X-Botmux-Auth-Scope") != "workbench" || got.Header.Get("Cache-Control") != "no-store" {
			t.Fatalf("%s %s %s = %d %v %s", tc.kind, tc.method, tc.path, got.Status, got.Header, got.Body)
		}
		if len(env.proxy.Calls()) != before {
			t.Fatalf("%s %s %s reached the daemon", tc.kind, tc.method, tc.path)
		}
	}
}

func TestViewerRefusedOnDaemonsWithoutGuestGating(t *testing.T) {
	for _, version := range []string{"", "3.15.0", "0.0.0", "3.16.0-canary.1"} {
		env := newMachineTestEnvVersion(t, version)
		dashboard := serveMachine(t, env.online, proxy.SurfaceDashboard)
		setViewer(t, env, "u-view")
		got := machineGet(t, dashboard+"/api/sessions", ownerCookie(env.cfg, "u-view"))
		if got.Status != http.StatusForbidden || !strings.Contains(got.Body, "viewer_requires_newer_botmux") || len(env.proxy.Calls()) != 0 {
			t.Fatalf("version %q = %d %s", version, got.Status, got.Body)
		}
		// The owner and co-managers are not version-gated.
		if got := machineGet(t, dashboard+"/api/settings", ownerCookie(env.cfg, "u-alice")); got.Status != http.StatusOK {
			t.Fatalf("version %q owner = %d", version, got.Status)
		}
	}
}

func TestViewerTerminalSurfaceIsAnonymousReadOnly(t *testing.T) {
	env := newMachineTestEnvVersion(t, viewerTestVersion)
	terminal := serveMachine(t, env.online, proxy.SurfaceTerminal)
	setViewer(t, env, "u-view")
	cookie := ownerCookie(env.cfg, "u-view")

	got := machineDo(t, http.MethodGet, terminal+"/s/s-1", withHeaders(forgedPlatformHeaders, map[string]string{"Cookie": cookie}))
	calls := env.proxy.Calls()
	if got.Status != http.StatusOK || got.Body != `{"role":"guest"}` || len(calls) != 1 {
		t.Fatalf("viewer terminal = %d %s", got.Status, got.Body)
	}
	// No actor: the daemon treats the viewer like an anonymous visitor and
	// attaches no wake proof, so a suspended session is not resumed.
	if calls[0].Platform.Role != "guest" || calls[0].Platform.Actor != "" {
		t.Fatalf("viewer terminal platform = %+v", calls[0].Platform)
	}
	for _, method := range []string{http.MethodPost, http.MethodPut, http.MethodDelete} {
		got := machineDo(t, method, terminal+"/s/s-1/input", map[string]string{"Cookie": cookie})
		if got.Status != http.StatusForbidden || !strings.Contains(got.Body, "viewer_read_only") {
			t.Fatalf("viewer terminal %s = %d %s", method, got.Status, got.Body)
		}
	}
	if len(env.proxy.Calls()) != 1 {
		t.Fatal("refused terminal writes reached the daemon")
	}
}

func TestViewerWebSockets(t *testing.T) {
	env := newMachineTestEnvVersion(t, viewerTestVersion)
	dashboard := serveMachine(t, env.online, proxy.SurfaceDashboard)
	terminal := serveMachine(t, env.online, proxy.SurfaceTerminal)
	setViewer(t, env, "u-view")
	cookie := map[string]string{"Cookie": ownerCookie(env.cfg, "u-view")}

	if got := rawUpgrade(t, dashboard, "/api/ws", cookie); got != "HTTP/1.1 403 Forbidden\r\n\r\n" {
		t.Fatalf("viewer dashboard ws = %q", got)
	}
	if len(env.proxy.Calls()) != 0 {
		t.Fatal("viewer dashboard ws reached the daemon")
	}
	// Terminal input WebSocket: bridged as guest (the worker drops input
	// frames from non-owner sockets), with no actor.
	if got := rawUpgrade(t, terminal, "/s/s-1", withHeaders(forgedPlatformHeaders, cookie)); !strings.HasPrefix(got, "HTTP/1.1 101") {
		t.Fatalf("viewer terminal ws = %q", got)
	}
	calls := env.proxy.Calls()
	if len(calls) != 1 || !calls[0].WS || calls[0].Platform != (proxy.PlatformHeaders{Role: "guest"}) {
		t.Fatalf("viewer terminal ws platform = %+v", calls)
	}
}

func TestCoManagerCapabilitiesUnchangedByViewerRole(t *testing.T) {
	// Deliberately the default fake daemon version ("test"): co-managers are
	// never version-gated.
	env := newMachineTestEnv(t)
	dashboard := serveMachine(t, env.online, proxy.SurfaceDashboard)
	terminal := serveMachine(t, env.online, proxy.SurfaceTerminal)
	setCoManager(t, env, "u-co", auth.ComanagerDefaultScopes()...)
	cookie := ownerCookie(env.cfg, "u-co")
	want := proxy.PlatformHeaders{Actor: "u-co", Scopes: "machines:read,sessions:open,terminal:control"}
	for _, tc := range []struct{ method, path string }{
		{http.MethodPut, "/api/settings"},
		{http.MethodPost, "/api/sessions/s-1/control/takeover"},
		{http.MethodGet, "/api/sessions/s-1/write-link"},
		{http.MethodDelete, "/api/sessions/s-1"},
	} {
		before := len(env.proxy.Calls())
		got := machineDo(t, tc.method, dashboard+tc.path, map[string]string{"Cookie": cookie})
		calls := env.proxy.Calls()
		if got.Status != http.StatusOK || len(calls) != before+1 || calls[before].Platform != want {
			t.Fatalf("co-manager %s %s = %d %+v", tc.method, tc.path, got.Status, calls)
		}
	}
	if got := machineGet(t, terminal+"/s/s-1", cookie); got.Body != `{"role":"owner"}` {
		t.Fatalf("co-manager terminal = %s", got.Body)
	}
	if calls := env.proxy.Calls(); calls[len(calls)-1].Platform.Actor != "u-co" {
		t.Fatalf("co-manager terminal actor = %+v", calls[len(calls)-1].Platform)
	}
	if got := rawUpgrade(t, dashboard, "/api/ws", map[string]string{"Cookie": cookie}); !strings.HasPrefix(got, "HTTP/1.1 101") {
		t.Fatalf("co-manager dashboard ws = %q", got)
	}
}

func TestRoleSwitchTakesEffectOnNextRequest(t *testing.T) {
	env := newMachineTestEnvVersion(t, viewerTestVersion)
	dashboard := serveMachine(t, env.online, proxy.SurfaceDashboard)
	cookie := ownerCookie(env.cfg, "u-view")

	setViewer(t, env, "u-view")
	if got := machineDo(t, http.MethodPut, dashboard+"/api/settings", map[string]string{"Cookie": cookie}); got.Status != http.StatusForbidden {
		t.Fatalf("viewer write = %d", got.Status)
	}
	setCoManager(t, env, "u-view", auth.ComanagerDefaultScopes()...)
	if got := machineDo(t, http.MethodPut, dashboard+"/api/settings", map[string]string{"Cookie": cookie}); got.Status != http.StatusOK {
		t.Fatalf("promoted write = %d", got.Status)
	}
	setViewer(t, env, "u-view")
	before := len(env.proxy.Calls())
	if got := machineDo(t, http.MethodPut, dashboard+"/api/settings", map[string]string{"Cookie": cookie}); got.Status != http.StatusForbidden || len(env.proxy.Calls()) != before {
		t.Fatalf("demoted write = %d", got.Status)
	}
	if err := env.repo.SetMachineCoManagers(context.Background(), testMID, "u-alice", nil); err != nil {
		t.Fatal(err)
	}
	if got := machineGet(t, dashboard+"/api/sessions", cookie); got.Status != http.StatusForbidden || got.Body != "无权访问该机器" {
		t.Fatalf("revoked viewer = %d %s", got.Status, got.Body)
	}
}

// Through the real proxy and tunnel: what the daemon receives for a viewer,
// and that the machine's dashboard token never reaches the browser.
func TestViewerThroughRealProxyKeepsDashboardTokenUpstream(t *testing.T) {
	t.Setenv("DASHBOARD_DIRECT", "0")
	env := newMachineTestEnvVersion(t, viewerTestVersion)
	upstream := httptest.NewServer(http.HandlerFunc(echoHeaders))
	t.Cleanup(upstream.Close)
	const secret = "dashboard-secret-token"
	daemon := tunneltest.Start(t, strings.TrimPrefix(upstream.URL, "http://"), tunneltest.Options{
		MachineID: testMID, UnionID: "u-alice", OwnerName: "Alice", BotmuxVersion: viewerTestVersion, DashboardToken: secret,
	})
	dashboardProxy := proxy.NewDashboard(daemon.Registry)
	t.Cleanup(func() { _ = dashboardProxy.Close() })
	env.online.Registry, env.online.Dashboard = daemon.Registry, dashboardProxy
	dashboard := serveMachine(t, env.online, proxy.SurfaceDashboard)
	setViewer(t, env, "u-view")

	got := machineDo(t, http.MethodGet, dashboard+"/api/sessions", withHeaders(forgedPlatformHeaders, map[string]string{
		"Cookie": ownerCookie(env.cfg, "u-view") + "; botmux_dashboard_token=browser-guess",
	}))
	if got.Status != http.StatusOK {
		t.Fatalf("viewer = %d %s", got.Status, got.Body)
	}
	seen := map[string]string{}
	if err := json.Unmarshal([]byte(got.Body), &seen); err != nil {
		t.Fatal(err)
	}
	if seen["x-botmux-role"] != "guest" || seen["x-botmux-actor"] != "u-view" || seen["x-botmux-scopes"] != "machines:read" {
		t.Fatalf("daemon saw %v", seen)
	}
	if seen["cookie"] != "botmux_dashboard_token="+secret {
		t.Fatalf("daemon cookie = %q", seen["cookie"])
	}
	// The echo body is the daemon's view; the browser-facing headers must not
	// carry the token.
	for name, values := range got.Header {
		for _, value := range values {
			if strings.Contains(value, secret) {
				t.Fatalf("browser response header %s leaks the dashboard token", name)
			}
		}
	}
	for _, cookie := range got.SetCookies {
		if strings.Contains(cookie, secret) {
			t.Fatal("browser Set-Cookie leaks the dashboard token")
		}
	}
}
