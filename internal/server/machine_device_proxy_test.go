package server

import (
	"bufio"
	"context"
	"io"
	"net/http"
	"net/url"
	"slices"
	"sort"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/botmux-ai/botmux-platform/internal/auth"
	"github.com/botmux-ai/botmux-platform/internal/proxy"
	"github.com/botmux-ai/botmux-platform/internal/store"
)

// Port of the machine-subdomain parts of test/server-device-proxy.test.ts.
// The apex signer (/api/machines/:id/open) is not part of this handler, so
// tickets are minted directly with the same claims it would sign.

func TestDeviceTicketRedeemAndPerRequestCheck(t *testing.T) {
	env := newMachineTestEnv(t)
	offline := serveMachine(t, env.offline, proxy.SurfaceDashboard)
	ticket := auth.IssueDeviceProxyTicket(env.cfg, deviceClaims(auth.DeviceProxyPurposeDashboardMobile, store.MobileDeviceScopes()))

	redeemed := machineGet(t, offline+"/__open?ticket="+url.QueryEscape(ticket))
	if redeemed.Status != http.StatusFound || redeemed.Header.Get("Location") != "/" {
		t.Fatalf("redeem = %d %v", redeemed.Status, redeemed.Header)
	}
	if redeemed.Header.Get("Content-Type") != "" || redeemed.Body != "" {
		t.Fatalf("redirect must carry no body: %v %q", redeemed.Header, redeemed.Body)
	}
	token := cookieValue(redeemed.SetCookies, "botmux_device_proxy_session")
	if token == "" {
		t.Fatalf("device cookie not set: %q", redeemed.SetCookies)
	}
	// The device session must not ride an ambient owner cookie.
	if !slices.Contains(redeemed.SetCookies, auth.ClearProxySessionCookieHeader(env.cfg)) {
		t.Fatalf("owner cookie not cleared: %q", redeemed.SetCookies)
	}
	if !slices.ContainsFunc(redeemed.SetCookies, func(c string) bool {
		return strings.HasPrefix(c, "botmux_device_proxy_session=") && strings.Contains(c, "; Path=/;") && strings.Contains(c, "Max-Age=")
	}) {
		t.Fatalf("device cookie attributes: %q", redeemed.SetCookies)
	}

	ok := machineGet(t, offline+"/api/sessions", "botmux_device_proxy_session="+token)
	if ok.Status != http.StatusServiceUnavailable || !strings.Contains(ok.Body, "正在重连") {
		t.Fatalf("authorized offline request = %d %q", ok.Status, ok.Body)
	}
	if got := machineGet(t, offline+"/api/sessions"); got.Status != http.StatusUnauthorized {
		t.Fatalf("no cookie = %d", got.Status)
	}
	env.revokeDevice()
	revoked := machineGet(t, offline+"/api/sessions", "botmux_device_proxy_session="+token)
	if revoked.Status != http.StatusUnauthorized || revoked.Body != "设备会话无效或已过期" {
		t.Fatalf("revoked = %d %q", revoked.Status, revoked.Body)
	}
}

func TestMobileShellRejectsNonAllowlistedPaths(t *testing.T) {
	env := newMachineTestEnv(t)
	dashboard := serveMachine(t, env.offline, proxy.SurfaceDashboard)
	terminal := serveMachine(t, env.online, proxy.SurfaceTerminal)
	cookie := dashboardDeviceCookie(env.cfg, deviceClaims(auth.DeviceProxyPurposeDashboardMobile, store.MobileDeviceScopes()))

	for _, path := range []string{
		"/workflow", "/api/workflow", "/api/v3/workflows", "/api/trigger",
		"/api/sessions/session-1/write-link", "/webhook/secret", "/api/anything",
	} {
		if got := machineGet(t, dashboard+path, cookie); got.Status != http.StatusForbidden {
			t.Fatalf("%s = %d %s", path, got.Status, got.Body)
		}
	}
	update := machineDo(t, http.MethodPost, dashboard+"/api/update/run", map[string]string{"Cookie": cookie})
	if update.Status != http.StatusForbidden || update.Body != `{"error":"path_not_allowed","clientShell":"mobile"}` ||
		update.Header.Get("Cache-Control") != "no-store" || update.Header.Get("Content-Type") != "application/json; charset=utf-8" {
		t.Fatalf("/api/update/run = %d %v %s", update.Status, update.Header, update.Body)
	}
	// A dashboard-purpose cookie never enters the terminal.
	if got := machineGet(t, terminal+"/s/session-1", cookie); got.Status != http.StatusForbidden || got.Body != `{"error":"device_purpose_mismatch","clientShell":"mobile"}` {
		t.Fatalf("terminal with dashboard cookie = %d %s", got.Status, got.Body)
	}
	if len(env.proxy.Calls()) != 0 {
		t.Fatalf("rejected requests reached the proxy: %+v", env.proxy.Calls())
	}
}

func TestDeviceCookiePresenceBlocksSSOOwnerFallback(t *testing.T) {
	env := newMachineTestEnv(t)
	dashboard := serveMachine(t, env.online, proxy.SurfaceDashboard)
	terminal := serveMachine(t, env.online, proxy.SurfaceTerminal)
	device := dashboardDeviceCookie(env.cfg, deviceClaims(auth.DeviceProxyPurposeDashboardMobile, store.MobileDeviceScopes()))
	owner := ownerCookie(env.cfg, "u-alice")

	if got := machineGet(t, dashboard+"/api/anything", device, owner); got.Status != http.StatusForbidden {
		t.Fatalf("restricted + owner = %d", got.Status)
	}
	expiredClaims := deviceClaims(auth.DeviceProxyPurposeDashboardMobile, store.MobileDeviceScopes())
	expiredClaims.AuthExp = time.Now().Unix() - 1
	expired := machineGet(t, dashboard+"/api/sessions", dashboardDeviceCookie(env.cfg, expiredClaims), owner)
	if expired.Status != http.StatusUnauthorized || expired.Body != `{"error":"invalid_device_session","clientShell":"mobile"}` {
		t.Fatalf("expired device + owner = %d %s", expired.Status, expired.Body)
	}
	if got := machineGet(t, terminal+"/s/session-1", device, owner); got.Status != http.StatusForbidden {
		t.Fatalf("terminal with dashboard cookie + owner = %d", got.Status)
	}
	if len(env.proxy.Calls()) != 0 {
		t.Fatal("owner fallback reached the proxy")
	}
}

func TestPurposeCookiesConflictAndTerminalDeviceAuthority(t *testing.T) {
	env := newMachineTestEnv(t)
	terminal := serveMachine(t, env.online, proxy.SurfaceTerminal)
	dashboardCookie := dashboardDeviceCookie(env.cfg, deviceClaims(auth.DeviceProxyPurposeDashboardMobile, store.MobileDeviceScopes()))
	terminalCookie := terminalDeviceCookie(env.cfg, deviceClaims(auth.DeviceProxyPurposeTerminal, store.MobileDeviceScopes()))
	owner := ownerCookie(env.cfg, "u-alice")

	conflicting := machineGet(t, terminal+"/s/session-1", dashboardCookie, terminalCookie, owner)
	if conflicting.Status != http.StatusForbidden || conflicting.Body != `{"error":"conflicting_device_purposes"}` {
		t.Fatalf("conflict = %d %s", conflicting.Status, conflicting.Body)
	}
	granted := machineGet(t, terminal+"/s/session-1", terminalCookie, owner)
	if granted.Status != http.StatusOK || granted.Body != `{"role":"owner"}` {
		t.Fatalf("terminal device = %d %s", granted.Status, granted.Body)
	}
	calls := env.proxy.Calls()
	if len(calls) != 1 || calls[0].Platform.Actor != "u-alice" || calls[0].Platform.Scopes != "" ||
		calls[0].Platform.LoginURL != "http://localhost/open/"+testMID+"?next=%2Fs%2Fsession-1" {
		t.Fatalf("platform = %+v", calls)
	}
}

func TestTerminalDeviceCookieRejections(t *testing.T) {
	env := newMachineTestEnv(t)
	terminal := serveMachine(t, env.online, proxy.SurfaceTerminal)

	noControl := terminalDeviceCookie(env.cfg, deviceClaims(auth.DeviceProxyPurposeTerminal, []string{store.DeviceScopeMachinesRead}))
	if got := machineGet(t, terminal+"/s/x", noControl); got.Status != http.StatusForbidden || got.Body != "设备无终端控制权限" {
		t.Fatalf("no terminal:control = %d %q", got.Status, got.Body)
	}
	foreign := deviceClaims(auth.DeviceProxyPurposeTerminal, store.MobileDeviceScopes())
	foreign.UnionID = "u-bob"
	if got := machineGet(t, terminal+"/s/x", terminalDeviceCookie(env.cfg, foreign)); got.Status != http.StatusForbidden {
		t.Fatalf("foreign device = %d", got.Status)
	}
	if got := machineGet(t, terminal+"/s/x", "botmux_device_terminal_session=garbage"); got.Status != http.StatusUnauthorized || got.Body != "设备终端会话无效或已过期" {
		t.Fatalf("garbage = %d %q", got.Status, got.Body)
	}
	env.devices.set(nil, store.ErrUnavailable)
	env.states.Invalidate("dev-1")
	valid := terminalDeviceCookie(env.cfg, deviceClaims(auth.DeviceProxyPurposeTerminal, store.MobileDeviceScopes()))
	if got := machineGet(t, terminal+"/s/x", valid); got.Status != http.StatusServiceUnavailable || got.Body != "设备状态暂不可用，请稍后重试" {
		t.Fatalf("unavailable = %d %q", got.Status, got.Body)
	}
	if len(env.proxy.Calls()) != 0 {
		t.Fatal("rejected terminal requests reached the proxy")
	}
}

func TestTerminalOriginGuestAndOwner(t *testing.T) {
	env := newMachineTestEnv(t)
	terminal := serveMachine(t, env.online, proxy.SurfaceTerminal)
	if got := machineGet(t, terminal+"/s/session-guest"); got.Status != http.StatusOK || got.Body != `{"role":"guest"}` {
		t.Fatalf("guest = %d %s", got.Status, got.Body)
	}
	if got := machineGet(t, terminal+"/s/session-owner", ownerCookie(env.cfg, "u-alice")); got.Status != http.StatusOK || got.Body != `{"role":"owner"}` {
		t.Fatalf("owner = %d %s", got.Status, got.Body)
	}
	calls := env.proxy.Calls()
	if calls[0].Platform.Actor != "" || calls[1].Platform.Actor != "u-alice" {
		t.Fatalf("actors = %q / %q", calls[0].Platform.Actor, calls[1].Platform.Actor)
	}
	// A cookie for another machine is anonymous here.
	other := auth.ProxySessionRequestCookie(env.cfg, auth.ProxyIdentity{UnionID: "u-alice", MachineID: "deadbeefdeadbeef"})
	if got := machineGet(t, terminal+"/s/x", other); got.Body != `{"role":"guest"}` {
		t.Fatalf("other machine cookie = %s", got.Body)
	}
}

func TestTerminalOriginAnonymousWebSocketIsGuest(t *testing.T) {
	env := newMachineTestEnv(t)
	terminal := serveMachine(t, env.online, proxy.SurfaceTerminal)
	raw := rawUpgrade(t, terminal, "/s/session-guest", nil)
	if !strings.HasPrefix(raw, "HTTP/1.1 101") {
		t.Fatalf("upgrade = %q", raw)
	}
	calls := env.proxy.Calls()
	if len(calls) != 1 || !calls[0].WS || calls[0].Platform != (proxy.PlatformHeaders{Role: "guest"}) {
		t.Fatalf("ws platform = %+v", calls)
	}
}

func TestSurfaceBindingAndCrossSurfaceTickets(t *testing.T) {
	env := newMachineTestEnv(t)
	dashboard := serveMachine(t, env.online, proxy.SurfaceDashboard)
	terminal := serveMachine(t, env.online, proxy.SurfaceTerminal)

	compat := machineGet(t, dashboard+"/s/session-1?mode=readonly&label=a%20b")
	if compat.Status != http.StatusFound || compat.Header.Get("Location") != "http://t-"+testMID+".localhost/s/session-1?mode=readonly&label=a%20b" {
		t.Fatalf("m- /s compat = %d %q", compat.Status, compat.Header.Get("Location"))
	}
	// A stale Authorization header must not block the compatibility redirect.
	stale := machineDo(t, http.MethodGet, dashboard+"/s", map[string]string{"Authorization": "Bearer stale"})
	if stale.Status != http.StatusFound || stale.Header.Get("Location") != "http://t-"+testMID+".localhost/s" {
		t.Fatalf("compat with bearer = %d %q", stale.Status, stale.Header.Get("Location"))
	}
	migrated := parseLocation(t, compat.Header.Get("Location"))
	if got := machineGet(t, terminal+migrated.RequestURI()); got.Status != http.StatusOK || got.Body != `{"role":"guest"}` {
		t.Fatalf("migrated guest = %d %s", got.Status, got.Body)
	}

	sso := auth.IssueProxyTicket(env.cfg, auth.ProxyIdentity{UnionID: "u-alice", MachineID: testMID})
	if got := machineGet(t, terminal+"/__open?ticket="+url.QueryEscape(sso)); got.Status != http.StatusForbidden {
		t.Fatalf("dashboard SSO ticket on terminal = %d", got.Status)
	}
	sso = auth.IssueProxyTicket(env.cfg, auth.ProxyIdentity{UnionID: "u-alice", MachineID: testMID})
	if got := machineGet(t, dashboard+"/__open?ticket="+url.QueryEscape(sso)+"&next="+url.QueryEscape("/s/session-1")); got.Status != http.StatusForbidden {
		t.Fatalf("terminal-landing SSO ticket on dashboard = %d", got.Status)
	}
	dashboardTicket := auth.IssueDeviceProxyTicket(env.cfg, deviceClaims(auth.DeviceProxyPurposeDashboardMobile, store.MobileDeviceScopes()))
	if got := machineGet(t, terminal+"/__open?ticket="+url.QueryEscape(dashboardTicket)+"&next="+url.QueryEscape("/s/session-1")); got.Status != http.StatusForbidden {
		t.Fatalf("dashboard device ticket on terminal = %d", got.Status)
	}
	terminalTicket := auth.IssueDeviceProxyTicket(env.cfg, deviceClaims(auth.DeviceProxyPurposeTerminal, store.MobileDeviceScopes()))
	if got := machineGet(t, terminal+"/__open?ticket="+url.QueryEscape(terminalTicket)); got.Status != http.StatusForbidden || got.Body != "ticket 无效或已过期，请回平台重新打开" {
		t.Fatalf("terminal device ticket, dashboard landing = %d %q", got.Status, got.Body)
	}
}

func TestOpenRejections(t *testing.T) {
	env := newMachineTestEnv(t)
	dashboard := serveMachine(t, env.offline, proxy.SurfaceDashboard)
	sso := auth.IssueProxyTicket(env.cfg, auth.ProxyIdentity{UnionID: "u-alice", MachineID: testMID})
	ok := machineGet(t, dashboard+"/__open?ticket="+url.QueryEscape(sso))
	if ok.Status != http.StatusFound || cookieValue(ok.SetCookies, auth.ProxyCookieName) == "" {
		t.Fatalf("sso = %d %q", ok.Status, ok.SetCookies)
	}
	garbage := machineGet(t, dashboard+"/__open?ticket=garbage")
	if garbage.Status != http.StatusForbidden || garbage.Body != "ticket 无效或已过期，请回平台重新打开" || garbage.Header.Get("Content-Type") != "text/plain; charset=utf-8" {
		t.Fatalf("garbage = %d %v %q", garbage.Status, garbage.Header, garbage.Body)
	}
	ticket := auth.IssueDeviceProxyTicket(env.cfg, deviceClaims(auth.DeviceProxyPurposeDashboardMobile, store.MobileDeviceScopes()))
	env.revokeDevice()
	if got := machineGet(t, dashboard+"/__open?ticket="+url.QueryEscape(ticket)); got.Status != http.StatusForbidden {
		t.Fatalf("revoked device ticket = %d", got.Status)
	}
	// Unavailable device authority fails closed with 503, ticket not consumed.
	env.devices.set(nil, store.ErrUnavailable)
	env.states.Invalidate("dev-1")
	ticket = auth.IssueDeviceProxyTicket(env.cfg, deviceClaims(auth.DeviceProxyPurposeDashboardMobile, store.MobileDeviceScopes()))
	if got := machineGet(t, dashboard+"/__open?ticket="+url.QueryEscape(ticket)); got.Status != http.StatusServiceUnavailable || got.Body != "设备状态暂不可用，请稍后重试" {
		t.Fatalf("unavailable device = %d %q", got.Status, got.Body)
	}
	env.devices.set(activeDevice(1), nil)
	env.states.Invalidate("dev-1")
	if got := machineGet(t, dashboard+"/__open?ticket="+url.QueryEscape(ticket)); got.Status != http.StatusFound {
		t.Fatalf("ticket was consumed by the failed attempt: %d", got.Status)
	}
	// next is sanitized; an open redirect falls back to "/".
	sso = auth.IssueProxyTicket(env.cfg, auth.ProxyIdentity{UnionID: "u-alice", MachineID: testMID})
	if got := machineGet(t, dashboard+"/__open?ticket="+url.QueryEscape(sso)+"&next="+url.QueryEscape("//evil.example/x")); got.Header.Get("Location") != "/" {
		t.Fatalf("unsafe next = %q", got.Header.Get("Location"))
	}
}

func TestColdNavigationBouncesThroughPlatformSSO(t *testing.T) {
	env := newMachineTestEnv(t)
	offline := serveMachine(t, env.offline, proxy.SurfaceDashboard)
	navigate := map[string]string{"Sec-Fetch-Mode": "navigate", "Accept": "text/html"}

	nav := machineDo(t, http.MethodGet, offline+"/foo/bar?x=1", navigate)
	if nav.Status != http.StatusFound || nav.Header.Get("Cache-Control") != "no-store" || len(nav.SetCookies) != 0 {
		t.Fatalf("nav = %d %v", nav.Status, nav.Header)
	}
	location := parseLocation(t, nav.Header.Get("Location"))
	if location.Scheme+"://"+location.Host != "http://localhost" || location.Path != "/open/"+testMID ||
		location.Query().Get("next") != "/foo/bar?x=1&__bmx_sso=1" {
		t.Fatalf("bounce location = %q", nav.Header.Get("Location"))
	}
	if nav.Header.Get("Location") != "http://localhost/open/"+testMID+"?next=%2Ffoo%2Fbar%3Fx%3D1%26__bmx_sso%3D1" {
		t.Fatalf("bounce bytes = %q", nav.Header.Get("Location"))
	}

	legacy := machineDo(t, http.MethodGet, offline+"/", map[string]string{"Accept": "text/html,application/xhtml+xml"})
	if legacy.Status != http.StatusFound || parseLocation(t, legacy.Header.Get("Location")).Path != "/open/"+testMID {
		t.Fatalf("legacy webview = %d %q", legacy.Status, legacy.Header.Get("Location"))
	}
	xhr := machineDo(t, http.MethodGet, offline+"/api/sessions", map[string]string{"Sec-Fetch-Mode": "cors", "Accept": "application/json"})
	if xhr.Status != http.StatusUnauthorized {
		t.Fatalf("xhr = %d", xhr.Status)
	}
	post := machineDo(t, http.MethodPost, offline+"/form", navigate)
	if post.Status != http.StatusUnauthorized {
		t.Fatalf("POST navigation = %d", post.Status)
	}
	reentry := machineDo(t, http.MethodGet, offline+"/foo?__bmx_sso=1", navigate)
	want := `<html><body style="font-family:sans-serif;padding:2rem">未授权访问该机器。请从 <a href="http://localhost">botmux 平台</a> 打开。</body></html>`
	if reentry.Status != http.StatusUnauthorized || reentry.Body != want ||
		reentry.Header.Get("Content-Type") != "text/html; charset=utf-8" || reentry.Header.Get("Cache-Control") != "no-store" {
		t.Fatalf("reentry = %d %v %q", reentry.Status, reentry.Header, reentry.Body)
	}

	owner := ownerCookie(env.cfg, "u-alice")
	landed := machineDo(t, http.MethodGet, offline+"/foo/bar?x=1&__bmx_sso=1", map[string]string{"Sec-Fetch-Mode": "navigate", "Accept": "text/html", "Cookie": owner})
	if landed.Status != http.StatusFound || landed.Header.Get("Location") != "/foo/bar?x=1" || landed.Header.Get("Cache-Control") != "no-store" {
		t.Fatalf("landed = %d %v", landed.Status, landed.Header)
	}
	proxied := machineDo(t, http.MethodGet, offline+"/foo/bar?x=1", map[string]string{"Sec-Fetch-Mode": "navigate", "Accept": "text/html", "Cookie": owner})
	if proxied.Status != http.StatusServiceUnavailable {
		t.Fatalf("authorized offline = %d", proxied.Status)
	}
}

func TestSSOOpenSetsOwnerCookieAndClearsDeviceCookies(t *testing.T) {
	env := newMachineTestEnv(t)
	dashboard := serveMachine(t, env.offline, proxy.SurfaceDashboard)
	ticket := auth.IssueProxyTicket(env.cfg, auth.ProxyIdentity{UnionID: "u-alice", MachineID: testMID})
	response := machineGet(t, dashboard+"/__open?ticket="+url.QueryEscape(ticket))
	if response.Status != http.StatusFound || response.Header.Get("Location") != "/" {
		t.Fatalf("open = %d %v", response.Status, response.Header)
	}
	has := func(prefix, path string, cleared bool) bool {
		return slices.ContainsFunc(response.SetCookies, func(cookie string) bool {
			return strings.HasPrefix(cookie, prefix) && strings.Contains(cookie+";", "; Path="+path+";") &&
				strings.Contains(cookie+";", "; Max-Age=0;") == cleared
		})
	}
	if !has("botmux_proxy_session=", "/", false) || !has("botmux_device_proxy_session=;", "/", true) || !has("botmux_device_terminal_session=;", "/s", true) {
		t.Fatalf("set-cookie = %q", response.SetCookies)
	}
}

type countingTicketStore struct {
	store.DesktopSessionRepository
	err error
}

func (c countingTicketStore) ConsumeProxyTicket(ctx context.Context, ticketID string, expiresAtMS int64) error {
	if c.err != nil {
		return c.err
	}
	return c.DesktopSessionRepository.ConsumeProxyTicket(ctx, ticketID, expiresAtMS)
}

func TestProxyTicketsAreSingleUse(t *testing.T) {
	env := newMachineTestEnv(t)
	dashboard := serveMachine(t, env.offline, proxy.SurfaceDashboard)
	ticket := auth.IssueDeviceProxyTicket(env.cfg, deviceClaims(auth.DeviceProxyPurposeDashboardMobile, store.MobileDeviceScopes()))
	statuses := make([]int, 2)
	var wg sync.WaitGroup
	for i := range statuses {
		wg.Add(1)
		go func() {
			defer wg.Done()
			statuses[i] = machineGet(t, dashboard+"/__open?ticket="+url.QueryEscape(ticket)).Status
		}()
	}
	wg.Wait()
	sort.Ints(statuses)
	if statuses[0] != http.StatusFound || statuses[1] != http.StatusForbidden {
		t.Fatalf("concurrent replay = %v", statuses)
	}

	sso := auth.IssueProxyTicket(env.cfg, auth.ProxyIdentity{UnionID: "u-alice", MachineID: testMID})
	if got := machineGet(t, dashboard+"/__open?ticket="+url.QueryEscape(sso)); got.Status != http.StatusFound {
		t.Fatalf("first SSO = %d", got.Status)
	}
	replay := machineGet(t, dashboard+"/__open?ticket="+url.QueryEscape(sso))
	if replay.Status != http.StatusForbidden || replay.Body != "ticket 已使用或已过期" {
		t.Fatalf("SSO replay = %d %q", replay.Status, replay.Body)
	}

	// The fence fails closed when the store cannot answer.
	env.offline.DesktopSessions = countingTicketStore{DesktopSessionRepository: env.repo, err: store.ErrUnavailable}
	sso = auth.IssueProxyTicket(env.cfg, auth.ProxyIdentity{UnionID: "u-alice", MachineID: testMID})
	unavailable := machineGet(t, dashboard+"/__open?ticket="+url.QueryEscape(sso))
	if unavailable.Status != http.StatusServiceUnavailable || unavailable.Body != "票据状态暂不可用，请稍后重试" || len(unavailable.SetCookies) != 0 {
		t.Fatalf("unavailable fence = %d %q %q", unavailable.Status, unavailable.Body, unavailable.SetCookies)
	}
}

func TestDeviceSessionAllOrNothingClaimsAndScopeGate(t *testing.T) {
	env := newMachineTestEnv(t)
	dashboard := serveMachine(t, env.offline, proxy.SurfaceDashboard)
	now := time.Now().Unix()
	base := map[string]any{
		"kind": "device-proxy-session", "unionId": "u-alice", "machineId": testMID, "deviceId": "dev-1",
		"credentialVersion": 1, "effectiveScopes": store.MobileDeviceScopes(), "sid": "sid-1",
		"sessionMaxExp": now + 3600, "authExp": now + 600, "purpose": "dashboard-mobile", "exp": now + 600,
	}
	forge := func(edit func(map[string]any)) string {
		payload := map[string]any{}
		for k, v := range base {
			payload[k] = v
		}
		edit(payload)
		token, err := auth.IssueToken(payload, env.cfg.SigningSecret)
		if err != nil {
			t.Fatal(err)
		}
		return "botmux_device_proxy_session=" + token
	}
	for name, edit := range map[string]func(map[string]any){
		"missing sid":             func(p map[string]any) { delete(p, "sid") },
		"authExp past maxExp":     func(p map[string]any) { p["authExp"] = now + 7200 },
		"missing purpose":         func(p map[string]any) { delete(p, "purpose") },
		"unknown purpose":         func(p map[string]any) { p["purpose"] = "unrestricted" },
		"wrong machine binding":   func(p map[string]any) { p["machineId"] = "deadbeefdeadbeef" },
		"stale credentialVersion": func(p map[string]any) { p["credentialVersion"] = 2 },
	} {
		if got := machineGet(t, dashboard+"/api/sessions", forge(edit)); got.Status != http.StatusUnauthorized {
			t.Fatalf("%s = %d %s", name, got.Status, got.Body)
		}
	}
	narrowed := dashboardDeviceCookie(env.cfg, deviceClaims(auth.DeviceProxyPurposeDashboardMobile, []string{store.DeviceScopeMachinesRead}))
	if got := machineGet(t, dashboard+"/api/sessions", narrowed); got.Status != http.StatusForbidden || got.Body != "设备无访问该机器面板的权限" {
		t.Fatalf("narrowed = %d %q", got.Status, got.Body)
	}
}

func TestTerminalPurposeCookieIsPathScopedAndNotADashboardSession(t *testing.T) {
	env := newMachineTestEnv(t)
	terminal := serveMachine(t, env.offline, proxy.SurfaceTerminal)
	dashboard := serveMachine(t, env.offline, proxy.SurfaceDashboard)
	ticket := auth.IssueDeviceProxyTicket(env.cfg, deviceClaims(auth.DeviceProxyPurposeTerminal, store.MobileDeviceScopes()))
	response := machineGet(t, terminal+"/__open?ticket="+url.QueryEscape(ticket)+"&next="+url.QueryEscape("/s/session-1"))
	if response.Status != http.StatusFound || response.Header.Get("Location") != "/s/session-1" {
		t.Fatalf("redeem = %d %v", response.Status, response.Header)
	}
	if !slices.ContainsFunc(response.SetCookies, func(c string) bool {
		return strings.HasPrefix(c, "botmux_device_terminal_session=") && strings.Contains(c, "; Path=/s;")
	}) || cookieValue(response.SetCookies, "botmux_device_proxy_session") != "" {
		t.Fatalf("set-cookie = %q", response.SetCookies)
	}
	token := cookieValue(response.SetCookies, "botmux_device_terminal_session")
	got := machineGet(t, dashboard+"/api/sessions", "botmux_device_terminal_session="+token)
	if got.Status != http.StatusForbidden || got.Body != `{"error":"device_purpose_mismatch"}` {
		t.Fatalf("terminal cookie on dashboard = %d %s", got.Status, got.Body)
	}
}

// openSSE opens the device-authenticated /events stream through the fake
// SSE proxy and returns a channel that closes when the stream ends.
func openSSE(t *testing.T, base, cookie string) (*http.Response, <-chan struct{}) {
	t.Helper()
	request, _ := http.NewRequest(http.MethodGet, base+"/events", nil)
	request.Header.Set("Cookie", cookie)
	client := &http.Client{Transport: &http.Transport{DisableKeepAlives: true}}
	response, err := client.Do(request)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = response.Body.Close() })
	reader := bufio.NewReader(response.Body)
	if line, err := reader.ReadString('\n'); err != nil || line != "data: hello\n" {
		t.Fatalf("first frame = %q, %v", line, err)
	}
	ended := make(chan struct{})
	go func() {
		defer close(ended)
		for {
			if _, err := reader.ReadByte(); err != nil {
				return
			}
		}
	}()
	return response, ended
}

func TestDeviceSSEStreamIsCutOnRevocation(t *testing.T) {
	env := newMachineTestEnv(t)
	env.proxy.sse = true
	dashboard := serveMachine(t, env.online, proxy.SurfaceDashboard)
	response, ended := openSSE(t, dashboard, dashboardDeviceCookie(env.cfg, deviceClaims(auth.DeviceProxyPurposeDashboardMobile, store.MobileDeviceScopes())))
	if response.Header.Get("Content-Type") != "text/event-stream" {
		t.Fatalf("content-type = %q", response.Header.Get("Content-Type"))
	}
	if got := env.registeredStreams(); got != 1 {
		t.Fatalf("registered streams = %d", got)
	}
	if closed := env.watcher.CloseDevice("dev-1", "owner_revoked"); closed != 1 {
		t.Fatalf("CloseDevice = %d", closed)
	}
	select {
	case <-ended:
	case <-time.After(2 * time.Second):
		t.Fatal("revoked SSE stream kept running")
	}
	eventuallyTrue(t, func() bool { return env.registeredStreams() == 0 })
}

func TestDeviceSSEStreamEndsAtAuthExpLease(t *testing.T) {
	env := newMachineTestEnv(t)
	env.proxy.sse = true
	terminal := serveMachine(t, env.online, proxy.SurfaceTerminal)
	claims := deviceClaims(auth.DeviceProxyPurposeTerminal, store.MobileDeviceScopes())
	claims.AuthExp = time.Now().Unix() + 2
	request, _ := http.NewRequest(http.MethodGet, terminal+"/s/events", nil)
	request.Header.Set("Cookie", terminalDeviceCookie(env.cfg, claims))
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
		// Aborted, not a clean end.
		if err == nil {
			t.Fatal("lease expiry ended the stream cleanly")
		}
	case <-time.After(4 * time.Second):
		t.Fatal("stream outlived authExp")
	}
}

func TestDeviceStreamEpochFenceRefusesRegistration(t *testing.T) {
	env := newMachineTestEnv(t)
	dashboard := serveMachine(t, env.online, proxy.SurfaceDashboard)
	// A revocation lands between the epoch capture and the registration: the
	// authority read itself bumps the epoch (Invalidate) and still answers
	// active, exactly the window the fence closes.
	var once sync.Once
	env.devices = nil
	reader := &epochBumpingReader{doc: *activeDevice(1)}
	states := auth.NewDeviceStateCache(reader)
	reader.onRead = func() { once.Do(func() { states.Invalidate("dev-1") }) }
	watcher := NewDeviceSocketWatcher(states)
	watcher.interval = time.Hour
	env.online.DeviceStates, env.online.DeviceSockets = states, watcher

	request, _ := http.NewRequest(http.MethodGet, dashboard+"/api/sessions", nil)
	request.Header.Set("Cookie", dashboardDeviceCookie(env.cfg, deviceClaims(auth.DeviceProxyPurposeDashboardMobile, store.MobileDeviceScopes())))
	response, err := http.DefaultTransport.RoundTrip(request)
	if err == nil {
		response.Body.Close()
		t.Fatalf("fenced request answered %d", response.StatusCode)
	}
	if len(env.proxy.Calls()) != 0 || len(watcher.snapshot("dev-1")) != 0 {
		t.Fatal("fenced stream reached the proxy or stayed registered")
	}
}

type epochBumpingReader struct {
	doc    store.DeviceDoc
	onRead func()
}

func (r *epochBumpingReader) GetDevice(context.Context, string) (store.DeviceDoc, error) {
	if r.onRead != nil {
		r.onRead()
	}
	return r.doc, nil
}

func eventuallyTrue(t *testing.T, condition func() bool) {
	t.Helper()
	deadline := time.Now().Add(3 * time.Second)
	for !condition() {
		if time.Now().After(deadline) {
			t.Fatal("condition not reached")
		}
		time.Sleep(5 * time.Millisecond)
	}
}
