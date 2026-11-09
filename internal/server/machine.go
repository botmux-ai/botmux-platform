package server

import (
	"context"
	"errors"
	"log/slog"
	"net/http"
	"net/url"
	"regexp"
	"slices"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/botmux-ai/botmux-platform/internal/auth"
	"github.com/botmux-ai/botmux-platform/internal/config"
	"github.com/botmux-ai/botmux-platform/internal/proxy"
	"github.com/botmux-ai/botmux-platform/internal/store"
	"github.com/botmux-ai/botmux-platform/internal/tunnel"
	"github.com/gorilla/websocket"
)

// Port of src/server/machine.ts: the m-<id> (dashboard) and t-<id> (device
// terminal) machine subdomains. Ticket bootstrap, proxy/device/desktop
// authentication, co-manager access and the reverse proxy into the tunnel.

// MachineDashboardProxy is the reverse proxy into a machine dashboard
// (*proxy.Dashboard). Platform authority headers travel as a separate value,
// never on the request headers, so client-supplied x-botmux-* headers can be
// dropped unconditionally without also dropping the platform's decision.
type MachineDashboardProxy interface {
	ProxyHTTP(w http.ResponseWriter, r *http.Request, machine tunnel.MachineConn, platform proxy.PlatformHeaders)
	ProxyWebSocket(w http.ResponseWriter, r *http.Request, machine tunnel.MachineConn, platform proxy.PlatformHeaders) error
}

// MachineRouteResolver reads which pod holds a machine tunnel. Every machine
// subdomain read goes through the short positive cache
// (store.MachineRouteCacheTTL): a first paint fans out into dozens of resource
// requests that would otherwise each hit Redis.
type MachineRouteResolver interface {
	GetMachineRouteCached(ctx context.Context, machineID string, opts store.RouteCacheOptions) (string, error)
}

// MachineHandler serves machine subdomain requests. The authority fields are
// wired from the Apex instances in wire_machine.go (same device state cache
// epochs, same device socket watcher, same ticket fence).
type MachineHandler struct {
	Config       config.Config
	Registry     *tunnel.Registry
	Dashboard    MachineDashboardProxy
	Routes       MachineRouteResolver
	ForwardHTTP  func(string, http.ResponseWriter, *http.Request) error
	ForwardRawWS func(string, http.ResponseWriter, *http.Request) error

	// Machines is the authoritative MachineDoc read (owner, co-managers,
	// RETIRED tombstone).
	Machines auth.MachineLookup
	// DesktopSessions provides the single-use proxy ticket fence and the
	// Desktop session family revocation status.
	DesktopSessions store.DesktopSessionRepository
	// DeviceStates is the device authority (5s positive cache + epochs).
	DeviceStates *auth.DeviceStateCache
	// DeviceSockets registers device-authenticated streams for revocation.
	DeviceSockets *DeviceSocketWatcher
	// Now overrides the clock (tests).
	Now func() time.Time
}

const ssoBounceParam = "__bmx_sso"

func (h *MachineHandler) now() time.Time {
	if h.Now != nil {
		return h.Now()
	}
	return time.Now()
}

// ServeMachine serves a request whose Host matched a machine subdomain; the
// surface (dashboard m- / terminal t-) is derived from the same Host.
func (h *MachineHandler) ServeMachine(w http.ResponseWriter, r *http.Request, machineID string) {
	surface := proxy.SurfaceDashboard
	if route, ok := proxy.MatchMachineSubdomainRoute(h.Config, r.Host); ok && route.MachineID == machineID {
		surface = route.Surface
	}
	h.ServeMachineSurface(w, r, machineID, surface)
}

// ServeMachineSurface is handleMachineHttp / handleMachineWs with an explicit
// surface, for callers that rewrite a request into machine subdomain form
// (the OpenAPI WebSocket proxy).
func (h *MachineHandler) ServeMachineSurface(w http.ResponseWriter, r *http.Request, machineID string, surface proxy.MachineSurface) {
	if websocket.IsWebSocketUpgrade(r) {
		h.serveWebSocket(w, r, machineID, surface)
		return
	}
	h.serveHTTP(w, r, machineID, surface)
}

type machineErrorBody struct {
	Error string `json:"error"`
}

type machineShellErrorBody struct {
	Error       string `json:"error"`
	ClientShell string `json:"clientShell"`
}

// requestPathQuery is `new URL(req.url, base)` for the raw request target:
// the WHATWG pathname and the raw query (proxy.RequestTarget explains why
// not r.URL).
func requestPathQuery(r *http.Request) (string, string) {
	path, query := proxy.SplitRequestTarget(r)
	return whatwgPathname(path), query
}

func searchOf(query string) string {
	if query == "" {
		return ""
	}
	return "?" + query
}

func isSharedTerminal(pathname string) bool {
	return pathname == "/s" || strings.HasPrefix(pathname, "/s/")
}

func (h *MachineHandler) serveHTTP(w http.ResponseWriter, r *http.Request, machineID string, surface proxy.MachineSurface) {
	// Strip every client-supplied platform/daemon header before branching:
	// per-branch stripping once missed /webhook/*, the one path that is fully
	// externally controlled. Forgetting to inject only disables a feature;
	// forgetting to strip is privilege escalation.
	proxy.StripReservedBotmuxHeaders(r.Header)
	pathname, rawQuery := requestPathQuery(r)
	search := searchOf(rawQuery)
	isTerminalPath := isSharedTerminal(pathname)
	ctx := r.Context()

	// Legacy m-<id>/s/* share links move to the isolated terminal origin and
	// keep anonymous guest semantics. Runs before Bearer parsing so a stale
	// Authorization header cannot block the compatibility redirect.
	if surface == proxy.SurfaceDashboard && isTerminalPath {
		next, ok := auth.SafeProxyNextPath(pathname + search)
		if !ok {
			next = "/s"
		}
		machineRedirect(w, proxy.MachineBaseURL(h.Config, machineID, proxy.SurfaceTerminal)+next)
		return
	}

	// Desktop Cloud never reuses Web SSO / device cookies: only the machine
	// bound, purpose-scoped five-minute Bearer. /webhook/* Bearer belongs to
	// the third-party webhook and goes to the dashboard untouched.
	isWebhookPath := surface == proxy.SurfaceDashboard && strings.HasPrefix(pathname, "/webhook/")
	if !isWebhookPath {
		if bearer := auth.ParseBearer(r.Header.Get("Authorization")); bearer != "" {
			h.serveDesktopDashboard(w, r, machineID, surface, bearer, pathname)
			return
		}
	}

	if pathname == "/__open" {
		h.serveOpen(w, r, machineID, surface)
		return
	}

	dashboardDeviceCookie := auth.HasDeviceProxySessionCookie(r, auth.DeviceProxyPurposeDashboardMobile)
	terminalDeviceCookie := auth.HasDeviceProxySessionCookie(r, auth.DeviceProxyPurposeTerminal)
	dashboardDeviceSession, dashboardDeviceErr := auth.ReadDeviceProxySession(h.Config, r, auth.DeviceProxyPurposeDashboardMobile)

	if surface == proxy.SurfaceTerminal && !isTerminalPath {
		writeJSONNoStore(w, http.StatusForbidden, machineErrorBody{Error: "terminal_surface_path_forbidden"})
		return
	}
	if dashboardDeviceCookie && terminalDeviceCookie {
		writeJSONNoStore(w, http.StatusForbidden, machineErrorBody{Error: "conflicting_device_purposes"})
		return
	}
	// Principal-presence fence: once a device cookie is present, a malformed
	// or expired value must not silently fall back to a longer-lived SSO
	// owner cookie from the shared WebView jar. Purpose is also path-bound.
	if !isTerminalPath && terminalDeviceCookie {
		writeJSONNoStore(w, http.StatusForbidden, machineErrorBody{Error: "device_purpose_mismatch"})
		return
	}
	if !isTerminalPath && dashboardDeviceCookie {
		if dashboardDeviceErr != nil {
			writeJSONNoStore(w, http.StatusUnauthorized, machineShellErrorBody{Error: "invalid_device_session", ClientShell: "mobile"})
			return
		}
		if decision := auth.AuthorizeDesktopDashboardRequest(auth.DesktopDashboardManage, r.Method, pathname); decision != auth.DashboardRequestOK {
			writeJSONNoStore(w, http.StatusForbidden, machineShellErrorBody{Error: string(decision), ClientShell: "mobile"})
			return
		}
	}
	if isTerminalPath && dashboardDeviceCookie {
		writeJSONNoStore(w, http.StatusForbidden, machineShellErrorBody{Error: "device_purpose_mismatch", ClientShell: "mobile"})
		return
	}

	// Webhooks carry their own token in the URL (verified by the dashboard)
	// and skip platform login so external services can reach the machine
	// through the central domain.
	if isWebhookPath {
		if machine, ok := h.Registry.Get(machineID); ok {
			h.Dashboard.ProxyHTTP(w, r, machine, proxy.PlatformHeaders{})
			return
		}
		if h.forwardToOwner(w, r, machineID, false) {
			return
		}
		text(w, http.StatusBadGateway, "机器当前不在线")
		return
	}

	// Web terminal /s/*: anonymous read-only by default; the owner, a
	// co-manager with terminal:control, or a terminal device session get the
	// owner role. The role is decided here and injected by the proxy layer.
	if isTerminalPath {
		local, ok := h.Registry.Get(machineID)
		if !ok {
			if h.forwardToOwner(w, r, machineID, false) {
				return
			}
			reconnect(w)
			return
		}
		sessionUnionID := ""
		if !terminalDeviceCookie {
			if session, err := auth.ReadProxySession(h.Config, r); err == nil && session.MachineID == machineID {
				sessionUnionID = session.UnionID
			}
		}
		isOwner, actor, viewer := h.terminalSessionRole(ctx, machineID, local, sessionUnionID)
		if viewer && !auth.ViewerTerminalRequestAllowed(r.Method) {
			writeViewerDenied(w, r.Method)
			return
		}
		var device *auth.DeviceProxySessionPayload
		var epoch uint64
		if terminalDeviceCookie {
			dev, err := auth.ReadDeviceProxySession(h.Config, r, auth.DeviceProxyPurposeTerminal)
			if err != nil {
				text(w, http.StatusUnauthorized, "设备终端会话无效或已过期")
				return
			}
			epoch = h.deviceEpoch(dev.DeviceID)
			switch h.checkDeviceProxyClaims(ctx, dev.DeviceProxyClaims, machineID) {
			case deviceClaimsUnavailable:
				text(w, http.StatusServiceUnavailable, "设备状态暂不可用，请稍后重试")
				return
			case deviceClaimsOK:
				if dev.UnionID == local.UnionID && slices.Contains(dev.EffectiveScopes, store.DeviceScopeTerminalControl) {
					break
				}
				fallthrough
			default:
				text(w, http.StatusForbidden, "设备无终端控制权限")
				return
			}
			isOwner, device, actor = true, dev, dev.UnionID
		}
		role := "guest"
		if isOwner {
			role = "owner"
		}
		platform := proxy.PlatformHeaders{
			Role:  role,
			Actor: actor,
			// Read-only banner target: platform /open (login if needed), new
			// ticket, back to this terminal path.
			LoginURL: h.Config.PublicBaseURL + "/open/" + machineID + "?next=" + jsEncodeURIComponent(pathname+search),
		}
		if device != nil {
			guarded, release, ok := h.guardDeviceStream(w, r, device, epoch)
			if !ok {
				return
			}
			defer release()
			r = guarded
		}
		h.Dashboard.ProxyHTTP(w, r, local, platform)
		return
	}

	// Other dashboard paths: SSO proxy session (owner / co-manager) or a
	// device session with explicit dashboard:manage.
	authedUnionID := ""
	if !dashboardDeviceCookie {
		if session, err := auth.ReadProxySession(h.Config, r); err == nil && session.MachineID == machineID {
			authedUnionID = session.UnionID
		}
	}
	var device *auth.DeviceProxySessionPayload
	var epoch uint64
	if dashboardDeviceCookie {
		dev := dashboardDeviceSession
		epoch = h.deviceEpoch(dev.DeviceID)
		switch h.checkDeviceProxyClaims(ctx, dev.DeviceProxyClaims, machineID) {
		case deviceClaimsUnavailable:
			text(w, http.StatusServiceUnavailable, "设备状态暂不可用，请稍后重试")
			return
		case deviceClaimsUnauthorized:
			text(w, http.StatusUnauthorized, "设备会话无效或已过期")
			return
		}
		if !slices.Contains(dev.EffectiveScopes, store.DeviceScopeDashboardManage) {
			text(w, http.StatusForbidden, "设备无访问该机器面板的权限")
			return
		}
		authedUnionID, device = dev.UnionID, dev
	}
	params := parseSearchParams(rawQuery)
	if authedUnionID == "" {
		// A cold top-level navigation bounces through platform SSO (/open)
		// and comes back with a cookie; XHR keeps 401. The sentinel breaks the
		// loop when the browser refuses cookies altogether.
		if isTopLevelNavigation(r) && !hasSearchParam(params, ssoBounceParam) {
			safe, ok := auth.SafeProxyNextPath(pathname + search)
			if !ok {
				safe = "/"
			}
			landingPath, landingQuery, _ := strings.Cut(safe, "?")
			next := whatwgPathname(landingPath) + serializeSearch(setSearchParam(parseSearchParams(landingQuery), ssoBounceParam, "1"))
			w.Header().Set("Location", h.Config.PublicBaseURL+"/open/"+machineID+"?next="+jsEncodeURIComponent(next))
			w.Header().Set("Cache-Control", "no-store")
			w.WriteHeader(http.StatusFound)
			return
		}
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		w.Header().Set("Cache-Control", "no-store")
		w.WriteHeader(http.StatusUnauthorized)
		_, _ = w.Write([]byte(`<html><body style="font-family:sans-serif;padding:2rem">未授权访问该机器。请从 <a href="` + h.Config.PublicBaseURL + `">botmux 平台</a> 打开。</body></html>`))
		return
	}

	// Landing after redemption still carries the sentinel: strip it so it is
	// not bookmarked (a later expired cookie would then look like a re-entry).
	if isTopLevelNavigation(r) && hasSearchParam(params, ssoBounceParam) {
		w.Header().Set("Location", pathname+serializeSearch(deleteSearchParam(params, ssoBounceParam)))
		w.Header().Set("Cache-Control", "no-store")
		w.WriteHeader(http.StatusFound)
		return
	}

	machine, ok := h.Registry.Get(machineID)
	if !ok {
		if h.forwardToOwner(w, r, machineID, false) {
			return
		}
		reconnect(w)
		return
	}
	// The owner is decided from memory; anyone else needs the authoritative
	// co-manager entry. A store outage (503) is kept apart from a real denial
	// (403) so a database hiccup never looks like a revoked permission.
	scopes := auth.OwnerHostScopes()
	role := ""
	if machine.UnionID != authedUnionID {
		access, _, err := auth.LookupMachineAccess(ctx, h.Machines, machineID, authedUnionID, store.AuthorityCacheOptions{PositiveTTL: store.MachineRouteCacheTTL})
		if err != nil {
			if errors.Is(err, auth.ErrMachineAccessDenied) {
				text(w, http.StatusForbidden, "无权访问该机器")
			} else {
				text(w, http.StatusServiceUnavailable, "机器归属状态暂不可用，请稍后重试")
			}
			return
		}
		scopes = access.Scopes
		if auth.IsViewer(access) {
			// Read-only viewer: the platform allowlist is the authority, and
			// the daemon additionally sees a guest so it applies its own
			// Workbench gate and redaction instead of legacy-owner.
			if !auth.BotmuxVersionSupportsViewer(machine.BotmuxVersion) {
				writeJSONNoStore(w, http.StatusForbidden, machineErrorBody{Error: "viewer_requires_newer_botmux"})
				return
			}
			if !auth.ViewerDashboardRequestAllowed(r.Method, pathname) {
				writeViewerDenied(w, r.Method)
				return
			}
			role = "guest"
		}
	}
	if device != nil {
		guarded, release, ok := h.guardDeviceStream(w, r, device, epoch)
		if !ok {
			return
		}
		defer release()
		r = guarded
	}
	// Deliberately no role, for the owner and for co-managers alike (product
	// decision 2026-09): without a role the daemon treats the request as
	// legacy-owner, so co-managers get owner-equivalent capabilities. Sending
	// a role to the owner would demote the machine's own owner; tightening
	// co-managers requires the daemon release that understands platform
	// scopes first (machine.ts carries the full rationale).
	// Viewers are the one exception and do get guest (see above).
	h.Dashboard.ProxyHTTP(w, r, machine, proxy.PlatformHeaders{Role: role, Actor: authedUnionID, Scopes: strings.Join(scopes, ",")})
}

// serveDesktopDashboard handles a Desktop Cloud Bearer on the dashboard
// surface: signature, surface, machine and allowlist locally; then (on the
// pod holding the tunnel) family revocation and current ownership.
func (h *MachineHandler) serveDesktopDashboard(w http.ResponseWriter, r *http.Request, machineID string, surface proxy.MachineSurface, bearer, pathname string) {
	claims, err := auth.VerifyDesktopDashboardAccessToken(h.Config, bearer)
	if err != nil {
		writeJSONNoStore(w, http.StatusUnauthorized, machineErrorBody{Error: "invalid_dashboard_access"})
		return
	}
	if surface != proxy.SurfaceDashboard {
		writeJSONNoStore(w, http.StatusForbidden, machineErrorBody{Error: "dashboard_surface_mismatch"})
		return
	}
	if claims.MachineID != machineID {
		writeJSONNoStore(w, http.StatusForbidden, machineErrorBody{Error: "machine_mismatch"})
		return
	}
	if decision := auth.AuthorizeDesktopDashboardRequest(claims.Scope, r.Method, pathname); decision != auth.DashboardRequestOK {
		writeJSONNoStore(w, http.StatusForbidden, machineErrorBody{Error: string(decision)})
		return
	}

	// Authentication query parameters never reach a peer or the dashboard.
	// If the tunnel is on a peer, forward first and let that pod repeat the
	// full authority check, so ingress and peer do not both read MongoDB for
	// every dashboard resource.
	_, rawQuery := requestPathQuery(r)
	stripped := auth.StripDesktopDashboardAuthQuery(&url.URL{Path: "/", RawQuery: rawQuery})
	_, strippedQuery, hasQuery := strings.Cut(stripped, "?")
	target := pathname
	if hasQuery {
		target += "?" + strippedQuery
	}
	setRequestTarget(r, target)
	machine, local := h.Registry.Get(machineID)
	if !local && h.forwardToOwner(w, r, machineID, false) {
		return
	}

	// The desktop shell injects the Bearer into every same-origin resource,
	// so both authority reads use the 5s positive cache (coalesced cold
	// reads); revoked / RETIRED / unavailable are never cached.
	ctx := r.Context()
	cacheOptions := store.AuthorityCacheOptions{PositiveTTL: store.DesktopDashboardAuthCacheTTL}
	var family store.DesktopFamilyStatus
	var familyErr, lookupErr error
	var doc store.MachineDoc
	var wg sync.WaitGroup
	wg.Add(2)
	go func() {
		defer wg.Done()
		if h.DesktopSessions == nil {
			familyErr = store.ErrUnavailable
			return
		}
		family, familyErr = h.DesktopSessions.GetDesktopSessionFamilyStatus(ctx, claims.SID, cacheOptions)
	}()
	go func() {
		defer wg.Done()
		if h.Machines == nil {
			lookupErr = store.ErrUnavailable
			return
		}
		doc, lookupErr = h.Machines.LookupMachine(ctx, machineID, cacheOptions)
	}()
	wg.Wait()
	if familyErr != nil {
		writeJSONNoStore(w, http.StatusServiceUnavailable, machineErrorBody{Error: "store_unavailable"})
		return
	}
	if family == store.DesktopFamilyRevoked {
		writeJSONNoStore(w, http.StatusUnauthorized, machineErrorBody{Error: "session_revoked"})
		return
	}
	found := lookupErr == nil
	if lookupErr != nil && !errors.Is(lookupErr, store.ErrNotFound) {
		writeJSONNoStore(w, http.StatusServiceUnavailable, machineErrorBody{Error: "store_unavailable"})
		return
	}
	if (found && doc.Status == store.MachineStatusRetired) ||
		(found && doc.UnionID != claims.Sub) ||
		(local && machine.UnionID != claims.Sub) ||
		(!found && !local) {
		writeJSONNoStore(w, http.StatusForbidden, machineErrorBody{Error: "machine_owner_mismatch"})
		return
	}
	if !local {
		reconnect(w)
		return
	}

	// Long streams (SSE /events, downloads) end at the ticket's exp: the
	// short ticket is the only clock on this path.
	streamCtx, cancel := context.WithCancel(ctx)
	defer cancel()
	cleanup := auth.RegisterDesktopDashboardExpiryLease(cancel, claims.Exp, h.now())
	defer cleanup()
	// The Bearer is removed as soon as the local tunnel is chosen; the proxy
	// layer strips it again as defense in depth.
	r.Header.Del("Authorization")
	r.Header.Del("Proxy-Authorization")
	h.Dashboard.ProxyHTTP(w, r.WithContext(streamCtx), machine, proxy.PlatformHeaders{})
}

// serveOpen redeems a /__open ticket into a subdomain cookie. Both the SSO
// ticket and the device proxy ticket are single-use (ConsumeProxyTicket):
// a replay inside the 30s window must not mint a second session.
func (h *MachineHandler) serveOpen(w http.ResponseWriter, r *http.Request, machineID string, surface proxy.MachineSurface) {
	ctx := r.Context()
	_, rawQuery := requestPathQuery(r)
	params := parseSearchParams(rawQuery)
	ticket := firstSearchParam(params, "ticket")
	rawNext := firstSearchParam(params, "next")
	if rawNext == "" {
		rawNext = "/"
	}
	next, ok := auth.SafeProxyNextPath(rawNext)
	if !ok {
		next = "/"
	}
	terminalLanding := isSharedTerminal(next)
	expectedSSOSurface := proxy.SurfaceDashboard
	if terminalLanding {
		expectedSSOSurface = proxy.SurfaceTerminal
	}

	if payload, err := auth.VerifyProxyTicket(h.Config, ticket); err == nil && payload.MachineID == machineID && surface == expectedSSOSurface {
		if !h.consumeTicket(ctx, w, payload.Kind+":"+payload.JTI, payload.Exp*1000) {
			return
		}
		token := auth.MintProxySession(h.Config, auth.ProxyIdentity{UnionID: payload.UnionID, MachineID: machineID})
		machineRedirect(w, next, auth.ProxySessionCookieHeaders(h.Config, token)...)
		return
	}

	// Device-derived ticket (separate kind; never interchangeable with SSO).
	if device, err := auth.VerifyDeviceProxyTicket(h.Config, ticket); err == nil {
		expectedSurface := proxy.SurfaceDashboard
		landingMatchesPurpose := !terminalLanding
		if device.Purpose == auth.DeviceProxyPurposeTerminal {
			expectedSurface = proxy.SurfaceTerminal
			landingMatchesPurpose = terminalLanding
		}
		if device.MachineID == machineID && surface == expectedSurface && landingMatchesPurpose {
			switch h.checkDeviceProxyClaims(ctx, device.DeviceProxyClaims, machineID) {
			case deviceClaimsUnavailable:
				text(w, http.StatusServiceUnavailable, "设备状态暂不可用，请稍后重试")
				return
			case deviceClaimsUnauthorized:
				text(w, http.StatusForbidden, "ticket 无效或已过期，请回平台重新打开")
				return
			}
			if !h.consumeTicket(ctx, w, device.Kind+":"+device.JTI, device.Exp*1000) {
				return
			}
			// The cookie outlives authExp up to the chain boundary (+60s) so a
			// failed renewal cannot silently fall back to an ambient SSO owner
			// cookie; token verification itself still ends at authExp.
			cookie := auth.DeviceProxySessionCookieHeader(h.Config, auth.MintDeviceProxySessionFromTicket(h.Config, device), device.SessionMaxExp-h.now().Unix()+60, device.Purpose)
			machineRedirect(w, next, auth.ClearProxySessionCookieHeader(h.Config), cookie)
			return
		}
	}
	text(w, http.StatusForbidden, "ticket 无效或已过期，请回平台重新打开")
}

// consumeTicket runs the single-use fence and answers 503/403 itself when
// the ticket cannot be consumed.
func (h *MachineHandler) consumeTicket(ctx context.Context, w http.ResponseWriter, ticketID string, expiresAtMS int64) bool {
	err := store.ErrUnavailable
	if h.DesktopSessions != nil {
		err = h.DesktopSessions.ConsumeProxyTicket(ctx, ticketID, expiresAtMS)
	}
	switch {
	case err == nil:
		return true
	case errors.Is(err, store.ErrReplayed):
		text(w, http.StatusForbidden, "ticket 已使用或已过期")
	default:
		text(w, http.StatusServiceUnavailable, "票据状态暂不可用，请稍后重试")
	}
	return false
}

type deviceClaimsDecision int

const (
	deviceClaimsOK deviceClaimsDecision = iota
	deviceClaimsUnauthorized
	deviceClaimsUnavailable
)

// checkDeviceProxyClaims is the per-request device check (/__open, every
// HTTP request, WS handshake): machine binding, both clocks (authExp and
// sessionMaxExp) and the device authority (5s positive cache): active with
// an unchanged credentialVersion. Unavailable means fail closed.
func (h *MachineHandler) checkDeviceProxyClaims(ctx context.Context, claims auth.DeviceProxyClaims, machineID string) deviceClaimsDecision {
	if claims.MachineID != machineID {
		return deviceClaimsUnauthorized
	}
	nowSec := h.now().Unix()
	if nowSec >= claims.AuthExp || nowSec >= claims.SessionMaxExp {
		return deviceClaimsUnauthorized
	}
	if h.DeviceStates == nil {
		return deviceClaimsUnavailable
	}
	state, err := h.DeviceStates.Get(ctx, claims.DeviceID, auth.DeviceStateOptions{})
	if err != nil {
		return deviceClaimsUnavailable
	}
	if state == nil || state.Status != store.DeviceStatusActive || state.CredentialVersion != claims.CredentialVersion {
		return deviceClaimsUnauthorized
	}
	return deviceClaimsOK
}

func (h *MachineHandler) deviceEpoch(deviceID string) uint64 {
	if h.DeviceStates == nil {
		return 0
	}
	return h.DeviceStates.Epoch(deviceID)
}

// guardDeviceStream registers a device-authenticated stream (HTTP long
// response or WebSocket) with the revocation watcher. epoch is the device
// state epoch captured before the authority check: a same-pod revocation in
// between trips the fence and the stream is refused. Destroying the stream
// cancels the returned request's context; the proxy layer turns that into
// an aborted (not ended) client connection.
func (h *MachineHandler) guardDeviceStream(w http.ResponseWriter, r *http.Request, device *auth.DeviceProxySessionPayload, epoch uint64) (*http.Request, func(), bool) {
	ctx, cancel := context.WithCancel(r.Context())
	if h.DeviceSockets == nil {
		cancel()
		abortMachineClient(w)
		return nil, nil, false
	}
	release, ok := h.DeviceSockets.Register(DeviceSocketClaims{
		DeviceID:          device.DeviceID,
		CredentialVersion: device.CredentialVersion,
		AuthExp:           device.AuthExp,
	}, cancel, &epoch)
	if !ok {
		cancel()
		abortMachineClient(w)
		return nil, nil, false
	}
	return r.WithContext(ctx), func() {
		cancel()
		release()
	}, true
}

// abortMachineClient closes the browser connection without a response, like
// socket.destroy() in Node.
func abortMachineClient(w http.ResponseWriter) {
	if hijacker, ok := w.(http.Hijacker); ok {
		if conn, _, err := hijacker.Hijack(); err == nil {
			_ = conn.Close()
		}
	}
}

func (h *MachineHandler) serveWebSocket(w http.ResponseWriter, r *http.Request, machineID string, surface proxy.MachineSurface) {
	proxy.StripReservedBotmuxHeaders(r.Header)
	pathname, _ := requestPathQuery(r)
	isTerminalPath := isSharedTerminal(pathname)
	ctx := r.Context()
	dashboardDeviceCookie := auth.HasDeviceProxySessionCookie(r, auth.DeviceProxyPurposeDashboardMobile)
	terminalDeviceCookie := auth.HasDeviceProxySessionCookie(r, auth.DeviceProxyPurposeTerminal)

	// The non-workflow dashboard uses SSE, not WebSocket; a restricted mobile
	// cookie (even malformed/expired) must not ride the SSO fallback into an
	// unaudited channel. m-<id>/s/* HTTP redirects to the terminal origin,
	// but a WebSocket cannot migrate origin, so it fails closed.
	if (surface == proxy.SurfaceTerminal && !isTerminalPath) ||
		(surface == proxy.SurfaceDashboard && isTerminalPath) ||
		(dashboardDeviceCookie && terminalDeviceCookie) ||
		(!isTerminalPath && (dashboardDeviceCookie || terminalDeviceCookie)) ||
		(isTerminalPath && dashboardDeviceCookie) {
		rejectUpgrade(w, http.StatusForbidden)
		return
	}

	if isTerminalPath {
		local, ok := h.Registry.Get(machineID)
		if !ok {
			if h.forwardToOwner(w, r, machineID, true) {
				return
			}
			rejectUpgrade(w, http.StatusBadGateway)
			return
		}
		sessionUnionID := ""
		if !terminalDeviceCookie {
			if session, err := auth.ReadProxySession(h.Config, r); err == nil && session.MachineID == machineID {
				sessionUnionID = session.UnionID
			}
		}
		isOwner, actor, _ := h.terminalSessionRole(ctx, machineID, local, sessionUnionID)
		var device *auth.DeviceProxySessionPayload
		var epoch uint64
		if terminalDeviceCookie {
			dev, err := auth.ReadDeviceProxySession(h.Config, r, auth.DeviceProxyPurposeTerminal)
			if err != nil {
				rejectUpgrade(w, http.StatusUnauthorized)
				return
			}
			epoch = h.deviceEpoch(dev.DeviceID)
			decision := h.checkDeviceProxyClaims(ctx, dev.DeviceProxyClaims, machineID)
			if decision == deviceClaimsUnavailable {
				rejectUpgrade(w, http.StatusServiceUnavailable)
				return
			}
			if decision != deviceClaimsOK || dev.UnionID != local.UnionID || !slices.Contains(dev.EffectiveScopes, store.DeviceScopeTerminalControl) {
				rejectUpgrade(w, http.StatusForbidden)
				return
			}
			isOwner, device, actor = true, dev, dev.UnionID
		}
		role := "guest"
		if isOwner {
			role = "owner"
		}
		// A device-sourced live WebSocket is registered for revocation and its
		// authExp lease before the upgrade is bridged.
		if device != nil {
			guarded, release, ok := h.guardDeviceStream(w, r, device, epoch)
			if !ok {
				return
			}
			defer release()
			r = guarded
		}
		h.proxyWebSocket(w, r, local, proxy.PlatformHeaders{Role: role, Actor: actor})
		return
	}

	// Other WebSockets: SSO owner or co-manager only.
	authedUnionID := ""
	if session, err := auth.ReadProxySession(h.Config, r); err == nil && session.MachineID == machineID {
		authedUnionID = session.UnionID
	}
	if authedUnionID == "" {
		rejectUpgrade(w, http.StatusUnauthorized)
		return
	}
	machine, ok := h.Registry.Get(machineID)
	if !ok {
		if h.forwardToOwner(w, r, machineID, true) {
			return
		}
		rejectUpgrade(w, http.StatusBadGateway)
		return
	}
	scopes := auth.OwnerHostScopes()
	if machine.UnionID != authedUnionID {
		access, _, err := auth.LookupMachineAccess(ctx, h.Machines, machineID, authedUnionID, store.AuthorityCacheOptions{PositiveTTL: store.MachineRouteCacheTTL})
		if err != nil {
			if errors.Is(err, auth.ErrMachineAccessDenied) {
				rejectUpgrade(w, http.StatusForbidden)
			} else {
				rejectUpgrade(w, http.StatusServiceUnavailable)
			}
			return
		}
		// Viewers have no business on a dashboard WebSocket: the session board
		// is SSE, and every dashboard socket (workflow, host terminal,
		// preview) is interactive.
		if auth.IsViewer(access) {
			rejectUpgrade(w, http.StatusForbidden)
			return
		}
		scopes = access.Scopes
	}
	// Same as HTTP: deliberately no role (owner-equivalent co-managers).
	h.proxyWebSocket(w, r, machine, proxy.PlatformHeaders{Actor: authedUnionID, Scopes: strings.Join(scopes, ",")})
}

// terminalSessionRole decides the terminal surface role (/s/*) for an SSO
// proxy session: the owner and a co-manager with terminal:control get owner,
// everyone else guest. actor is the person attached for the daemon (audit,
// and the wake proof that lets a signed-in person resume a suspended
// session). It is cleared for viewers, who must not wake sessions, for a
// person whose grant is gone, and when the authority cannot be read, since the
// person cannot then be told apart from a viewer. This path allows anonymous
// read-only access, so a degraded lookup stays guest rather than answering 403.
func (h *MachineHandler) terminalSessionRole(ctx context.Context, machineID string, local tunnel.MachineConn, sessionUnionID string) (isOwner bool, actor string, viewer bool) {
	if sessionUnionID == "" {
		return false, "", false
	}
	if sessionUnionID == local.UnionID {
		return true, sessionUnionID, false
	}
	access, _, err := auth.LookupMachineAccess(ctx, h.Machines, machineID, sessionUnionID, store.AuthorityCacheOptions{PositiveTTL: store.MachineRouteCacheTTL})
	switch {
	case err == nil && auth.IsViewer(access):
		return false, "", true
	case err == nil:
		return auth.AccessCanControlTerminal(access), sessionUnionID, false
	default:
		// Denied (a revoked grant still holding its proxy cookie) or
		// unavailable: anonymous guest.
		return false, "", false
	}
}

// writeViewerDenied refuses a viewer request the read allowlist does not
// cover. The x-botmux-auth-scope marker matches the daemon's narrow Workbench
// denial, so the dashboard SPA treats it as "not for this identity" instead
// of opening its login overlay.
func writeViewerDenied(w http.ResponseWriter, method string) {
	w.Header().Set("X-Botmux-Auth-Scope", "workbench")
	status := http.StatusForbidden
	if method == http.MethodGet || method == http.MethodHead {
		status = http.StatusUnauthorized
	}
	writeJSONNoStore(w, status, machineErrorBody{Error: "viewer_read_only"})
}

func (h *MachineHandler) proxyWebSocket(w http.ResponseWriter, r *http.Request, machine tunnel.MachineConn, platform proxy.PlatformHeaders) {
	if err := h.Dashboard.ProxyWebSocket(w, r, machine, platform); err != nil {
		slog.Warn("proxy failure", "proxyPath", "dashboard_ws", "machineId", machine.MachineID, "role", platform.Role, "error", err)
	}
}

// forwardToOwner forwards to the pod holding the tunnel. The loop guard only
// prevents forwarding loops (the peer re-authenticates); a route read failure
// is treated as "no route".
func (h *MachineHandler) forwardToOwner(w http.ResponseWriter, r *http.Request, machineID string, websocket bool) bool {
	if h.Routes == nil || r.Header.Get(proxy.ForwardHeader) != "" {
		return false
	}
	owner, err := h.Routes.GetMachineRouteCached(r.Context(), machineID, store.RouteCacheOptions{PositiveTTL: store.MachineRouteCacheTTL})
	if err != nil || owner == "" || owner == h.Config.SelfPodAddr {
		return false
	}
	if websocket {
		forward := h.ForwardRawWS
		if forward == nil {
			forward = proxy.ForwardWebSocket
		}
		if err := forward(owner, w, r); err != nil {
			slog.Warn("proxy failure", "proxyPath", "peer_machine_ws", "machineId", machineID, "owner", owner, "error", err)
		}
	} else {
		forward := h.ForwardHTTP
		if forward == nil {
			forward = proxy.ForwardHTTP
		}
		if err := forward(owner, w, r); err != nil {
			slog.Warn("proxy failure", "proxyPath", "peer_machine_http", "machineId", machineID, "owner", owner, "error", err)
		}
	}
	return true
}

// isTopLevelNavigation: a real browser navigation (address bar / link), not
// XHR, fetch or a subresource. Sec-Fetch-Mode decides when present; older
// WebViews fall back to Accept: text/html. Only GET: a POST form navigation
// must not be turned into a GET by a redirect.
func isTopLevelNavigation(r *http.Request) bool {
	if strings.ToUpper(r.Method) != http.MethodGet {
		return false
	}
	if mode := strings.ToLower(r.Header.Get("Sec-Fetch-Mode")); mode != "" {
		return mode == "navigate"
	}
	return strings.Contains(strings.ToLower(r.Header.Get("Accept")), "text/html")
}

func firstSearchParam(params []searchParam, name string) string {
	for _, param := range params {
		if param.name == name {
			return param.value
		}
	}
	return ""
}

// setRequestTarget replaces the request target (escaped path + query) of a
// request about to be proxied or forwarded (Node assigns req.url).
func setRequestTarget(r *http.Request, target string) {
	parsed, err := url.ParseRequestURI(target)
	if err != nil {
		return
	}
	r.URL.Path, r.URL.RawPath = parsed.Path, parsed.RawPath
	r.URL.RawQuery, r.URL.ForceQuery = parsed.RawQuery, false
	r.RequestURI = target
}

// machineRedirect is util.ts redirect(): 302 + Location (+ Set-Cookie), no
// body and no Content-Type.
func machineRedirect(w http.ResponseWriter, location string, cookies ...string) {
	for _, cookie := range cookies {
		w.Header().Add("Set-Cookie", cookie)
	}
	w.Header().Set("Location", location)
	w.WriteHeader(http.StatusFound)
}

// rejectUpgrade answers an upgrade like Node's raw socket.write of a bare
// status line followed by destroy().
func rejectUpgrade(w http.ResponseWriter, status int) {
	if hijacker, ok := w.(http.Hijacker); ok {
		if conn, buffered, err := hijacker.Hijack(); err == nil {
			_, _ = buffered.WriteString("HTTP/1.1 " + strconv.Itoa(status) + " " + http.StatusText(status) + "\r\n\r\n")
			_ = buffered.Flush()
			_ = conn.Close()
			return
		}
	}
	http.Error(w, http.StatusText(status), status)
}

// MatchMachineSubdomain reports the machine id of an m-<id> or t-<id> host
// (proxy.MatchMachineSubdomainRoute projected to the id).
func MatchMachineSubdomain(cfg config.Config, hostHeader string) (string, bool) {
	route, ok := proxy.MatchMachineSubdomainRoute(cfg, hostHeader)
	return route.MachineID, ok
}

// MachineBaseURL is the public origin of a machine's dashboard surface.
func MachineBaseURL(cfg config.Config, machineID string) string {
	return proxy.MachineBaseURL(cfg, machineID, proxy.SurfaceDashboard)
}

func validRelativeRedirect(value string) bool {
	return strings.HasPrefix(value, "/") && !strings.HasPrefix(value, "//")
}

var machineIDPattern = regexp.MustCompile(`^[a-f0-9]{8,64}$`)

// reconnectHTML is RECONNECT_HTML of machine.ts byte for byte: the friendly
// "machine reconnecting" page (usually a daemon restart) that polls and
// reloads once the machine answers anything but 503.
const reconnectHTML = `<!doctype html><html lang="zh"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1"><title>正在重连…</title>
<style>
*{box-sizing:border-box}html,body{height:100%;margin:0}
body{background:#0d1017;color:#c9d1d9;font:14px/1.6 -apple-system,BlinkMacSystemFont,"Segoe UI",sans-serif;
display:flex;align-items:center;justify-content:center;flex-direction:column;gap:18px}
.ring{width:46px;height:46px;border-radius:50%;border:3px solid rgba(88,166,255,0.18);
border-top-color:#58a6ff;animation:spin 0.9s linear infinite}
@keyframes spin{to{transform:rotate(360deg)}}
h1{font-size:16px;font-weight:600;margin:0;color:#e6edf3}
p{margin:0;color:#7d8590;font-size:13px}
.dot{display:inline-block;animation:blink 1.4s infinite both}
.dot:nth-child(2){animation-delay:.2s}.dot:nth-child(3){animation-delay:.4s}
@keyframes blink{0%,80%,100%{opacity:.2}40%{opacity:1}}
</style></head><body>
<div class="ring"></div>
<h1>机器正在重连<span class="dot">.</span><span class="dot">.</span><span class="dot">.</span></h1>
<p>连接暂时中断（通常是 daemon 重启），恢复后会自动打开，无需手动刷新。</p>
<script>
(function(){
  var tries=0;
  function poll(){
    tries++;
    fetch(location.href,{cache:'no-store',redirect:'manual'}).then(function(r){
      if(r.status!==503){location.reload();return;}
      setTimeout(poll, Math.min(1000+tries*250, 3000));
    }).catch(function(){ setTimeout(poll, 2000); });
  }
  setTimeout(poll, 1200);
})();
</script>
</body></html>`

func reconnect(w http.ResponseWriter) {
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.Header().Set("Retry-After", "2")
	w.Header().Set("Cache-Control", "no-store")
	w.WriteHeader(http.StatusServiceUnavailable)
	_, _ = w.Write([]byte(reconnectHTML))
}

func text(w http.ResponseWriter, status int, value string) {
	w.Header().Set("Content-Type", "text/plain; charset=utf-8")
	w.WriteHeader(status)
	_, _ = w.Write([]byte(value))
}
