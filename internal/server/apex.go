package server

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"log/slog"
	"net/http"
	"net/url"
	"regexp"
	"strings"
	"time"

	"github.com/botmux-ai/botmux-platform/internal/auth"
	"github.com/botmux-ai/botmux-platform/internal/config"
	"github.com/botmux-ai/botmux-platform/internal/feishu"
	"github.com/botmux-ai/botmux-platform/internal/proxy"
	"github.com/botmux-ai/botmux-platform/internal/store"
	"github.com/botmux-ai/botmux-platform/internal/teamsync"
	"github.com/botmux-ai/botmux-platform/internal/tunnel"
)

type RuntimeRoutes interface {
	GetMachineRoute(context.Context, string) (string, error)
	DeleteMachineRoute(context.Context, string, string) error
}

type Apex struct {
	Config            config.Config
	Registry          *tunnel.Registry
	Repository        store.Repository
	Routes            RuntimeRoutes
	KV                *store.KVStore
	RoutingConfigured bool
	Feishu            *feishu.Client
	TeamSync          *teamsync.Service
	MachineAPI        *MachineAPI
	ForwardHTTP       func(string, http.ResponseWriter, *http.Request) error
	// FeishuWritesDisabled is the canary kill switch. It blocks user-facing
	// team/group mutations before they touch MongoDB as well as the background
	// hall writes guarded by TeamSync, so a Go canary cannot leave external
	// Feishu state that an artifact rollback cannot undo.
	FeishuWritesDisabled bool
	// PublicRoutes serves an entrypoint's extra public apex routes, ahead of
	// the module APIs, and reports whether it handled the request.
	PublicRoutes func(http.ResponseWriter, *http.Request) bool

	// Shared authorities (Phase 2). Every module handler reads these instead
	// of holding its own copy, so a revocation on this pod is seen by all.
	DeviceRepo      store.DeviceRepository
	DesktopSessions store.DesktopSessionRepository
	DeviceStates    *auth.DeviceStateCache
	DeviceSockets   *DeviceSocketWatcher
	IssueStore      *store.IssueStore
	CredentialStore *store.CredentialStore

	// Per-module seams; each type lives in its module's file.
	Devices       DevicesDeps
	Desktop       DesktopDeps
	Issues        IssuesDeps
	Credentials   CredentialsDeps
	OpenAPI       OpenAPIDeps
	MachineGroups MachineGroupsDeps
	Stats         StatsDeps
}

// hasPathPrefix reports p === base || p.startsWith(base + '/').
func hasPathPrefix(p, base string) bool {
	return p == base || strings.HasPrefix(p, base+"/")
}

func (a *Apex) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	path := r.URL.Path
	if path == "/healthz" {
		text(w, http.StatusOK, "ok")
		return
	}
	if path == "/install.sh" || path == "/api/install.sh" {
		ServeDownload(w, r, a.Config.InstallerFile, "text/x-shellscript; charset=utf-8", "botmux-install.sh")
		return
	}
	if a.PublicRoutes != nil && a.PublicRoutes(w, r) {
		return
	}
	// Self-authenticating module APIs, in handleApex order. Each hook reports
	// whether it handled the request; false falls through like the TS
	// `if (await handleXxx(...)) return;`.
	switch {
	case hasPathPrefix(path, "/api/devices"):
		if a.handleDevicesAPI(w, r) {
			return
		}
	case hasPathPrefix(path, "/api/credentials"):
		if a.handleCredentialsAPI(w, r) {
			return
		}
	case hasPathPrefix(path, "/v1/desktop/auth"):
		if a.handleDesktopAuth(w, r) {
			return
		}
	case hasPathPrefix(path, "/v1/desktop/machines"):
		if a.handleDesktopDashboard(w, r) {
			return
		}
	case path == "/v1/desktop/teams" || hasPathPrefix(path, "/v1/desktop/issues"):
		if a.handleDesktopIssuesAPI(w, r) {
			return
		}
	case path == "/v1/machine/teams" || hasPathPrefix(path, "/v1/machine/issues"):
		if a.handleMachineIssuesAPI(w, r) {
			return
		}
	case path == "/v1/machine/agents":
		if a.handleMachineAgentsAPI(w, r) {
			return
		}
	case path == "/v1/machine/credential-grant":
		if a.handleMachineCredentialsAPI(w, r) {
			return
		}
	case hasPathPrefix(path, "/v1/machine/groups"):
		if a.handleMachineGroupsAPI(w, r) {
			return
		}
	case hasPathPrefix(path, "/openapi/machines"):
		if a.handleOpenAPI(w, r) {
			return
		}
	case hasPathPrefix(path, "/api/issues"):
		if a.handleWebIssuesAPI(w, r) {
			return
		}
	}

	if a.handleAuth(w, r) {
		return
	}
	// DESIGN §3.2: high-risk SSO routes need a recently authenticated SSO
	// principal and an exact same-origin request (see freshSSOTier). Team read
	// routes still accept older cookies; /api/bind is redeemed by the daemon
	// with a bind token and is not an SSO route. This runs before every route
	// below, including the team issue-settings/admins hook, so appointing an
	// admin or saving a form can never bypass the freshness gate.
	if tier := freshSSOTier(path, r.Method); tier != ssoTierNone && !a.enforceFreshSSO(w, r, tier) {
		return
	}
	if strings.HasPrefix(path, "/api/teams/") && a.handleTeamIssueSettingsAPI(w, r) {
		return
	}
	if path == "/api/bind" && r.Method == http.MethodPost {
		a.bind(w, r)
		return
	}

	session, sessionErr := auth.ReadSession(a.Config, r)
	if path == "/api/me" {
		if sessionErr != nil {
			writeJSON(w, http.StatusUnauthorized, apexError{Error: "unauthenticated"})
			return
		}
		writeJSON(w, http.StatusOK, meResponse{UnionID: session.UnionID, Name: session.Name, Avatar: session.Avatar})
		return
	}
	if strings.HasPrefix(path, "/api/stats/") {
		if sessionErr != nil {
			writeJSON(w, http.StatusUnauthorized, apexError{Error: "unauthenticated"})
			return
		}
		if a.handleStatsAPI(w, r, session) {
			return
		}
	}
	if path == "/api/machines" && r.Method == http.MethodGet {
		a.listMachines(w, r)
		return
	}
	if match := mobileSessionsPattern.FindStringSubmatch(path); match != nil && r.Method == http.MethodGet {
		a.mobileMachineSessions(w, r, match[1])
		return
	}
	// The session id is matched on the escaped path: like the TS pathname it
	// is decoded exactly once, by decodeURIComponent below.
	if match := mobileSessionOpenPattern.FindStringSubmatch(r.URL.EscapedPath()); match != nil && r.Method == http.MethodPost {
		a.mobileSessionOpen(w, r, match[1], match[2])
		return
	}
	if path == "/api/bind-code" && r.Method == http.MethodPost {
		if sessionErr != nil {
			writeJSON(w, http.StatusUnauthorized, apexError{Error: "unauthenticated"})
			return
		}
		// A stateless signed bind token wrapped in a self-contained blob that
		// carries the platform address (botmux never hardcodes the domain).
		token := auth.IssueBindToken(a.Config, auth.BindIdentity{UnionID: session.UnionID, OwnerName: session.Name})
		blob := auth.EncodeBindBlob(a.Config.PublicBaseURL, token)
		writeJSON(w, http.StatusOK, bindCodeResponse{Code: blob, ExpiresInSec: int64(a.Config.BindCodeTTL / time.Second), Command: "botmux bind " + blob})
		return
	}
	if a.blockFeishuMutation(w, r, sessionErr) {
		return
	}
	if a.handleMachineEndpoints(w, r, session, sessionErr) {
		return
	}
	if a.handleTeamEndpoints(w, r, session, sessionErr) {
		return
	}
	if path == "/api/groups/create" && r.Method == http.MethodPost {
		a.createGroup(w, r, session, sessionErr)
		return
	}
	if path == "/api/users/search" && r.Method == http.MethodGet {
		a.searchUsers(w, r, session, sessionErr)
		return
	}

	if r.Method == http.MethodGet {
		if path == "/" || path == "/index.html" {
			serveIndex(w, a.Config.WebDir)
			return
		}
		// /v1/ is the desktop/machine protocol surface: an unknown /v1 route
		// must be a plain 404, never the SPA shell.
		if !strings.HasPrefix(path, "/api/") && !strings.HasPrefix(path, "/auth/") && !strings.HasPrefix(path, "/v1/") && !strings.HasPrefix(path, "/__internal/") && !strings.HasPrefix(path, "/tunnel/") {
			if serveStatic(w, a.Config.WebDir, path) {
				return
			}
			if staticExtension.MatchString(path) {
				text(w, http.StatusNotFound, "not found")
				return
			}
			serveIndex(w, a.Config.WebDir)
			return
		}
	}
	text(w, http.StatusNotFound, "not found")
}

func (a *Apex) blockFeishuMutation(w http.ResponseWriter, r *http.Request, sessionErr error) bool {
	if !a.FeishuWritesDisabled || !isFeishuMutation(r.Method, r.URL.Path) {
		return false
	}
	if !requireSession(w, sessionErr) {
		return true
	}
	w.Header().Set("Retry-After", "60")
	writeJSON(w, http.StatusServiceUnavailable, map[string]any{"error": "feishu_writes_disabled"})
	return true
}

func isFeishuMutation(method, path string) bool {
	if method == http.MethodPost && (path == "/api/teams" || path == "/api/teams/accept" || path == "/api/groups/create") {
		return true
	}
	if method == http.MethodDelete && deleteTeamPattern.MatchString(path) {
		return true
	}
	if method != http.MethodPost {
		return false
	}
	return renameTeamPattern.MatchString(path) || leaveTeamPattern.MatchString(path) ||
		hallJoinPattern.MatchString(path) || inviteTeamPattern.MatchString(path) ||
		inviteUserPattern.MatchString(path) || teamBotsPattern.MatchString(path)
}

func (a *Apex) handleAuth(w http.ResponseWriter, r *http.Request) bool {
	switch {
	case r.URL.Path == "/auth/login" && r.Method == http.MethodGet:
		if a.Config.DevLogin {
			// Local / integration: no Feishu, mint the session directly.
			token := auth.MintSession(a.Config, auth.SessionUser{UnionID: a.Config.DevUnionID, Name: a.Config.DevName})
			redirectWithCookie(w, r, "/", auth.SessionCookieHeader(a.Config, token))
			return true
		}
		if a.Config.FeishuAppID == "" {
			text(w, http.StatusInternalServerError, "飞书登录未配置（缺 FEISHU_APP_ID/SECRET）。联调可临时设 DEV_LOGIN=true。")
			return true
		}
		// scope=search is the incremental-authorization entry: the people
		// search scope is requested only when the user wants to search, so a
		// plain login shows no confirmation dialog. A still-signed older
		// session that already had search keeps asking for it on re-login;
		// otherwise "stale invite -> re-login -> ss lost -> authorize again"
		// would cost the user a second round trip (and could loop on
		// needScope).
		wantSearch := queryParamJS(r.URL.RawQuery, "scope") == "search"
		if prior, err := auth.ReadSession(a.Config, r); err == nil && prior.SearchScope {
			wantSearch = true
		}
		next := first(queryParamJS(r.URL.RawQuery, "next"), "/")
		redirect := auth.BuildAuthorizeRedirect(a.Config, next, auth.AuthorizeOptions{SearchScope: wantSearch})
		redirectWithCookie(w, r, redirect.URL, redirect.StateCookie)
		return true
	case r.URL.Path == "/auth/callback" && r.Method == http.MethodGet:
		code, state := queryParamJS(r.URL.RawQuery, "code"), queryParamJS(r.URL.RawQuery, "state")
		cookieNonce := auth.ParseCookie(r.Header.Get("Cookie"))[auth.OAuthStateCookieName]
		verified, err := auth.VerifyState(a.Config, state, cookieNonce)
		if err != nil || verified == nil || code == "" {
			text(w, http.StatusBadRequest, "登录校验失败（state/code 无效）")
			return true
		}
		// Desktop PKCE: issue the one-time code and 302 to the loopback; the
		// web session cookie is never written for a desktop login.
		if verified.Desktop != nil {
			a.completeDesktopAuthFromFeishuCallback(w, r, code, verified.Desktop)
			return true
		}
		// Credential vault authorize: no session is minted.
		if verified.Credential == "lark-cli" {
			a.handleLarkCredentialCallback(w, r, code)
			return true
		}
		next := verified.Next
		if !validRelativeRedirect(next) {
			next = "/"
		}
		if a.Feishu == nil {
			text(w, http.StatusBadGateway, "飞书登录失败：Error: feishu_not_configured")
			return true
		}
		ctx, cancel := context.WithTimeout(r.Context(), 15*time.Second)
		defer cancel()
		user, userToken, err := a.Feishu.ExchangeCode(ctx, code)
		if err != nil {
			// The TS handler renders String(e) of the thrown Error.
			text(w, http.StatusBadGateway, "飞书登录失败：Error: "+err.Error())
			return true
		}
		token := auth.MintSession(a.Config, auth.SessionUser{
			UnionID: user.UnionID,
			// Message cards only @-mention by open_id (invite DMs).
			OpenID:    user.OpenID,
			Name:      user.Name,
			Avatar:    user.Avatar,
			UserToken: &auth.SessionUserToken{AccessToken: userToken.AccessToken, RefreshToken: userToken.RefreshToken, ExpiresAt: userToken.ExpiresAt},
			// Whether this login granted people search: a session without it
			// is sent to incremental authorization instead of a doomed search.
			SearchScope: verified.SearchScope,
		})
		go func() {
			ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			defer cancel()
			_ = a.Repository.UpsertUserProfile(ctx, store.UserProfile{ID: user.UnionID, Name: user.Name, Avatar: user.Avatar, UpdatedAt: time.Now().UnixMilli()})
		}()
		redirectWithCookie(w, r, next, auth.SessionCookieHeader(a.Config, token))
		return true
	case r.URL.Path == "/auth/logout" && r.Method == http.MethodPost:
		redirectWithCookie(w, r, "/", auth.ClearSessionCookieHeader(a.Config))
		return true
	default:
		return false
	}
}

func (a *Apex) bind(w http.ResponseWriter, r *http.Request) {
	var body struct {
		Code      string `json:"code"`
		MachineID string `json:"machineId"`
	}
	if !readJSON(r, &body) {
		writeJSON(w, http.StatusBadRequest, map[string]any{"error": "invalid_or_expired"})
		return
	}
	payload, err := auth.VerifyBindToken(a.Config, body.Code)
	if err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]any{"error": "invalid_or_expired"})
		return
	}
	machineID := body.MachineID
	if !machineIDPattern.MatchString(machineID) {
		machineID = randomID(8)
	}
	// Ownership CAS before minting: a RETIRED tombstone id is never reused
	// and an ACTIVE machine owned by someone else is never overwritten. In
	// both cases the binder gets a fresh random id instead (the CLI adopts the
	// machineId in the response). An id owned by someone else usually reached
	// this host through a copied ~/.botmux, a shared HOME or a machine image;
	// the other owner's record is left untouched, so this cannot take over
	// their machine. A degraded store never yields a token.
	result, err := a.Repository.BindMachineCAS(r.Context(), machineID, payload.UnionID, payload.OwnerName)
	reassigned := false
	if err == nil && (result == store.BindRetired || result == store.BindConflictOwner) {
		reassigned = result == store.BindConflictOwner
		machineID = randomID(8)
		result, err = a.Repository.BindMachineCAS(r.Context(), machineID, payload.UnionID, payload.OwnerName)
	}
	if err == nil && result == store.BindConflictOwner {
		writeJSON(w, http.StatusConflict, map[string]any{"error": "machine_owned_by_other"})
		return
	}
	if err != nil || (result != store.BindCreated && result != store.BindRebound) {
		slog.Warn("bind machine", "machineId", machineID, "result", result, "error", err)
		writeJSON(w, http.StatusServiceUnavailable, map[string]any{"error": "store_unavailable"})
		return
	}
	if reassigned {
		slog.Info("bind reassigned machine id", "requestedMachineId", body.MachineID, "machineId", machineID, "unionId", payload.UnionID)
	}
	machineToken := auth.MintMachineToken(a.Config, auth.MachineIdentity{UnionID: payload.UnionID, OwnerName: payload.OwnerName, MachineID: machineID})
	response := map[string]any{"machineId": machineID, "machineToken": machineToken, "tunnelUrl": tunnelControlURL(a.Config, machineToken)}
	if reassigned {
		response["reassigned"] = true
	}
	writeJSON(w, http.StatusOK, response)
}

func (a *Apex) handleMachineEndpoints(w http.ResponseWriter, r *http.Request, session *auth.SessionPayload, sessionErr error) bool {
	path := r.URL.Path
	if match := openMachinePattern.FindStringSubmatch(path); match != nil && r.Method == http.MethodPost {
		a.openMachine(w, r, session, sessionErr, match[1])
		return true
	}
	if match := openRedirectPattern.FindStringSubmatch(path); match != nil && r.Method == http.MethodGet {
		a.openMachineRedirect(w, r, session, sessionErr, match[1])
		return true
	}
	if match := renameMachinePattern.FindStringSubmatch(path); match != nil && r.Method == http.MethodPost {
		if !requireSession(w, sessionErr) {
			return true
		}
		machineID := match[1]
		if !a.requireOwnedActiveMachine(w, r, machineID, session.UnionID, false) {
			return true
		}
		var body struct {
			Name string `json:"name"`
		}
		if !readJSON(r, &body) {
			body.Name = ""
		}
		name := truncate(trimJS(body.Name), 64)
		if name == "" {
			writeJSON(w, http.StatusBadRequest, apexError{Error: "name_required"})
			return true
		}
		_ = a.Repository.RenameMachine(r.Context(), machineID, name)
		writeJSON(w, http.StatusOK, renameMachineResponse{OK: true, Name: name})
		return true
	}
	if match := upgradeMachinePattern.FindStringSubmatch(path); match != nil && r.Method == http.MethodPost {
		if !requireSession(w, sessionErr) {
			return true
		}
		if !strings.HasPrefix(strings.ToLower(r.Header.Get("Content-Type")), "application/json") {
			writeJSON(w, http.StatusUnsupportedMediaType, apexError{Error: "json_required"})
			return true
		}
		machineID := match[1]
		if a.Repository == nil {
			writeJSON(w, http.StatusServiceUnavailable, apexError{Error: "store_unavailable"})
			return true
		}
		doc, err := a.Repository.GetMachine(r.Context(), machineID)
		if err != nil && !errors.Is(err, store.ErrNotFound) {
			writeJSON(w, http.StatusServiceUnavailable, apexError{Error: "store_unavailable"})
			return true
		}
		// The authoritative record decides (a tombstone is gone); only a
		// machine with no record at all falls back to live local ownership.
		owned := err == nil && doc.UnionID == session.UnionID && !doc.Retired()
		if errors.Is(err, store.ErrNotFound) && a.Registry != nil {
			live, local := a.Registry.Get(machineID)
			owned = local && live.UnionID == session.UnionID
		}
		if !owned {
			writeJSON(w, http.StatusNotFound, apexError{Error: "machine_not_found"})
			return true
		}
		if a.MachineAPI == nil {
			writeJSON(w, http.StatusBadGateway, okError{OK: false, Error: "machine_unreachable"})
			return true
		}
		status, response := a.MachineAPI.UpgradeMachine(r.Context(), machineID, session.UnionID)
		writeJSON(w, status, response)
		return true
	}
	if match := workingDirPattern.FindStringSubmatch(path); match != nil && r.Method == http.MethodPut {
		if !requireSession(w, sessionErr) {
			return true
		}
		machineID, appID := match[1], match[2]
		if !a.requireOwnedActiveMachine(w, r, machineID, session.UnionID, false) {
			return true
		}
		body := readJSONObject(r)
		mode, _ := body["mode"].(string)
		if mode != "off" && mode != "default" && mode != "oncall" {
			writeJSON(w, http.StatusBadRequest, okError{OK: false, Error: "invalid_mode"})
			return true
		}
		workingDir, _ := body["workingDir"].(string)
		workingDir = trimJS(workingDir)
		if mode != "off" && workingDir == "" {
			writeJSON(w, http.StatusBadRequest, okError{OK: false, Error: "workingDir_required"})
			return true
		}
		if a.MachineAPI == nil {
			writeJSON(w, http.StatusBadGateway, okError{OK: false, Error: "machine_unreachable"})
			return true
		}
		status, response := a.MachineAPI.SetWorkingDir(r.Context(), machineID, session.UnionID, appID, mode, workingDir)
		writeJSON(w, status, response)
		return true
	}
	if match := unbindPattern.FindStringSubmatch(path); match != nil && r.Method == http.MethodPost {
		a.unbind(w, r, session, sessionErr, match[1])
		return true
	}
	if match := coManagersPattern.FindStringSubmatch(path); match != nil && (r.Method == http.MethodGet || r.Method == http.MethodPut) {
		if !requireSession(w, sessionErr) {
			return true
		}
		a.machineCoManagers(w, r, session, match[1])
		return true
	}
	// The target is matched on the escaped path and decoded once, as the TS
	// pathname + decodeURIComponent.
	if match := coManagerOnePattern.FindStringSubmatch(r.URL.EscapedPath()); match != nil && r.Method == http.MethodDelete {
		if !requireSession(w, sessionErr) {
			return true
		}
		a.removeMachineCoManager(w, r, session, match[1], match[2])
		return true
	}
	return false
}

// listMachines is GET /api/machines for both principal shapes: an SSO
// session gets the full contract (versions, teams, bots, co-managed
// machines); a device bearer with machines:read gets the reduced list.
func (a *Apex) listMachines(w http.ResponseWriter, r *http.Request) {
	principal, err := a.ReadPrincipal(r)
	if err != nil {
		writePrincipalError(w, err, false)
		return
	}
	if principal == nil {
		writeJSON(w, http.StatusUnauthorized, apexError{Error: "unauthenticated"})
		return
	}
	if principal.Kind == auth.PrincipalDevice {
		unionID, ok := auth.RequireDeviceScope(principal, store.DeviceScopeMachinesRead)
		if !ok {
			writeJSON(w, http.StatusForbidden, apexError{Error: "insufficient_scope"})
			return
		}
		machines, err := a.machinesForUser(r.Context(), unionID)
		if err != nil {
			writeJSON(w, http.StatusServiceUnavailable, apexError{Error: "store_unavailable"})
			return
		}
		out := make([]deviceMachineView, 0, len(machines))
		for _, machine := range machines {
			out = append(out, deviceMachineView{MachineID: machine.MachineID, Name: machine.Name, Online: machine.Online, LastSeenAt: machine.LastSeen})
		}
		writeJSON(w, http.StatusOK, deviceMachinesResponse{Machines: out})
		return
	}
	unionID := principal.Session.UnionID
	managedCh := make(chan []MachineView, 1)
	go func() { managedCh <- a.machinesCoManagedBy(r.Context(), unionID) }()
	machines, err := a.machinesForUser(r.Context(), unionID)
	managed := <-managedCh
	if err != nil {
		writeJSON(w, http.StatusServiceUnavailable, apexError{Error: "store_unavailable"})
		return
	}
	// The version hint only considers machines I own: someone else's machine
	// must not drive my "upgrade suggested" badge (I cannot upgrade it).
	writeJSON(w, http.StatusOK, machinesResponse{Machines: machines, ManagedMachines: managed, LatestVersion: highestVersion(machines)})
}

// mobileMachineSessions is GET /api/machines/:id/sessions. It accepts an SSO
// cookie or a device bearer with sessions:open: the SSO login binds the
// device once, after which the native client only holds its device tokens.
func (a *Apex) mobileMachineSessions(w http.ResponseWriter, r *http.Request, machineID string) {
	principal, err := a.ReadPrincipal(r)
	if err != nil {
		writePrincipalError(w, err, true)
		return
	}
	unionID, scoped := auth.RequireDeviceScope(principal, store.DeviceScopeSessionsOpen)
	if principal == nil {
		writeJSONNoStore(w, http.StatusUnauthorized, apexError{Error: "unauthenticated"})
		return
	}
	if !scoped {
		writeJSONNoStore(w, http.StatusForbidden, apexError{Error: "insufficient_scope"})
		return
	}
	if !a.requireOwnedActiveMachine(w, r, machineID, unionID, true) {
		return
	}
	if a.MachineAPI == nil {
		writeJSONNoStore(w, http.StatusBadGateway, apexError{Error: "machine_unreachable"})
		return
	}
	result := a.MachineAPI.FetchMachineSessions(r.Context(), machineID, unionID)
	writeJSONNoStore(w, result.Status, result.Body)
}

// mobileSessionOpen is POST /api/machines/:id/sessions/:sid/open: resolve the
// session's dashboard write-link, then either re-open a Botmux terminal
// through the machine proxy or hand back an external URL.
func (a *Apex) mobileSessionOpen(w http.ResponseWriter, r *http.Request, machineID, rawSessionID string) {
	principal, err := a.ReadPrincipal(r)
	if err != nil {
		writePrincipalError(w, err, true)
		return
	}
	unionID, scoped := auth.RequireDeviceScope(principal, store.DeviceScopeSessionsOpen)
	if principal == nil {
		writeJSONNoStore(w, http.StatusUnauthorized, apexError{Error: "unauthenticated"})
		return
	}
	if !scoped {
		writeJSONNoStore(w, http.StatusForbidden, apexError{Error: "insufficient_scope"})
		return
	}
	sessionID, ok := decodeURIComponentJS(rawSessionID)
	if !ok {
		writeJSONNoStore(w, http.StatusBadRequest, apexError{Error: "invalid_session_id"})
		return
	}
	if !a.requireOwnedActiveMachine(w, r, machineID, unionID, true) {
		return
	}
	if a.MachineAPI == nil {
		writeJSONNoStore(w, http.StatusBadGateway, apexError{Error: "machine_unreachable"})
		return
	}
	link := a.MachineAPI.FetchMachineSessionWriteLink(r.Context(), machineID, unionID, sessionID)
	if link.Status < 200 || link.Status >= 300 {
		writeJSONNoStore(w, link.Status, link.Body)
		return
	}
	rawLink, ok := link.Body.StringField("url")
	if !ok {
		rawLink, _ = link.Body.StringField("writeUrl")
	}
	writeLink, ok := parseAbsoluteURL(rawLink)
	if !ok {
		writeJSONNoStore(w, http.StatusBadGateway, apexError{Error: "invalid_write_link"})
		return
	}
	// Ordinary Botmux terminals are re-opened through the machine proxy. The
	// dashboard/private write tokens are stripped: the redeemed owner proxy
	// cookie grants terminal control through the authoritative X-Botmux-Role
	// path instead.
	if pathname := writeLink.pathname(); isSharedTerminal(pathname) {
		next := pathname + writeLink.searchWithout("t", "token") + writeLink.hash()
		if principal.Kind == auth.PrincipalDevice {
			a.handleDeviceMachineOpen(w, r, machineID, principal.Device, auth.DeviceProxyPurposeTerminal, &next)
			return
		}
		ticket := auth.IssueProxyTicket(a.Config, auth.ProxyIdentity{UnionID: principal.Session.UnionID, MachineID: machineID})
		writeJSONNoStore(w, http.StatusOK, openURLResponse{OpenURL: machineSurfaceBaseURL(a.Config, machineID, true) + "/__open?ticket=" + encodeURIComponentJS(ticket) + "&next=" + encodeURIComponentJS(next)})
		return
	}
	// Sandbox-style sessions live outside the machine dashboard and keep
	// their external URL contract.
	writeJSONNoStore(w, http.StatusOK, externalURLResponse{ExternalURL: writeLink.href()})
}

// openMachine is POST /api/machines/:id/open: a proxy ticket plus the machine
// subdomain open URL. SSO keeps the original contract; a device bearer takes
// the device-proxy-ticket branch. Cookie + Bearer together is a 400, never a
// silent choice.
func (a *Apex) openMachine(w http.ResponseWriter, r *http.Request, session *auth.SessionPayload, sessionErr error, machineID string) {
	principal, err := a.ReadPrincipal(r)
	if err != nil {
		writePrincipalError(w, err, false)
		return
	}
	if principal != nil && principal.Kind == auth.PrincipalDevice {
		// The generic device dashboard is the mobile client shell. The signed
		// purpose enforces the non-Workflow allowlist at the machine proxy;
		// body.next only picks the landing route.
		a.handleDeviceMachineOpen(w, r, machineID, principal.Device, auth.DeviceProxyPurposeDashboardMobile, nil)
		return
	}
	if !requireSession(w, sessionErr) {
		return
	}
	issue := func() {
		if a.MachineAPI == nil || !a.MachineAPI.CheckDashboardHealth(r.Context(), machineID, session.UnionID) {
			writeJSON(w, http.StatusServiceUnavailable, apexError{Error: "dashboard_unreachable"})
			return
		}
		ticket := auth.IssueProxyTicket(a.Config, auth.ProxyIdentity{UnionID: session.UnionID, MachineID: machineID})
		writeJSON(w, http.StatusOK, openURLResponse{OpenURL: MachineBaseURL(a.Config, machineID) + "/__open?ticket=" + encodeURIComponentJS(ticket)})
	}
	// Tunnel on this pod and owned by the caller: issue directly (an
	// in-memory comparison saves one authoritative read).
	live, local := a.Registry.Get(machineID)
	if local && live.UnionID == session.UnionID {
		issue()
		return
	}
	// Otherwise the authoritative record decides (owner or co-manager).
	// Degraded store -> 503; no access -> 404, so the response never reveals
	// that a machine exists but belongs to someone else.
	if _, _, err := auth.LookupMachineAccess(r.Context(), a.Repository, machineID, session.UnionID, store.AuthorityCacheOptions{}); err != nil {
		if errors.Is(err, auth.ErrMachineAccessDenied) {
			writeJSON(w, http.StatusNotFound, apexError{Error: "machine_not_found"})
		} else {
			writeJSON(w, http.StatusServiceUnavailable, apexError{Error: "store_unavailable"})
		}
		return
	}
	// Online on this pod, or on another pod via the Redis route (the proxy
	// then forwards across pods).
	if local || a.machineRouted(r.Context(), machineID) {
		issue()
		return
	}
	writeJSON(w, http.StatusConflict, apexError{Error: "machine_offline"})
}

// openMachineRedirect is GET /open/:id, the friendly "open terminal" hop used
// by the read-only terminal banner: log in if needed, then issue a proxy
// ticket and land on the machine's /__open with next.
func (a *Apex) openMachineRedirect(w http.ResponseWriter, r *http.Request, session *auth.SessionPayload, sessionErr error, machineID string) {
	// The same WHATWG-URL safety boundary as /__open and device open. The
	// surface is chosen from the sanitized next only, so a bad path can never
	// be routed onto the terminal origin.
	next, ok := auth.SafeProxyNextPath(first(queryParamJS(r.URL.RawQuery, "next"), "/"))
	if !ok {
		next = "/"
	}
	if sessionErr != nil {
		back := "/open/" + machineID + "?next=" + encodeURIComponentJS(next)
		redirectWithCookie(w, r, "/auth/login?next="+encodeURIComponentJS(back), "")
		return
	}
	if _, _, err := auth.LookupMachineAccess(r.Context(), a.Repository, machineID, session.UnionID, store.AuthorityCacheOptions{}); err != nil {
		if errors.Is(err, auth.ErrMachineAccessDenied) {
			text(w, http.StatusForbidden, "无权打开该机器")
		} else {
			text(w, http.StatusServiceUnavailable, "机器归属状态暂不可用，请稍后重试")
		}
		return
	}
	ticket := auth.IssueProxyTicket(a.Config, auth.ProxyIdentity{UnionID: session.UnionID, MachineID: machineID})
	base := machineSurfaceBaseURL(a.Config, machineID, isSharedTerminal(next))
	redirectWithCookie(w, r, base+"/__open?ticket="+encodeURIComponentJS(ticket)+"&next="+encodeURIComponentJS(next), "")
}

// requireOwnedActiveMachine answers 404 unless the machine record exists, is
// owned by unionID and is not a tombstone. Unlike the TS getMachineDoc (which
// folds a degraded store into "missing"), a store failure is a 503: an outage
// must not read as "your machine does not exist".
func (a *Apex) requireOwnedActiveMachine(w http.ResponseWriter, r *http.Request, machineID, unionID string, noStore bool) bool {
	write := writeJSON
	if noStore {
		write = writeJSONNoStore
	}
	if a.Repository == nil {
		write(w, http.StatusServiceUnavailable, apexError{Error: "store_unavailable"})
		return false
	}
	doc, err := a.Repository.GetMachine(r.Context(), machineID)
	if err != nil && !errors.Is(err, store.ErrNotFound) {
		write(w, http.StatusServiceUnavailable, apexError{Error: "store_unavailable"})
		return false
	}
	if err != nil || doc.UnionID != unionID || doc.Retired() {
		write(w, http.StatusNotFound, apexError{Error: "machine_not_found"})
		return false
	}
	return true
}

// machineCoManagers is GET/PUT /api/machines/:id/co-managers
// (DESIGN-machine-comanager.md). The owner grants people who may open the
// dashboard / take over the terminal. Candidates must share a team with the
// owner at grant time; access checks afterwards only read the list (the
// proxy is a hot path). PUT is strict fresh-SSO, like appointing admins.
func (a *Apex) machineCoManagers(w http.ResponseWriter, r *http.Request, session *auth.SessionPayload, machineID string) {
	// MongoDB is the authority here: guessing from a degraded read would
	// treat the list as empty, a silent revocation.
	doc, ok := a.lookupActiveMachine(w, r, machineID)
	if !ok {
		return
	}
	isOwner := doc.UnionID == session.UnionID
	if r.Method == http.MethodGet {
		// The owner sees everyone; a co-manager sees only their own entry and
		// never learns who else shares the machine.
		if !isOwner {
			for _, entry := range doc.CoManagers {
				if entry.UnionID == session.UnionID {
					writeJSON(w, http.StatusOK, coManagersResponse{MachineID: machineID, MachineName: first(doc.DisplayName, doc.Name), OwnerName: doc.OwnerName, IsOwner: false, CoManagers: []store.MachineCoManager{entry}})
					return
				}
			}
			writeJSON(w, http.StatusNotFound, apexError{Error: "machine_not_found"})
			return
		}
		// Owner view: flag people no longer in any shared team so the UI can
		// suggest cleanup (auto-removal on leave is best effort; teams and
		// machines are separate collections without transactions).
		teams, teamsErr := a.Repository.ListTeamsForUser(r.Context(), session.UnionID)
		teammates := map[string]bool{}
		for _, team := range teams {
			for _, member := range team.Members {
				teammates[member] = true
			}
		}
		list := make([]coManagerView, 0, len(doc.CoManagers))
		for _, entry := range doc.CoManagers {
			view := coManagerView{MachineCoManager: entry}
			// A failed team read must not conclude "left the team".
			if teamsErr == nil {
				left := !teammates[entry.UnionID]
				view.LeftTeam = &left
			}
			list = append(list, view)
		}
		writeJSON(w, http.StatusOK, coManagersResponse{MachineID: machineID, MachineName: first(doc.DisplayName, doc.Name), OwnerName: doc.OwnerName, IsOwner: true, CoManagers: list})
		return
	}

	// PUT replaces the whole list. Owner only: a co-manager cannot grant
	// further, so permissions never spread transitively.
	if !isOwner {
		writeJSON(w, http.StatusForbidden, apexError{Error: "owner_only"})
		return
	}
	if !strings.HasPrefix(strings.ToLower(r.Header.Get("Content-Type")), "application/json") {
		writeJSON(w, http.StatusUnsupportedMediaType, apexError{Error: "json_required"})
		return
	}
	body := readJSONObject(r)
	rawIDs, isArray := body["unionIds"].([]any)
	// Optionally also grant "change configuration" (settings / schedules /
	// groups) to newly added people; needs a machine-side botmux that
	// understands dashboard:manage.
	wantManage := body["canManage"] == true
	if !isArray {
		writeJSON(w, http.StatusBadRequest, apexError{Error: "unionIds_required"})
		return
	}
	// Optional per-person role, {unionId: "co-manager" | "viewer"}. Absent
	// (older clients) or absent for a person keeps today's behaviour: a new
	// person becomes a co-manager, an existing entry is kept as it is. A
	// listed role is applied to new and existing people alike, which is how
	// the owner switches someone between co-manager and read-only.
	roles := map[string]string{}
	if rawRoles, present := body["roles"]; present && rawRoles != nil {
		object, isObject := rawRoles.(map[string]any)
		if !isObject {
			writeJSON(w, http.StatusBadRequest, apexError{Error: "invalid_roles"})
			return
		}
		for id, raw := range object {
			role, _ := raw.(string)
			if role != store.CoManagerRoleManager && role != store.CoManagerRoleViewer {
				writeJSON(w, http.StatusBadRequest, apexError{Error: "invalid_roles"})
				return
			}
			roles[id] = role
		}
	}
	unionIDs := make([]string, 0, len(rawIDs))
	for _, raw := range rawIDs {
		if id, ok := raw.(string); ok && trimJS(id) != "" && !contains(unionIDs, id) {
			unionIDs = append(unionIDs, id)
		}
	}
	if len(unionIDs) > auth.ComanagerMax {
		writeJSON(w, http.StatusBadRequest, apexError{Error: "too_many"})
		return
	}
	// The owner cannot list themselves (meaningless, and the UI would offer
	// "remove yourself").
	if contains(unionIDs, session.UnionID) {
		writeJSON(w, http.StatusBadRequest, apexError{Error: "owner_not_allowed"})
		return
	}
	// Candidate gate: everyone must share a team with the owner, otherwise
	// the whole request is refused (no partial success).
	teams, err := a.Repository.ListTeamsForUser(r.Context(), session.UnionID)
	if err != nil {
		writeJSON(w, http.StatusServiceUnavailable, apexError{Error: "store_unavailable"})
		return
	}
	teamByMember := map[string]string{}
	for _, team := range teams {
		for _, member := range team.Members {
			if _, seen := teamByMember[member]; !seen {
				teamByMember[member] = team.ID
			}
		}
	}
	outsiders := make([]string, 0)
	for _, id := range unionIDs {
		if _, ok := teamByMember[id]; !ok {
			outsiders = append(outsiders, id)
		}
	}
	if len(outsiders) > 0 {
		writeJSON(w, http.StatusForbidden, notTeammateResponse{Error: "not_teammate", UnionIDs: outsiders})
		return
	}
	// Existing entries keep grantedAt/grantedBy (reordering must not refresh
	// the grant time); new people are filled in.
	existing := make(map[string]store.MachineCoManager, len(doc.CoManagers))
	for _, entry := range doc.CoManagers {
		existing[entry.UnionID] = entry
	}
	profiles, err := a.Repository.GetUserProfiles(r.Context(), unionIDs)
	if err != nil {
		profiles = nil // names fall back to the unionId prefix
	}
	next := make([]store.MachineCoManager, 0, len(unionIDs))
	for _, id := range unionIDs {
		role, roleListed := roles[id]
		previous, known := existing[id]
		if known && (!roleListed || coManagerRole(previous) == role) {
			next = append(next, previous)
			continue
		}
		entry := store.MachineCoManager{
			UnionID:   id,
			Name:      first(profiles[id].Name, prefix(id, 12)),
			GrantedAt: time.Now().UnixMilli(),
			GrantedBy: session.UnionID,
			ViaTeamID: teamByMember[id],
		}
		if known {
			// A role switch keeps who/when/why of the original grant; only
			// the role and its scopes change.
			entry = previous
			entry.GrantedBy = session.UnionID
		}
		if role == store.CoManagerRoleViewer {
			entry.Role = store.CoManagerRoleViewer
			entry.Scopes = auth.ViewerScopes()
		} else {
			// New co-manager, or a viewer promoted back: the same default
			// grant a new person gets. The legacy empty role is kept so the
			// stored shape of co-managers does not change.
			entry.Role = ""
			entry.Scopes = auth.ComanagerDefaultScopes()
			if wantManage {
				entry.Scopes = append(entry.Scopes, store.DeviceScopeDashboardManage)
			}
		}
		next = append(next, entry)
	}
	// CAS write (re-checks ownership and non-tombstone); a success
	// invalidates the positive cache so a revocation takes effect at once.
	if !a.setCoManagers(w, r, machineID, doc.UnionID, next) {
		return
	}
	viewers := 0
	for _, entry := range next {
		if entry.Role == store.CoManagerRoleViewer {
			viewers++
		}
	}
	slog.Info("machine co-managers updated", "machineId", machineID, "by", session.UnionID, "total", len(next), "viewers", viewers)
	writeJSON(w, http.StatusOK, coManagersUpdateResponse{OK: true, CoManagers: next})
}

// coManagerRole is the effective role of a stored entry: the legacy empty
// role reads as a co-manager.
func coManagerRole(entry store.MachineCoManager) string {
	if entry.Role == store.CoManagerRoleViewer {
		return store.CoManagerRoleViewer
	}
	if entry.Role == "" || entry.Role == store.CoManagerRoleManager {
		return store.CoManagerRoleManager
	}
	return entry.Role
}

// removeMachineCoManager is DELETE /api/machines/:id/co-managers/:unionId:
// the owner may remove anyone; a co-manager may only remove themselves.
func (a *Apex) removeMachineCoManager(w http.ResponseWriter, r *http.Request, session *auth.SessionPayload, machineID, rawTarget string) {
	target, ok := decodeURIComponentJS(rawTarget)
	if !ok {
		// decodeURIComponent throws URIError; the TS server turns any
		// handler exception into this bare 500.
		text(w, http.StatusInternalServerError, "internal error")
		return
	}
	doc, ok := a.lookupActiveMachine(w, r, machineID)
	if !ok {
		return
	}
	isOwner := doc.UnionID == session.UnionID
	if !isOwner && target != session.UnionID {
		writeJSON(w, http.StatusForbidden, apexError{Error: "owner_only"})
		return
	}
	current := doc.CoManagers
	if current == nil {
		current = []store.MachineCoManager{}
	}
	next := make([]store.MachineCoManager, 0, len(current))
	for _, entry := range current {
		if entry.UnionID != target {
			next = append(next, entry)
		}
	}
	if len(next) == len(current) {
		// Idempotent: already absent (double click / concurrent revoke).
		writeJSON(w, http.StatusOK, coManagersUpdateResponse{OK: true, CoManagers: current})
		return
	}
	// The CAS owner is always doc.UnionID: a co-manager leaving is not the
	// owner, but the document written is still the owner's.
	if !a.setCoManagers(w, r, machineID, doc.UnionID, next) {
		return
	}
	slog.Info("machine co-manager removed", "machineId", machineID, "by", session.UnionID, "target", target, "selfLeave", !isOwner)
	writeJSON(w, http.StatusOK, coManagersUpdateResponse{OK: true, CoManagers: next})
}

// lookupActiveMachine reads the authoritative machine record for the
// co-manager endpoints: 503 when the store cannot answer, 404 when missing or
// a tombstone.
func (a *Apex) lookupActiveMachine(w http.ResponseWriter, r *http.Request, machineID string) (store.MachineDoc, bool) {
	if a.Repository == nil {
		writeJSON(w, http.StatusServiceUnavailable, apexError{Error: "store_unavailable"})
		return store.MachineDoc{}, false
	}
	doc, err := a.Repository.LookupMachine(r.Context(), machineID, store.AuthorityCacheOptions{})
	if err != nil && !errors.Is(err, store.ErrNotFound) {
		writeJSON(w, http.StatusServiceUnavailable, apexError{Error: "store_unavailable"})
		return store.MachineDoc{}, false
	}
	if err != nil || doc.Retired() {
		writeJSON(w, http.StatusNotFound, apexError{Error: "machine_not_found"})
		return store.MachineDoc{}, false
	}
	return doc, true
}

// setCoManagers writes the list with the ownership CAS: a lost CAS (machine
// re-bound, retired or gone meanwhile) is 409 machine_changed. A degraded
// store is reported as 503 rather than folded into the CAS answer.
func (a *Apex) setCoManagers(w http.ResponseWriter, r *http.Request, machineID, ownerUnionID string, next []store.MachineCoManager) bool {
	err := a.Repository.SetMachineCoManagers(r.Context(), machineID, ownerUnionID, next)
	switch {
	case err == nil:
		return true
	case errors.Is(err, store.ErrNotFound):
		writeJSON(w, http.StatusConflict, apexError{Error: "machine_changed"})
	default:
		writeJSON(w, http.StatusServiceUnavailable, apexError{Error: "store_unavailable"})
	}
	return false
}

func (a *Apex) unbind(w http.ResponseWriter, r *http.Request, session *auth.SessionPayload, sessionErr error, machineID string) {
	if !requireSession(w, sessionErr) {
		return
	}
	live, liveOK := a.Registry.Get(machineID)
	doc, docErr := a.Repository.GetMachine(r.Context(), machineID)
	if docErr == nil {
		if doc.UnionID != session.UnionID {
			writeJSON(w, http.StatusNotFound, map[string]any{"error": "machine_not_found"})
			return
		}
		// Already a tombstone: unbind is idempotent (repeated click / replay).
		if doc.Retired() && !liveOK {
			writeJSON(w, http.StatusOK, map[string]any{"ok": true})
			return
		}
	} else if !liveOK || live.UnionID != session.UnionID {
		writeJSON(w, http.StatusNotFound, map[string]any{"error": "machine_not_found"})
		return
	}
	if a.KV != nil {
		if err := a.KV.RevokeMachineToken(r.Context(), machineID, time.Now().UnixMilli(), a.Config.MachineTokenTTL); err != nil && a.RoutingConfigured {
			writeJSON(w, http.StatusServiceUnavailable, map[string]any{"error": "revoke_failed"})
			return
		}
	} else if a.RoutingConfigured {
		writeJSON(w, http.StatusServiceUnavailable, map[string]any{"error": "revoke_failed"})
		return
	}
	if liveOK {
		a.Registry.UnbindLocal(machineID)
	} else if r.Header.Get(proxy.ForwardHeader) == "" && a.Routes != nil {
		if route, _ := a.Routes.GetMachineRoute(r.Context(), machineID); route != "" && route != a.Config.SelfPodAddr {
			forward := a.ForwardHTTP
			if forward == nil {
				forward = proxy.ForwardHTTP
			}
			_ = forward(route, w, r)
			return
		}
	}
	// Tombstone instead of delete: the machineId is never reused. Fail closed
	// if it cannot be written (the token is already revoked; users retry).
	if err := a.Repository.RetireMachine(r.Context(), machineID); err != nil {
		writeJSON(w, http.StatusServiceUnavailable, map[string]any{"error": "store_unavailable"})
		return
	}
	_ = a.Repository.RemoveMachineFromTeamBots(r.Context(), machineID)
	if a.Routes != nil {
		_ = a.Routes.DeleteMachineRoute(r.Context(), machineID, "")
	}
	writeJSON(w, http.StatusOK, map[string]any{"ok": true})
}

func requireSession(w http.ResponseWriter, err error) bool {
	if err == nil {
		return true
	}
	writeJSON(w, http.StatusUnauthorized, apexError{Error: "unauthenticated"})
	return false
}

func tunnelControlURL(cfg config.Config, token string) string {
	u, err := url.Parse(cfg.PublicBaseURL)
	if err != nil {
		return cfg.PublicBaseURL + "/tunnel/control?token=" + url.QueryEscape(token)
	}
	if u.Scheme == "https" {
		u.Scheme = "wss"
	} else {
		u.Scheme = "ws"
	}
	u.Path = "/tunnel/control"
	u.RawQuery = url.Values{"token": []string{token}}.Encode()
	return u.String()
}

func randomID(size int) string {
	buf := make([]byte, size)
	_, _ = rand.Read(buf)
	return hex.EncodeToString(buf)
}

// truncate is String.prototype.slice(0, count): it counts UTF-16 code units,
// so a name of emoji is cut where Node cuts it (a split surrogate pair
// becomes U+FFFD, as the Node driver stores it).
func truncate(value string, count int) string {
	return store.JSSliceUTF16(value, count)
}

var (
	openMachinePattern       = regexp.MustCompile(`^/api/machines/([a-f0-9]{8,64})/open$`)
	openRedirectPattern      = regexp.MustCompile(`^/open/([a-f0-9]{8,64})$`)
	renameMachinePattern     = regexp.MustCompile(`^/api/machines/([a-f0-9]{8,64})/rename$`)
	upgradeMachinePattern    = regexp.MustCompile(`^/api/machines/([a-f0-9]{8,64})/upgrade$`)
	workingDirPattern        = regexp.MustCompile(`^/api/machines/([a-f0-9]{8,64})/bots/([A-Za-z0-9_-]+)/working-dir-mode$`)
	unbindPattern            = regexp.MustCompile(`^/api/machines/([a-f0-9]{8,64})/unbind$`)
	mobileSessionsPattern    = regexp.MustCompile(`^/api/machines/([a-f0-9]{8,64})/sessions$`)
	mobileSessionOpenPattern = regexp.MustCompile(`^/api/machines/([a-f0-9]{8,64})/sessions/([^/]+)/open$`)
	coManagersPattern        = regexp.MustCompile(`^/api/machines/([a-f0-9]{8,64})/co-managers$`)
	coManagerOnePattern      = regexp.MustCompile(`^/api/machines/([a-f0-9]{8,64})/co-managers/([^/]+)$`)

	strictMachinePattern    = regexp.MustCompile(`^/api/machines/[a-f0-9]{8,64}/(?:upgrade|unbind)$`)
	strictTeamAdminsPattern = regexp.MustCompile(`^/api/teams/[a-f0-9]{8,64}/admins$`)
	strictCoManagersPattern = regexp.MustCompile(`^/api/machines/[a-f0-9]{8,64}/co-managers(?:/[^/]+)?$`)
	strictTeamInvitePattern = regexp.MustCompile(`^/api/teams/[a-f0-9]{8,64}/invite(?:-user)?$`)
)

// ssoTier is the DESIGN §3.2 fresh-SSO class of a route.
type ssoTier int

const (
	ssoTierNone ssoTier = iota
	// ssoTierRoutine (12h) covers everyday collaborative writes: create /
	// rename / leave a team, join the hall, accept an invite, the bot list,
	// group creation, issue-board settings. Frequent saves must not keep
	// bouncing through Feishu re-authorization.
	ssoTierRoutine
	// ssoTierStrict (10min) covers irreversible, credential-like and durable
	// permission grants: unbind, team deletion, machine upgrade, bind codes,
	// appointing admins, issuing invites, machine co-managers.
	ssoTierStrict
)

// freshSSOTier is the TS freshSsoTier(pathname, method). Ordinary GETs keep
// the legacy cookie behaviour.
func freshSSOTier(path, method string) ssoTier {
	if path == "/api/bind-code" && method == http.MethodPost {
		return ssoTierStrict
	}
	if strictMachinePattern.MatchString(path) && method == http.MethodPost {
		return ssoTierStrict
	}
	// Deleting a team is irreversible; it must match before the routine
	// team-write blanket below.
	if deleteTeamPattern.MatchString(path) && method == http.MethodDelete {
		return ssoTierStrict
	}
	// Durable permission grants stay strict as well: admins can change team
	// settings and force-detach/archive issues; an invite is a 30-day
	// multi-use bearer link that would turn a short session compromise into
	// a long-lived team membership.
	if strictTeamAdminsPattern.MatchString(path) && method == http.MethodPut {
		return ssoTierStrict
	}
	// Co-managers may open the owner's dashboard and drive the owner's CLI:
	// heavier than a team admin, so the same strict class.
	if strictCoManagersPattern.MatchString(path) && (method == http.MethodPut || method == http.MethodDelete) {
		return ssoTierStrict
	}
	if strictTeamInvitePattern.MatchString(path) && method == http.MethodPost {
		return ssoTierStrict
	}
	if hasPathPrefix(path, "/api/teams") {
		switch method {
		case http.MethodPost, http.MethodPut, http.MethodPatch, http.MethodDelete:
			return ssoTierRoutine
		}
	}
	// Platform-bot group creation is an invite-like collaborative write.
	if path == "/api/groups/create" && method == http.MethodPost {
		return ssoTierRoutine
	}
	return ssoTierNone
}

// enforceFreshSSO writes the gate's rejection and reports whether the
// request may proceed.
func (a *Apex) enforceFreshSSO(w http.ResponseWriter, r *http.Request, tier ssoTier) bool {
	principal, err := a.ReadPrincipal(r)
	if err != nil {
		writePrincipalError(w, err, false)
		return false
	}
	if principal == nil {
		writeJSON(w, http.StatusUnauthorized, apexError{Error: "unauthenticated"})
		return false
	}
	if principal.Kind == auth.PrincipalDevice {
		writeJSON(w, http.StatusForbidden, apexError{Error: "sso_required"})
		return false
	}
	var passed *auth.SessionPayload
	if tier == ssoTierRoutine {
		passed = auth.RequireRoutineSSO(principal, time.Now())
	} else {
		passed = auth.RequireFreshSSO(principal, time.Now())
	}
	if passed == nil {
		writeJSON(w, http.StatusUnauthorized, staleSessionResponse{Error: "stale_session", LoginURL: "/auth/login"})
		return false
	}
	// CSRF: high-risk writes only accept the platform's own exact origin.
	// Freshness is judged first so an expired login keeps getting
	// stale_session; only a fresh session reaches the Origin check. Browsers
	// send Origin on same-origin fetches, so a missing Origin (including
	// non-browser callers) fails closed too.
	// An unparsable PUBLIC_BASE_URL has the opaque origin "null", which a
	// sandboxed page can send; it must never match.
	if want := urlOrigin(a.Config.PublicBaseURL); want == "null" || r.Header.Get("Origin") != want {
		writeJSON(w, http.StatusForbidden, apexError{Error: "bad_origin"})
		return false
	}
	return true
}

// writePrincipalError maps a ReadPrincipal rejection like the TS routes do:
// conflicting credentials 400, a degraded device authority 503
// store_unavailable (fail closed), anything else 401 with its code.
func writePrincipalError(w http.ResponseWriter, err error, noStore bool) {
	write := writeJSON
	if noStore {
		write = writeJSONNoStore
	}
	var principalErr auth.PrincipalError
	if !errors.As(err, &principalErr) || principalErr == auth.ErrDeviceUnavailable {
		write(w, http.StatusServiceUnavailable, apexError{Error: "store_unavailable"})
		return
	}
	if principalErr == auth.ErrConflictingCredentials {
		write(w, http.StatusBadRequest, apexError{Error: string(principalErr)})
		return
	}
	write(w, http.StatusUnauthorized, apexError{Error: string(principalErr)})
}

// urlOrigin is `new URL(value).origin` for http(s): lowercase scheme and
// host, default port dropped.
func urlOrigin(value string) string {
	u, err := url.Parse(value)
	if err != nil || u.Host == "" {
		return "null"
	}
	scheme := strings.ToLower(u.Scheme)
	host := strings.ToLower(u.Hostname())
	if strings.Contains(host, ":") {
		host = "[" + host + "]"
	}
	port := u.Port()
	if (scheme == "http" && port == "80") || (scheme == "https" && port == "443") {
		port = ""
	}
	if port != "" {
		host += ":" + port
	}
	return scheme + "://" + host
}

// readJSONObject is `await readJson(req)` read as an object: nil (so every
// field lookup is undefined) for an empty, invalid, oversized or non-object
// body. Typed fields are then checked with `typeof`-like assertions.
func readJSONObject(r *http.Request) map[string]any {
	var value any
	if !readJSON(r, &value) {
		return nil
	}
	object, _ := value.(map[string]any)
	return object
}

// queryParamJS is `url.searchParams.get(name) || ”` (WHATWG urlencoded
// parsing: '+' is a space, malformed escapes stay literal), which
// url.ParseQuery would reject or drop.
func queryParamJS(rawQuery, name string) string {
	for _, part := range strings.Split(rawQuery, "&") {
		if part == "" {
			continue
		}
		key, value, _ := strings.Cut(part, "=")
		if formDecodeJS(key) == name {
			return formDecodeJS(value)
		}
	}
	return ""
}

func formDecodeJS(value string) string {
	value = strings.ReplaceAll(value, "+", " ")
	if !strings.Contains(value, "%") {
		return value
	}
	out := make([]byte, 0, len(value))
	for i := 0; i < len(value); i++ {
		if b, ok := percentByte(value, i); ok {
			out = append(out, b)
			i += 2
			continue
		}
		out = append(out, value[i])
	}
	return strings.ToValidUTF8(string(out), "\uFFFD")
}

// trimJS is String#trim (JS whitespace and line terminators, including
// U+FEFF, which strings.TrimSpace keeps, and excluding U+0085, which it
// strips).
func trimJS(value string) string {
	return strings.TrimFunc(value, func(r rune) bool {
		switch r {
		case '\t', '\n', '\v', '\f', '\r', ' ', '\u00a0', '\u1680', '\u2028', '\u2029', '\u202f', '\u205f', '\u3000', '\ufeff':
			return true
		}
		return r >= '\u2000' && r <= '\u200a'
	})
}

// writeLinkURL is the subset of WHATWG URL used on a dashboard write-link.
// net/url is stricter than WHATWG on exotic input (such links are reported
// as invalid_write_link); for ordinary absolute http(s) links the getters
// below serialize like the URL object.
type writeLinkURL struct{ u *url.URL }

var specialURLSchemes = map[string]bool{"http": true, "https": true, "ws": true, "wss": true, "ftp": true, "file": true}

// parseAbsoluteURL is `new URL(raw)` without a base: a relative reference
// (no scheme) throws.
func parseAbsoluteURL(raw string) (writeLinkURL, bool) {
	// WHATWG strips leading/trailing C0 controls and spaces, and removes tab
	// and newline characters anywhere.
	raw = strings.TrimFunc(raw, func(r rune) bool { return r <= 0x20 })
	raw = strings.NewReplacer("\t", "", "\n", "", "\r", "").Replace(raw)
	u, err := url.Parse(raw)
	if err != nil || u.Scheme == "" {
		return writeLinkURL{}, false
	}
	if specialURLSchemes[u.Scheme] && u.Scheme != "file" && u.Host == "" {
		return writeLinkURL{}, false
	}
	return writeLinkURL{u: u}, true
}

func (l writeLinkURL) pathname() string {
	if l.u.Opaque != "" {
		return l.u.Opaque
	}
	path := l.u.EscapedPath()
	if path == "" && specialURLSchemes[l.u.Scheme] {
		return "/"
	}
	return path
}

// searchWithout is `searchParams.delete(...)` then `.search`: deleting
// re-serializes the remaining query as form-urlencoded, and an empty query
// disappears entirely.
func (l writeLinkURL) searchWithout(names ...string) string {
	var parts []string
	for _, part := range strings.Split(l.u.RawQuery, "&") {
		if part == "" {
			continue
		}
		key, value, _ := strings.Cut(part, "=")
		key, value = formDecodeJS(key), formDecodeJS(value)
		if contains(names, key) {
			continue
		}
		parts = append(parts, formEncodeJS(key)+"="+formEncodeJS(value))
	}
	if len(parts) == 0 {
		return ""
	}
	return "?" + strings.Join(parts, "&")
}

func (l writeLinkURL) hash() string {
	if l.u.Fragment == "" {
		return ""
	}
	return "#" + l.u.EscapedFragment()
}

// href is URL#toString: lowercase host, default port dropped, "/" for an
// empty special path.
func (l writeLinkURL) href() string {
	u := l.u
	out := u.Scheme + ":"
	if u.Opaque != "" {
		out += u.Opaque
	} else {
		if u.Host != "" || specialURLSchemes[u.Scheme] {
			out += "//"
			if u.User != nil {
				out += u.User.String() + "@"
			}
			host := strings.ToLower(u.Hostname())
			if strings.Contains(host, ":") {
				host = "[" + host + "]"
			}
			port := u.Port()
			if defaultPort := map[string]string{"http": "80", "https": "443", "ws": "80", "wss": "443", "ftp": "21"}[u.Scheme]; port == defaultPort {
				port = ""
			}
			if port != "" {
				host += ":" + port
			}
			out += host
		}
		out += l.pathname()
	}
	if u.ForceQuery || u.RawQuery != "" {
		out += "?" + u.RawQuery
	}
	if u.Fragment != "" {
		out += "#" + u.EscapedFragment()
	}
	return out
}

type apexError struct {
	Error string `json:"error"`
}

type okError struct {
	OK    bool   `json:"ok"`
	Error string `json:"error"`
}

type staleSessionResponse struct {
	Error    string `json:"error"`
	LoginURL string `json:"loginUrl"`
}

type meResponse struct {
	UnionID string `json:"unionId"`
	Name    string `json:"name"`
	// Old/dev sessions have no avatar; JSON.stringify omits the undefined.
	Avatar string `json:"avatar,omitempty"`
}

type bindCodeResponse struct {
	Code         string `json:"code"`
	ExpiresInSec int64  `json:"expiresInSec"`
	Command      string `json:"command"`
}

type machinesResponse struct {
	Machines        []MachineView `json:"machines"`
	ManagedMachines []MachineView `json:"managedMachines"`
	LatestVersion   *string       `json:"latestVersion"`
}

type deviceMachinesResponse struct {
	Machines []deviceMachineView `json:"machines"`
}

type renameMachineResponse struct {
	OK   bool   `json:"ok"`
	Name string `json:"name"`
}

type openURLResponse struct {
	OpenURL string `json:"openUrl"`
}

type externalURLResponse struct {
	ExternalURL string `json:"externalUrl"`
}

// coManagerView is the owner's `{...entry, leftTeam}`; leftTeam is undefined
// (omitted) when the team read failed.
type coManagerView struct {
	store.MachineCoManager
	LeftTeam *bool `json:"leftTeam,omitempty"`
}

type coManagersResponse struct {
	MachineID   string `json:"machineId"`
	MachineName string `json:"machineName"`
	OwnerName   string `json:"ownerName"`
	IsOwner     bool   `json:"isOwner"`
	CoManagers  any    `json:"coManagers"`
}

type coManagersUpdateResponse struct {
	OK         bool                     `json:"ok"`
	CoManagers []store.MachineCoManager `json:"coManagers"`
}

type notTeammateResponse struct {
	Error    string   `json:"error"`
	UnionIDs []string `json:"unionIds"`
}
