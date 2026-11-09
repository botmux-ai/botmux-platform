package server

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"log/slog"
	"net/http"
	"net/url"
	"regexp"
	"strconv"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/botmux-ai/botmux-platform/internal/auth"
	"github.com/botmux-ai/botmux-platform/internal/feishu"
	"github.com/botmux-ai/botmux-platform/internal/store"
)

// Desktop Cloud auth routes (src/server/desktop-auth.ts): the Electron
// loopback PKCE login, its session family (refresh / logout tombstones), the
// Personal-org profile and capability views, relay tokens and the
// desktop-initiated machine bind. Nothing here touches cookie SSO; unknown
// paths answer a JSON 404 rather than the SPA.

var (
	desktopLocalProfileIDPattern = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$`)
	desktopRelayHostIDPattern    = regexp.MustCompile(`^[A-Za-z0-9_-]{16}$`)
	desktopMachineIDPattern      = regexp.MustCompile(`^[a-f0-9]{16,64}$`)
)

// DesktopDeps holds Desktop Cloud seams that are not shared Apex authorities.
type DesktopDeps struct {
	// Now overrides the handler clock (tests); nil means time.Now.
	Now func() time.Time
}

func (a *Apex) desktopNow() time.Time {
	if a.Desktop.Now != nil {
		return a.Desktop.Now()
	}
	return time.Now()
}

// handleDesktopAuth serves /v1/desktop/auth and /v1/desktop/auth/*. Every
// path under the prefix is answered (unknown ones with a JSON 404).
func (a *Apex) handleDesktopAuth(w http.ResponseWriter, r *http.Request) bool {
	path, method := r.URL.EscapedPath(), r.Method
	switch {
	case path == "/v1/desktop/auth/authorize" && method == http.MethodGet:
		a.desktopAuthorize(w, r)
	case path == "/v1/desktop/auth/session" && method == http.MethodPost:
		a.desktopSession(w, r)
	case path == "/v1/desktop/auth/refresh" && method == http.MethodPost:
		a.desktopRefresh(w, r)
	case path == "/v1/desktop/auth/logout" && method == http.MethodPost:
		a.desktopLogout(w, r)
	case path == "/v1/desktop/auth/capabilities" && method == http.MethodPost:
		a.desktopCapabilities(w, r)
	case path == "/v1/desktop/auth/profile" && method == http.MethodPost:
		a.desktopProfile(w, r)
	case path == "/v1/desktop/auth/org" && method == http.MethodPost:
		a.desktopOrg(w, r)
	case path == "/v1/desktop/auth/relay-token" && method == http.MethodPost:
		a.desktopRelayToken(w, r)
	case path == "/v1/desktop/auth/machine-bind" && method == http.MethodPost:
		a.desktopMachineBind(w, r)
	default:
		writeJSONNoStore(w, http.StatusNotFound, map[string]any{"error": "not_found"})
	}
	return true
}

// desktopAuthorize is GET /v1/desktop/auth/authorize: validate the PKCE
// request, then either sign the one-time code directly (DEV_LOGIN) or carry
// the pending request through the Feishu OAuth state.
func (a *Apex) desktopAuthorize(w http.ResponseWriter, r *http.Request) {
	pending, err := auth.ParseDesktopAuthorizeQuery(desktopSearchParams(r.URL.RawQuery))
	if err != nil {
		writeJSONNoStore(w, http.StatusBadRequest, map[string]any{"error": err.Error()})
		return
	}
	if a.Config.DevLogin {
		// Local development: skip Feishu and hand the loopback a code directly.
		code := auth.MintDesktopAuthCodeAt(a.Config, auth.DesktopUser{UnionID: a.Config.DevUnionID, Name: a.Config.DevName}, pending, a.desktopNow())
		redirectDesktop(w, desktopLoopbackRedirect(pending.RedirectURI, code, pending.State), "")
		return
	}
	if a.Config.FeishuAppID == "" || a.Config.FeishuAppSecret == "" {
		text(w, http.StatusInternalServerError, "飞书登录未配置（缺 FEISHU_APP_ID/SECRET）。联调可临时设 DEV_LOGIN=true。")
		return
	}
	redirect := auth.BuildAuthorizeRedirect(a.Config, "/", auth.AuthorizeOptions{Desktop: &pending})
	redirectDesktop(w, redirect.URL, redirect.StateCookie)
}

// desktopSession is POST /v1/desktop/auth/session: one-time code + PKCE
// verifier → session tickets. The code is consumed in MongoDB so it can be
// exchanged exactly once across pods.
func (a *Apex) desktopSession(w http.ResponseWriter, r *http.Request) {
	body := readDeviceBody(r)
	code := body.trimmed("code")
	codeVerifier := body.trimmed("codeVerifier")
	nonce := body.trimmed("nonce")
	redirectURI := body.trimmed("redirectUri")
	state := body.trimmed("state")
	localProfileID := body.trimmed("localProfileId")
	if code == "" || codeVerifier == "" || nonce == "" || redirectURI == "" || state == "" || localProfileID == "" {
		writeJSONNoStore(w, http.StatusBadRequest, map[string]any{"error": "invalid_request"})
		return
	}
	if !auth.IsAllowedDesktopRedirectURI(redirectURI) {
		writeJSONNoStore(w, http.StatusBadRequest, map[string]any{"error": "invalid_redirect_uri"})
		return
	}
	now := a.desktopNow()
	authCode, err := auth.VerifyDesktopAuthCodeAt(a.Config, code, now)
	if err != nil || authCode == nil ||
		authCode.Nonce != nonce || authCode.State != state ||
		authCode.RedirectURI != redirectURI || authCode.LocalProfileID != localProfileID ||
		!auth.VerifyPKCES256(codeVerifier, authCode.CodeChallenge) {
		writeJSONNoStore(w, http.StatusBadRequest, map[string]any{"error": "invalid_grant"})
		return
	}
	if a.DesktopSessions == nil {
		writeJSONNoStore(w, http.StatusServiceUnavailable, map[string]any{"error": "store_unavailable"})
		return
	}
	switch err := a.DesktopSessions.ConsumeDesktopAuthCode(r.Context(), authCode.JTI, authCode.Exp*1000); {
	case errors.Is(err, store.ErrReplayed):
		writeJSONNoStore(w, http.StatusBadRequest, map[string]any{"error": "invalid_grant"})
		return
	case err != nil:
		writeJSONNoStore(w, http.StatusServiceUnavailable, map[string]any{"error": "store_unavailable"})
		return
	}

	session := auth.MintDesktopSessionAt(a.Config, auth.DesktopSessionInput{
		UnionID: authCode.UnionID, Name: authCode.Name, LocalProfileID: authCode.LocalProfileID, LinkedAt: authCode.LinkedAt,
	}, now)
	// Probe the family authority before handing out tickets that the very
	// next request could not use.
	access, err := auth.VerifyDesktopAccessTokenAt(a.Config, session.AccessToken, now)
	if err != nil || access == nil {
		writeJSONNoStore(w, http.StatusServiceUnavailable, map[string]any{"error": "store_unavailable"})
		return
	}
	if _, err := a.DesktopSessions.GetDesktopSessionFamilyStatus(r.Context(), access.SID, store.AuthorityCacheOptions{}); err != nil {
		writeJSONNoStore(w, http.StatusServiceUnavailable, map[string]any{"error": "store_unavailable"})
		return
	}
	writeJSONNoStore(w, http.StatusOK, session)
}

// desktopRefresh is POST /v1/desktop/auth/refresh: a revoked family (logout
// tombstone) can never mint again.
func (a *Apex) desktopRefresh(w http.ResponseWriter, r *http.Request) {
	refreshToken := readDeviceBody(r).trimmed("refreshToken")
	if refreshToken == "" {
		writeJSONNoStore(w, http.StatusBadRequest, map[string]any{"error": "invalid_request"})
		return
	}
	now := a.desktopNow()
	payload, err := auth.VerifyDesktopRefreshTokenAt(a.Config, refreshToken, now)
	if err != nil || payload == nil {
		writeJSONNoStore(w, http.StatusUnauthorized, map[string]any{"error": "invalid_grant"})
		return
	}
	if a.DesktopSessions == nil {
		writeJSONNoStore(w, http.StatusServiceUnavailable, map[string]any{"error": "store_unavailable"})
		return
	}
	status, err := a.DesktopSessions.GetDesktopSessionFamilyStatus(r.Context(), payload.SID, store.AuthorityCacheOptions{})
	if err != nil {
		writeJSONNoStore(w, http.StatusServiceUnavailable, map[string]any{"error": "store_unavailable"})
		return
	}
	if status == store.DesktopFamilyRevoked {
		writeJSONNoStore(w, http.StatusUnauthorized, map[string]any{"error": "invalid_grant"})
		return
	}
	writeJSONNoStore(w, http.StatusOK, auth.MintDesktopSessionAt(a.Config, auth.DesktopSessionInput{
		UnionID: payload.UnionID, Name: payload.Name, LocalProfileID: payload.LocalProfileID,
		ActiveOrgID: payload.ActiveOrgID, CloudProfileID: payload.CloudProfileID,
		LinkedAt: payload.LinkedAt, SessionID: payload.SID,
	}, now))
}

// desktopLogout is POST /v1/desktop/auth/logout: persist the session-family
// tombstone so access and refresh tickets die immediately on every pod.
// Invalid or expired credentials still answer 200 so a local sign-out can
// never deadlock.
func (a *Apex) desktopLogout(w http.ResponseWriter, r *http.Request) {
	body := readDeviceBody(r)
	now := a.desktopNow()
	access, _ := auth.VerifyDesktopAccessTokenAt(a.Config, auth.ParseBearer(r.Header.Get("Authorization")), now)
	refresh, _ := auth.VerifyDesktopRefreshTokenAt(a.Config, body.trimmed("refreshToken"), now)

	type family struct {
		sid         string
		expiresAtMS int64
	}
	var families []family
	if access != nil {
		families = append(families, family{access.SID, access.Exp * 1000})
	}
	if refresh != nil {
		if len(families) > 0 && families[0].sid == refresh.SID {
			families[0].expiresAtMS = max(families[0].expiresAtMS, refresh.Exp*1000)
		} else {
			families = append(families, family{refresh.SID, refresh.Exp * 1000})
		}
	}
	for _, f := range families {
		if a.DesktopSessions == nil || a.DesktopSessions.RevokeDesktopSessionFamily(r.Context(), f.sid, f.expiresAtMS) != nil {
			writeJSONNoStore(w, http.StatusServiceUnavailable, map[string]any{"error": "store_unavailable"})
			return
		}
	}
	writeJSONNoStore(w, http.StatusOK, map[string]any{"ok": true})
}

// desktopCloudView is the capabilities/org response.
type desktopCloudView struct {
	Cloud         auth.DesktopCloudSummary `json:"cloud"`
	Organizations []auth.DesktopOrgSummary `json:"organizations"`
	Capabilities  auth.DesktopCapabilities `json:"capabilities"`
}

func (a *Apex) desktopCloudView(access *auth.DesktopAccessPayload, org auth.DesktopOrgSummary, activeOrgID string) desktopCloudView {
	return desktopCloudView{
		Cloud: auth.DesktopCloudSummary{
			CloudProfileID: access.CloudProfileID,
			UserID:         access.UnionID,
			Email:          auth.SyntheticEmail(access.UnionID),
			DisplayName:    access.Name,
			ActiveOrgID:    activeOrgID,
			ActiveOrgName:  org.Name,
			LinkedAt:       access.LinkedAt,
		},
		Organizations: []auth.DesktopOrgSummary{org},
		Capabilities:  auth.DefaultDesktopCapabilitiesAt(a.Config.RelaySigningSecret != "", a.desktopNow()),
	}
}

// desktopCapabilities is POST /v1/desktop/auth/capabilities.
func (a *Apex) desktopCapabilities(w http.ResponseWriter, r *http.Request) {
	access, ok := a.RequireActiveDesktopAccess(w, r)
	if !ok {
		return
	}
	org := auth.PersonalOrgFor(access.UnionID)
	activeOrgID := org.OrgID
	if access.ActiveOrgID == org.OrgID {
		activeOrgID = access.ActiveOrgID
	}
	writeJSONNoStore(w, http.StatusOK, a.desktopCloudView(access, org, activeOrgID))
}

// desktopProfile is POST /v1/desktop/auth/profile: an independent cloud
// profile with its own session family.
func (a *Apex) desktopProfile(w http.ResponseWriter, r *http.Request) {
	access, ok := a.RequireActiveDesktopAccess(w, r)
	if !ok {
		return
	}
	body := readDeviceBody(r)
	org := auth.PersonalOrgFor(access.UnionID)
	// String(body.orgId || access.activeOrgId || org.orgId).trim() || org.orgId
	activeOrgID := deviceJSTrim(desktopFirstTruthy(body, "orgId", access.ActiveOrgID, org.OrgID))
	if activeOrgID == "" {
		activeOrgID = org.OrgID
	}
	if activeOrgID != org.OrgID {
		writeJSONNoStore(w, http.StatusNotFound, map[string]any{"error": "org_not_found"})
		return
	}
	// The desktop pre-allocates the new profile's local id so the token claim
	// matches where it is stored locally; old clients get an independent
	// server-generated id that can never chain to the source profile/session.
	localProfileID := body.trimmed("localProfileId")
	if localProfileID == "" {
		localProfileID = "cloud-" + desktopRandomUUID()
	}
	if !desktopLocalProfileIDPattern.MatchString(localProfileID) || localProfileID == access.LocalProfileID {
		writeJSONNoStore(w, http.StatusBadRequest, map[string]any{"error": "invalid_local_profile_id"})
		return
	}
	name := deviceJSTrim(desktopFirstTruthy(body, "name", access.Name))
	if name == "" {
		name = access.Name
	}
	writeJSONNoStore(w, http.StatusOK, auth.MintDesktopSessionAt(a.Config, auth.DesktopSessionInput{
		UnionID: access.UnionID, Name: name, LocalProfileID: localProfileID, ActiveOrgID: activeOrgID,
		// Cloud identity is server-assigned and independent even if a buggy
		// client reuses a local id that belonged to another profile.
		CloudProfileID: "dcp_" + desktopRandomBase64URL(18),
	}, a.desktopNow()))
}

// desktopOrg is POST /v1/desktop/auth/org: echo-style active org switch (no
// storage; only the Personal org exists).
func (a *Apex) desktopOrg(w http.ResponseWriter, r *http.Request) {
	access, ok := a.RequireActiveDesktopAccess(w, r)
	if !ok {
		return
	}
	orgID := readDeviceBody(r).trimmed("orgId")
	if orgID == "" {
		writeJSONNoStore(w, http.StatusBadRequest, map[string]any{"error": "invalid_request"})
		return
	}
	org := auth.PersonalOrgFor(access.UnionID)
	if orgID != org.OrgID {
		writeJSONNoStore(w, http.StatusNotFound, map[string]any{"error": "org_not_found"})
		return
	}
	writeJSONNoStore(w, http.StatusOK, a.desktopCloudView(access, org, org.OrgID))
}

// desktopRelayToken is POST /v1/desktop/auth/relay-token: a short-lived
// host-scoped JWT bound to relayHostId and the host's X25519 public key.
func (a *Apex) desktopRelayToken(w http.ResponseWriter, r *http.Request) {
	access, ok := a.RequireActiveDesktopAccess(w, r)
	if !ok {
		return
	}
	if a.Config.RelaySigningSecret == "" {
		writeJSONNoStore(w, http.StatusServiceUnavailable, map[string]any{"error": "relay_unavailable"})
		return
	}
	body := readDeviceBody(r)
	relayHostID := body.str("relayHostId")
	hostPublicKeyB64 := body.str("hostPublicKeyB64")
	if !desktopRelayHostIDPattern.MatchString(relayHostID) || deviceJSLength(hostPublicKeyB64) > 128 {
		writeJSONNoStore(w, http.StatusBadRequest, map[string]any{"error": "invalid_request"})
		return
	}
	issued, ok := auth.MintDesktopRelayTokenAt(a.Config, access, auth.RelayHostInput{RelayHostID: relayHostID, HostPublicKeyB64: hostPublicKeyB64}, a.desktopNow())
	if !ok {
		writeJSONNoStore(w, http.StatusBadRequest, map[string]any{"error": "invalid_relay_host_key"})
		return
	}
	writeJSONNoStore(w, http.StatusOK, struct {
		RelayToken string  `json:"relayToken"`
		ExpiresAt  float64 `json:"expiresAt"`
	}{issued.RelayToken, issued.ExpiresAt})
}

// desktopMachineBind is POST /v1/desktop/auth/machine-bind: Desktop SSO binds
// the same-host daemon directly. Same CAS/tombstone rules as the one-time
// CLI bind: another owner is never displaced and a retired id is never
// resurrected (a fresh id is allocated instead).
func (a *Apex) desktopMachineBind(w http.ResponseWriter, r *http.Request) {
	access, ok := a.RequireActiveDesktopAccess(w, r)
	if !ok {
		return
	}
	machineID := readDeviceBody(r).str("machineId")
	if !desktopMachineIDPattern.MatchString(machineID) {
		writeJSONNoStore(w, http.StatusBadRequest, map[string]any{"error": "invalid_machine_id"})
		return
	}
	if a.Repository == nil {
		writeJSONNoStore(w, http.StatusServiceUnavailable, map[string]any{"error": "store_unavailable"})
		return
	}
	// Same rules as /api/bind: a retired id or one owned by someone else
	// (copied config, shared HOME, image) gets a fresh id; the other owner's
	// record is never touched.
	requestedMachineID := machineID
	result, err := a.Repository.BindMachineCAS(r.Context(), machineID, access.UnionID, access.Name)
	reassigned := false
	if err == nil && (result == store.BindRetired || result == store.BindConflictOwner) {
		reassigned = result == store.BindConflictOwner
		machineID = randomID(16)
		result, err = a.Repository.BindMachineCAS(r.Context(), machineID, access.UnionID, access.Name)
	}
	if err == nil && result == store.BindConflictOwner {
		writeJSONNoStore(w, http.StatusConflict, map[string]any{"error": "machine_owned_by_other"})
		return
	}
	if err != nil || (result != store.BindCreated && result != store.BindRebound) {
		writeJSONNoStore(w, http.StatusServiceUnavailable, map[string]any{"error": "store_unavailable"})
		return
	}
	if reassigned {
		slog.Info("desktop bind reassigned machine id", "requestedMachineId", requestedMachineID, "machineId", machineID, "unionId", access.UnionID)
	}
	writeJSONNoStore(w, http.StatusOK, struct {
		PlatformURL  string `json:"platformUrl"`
		MachineID    string `json:"machineId"`
		MachineToken string `json:"machineToken"`
		Reassigned   bool   `json:"reassigned,omitempty"`
	}{
		a.Config.PublicBaseURL, machineID,
		auth.MintMachineTokenAt(a.Config, auth.MachineIdentity{UnionID: access.UnionID, OwnerName: access.Name, MachineID: machineID}, a.desktopNow()),
		reassigned,
	})
}

// completeDesktopAuthFromFeishuCallback finishes a desktop login on
// /auth/callback once the verified OAuth state carries a desktop mount:
// exchange the Feishu code, sign the one-time desktop code and 302 to the
// loopback. The web session cookie is never written.
func (a *Apex) completeDesktopAuthFromFeishuCallback(w http.ResponseWriter, r *http.Request, code string, desktop *auth.DesktopAuthPending) {
	if desktop == nil || !auth.IsAllowedDesktopRedirectURI(desktop.RedirectURI) {
		text(w, http.StatusBadRequest, "登录校验失败（redirect_uri 无效）")
		return
	}
	var (
		user feishu.User
		err  = feishu.ErrNotConfigured
	)
	if a.Feishu != nil {
		ctx, cancel := context.WithTimeout(r.Context(), 15*time.Second)
		user, _, err = a.Feishu.ExchangeCode(ctx, code)
		cancel()
	}
	if err != nil {
		slog.Error("桌面飞书登录失败", "error", err)
		// String(e) of a JavaScript Error carries the "Error: " prefix.
		text(w, http.StatusBadGateway, "飞书登录失败：Error: "+err.Error())
		return
	}
	if a.Repository != nil {
		profile := store.UserProfile{ID: user.UnionID, Name: user.Name, Avatar: user.Avatar, UpdatedAt: time.Now().UnixMilli()}
		go func() {
			ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			defer cancel()
			_ = a.Repository.UpsertUserProfile(ctx, profile)
		}()
	}
	oneTime := auth.MintDesktopAuthCodeAt(a.Config, auth.DesktopUser{UnionID: user.UnionID, Name: user.Name}, *desktop, a.desktopNow())
	redirectDesktop(w, desktopLoopbackRedirect(desktop.RedirectURI, oneTime, desktop.State), "")
}

// redirectDesktop is the desktop 302: the OAuth state/code travel in
// Location, so browsers and proxies must neither cache it nor leak it as a
// referrer.
func redirectDesktop(w http.ResponseWriter, location, setCookie string) {
	h := w.Header()
	h.Set("Location", location)
	h.Set("Cache-Control", "no-store")
	h.Set("Pragma", "no-cache")
	h.Set("Referrer-Policy", "no-referrer")
	if setCookie != "" {
		h.Add("Set-Cookie", setCookie)
	}
	w.WriteHeader(http.StatusFound)
}

// desktopLoopbackRedirect is buildLoopbackRedirect: new URL(redirectUri) with
// searchParams.set('code') / set('state'), serialized like the WHATWG URL
// (lower-case host, canonical port, form-urlencoded query, an empty fragment
// kept as a trailing '#'). redirectUri already passed
// IsAllowedDesktopRedirectURI, so it has no userinfo or query and the path is
// exactly /auth/callback.
func desktopLoopbackRedirect(redirectURI, code, state string) string {
	u, err := url.Parse(redirectURI)
	if err != nil {
		return redirectURI
	}
	host := strings.ToLower(u.Hostname())
	if strings.Contains(host, ":") {
		host = "[" + host + "]"
	}
	if port, err := strconv.Atoi(u.Port()); err == nil {
		host += ":" + strconv.Itoa(port)
	}
	out := "http://" + host + "/auth/callback?code=" + desktopFormEncode(code) + "&state=" + desktopFormEncode(state)
	if strings.HasSuffix(redirectURI, "#") {
		out += "#"
	}
	return out
}

// desktopFirstTruthy is String(body[key] || fallbacks[0] || ...): the first
// truthy candidate, stringified like JavaScript.
func desktopFirstTruthy(body deviceBody, key string, fallbacks ...string) string {
	if v, _ := body.value(key); deviceJSTruthy(v) {
		return deviceJSString(v)
	}
	for _, f := range fallbacks {
		if f != "" {
			return f
		}
	}
	return ""
}

// desktopSearchParams parses a raw query like URLSearchParams (WHATWG
// application/x-www-form-urlencoded): '+' is a space, malformed escapes stay
// literal and invalid UTF-8 becomes U+FFFD. url.ParseQuery would drop a pair
// with a malformed escape and so fail requests Node accepts.
func desktopSearchParams(rawQuery string) url.Values {
	values := url.Values{}
	for _, part := range strings.Split(rawQuery, "&") {
		if part == "" {
			continue
		}
		name, value, _ := strings.Cut(part, "=")
		key := desktopFormDecode(name)
		values[key] = append(values[key], desktopFormDecode(value))
	}
	return values
}

func desktopFormDecode(value string) string {
	value = strings.ReplaceAll(value, "+", " ")
	out := make([]byte, 0, len(value))
	for i := 0; i < len(value); i++ {
		if value[i] == '%' && i+2 < len(value) {
			if b, err := hex.DecodeString(value[i+1 : i+3]); err == nil {
				out = append(out, b[0])
				i += 2
				continue
			}
		}
		out = append(out, value[i])
	}
	return desktopReplaceInvalidUTF8(string(out))
}

// desktopReplaceInvalidUTF8 substitutes U+FFFD per invalid byte like the
// WHATWG UTF-8 decoder (strings.ToValidUTF8 would collapse a whole run).
func desktopReplaceInvalidUTF8(value string) string {
	if utf8.ValidString(value) {
		return value
	}
	var b strings.Builder
	for i := 0; i < len(value); {
		r, size := utf8.DecodeRuneInString(value[i:])
		if r == utf8.RuneError && size == 1 {
			b.WriteString("\uFFFD")
		} else {
			b.WriteString(value[i : i+size])
		}
		i += size
	}
	return b.String()
}

// desktopFormEncode is the URLSearchParams serializer for one name or value
// (unlike url.QueryEscape it keeps '*' literal and escapes '~').
func desktopFormEncode(value string) string {
	const upperHex = "0123456789ABCDEF"
	var b strings.Builder
	for i := 0; i < len(value); i++ {
		c := value[i]
		switch {
		case c == ' ':
			b.WriteByte('+')
		case c == '*' || c == '-' || c == '.' || c == '_' ||
			(c >= '0' && c <= '9') || (c >= 'A' && c <= 'Z') || (c >= 'a' && c <= 'z'):
			b.WriteByte(c)
		default:
			b.WriteByte('%')
			b.WriteByte(upperHex[c>>4])
			b.WriteByte(upperHex[c&0xF])
		}
	}
	return b.String()
}

// desktopRandomUUID is crypto.randomUUID().
func desktopRandomUUID() string {
	var b [16]byte
	_, _ = rand.Read(b[:])
	b[6] = b[6]&0x0f | 0x40
	b[8] = b[8]&0x3f | 0x80
	h := hex.EncodeToString(b[:])
	return h[0:8] + "-" + h[8:12] + "-" + h[12:16] + "-" + h[16:20] + "-" + h[20:32]
}

// randomBase64URL is crypto.randomBytes(n).toString('base64url').
func desktopRandomBase64URL(n int) string {
	b := make([]byte, n)
	_, _ = rand.Read(b)
	return base64.RawURLEncoding.EncodeToString(b)
}
