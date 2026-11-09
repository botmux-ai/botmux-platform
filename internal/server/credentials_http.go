package server

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"log/slog"
	"math"
	"net/http"
	"net/url"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/botmux-ai/botmux-platform/internal/auth"
	"github.com/botmux-ai/botmux-platform/internal/credential"
	"github.com/botmux-ai/botmux-platform/internal/feishu"
	"github.com/botmux-ai/botmux-platform/internal/store"
)

// Credential vault HTTP (src/server/credentials-http.ts,
// machine-credentials-http.ts, src/auth/credential-providers.ts;
// DESIGN-credential-vault.md). Owned by Phase 2 agent B3.
//
// "My credentials" SSO surface — a self-authenticating module like devices:
//
//	GET    /api/credentials                       my credentials + teams + an in-flight device login
//	POST   /api/credentials/lark-cli/authorize    strict fresh SSO + Origin → Feishu authorize URL (state carries the credential mount)
//	GET    /auth/callback (credential=lark-cli)   routed here by apex → handleLarkCredentialCallback
//	POST   /api/credentials/:device/authorize     strict → start a device login, return link + pendingId
//	POST   /api/credentials/:device/complete      routine → poll for completion
//	PUT    /api/credentials/:platform/consent     routine → {teams: 'all' | [teamId]}
//	DELETE /api/credentials/:platform             strict → revoke
//	GET    /api/credentials/grants?limit=         recent issuance audit
//
// Authorize/revoke grant or drop a standing permission and use the strict
// (10 minute) window; consent edits and polling use routine. Every write
// checks Origin, the platform's CSRF defence.

// CredentialsDeps holds credential-module seams (provider runners, clocks)
// that are not shared Apex authorities. Nil fields fall back to the Apex
// config / Feishu client, so a bare Apex behaves like production.
type CredentialsDeps struct {
	// Providers mint short-lived tokens and drive device logins. Config is
	// always the Apex config; nil Keys / Feishu use their defaults.
	Providers credential.Providers
	// ExchangeCode is the OAuth v2 credential code exchange.
	ExchangeCode func(ctx context.Context, code string) (feishu.User, feishu.CredentialTokenBundle, error)
	// ListUserScopes lists the platform app's enabled user scopes ("empty
	// LARK_CREDENTIAL_SCOPES = app default").
	ListUserScopes func(ctx context.Context) ([]string, error)
	// Mint replaces the providers for /v1/machine/credential-grant (tests).
	Mint func(ctx context.Context, doc store.CredentialDoc) credential.MintResult
	// Notify sends the first-use-on-a-new-machine DM.
	Notify func(ctx context.Context, unionID string, info feishu.CredentialFirstUseMessage) error
	// GrantLimiter rate-limits grants per machine; nil uses the process-wide one.
	GrantLimiter *CredentialGrantLimiter
	// Now is the clock; nil is time.Now.
	Now func() time.Time
}

const credentialsPagePath = "/credentials"

var (
	credentialPlatformRoute = regexp.MustCompile(`^/api/credentials/([a-z-]+)(?:/([a-z]+))?$`)
	credentialPendingID     = regexp.MustCompile(`^cp_[a-f0-9]{24}$`)
	credentialConsentTeamID = regexp.MustCompile(`^[A-Za-z0-9_-]{1,64}$`)
)

func (a *Apex) credentialNow() time.Time {
	if a.Credentials.Now != nil {
		return a.Credentials.Now()
	}
	return time.Now()
}

func (a *Apex) credentialProviders() credential.Providers {
	p := a.Credentials.Providers
	p.Config = a.Config
	if p.Keys == nil {
		p.Keys = credential.ConfigKeySource(a.Config)
	}
	if p.Feishu == nil {
		p.Feishu = a.Feishu
	}
	if p.Now == nil {
		p.Now = a.credentialNow
	}
	return p
}

// credentialKeys is getCredentialKeys: nil when no usable key is available.
func (a *Apex) credentialKeys(ctx context.Context) *credential.Keys {
	source := a.credentialProviders().Keys
	keys, err := source(ctx)
	if err != nil {
		return nil
	}
	return keys
}

// credentialVaultEnabled is vaultEnabled(cfg): the KEK is configured.
func (a *Apex) credentialVaultEnabled() bool {
	return credential.VaultConfigured(a.Config)
}

// credentialsOriginOK: the request Origin must be exactly the public origin.
func (a *Apex) credentialsOriginOK(r *http.Request) bool {
	return r.Header.Get("Origin") == credentialPublicOrigin(a.Config.PublicBaseURL)
}

// credentialPublicOrigin is `new URL(publicBaseUrl).origin` (scheme://host[:port], the
// default port dropped).
func credentialPublicOrigin(base string) string {
	u, err := url.Parse(base)
	if err != nil || u.Scheme == "" || u.Host == "" {
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

// credentialPrincipal is principalOf: a principal error has been answered
// (sent=true); otherwise the principal may be nil (anonymous).
func (a *Apex) credentialPrincipal(w http.ResponseWriter, r *http.Request) (principal *auth.Principal, sent bool) {
	principal, err := a.ReadPrincipal(r)
	if err == nil {
		return principal, false
	}
	var principalErr auth.PrincipalError
	if !errors.As(err, &principalErr) {
		principalErr = auth.ErrDeviceUnavailable
	}
	writeJSONNoStore(w, principalErr.HTTPStatus(), map[string]any{"error": string(principalErr)})
	return nil, true
}

func writeCredentialStaleSession(w http.ResponseWriter) {
	writeJSONNoStore(w, http.StatusUnauthorized, credentialStaleSessionBody{Error: "stale_session", LoginURL: "/auth/login"})
}

type credentialStaleSessionBody struct {
	Error    string `json:"error"`
	LoginURL string `json:"loginUrl"`
}

// credentialErrorBody is `{error, detail}` where TS always sets detail.
type credentialErrorBody struct {
	Error  string `json:"error"`
	Detail string `json:"detail"`
}

// readCredentialJSONFields is TS readJson narrowed to what the credential routes read:
// the members of a JSON object body. An empty, invalid, oversized or
// non-object body yields nil, which every route rejects like `!body`.
func readCredentialJSONFields(r *http.Request) map[string]json.RawMessage {
	var raw json.RawMessage
	if !readJSON(r, &raw) {
		return nil
	}
	trimmed := bytes.TrimSpace(raw)
	if len(trimmed) == 0 || trimmed[0] != '{' {
		return nil
	}
	var fields map[string]json.RawMessage
	if json.Unmarshal(trimmed, &fields) != nil {
		return nil
	}
	return fields
}

// credentialFieldString is `typeof body[name] === 'string'` plus the value.
func credentialFieldString(fields map[string]json.RawMessage, name string) (string, bool) {
	raw := bytes.TrimSpace(fields[name])
	if len(raw) == 0 || raw[0] != '"' {
		return "", false
	}
	var value string
	if json.Unmarshal(raw, &value) != nil {
		return "", false
	}
	return value, true
}

// handleCredentialsAPI serves /api/credentials and /api/credentials/*.
func (a *Apex) handleCredentialsAPI(w http.ResponseWriter, r *http.Request) bool {
	path := r.URL.Path
	if !hasPathPrefix(path, "/api/credentials") {
		return false
	}
	// Writes here are not idempotent with respect to provider state (a
	// consumed code, a rotated login): once started they finish even if the
	// browser goes away, like the Node handler.
	ctx := context.WithoutCancel(r.Context())

	if path == "/api/credentials" && r.Method == http.MethodGet {
		a.listCredentials(ctx, w, r)
		return true
	}
	if path == "/api/credentials/grants" && r.Method == http.MethodGet {
		a.listCredentialGrants(ctx, w, r)
		return true
	}

	match := credentialPlatformRoute.FindStringSubmatch(path)
	if match == nil || !a.Credentials.Providers.Known(match[1]) {
		writeJSONNoStore(w, http.StatusNotFound, map[string]any{"error": "not_found"})
		return true
	}
	platform, action := store.CredentialPlatform(match[1]), match[2]
	if !a.credentialVaultEnabled() {
		writeJSONNoStore(w, http.StatusServiceUnavailable, map[string]any{"error": "credential_vault_disabled"})
		return true
	}
	if !a.credentialsOriginOK(r) {
		writeJSONNoStore(w, http.StatusForbidden, map[string]any{"error": "bad_origin"})
		return true
	}
	principal, sent := a.credentialPrincipal(w, r)
	if sent {
		return true
	}
	if principal != nil && principal.Kind != auth.PrincipalSSO {
		writeJSONNoStore(w, http.StatusForbidden, map[string]any{"error": "sso_required"})
		return true
	}
	now := a.credentialNow()
	switch {
	case action == "authorize" && r.Method == http.MethodPost:
		session := auth.RequireFreshSSO(principal, now)
		if session == nil {
			writeCredentialStaleSession(w)
			return true
		}
		if platform == store.CredentialPlatformLarkCLI {
			a.authorizeLarkCredential(ctx, w, r, session)
		} else {
			a.authorizeDeviceCredential(ctx, w, session, a.Credentials.Providers.DeviceLogin(string(platform)))
		}
	case platform != store.CredentialPlatformLarkCLI && action == "complete" && r.Method == http.MethodPost:
		session := auth.RequireRoutineSSO(principal, now)
		if session == nil {
			writeCredentialStaleSession(w)
			return true
		}
		a.completeDeviceCredential(ctx, w, r, session, a.Credentials.Providers.DeviceLogin(string(platform)))
	case action == "consent" && r.Method == http.MethodPut:
		session := auth.RequireRoutineSSO(principal, now)
		if session == nil {
			writeCredentialStaleSession(w)
			return true
		}
		a.setCredentialConsent(ctx, w, r, session, platform)
	case action == "" && r.Method == http.MethodDelete:
		session := auth.RequireFreshSSO(principal, now)
		if session == nil {
			writeCredentialStaleSession(w)
			return true
		}
		err := a.CredentialStore.Delete(ctx, session.UnionID, platform)
		if err != nil && !errors.Is(err, store.ErrNotFound) {
			writeJSONNoStore(w, http.StatusServiceUnavailable, map[string]any{"error": "store_unavailable"})
			return true
		}
		slog.Info("credential revoked", "unionId", session.UnionID, "platform", string(platform))
		writeJSONNoStore(w, http.StatusOK, credentialRemovedBody{OK: true, Removed: err == nil})
	default:
		writeJSONNoStore(w, http.StatusMethodNotAllowed, map[string]any{"error": "method_not_allowed"})
	}
	return true
}

type credentialRemovedBody struct {
	OK      bool `json:"ok"`
	Removed bool `json:"removed"`
}

type credentialsListBody struct {
	VaultEnabled bool `json:"vaultEnabled"`
	// Providers maps each platform to whether this pod can authorize it.
	Providers map[string]bool `json:"providers"`
	// Platforms are the page cards, in order.
	Platforms   []credentialPlatformBody `json:"platforms"`
	Teams       []credentialTeamBody     `json:"teams"`
	Credentials []credentialBody         `json:"credentials"`
	Pending     *credentialPendingBody   `json:"pending,omitempty"`
}

// credentialPlatformBody is one page card: flow "oauth" redirects (lark-cli),
// "device" opens a login link and polls complete.
type credentialPlatformBody struct {
	Platform    string                     `json:"platform"`
	Flow        string                     `json:"flow"`
	Available   bool                       `json:"available"`
	Title       string                     `json:"title"`
	Description string                     `json:"description"`
	Linked      []credential.LinkedService `json:"linked,omitempty"`
}

type credentialTeamBody struct {
	ID   string `json:"id"`
	Name string `json:"name"`
}

type credentialBody struct {
	Platform          store.CredentialPlatform `json:"platform"`
	Status            store.CredentialStatus   `json:"status"`
	StatusReason      string                   `json:"statusReason,omitempty"`
	ConsentTeams      store.ConsentTeams       `json:"consentTeams"`
	CreatedAt         int64                    `json:"createdAt"`
	UpdatedAt         int64                    `json:"updatedAt"`
	LastUsedAt        int64                    `json:"lastUsedAt,omitempty"`
	LastUsedMachineID string                   `json:"lastUsedMachineId,omitempty"`
	RefreshExpiresAt  int64                    `json:"refreshExpiresAt,omitempty"`
	Meta              credentialMetaBody       `json:"meta"`
}

// credentialMetaBody exposes only the display metadata (account, appId), in
// that order; the scope list stays server-side.
type credentialMetaBody struct {
	Account string `json:"account,omitempty"`
	AppID   string `json:"appId,omitempty"`
}

type credentialPendingBody struct {
	Platform  string `json:"platform"`
	ID        string `json:"id"`
	AuthURL   string `json:"authUrl"`
	CreatedAt int64  `json:"createdAt"`
}

// credentialPlatforms lists lark-cli and then the linked device logins.
func (a *Apex) credentialPlatforms() []credentialPlatformBody {
	out := []credentialPlatformBody{{
		Platform: string(store.CredentialPlatformLarkCLI), Flow: "oauth", Available: a.Config.FeishuAppID != "",
		Title: "飞书", Description: "访问飞书文档、日历与消息等服务。",
	}}
	for _, provider := range a.Credentials.Providers.DeviceLogins {
		d := provider.Descriptor()
		out = append(out, credentialPlatformBody{
			Platform: d.Platform, Flow: "device", Available: provider.Available(),
			Title: d.Title, Description: d.Description, Linked: d.Linked,
		})
	}
	return out
}

func (a *Apex) listCredentials(ctx context.Context, w http.ResponseWriter, r *http.Request) {
	principal, sent := a.credentialPrincipal(w, r)
	if sent {
		return
	}
	session := auth.RequireSSO(principal)
	if session == nil {
		writeJSONNoStore(w, http.StatusUnauthorized, map[string]any{"error": "unauthenticated"})
		return
	}
	var teams []store.TeamDoc
	teamsErr := store.ErrUnavailable
	if a.Repository != nil {
		teams, teamsErr = a.Repository.ListTeamsForUser(ctx, session.UnionID)
	}
	vaultEnabled := a.credentialVaultEnabled()
	var creds []store.CredentialDoc
	var credsErr, pendingErr error
	var pending *store.CredentialPendingDoc
	if vaultEnabled {
		creds, credsErr = a.CredentialStore.ListForUser(ctx, session.UnionID)
		doc, err := a.CredentialStore.GetPendingForUser(ctx, session.UnionID)
		switch {
		case err == nil:
			pending = &doc
		case !errors.Is(err, store.ErrNotFound):
			pendingErr = err
		}
	}
	if teamsErr != nil || credsErr != nil || pendingErr != nil {
		writeJSONNoStore(w, http.StatusServiceUnavailable, map[string]any{"error": "store_unavailable"})
		return
	}
	platforms := a.credentialPlatforms()
	body := credentialsListBody{
		VaultEnabled: vaultEnabled,
		Providers:    make(map[string]bool, len(platforms)),
		Platforms:    platforms,
		Teams:        make([]credentialTeamBody, 0, len(teams)),
		Credentials:  make([]credentialBody, 0, len(creds)),
	}
	for _, p := range platforms {
		body.Providers[p.Platform] = p.Available
	}
	for _, team := range teams {
		body.Teams = append(body.Teams, credentialTeamBody{ID: team.ID, Name: team.Name})
	}
	for _, c := range creds {
		body.Credentials = append(body.Credentials, credentialBody{
			Platform: c.Platform, Status: c.Status, StatusReason: c.StatusReason, ConsentTeams: c.ConsentTeams,
			CreatedAt: c.CreatedAt, UpdatedAt: c.UpdatedAt, LastUsedAt: c.LastUsedAt, LastUsedMachineID: c.LastUsedMachineID,
			RefreshExpiresAt: c.RefreshExpiresAt,
			Meta:             credentialMetaBody{Account: c.Meta.Account, AppID: c.Meta.AppID},
		})
	}
	if pending != nil {
		body.Pending = &credentialPendingBody{Platform: string(pending.Platform), ID: pending.ID, AuthURL: pending.AuthURL, CreatedAt: pending.CreatedAt}
	}
	writeJSONNoStore(w, http.StatusOK, body)
}

type credentialGrantsBody struct {
	Grants []credentialGrantBody `json:"grants"`
}

type credentialGrantBody struct {
	At           int64                        `json:"at"`
	Platform     store.CredentialPlatform     `json:"platform"`
	MachineID    string                       `json:"machineId"`
	MachineName  string                       `json:"machineName"`
	OwnerUnionID string                       `json:"ownerUnionId"`
	AppID        string                       `json:"appId"`
	Outcome      store.CredentialGrantOutcome `json:"outcome"`
	Reason       string                       `json:"reason,omitempty"`
}

func (a *Apex) listCredentialGrants(ctx context.Context, w http.ResponseWriter, r *http.Request) {
	principal, sent := a.credentialPrincipal(w, r)
	if sent {
		return
	}
	session := auth.RequireSSO(principal)
	if session == nil {
		writeJSONNoStore(w, http.StatusUnauthorized, map[string]any{"error": "unauthenticated"})
		return
	}
	grants, err := a.CredentialStore.ListGrantsForUser(ctx, session.UnionID, credentialGrantLimit(r.URL.Query()))
	if err != nil {
		writeJSONNoStore(w, http.StatusServiceUnavailable, map[string]any{"error": "store_unavailable"})
		return
	}
	body := credentialGrantsBody{Grants: make([]credentialGrantBody, 0, len(grants))}
	for _, g := range grants {
		name := g.MachineName
		if name == "" {
			name = g.MachineID
		}
		body.Grants = append(body.Grants, credentialGrantBody{
			At: g.At, Platform: g.Platform, MachineID: g.MachineID, MachineName: name,
			OwnerUnionID: g.OwnerUnionID, AppID: g.AppID, Outcome: g.Outcome, Reason: g.Reason,
		})
	}
	writeJSONNoStore(w, http.StatusOK, body)
}

// credentialGrantLimit is Math.max(1, Math.min(200, Number(limit || 50) || 50)).
func credentialGrantLimit(query url.Values) int {
	raw := query.Get("limit")
	if _, present := query["limit"]; !present || raw == "" {
		return 50
	}
	n := credentialJSNumber(raw)
	if n == 0 || math.IsNaN(n) {
		n = 50
	}
	n = math.Max(1, math.Min(200, n))
	return int(n)
}

// credentialJSNumber is Number(string): whitespace-trimmed decimal, hex/octal/
// binary literals, Infinity; NaN otherwise.
func credentialJSNumber(s string) float64 {
	s = strings.TrimFunc(s, isCredentialJSSpace)
	switch s {
	case "":
		return 0
	case "Infinity", "+Infinity":
		return math.Inf(1)
	case "-Infinity":
		return math.Inf(-1)
	}
	if len(s) > 2 && s[0] == '0' {
		base := 0
		switch s[1] {
		case 'x', 'X':
			base = 16
		case 'o', 'O':
			base = 8
		case 'b', 'B':
			base = 2
		}
		if base != 0 {
			n, err := strconv.ParseUint(s[2:], base, 64)
			if err != nil {
				return math.NaN()
			}
			return float64(n)
		}
	}
	if !jsDecimalLiteral.MatchString(s) {
		return math.NaN()
	}
	f, err := strconv.ParseFloat(s, 64)
	if err != nil && !math.IsInf(f, 0) {
		return math.NaN()
	}
	return f
}

var jsDecimalLiteral = regexp.MustCompile(`^[+-]?(?:[0-9]+\.?[0-9]*|\.[0-9]+)(?:[eE][+-]?[0-9]+)?$`)

func isCredentialJSSpace(r rune) bool {
	switch r {
	case '\t', '\n', '\v', '\f', '\r', ' ',
		'\u00a0', '\u1680', '\u2028', '\u2029', '\u202f', '\u205f', '\u3000', '\ufeff':
		return true
	}
	return r >= '\u2000' && r <= '\u200a'
}

// resolveLarkCredentialScope returns the scope requested for a lark-cli
// authorization, or the wire error code refusing it:
//   - LARK_CREDENTIAL_SCOPES set: that list;
//   - unset: every user scope the platform app has enabled (authorize without
//     a scope only grants basic identity, useless to lark-cli);
//   - either way plus offline_access, without which Feishu returns no
//     refresh_token and the stored credential dies within two hours.
//
// No scope list → refuse rather than store an unusable credential; an app
// without offline_access enabled → refuse with a readable code instead of
// Feishu's authorize page error 20027.
//
// An incremental request (requested non-empty, from a machine's
// `botmux auth request --scope` via /credentials?scope=…) asks for exactly
// what the person already granted plus the missing scopes:
//   - every requested scope must be requestable (in the list above); the ones
//     that are not come back as notEnabled with "scope_not_enabled", because
//     only the platform app's administrator can fix that and Feishu would
//     reject the whole authorize page otherwise;
//   - granted is the existing credential's scope; entries no longer
//     requestable are dropped, and an empty grant (no credential, or none
//     recorded) falls back to the full default list so a first authorization
//     is never narrower than before;
//   - requested scopes survive the 200-scope cap ahead of everything else.
func (a *Apex) resolveLarkCredentialScope(ctx context.Context, requested []string, granted string) (scope, errCode string, notEnabled []string) {
	base := strings.FieldsFunc(a.Config.LarkCredentialScopes, isCredentialJSSpace)
	if len(base) == 0 {
		list := a.Credentials.ListUserScopes
		if list == nil {
			list = func(ctx context.Context) ([]string, error) {
				if a.Feishu == nil {
					return nil, feishu.ErrScopesUnavailable
				}
				return a.Feishu.ListGrantedUserScopes(ctx)
			}
		}
		scopes, err := list(ctx)
		if err != nil || scopes == nil {
			return "", "scope_unavailable", nil
		}
		if !credentialContains(scopes, feishu.OfflineAccessScope) {
			return "", "offline_access_not_enabled", nil
		}
		base = scopes
	}
	base = feishu.WithOfflineAccess(base)
	if len(requested) == 0 {
		return strings.Join(feishu.CapAuthorizeScopes(base), " "), "", nil
	}
	for _, want := range requested {
		if !credentialContains(base, want) {
			notEnabled = append(notEnabled, want)
		}
	}
	if len(notEnabled) > 0 {
		return "", "scope_not_enabled", notEnabled
	}
	kept := []string{}
	for _, have := range strings.FieldsFunc(granted, isCredentialJSSpace) {
		if credentialContains(base, have) {
			kept = append(kept, have)
		}
	}
	if len(kept) == 0 || (len(kept) == 1 && kept[0] == feishu.OfflineAccessScope) {
		kept = base
	}
	merged := feishu.WithOfflineAccess(append(append([]string{}, requested...), kept...))
	return strings.Join(feishu.CapAuthorizeScopes(merged, requested...), " "), "", nil
}

func credentialContains(values []string, want string) bool {
	for _, value := range values {
		if value == want {
			return true
		}
	}
	return false
}

// maxIncrementalScopes bounds an incremental request; botmux sends at most 100.
const maxIncrementalScopes = 100

// larkScopeSyntax is a Feishu scope name (same rule as botmux's catalog check).
var larkScopeSyntax = regexp.MustCompile(`^[a-z0-9_]+(:[a-z0-9_.-]+)+$|^offline_access$`)

// readIncrementalScopes reads the optional {"scopes": [...]} body of
// POST /api/credentials/lark-cli/authorize. No body or no "scopes" member is
// the default (full) authorization; ok=false means the member is malformed.
func readIncrementalScopes(r *http.Request) (scopes []string, ok bool) {
	body := readCredentialJSONFields(r)
	raw, present := body["scopes"]
	if body == nil || !present || string(bytes.TrimSpace(raw)) == "null" {
		return nil, true
	}
	var list []string
	if json.Unmarshal(raw, &list) != nil || len(list) > maxIncrementalScopes {
		return nil, false
	}
	for _, scope := range list {
		scope = strings.TrimSpace(scope)
		if len(scope) > 128 || !larkScopeSyntax.MatchString(scope) {
			return nil, false
		}
		if !credentialContains(scopes, scope) {
			scopes = append(scopes, scope)
		}
	}
	return scopes, true
}

type credentialAuthorizeURLBody struct {
	URL string `json:"url"`
}

func (a *Apex) authorizeLarkCredential(ctx context.Context, w http.ResponseWriter, r *http.Request, session *auth.SessionPayload) {
	if a.Config.FeishuAppID == "" || a.Config.FeishuAppSecret == "" {
		writeJSONNoStore(w, http.StatusServiceUnavailable, map[string]any{"error": "provider_unavailable"})
		return
	}
	requested, valid := readIncrementalScopes(r)
	if !valid {
		writeJSONNoStore(w, http.StatusBadRequest, map[string]any{"error": "invalid"})
		return
	}
	granted := ""
	if len(requested) > 0 {
		doc, err := a.CredentialStore.Get(ctx, session.UnionID, store.CredentialPlatformLarkCLI)
		switch {
		case err == nil:
			granted = doc.Meta.Scope
		case errors.Is(err, store.ErrNotFound), errors.Is(err, store.ErrInvalid):
			// No usable credential yet: a first authorization, full default list.
		default:
			writeJSONNoStore(w, http.StatusServiceUnavailable, map[string]any{"error": "store_unavailable"})
			return
		}
	}
	scope, errCode, notEnabled := a.resolveLarkCredentialScope(ctx, requested, granted)
	if errCode == "scope_not_enabled" {
		slog.Warn("lark credential authorize: requested scopes not enabled on the platform app", "scopes", notEnabled)
		writeJSONNoStore(w, http.StatusConflict, map[string]any{"error": errCode, "scopes": notEnabled})
		return
	}
	if errCode != "" {
		slog.Warn("lark credential authorize: cannot assemble scope", "error", errCode)
		writeJSONNoStore(w, http.StatusServiceUnavailable, map[string]any{"error": errCode})
		return
	}
	redirect := auth.BuildAuthorizeRedirect(a.Config, credentialsPagePath, auth.AuthorizeOptions{
		Credential: auth.OAuthCredentialLarkCLI, Scope: scope,
	})
	w.Header().Set("Set-Cookie", redirect.StateCookie)
	writeJSONNoStore(w, http.StatusOK, credentialAuthorizeURLBody{URL: redirect.URL})
}

type deviceAuthorizeBody struct {
	PendingID string `json:"pendingId"`
	AuthURL   string `json:"authUrl"`
}

func (a *Apex) authorizeDeviceCredential(ctx context.Context, w http.ResponseWriter, session *auth.SessionPayload, provider credential.DeviceLogin) {
	if !provider.Available() {
		writeJSONNoStore(w, http.StatusServiceUnavailable, map[string]any{"error": "provider_unavailable"})
		return
	}
	keys := a.credentialKeys(ctx)
	if keys == nil {
		writeJSONNoStore(w, http.StatusServiceUnavailable, map[string]any{"error": "store_unavailable"})
		return
	}
	platform := provider.Descriptor().Platform
	begun := provider.Begin(ctx)
	if !begun.OK {
		writeJSONNoStore(w, http.StatusBadGateway, credentialErrorBody{Error: "provider_unavailable", Detail: begun.Detail})
		return
	}
	sealed, err := credential.SealPayload(keys, session.UnionID, platform, begun.Payload)
	if err != nil {
		writeJSONNoStore(w, http.StatusServiceUnavailable, map[string]any{"error": "store_unavailable"})
		return
	}
	pending, err := a.CredentialStore.PutPending(ctx, session.UnionID, store.CredentialPlatform(platform), sealed, begun.AuthURL)
	if err != nil {
		writeJSONNoStore(w, http.StatusServiceUnavailable, map[string]any{"error": "store_unavailable"})
		return
	}
	writeJSONNoStore(w, http.StatusOK, deviceAuthorizeBody{PendingID: pending.ID, AuthURL: begun.AuthURL})
}

type deviceCompleteBody struct {
	State   credential.DeviceLoginState `json:"state"`
	AuthURL string                      `json:"authUrl,omitempty"`
	Detail  *string                     `json:"detail,omitempty"`
}

func (a *Apex) completeDeviceCredential(ctx context.Context, w http.ResponseWriter, r *http.Request, session *auth.SessionPayload, provider credential.DeviceLogin) {
	body := readCredentialJSONFields(r)
	pendingID, isString := credentialFieldString(body, "pendingId")
	if body == nil || !isString || !credentialPendingID.MatchString(pendingID) {
		writeJSONNoStore(w, http.StatusBadRequest, map[string]any{"error": "invalid"})
		return
	}
	descriptor := provider.Descriptor()
	platform := descriptor.Platform
	pending, err := a.CredentialStore.GetPending(ctx, session.UnionID, pendingID)
	if errors.Is(err, store.ErrNotFound) || (err == nil && string(pending.Platform) != platform) {
		writeJSONNoStore(w, http.StatusNotFound, map[string]any{"error": "pending_not_found"})
		return
	}
	if err != nil {
		writeJSONNoStore(w, http.StatusServiceUnavailable, map[string]any{"error": "store_unavailable"})
		return
	}
	keys := a.credentialKeys(ctx)
	if keys == nil {
		writeJSONNoStore(w, http.StatusServiceUnavailable, map[string]any{"error": "store_unavailable"})
		return
	}
	plain, opened := credential.OpenPayload(keys, session.UnionID, platform, pending.Sealed)
	defer clear(plain)
	if trimmed := bytes.TrimSpace(plain); !opened || len(trimmed) == 0 || trimmed[0] != '{' || !json.Valid(trimmed) {
		a.CredentialStore.DeletePending(ctx, pending.ID)
		writeJSONNoStore(w, http.StatusConflict, map[string]any{"error": "pending_invalid"})
		return
	}
	done := provider.Complete(ctx, plain)
	if done.State == credential.DeviceLoginAuthorized {
		sealed, err := credential.SealPayload(keys, session.UnionID, platform, done.Payload)
		if err != nil {
			writeJSONNoStore(w, http.StatusServiceUnavailable, map[string]any{"error": "store_unavailable"})
			return
		}
		_, err = a.CredentialStore.Upsert(ctx, store.UpsertCredentialInput{
			UnionID: session.UnionID, Platform: store.CredentialPlatform(platform), Kind: store.CredentialKind(descriptor.Kind),
			Sealed: sealed, Meta: store.CredentialMeta{Account: done.Account}, RefreshExpiresAt: done.LoginExpiresAt,
		})
		if err != nil {
			writeJSONNoStore(w, http.StatusServiceUnavailable, map[string]any{"error": "store_unavailable"})
			return
		}
		a.CredentialStore.DeletePending(ctx, pending.ID)
		slog.Info("credential authorized", "unionId", session.UnionID, "platform", platform)
		writeJSONNoStore(w, http.StatusOK, deviceCompleteBody{State: done.State})
		return
	}
	if done.State == credential.DeviceLoginFailed {
		a.CredentialStore.DeletePending(ctx, pending.ID)
	}
	out := deviceCompleteBody{State: done.State}
	if done.State == credential.DeviceLoginPending {
		out.AuthURL = pending.AuthURL
	} else {
		// `'detail' in done`: failed and unavailable always carry one.
		detail := done.Detail
		out.Detail = &detail
	}
	writeJSONNoStore(w, http.StatusOK, out)
}

type credentialConsentBody struct {
	OK           bool               `json:"ok"`
	ConsentTeams store.ConsentTeams `json:"consentTeams"`
}

type credentialNotInTeamBody struct {
	Error   string   `json:"error"`
	TeamIDs []string `json:"teamIds"`
}

func (a *Apex) setCredentialConsent(ctx context.Context, w http.ResponseWriter, r *http.Request, session *auth.SessionPayload, platform store.CredentialPlatform) {
	body := readCredentialJSONFields(r)
	var consent store.ConsentTeams
	teamsRaw := bytes.TrimSpace(body["teams"])
	if all, isString := credentialFieldString(body, "teams"); isString && all == "all" {
		consent = store.ConsentAll()
	} else if teams, ok := consentTeamList(teamsRaw); ok {
		if a.Repository == nil {
			writeJSONNoStore(w, http.StatusServiceUnavailable, map[string]any{"error": "store_unavailable"})
			return
		}
		mine, err := a.Repository.ListTeamsForUser(ctx, session.UnionID)
		if err != nil {
			writeJSONNoStore(w, http.StatusServiceUnavailable, map[string]any{"error": "store_unavailable"})
			return
		}
		ids := make(map[string]bool, len(mine))
		for _, team := range mine {
			ids[team.ID] = true
		}
		outsiders := []string{}
		for _, id := range teams {
			if !ids[id] {
				outsiders = append(outsiders, id)
			}
		}
		if len(outsiders) > 0 {
			writeJSONNoStore(w, http.StatusForbidden, credentialNotInTeamBody{Error: "not_in_team", TeamIDs: outsiders})
			return
		}
		// [...new Set(teams)]: first occurrence order.
		seen := make(map[string]bool, len(teams))
		unique := []string{}
		for _, id := range teams {
			if !seen[id] {
				seen[id] = true
				unique = append(unique, id)
			}
		}
		consent = store.ConsentToTeams(unique)
	} else {
		writeJSONNoStore(w, http.StatusBadRequest, map[string]any{"error": "invalid"})
		return
	}
	if err := a.CredentialStore.SetConsent(ctx, session.UnionID, platform, consent); err != nil {
		if errors.Is(err, store.ErrNotFound) {
			writeJSONNoStore(w, http.StatusNotFound, map[string]any{"error": "not_found"})
		} else {
			writeJSONNoStore(w, http.StatusServiceUnavailable, map[string]any{"error": "store_unavailable"})
		}
		return
	}
	slog.Info("credential consent updated", "unionId", session.UnionID, "platform", string(platform))
	writeJSONNoStore(w, http.StatusOK, credentialConsentBody{OK: true, ConsentTeams: consent})
}

// consentTeamList accepts a JSON array whose every element is a team id
// string (Array.isArray + every).
func consentTeamList(raw json.RawMessage) ([]string, bool) {
	if len(raw) == 0 || raw[0] != '[' {
		return nil, false
	}
	var items []json.RawMessage
	if json.Unmarshal(raw, &items) != nil {
		return nil, false
	}
	teams := make([]string, 0, len(items))
	for _, item := range items {
		item = bytes.TrimSpace(item)
		if len(item) == 0 || item[0] != '"' {
			return nil, false
		}
		var id string
		if json.Unmarshal(item, &id) != nil || !credentialConsentTeamID.MatchString(id) {
			return nil, false
		}
		teams = append(teams, id)
	}
	return teams, true
}

// handleLarkCredentialCallback is the /auth/callback branch for a state minted
// by the lark-cli credential authorize flow (verified.credential === 'lark-cli').
// The Feishu account behind the code must be the cookie session's person: the
// authorize page was opened while logged in, and a code from another account
// (scanned with a different Feishu login) must never store A's refresh token
// under B.
func (a *Apex) handleLarkCredentialCallback(w http.ResponseWriter, r *http.Request, code string) {
	session, err := auth.ReadSession(a.Config, r)
	if err != nil || session == nil {
		redirectWithCookie(w, r, "/auth/login?next=%2Fcredentials", "")
		return
	}
	if !a.credentialVaultEnabled() {
		redirectWithCookie(w, r, credentialsPagePath+"?error=credential_vault_disabled", "")
		return
	}
	// The code is single-use: once exchanged the result must be stored even
	// if the browser has gone.
	ctx := context.WithoutCancel(r.Context())
	exchange := a.Credentials.ExchangeCode
	if exchange == nil {
		exchange = func(ctx context.Context, code string) (feishu.User, feishu.CredentialTokenBundle, error) {
			if a.Feishu == nil {
				return feishu.User{}, feishu.CredentialTokenBundle{}, feishu.ErrNotConfigured
			}
			return a.Feishu.ExchangeCodeForCredential(ctx, code, a.Config.PublicBaseURL+"/auth/callback")
		}
	}
	user, token, err := exchange(ctx, code)
	if err != nil {
		slog.Error("credential authorize code exchange failed", "error", err)
		text(w, http.StatusBadGateway, "飞书授权失败："+feishu.JSErrorString(err))
		return
	}
	if user.UnionID != session.UnionID {
		slog.Warn("credential authorize account mismatch", "session", session.UnionID, "callback", user.UnionID)
		text(w, http.StatusForbidden, "授权账号与当前登录账号不一致，未保存。请用当前登录的飞书账号重新授权。")
		return
	}
	if token.RefreshToken == "" {
		// Without a refresh_token the credential lives two hours and every
		// later grant would demand a new authorization — exactly what the vault
		// exists to remove. Refuse now and hand the granted scope list (names
		// only, no credential) back to the page: Feishu only returns a
		// refresh_token when offline_access was actually granted, and it may
		// trim the requested scopes.
		granted := token.Scope
		slog.Warn("credential authorize: Feishu returned no refresh_token, not stored",
			"unionId", user.UnionID, "grantedScope", granted,
			"hasOfflineAccess", credentialContains(strings.FieldsFunc(granted, isCredentialJSSpace), feishu.OfflineAccessScope))
		query := "error=no_refresh_token"
		if granted != "" {
			query += "&granted=" + credentialFormEncode(granted)
		}
		redirectWithCookie(w, r, credentialsPagePath+"?"+query, "")
		return
	}
	var refreshExpiresAt int64
	if token.RefreshExpiresAt != 0 {
		refreshExpiresAt = token.RefreshExpiresAt * 1000
	}
	payload := credential.LarkOAuthPayload{
		OAuth:            credential.OAuthV2,
		RefreshToken:     token.RefreshToken,
		AccessToken:      token.AccessToken,
		AccessExpiresAt:  float64(token.ExpiresAt * 1000),
		RefreshExpiresAt: float64(refreshExpiresAt),
	}
	grantedScope := token.Scope
	if grantedScope == "" {
		grantedScope = a.Config.LarkCredentialScopes
	}
	keys := a.credentialKeys(ctx)
	if keys == nil {
		redirectWithCookie(w, r, credentialsPagePath+"?error=store_unavailable", "")
		return
	}
	sealed, err := credential.SealPayload(keys, user.UnionID, string(store.CredentialPlatformLarkCLI), payload)
	if err != nil {
		redirectWithCookie(w, r, credentialsPagePath+"?error=store_unavailable", "")
		return
	}
	// meta: { appId: cfg.feishuAppId, scope?, account: user.name }. appId is
	// never empty here (the authorize step required it and Feishu rejects an
	// exchange without it) and the account always has a display name, so the
	// omitempty meta fields write the same document as TS.
	_, err = a.CredentialStore.Upsert(ctx, store.UpsertCredentialInput{
		UnionID: user.UnionID, Platform: store.CredentialPlatformLarkCLI, Kind: store.CredentialKindLarkOAuth, Sealed: sealed,
		Meta:             store.CredentialMeta{AppID: a.Config.FeishuAppID, Scope: grantedScope, Account: user.Name},
		RefreshExpiresAt: refreshExpiresAt,
	})
	if err != nil {
		redirectWithCookie(w, r, credentialsPagePath+"?error=store_unavailable", "")
		return
	}
	slog.Info("credential authorized", "unionId", user.UnionID, "platform", string(store.CredentialPlatformLarkCLI))
	redirectWithCookie(w, r, credentialsPagePath+"?authorized=lark-cli", "")
}

// credentialFormEncode is URLSearchParams value serialization
// (application/x-www-form-urlencoded: space → '+', only *-._ and
// alphanumerics left as is).
func credentialFormEncode(value string) string {
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

// CredentialGrantLimiter caps credential grants per machine (120 per minute).
// It only guards against a runaway or leaked machine token; the real
// boundary is team membership plus the person's consent.
type CredentialGrantLimiter struct {
	mu      sync.Mutex
	windows map[string]*credentialGrantWindow
}

type credentialGrantWindow struct {
	since int64
	count int
}

const (
	credentialGrantWindowMS = 60_000
	credentialGrantMax      = 120
)

func NewCredentialGrantLimiter() *CredentialGrantLimiter {
	return &CredentialGrantLimiter{windows: map[string]*credentialGrantWindow{}}
}

var defaultCredentialGrantLimiter = NewCredentialGrantLimiter()

// take counts one grant; limited=true carries the ms until the window resets.
func (l *CredentialGrantLimiter) take(machineID string, nowMS int64) (retryAfterMS int64, limited bool) {
	l.mu.Lock()
	defer l.mu.Unlock()
	window := l.windows[machineID]
	if window == nil || nowMS-window.since >= credentialGrantWindowMS {
		l.windows[machineID] = &credentialGrantWindow{since: nowMS, count: 1}
		return 0, false
	}
	if window.count >= credentialGrantMax {
		return window.since + credentialGrantWindowMS - nowMS, true
	}
	window.count++
	return 0, false
}
