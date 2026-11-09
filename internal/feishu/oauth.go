package feishu

import (
	"context"
	"encoding/json"
	"errors"
	"log/slog"
	"math"
	"net/http"
	"net/url"
	"strings"
)

const (
	ContactSearchScope = "contact:user:search"

	appTokenPath     = "/open-apis/auth/v3/app_access_token/internal"
	userTokenPath    = "/open-apis/authen/v1/oidc/access_token"
	userRefreshPath  = "/open-apis/authen/v1/oidc/refresh_access_token"
	userInfoPath     = "/open-apis/authen/v1/user_info"
	tenantTokenPath  = "/open-apis/auth/v3/tenant_access_token/internal"
	appScopesPath    = "/open-apis/application/v6/scopes"
	defaultExpiresIn = 7000

	// OAuthV2TokenPath is used for both the credential code exchange and its
	// renewal (client_id + client_secret, flat response).
	OAuthV2TokenPath = "/open-apis/authen/v2/oauth/token"
	// OfflineAccessScope must be requested explicitly for the new authorize
	// page to return a refresh_token.
	OfflineAccessScope = "offline_access"
	// MaxAuthorizeScopes is Feishu's per-authorize scope limit.
	MaxAuthorizeScopes = 200
)

type UserTokenBundle struct {
	AccessToken string `json:"accessToken"`
	// RefreshToken is empty when Feishu returned none (no offline_access).
	RefreshToken string `json:"refreshToken"`
	// ExpiresAt is epoch seconds.
	ExpiresAt int64 `json:"expiresAt"`
	// RefreshExpiresAt is epoch seconds; 0 (omitted) when Feishu returned none.
	RefreshExpiresAt int64 `json:"refreshExpiresAt,omitempty"`
}

// CredentialTokenBundle is a credential-vault exchange result: it also carries
// the scope Feishu actually granted (space separated) when returned.
type CredentialTokenBundle struct {
	UserTokenBundle
	Scope string `json:"scope,omitempty"`
}

type User struct {
	UnionID string `json:"unionId"`
	OpenID  string `json:"openId"`
	Name    string `json:"name"`
	Avatar  string `json:"avatar,omitempty"`
}

// AuthorizeURL is the legacy login redirect that always requests the search
// scope. The master flow (no scope on plain login, incremental search scope,
// desktop/credential variants) is auth.BuildAuthorizeRedirect.
func (c *Client) AuthorizeURL(redirectURI, state string) string {
	q := url.Values{"app_id": {c.appID}, "redirect_uri": {redirectURI}, "scope": {ContactSearchScope}, "state": {state}}
	return c.baseURL + "/open-apis/authen/v1/authorize?" + q.Encode()
}

func (c *Client) AppAccessToken(ctx context.Context) (string, error) {
	e, err := c.doJSON(ctx, http.MethodPost, appTokenPath, "", jsObj{{"app_id", c.appID}, {"app_secret", c.appSecret}})
	if err != nil {
		return "", err
	}
	token := e.str("app_access_token")
	if !e.ok() || !truthy(e.fields["app_access_token"]) || token == "" {
		return "", e.apiError("飞书 app_access_token 失败: code=" + e.codeText() + " msg=" + e.msgText())
	}
	return token, nil
}

// ExchangeCode is the login code exchange (v1 OIDC with an app token).
func (c *Client) ExchangeCode(ctx context.Context, code string) (User, UserTokenBundle, error) {
	appToken, err := c.AppAccessToken(ctx)
	if err != nil {
		return User{}, UserTokenBundle{}, err
	}
	e, err := c.doJSON(ctx, http.MethodPost, userTokenPath, appToken, jsObj{{"grant_type", "authorization_code"}, {"code", code}})
	if err != nil {
		return User{}, UserTokenBundle{}, err
	}
	d := e.dataOrSelf()
	access := str(d, "access_token")
	if !e.ok() || access == "" {
		return User{}, UserTokenBundle{}, e.apiError("飞书 user_access_token 失败: code=" + e.codeText() + " msg=" + e.msgText())
	}
	now := c.now().Unix()
	token := UserTokenBundle{
		AccessToken:      access,
		RefreshToken:     str(d, "refresh_token"),
		ExpiresAt:        expiresAt(now, d["expires_in"]),
		RefreshExpiresAt: refreshExpiresAt(now, d["refresh_expires_in"]),
	}
	user, err := c.UserInfo(ctx, token.AccessToken)
	if err != nil {
		return User{}, UserTokenBundle{}, err
	}
	return user, token, nil
}

// ExchangeCodeForCredential is the credential-vault code exchange on the OAuth
// v2 token endpoint: v1 OIDC does not return a refresh_token under the new
// authorize page even with offline_access. redirectURI must be the one used
// for the authorize request (PublicBaseURL + "/auth/callback").
func (c *Client) ExchangeCodeForCredential(ctx context.Context, code, redirectURI string) (User, CredentialTokenBundle, error) {
	e, err := c.doJSON(ctx, http.MethodPost, OAuthV2TokenPath, "", jsObj{
		{"grant_type", "authorization_code"},
		{"client_id", c.appID},
		{"client_secret", c.appSecret},
		{"code", code},
		{"redirect_uri", redirectURI},
	})
	if err != nil {
		return User{}, CredentialTokenBundle{}, err
	}
	access, isString := stringValue(e.fields["access_token"])
	if !e.ok() || !isString || access == "" {
		text := jsTrim("飞书 OAuth v2 换票失败: code=" + e.codeText() + " error=" + jsNullishEmpty(e.fields["error"]) + " " + jsNullishEmpty(e.fields["error_description"]))
		return User{}, CredentialTokenBundle{}, e.apiError(text)
	}
	now := c.now().Unix()
	token := CredentialTokenBundle{UserTokenBundle: UserTokenBundle{
		AccessToken:      access,
		RefreshToken:     e.str("refresh_token"),
		ExpiresAt:        expiresAt(now, e.fields["expires_in"]),
		RefreshExpiresAt: refreshExpiresAt(now, e.fields["refresh_token_expires_in"]),
	}}
	token.Scope = e.str("scope")
	user, err := c.UserInfo(ctx, token.AccessToken)
	if err != nil {
		return User{}, CredentialTokenBundle{}, err
	}
	return user, token, nil
}

// RefreshUserToken renews a login user token (v1 OIDC). Any failure means the
// user must log in again.
func (c *Client) RefreshUserToken(ctx context.Context, refreshToken string) (UserTokenBundle, error) {
	appToken, err := c.AppAccessToken(ctx)
	if err != nil {
		return UserTokenBundle{}, err
	}
	e, err := c.doJSON(ctx, http.MethodPost, userRefreshPath, appToken, jsObj{{"grant_type", "refresh_token"}, {"refresh_token", refreshToken}})
	if err != nil {
		return UserTokenBundle{}, err
	}
	d := e.dataOrSelf()
	access := str(d, "access_token")
	if !e.ok() || access == "" {
		return UserTokenBundle{}, e.apiError("")
	}
	now := c.now().Unix()
	next := str(d, "refresh_token")
	if next == "" {
		next = refreshToken
	}
	return UserTokenBundle{
		AccessToken:      access,
		RefreshToken:     next,
		ExpiresAt:        expiresAt(now, d["expires_in"]),
		RefreshExpiresAt: refreshExpiresAt(now, d["refresh_expires_in"]),
	}, nil
}

// expiresAt is now + (Number(expires_in) || 7000).
func expiresAt(now int64, raw json.RawMessage) int64 {
	seconds := jsNumber(raw)
	if seconds == 0 || math.IsNaN(seconds) {
		seconds = defaultExpiresIn
	}
	return int64(float64(now) + seconds)
}

// refreshExpiresAt is now + Number(raw) when finite and positive, else 0.
func refreshExpiresAt(now int64, raw json.RawMessage) int64 {
	seconds := jsNumber(raw)
	if math.IsNaN(seconds) || math.IsInf(seconds, 0) || seconds <= 0 {
		return 0
	}
	return int64(float64(now) + seconds)
}

// WithOfflineAccess trims and de-duplicates scopes (input order kept) and
// appends offline_access when missing.
func WithOfflineAccess(scopes []string) []string {
	out := []string{}
	for _, scope := range scopes {
		value := jsTrim(scope)
		if value != "" && !containsString(out, value) {
			out = append(out, value)
		}
	}
	if !containsString(out, OfflineAccessScope) {
		out = append(out, OfflineAccessScope)
	}
	return out
}

// ParseGrantedUserScopes extracts the enabled user scopes from a
// `GET /open-apis/application/v6/scopes` response body: grant_status 1 and 2
// both count, and only scope_type=user (tenant scopes in an authorize request
// are rejected with 20027). ok=false when the response cannot be used.
func ParseGrantedUserScopes(body []byte) (scopes []string, ok bool) {
	e, parsed := parseEnvelope(body)
	if !parsed || !truthy(body) || !e.ok() {
		return nil, false
	}
	items, isArray := arrayItems(e.dataFields()["scopes"])
	if !isArray {
		return nil, false
	}
	names := []string{}
	for _, item := range items {
		fields := objectFields(item)
		if !truthy(item) || str(fields, "scope_type") != "user" {
			continue
		}
		name, isString := stringValue(fields["scope_name"])
		if !isString {
			continue
		}
		status, isNumber := numberValue(fields["grant_status"])
		if !isNumber || (status != 1 && status != 2) {
			continue
		}
		if !containsString(names, name) {
			names = append(names, name)
		}
	}
	return names, true
}

// ErrScopesUnavailable is returned when the app's scope list cannot be read.
var ErrScopesUnavailable = errors.New("feishu: granted user scopes unavailable")

// ListGrantedUserScopes returns every user scope the platform app currently
// has enabled ("LARK_CREDENTIAL_SCOPES empty = app default"). Any failure is
// ErrScopesUnavailable (or the transport error) so the caller refuses to
// authorize instead of requesting a partial scope set.
func (c *Client) ListGrantedUserScopes(ctx context.Context) ([]string, error) {
	tenant, _, err := c.TenantAccessTokenWithExpiry(ctx)
	if err != nil {
		slog.Warn("feishu tenant_access_token failed", "error", err)
		return nil, err
	}
	body, err := c.getRaw(ctx, appScopesPath, tenant)
	if err != nil {
		slog.Warn("feishu app scope list failed", "error", err)
		return nil, err
	}
	names, ok := ParseGrantedUserScopes(body)
	if !ok {
		e, _ := parseEnvelope(body)
		slog.Warn("feishu app scope list failed", "code", e.codeText(), "msg", e.msgText())
		return nil, ErrScopesUnavailable
	}
	return names, nil
}

// getRaw is a GET returning the raw JSON body (non-JSON is an HTTPError).
func (c *Client) getRaw(ctx context.Context, path, bearer string) ([]byte, error) {
	e, err := c.doJSON(ctx, http.MethodGet, path, bearer, nil)
	if err != nil {
		return nil, err
	}
	return json.Marshal(e.fields)
}

// CapAuthorizeScopes truncates to MaxAuthorizeScopes while keeping
// offline_access (moved to the end when truncation happens). A list within the
// limit is returned unchanged, order included.
//
// When truncation is needed, scopes are kept by priority rather than by the
// order Feishu listed them, so a long app scope list cannot silently drop the
// scopes lark-cli needs most:
//  1. keep — scopes the caller must not lose (an incremental request), in order;
//  2. reads in the everyday domains (base, bitable, docx, docs, wiki, im, drive, sheets);
//  3. writes in those domains;
//  4. reads elsewhere;
//  5. everything else.
//
// Within a tier the input order is kept. keep entries that are not in scopes
// are ignored: the caller decides what is requestable.
func CapAuthorizeScopes(scopes []string, keep ...string) []string {
	if len(scopes) <= MaxAuthorizeScopes {
		return scopes
	}
	present := map[string]bool{}
	for _, scope := range scopes {
		present[scope] = true
	}
	const tiers = 5
	buckets := make([][]string, tiers)
	seen := map[string]bool{OfflineAccessScope: true}
	for _, scope := range keep {
		if present[scope] && !seen[scope] {
			seen[scope] = true
			buckets[0] = append(buckets[0], scope)
		}
	}
	for _, scope := range scopes {
		if seen[scope] {
			continue
		}
		seen[scope] = true
		buckets[authorizeScopeTier(scope)] = append(buckets[authorizeScopeTier(scope)], scope)
	}
	rest := make([]string, 0, MaxAuthorizeScopes)
	for _, bucket := range buckets {
		for _, scope := range bucket {
			if len(rest) < MaxAuthorizeScopes-1 {
				rest = append(rest, scope)
			}
		}
	}
	return append(rest, OfflineAccessScope)
}

// preferredScopeDomains are the domains lark-cli is used for day to day.
var preferredScopeDomains = map[string]bool{
	"base": true, "bitable": true, "docx": true, "docs": true,
	"wiki": true, "im": true, "drive": true, "sheets": true,
}

// authorizeScopeTier is the truncation tier (1–4) of a non-keep scope.
func authorizeScopeTier(scope string) int {
	parts := strings.Split(scope, ":")
	preferred := preferredScopeDomains[parts[0]]
	read := isReadScope(parts[len(parts)-1])
	switch {
	case preferred && read:
		return 1
	case preferred:
		return 2
	case read:
		return 3
	default:
		return 4
	}
}

// isReadScope reports whether a scope's action segment only reads
// (read, readonly, read_only, retrieve, list, search …).
func isReadScope(action string) bool {
	action = strings.ToLower(action)
	return strings.Contains(action, "read") || action == "retrieve" || action == "list" || action == "search"
}

// UserInfo resolves the identity behind a user token: union_id (stable across
// apps) with open_id as the fallback identity.
func (c *Client) UserInfo(ctx context.Context, userToken string) (User, error) {
	e, err := c.doJSON(ctx, http.MethodGet, userInfoPath, userToken, nil)
	if err != nil {
		return User{}, err
	}
	// `res.data || res` is always truthy for a successful (object) response.
	if !e.ok() {
		return User{}, e.apiError("飞书 user_info 失败: code=" + e.codeText() + " msg=" + e.msgText())
	}
	d := e.dataOrSelf()
	identity := str(d, "union_id")
	if identity == "" {
		identity = str(d, "open_id")
	}
	if identity == "" {
		return User{}, errors.New("飞书 user_info 未返回 union_id 或 open_id")
	}
	name := str(d, "name")
	if name == "" {
		name = str(d, "en_name")
	}
	if name == "" {
		name = "飞书用户"
	}
	avatar := str(d, "avatar_url")
	if avatar == "" {
		avatar = str(d, "avatar_thumb")
	}
	return User{UnionID: identity, OpenID: str(d, "open_id"), Name: name, Avatar: avatar}, nil
}
