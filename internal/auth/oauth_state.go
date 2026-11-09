package auth

import (
	"io"
	"strings"
	"time"

	"github.com/botmux-ai/botmux-platform/internal/config"
)

const OAuthStateCookieName = "botmux_oauth_state"

const (
	feishuAuthorizePath = "/open-apis/authen/v1/authorize"
	// FeishuSearchScope is requested only by the incremental "search people"
	// authorization. It is sensitive (Feishu shows a confirmation every time),
	// and basic identity (union_id/open_id/name/avatar) needs no scope at all.
	FeishuSearchScope = "contact:user:search"
	// OAuthCredentialLarkCLI marks a state that belongs to the credential vault
	// authorization flow instead of a login.
	OAuthCredentialLarkCLI = "lark-cli"
	oauthStateTTLSeconds   = 600
)

// OAuthStatePayload is the signed Feishu OAuth state. Optional fields are
// omitted exactly when the TypeScript value is undefined.
type OAuthStatePayload struct {
	Kind  string `json:"kind"`
	Nonce string `json:"nonce"`
	// Next is the post-login same-site path (browser cookie SSO).
	Next string `json:"next"`
	// SearchScope records that this authorize requested contact:user:search;
	// the callback stores it on the session as `ss`.
	SearchScope bool `json:"searchScope,omitempty"`
	// Desktop present: the callback mints a one-time desktop auth code and
	// redirects to the loopback instead of writing a session cookie.
	Desktop *DesktopAuthPending `json:"desktop,omitempty"`
	// Credential present: the callback stores the refresh token in the vault
	// and must not touch the login session.
	Credential string `json:"credential,omitempty"`
	Exp        int64  `json:"exp"`
}

func (p OAuthStatePayload) compatJSON() []byte {
	dst := []byte{'{'}
	first := true
	dst = appendStringField(dst, "kind", p.Kind, &first)
	dst = appendStringField(dst, "nonce", p.Nonce, &first)
	dst = appendStringField(dst, "next", p.Next, &first)
	if p.SearchScope {
		dst = appendBoolJSONField(dst, "searchScope", true, &first)
	}
	if p.Desktop != nil {
		dst = appendFieldName(dst, "desktop", &first)
		dst = p.Desktop.appendCompatJSON(dst)
	}
	if p.Credential != "" {
		dst = appendStringField(dst, "credential", p.Credential, &first)
	}
	dst = appendInt64Field(dst, "exp", p.Exp, &first)
	return append(dst, '}')
}

// AuthorizeOptions selects the authorize variant: Desktop PKCE mount,
// incremental search scope, or a credential-vault authorization with its own
// requested Scope (space separated).
type AuthorizeOptions struct {
	Desktop     *DesktopAuthPending
	SearchScope bool
	Credential  string
	Scope       string
}

// AuthorizeRedirect is the Feishu authorize URL plus the Set-Cookie value that
// carries the state nonce for the callback's double-submit check.
type AuthorizeRedirect struct {
	URL         string
	StateCookie string
}

// BuildAuthorizeRedirect builds the Feishu authorize redirect for a login,
// desktop PKCE or credential authorization (master semantics: a plain login
// requests no scope, so Feishu shows no confirmation dialog).
func BuildAuthorizeRedirect(cfg config.Config, next string, opts AuthorizeOptions) AuthorizeRedirect {
	return buildAuthorizeRedirect(cfg, next, opts, time.Now(), defaultRandom)
}

func buildAuthorizeRedirect(cfg config.Config, next string, opts AuthorizeOptions, now time.Time, random io.Reader) AuthorizeRedirect {
	nonce := randomHexFrom(random, 16)
	statePath := safeNext(next)
	if opts.Desktop != nil {
		statePath = "/"
	}
	payload := OAuthStatePayload{
		Kind:        "oauth-state",
		Nonce:       nonce,
		Next:        statePath,
		SearchScope: opts.SearchScope,
		Desktop:     opts.Desktop,
		Credential:  opts.Credential,
		Exp:         now.Unix() + oauthStateTTLSeconds,
	}
	state := mustIssueCompat(payload.compatJSON(), cfg.SigningSecret)

	// URLSearchParams order and serialization: app_id, redirect_uri, state,
	// then scope only when non-empty.
	query := "app_id=" + formURLEncode(cfg.FeishuAppID) +
		"&redirect_uri=" + formURLEncode(cfg.PublicBaseURL+"/auth/callback") +
		"&state=" + formURLEncode(state)
	var scopes []string
	if opts.SearchScope {
		scopes = append(scopes, FeishuSearchScope)
	}
	if opts.Scope != "" {
		scopes = append(scopes, opts.Scope)
	}
	if scope := jsTrim(strings.Join(scopes, " ")); scope != "" {
		query += "&scope=" + formURLEncode(scope)
	}
	return AuthorizeRedirect{
		URL:         cfg.FeishuHost + feishuAuthorizePath + "?" + query,
		StateCookie: oauthStateCookie(cfg, nonce),
	}
}

// oauthStateCookie uses SameSite=None;Secure on HTTPS: the Feishu webview
// authorize hop is cross-site and Lax cookies are dropped by some webviews.
func oauthStateCookie(cfg config.Config, nonce string) string {
	parts := []string{OAuthStateCookieName + "=" + nonce, "Path=/auth", "HttpOnly", "Max-Age=600"}
	if cfg.CookieSecure {
		parts = append(parts, "SameSite=None", "Secure")
	} else {
		parts = append(parts, "SameSite=Lax")
	}
	return strings.Join(parts, "; ")
}

// VerifiedOAuthState is the decoded callback state.
type VerifiedOAuthState struct {
	Next        string
	SearchScope bool
	Desktop     *DesktopAuthPending
	Credential  string
}

// VerifyState validates a callback state. The state is HMAC-signed with a
// 10-minute lifetime; when the state cookie is present the nonce must match
// (login-CSRF double submit). Feishu's webview often drops the cookie after
// the authorize hop, so a missing cookie falls back to signature-only.
func VerifyState(cfg config.Config, state, cookieNonce string) (*VerifiedOAuthState, error) {
	return VerifyStateAt(cfg, state, cookieNonce, time.Now())
}

func VerifyStateAt(cfg config.Config, state, cookieNonce string, now time.Time) (*VerifiedOAuthState, error) {
	var payload OAuthStatePayload
	if err := VerifyToken(state, cfg.SigningSecret, "oauth-state", now, &payload); err != nil {
		return nil, err
	}
	if cookieNonce != "" && cookieNonce != payload.Nonce {
		return nil, ErrInvalidToken
	}
	return &VerifiedOAuthState{
		Next:        payload.Next,
		SearchScope: payload.SearchScope,
		Desktop:     payload.Desktop,
		Credential:  payload.Credential,
	}, nil
}

// IssueOAuthState mints a plain login state and its nonce cookie. It is kept
// for the existing login handler; new code should use BuildAuthorizeRedirect.
func IssueOAuthState(cfg config.Config, next string) (state, cookie string, err error) {
	nonce := randomHexFrom(defaultRandom, 16)
	payload := OAuthStatePayload{Kind: "oauth-state", Nonce: nonce, Next: safeNext(next), Exp: time.Now().Unix() + oauthStateTTLSeconds}
	return mustIssueCompat(payload.compatJSON(), cfg.SigningSecret), oauthStateCookie(cfg, nonce), nil
}

// VerifyOAuthState returns only the post-login path (legacy login handler).
func VerifyOAuthState(cfg config.Config, state, cookieNonce string) (string, error) {
	verified, err := VerifyState(cfg, state, cookieNonce)
	if err != nil {
		return "", err
	}
	if !safeRelative(verified.Next) {
		return "/", nil
	}
	return verified.Next, nil
}

// safeNext allows only same-site relative paths (open-redirect guard).
func safeNext(next string) string {
	if !safeRelative(next) {
		return "/"
	}
	return next
}

func safeRelative(value string) bool {
	return strings.HasPrefix(value, "/") && !strings.HasPrefix(value, "//")
}
