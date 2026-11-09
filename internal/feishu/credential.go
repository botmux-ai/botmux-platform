package feishu

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"regexp"
	"strings"
	"time"
)

// Credential-vault token renewal (credential-providers.ts refreshViaOauthV2 /
// refreshViaOidcV1). Unlike the login helpers these calls never fail on a
// Feishu answer: every answer is classified as "the refresh token is dead"
// (Reauth) or "transient" so the vault only voids a credential when Feishu
// says so explicitly. Only a transport failure (TS: fetch throws) is an error.

// larkReauthCodes are the Feishu codes that mean the refresh token itself is
// invalid or expired.
var larkReauthCodes = map[float64]bool{20026: true, 20037: true, 20064: true, 20065: true, 20066: true, 20067: true}

var (
	refreshWord      = regexp.MustCompile(`refresh`)
	refreshDeadWords = regexp.MustCompile(`(invalid|expired|not exist|revoked|无效|过期)`)
)

// CredentialRefresh is the outcome of renewing a vault user token.
type CredentialRefresh struct {
	OK bool
	// Reauth (only when !OK) marks a definitive rejection of the refresh
	// token; any other failure must keep the credential.
	Reauth bool
	Detail string

	AccessToken string
	// RefreshToken is the rotated refresh token; "" means Feishu kept the old one.
	RefreshToken string
	// ExpiresInSec is Number(expires_in || 7000).
	ExpiresInSec float64
	// RefreshExpiresInSec is the refresh token lifetime; 0 when not returned.
	RefreshExpiresInSec float64
}

// RefreshCredentialToken renews a vault lark-cli token in the scheme that
// issued it: a refresh token only renews where it was minted. oauthV2 uses
// the OAuth v2 token endpoint (client_id + client_secret); otherwise the
// early v1 OIDC endpoint with an app_access_token. appID is the credential's
// issuing app (meta.appId), the secret is this client's.
func (c *Client) RefreshCredentialToken(ctx context.Context, oauthV2 bool, appID, refreshToken string) (CredentialRefresh, error) {
	if oauthV2 {
		return c.refreshCredentialV2(ctx, appID, refreshToken)
	}
	return c.refreshCredentialOIDC(ctx, appID, refreshToken)
}

func (c *Client) refreshCredentialV2(ctx context.Context, appID, refreshToken string) (CredentialRefresh, error) {
	status, e, err := c.postStatusJSON(ctx, OAuthV2TokenPath, "", jsObj{
		{"grant_type", "refresh_token"}, {"client_id", appID}, {"client_secret", c.appSecret}, {"refresh_token", refreshToken},
	})
	if err != nil {
		return CredentialRefresh{}, err
	}
	if status >= 500 {
		return CredentialRefresh{Detail: fmt.Sprintf("feishu http %d", status)}, nil
	}
	if !e.ok() || !truthy(e.fields["access_token"]) {
		detail := collapseJSWhitespace("feishu refresh rejected: code=" + nullishOr(e.fields["code"], "unknown") + " " +
			jsNullishEmpty(e.fields["error"]) + " " + jsNullishEmpty(e.fields["error_description"]))
		// OAuth invalid_grant = the refresh token is invalid, expired, revoked
		// or already used; anything else is treated as transient.
		grantErr, _ := stringValue(e.fields["error"])
		reauth := grantErr == "invalid_grant" || larkRefreshRejectedForGood(e, e.fields["error_description"])
		return CredentialRefresh{Reauth: reauth, Detail: detail}, nil
	}
	return refreshedTokens(e.fields, "refresh_token_expires_in"), nil
}

func (c *Client) refreshCredentialOIDC(ctx context.Context, appID, refreshToken string) (CredentialRefresh, error) {
	status, app, err := c.postStatusJSON(ctx, appTokenPath, "", jsObj{{"app_id", appID}, {"app_secret", c.appSecret}})
	if err != nil {
		return CredentialRefresh{}, err
	}
	appToken := app.fields["app_access_token"]
	if status >= 500 || !app.ok() || !truthy(appToken) {
		return CredentialRefresh{Detail: fmt.Sprintf("feishu app_access_token failed: http %d code=%s", status, nullishOr(app.fields["code"], "unknown"))}, nil
	}
	status, r, err := c.postStatusJSON(ctx, userRefreshPath, jsString(appToken), jsObj{{"grant_type", "refresh_token"}, {"refresh_token", refreshToken}})
	if err != nil {
		return CredentialRefresh{}, err
	}
	if status >= 500 {
		return CredentialRefresh{Detail: fmt.Sprintf("feishu http %d", status)}, nil
	}
	data := r.dataFields()
	if !r.ok() || !truthy(data["access_token"]) {
		detail := jsTrim("feishu refresh rejected: code=" + nullishOr(r.fields["code"], "unknown") + " " + jsNullishEmpty(r.fields["msg"]))
		return CredentialRefresh{Reauth: larkRefreshRejectedForGood(r, r.fields["msg"]), Detail: detail}, nil
	}
	return refreshedTokens(data, "refresh_expires_in"), nil
}

// refreshedTokens reads a successful token answer (v2: the flat response, v1:
// its data object) with the provider's truthiness rules.
func refreshedTokens(fields map[string]json.RawMessage, refreshLifetimeKey string) CredentialRefresh {
	out := CredentialRefresh{OK: true, AccessToken: jsString(fields["access_token"]), ExpiresInSec: defaultExpiresIn}
	if truthy(fields["refresh_token"]) {
		out.RefreshToken = jsString(fields["refresh_token"])
	}
	if truthy(fields["expires_in"]) {
		out.ExpiresInSec = jsNumber(fields["expires_in"])
	}
	if truthy(fields[refreshLifetimeKey]) {
		out.RefreshExpiresInSec = jsNumber(fields[refreshLifetimeKey])
	}
	return out
}

// larkRefreshRejectedForGood: only an explicit "refresh token invalid /
// expired" answer voids a credential; unknown errors keep it.
func larkRefreshRejectedForGood(e envelope, message json.RawMessage) bool {
	if code, ok := numberValue(e.fields["code"]); ok && larkReauthCodes[code] {
		return true
	}
	m := jsLowerCase(jsOrEmpty(message))
	return refreshWord.MatchString(m) && refreshDeadWords.MatchString(m)
}

// postStatusJSON mirrors the provider's postFeishuJson: the HTTP status is
// returned as is and an unparsable body reads as `{}` (res.json().catch), so
// callers decide on status + fields. Only a transport failure is an error.
func (c *Client) postStatusJSON(ctx context.Context, path, bearer string, body jsObj) (status int, result envelope, resultErr error) {
	started := time.Now()
	operation := feishuOperation(http.MethodPost, path)
	defer func() {
		if resultErr != nil && !errors.Is(resultErr, context.Canceled) {
			logFeishuFailure(operation, time.Since(started), resultErr)
		}
	}()
	ctx, cancel := context.WithTimeout(ctx, apiTimeout)
	defer cancel()
	payload, err := marshalJS(body)
	if err != nil {
		return 0, envelope{}, err
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, c.baseURL+path, bytes.NewReader(payload))
	if err != nil {
		return 0, envelope{}, err
	}
	req.Header.Set("Content-Type", "application/json")
	if bearer != "" {
		req.Header.Set("Authorization", "Bearer "+bearer)
	}
	res, err := c.http.Do(req)
	if err != nil {
		return 0, envelope{}, err
	}
	defer res.Body.Close()
	raw, _ := io.ReadAll(io.LimitReader(res.Body, 4<<20))
	out, ok := parseEnvelope(raw)
	if !ok {
		out = envelope{Code: codeMissing, fields: map[string]json.RawMessage{}}
	}
	if res.StatusCode >= 500 || !out.ok() {
		// Never log the body: token endpoints echo grant details.
		slog.Warn("runtime dependency failure", "dependency", "feishu", "operation", operation, "durationMs", time.Since(started).Milliseconds(), "apiCode", out.Code, "httpStatus", res.StatusCode)
	}
	return res.StatusCode, out, nil
}

// nullishOr is the template `${value ?? fallback}`.
func nullishOr(raw json.RawMessage, fallback string) string {
	if nullish(raw) {
		return fallback
	}
	return jsString(raw)
}

// collapseJSWhitespace is `.replace(/\s+/g, ' ').trim()` with JavaScript's \s.
func collapseJSWhitespace(s string) string {
	return strings.Join(strings.FieldsFunc(s, isJSWhitespace), " ")
}

// JSErrorString renders err the way TS `String(e)` renders the matching
// exception, for texts the Node service builds from a caught error: a Feishu
// API failure is an Error ("Error: <message>"), an aborted fetch an AbortError
// and any other transport failure undici's "TypeError: fetch failed". A
// non-JSON body (TS: a SyntaxError from res.json()) cannot be reproduced byte
// for byte and keeps a generic message.
func JSErrorString(err error) string {
	if err == nil {
		return "undefined"
	}
	var apiErr *APIError
	var httpErr *HTTPError
	switch {
	case errors.As(err, &apiErr):
		return "Error: " + apiErr.Error()
	case errors.As(err, &httpErr):
		return "SyntaxError: Unexpected token in JSON response"
	case errors.Is(err, context.DeadlineExceeded) || errors.Is(err, context.Canceled):
		return "AbortError: This operation was aborted"
	}
	var transport interface{ Timeout() bool }
	if errors.As(err, &transport) {
		return "TypeError: fetch failed"
	}
	return "Error: " + err.Error()
}
