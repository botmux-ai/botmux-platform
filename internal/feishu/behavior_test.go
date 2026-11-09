package feishu

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"math"
	"net/http"
	"reflect"
	"strings"
	"testing"
	"time"
)

var bg = context.Background()

func fixedJSON(status int, body string) func(*http.Request, goldenCall) (int, string) {
	return func(*http.Request, goldenCall) (int, string) { return status, body }
}

func byPath(routes map[string]string) func(*http.Request, goldenCall) (int, string) {
	return func(r *http.Request, _ goldenCall) (int, string) {
		if body, ok := routes[r.URL.Path]; ok {
			return http.StatusOK, body
		}
		return http.StatusNotFound, "not found"
	}
}

const tenantOK = `{"code":0,"tenant_access_token":"t-1","expire":7200}`

// ── OAuth scopes (port of auth-feishu-oauth-scopes.test.ts) ─────────────────

func TestWithOfflineAccess(t *testing.T) {
	t.Parallel()
	cases := []struct{ in, want []string }{
		{nil, []string{OfflineAccessScope}},
		{[]string{"a", " a ", "", "b"}, []string{"a", "b", OfflineAccessScope}},
		{[]string{"offline_access", "a"}, []string{"offline_access", "a"}},
	}
	for _, c := range cases {
		if got := WithOfflineAccess(c.in); !reflect.DeepEqual(got, c.want) {
			t.Errorf("WithOfflineAccess(%q) = %q, want %q", c.in, got, c.want)
		}
	}
}

func TestParseGrantedUserScopes(t *testing.T) {
	t.Parallel()
	resp := `{"code":0,"data":{"scopes":[
		{"scope_name":"docx:document:readonly","scope_type":"user","grant_status":1},
		{"scope_name":"im:message:readonly","scope_type":"user","grant_status":2},
		{"scope_name":"contact:user.base:readonly","scope_type":"user","grant_status":0},
		{"scope_name":"im:message","scope_type":"tenant","grant_status":1},
		{"scope_name":"docx:document:readonly","scope_type":"user","grant_status":1},
		{"scope_type":"user","grant_status":1},
		{"scope_name":"x","scope_type":"user","grant_status":"1"},
		null
	]}}`
	got, ok := ParseGrantedUserScopes([]byte(resp))
	if !ok || !reflect.DeepEqual(got, []string{"docx:document:readonly", "im:message:readonly"}) {
		t.Fatalf("scopes = %q ok=%v", got, ok)
	}
	for _, bad := range []string{`{"code":99991672,"msg":"no permission"}`, `{"code":0,"data":{}}`, `null`, `{"data":{"scopes":[]}}`, `not json`} {
		if got, ok := ParseGrantedUserScopes([]byte(bad)); ok || got != nil {
			t.Errorf("%s: got %q ok=%v", bad, got, ok)
		}
	}
	if got, ok := ParseGrantedUserScopes([]byte(`{"code":0,"data":{"scopes":[]}}`)); !ok || got == nil || len(got) != 0 {
		t.Fatalf("empty scope list must be an empty (non-nil) result: %q %v", got, ok)
	}
}

func TestCapAuthorizeScopes(t *testing.T) {
	t.Parallel()
	many := make([]string, 250)
	for i := range many {
		many[i] = fmt.Sprintf("s%d", i)
	}
	capped := CapAuthorizeScopes(WithOfflineAccess(many))
	if len(capped) != MaxAuthorizeScopes || capped[len(capped)-1] != OfflineAccessScope || capped[0] != "s0" {
		t.Fatalf("capped = %d %q", len(capped), capped[len(capped)-1])
	}
	if got := CapAuthorizeScopes([]string{"a", OfflineAccessScope}); !reflect.DeepEqual(got, []string{"a", OfflineAccessScope}) {
		t.Fatalf("short list must be unchanged: %q", got)
	}
}

func TestListGrantedUserScopes(t *testing.T) {
	t.Parallel()
	rec, c := newRecorder(t, byPath(map[string]string{
		tenantTokenPath: tenantOK,
		appScopesPath:   `{"code":0,"data":{"scopes":[{"scope_name":"offline_access","scope_type":"user","grant_status":1}]}}`,
	}))
	got, err := c.ListGrantedUserScopes(bg)
	if err != nil || !reflect.DeepEqual(got, []string{"offline_access"}) {
		t.Fatalf("scopes = %q err = %v", got, err)
	}
	calls := rec.take()
	if len(calls) != 2 || calls[1].Method != http.MethodGet || calls[1].Auth != "Bearer t-1" || calls[1].ContentType != "" {
		t.Fatalf("calls = %+v", calls)
	}

	rec.respond = byPath(map[string]string{tenantTokenPath: tenantOK, appScopesPath: `{"code":99991672,"msg":"no permission"}`})
	if _, err := c.ListGrantedUserScopes(bg); !errors.Is(err, ErrScopesUnavailable) {
		t.Fatalf("err = %v", err)
	}
	rec.respond = byPath(map[string]string{tenantTokenPath: `{"code":10003,"msg":"bad app"}`})
	if _, err := c.ListGrantedUserScopes(bg); err == nil || err.Error() != "tenant_access_token 失败 code=10003 bad app" {
		t.Fatalf("err = %v", err)
	}
}

// ── OAuth exchanges ─────────────────────────────────────────────────────────

func TestExchangeCodeForCredential(t *testing.T) {
	t.Parallel()
	rec, c := newRecorder(t, byPath(map[string]string{
		OAuthV2TokenPath: `{"code":0,"access_token":"ua","expires_in":7200,"refresh_token":"ur","refresh_token_expires_in":604800,"scope":"offline_access docx:document:readonly"}`,
		userInfoPath:     `{"code":0,"data":{"union_id":"on_x","open_id":"ou_x","name":"X"}}`,
	}))
	c.now = func() time.Time { return time.Unix(1_000_000, 0) }
	user, token, err := c.ExchangeCodeForCredential(bg, "the-code", "https://platform.test/auth/callback")
	if err != nil {
		t.Fatal(err)
	}
	want := CredentialTokenBundle{UserTokenBundle: UserTokenBundle{AccessToken: "ua", RefreshToken: "ur", ExpiresAt: 1_007_200, RefreshExpiresAt: 1_604_800}, Scope: "offline_access docx:document:readonly"}
	if user.UnionID != "on_x" || token != want {
		t.Fatalf("user=%+v token=%+v", user, token)
	}
	calls := rec.take()
	if calls[0].Auth != "" || calls[1].Auth != "Bearer ua" {
		t.Fatalf("auth headers = %q %q", calls[0].Auth, calls[1].Auth)
	}

	// Missing refresh token / expiries / scope: defaults and omissions.
	rec.respond = byPath(map[string]string{
		OAuthV2TokenPath: `{"code":0,"access_token":"ua","expires_in":"abc","refresh_token_expires_in":0}`,
		userInfoPath:     `{"code":0,"data":{"open_id":"ou_only"}}`,
	})
	user, token, err = c.ExchangeCodeForCredential(bg, "c", "r")
	if err != nil {
		t.Fatal(err)
	}
	if token.RefreshToken != "" || token.ExpiresAt != 1_007_000 || token.RefreshExpiresAt != 0 || token.Scope != "" || user.UnionID != "ou_only" || user.Name != "飞书用户" {
		t.Fatalf("user=%+v token=%+v", user, token)
	}
	raw, _ := json.Marshal(token)
	if string(raw) != `{"accessToken":"ua","refreshToken":"","expiresAt":1007000}` {
		t.Fatalf("token JSON = %s", raw)
	}

	errorCases := map[string]string{
		`{"code":20050,"error":"invalid_grant","error_description":"code expired"}`: "飞书 OAuth v2 换票失败: code=20050 error=invalid_grant code expired",
		`{"error":"invalid_client"}`:  "飞书 OAuth v2 换票失败: code=undefined error=invalid_client",
		`{}`:                          "飞书 OAuth v2 换票失败: code=undefined error=",
		`{"code":0,"access_token":5}`: "飞书 OAuth v2 换票失败: code=0 error=",
		`{"code":"0","access_token":"ua","error":null}`:     "飞书 OAuth v2 换票失败: code=0 error=",
		`{"code":20050,"error_description":"x","error":{}}`: "飞书 OAuth v2 换票失败: code=20050 error=[object Object] x",
	}
	for body, want := range errorCases {
		rec.respond = func(*http.Request, goldenCall) (int, string) { return http.StatusBadRequest, body }
		if _, _, err := c.ExchangeCodeForCredential(bg, "c", "r"); err == nil || err.Error() != want {
			t.Errorf("%s: err = %v, want %q", body, err, want)
		}
	}
}

func TestExchangeCodeLoginFlow(t *testing.T) {
	t.Parallel()
	rec, c := newRecorder(t, byPath(map[string]string{
		appTokenPath:  `{"code":0,"app_access_token":"app"}`,
		userTokenPath: `{"code":0,"data":{"access_token":"user","refresh_token":"r","expires_in":60,"refresh_expires_in":"600"}}`,
		userInfoPath:  `{"code":0,"data":{"union_id":"on_1","open_id":"ou_1","en_name":"EN","avatar_thumb":"thumb"}}`,
	}))
	c.now = func() time.Time { return time.Unix(1000, 0) }
	user, token, err := c.ExchangeCode(bg, "code")
	if err != nil {
		t.Fatal(err)
	}
	if token != (UserTokenBundle{AccessToken: "user", RefreshToken: "r", ExpiresAt: 1060, RefreshExpiresAt: 1600}) ||
		user != (User{UnionID: "on_1", OpenID: "ou_1", Name: "EN", Avatar: "thumb"}) {
		t.Fatalf("user=%+v token=%+v", user, token)
	}
	calls := rec.take()
	if calls[1].Body != `{"grant_type":"authorization_code","code":"code"}` || calls[1].Auth != "Bearer app" {
		t.Fatalf("token call = %+v", calls[1])
	}

	// `res.data || res`: a truthy data object without access_token fails even
	// when the token sits at the top level.
	rec.respond = byPath(map[string]string{
		appTokenPath:  `{"code":0,"app_access_token":"app"}`,
		userTokenPath: `{"code":0,"data":{},"access_token":"top"}`,
	})
	if _, _, err := c.ExchangeCode(bg, "code"); err == nil || err.Error() != "飞书 user_access_token 失败: code=0 msg=undefined" {
		t.Fatalf("err = %v", err)
	}
	// Falsy data falls back to the top level.
	rec.respond = byPath(map[string]string{
		appTokenPath:  `{"code":0,"app_access_token":"app"}`,
		userTokenPath: `{"code":0,"data":null,"access_token":"top"}`,
		userInfoPath:  `{"code":0,"union_id":"on_top"}`,
	})
	if user, token, err := c.ExchangeCode(bg, "code"); err != nil || token.AccessToken != "top" || token.ExpiresAt != 8000 || user.UnionID != "on_top" {
		t.Fatalf("user=%+v token=%+v err=%v", user, token, err)
	}

	rec.respond = byPath(map[string]string{appTokenPath: `{"code":10003,"msg":"invalid app"}`})
	if _, _, err := c.ExchangeCode(bg, "code"); err == nil || err.Error() != "飞书 app_access_token 失败: code=10003 msg=invalid app" {
		t.Fatalf("err = %v", err)
	}
	// A JSON error body on a non-2xx status is still parsed by its code.
	rec.respond = func(r *http.Request, _ goldenCall) (int, string) {
		if r.URL.Path == appTokenPath {
			return http.StatusOK, `{"code":0,"app_access_token":"app"}`
		}
		if r.URL.Path == userTokenPath {
			return http.StatusOK, `{"code":0,"data":{"access_token":"user"}}`
		}
		return http.StatusUnauthorized, `{"code":20005,"msg":"invalid access token"}`
	}
	if _, _, err := c.ExchangeCode(bg, "code"); err == nil || err.Error() != "飞书 user_info 失败: code=20005 msg=invalid access token" {
		t.Fatalf("err = %v", err)
	}
	rec.respond = byPath(map[string]string{
		appTokenPath:  `{"code":0,"app_access_token":"app"}`,
		userTokenPath: `{"code":0,"data":{"access_token":"user"}}`,
		userInfoPath:  `{"code":0,"data":{"name":"nobody"}}`,
	})
	if _, _, err := c.ExchangeCode(bg, "code"); err == nil || err.Error() != "飞书 user_info 未返回 union_id 或 open_id" {
		t.Fatalf("err = %v", err)
	}
}

func TestRefreshUserToken(t *testing.T) {
	t.Parallel()
	rec, c := newRecorder(t, byPath(map[string]string{
		appTokenPath:    `{"code":0,"app_access_token":"app"}`,
		userRefreshPath: `{"code":0,"data":{"access_token":"new","expires_in":"3600"}}`,
	}))
	c.now = func() time.Time { return time.Unix(1000, 0) }
	token, err := c.RefreshUserToken(bg, "old-refresh")
	if err != nil || token != (UserTokenBundle{AccessToken: "new", RefreshToken: "old-refresh", ExpiresAt: 4600}) {
		t.Fatalf("token=%+v err=%v", token, err)
	}
	if body := rec.take()[1].Body; body != `{"grant_type":"refresh_token","refresh_token":"old-refresh"}` {
		t.Fatalf("body = %s", body)
	}
	rec.respond = func(r *http.Request, _ goldenCall) (int, string) {
		if r.URL.Path == appTokenPath {
			return http.StatusOK, `{"code":0,"app_access_token":"app"}`
		}
		return http.StatusBadRequest, `{"code":20064,"msg":"refresh token revoked"}`
	}
	var apiErr *APIError
	if _, err := c.RefreshUserToken(bg, "old"); !errors.As(err, &apiErr) || apiErr.Code != 20064 {
		t.Fatalf("err = %v", err)
	}
}

// ── Contact ─────────────────────────────────────────────────────────────────

func TestSearchUsers(t *testing.T) {
	t.Parallel()
	rec, c := newRecorder(t, fixedJSON(http.StatusOK, `{"code":0,"data":{"users":[
		{"union_id":"on_1","open_id":"ou_1","name":"","en_name":"Alice","enterprise_email":"a@corp","avatar":{"avatar_72":"a72"}},
		{"union_id":"on_2","name":"no open id"},
		{"union_id":"on_3","open_id":"ou_3","name":"Bob","email":"b@x","avatar":"bad-shape","avatar_url":"url"}
	]}}`))
	users, err := c.SearchUsers(bg, "a b", "u-1")
	if err != nil {
		t.Fatal(err)
	}
	want := []TenantUser{
		{UnionID: "on_1", OpenID: "ou_1", Name: "Alice", Email: "a@corp", Avatar: "a72"},
		{UnionID: "on_3", OpenID: "ou_3", Name: "Bob", Email: "b@x", Avatar: "url"},
	}
	if !reflect.DeepEqual(users, want) {
		t.Fatalf("users = %+v", users)
	}
	if got := rec.take()[0].URL; got != goldenHost+"/open-apis/search/v1/user?query=a%20b&page_size=20" {
		t.Fatalf("url = %s", got)
	}

	if _, err := c.SearchUsers(bg, "x", ""); !errors.Is(err, ErrTokenInvalid) {
		t.Fatalf("empty token err = %v", err)
	}
	if len(rec.take()) != 0 {
		t.Fatal("no request without a user token")
	}
	invalid := []struct {
		status int
		body   string
	}{
		{http.StatusUnauthorized, `{"code":99991677,"msg":"token expired"}`},
		{http.StatusOK, `{"code":99991663}`},
		{http.StatusOK, `{"code":12345,"msg":"Authentication token is bad"}`},
		{http.StatusBadRequest, `{"code":1,"msg":"user TOKEN INVALID"}`},
	}
	for _, c2 := range invalid {
		rec.respond = fixedJSON(c2.status, c2.body)
		if _, err := c.SearchUsers(bg, "x", "u-1"); !errors.Is(err, ErrTokenInvalid) {
			t.Errorf("%d %s: err = %v", c2.status, c2.body, err)
		}
	}
	errorTexts := map[string]string{
		`{"code":1234,"msg":"boom"}`: "feishu code=1234 boom",
		`{"code":1234}`:              "feishu code=1234 ",
		`{"msg":"no code"}`:          "feishu code=undefined no code",
	}
	for body, want := range errorTexts {
		rec.respond = fixedJSON(http.StatusOK, body)
		if _, err := c.SearchUsers(bg, "x", "u-1"); err == nil || err.Error() != want {
			t.Errorf("%s: err = %v, want %q", body, err, want)
		}
	}
	rec.respond = fixedJSON(http.StatusBadGateway, "<html>bad gateway</html>")
	var httpErr *HTTPError
	if _, err := c.SearchUsers(bg, "x", "u-1"); !errors.As(err, &httpErr) || httpErr.Status != http.StatusBadGateway {
		t.Fatalf("non-JSON err = %v", err)
	}
}

func TestResolveOpenIDTrimsEncodesAndCaches(t *testing.T) {
	t.Parallel()
	rec, c := newRecorder(t, fixedJSON(http.StatusOK, `{"code":0,"data":{"user":{"open_id":"ou_1"}}}`))
	for i := 0; i < 2; i++ {
		if got, err := c.ResolveOpenID(bg, "t-1", "  on:1/x "); err != nil || got != "ou_1" {
			t.Fatalf("got %q err %v", got, err)
		}
	}
	calls := rec.take()
	if len(calls) != 1 || calls[0].URL != goldenHost+"/open-apis/contact/v3/users/on%3A1%2Fx?user_id_type=union_id&department_id_type=open_department_id" {
		t.Fatalf("calls = %+v", calls)
	}
	if _, err := c.ResolveOpenID(bg, "t-1", " \t"); !errors.Is(err, ErrUserNotFound) || len(rec.take()) != 0 {
		t.Fatalf("blank union id must not hit Feishu: %v", err)
	}
	rec.respond = fixedJSON(http.StatusForbidden, `{"code":40004,"msg":"no dept authority"}`)
	if _, err := c.ResolveOpenID(bg, "t-1", "on_2"); err == nil {
		t.Fatal("failure must surface")
	}
	if _, err := c.ResolveOpenID(bg, "t-1", "on_2"); err == nil || len(rec.take()) != 2 {
		t.Fatal("failures must not be cached")
	}
}

func TestResolveUnionIDByEmail(t *testing.T) {
	t.Parallel()
	rec, c := newRecorder(t, fixedJSON(http.StatusOK, `{"code":0,"data":{"user_list":[{"email":"other@corp.com","user_id":"on_other"},{"email":"ALICE@corp.com"},{"email":"alice@CORP.com","user_id":"on_alice"}]}}`))
	for i := 0; i < 2; i++ {
		if got, err := c.ResolveUnionIDByEmail(bg, "t-1", " Alice@Corp.com\n"); err != nil || got != "on_alice" {
			t.Fatalf("got %q err %v", got, err)
		}
	}
	calls := rec.take()
	if len(calls) != 1 || calls[0].Body != `{"emails":["alice@corp.com"]}` || calls[0].ContentType != "application/json; charset=utf-8" || calls[0].Auth != "Bearer t-1" {
		t.Fatalf("calls = %+v", calls)
	}
	rec.respond = fixedJSON(http.StatusOK, `{"code":0,"data":{"user_list":[{"email":"bob@corp.com"}]}}`)
	if _, err := c.ResolveUnionIDByEmail(bg, "t-1", "bob@corp.com"); !errors.Is(err, ErrUserNotFound) {
		t.Fatalf("unknown email err = %v", err)
	}
	rec.respond = fixedJSON(http.StatusOK, `{"code":99991672,"msg":"no permission"}`)
	var apiErr *APIError
	if _, err := c.ResolveUnionIDByEmail(bg, "t-1", "carol@corp.com"); !errors.As(err, &apiErr) || apiErr.Code != 99991672 {
		t.Fatalf("api failure err = %v", err)
	}
	if _, err := c.ResolveUnionIDByEmail(bg, "t-1", "  "); !errors.Is(err, ErrUserNotFound) {
		t.Fatalf("blank email err = %v", err)
	}
}

// ── Groups ──────────────────────────────────────────────────────────────────

func TestIsPlatformBotInChatTriState(t *testing.T) {
	t.Parallel()
	rec, c := newRecorder(t, nil)
	cases := []struct {
		status  int
		body    string
		want    bool
		wantErr bool
	}{
		{200, `{"code":0,"data":{"is_in_chat":true}}`, true, false},
		{200, `{"code":0,"data":{"is_in_chat":false}}`, false, false},
		{400, `{"code":232002,"msg":"bot not in chat"}`, false, false},
		{400, `{"code":232009}`, false, false},
		{400, `{"code":232001}`, false, false},
		{429, `{"code":99991400,"msg":"rate limited"}`, false, true},
		{200, `{"code":0,"data":{"is_in_chat":"true"}}`, false, true},
		{502, `upstream`, false, true},
	}
	for _, tc := range cases {
		rec.respond = fixedJSON(tc.status, tc.body)
		got, err := c.IsPlatformBotInChat(bg, "t-1", "oc_1")
		if got != tc.want || (err != nil) != tc.wantErr {
			t.Errorf("%d %s: got %v err %v", tc.status, tc.body, got, err)
		}
	}
}

func TestIsUserInChatFailsClosedOnPageError(t *testing.T) {
	t.Parallel()
	page := 0
	rec, c := newRecorder(t, func(*http.Request, goldenCall) (int, string) {
		page++
		if page == 1 {
			return 200, `{"code":0,"data":{"items":[{"member_id":"x"}],"has_more":true,"page_token":7}}`
		}
		return 200, `{"code":99991400,"msg":"rate limited"}`
	})
	if in, err := c.IsUserInChat(bg, "t-1", "oc_1", "on_target"); in || err == nil {
		t.Fatalf("page failure must be an error: %v %v", in, err)
	}
	calls := rec.take()
	if len(calls) != 2 || !strings.HasSuffix(calls[1].URL, "&page_token=7") {
		t.Fatalf("calls = %+v", calls)
	}
	rec.respond = fixedJSON(200, `{"code":0,"data":{"items":[{"member_id":"x"}],"has_more":true}}`)
	if in, err := c.IsUserInChat(bg, "t-1", "oc_1", "on_target"); in || err != nil {
		t.Fatalf("has_more without page_token ends the scan: %v %v", in, err)
	}
}

func TestListHallBotsReturnsPartialOnError(t *testing.T) {
	t.Parallel()
	page := 0
	_, c := newRecorder(t, func(*http.Request, goldenCall) (int, string) {
		page++
		if page == 1 {
			return 200, `{"code":0,"data":{"items":[{"bot_id":"ou_1","bot_name":"one"}],"has_more":true,"page_token":"p2"}}`
		}
		return 200, `{"code":-1,"msg":"boom"}`
	})
	if got := c.ListHallBots(bg, "t-1", "oc_1"); !reflect.DeepEqual(got, []HallBot{{OpenID: "ou_1", Name: "one"}}) {
		t.Fatalf("bots = %+v", got)
	}
}

func TestSendHallTeachMentionSkipsEmpty(t *testing.T) {
	t.Parallel()
	rec, c := newRecorder(t, fixedJSON(200, `{"code":230002,"msg":"bot not in chat"}`))
	if c.SendHallTeachMention(bg, "t-1", "oc_1", []string{"", ""}) || len(rec.take()) != 0 {
		t.Fatal("nobody to mention must not send")
	}
	if c.SendHallTeachMention(bg, "t-1", "oc_1", []string{"ou_1"}) {
		t.Fatal("failed send must report false")
	}
}

func TestMemberBatchesContinueAfterFailures(t *testing.T) {
	t.Parallel()
	n := 0
	rec, c := newRecorder(t, func(*http.Request, goldenCall) (int, string) {
		n++
		if n == 1 {
			return 400, `{"code":232009,"msg":"chat gone"}`
		}
		return 200, `{"code":0,"data":{"invalid_id_list":["u55",7]}}`
	})
	users := make([]string, 60)
	for i := range users {
		users[i] = fmt.Sprintf("u%d", i)
	}
	invalid, err := c.AddUsersToChat(bg, "t-1", "oc_1", users)
	if err != nil || len(invalid) != 51 || invalid[0] != "u0" || invalid[50] != "u55" {
		t.Fatalf("invalid = %d %v err=%v", len(invalid), invalid, err)
	}
	if calls := rec.take(); len(calls) != 2 {
		t.Fatalf("calls = %d", len(calls))
	}

	// A failing single-bot batch is not retried (TypeScript only retries
	// multi-bot batches refused as a whole).
	rec.respond = fixedJSON(400, `{"code":232009}`)
	invalid, _ = c.AddBotsToChat(bg, "t-1", "oc_1", []string{"a1", "a2", "a3", "a4", "a5", "a6"})
	if len(invalid) != 6 || len(rec.take()) != 1+5+1 {
		t.Fatalf("invalid = %v", invalid)
	}

	n = 0
	rec.respond = func(*http.Request, goldenCall) (int, string) {
		n++
		if n == 1 {
			return 200, `{"code":99991400,"msg":"rate limited"}`
		}
		return 200, `{"code":0}`
	}
	err = c.RemoveBotsFromChat(bg, "t-1", "oc_1", []string{"a1", "a2", "a3", "a4", "a5", "a6", "a7"})
	calls := rec.take()
	if err == nil || len(calls) != 2 || calls[1].Body != `{"id_list":["a6","a7"]}` || calls[1].Method != http.MethodDelete {
		t.Fatalf("err=%v calls=%+v", err, calls)
	}
}

func TestGroupFailureTexts(t *testing.T) {
	t.Parallel()
	rec, c := newRecorder(t, nil)
	rec.respond = func(r *http.Request, _ goldenCall) (int, string) {
		if r.URL.Path == tenantTokenPath {
			return 200, tenantOK
		}
		return 400, `{"code":232099,"msg":"bad"}`
	}
	if _, err := c.CreateGroup(bg, GroupCreateOptions{RequesterUnionID: "u"}); err == nil || err.Error() != "建群失败 code=232099 bad" {
		t.Fatalf("err = %v", err)
	}
	if _, _, err := c.CreateHallGroup(bg, "T", nil); err == nil || err.Error() != "建大厅失败 code=232099 bad" {
		t.Fatalf("err = %v", err)
	}
	long := strings.Repeat("页", 300)
	rec.respond = func(r *http.Request, _ goldenCall) (int, string) {
		if r.URL.Path == tenantTokenPath {
			return 200, tenantOK
		}
		return 502, long
	}
	if _, err := c.CreateGroup(bg, GroupCreateOptions{RequesterUnionID: "u"}); err == nil || err.Error() != "建群失败 code=-1 HTTP 502: "+strings.Repeat("页", 200) {
		t.Fatalf("err = %v", err)
	}
	rec.respond = func(r *http.Request, _ goldenCall) (int, string) {
		if r.URL.Path == tenantTokenPath {
			return 200, `{"code":99991663,"msg":"app not found"}`
		}
		return 200, `{"code":0}`
	}
	if _, err := c.CreateGroup(bg, GroupCreateOptions{RequesterUnionID: "u"}); err == nil || err.Error() != "tenant_access_token 失败 code=99991663 app not found" {
		t.Fatalf("err = %v", err)
	}
	unconfigured := NewClient(rec.URL, "", "", rec.Client())
	if _, err := unconfigured.CreateGroup(bg, GroupCreateOptions{}); !errors.Is(err, ErrFeishuNotConfigured) || err.Error() != "feishu_not_configured" {
		t.Fatalf("err = %v", err)
	}

	statuses := map[string]ChatStatus{
		`{"code":0}`:      ChatOK,
		`{"code":232009}`: ChatGone,
		`{"code":232001}`: ChatGone,
		`{"code":232002}`: ChatGone,
		`{"code":-1}`:     ChatError,
		`{}`:              ChatError,
		`oops`:            ChatError,
	}
	for body, want := range statuses {
		rec.respond = fixedJSON(400, body)
		if got := c.GetChatStatus(bg, "t-1", "oc_1"); got != want {
			t.Errorf("%s: %s, want %s", body, got, want)
		}
	}
}

// ── IM ──────────────────────────────────────────────────────────────────────

func TestTenantAccessTokenExpiryAndCache(t *testing.T) {
	t.Parallel()
	rec, c := newRecorder(t, fixedJSON(200, `{"code":0,"tenant_access_token":"t-1","expire":7200}`))
	now := time.Unix(1000, 0)
	c.now = func() time.Time { return now }
	for body, want := range map[string]float64{
		`{"code":0,"tenant_access_token":"t","expire":7200}`:   7200,
		`{"code":0,"tenant_access_token":"t","expire":"7200"}`: 3600,
		`{"code":0,"tenant_access_token":"t","expire":0}`:      3600,
		`{"code":0,"tenant_access_token":"t"}`:                 3600,
		`{"code":0,"tenant_access_token":"t","expire":1.5}`:    1.5,
	} {
		rec.respond = fixedJSON(200, body)
		if _, got, err := c.TenantAccessTokenWithExpiry(bg); err != nil || got != want {
			t.Errorf("%s: expire %v err %v", body, got, err)
		}
	}
	for body, want := range map[string]string{
		`{"code":99991663,"msg":"app not found"}`: "tenant_access_token 失败 code=99991663 app not found",
		`{"code":0}`:                          "tenant_access_token 失败 code=0 ",
		`{"code":0,"tenant_access_token":""}`: "tenant_access_token 失败 code=0 ",
	} {
		rec.respond = fixedJSON(200, body)
		if _, _, err := c.TenantAccessTokenWithExpiry(bg); err == nil || err.Error() != want {
			t.Errorf("%s: err %v want %q", body, err, want)
		}
	}
	rec.take()

	// expire 7200 -> min(90min, 5400s) = 90 min.
	rec.respond = fixedJSON(200, `{"code":0,"tenant_access_token":"t-long","expire":7200}`)
	for i := 0; i < 3; i++ {
		if token, err := c.TenantAccessTokenCached(bg); err != nil || token != "t-long" {
			t.Fatalf("token %q err %v", token, err)
		}
	}
	if n := len(rec.take()); n != 1 {
		t.Fatalf("cached calls = %d", n)
	}
	now = now.Add(90*time.Minute - time.Millisecond)
	_, _ = c.TenantAccessTokenCached(bg)
	if n := len(rec.take()); n != 0 {
		t.Fatalf("still cached before 90min, calls = %d", n)
	}
	// A short expire is honored but floored at one minute.
	now = now.Add(time.Millisecond)
	rec.respond = fixedJSON(200, `{"code":0,"tenant_access_token":"t-short","expire":10}`)
	if token, _ := c.TenantAccessTokenCached(bg); token != "t-short" {
		t.Fatalf("token %q", token)
	}
	now = now.Add(59 * time.Second)
	_, _ = c.TenantAccessTokenCached(bg)
	now = now.Add(time.Second)
	_, _ = c.TenantAccessTokenCached(bg)
	if n := len(rec.take()); n != 2 {
		t.Fatalf("calls = %d, want refresh exactly at the 60s floor", n)
	}
}

func TestDirectMessageFailures(t *testing.T) {
	t.Parallel()
	rec, c := newRecorder(t, nil)
	unconfigured := NewClient(rec.URL, "", "", rec.Client())
	if err := unconfigured.SendInviteDM(bg, "ou", InviteMessage{}); !errors.Is(err, ErrFeishuNotConfigured) {
		t.Fatalf("invite err = %v", err)
	}
	notConfigured := []error{
		unconfigured.SendTeamJoinedDM(bg, "on", TeamJoinedMessage{}),
		c.SendTeamJoinedDM(bg, "", TeamJoinedMessage{}),
		c.SendTeamDisbandedDM(bg, "", TeamDisbandedMessage{}),
		c.SendCredentialFirstUseDM(bg, "", CredentialFirstUseMessage{}),
		c.SendDeviceConfirmDM(bg, "", DeviceConfirmMessage{}),
		c.SendDeviceRevokedAlarmDM(bg, "", DeviceRevokedMessage{}),
	}
	for i, err := range notConfigured {
		if !errors.Is(err, ErrNotConfigured) || err.Error() != "not_configured" {
			t.Errorf("case %d: err = %v", i, err)
		}
	}
	if len(rec.take()) != 0 {
		t.Fatal("unconfigured sends must not reach Feishu")
	}
	rec.respond = func(r *http.Request, _ goldenCall) (int, string) {
		if r.URL.Path == tenantTokenPath {
			return 200, tenantOK
		}
		return 400, `{"code":230002,"msg":"bot not in chat"}`
	}
	if err := c.SendDeviceRevokedAlarmDM(bg, "on", DeviceRevokedMessage{DeviceName: "d"}); err == nil || err.Error() != "feishu code=230002 bot not in chat" {
		t.Fatalf("err = %v", err)
	}
	// Mention lookup failure falls back to a bold name and still sends.
	rec.respond = func(r *http.Request, _ goldenCall) (int, string) {
		switch {
		case r.URL.Path == tenantTokenPath:
			return 200, tenantOK
		case strings.HasPrefix(r.URL.Path, "/open-apis/contact/"):
			return 400, `{"code":40004}`
		}
		return 200, `{"code":0}`
	}
	if err := c.SendTeamDisbandedDM(bg, "on_m", TeamDisbandedMessage{TeamName: "T", DissolverName: "D", DissolverUnionID: "on_d"}); err != nil {
		t.Fatal(err)
	}
	calls := rec.take()
	if !strings.Contains(calls[len(calls)-1].Body, `**D** 解散了团队 **T**`) {
		t.Fatalf("body = %s", calls[len(calls)-1].Body)
	}
}

func TestDeviceConfirmRoundsMinutesLikeMathRound(t *testing.T) {
	t.Parallel()
	cases := map[int64]string{29: "0", 30: "1", 89: "1", 90: "2", 150: "3", 600: "10", -90: "-1"}
	for seconds, minutes := range cases {
		rec, c := newRecorder(t, func(r *http.Request, _ goldenCall) (int, string) {
			if r.URL.Path == tenantTokenPath {
				return 200, tenantOK
			}
			return 200, `{"code":0}`
		})
		if err := c.SendDeviceConfirmDM(bg, "on", DeviceConfirmMessage{ExpiresInSec: seconds}); err != nil {
			t.Fatal(err)
		}
		calls := rec.take()
		if want := "本请求 " + minutes + " 分钟内有效。"; !strings.Contains(calls[1].Body, want) {
			t.Errorf("%ds: body %s lacks %q", seconds, calls[1].Body, want)
		}
	}
}

// ── JS helpers ──────────────────────────────────────────────────────────────

func TestJSHelpers(t *testing.T) {
	t.Parallel()
	if got := encodeURIComponent("a b/c?d=e&f+g~*'()!-_.中"); got != "a%20b%2Fc%3Fd%3De%26f%2Bg~*'()!-_.%E4%B8%AD" {
		t.Errorf("encodeURIComponent = %s", got)
	}
	numbers := map[string]float64{`"7200"`: 7200, `" 12 "`: 12, `""`: 0, `"0x10"`: 16, `"1e3"`: 1000, `true`: 1, `null`: 0, `[]`: 0, `["5"]`: 5, `"Infinity"`: math.Inf(1)}
	for raw, want := range numbers {
		if got := jsNumber(json.RawMessage(raw)); got != want {
			t.Errorf("Number(%s) = %v, want %v", raw, got, want)
		}
	}
	for _, raw := range []string{"", `"abc"`, `{}`, `[1,2]`, `"1_000"`, `"inf"`, `"0x1p3"`} {
		if got := jsNumber(json.RawMessage(raw)); !math.IsNaN(got) {
			t.Errorf("Number(%s) = %v, want NaN", raw, got)
		}
	}
	stringsCases := map[string]string{"": "undefined", `null`: "null", `12.50`: "12.5", `1e21`: "1e+21", `1e-7`: "1e-7", `"s"`: "s", `{"a":1}`: "[object Object]", `[1,null,"x"]`: "1,,x", `-0`: "0"}
	for raw, want := range stringsCases {
		if got := jsString(json.RawMessage(raw)); got != want {
			t.Errorf("String(%s) = %q, want %q", raw, got, want)
		}
	}
	if got := sliceUTF16("ab\U0001F600c", 3); got != "ab\uFFFD" {
		t.Errorf("slice through a surrogate pair = %q", got)
	}
	if got := sliceUTF16("ab\U0001F600c", 4); got != "ab\U0001F600" {
		t.Errorf("slice = %q", got)
	}
	for x, want := range map[float64]int64{2.5: 3, -2.5: -2, 0.49999999999999994: 0, -0.5: 0, 1.4999: 1} {
		if got := jsRound(x); got != want {
			t.Errorf("Math.round(%v) = %d, want %d", x, got, want)
		}
	}
	body, _ := marshalJS(jsObj{{"b", "<&>"}, {"a", jsObj{{"z", 1}, {"y", []string{"x"}}}}})
	if string(body) != `{"b":"<&>","a":{"z":1,"y":["x"]}}` {
		t.Errorf("ordered JSON = %s", body)
	}
}

func TestCapAuthorizeScopesKeepsByPriority(t *testing.T) {
	t.Parallel()
	scopes := []string{}
	for i := 0; i < 230; i++ {
		scopes = append(scopes, fmt.Sprintf("calendar:c%d:update", i))
	}
	tail := []string{"base:record:create", "contact:user:readonly", "base:record:read", "im:message:readonly", "docx:document:write_only", "wiki:node:read", "bitable:app"}
	scopes = WithOfflineAccess(append(scopes, tail...))
	capped := CapAuthorizeScopes(scopes)
	if len(capped) != MaxAuthorizeScopes || capped[len(capped)-1] != OfflineAccessScope {
		t.Fatalf("capped = %d, last %q", len(capped), capped[len(capped)-1])
	}
	// Everyday reads, then everyday writes, then other reads, then the rest.
	want := []string{"base:record:read", "im:message:readonly", "wiki:node:read", "base:record:create", "docx:document:write_only", "bitable:app", "contact:user:readonly", "calendar:c0:update"}
	if !reflect.DeepEqual(capped[:len(want)], want) {
		t.Fatalf("priority head = %q", capped[:len(want)])
	}
	if capped[len(capped)-2] != "calendar:c191:update" {
		t.Fatalf("lowest tier is cut from the end: %q", capped[len(capped)-2])
	}
	// keep wins over every tier, in its own order; unknown keep entries are ignored.
	kept := CapAuthorizeScopes(scopes, "calendar:c229:update", "not:in:list", "calendar:c228:update")
	if kept[0] != "calendar:c229:update" || kept[1] != "calendar:c228:update" || kept[2] != "base:record:read" {
		t.Fatalf("keep head = %q", kept[:3])
	}
	// Within the limit nothing moves.
	short := []string{"calendar:x:update", "base:record:read", OfflineAccessScope}
	if got := CapAuthorizeScopes(short, "base:record:read"); !reflect.DeepEqual(got, short) {
		t.Fatalf("short list must be unchanged: %q", got)
	}
}
