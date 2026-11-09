package server

import (
	"context"
	"crypto/rand"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/url"
	"regexp"
	"sort"
	"strings"
	"sync"
	"testing"
	"time"

	"go.mongodb.org/mongo-driver/bson"

	"github.com/botmux-ai/botmux-platform/internal/auth"
	"github.com/botmux-ai/botmux-platform/internal/config"
	"github.com/botmux-ai/botmux-platform/internal/credential"
	"github.com/botmux-ai/botmux-platform/internal/feishu"
	"github.com/botmux-ai/botmux-platform/internal/store"
)

// Ports test/server-credentials.test.ts: the "my credentials" SSO surface —
// list / authorize / consent / revoke / the Feishu callback branch. Teams use
// the memory repository, the vault a MemoryDatabase-backed CredentialStore;
// a device-login platform and the Feishu code exchange are injected.

const credentialTestOrigin = "http://localhost"

type credentialTestEnv struct {
	t     *testing.T
	apex  *Apex
	keys  *credential.Keys
	vault store.StaticDatabaseProvider
	repo  *store.DocumentRepository
	// device scripts the device-login platform.
	device *fakeDeviceLogin
}

func credentialTestConfig(t *testing.T) config.Config {
	t.Helper()
	kek := make([]byte, 32)
	if _, err := rand.Read(kek); err != nil {
		t.Fatal(err)
	}
	return config.Config{
		SigningSecret:        "cred-sso-test-secret",
		PublicBaseURL:        "http://localhost",
		FeishuAppID:          "cli_platform",
		FeishuAppSecret:      "app-secret",
		FeishuHost:           "https://open.feishu.test",
		SessionTTL:           7 * 24 * time.Hour,
		MachineTokenTTL:      180 * 24 * time.Hour,
		CredentialKEK:        kek,
		LarkCredentialScopes: "docx:document:readonly",
	}
}

func newCredentialTestEnv(t *testing.T) *credentialTestEnv {
	t.Helper()
	cfg := credentialTestConfig(t)
	env := &credentialTestEnv{
		t:      t,
		keys:   credential.KeysFromConfig(cfg),
		vault:  store.NewMemoryDatabaseProvider(),
		repo:   newMemoryRepository(),
		device: &fakeDeviceLogin{available: true, complete: credential.DeviceLoginPending},
	}
	ctx := context.Background()
	for _, team := range []store.TeamDoc{
		{ID: "t1", Name: "Team One", CreatedBy: "u-alice", Members: []string{"u-alice"}},
		{ID: "t2", Name: "Team Two", CreatedBy: "u-bob", Members: []string{"u-bob", "u-alice"}},
	} {
		if err := env.repo.CreateTeam(ctx, team); err != nil {
			t.Fatal(err)
		}
	}
	env.apex = &Apex{
		Config:          cfg,
		Repository:      env.repo,
		CredentialStore: store.NewCredentialStore(env.vault),
		Credentials: CredentialsDeps{
			Providers:    credential.Providers{DeviceLogins: []credential.DeviceLogin{env.device}},
			GrantLimiter: NewCredentialGrantLimiter(),
		},
	}
	return env
}

// testDevicePlatform is the device-login platform the tests link in.
const testDevicePlatform store.CredentialPlatform = "device-cli"

// fakeDeviceLogin scripts a device login: Begin hands out a fixed link,
// Complete answers complete, Mint answers mint.
type fakeDeviceLogin struct {
	mu         sync.Mutex
	available  bool
	beginFails bool
	complete   credential.DeviceLoginState
	// polled records each pending payload Complete was given.
	polled []string
	mint   func(rec credential.Record) credential.MintResult
	minted int
}

func (f *fakeDeviceLogin) Descriptor() credential.DeviceLoginDescriptor {
	return credential.DeviceLoginDescriptor{
		Platform: string(testDevicePlatform), Kind: "device-archive",
		Title: "Device", Description: "A CLI authorized by a device login.",
		Linked: []credential.LinkedService{{Title: "Git", Description: "Shares the device login."}},
	}
}

func (f *fakeDeviceLogin) Available() bool {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.available
}

func (f *fakeDeviceLogin) Begin(context.Context) credential.DeviceLoginBegin {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.beginFails {
		return credential.DeviceLoginBegin{Detail: "could not start a login"}
	}
	return credential.DeviceLoginBegin{OK: true, AuthURL: "https://sso.test/v?1", Payload: map[string]string{"challenge": "ct"}}
}

func (f *fakeDeviceLogin) Complete(_ context.Context, pending []byte) credential.DeviceLoginComplete {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.polled = append(f.polled, string(pending))
	switch f.complete {
	case credential.DeviceLoginAuthorized:
		return credential.DeviceLoginComplete{State: f.complete, Payload: map[string]string{"login": "archive"}, Account: "alice@example.test", LoginExpiresAt: 42}
	case credential.DeviceLoginFailed:
		return credential.DeviceLoginComplete{State: f.complete, Detail: "login challenge expired or was rejected"}
	case credential.DeviceLoginUnavailable:
		return credential.DeviceLoginComplete{State: f.complete, Detail: "authorization service unavailable"}
	}
	return credential.DeviceLoginComplete{State: credential.DeviceLoginPending}
}

func (f *fakeDeviceLogin) Mint(_ context.Context, _ *credential.Keys, rec credential.Record) credential.MintResult {
	f.mu.Lock()
	f.minted++
	mint := f.mint
	f.mu.Unlock()
	if mint == nil {
		return credential.MintResult{Reason: credential.MintUnavailable, Detail: "not scripted"}
	}
	return mint(rec)
}

func (f *fakeDeviceLogin) set(update func(f *fakeDeviceLogin)) {
	f.mu.Lock()
	defer f.mu.Unlock()
	update(f)
}

func (e *credentialTestEnv) cookie(unionID string, age time.Duration) string {
	token := auth.MintSessionAt(e.apex.Config, auth.SessionUser{UnionID: unionID, Name: "Alice"}, time.Now().Add(-age))
	return auth.SessionCookieName + "=" + token
}

type credentialRequest struct {
	method string
	body   string
	cookie *string
	origin *string
}

func credentialStr(s string) *string { return &s }

func (e *credentialTestEnv) do(path string, opts credentialRequest) *httptest.ResponseRecorder {
	e.t.Helper()
	method := opts.method
	if method == "" {
		method = http.MethodGet
	}
	var request *http.Request
	if method == http.MethodGet {
		request = httptest.NewRequest(method, "http://localhost"+path, nil)
	} else {
		body := opts.body
		if body == "" {
			body = "{}"
		}
		request = httptest.NewRequest(method, "http://localhost"+path, strings.NewReader(body))
	}
	request.Header.Set("Content-Type", "application/json")
	if opts.cookie == nil {
		request.Header.Set("Cookie", e.cookie("u-alice", 0))
	} else if *opts.cookie != "" {
		request.Header.Set("Cookie", *opts.cookie)
	}
	if opts.origin == nil {
		request.Header.Set("Origin", credentialTestOrigin)
	} else if *opts.origin != "" {
		request.Header.Set("Origin", *opts.origin)
	}
	recorder := httptest.NewRecorder()
	e.apex.ServeHTTP(recorder, request)
	return recorder
}

func (e *credentialTestEnv) stored(unionID string, platform store.CredentialPlatform) (store.CredentialDoc, error) {
	return e.apex.CredentialStore.Get(context.Background(), unionID, platform)
}

func (e *credentialTestEnv) rawDocs(collection string) []bson.M {
	e.t.Helper()
	db, err := e.vault.Database(context.Background())
	if err != nil {
		e.t.Fatal(err)
	}
	var docs []bson.M
	if err := db.Collection(collection).FindMany(context.Background(), store.Document{}, &docs); err != nil {
		e.t.Fatal(err)
	}
	return docs
}

func (e *credentialTestEnv) openStored(doc store.CredentialDoc) string {
	e.t.Helper()
	plain, ok := credential.OpenPayload(e.keys, doc.UnionID, string(doc.Platform), doc.Sealed)
	if !ok {
		e.t.Fatal("stored credential cannot be opened")
	}
	return string(plain)
}

func decodeBody(t *testing.T, recorder *httptest.ResponseRecorder) map[string]any {
	t.Helper()
	var body map[string]any
	if err := json.Unmarshal(recorder.Body.Bytes(), &body); err != nil {
		t.Fatalf("body %q: %v", recorder.Body.String(), err)
	}
	return body
}

func assertCredentialResponse(t *testing.T, recorder *httptest.ResponseRecorder, status int, body string) {
	t.Helper()
	if recorder.Code != status || recorder.Body.String() != body {
		t.Fatalf("got %d %s, want %d %s", recorder.Code, recorder.Body.String(), status, body)
	}
	if recorder.Header().Get("Cache-Control") != "no-store" {
		t.Fatalf("Cache-Control = %q", recorder.Header().Get("Cache-Control"))
	}
}

func TestCredentialsListRequiresSessionAndShowsTeamsAndProviders(t *testing.T) {
	env := newCredentialTestEnv(t)
	assertJSONError(t, env.do("/api/credentials", credentialRequest{cookie: credentialStr("")}), http.StatusUnauthorized, "unauthenticated")

	recorder := env.do("/api/credentials", credentialRequest{})
	if recorder.Code != http.StatusOK {
		t.Fatalf("list = %d %s", recorder.Code, recorder.Body.String())
	}
	var body struct {
		VaultEnabled bool            `json:"vaultEnabled"`
		Providers    json.RawMessage `json:"providers"`
		Platforms    json.RawMessage `json:"platforms"`
		Teams        []struct {
			ID   string `json:"id"`
			Name string `json:"name"`
		} `json:"teams"`
		Credentials json.RawMessage `json:"credentials"`
	}
	if err := json.Unmarshal(recorder.Body.Bytes(), &body); err != nil {
		t.Fatal(err)
	}
	ids := []string{}
	for _, team := range body.Teams {
		ids = append(ids, team.ID)
	}
	sort.Strings(ids)
	if !body.VaultEnabled || string(body.Providers) != `{"device-cli":true,"lark-cli":true}` ||
		strings.Join(ids, ",") != "t1,t2" || string(body.Credentials) != `[]` {
		t.Fatalf("list = %s", recorder.Body.String())
	}
	wantPlatforms := `[{"platform":"lark-cli","flow":"oauth","available":true,"title":"飞书","description":"访问飞书文档、日历与消息等服务。"},` +
		`{"platform":"device-cli","flow":"device","available":true,"title":"Device","description":"A CLI authorized by a device login.","linked":[{"title":"Git","description":"Shares the device login."}]}]`
	if string(body.Platforms) != wantPlatforms {
		t.Fatalf("platforms = %s", body.Platforms)
	}
	if strings.Contains(recorder.Body.String(), `"pending"`) {
		t.Fatalf("no pending login must omit pending: %s", recorder.Body.String())
	}

	// An edition without device logins lists lark-cli alone.
	env.apex.Credentials.Providers.DeviceLogins = nil
	env.apex.Config.FeishuAppID = ""
	bare := decodeBody(t, env.do("/api/credentials", credentialRequest{}))
	if providers, _ := json.Marshal(bare["providers"]); string(providers) != `{"lark-cli":false}` || len(bare["platforms"].([]any)) != 1 {
		t.Fatalf("bare list = %v", bare)
	}
}

func TestCredentialsListShapeHidesScopeAndSecrets(t *testing.T) {
	env := newCredentialTestEnv(t)
	sealed, err := credential.SealPayload(env.keys, "u-alice", "lark-cli", credential.LarkOAuthPayload{RefreshToken: "refresh-sentinel"})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := env.apex.CredentialStore.Upsert(context.Background(), store.UpsertCredentialInput{
		UnionID: "u-alice", Platform: store.CredentialPlatformLarkCLI, Kind: store.CredentialKindLarkOAuth, Sealed: sealed,
		Meta: store.CredentialMeta{AppID: "cli_platform", Scope: "offline_access", Account: "Alice"}, RefreshExpiresAt: 1_902_000_000_000,
	}); err != nil {
		t.Fatal(err)
	}
	recorder := env.do("/api/credentials", credentialRequest{})
	var body struct {
		Credentials []json.RawMessage `json:"credentials"`
	}
	if err := json.Unmarshal(recorder.Body.Bytes(), &body); err != nil || len(body.Credentials) != 1 {
		t.Fatalf("list = %s (%v)", recorder.Body.String(), err)
	}
	entry := regexp.MustCompile(`"createdAt":\d+,"updatedAt":\d+`).ReplaceAllString(string(body.Credentials[0]), `"createdAt":0,"updatedAt":0`)
	want := `{"platform":"lark-cli","status":"active","consentTeams":"all","createdAt":0,"updatedAt":0,"refreshExpiresAt":1902000000000,"meta":{"account":"Alice","appId":"cli_platform"}}`
	if entry != want {
		t.Fatalf("entry = %s\nwant    %s", entry, want)
	}
	if strings.Contains(recorder.Body.String(), "offline_access") || strings.Contains(recorder.Body.String(), "sealed") {
		t.Fatalf("list leaks scope or sealed data: %s", recorder.Body.String())
	}
}

func TestLarkAuthorizeNeedsStrictFreshnessAndOrigin(t *testing.T) {
	env := newCredentialTestEnv(t)
	assertJSONError(t, env.do("/api/credentials/lark-cli/authorize", credentialRequest{method: http.MethodPost, origin: credentialStr("http://evil")}), http.StatusForbidden, "bad_origin")
	assertJSONError(t, env.do("/api/credentials/lark-cli/authorize", credentialRequest{method: http.MethodPost, origin: credentialStr("")}), http.StatusForbidden, "bad_origin")
	stale := env.do("/api/credentials/lark-cli/authorize", credentialRequest{method: http.MethodPost, cookie: credentialStr(env.cookie("u-alice", 601*time.Second))})
	assertCredentialResponse(t, stale, http.StatusUnauthorized, `{"error":"stale_session","loginUrl":"/auth/login"}`)

	recorder := env.do("/api/credentials/lark-cli/authorize", credentialRequest{method: http.MethodPost})
	if recorder.Code != http.StatusOK {
		t.Fatalf("authorize = %d %s", recorder.Code, recorder.Body.String())
	}
	u, err := url.Parse(decodeBody(t, recorder)["url"].(string))
	if err != nil {
		t.Fatal(err)
	}
	if u.Scheme+"://"+u.Host+u.Path != "https://open.feishu.test/open-apis/authen/v1/authorize" {
		t.Fatalf("authorize url = %s", u)
	}
	q := u.Query()
	if q.Get("app_id") != "cli_platform" || q.Get("state") == "" {
		t.Fatalf("authorize query = %v", q)
	}
	// offline_access always rides along: without it Feishu returns no refresh_token.
	if q.Get("scope") != "docx:document:readonly offline_access" {
		t.Fatalf("scope = %q", q.Get("scope"))
	}
	if !strings.Contains(recorder.Header().Get("Set-Cookie"), auth.OAuthStateCookieName+"=") {
		t.Fatalf("Set-Cookie = %q", recorder.Header().Get("Set-Cookie"))
	}
}

func TestLarkAuthorizeDiscoversAppScopesWhenUnconfigured(t *testing.T) {
	env := newCredentialTestEnv(t)
	env.apex.Config.LarkCredentialScopes = ""
	calls := 0
	authorize := func(list func(context.Context) ([]string, error)) *httptest.ResponseRecorder {
		env.apex.Credentials.ListUserScopes = list
		return env.do("/api/credentials/lark-cli/authorize", credentialRequest{method: http.MethodPost})
	}
	ok := authorize(func(context.Context) ([]string, error) {
		calls++
		return []string{"docx:document:readonly", "im:message:readonly", "offline_access", "docx:document:readonly"}, nil
	})
	if ok.Code != http.StatusOK || calls != 1 {
		t.Fatalf("authorize = %d %s (calls=%d)", ok.Code, ok.Body.String(), calls)
	}
	u, _ := url.Parse(decodeBody(t, ok)["url"].(string))
	// Deduplicated, and offline_access is not appended twice.
	if got := u.Query().Get("scope"); got != "docx:document:readonly im:message:readonly offline_access" {
		t.Fatalf("scope = %q", got)
	}

	assertCredentialResponse(t, authorize(func(context.Context) ([]string, error) { return nil, nil }), http.StatusServiceUnavailable, `{"error":"scope_unavailable"}`)
	assertCredentialResponse(t, authorize(func(context.Context) ([]string, error) { return nil, errors.New("down") }), http.StatusServiceUnavailable, `{"error":"scope_unavailable"}`)
	// The app never enabled offline_access: Feishu's page would fail with
	// 20027, so refuse up front with a readable code.
	assertCredentialResponse(t, authorize(func(context.Context) ([]string, error) { return []string{"contact:user:search"}, nil }), http.StatusServiceUnavailable, `{"error":"offline_access_not_enabled"}`)
	assertCredentialResponse(t, authorize(func(context.Context) ([]string, error) { return []string{}, nil }), http.StatusServiceUnavailable, `{"error":"offline_access_not_enabled"}`)

	// A configured scope list never consults the app.
	env.apex.Config.LarkCredentialScopes = "docx:document:readonly"
	touched := 0
	if r := authorize(func(context.Context) ([]string, error) { touched++; return []string{}, nil }); r.Code != http.StatusOK || touched != 0 {
		t.Fatalf("configured authorize = %d (touched=%d)", r.Code, touched)
	}

	// No platform app → provider_unavailable before any scope lookup.
	env.apex.Config.FeishuAppSecret = ""
	assertCredentialResponse(t, authorize(nil), http.StatusServiceUnavailable, `{"error":"provider_unavailable"}`)
}

type larkExchange struct {
	user  feishu.User
	token feishu.CredentialTokenBundle
	err   error
}

func (e *credentialTestEnv) callback(cookie string, exchange larkExchange) *httptest.ResponseRecorder {
	e.t.Helper()
	e.apex.Credentials.ExchangeCode = func(context.Context, string) (feishu.User, feishu.CredentialTokenBundle, error) {
		return exchange.user, exchange.token, exchange.err
	}
	request := httptest.NewRequest(http.MethodGet, "http://localhost/auth/callback", nil)
	if cookie != "" {
		request.Header.Set("Cookie", cookie)
	}
	recorder := httptest.NewRecorder()
	e.apex.handleLarkCredentialCallback(recorder, request, "code-1")
	return recorder
}

func alice() feishu.User { return feishu.User{UnionID: "u-alice", OpenID: "ou", Name: "Alice"} }

func credentialToken(access, refresh string, expiresAt, refreshExpiresAt int64, scope string) feishu.CredentialTokenBundle {
	return feishu.CredentialTokenBundle{
		UserTokenBundle: feishu.UserTokenBundle{AccessToken: access, RefreshToken: refresh, ExpiresAt: expiresAt, RefreshExpiresAt: refreshExpiresAt},
		Scope:           scope,
	}
}

func assertRedirect(t *testing.T, recorder *httptest.ResponseRecorder, location string) {
	t.Helper()
	if recorder.Code != http.StatusFound || recorder.Header().Get("Location") != location {
		t.Fatalf("got %d Location=%q, want 302 %q (%s)", recorder.Code, recorder.Header().Get("Location"), location, recorder.Body.String())
	}
}

func TestLarkCallbackRefusesMissingRefreshTokenAndRecordsExpiry(t *testing.T) {
	env := newCredentialTestEnv(t)
	cookie := env.cookie("u-alice", 0)
	assertRedirect(t, env.callback(cookie, larkExchange{user: alice(), token: credentialToken("a2", "", 1_900_000_000, 0, "")}), "/credentials?error=no_refresh_token")
	if docs := env.rawDocs("credentials"); len(docs) != 0 {
		t.Fatalf("a credential without refresh_token must not be stored: %v", docs)
	}

	// The scope Feishu actually granted rides back to the page (URLSearchParams encoding).
	trimmed := env.callback(cookie, larkExchange{user: alice(), token: credentialToken("a2", "", 1_900_000_000, 0, "contact:user:search wiki:wiki:readonly")})
	assertRedirect(t, trimmed, "/credentials?error=no_refresh_token&granted=contact%3Auser%3Asearch+wiki%3Awiki%3Areadonly")
	loc, _ := url.Parse(trimmed.Header().Get("Location"))
	if loc.Query().Get("granted") != "contact:user:search wiki:wiki:readonly" {
		t.Fatalf("granted = %q", loc.Query().Get("granted"))
	}
	if docs := env.rawDocs("credentials"); len(docs) != 0 {
		t.Fatalf("stored: %v", docs)
	}

	withExpiry := env.callback(cookie, larkExchange{user: alice(), token: credentialToken("a3", "refresh-3", 1_900_000_000, 1_902_000_000, "offline_access wiki:wiki:readonly")})
	assertRedirect(t, withExpiry, "/credentials?authorized=lark-cli")
	stored, err := env.stored("u-alice", store.CredentialPlatformLarkCLI)
	if err != nil {
		t.Fatal(err)
	}
	if stored.RefreshExpiresAt != 1_902_000_000_000 {
		t.Fatalf("refreshExpiresAt = %d", stored.RefreshExpiresAt)
	}
	// The granted scope is recorded, not the configured one.
	if stored.Meta.Scope != "offline_access wiki:wiki:readonly" {
		t.Fatalf("meta.scope = %q", stored.Meta.Scope)
	}
	if got := env.openStored(stored); got != `{"oauth":"v2","refreshToken":"refresh-3","accessToken":"a3","accessExpiresAt":1900000000000,"refreshExpiresAt":1902000000000}` {
		t.Fatalf("payload = %s", got)
	}
	// BSON types match the Node driver: ms timestamps are doubles.
	raw := env.rawDocs("credentials")[0]
	if _, isDouble := raw["refreshExpiresAt"].(float64); !isDouble {
		t.Fatalf("refreshExpiresAt BSON type = %T", raw["refreshExpiresAt"])
	}
}

func TestLarkCallbackAccountMismatchAndStore(t *testing.T) {
	env := newCredentialTestEnv(t)
	cookie := env.cookie("u-alice", 0)
	mallory := feishu.User{UnionID: "u-mallory", OpenID: "ou", Name: "Alice"}
	bad := env.callback(cookie, larkExchange{user: mallory, token: credentialToken("a1", "refresh-token-plaintext-sentinel", 1_900_000_000, 0, "")})
	if bad.Code != http.StatusForbidden || bad.Body.String() != "授权账号与当前登录账号不一致，未保存。请用当前登录的飞书账号重新授权。" {
		t.Fatalf("mismatch = %d %q", bad.Code, bad.Body.String())
	}
	if docs := env.rawDocs("credentials"); len(docs) != 0 {
		t.Fatalf("stored: %v", docs)
	}

	ok := env.callback(cookie, larkExchange{user: alice(), token: credentialToken("a1", "refresh-token-plaintext-sentinel", 1_900_000_000, 0, "")})
	assertRedirect(t, ok, "/credentials?authorized=lark-cli")
	stored, err := env.stored("u-alice", store.CredentialPlatformLarkCLI)
	if err != nil {
		t.Fatal(err)
	}
	if stored.Kind != store.CredentialKindLarkOAuth || stored.Meta.AppID != "cli_platform" || !stored.ConsentTeams.All {
		t.Fatalf("stored = %+v", stored)
	}
	// Without a granted scope the configured list is recorded.
	if stored.Meta.Scope != "docx:document:readonly" || stored.Meta.Account != "Alice" {
		t.Fatalf("meta = %+v", stored.Meta)
	}
	if got := env.openStored(stored); got != `{"oauth":"v2","refreshToken":"refresh-token-plaintext-sentinel","accessToken":"a1","accessExpiresAt":1900000000000}` {
		t.Fatalf("payload = %s", got)
	}
	rawJSON, _ := json.Marshal(env.rawDocs("credentials"))
	if strings.Contains(string(rawJSON), "refresh-token-plaintext-sentinel") {
		t.Fatal("the plaintext refresh token must never be stored")
	}
	// meta is written in the TS literal order {appId, scope, account}
	// (MemoryDatabase keeps documents as maps, so check the encoded value).
	encoded, err := bson.Marshal(stored.Meta)
	if err != nil {
		t.Fatal(err)
	}
	elements, _ := bson.Raw(encoded).Elements()
	keys := []string{}
	for _, element := range elements {
		keys = append(keys, element.Key())
	}
	if strings.Join(keys, ",") != "appId,scope,account" {
		t.Fatalf("meta order = %v", keys)
	}
}

func TestLarkCallbackEdgeCases(t *testing.T) {
	env := newCredentialTestEnv(t)
	assertRedirect(t, env.callback("", larkExchange{user: alice()}), "/auth/login?next=%2Fcredentials")

	failed := env.callback(env.cookie("u-alice", 0), larkExchange{err: errors.New("boom")})
	if failed.Code != http.StatusBadGateway || failed.Body.String() != "飞书授权失败：Error: boom" {
		t.Fatalf("exchange failure = %d %q", failed.Code, failed.Body.String())
	}

	env.apex.CredentialStore = store.NewCredentialStore(store.UnavailableDatabaseProvider{})
	assertRedirect(t, env.callback(env.cookie("u-alice", 0), larkExchange{user: alice(), token: credentialToken("a", "r", 1, 0, "")}), "/credentials?error=store_unavailable")

	env.apex.Config.CredentialKEK = nil
	assertRedirect(t, env.callback(env.cookie("u-alice", 0), larkExchange{user: alice()}), "/credentials?error=credential_vault_disabled")
}

// TestLarkCallbackThroughApexState drives the real authorize → /auth/callback
// round trip: the signed state carries the credential mount, so the apex
// routes the callback here instead of minting a login session.
func TestLarkCallbackThroughApexState(t *testing.T) {
	env := newCredentialTestEnv(t)
	authorize := env.do("/api/credentials/lark-cli/authorize", credentialRequest{method: http.MethodPost})
	u, _ := url.Parse(decodeBody(t, authorize)["url"].(string))
	stateCookie := strings.SplitN(authorize.Header().Get("Set-Cookie"), ";", 2)[0]
	env.apex.Credentials.ExchangeCode = func(_ context.Context, code string) (feishu.User, feishu.CredentialTokenBundle, error) {
		if code != "the-code" {
			t.Errorf("code = %q", code)
		}
		return alice(), credentialToken("a1", "r1", 1_900_000_000, 0, "offline_access"), nil
	}
	request := httptest.NewRequest(http.MethodGet, "http://localhost/auth/callback?code=the-code&state="+url.QueryEscape(u.Query().Get("state")), nil)
	request.Header.Set("Cookie", env.cookie("u-alice", 0)+"; "+stateCookie)
	recorder := httptest.NewRecorder()
	env.apex.ServeHTTP(recorder, request)
	assertRedirect(t, recorder, "/credentials?authorized=lark-cli")
	if _, err := env.stored("u-alice", store.CredentialPlatformLarkCLI); err != nil {
		t.Fatal(err)
	}
}

func TestDeviceLoginAuthorizeAndCompleteFlow(t *testing.T) {
	env := newCredentialTestEnv(t)
	begun := env.do("/api/credentials/device-cli/authorize", credentialRequest{method: http.MethodPost})
	if begun.Code != http.StatusOK {
		t.Fatalf("begin = %d %s", begun.Code, begun.Body.String())
	}
	body := decodeBody(t, begun)
	pendingID, _ := body["pendingId"].(string)
	if body["authUrl"] != "https://sso.test/v?1" || !regexp.MustCompile(`^cp_[a-f0-9]{24}$`).MatchString(pendingID) {
		t.Fatalf("begin = %s", begun.Body.String())
	}
	if begun.Body.String() != `{"pendingId":"`+pendingID+`","authUrl":"https://sso.test/v?1"}` {
		t.Fatalf("begin body order = %s", begun.Body.String())
	}
	list := decodeBody(t, env.do("/api/credentials", credentialRequest{}))
	pending, _ := list["pending"].(map[string]any)
	if pending["platform"] != "device-cli" || pending["id"] != pendingID || pending["authUrl"] != "https://sso.test/v?1" {
		t.Fatalf("list pending = %v", list["pending"])
	}

	completeBody := `{"pendingId":"` + pendingID + `"}`
	// Polling uses the routine window: an hour-old session still works.
	stillPending := env.do("/api/credentials/device-cli/complete", credentialRequest{method: http.MethodPost, body: completeBody, cookie: credentialStr(env.cookie("u-alice", time.Hour))})
	assertCredentialResponse(t, stillPending, http.StatusOK, `{"state":"pending","authUrl":"https://sso.test/v?1"}`)

	env.device.set(func(f *fakeDeviceLogin) { f.complete = credential.DeviceLoginAuthorized })
	done := env.do("/api/credentials/device-cli/complete", credentialRequest{method: http.MethodPost, body: completeBody})
	assertCredentialResponse(t, done, http.StatusOK, `{"state":"authorized"}`)
	if strings.Join(env.device.polled, "|") != `{"challenge":"ct"}|{"challenge":"ct"}` {
		t.Fatalf("provider polled with %q", env.device.polled)
	}
	stored, err := env.stored("u-alice", testDevicePlatform)
	if err != nil || stored.Kind != "device-archive" || stored.Meta.Account != "alice@example.test" || stored.RefreshExpiresAt != 42 {
		t.Fatalf("stored = %+v (%v)", stored, err)
	}
	if got := env.openStored(stored); got != `{"login":"archive"}` {
		t.Fatalf("stored payload = %s", got)
	}
	if docs := env.rawDocs("credential_pending"); len(docs) != 0 {
		t.Fatalf("pending left behind: %v", docs)
	}

	// Somebody else's (or a finished) pending id is not found.
	other := env.do("/api/credentials/device-cli/complete", credentialRequest{method: http.MethodPost, body: completeBody, cookie: credentialStr(env.cookie("u-bob", 0))})
	assertCredentialResponse(t, other, http.StatusNotFound, `{"error":"pending_not_found"}`)
}

func TestDeviceLoginCompleteEdgeCases(t *testing.T) {
	env := newCredentialTestEnv(t)
	for _, body := range []string{`{}`, `{"pendingId":"cp_xyz"}`, `{"pendingId":42}`, `[]`, `not json`} {
		assertCredentialResponse(t, env.do("/api/credentials/device-cli/complete", credentialRequest{method: http.MethodPost, body: body}), http.StatusBadRequest, `{"error":"invalid"}`)
	}
	begun := decodeBody(t, env.do("/api/credentials/device-cli/authorize", credentialRequest{method: http.MethodPost}))
	completeBody := `{"pendingId":"` + begun["pendingId"].(string) + `"}`
	env.device.set(func(f *fakeDeviceLogin) { f.complete = credential.DeviceLoginUnavailable })
	assertCredentialResponse(t, env.do("/api/credentials/device-cli/complete", credentialRequest{method: http.MethodPost, body: completeBody}), http.StatusOK, `{"state":"unavailable","detail":"authorization service unavailable"}`)
	env.device.set(func(f *fakeDeviceLogin) { f.complete = credential.DeviceLoginFailed })
	assertCredentialResponse(t, env.do("/api/credentials/device-cli/complete", credentialRequest{method: http.MethodPost, body: completeBody}), http.StatusOK, `{"state":"failed","detail":"login challenge expired or was rejected"}`)
	// A failed login drops its pending record.
	assertCredentialResponse(t, env.do("/api/credentials/device-cli/complete", credentialRequest{method: http.MethodPost, body: completeBody}), http.StatusNotFound, `{"error":"pending_not_found"}`)

	// A pending login of another platform is not this platform's to complete.
	begun = decodeBody(t, env.do("/api/credentials/device-cli/authorize", credentialRequest{method: http.MethodPost}))
	completeBody = `{"pendingId":"` + begun["pendingId"].(string) + `"}`
	second := &fakeDeviceLogin{available: true}
	env.apex.Credentials.Providers.DeviceLogins = append(env.apex.Credentials.Providers.DeviceLogins, secondDeviceLogin{second})
	assertCredentialResponse(t, env.do("/api/credentials/other-cli/complete", credentialRequest{method: http.MethodPost, body: completeBody}), http.StatusNotFound, `{"error":"pending_not_found"}`)
	if len(second.polled) != 0 {
		t.Fatalf("another platform polled %q", second.polled)
	}

	// A pending record sealed under another key is dropped as invalid.
	other := make([]byte, 32)
	_, _ = rand.Read(other)
	env.apex.Config.CredentialKEK = other
	assertCredentialResponse(t, env.do("/api/credentials/device-cli/complete", credentialRequest{method: http.MethodPost, body: completeBody}), http.StatusConflict, `{"error":"pending_invalid"}`)
	if docs := env.rawDocs("credential_pending"); len(docs) != 0 {
		t.Fatalf("invalid pending kept: %v", docs)
	}

	// The provider cannot run on this pod.
	env.device.set(func(f *fakeDeviceLogin) { f.available = false })
	assertCredentialResponse(t, env.do("/api/credentials/device-cli/authorize", credentialRequest{method: http.MethodPost}), http.StatusServiceUnavailable, `{"error":"provider_unavailable"}`)
	// It runs but the login cannot start.
	env.device.set(func(f *fakeDeviceLogin) { f.available, f.beginFails = true, true })
	assertCredentialResponse(t, env.do("/api/credentials/device-cli/authorize", credentialRequest{method: http.MethodPost}), http.StatusBadGateway, `{"error":"provider_unavailable","detail":"could not start a login"}`)
}

// secondDeviceLogin is another device-login platform.
type secondDeviceLogin struct{ *fakeDeviceLogin }

func (s secondDeviceLogin) Descriptor() credential.DeviceLoginDescriptor {
	d := s.fakeDeviceLogin.Descriptor()
	d.Platform = "other-cli"
	return d
}

func TestCredentialConsentOnlyOwnTeamsAndStrictRevoke(t *testing.T) {
	env := newCredentialTestEnv(t)
	sealed, _ := credential.SealPayload(env.keys, "u-alice", "lark-cli", map[string]string{"refreshToken": "r"})
	if _, err := env.apex.CredentialStore.Upsert(context.Background(), store.UpsertCredentialInput{
		UnionID: "u-alice", Platform: store.CredentialPlatformLarkCLI, Kind: store.CredentialKindLarkOAuth, Sealed: sealed,
	}); err != nil {
		t.Fatal(err)
	}
	put := func(body string, cookie *string) *httptest.ResponseRecorder {
		return env.do("/api/credentials/lark-cli/consent", credentialRequest{method: http.MethodPut, body: body, cookie: cookie})
	}
	assertCredentialResponse(t, put(`{"teams":["t1","deadbeefdeadbeef"]}`, nil), http.StatusForbidden, `{"error":"not_in_team","teamIds":["deadbeefdeadbeef"]}`)
	assertCredentialResponse(t, put(`{"teams":["t2","t2"]}`, credentialStr(env.cookie("u-alice", time.Hour))), http.StatusOK, `{"ok":true,"consentTeams":["t2"]}`)
	stored, _ := env.stored("u-alice", store.CredentialPlatformLarkCLI)
	if stored.ConsentTeams.All || strings.Join(stored.ConsentTeams.Teams, ",") != "t2" {
		t.Fatalf("consent = %+v", stored.ConsentTeams)
	}
	assertCredentialResponse(t, put(`{"teams":[]}`, nil), http.StatusOK, `{"ok":true,"consentTeams":[]}`)
	for _, body := range []string{`{"teams":"everyone"}`, `{"teams":["bad id"]}`, `{"teams":[1]}`, `{}`, `null`} {
		assertCredentialResponse(t, put(body, nil), http.StatusBadRequest, `{"error":"invalid"}`)
	}
	assertCredentialResponse(t, put(`{"teams":"all"}`, nil), http.StatusOK, `{"ok":true,"consentTeams":"all"}`)
	assertCredentialResponse(t, env.do("/api/credentials/device-cli/consent", credentialRequest{method: http.MethodPut, body: `{"teams":"all"}`}), http.StatusNotFound, `{"error":"not_found"}`)
	// Consent edits use the routine window; a day-old session is stale.
	assertCredentialResponse(t, put(`{"teams":"all"}`, credentialStr(env.cookie("u-alice", 13*time.Hour))), http.StatusUnauthorized, `{"error":"stale_session","loginUrl":"/auth/login"}`)

	stale := env.do("/api/credentials/lark-cli", credentialRequest{method: http.MethodDelete, cookie: credentialStr(env.cookie("u-alice", 601*time.Second))})
	assertCredentialResponse(t, stale, http.StatusUnauthorized, `{"error":"stale_session","loginUrl":"/auth/login"}`)
	assertCredentialResponse(t, env.do("/api/credentials/lark-cli", credentialRequest{method: http.MethodDelete}), http.StatusOK, `{"ok":true,"removed":true}`)
	if docs := env.rawDocs("credentials"); len(docs) != 0 {
		t.Fatalf("revoked credential kept: %v", docs)
	}
	assertCredentialResponse(t, env.do("/api/credentials/lark-cli", credentialRequest{method: http.MethodDelete}), http.StatusOK, `{"ok":true,"removed":false}`)
}

func TestCredentialsVaultDisabled(t *testing.T) {
	env := newCredentialTestEnv(t)
	env.apex.Config.CredentialKEK = nil
	list := env.do("/api/credentials", credentialRequest{})
	if list.Code != http.StatusOK || decodeBody(t, list)["vaultEnabled"] != false {
		t.Fatalf("list = %d %s", list.Code, list.Body.String())
	}
	assertCredentialResponse(t, env.do("/api/credentials/lark-cli/authorize", credentialRequest{method: http.MethodPost}), http.StatusServiceUnavailable, `{"error":"credential_vault_disabled"}`)
}

func TestCredentialsRoutingAndPrincipalErrors(t *testing.T) {
	env := newCredentialTestEnv(t)
	assertCredentialResponse(t, env.do("/api/credentials/git/authorize", credentialRequest{method: http.MethodPost}), http.StatusNotFound, `{"error":"not_found"}`)
	assertCredentialResponse(t, env.do("/api/credentials/lark-cli/a/b", credentialRequest{method: http.MethodPost}), http.StatusNotFound, `{"error":"not_found"}`)
	assertCredentialResponse(t, env.do("/api/credentials", credentialRequest{method: http.MethodPost}), http.StatusNotFound, `{"error":"not_found"}`)
	assertCredentialResponse(t, env.do("/api/credentials/lark-cli/authorize", credentialRequest{method: http.MethodGet}), http.StatusMethodNotAllowed, `{"error":"method_not_allowed"}`)
	assertCredentialResponse(t, env.do("/api/credentials/lark-cli/complete", credentialRequest{method: http.MethodPost}), http.StatusMethodNotAllowed, `{"error":"method_not_allowed"}`)
	// Anonymous writes are stale sessions (requireFreshSso(null) is null).
	assertCredentialResponse(t, env.do("/api/credentials/lark-cli/authorize", credentialRequest{method: http.MethodPost, cookie: credentialStr("")}), http.StatusUnauthorized, `{"error":"stale_session","loginUrl":"/auth/login"}`)
	assertCredentialResponse(t, env.do("/api/credentials/grants", credentialRequest{cookie: credentialStr("")}), http.StatusUnauthorized, `{"error":"unauthenticated"}`)
}

func TestCredentialGrantLimitParsing(t *testing.T) {
	cases := map[string]int{
		"": 50, "limit=": 50, "limit=0": 50, "limit=abc": 50, "limit=10": 10, "limit=500": 200, "limit=-3": 1,
		"limit=0x10": 16, "limit=%2010%20": 10, "limit=Infinity": 200, "limit=1e2": 100, "limit=2.9": 2,
	}
	for query, want := range cases {
		values, _ := url.ParseQuery(query)
		if got := credentialGrantLimit(values); got != want {
			t.Errorf("limit(%q) = %d, want %d", query, got, want)
		}
	}
}

func TestCredentialFormEncodeMatchesURLSearchParams(t *testing.T) {
	if got := credentialFormEncode("contact:user:search wiki:wiki.readonly*-_~é"); got != "contact%3Auser%3Asearch+wiki%3Awiki.readonly*-_%7E%C3%A9" {
		t.Fatalf("encode = %s", got)
	}
}

func TestCredentialPublicOrigin(t *testing.T) {
	for base, want := range map[string]string{
		"http://localhost":              "http://localhost",
		"https://Botmux.Example:443/x/": "https://botmux.example",
		"http://127.0.0.1:8080/":        "http://127.0.0.1:8080",
		"not a url":                     "null",
	} {
		if got := credentialPublicOrigin(base); got != want {
			t.Errorf("origin(%q) = %q, want %q", base, got, want)
		}
	}
}

// TestCredentialsMemoryModeFailsClosed: without MONGODB_URI the vault sits on
// UnavailableDatabaseProvider and never falls back to process memory.
func TestCredentialsMemoryModeFailsClosed(t *testing.T) {
	env := newCredentialTestEnv(t)
	env.apex.CredentialStore = store.NewCredentialStore(store.UnavailableDatabaseProvider{})
	assertCredentialResponse(t, env.do("/api/credentials", credentialRequest{}), http.StatusServiceUnavailable, `{"error":"store_unavailable"}`)
	assertCredentialResponse(t, env.do("/api/credentials/grants", credentialRequest{}), http.StatusServiceUnavailable, `{"error":"store_unavailable"}`)
	assertCredentialResponse(t, env.do("/api/credentials/lark-cli", credentialRequest{method: http.MethodDelete}), http.StatusServiceUnavailable, `{"error":"store_unavailable"}`)
	assertCredentialResponse(t, env.do("/api/credentials/lark-cli/consent", credentialRequest{method: http.MethodPut, body: `{"teams":"all"}`}), http.StatusServiceUnavailable, `{"error":"store_unavailable"}`)
	assertCredentialResponse(t, env.do("/api/credentials/device-cli/authorize", credentialRequest{method: http.MethodPost}), http.StatusServiceUnavailable, `{"error":"store_unavailable"}`)
}

// authorizeScope posts an authorize request and returns the requested scope.
func (e *credentialTestEnv) authorizeScope(body string) (*httptest.ResponseRecorder, string) {
	e.t.Helper()
	recorder := e.do("/api/credentials/lark-cli/authorize", credentialRequest{method: http.MethodPost, body: body})
	if recorder.Code != http.StatusOK {
		return recorder, ""
	}
	u, err := url.Parse(decodeBody(e.t, recorder)["url"].(string))
	if err != nil {
		e.t.Fatal(err)
	}
	return recorder, u.Query().Get("scope")
}

func (e *credentialTestEnv) seedLarkGrant(scope string) {
	e.t.Helper()
	sealed, err := credential.SealPayload(e.keys, "u-alice", "lark-cli", credential.LarkOAuthPayload{RefreshToken: "r"})
	if err != nil {
		e.t.Fatal(err)
	}
	if _, err := e.apex.CredentialStore.Upsert(context.Background(), store.UpsertCredentialInput{
		UnionID: "u-alice", Platform: store.CredentialPlatformLarkCLI, Kind: store.CredentialKindLarkOAuth, Sealed: sealed,
		Meta: store.CredentialMeta{AppID: "cli_platform", Scope: scope, Account: "Alice"},
	}); err != nil {
		e.t.Fatal(err)
	}
}

func TestLarkAuthorizeIncrementalScopes(t *testing.T) {
	env := newCredentialTestEnv(t)
	env.apex.Config.LarkCredentialScopes = ""
	enabled := []string{"docx:document:readonly", "im:message:readonly", "base:record:read", "base:record:create", "base:field:read", "offline_access"}
	env.apex.Credentials.ListUserScopes = func(context.Context) ([]string, error) { return enabled, nil }

	// Old clients send no scopes: the full default list, unchanged.
	if _, got := env.authorizeScope(""); got != strings.Join(enabled, " ") {
		t.Fatalf("default scope = %q", got)
	}
	if _, got := env.authorizeScope(`{"scopes":null}`); got != strings.Join(enabled, " ") {
		t.Fatalf("null scopes = %q", got)
	}

	// No credential yet: the default list, with the requested scopes first.
	if _, got := env.authorizeScope(`{"scopes":["base:record:read","base:field:read"]}`); got != "base:record:read base:field:read docx:document:readonly im:message:readonly base:record:create offline_access" {
		t.Fatalf("first incremental scope = %q", got)
	}

	// An existing grant: exactly what was granted plus the missing scopes.
	// A granted scope the app no longer enables is dropped (Feishu would
	// reject the whole page), and offline_access always rides along.
	env.seedLarkGrant("docx:document:readonly im:chat:gone offline_access")
	if _, got := env.authorizeScope(`{"scopes":["base:record:read","base:record:create","base:record:read"]}`); got != "base:record:read base:record:create docx:document:readonly offline_access" {
		t.Fatalf("merged scope = %q", got)
	}

	// A grant that recorded nothing usable falls back to the full list.
	env.seedLarkGrant("offline_access")
	if _, got := env.authorizeScope(`{"scopes":["base:field:read"]}`); got != "base:field:read docx:document:readonly im:message:readonly base:record:read base:record:create offline_access" {
		t.Fatalf("empty-grant scope = %q", got)
	}

	// Scopes the platform app has not enabled: refuse with the list, before
	// any Feishu page is built.
	recorder, _ := env.authorizeScope(`{"scopes":["base:record:read","base:record:delete","bitable:app"]}`)
	assertCredentialResponse(t, recorder, http.StatusConflict, `{"error":"scope_not_enabled","scopes":["base:record:delete","bitable:app"]}`)
	if recorder.Header().Get("Set-Cookie") != "" {
		t.Fatalf("refusal must not start an OAuth state: %q", recorder.Header().Get("Set-Cookie"))
	}

	// A configured whitelist is the requestable set: outside it is refused too.
	env.apex.Config.LarkCredentialScopes = "docx:document:readonly"
	recorder, _ = env.authorizeScope(`{"scopes":["base:record:read"]}`)
	assertCredentialResponse(t, recorder, http.StatusConflict, `{"error":"scope_not_enabled","scopes":["base:record:read"]}`)
	env.apex.Config.LarkCredentialScopes = ""

	// Malformed scope members are a 400, never a silently full authorization.
	for _, bad := range []string{`{"scopes":"base:record:read"}`, `{"scopes":[1]}`, `{"scopes":["no spaces allowed"]}`, `{"scopes":["base:record:read&x=1"]}`, `{"scopes":["` + strings.Repeat("a:", 70) + `b"]}`} {
		recorder, _ := env.authorizeScope(bad)
		assertCredentialResponse(t, recorder, http.StatusBadRequest, `{"error":"invalid"}`)
	}
	many := make([]string, maxIncrementalScopes+1)
	for i := range many {
		many[i] = fmt.Sprintf(`"s:%d"`, i)
	}
	recorder, _ = env.authorizeScope(`{"scopes":[` + strings.Join(many, ",") + `]}`)
	assertCredentialResponse(t, recorder, http.StatusBadRequest, `{"error":"invalid"}`)
}

func TestLarkAuthorizeIncrementalScopesSurviveTheCap(t *testing.T) {
	env := newCredentialTestEnv(t)
	env.apex.Config.LarkCredentialScopes = ""
	enabled := []string{}
	for i := 0; i < 260; i++ {
		enabled = append(enabled, fmt.Sprintf("calendar:s%d:write", i))
	}
	enabled = append(enabled, "base:record:read", "offline_access")
	env.apex.Credentials.ListUserScopes = func(context.Context) ([]string, error) { return enabled, nil }
	_, got := env.authorizeScope(`{"scopes":["calendar:s259:write"]}`)
	scopes := strings.Fields(got)
	if len(scopes) != feishu.MaxAuthorizeScopes || scopes[0] != "calendar:s259:write" || scopes[1] != "base:record:read" || scopes[len(scopes)-1] != "offline_access" {
		t.Fatalf("capped incremental scope = %d %q … %q", len(scopes), scopes[:2], scopes[len(scopes)-1])
	}
}
