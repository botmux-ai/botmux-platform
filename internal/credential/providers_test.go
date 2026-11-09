package credential

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/botmux-ai/botmux-platform/internal/config"
	"github.com/botmux-ai/botmux-platform/internal/feishu"
)

// Ports test/auth-credential-providers.test.ts.

const providerNowMS int64 = 1_800_000_000_000

type feishuCall struct {
	Path          string
	Body          string
	Authorization string
}

type feishuAnswer struct {
	status int
	body   string
}

// fakeFeishu answers the app_access_token call with appToken and every other
// call with handler, recording the raw request bodies (key order included).
type fakeFeishu struct {
	t        *testing.T
	server   *httptest.Server
	mu       sync.Mutex
	calls    []feishuCall
	handler  func(call feishuCall) feishuAnswer
	appToken feishuAnswer
}

func newFakeFeishu(t *testing.T, handler func(call feishuCall) feishuAnswer) *fakeFeishu {
	t.Helper()
	f := &fakeFeishu{t: t, handler: handler, appToken: feishuAnswer{200, `{"code":0,"app_access_token":"app-at"}`}}
	f.server = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		raw, _ := io.ReadAll(r.Body)
		call := feishuCall{Path: r.URL.Path, Body: string(raw), Authorization: r.Header.Get("Authorization")}
		f.mu.Lock()
		f.calls = append(f.calls, call)
		f.mu.Unlock()
		answer := f.appToken
		if r.URL.Path != "/open-apis/auth/v3/app_access_token/internal" {
			answer = f.handler(call)
		}
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(answer.status)
		_, _ = io.WriteString(w, answer.body)
	}))
	t.Cleanup(f.server.Close)
	return f
}

func (f *fakeFeishu) recorded() []feishuCall {
	f.mu.Lock()
	defer f.mu.Unlock()
	return append([]feishuCall(nil), f.calls...)
}

type providerFixture struct {
	keys      *Keys
	providers Providers
}

func newProviderFixture(t *testing.T, fake *fakeFeishu) providerFixture {
	t.Helper()
	kek := randomKey(t)
	keys := &Keys{Current: kek, All: [][]byte{kek}}
	cfg := config.Config{
		PublicBaseURL: "http://localhost", FeishuAppID: "cli_platform", FeishuAppSecret: "app-secret",
		CredentialKEK: kek,
	}
	p := Providers{
		Config: cfg,
		Keys:   StaticKeySource(keys),
		Now:    func() time.Time { return time.UnixMilli(providerNowMS) },
	}
	if fake != nil {
		p.Feishu = feishu.NewClient(fake.server.URL, cfg.FeishuAppID, cfg.FeishuAppSecret, fake.server.Client())
	}
	return providerFixture{keys: keys, providers: p}
}

func (f providerFixture) record(t *testing.T, platform string, payload any) Record {
	t.Helper()
	sealed, err := SealPayload(f.keys, "on_a", platform, payload)
	if err != nil {
		t.Fatal(err)
	}
	return Record{UnionID: "on_a", Platform: platform, Sealed: sealed}
}

func (f providerFixture) reopen(t *testing.T, platform string, sealed *Sealed) string {
	t.Helper()
	if sealed == nil {
		t.Fatal("expected a resealed payload")
	}
	plain, ok := OpenPayload(f.keys, "on_a", platform, *sealed)
	if !ok {
		t.Fatal("resealed payload cannot be opened")
	}
	return string(plain)
}

func assertMintFailure(t *testing.T, got MintResult, want MintFailure) {
	t.Helper()
	if got.OK || got.Reason != want {
		t.Fatalf("mint = %+v, want failure %q", got, want)
	}
}

// variablesJSON encodes like the server's writeJSON (no HTML escaping, as
// JSON.stringify).
func variablesJSON(t *testing.T, v Variables) string {
	t.Helper()
	var out strings.Builder
	encoder := json.NewEncoder(&out)
	encoder.SetEscapeHTML(false)
	if err := encoder.Encode(v); err != nil {
		t.Fatal(err)
	}
	return strings.TrimSuffix(out.String(), "\n")
}

// ---- lark-cli ----

func TestMintLarkReusesCachedAccessToken(t *testing.T) {
	fake := newFakeFeishu(t, func(feishuCall) feishuAnswer { return feishuAnswer{500, `{}`} })
	f := newProviderFixture(t, fake)
	rec := f.record(t, PlatformLarkCLI, LarkOAuthPayload{RefreshToken: "r1", AccessToken: "a1", AccessExpiresAt: float64(providerNowMS + 3_600_000)})
	got := f.providers.MintLark(context.Background(), rec)
	if !got.OK {
		t.Fatalf("mint = %+v", got)
	}
	if v := variablesJSON(t, got.Variables); v != `{"LARKSUITE_CLI_APP_ID":"cli_platform","LARKSUITE_CLI_USER_ACCESS_TOKEN":"a1"}` {
		t.Fatalf("variables = %s", v)
	}
	if got.ExpiresAt != providerNowMS+3_600_000 || got.UpdatedSealed != nil {
		t.Fatalf("expiresAt=%d updated=%v", got.ExpiresAt, got.UpdatedSealed)
	}
	if calls := fake.recorded(); len(calls) != 0 {
		t.Fatalf("cached token must not refresh: %+v", calls)
	}
}

func TestMintLarkRefreshesViaOIDCAndReseals(t *testing.T) {
	fake := newFakeFeishu(t, func(call feishuCall) feishuAnswer {
		return feishuAnswer{200, `{"code":0,"data":{"access_token":"a2","refresh_token":"r2","expires_in":7000,"refresh_expires_in":2592000}}`}
	})
	f := newProviderFixture(t, fake)
	rec := f.record(t, PlatformLarkCLI, LarkOAuthPayload{RefreshToken: "r1", AccessToken: "a1", AccessExpiresAt: float64(providerNowMS + 60_000)})
	got := f.providers.MintLark(context.Background(), rec)
	if !got.OK {
		t.Fatalf("mint = %+v", got)
	}
	calls := fake.recorded()
	if len(calls) != 2 {
		t.Fatalf("calls = %+v", calls)
	}
	if calls[0].Path != "/open-apis/auth/v3/app_access_token/internal" || calls[0].Body != `{"app_id":"cli_platform","app_secret":"app-secret"}` {
		t.Fatalf("app token call = %+v", calls[0])
	}
	if calls[1].Path != "/open-apis/authen/v1/oidc/refresh_access_token" || calls[1].Body != `{"grant_type":"refresh_token","refresh_token":"r1"}` || calls[1].Authorization != "Bearer app-at" {
		t.Fatalf("refresh call = %+v", calls[1])
	}
	if got.Variables.Get("LARKSUITE_CLI_USER_ACCESS_TOKEN") != "a2" {
		t.Fatalf("variables = %+v", got.Variables)
	}
	if got.ExpiresAt != providerNowMS+7000*1000 || got.RefreshExpiresAt != providerNowMS+2_592_000*1000 {
		t.Fatalf("expiresAt=%d refreshExpiresAt=%d", got.ExpiresAt, got.RefreshExpiresAt)
	}
	want := fmt.Sprintf(`{"refreshToken":"r2","accessToken":"a2","accessExpiresAt":%d,"refreshExpiresAt":%d}`, providerNowMS+7000*1000, providerNowMS+2_592_000*1000)
	if reopened := f.reopen(t, PlatformLarkCLI, got.UpdatedSealed); reopened != want {
		t.Fatalf("resealed = %s, want %s", reopened, want)
	}
}

func TestMintLarkRefreshFailureClassification(t *testing.T) {
	ctx := context.Background()
	cases := []struct {
		name     string
		answer   feishuAnswer
		appToken *feishuAnswer
		want     MintFailure
		detail   string
	}{
		{name: "explicit reject code", answer: feishuAnswer{200, `{"code":20037,"msg":"refresh token invalid"}`}, want: MintReauthRequired, detail: "feishu refresh rejected: code=20037 refresh token invalid"},
		{name: "reject by message", answer: feishuAnswer{200, `{"code":12345,"msg":"Refresh Token has EXPIRED"}`}, want: MintReauthRequired},
		{name: "unknown code keeps the credential", answer: feishuAnswer{200, `{"code":99991663,"msg":"internal error"}`}, want: MintUnavailable, detail: "feishu refresh rejected: code=99991663 internal error"},
		{name: "5xx", answer: feishuAnswer{502, `{}`}, want: MintUnavailable, detail: "feishu http 502"},
		{name: "non-json body", answer: feishuAnswer{200, `<html>`}, want: MintUnavailable, detail: "feishu refresh rejected: code=unknown"},
		{name: "app token failure", answer: feishuAnswer{200, `{"code":0,"data":{"access_token":"x"}}`}, appToken: &feishuAnswer{200, `{"code":10003,"msg":"invalid app"}`}, want: MintUnavailable, detail: "feishu app_access_token failed: http 200 code=10003"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			fake := newFakeFeishu(t, func(feishuCall) feishuAnswer { return tc.answer })
			if tc.appToken != nil {
				fake.appToken = *tc.appToken
			}
			f := newProviderFixture(t, fake)
			got := f.providers.MintLark(ctx, f.record(t, PlatformLarkCLI, LarkOAuthPayload{RefreshToken: "r1"}))
			assertMintFailure(t, got, tc.want)
			if tc.detail != "" && got.Detail != tc.detail {
				t.Fatalf("detail = %q, want %q", got.Detail, tc.detail)
			}
		})
	}

	t.Run("expired refresh token never calls feishu", func(t *testing.T) {
		fake := newFakeFeishu(t, func(feishuCall) feishuAnswer { return feishuAnswer{200, `{"access_token":"x"}`} })
		f := newProviderFixture(t, fake)
		got := f.providers.MintLark(ctx, f.record(t, PlatformLarkCLI, LarkOAuthPayload{RefreshToken: "r1", RefreshExpiresAt: float64(providerNowMS - 1)}))
		assertMintFailure(t, got, MintReauthRequired)
		if got.Detail != "refresh token expired" || len(fake.recorded()) != 0 {
			t.Fatalf("detail=%q calls=%d", got.Detail, len(fake.recorded()))
		}
	})
}

func TestMintLarkOAuthV2RefreshKeepsMarker(t *testing.T) {
	fake := newFakeFeishu(t, func(call feishuCall) feishuAnswer {
		return feishuAnswer{200, `{"code":0,"access_token":"a2","refresh_token":"r2","expires_in":7200,"refresh_token_expires_in":604800,"scope":"offline_access docx:document:readonly"}`}
	})
	f := newProviderFixture(t, fake)
	rec := f.record(t, PlatformLarkCLI, LarkOAuthPayload{OAuth: OAuthV2, RefreshToken: "r1", AccessToken: "a1", AccessExpiresAt: float64(providerNowMS + 60_000)})
	got := f.providers.MintLark(context.Background(), rec)
	if !got.OK {
		t.Fatalf("mint = %+v", got)
	}
	calls := fake.recorded()
	if len(calls) != 1 {
		t.Fatalf("v2 must not fetch an app_access_token: %+v", calls)
	}
	if calls[0].Path != "/open-apis/authen/v2/oauth/token" ||
		calls[0].Body != `{"grant_type":"refresh_token","client_id":"cli_platform","client_secret":"app-secret","refresh_token":"r1"}` ||
		calls[0].Authorization != "" {
		t.Fatalf("v2 call = %+v", calls[0])
	}
	if got.Variables.Get("LARKSUITE_CLI_USER_ACCESS_TOKEN") != "a2" || got.ExpiresAt != providerNowMS+7200*1000 || got.RefreshExpiresAt != providerNowMS+604_800*1000 {
		t.Fatalf("mint = %+v", got)
	}
	want := fmt.Sprintf(`{"oauth":"v2","refreshToken":"r2","accessToken":"a2","accessExpiresAt":%d,"refreshExpiresAt":%d}`, providerNowMS+7200*1000, providerNowMS+604_800*1000)
	if reopened := f.reopen(t, PlatformLarkCLI, got.UpdatedSealed); reopened != want {
		t.Fatalf("resealed = %s, want %s", reopened, want)
	}
}

func TestMintLarkOAuthV2FailureClassification(t *testing.T) {
	cases := []struct {
		name   string
		answer feishuAnswer
		want   MintFailure
		detail string
	}{
		{name: "invalid_grant", answer: feishuAnswer{400, `{"code":20073,"error":"invalid_grant","error_description":"The refresh token has been used."}`}, want: MintReauthRequired, detail: "feishu refresh rejected: code=20073 invalid_grant The refresh token has been used."},
		{name: "unknown error keeps the credential", answer: feishuAnswer{400, `{"code":99991400,"error":"server_error","error_description":"busy"}`}, want: MintUnavailable, detail: "feishu refresh rejected: code=99991400 server_error busy"},
		{name: "5xx", answer: feishuAnswer{503, `{}`}, want: MintUnavailable, detail: "feishu http 503"},
		{name: "reauth code without invalid_grant", answer: feishuAnswer{400, `{"code":20064}`}, want: MintReauthRequired, detail: "feishu refresh rejected: code=20064"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			fake := newFakeFeishu(t, func(feishuCall) feishuAnswer { return tc.answer })
			f := newProviderFixture(t, fake)
			got := f.providers.MintLark(context.Background(), f.record(t, PlatformLarkCLI, LarkOAuthPayload{OAuth: OAuthV2, RefreshToken: "r1"}))
			assertMintFailure(t, got, tc.want)
			if got.Detail != tc.detail {
				t.Fatalf("detail = %q, want %q", got.Detail, tc.detail)
			}
		})
	}
}

func TestMintLarkWrongKEKNeedsReauth(t *testing.T) {
	fake := newFakeFeishu(t, func(feishuCall) feishuAnswer { return feishuAnswer{500, `{}`} })
	f := newProviderFixture(t, fake)
	rec := f.record(t, PlatformLarkCLI, LarkOAuthPayload{RefreshToken: "r1"})
	other := randomKey(t)
	f.providers.Keys = StaticKeySource(&Keys{Current: other, All: [][]byte{other}})
	got := f.providers.MintLark(context.Background(), rec)
	assertMintFailure(t, got, MintReauthRequired)
	if got.Detail != "stored credential cannot be opened" {
		t.Fatalf("detail = %q", got.Detail)
	}
}

func TestMintLarkPreconditions(t *testing.T) {
	ctx := context.Background()
	fake := newFakeFeishu(t, func(feishuCall) feishuAnswer { return feishuAnswer{500, `{}`} })

	f := newProviderFixture(t, fake)
	got := f.providers.MintLark(ctx, f.record(t, PlatformLarkCLI, map[string]any{"accessToken": "a1"}))
	assertMintFailure(t, got, MintReauthRequired)
	if got.Detail != "stored credential has no refresh token (re-authorize with offline_access)" {
		t.Fatalf("detail = %q", got.Detail)
	}

	f.providers.Config.FeishuAppSecret = ""
	got = f.providers.MintLark(ctx, f.record(t, PlatformLarkCLI, LarkOAuthPayload{RefreshToken: "r1"}))
	assertMintFailure(t, got, MintUnavailable)
	if got.Detail != "platform feishu app not configured" {
		t.Fatalf("detail = %q", got.Detail)
	}

	f = newProviderFixture(t, fake)
	f.providers.Keys = StaticKeySource(nil)
	got = f.providers.MintLark(ctx, Record{UnionID: "on_a", Platform: PlatformLarkCLI})
	assertMintFailure(t, got, MintUnavailable)
	if got.Detail != "credential keys unavailable" {
		t.Fatalf("detail = %q", got.Detail)
	}

	// A stored issuing app id wins over the platform app.
	f = newProviderFixture(t, fake)
	rec := f.record(t, PlatformLarkCLI, LarkOAuthPayload{RefreshToken: "r1", AccessToken: "a1", AccessExpiresAt: float64(providerNowMS + 3_600_000)})
	rec.AppID = "cli_other"
	got = f.providers.MintLark(ctx, rec)
	if !got.OK || got.Variables.Get("LARKSUITE_CLI_APP_ID") != "cli_other" {
		t.Fatalf("mint = %+v", got)
	}
}

func TestMintLarkTransportFailureIsUnavailable(t *testing.T) {
	fake := newFakeFeishu(t, func(feishuCall) feishuAnswer { return feishuAnswer{200, `{}`} })
	f := newProviderFixture(t, fake)
	fake.server.Close()
	got := f.providers.MintLark(context.Background(), f.record(t, PlatformLarkCLI, LarkOAuthPayload{OAuth: OAuthV2, RefreshToken: "r1"}))
	assertMintFailure(t, got, MintUnavailable)
	if got.Detail != "feishu refresh failed: TypeError: fetch failed" {
		t.Fatalf("detail = %q", got.Detail)
	}
}

func TestVariablesMarshalInInsertionOrder(t *testing.T) {
	v := Variables{{"B", "2"}, {"A", "<&>"}}
	if got := variablesJSON(t, v); got != `{"B":"2","A":"<&>"}` {
		t.Fatalf("variables = %s", got)
	}
	if got := variablesJSON(t, nil); got != `{}` {
		t.Fatalf("empty variables = %s", got)
	}
}

// deviceLoginStub records what the vault hands a device-login provider.
type deviceLoginStub struct {
	keys *Keys
	recs []Record
}

func (s *deviceLoginStub) Descriptor() DeviceLoginDescriptor {
	return DeviceLoginDescriptor{Platform: "device-cli", Kind: "device-archive"}
}
func (s *deviceLoginStub) Available() bool                        { return true }
func (s *deviceLoginStub) Begin(context.Context) DeviceLoginBegin { return DeviceLoginBegin{} }
func (s *deviceLoginStub) Complete(context.Context, []byte) DeviceLoginComplete {
	return DeviceLoginComplete{}
}
func (s *deviceLoginStub) Mint(_ context.Context, keys *Keys, rec Record) MintResult {
	s.keys = keys
	s.recs = append(s.recs, rec)
	return MintResult{OK: true, Variables: Variables{{"DEVICE_CLI_TOKEN", "t"}}}
}

func TestMintDispatchesToDeviceLogins(t *testing.T) {
	ctx := context.Background()
	f := newProviderFixture(t, nil)
	stub := &deviceLoginStub{}
	f.providers.DeviceLogins = []DeviceLogin{stub}
	rec := f.record(t, "device-cli", map[string]string{"login": "x"})
	if got := f.providers.Mint(ctx, rec); !got.OK || got.Variables.Get("DEVICE_CLI_TOKEN") != "t" {
		t.Fatalf("mint = %+v", got)
	}
	if stub.keys != f.keys || len(stub.recs) != 1 || stub.recs[0].Sealed != rec.Sealed {
		t.Fatalf("provider got keys=%p recs=%+v", stub.keys, stub.recs)
	}
	if !f.providers.Known("device-cli") || !f.providers.Known(PlatformLarkCLI) || f.providers.Known("other-cli") {
		t.Fatal("Known must cover lark-cli and the linked device logins only")
	}

	unknown := rec
	unknown.Platform = "other-cli"
	assertMintFailure(t, f.providers.Mint(ctx, unknown), MintUnavailable)

	f.providers.Keys = func(context.Context) (*Keys, error) { return nil, errors.New("no keys") }
	assertMintFailure(t, f.providers.Mint(ctx, rec), MintUnavailable)
	if len(stub.recs) != 1 {
		t.Fatal("a vault without keys must not reach the provider")
	}
}
