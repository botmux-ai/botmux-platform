package server

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/botmux-ai/botmux-platform/internal/auth"
	"github.com/botmux-ai/botmux-platform/internal/config"
	"github.com/botmux-ai/botmux-platform/internal/tunnel"
)

// Port of test/server-fresh-sso-routes.test.ts: existing sensitive platform
// routes require a fresh SSO (strict 10 min / routine 12 h) and the exact
// platform Origin, while plain reads keep accepting legacy cookies.

func freshSSOTestConfig() config.Config {
	return config.Config{
		PublicBaseURL: "http://localhost", RootHost: "localhost", MachineSubdomainPrefix: "m-",
		SigningSecret: "fresh-sso-route-test-secret", SessionTTL: 7 * 24 * time.Hour,
		BindCodeTTL: 300 * time.Second, MachineTokenTTL: 180 * 24 * time.Hour, StaleAfter: time.Minute,
	}
}

func freshSSOTestApex(t *testing.T, cfg config.Config) *Apex {
	t.Helper()
	registry := tunnel.NewRegistry(time.Minute, "", nil)
	t.Cleanup(func() { _ = registry.Close() })
	return &Apex{Config: cfg, Registry: registry, Repository: newMemoryRepository()}
}

// legacySessionPayload mirrors SessionPayload key order; AuthTime nil is the
// pre-fresh-SSO cookie format.
type legacySessionPayload struct {
	Kind        string                 `json:"kind"`
	UnionID     string                 `json:"unionId"`
	Name        string                 `json:"name"`
	UserToken   *auth.SessionUserToken `json:"ut,omitempty"`
	SearchScope bool                   `json:"ss,omitempty"`
	AuthTime    *int64                 `json:"authTime,omitempty"`
	Exp         int64                  `json:"exp"`
}

func signedSessionCookie(t *testing.T, cfg config.Config, payload legacySessionPayload) string {
	t.Helper()
	payload.Kind = "session"
	token, err := auth.IssueToken(payload, cfg.SigningSecret)
	if err != nil {
		t.Fatal(err)
	}
	return auth.SessionCookieName + "=" + token
}

// agedCookie is a session whose SSO happened ageSec ago.
func agedCookie(t *testing.T, cfg config.Config, ageSec int64) string {
	now := time.Now().Unix()
	authTime := now - ageSec
	return signedSessionCookie(t, cfg, legacySessionPayload{UnionID: "u-alice", Name: "Alice", AuthTime: &authTime, Exp: now + 7*24*3600})
}

func staleCookie(t *testing.T, cfg config.Config, includeAuthTime bool) string {
	now := time.Now().Unix()
	payload := legacySessionPayload{UnionID: "u-alice", Name: "Alice", Exp: now + 3600}
	if includeAuthTime {
		authTime := now - 601
		payload.AuthTime = &authTime
	}
	return signedSessionCookie(t, cfg, payload)
}

func freshCookie(cfg config.Config) string {
	return auth.SessionCookieName + "=" + auth.MintSession(cfg, auth.SessionUser{UnionID: "u-alice", Name: "Alice"})
}

type apexResult struct {
	status int
	header http.Header
	raw    string
	body   map[string]any
}

// serveApex sends a JSON request like the TS test helper (content-type
// always application/json, `{}` body for non-GET).
func serveApex(a *Apex, method, path, cookie, origin string, body string) apexResult {
	var reader *strings.Reader
	if method != http.MethodGet && method != http.MethodHead {
		if body == "" {
			body = "{}"
		}
		reader = strings.NewReader(body)
	} else {
		reader = strings.NewReader("")
	}
	request := httptest.NewRequest(method, "http://localhost"+path, reader)
	request.Header.Set("Content-Type", "application/json")
	if cookie != "" {
		request.Header.Set("Cookie", cookie)
	}
	if origin != "" {
		request.Header.Set("Origin", origin)
	}
	recorder := httptest.NewRecorder()
	a.ServeHTTP(recorder, request)
	result := apexResult{status: recorder.Code, header: recorder.Header(), raw: recorder.Body.String()}
	_ = json.Unmarshal(recorder.Body.Bytes(), &result.body)
	return result
}

func (r apexResult) errorCode() string {
	code, _ := r.body["error"].(string)
	return code
}

var freshSSOStrictRoutes = []struct{ name, method, path string }{
	{"bind-code", http.MethodPost, "/api/bind-code"},
	{"machine upgrade", http.MethodPost, "/api/machines/feedfacefeedface/upgrade"},
	{"machine unbind", http.MethodPost, "/api/machines/feedfacefeedface/unbind"},
	{"delete team", http.MethodDelete, "/api/teams/feedfacefeedface"},
	{"team admins", http.MethodPut, "/api/teams/feedfacefeedface/admins"},
	{"team invite", http.MethodPost, "/api/teams/feedfacefeedface/invite"},
	{"team invite-user", http.MethodPost, "/api/teams/feedfacefeedface/invite-user"},
	{"co-managers put", http.MethodPut, "/api/machines/feedfacefeedface/co-managers"},
	{"co-manager delete", http.MethodDelete, "/api/machines/feedfacefeedface/co-managers/u-bob"},
}

var freshSSORoutineRoutes = []struct{ name, method, path string }{
	{"create team", http.MethodPost, "/api/teams"},
	{"rename team", http.MethodPost, "/api/teams/feedfacefeedface/rename"},
	{"leave team", http.MethodPost, "/api/teams/feedfacefeedface/leave"},
	{"hall join", http.MethodPost, "/api/teams/feedfacefeedface/hall/join"},
	{"accept invite", http.MethodPost, "/api/teams/accept"},
	{"team bots", http.MethodPost, "/api/teams/feedfacefeedface/bots"},
	{"create group", http.MethodPost, "/api/groups/create"},
}

func TestFreshSSOStrictRoutesCheckFreshnessBeforeOrigin(t *testing.T) {
	cfg := freshSSOTestConfig()
	for _, route := range freshSSOStrictRoutes {
		t.Run(route.name, func(t *testing.T) {
			a := freshSSOTestApex(t, cfg)
			stale := serveApex(a, route.method, route.path, staleCookie(t, cfg, true), "", "")
			if stale.status != http.StatusUnauthorized || stale.raw != `{"error":"stale_session","loginUrl":"/auth/login"}` {
				t.Fatalf("stale = %d %s", stale.status, stale.raw)
			}
			missingOrigin := serveApex(a, route.method, route.path, freshCookie(cfg), "", "")
			if missingOrigin.status != http.StatusForbidden || missingOrigin.raw != `{"error":"bad_origin"}` {
				t.Fatalf("missing origin = %d %s", missingOrigin.status, missingOrigin.raw)
			}
			badOrigin := serveApex(a, route.method, route.path, freshCookie(cfg), "https://evil.example.test", "")
			if badOrigin.status != http.StatusForbidden || badOrigin.raw != `{"error":"bad_origin"}` {
				t.Fatalf("bad origin = %d %s", badOrigin.status, badOrigin.raw)
			}
			fresh := serveApex(a, route.method, route.path, freshCookie(cfg), "http://localhost", "")
			switch fresh.errorCode() {
			case "stale_session", "unauthenticated", "bad_origin":
				t.Fatalf("fresh same-origin request rejected by the gate: %d %s", fresh.status, fresh.raw)
			}
		})
	}
}

func TestFreshSSORoutineRoutesAcceptTwelveHourWindow(t *testing.T) {
	cfg := freshSSOTestConfig()
	const routineWindowSec = 12 * 3600
	for _, route := range freshSSORoutineRoutes {
		t.Run(route.name, func(t *testing.T) {
			a := freshSSOTestApex(t, cfg)
			// 601s old: strict would refuse, routine lets it through.
			recent := serveApex(a, route.method, route.path, agedCookie(t, cfg, 601), "http://localhost", "")
			switch recent.errorCode() {
			case "stale_session", "unauthenticated", "bad_origin":
				t.Fatalf("601s-old session rejected by the routine gate: %d %s", recent.status, recent.raw)
			}
			expired := serveApex(a, route.method, route.path, agedCookie(t, cfg, routineWindowSec+60), "http://localhost", "")
			if expired.status != http.StatusUnauthorized || expired.raw != `{"error":"stale_session","loginUrl":"/auth/login"}` {
				t.Fatalf("expired = %d %s", expired.status, expired.raw)
			}
			missingOrigin := serveApex(a, route.method, route.path, agedCookie(t, cfg, 601), "", "")
			if missingOrigin.status != http.StatusForbidden || missingOrigin.raw != `{"error":"bad_origin"}` {
				t.Fatalf("missing origin = %d %s", missingOrigin.status, missingOrigin.raw)
			}
			badOrigin := serveApex(a, route.method, route.path, agedCookie(t, cfg, 601), "https://evil.example.test", "")
			if badOrigin.status != http.StatusForbidden || badOrigin.raw != `{"error":"bad_origin"}` {
				t.Fatalf("bad origin = %d %s", badOrigin.status, badOrigin.raw)
			}
		})
	}
}

func TestFreshSSOGateRejectsMissingSessionAndDevicePrincipals(t *testing.T) {
	cfg := freshSSOTestConfig()
	a := freshSSOTestApex(t, cfg)
	unauthenticated := serveApex(a, http.MethodPost, "/api/bind-code", "", "http://localhost", "")
	if unauthenticated.status != http.StatusUnauthorized || unauthenticated.raw != `{"error":"unauthenticated"}` {
		t.Fatalf("no session = %d %s", unauthenticated.status, unauthenticated.raw)
	}
	// Reads are not gated: GET /api/teams with a legacy cookie is fine.
	read := serveApex(a, http.MethodGet, "/api/teams", staleCookie(t, cfg, false), "", "")
	if read.status != http.StatusOK || read.raw != `{"teams":[]}` {
		t.Fatalf("legacy read = %d %s", read.status, read.raw)
	}
}

func TestFreshSSOGateFailsClosedOnUnparsablePublicBaseURL(t *testing.T) {
	cfg := freshSSOTestConfig()
	cfg.PublicBaseURL = "not a url"
	a := freshSSOTestApex(t, cfg)
	// The opaque origin "null" can be sent by sandboxed pages; it must never
	// match a broken PUBLIC_BASE_URL.
	for _, origin := range []string{"", "null"} {
		result := serveApex(a, http.MethodPost, "/api/teams", freshCookie(cfg), origin, `{"name":"x"}`)
		if result.status != http.StatusForbidden || result.raw != `{"error":"bad_origin"}` {
			t.Fatalf("origin %q = %d %s", origin, result.status, result.raw)
		}
	}
}

func TestLegacyCookieIsStaleOnSensitiveRoutesButReadsStillWork(t *testing.T) {
	cfg := freshSSOTestConfig()
	a := freshSSOTestApex(t, cfg)
	cookie := staleCookie(t, cfg, false)
	sensitive := serveApex(a, http.MethodPost, "/api/bind-code", cookie, "", "")
	if sensitive.status != http.StatusUnauthorized || sensitive.errorCode() != "stale_session" {
		t.Fatalf("bind-code = %d %s", sensitive.status, sensitive.raw)
	}
	me := serveApex(a, http.MethodGet, "/api/me", cookie, "", "")
	if me.status != http.StatusOK || me.raw != `{"unionId":"u-alice","name":"Alice"}` {
		t.Fatalf("me = %d %s", me.status, me.raw)
	}
	teams := serveApex(a, http.MethodGet, "/api/teams", cookie, "", "")
	if teams.status != http.StatusOK || teams.raw != `{"teams":[]}` {
		t.Fatalf("teams = %d %s", teams.status, teams.raw)
	}
}

func TestRenewSessionUserTokenKeepsAuthTimeAndNeverPromotesLegacyCookies(t *testing.T) {
	cfg := freshSSOTestConfig()
	now := time.Now().Unix()
	staleAuthTime := now - 601
	ut := auth.SessionUserToken{AccessToken: "new-access", RefreshToken: "new-refresh", ExpiresAt: now + 3600}
	for _, tc := range []struct {
		name     string
		authTime *int64
	}{
		{name: "stale authTime kept", authTime: &staleAuthTime},
		{name: "legacy stays legacy", authTime: nil},
	} {
		t.Run(tc.name, func(t *testing.T) {
			token, err := auth.IssueToken(legacySessionPayload{Kind: "session", UnionID: "u-alice", Name: "Alice", AuthTime: tc.authTime, Exp: now + 60}, cfg.SigningSecret)
			if err != nil {
				t.Fatal(err)
			}
			session, err := auth.VerifySession(cfg, token)
			if err != nil {
				t.Fatal(err)
			}
			renewed, err := auth.VerifySession(cfg, auth.RenewSessionUserToken(cfg, session, ut))
			if err != nil {
				t.Fatal(err)
			}
			if (renewed.AuthTime == nil) != (tc.authTime == nil) || (tc.authTime != nil && *renewed.AuthTime != *tc.authTime) {
				t.Fatalf("authTime = %v, want %v", renewed.AuthTime, tc.authTime)
			}
		})
	}
}

// Login does not ask for the people-search scope; only ?scope=search (or a
// session that already granted it) adds contact:user:search.

func feishuLoginTestApex(t *testing.T) (*Apex, config.Config) {
	cfg := freshSSOTestConfig()
	cfg.FeishuAppID, cfg.FeishuAppSecret, cfg.FeishuHost = "cli_test_app", "secret", "https://open.feishu.cn"
	cfg.DevLogin = false
	return freshSSOTestApex(t, cfg), cfg
}

func loginLocation(t *testing.T, a *Apex, path, cookie string) *url.URL {
	t.Helper()
	result := serveApex(a, http.MethodGet, path, cookie, "", "")
	if result.status != http.StatusFound {
		t.Fatalf("%s = %d %s", path, result.status, result.raw)
	}
	location, err := url.Parse(result.header.Get("Location"))
	if err != nil {
		t.Fatal(err)
	}
	return location
}

func TestLoginRequestsNoScopeByDefault(t *testing.T) {
	a, _ := feishuLoginTestApex(t)
	location := loginLocation(t, a, "/auth/login", "")
	if !strings.Contains(location.Path, "/authen/v1/authorize") {
		t.Fatalf("authorize URL = %s", location)
	}
	if _, ok := location.Query()["scope"]; ok {
		t.Fatalf("plain login asked for scope: %s", location)
	}
}

func TestLoginWithSearchScopeRequestsContactSearch(t *testing.T) {
	a, _ := feishuLoginTestApex(t)
	location := loginLocation(t, a, "/auth/login?scope=search", "")
	if got := location.Query().Get("scope"); got != "contact:user:search" {
		t.Fatalf("scope = %q", got)
	}
}

func TestLoginRenewsSearchScopeGrantedBySession(t *testing.T) {
	a, cfg := feishuLoginTestApex(t)
	now := time.Now().Unix()
	old := now - 24*3600
	granted := signedSessionCookie(t, cfg, legacySessionPayload{UnionID: "u-alice", Name: "Alice", AuthTime: &old, SearchScope: true, Exp: now + 7*24*3600})
	if got := loginLocation(t, a, "/auth/login", granted).Query().Get("scope"); got != "contact:user:search" {
		t.Fatalf("re-login of a search-granted session: scope = %q", got)
	}
	plain := signedSessionCookie(t, cfg, legacySessionPayload{UnionID: "u-alice", Name: "Alice", AuthTime: &old, Exp: now + 7*24*3600})
	if _, ok := loginLocation(t, a, "/auth/login", plain).Query()["scope"]; ok {
		t.Fatal("re-login of a plain session asked for the search scope")
	}
}

func TestLoginWithoutFeishuAppAnswersConfigError(t *testing.T) {
	cfg := freshSSOTestConfig()
	a := freshSSOTestApex(t, cfg)
	result := serveApex(a, http.MethodGet, "/auth/login", "", "", "")
	if result.status != http.StatusInternalServerError {
		t.Fatalf("login without FEISHU_APP_ID = %d %s", result.status, result.raw)
	}
}

func TestUserSearchWithoutSearchScopeAsksForScope(t *testing.T) {
	a, cfg := feishuLoginTestApex(t)
	now := time.Now().Unix()
	base := signedSessionCookie(t, cfg, legacySessionPayload{
		UnionID: "u-alice", Name: "Alice", AuthTime: &now,
		UserToken: &auth.SessionUserToken{AccessToken: "valid-access", RefreshToken: "valid-refresh", ExpiresAt: now + 3600},
		Exp:       now + 7*24*3600,
	})
	result := serveApex(a, http.MethodGet, "/api/users/search?q=bob", base, "", "")
	if result.status != http.StatusOK || result.raw != `{"users":[],"configured":true,"needScope":true}` {
		t.Fatalf("search = %d %s", result.status, result.raw)
	}
	blank := serveApex(a, http.MethodGet, "/api/users/search?q=%20", base, "", "")
	if blank.raw != `{"users":[],"configured":true}` {
		t.Fatalf("blank query = %s", blank.raw)
	}
	unconfigured := freshSSOTestApex(t, freshSSOTestConfig())
	if got := serveApex(unconfigured, http.MethodGet, "/api/users/search?q=bob", base, "", "").raw; got != `{"users":[],"configured":false,"needScope":true}` {
		t.Fatalf("unconfigured search = %s", got)
	}
}
