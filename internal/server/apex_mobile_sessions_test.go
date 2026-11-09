package server

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/botmux-ai/botmux-platform/internal/auth"
	"github.com/botmux-ai/botmux-platform/internal/config"
	"github.com/botmux-ai/botmux-platform/internal/store"
	"github.com/botmux-ai/botmux-platform/internal/tunnel"
)

// Port of test/server-mobile-machine-sessions.test.ts plus the write-link
// branches it leaves out.

const mobileMachineID = "feedfacefeedface"

type mobileSessionsFixture struct {
	cfg        config.Config
	apex       *Apex
	repository *store.DocumentRepository
	writeLink  string
	writeCode  int
	paths      []string
}

func newMobileSessionsFixture(t *testing.T) *mobileSessionsFixture {
	t.Helper()
	cfg := config.Config{
		PublicBaseURL: "http://localhost", RootHost: "localhost", MachineSubdomainPrefix: "m-",
		SigningSecret: "mobile-session-test-secret", SessionTTL: 7 * 24 * time.Hour, StaleAfter: time.Minute,
	}
	repository := newMemoryRepository()
	if err := seedMachine(repository, store.RegisterMachine{
		MachineID: mobileMachineID, UnionID: "u-alice", OwnerName: "Alice", Name: "alice-mac", BotmuxVersion: "1.0.0",
		DashboardPort: 7891, LastSeen: time.Now().UnixMilli(),
	}); err != nil {
		t.Fatal(err)
	}
	registry := tunnel.NewRegistry(time.Minute, "", nil)
	t.Cleanup(func() { _ = registry.Close() })
	registry.Upsert(&tunnel.MachineConn{MachineID: mobileMachineID, UnionID: "u-alice", Name: "alice-mac", LastSeen: time.Now()})
	f := &mobileSessionsFixture{
		cfg: cfg, repository: repository,
		writeLink: `{"url":"http://127.0.0.1:7891/s/session-1?token=private&t=dashboard"}`, writeCode: http.StatusOK,
	}
	api := NewMachineAPI(cfg)
	api.client.Transport = machineRouteRoundTripFunc(func(request *http.Request) (*http.Response, error) {
		f.paths = append(f.paths, request.URL.EscapedPath())
		switch {
		case request.URL.Path == "/__health":
			return machineRouteResponse(http.StatusOK, "ok"), nil
		case request.URL.Path == "/api/sessions":
			return machineRouteResponse(http.StatusOK, `{"sessions":[{"sessionId":"session-1","title":"Codex"}]}`), nil
		case strings.HasSuffix(request.URL.Path, "/write-link"):
			return machineRouteResponse(f.writeCode, f.writeLink), nil
		}
		t.Fatalf("unexpected dashboard request %s", request.URL)
		return nil, nil
	})
	f.apex = &Apex{
		Config: cfg, Registry: registry, Repository: repository, MachineAPI: api,
		DeviceRepo: repository, DeviceStates: auth.NewDeviceStateCache(repository),
	}
	return f
}

func (f *mobileSessionsFixture) cookie(unionID string) string {
	return auth.SessionCookieName + "=" + auth.MintSession(f.cfg, auth.SessionUser{UnionID: unionID, Name: unionID})
}

func (f *mobileSessionsFixture) seedMobileDevice(t *testing.T, edit func(*store.DeviceDoc)) store.DeviceDoc {
	t.Helper()
	now := time.Now().UnixMilli()
	doc := store.DeviceDoc{
		ID: "d-0011223344556677", UnionID: "u-alice", OwnerName: "Alice", DeviceKind: store.DeviceKindMobile, DeviceName: "Alice iPhone",
		Scopes: store.MobileDeviceScopes(), CredentialVersion: 1, Status: store.DeviceStatusActive,
		RefreshFamilyID: "f-mobile-session-test", RefreshGeneration: 1, RefreshTokenHash: "hash", RefreshCurrentJTI: "jti",
		RefreshRotatedAt: now, EnrolledAt: now, DeviceExp: now + 90*24*3600*1000, LastSeenAt: now,
		ApprovedVia: store.DeviceApprovedViaSSOMobile,
	}
	if edit != nil {
		edit(&doc)
	}
	if err := f.repository.CreateDevice(context.Background(), doc); err != nil {
		t.Fatal(err)
	}
	return doc
}

func (f *mobileSessionsFixture) bearer(doc store.DeviceDoc) string {
	return "Bearer " + auth.MintDeviceAccessToken(f.cfg, doc, time.Now().UnixMilli())
}

func (f *mobileSessionsFixture) do(method, path string, headers map[string]string) *httptest.ResponseRecorder {
	var body *strings.Reader
	if method == http.MethodPost {
		body = strings.NewReader("{}")
	} else {
		body = strings.NewReader("")
	}
	request := httptest.NewRequest(method, "http://localhost"+path, body)
	for key, value := range headers {
		request.Header.Set(key, value)
	}
	recorder := httptest.NewRecorder()
	f.apex.ServeHTTP(recorder, request)
	return recorder
}

func TestMobileSessionsListRequiresOwnerAndIsNoStore(t *testing.T) {
	f := newMobileSessionsFixture(t)
	path := "/api/machines/" + mobileMachineID + "/sessions"
	if got := f.do(http.MethodGet, path, nil); got.Code != http.StatusUnauthorized || got.Body.String() != `{"error":"unauthenticated"}` {
		t.Fatalf("unauthenticated = %d %s", got.Code, got.Body.String())
	}
	if got := f.do(http.MethodGet, path, map[string]string{"Cookie": f.cookie("u-bob")}); got.Code != http.StatusNotFound || got.Body.String() != `{"error":"machine_not_found"}` {
		t.Fatalf("foreign = %d %s", got.Code, got.Body.String())
	}
	ok := f.do(http.MethodGet, path, map[string]string{"Cookie": f.cookie("u-alice")})
	if ok.Code != http.StatusOK || ok.Header().Get("Cache-Control") != "no-store" {
		t.Fatalf("owner = %d cache-control=%q", ok.Code, ok.Header().Get("Cache-Control"))
	}
	if got := ok.Body.String(); got != `{"sessions":[{"sessionId":"session-1","title":"Codex"}]}` {
		t.Fatalf("body = %s", got)
	}
}

func TestMobileSessionOpenIssuesTerminalTicketAndStripsWriteTokens(t *testing.T) {
	f := newMobileSessionsFixture(t)
	response := f.do(http.MethodPost, "/api/machines/"+mobileMachineID+"/sessions/session-1/open", map[string]string{"Cookie": f.cookie("u-alice")})
	if response.Code != http.StatusOK {
		t.Fatalf("open = %d %s", response.Code, response.Body.String())
	}
	var body struct {
		OpenURL string `json:"openUrl"`
	}
	if err := json.Unmarshal(response.Body.Bytes(), &body); err != nil {
		t.Fatal(err)
	}
	open, err := url.Parse(body.OpenURL)
	if err != nil {
		t.Fatal(err)
	}
	if open.Hostname() != "t-"+mobileMachineID+".localhost" || open.Query().Get("next") != "/s/session-1" {
		t.Fatalf("openUrl = %s", body.OpenURL)
	}
	claims, err := auth.VerifyProxyTicket(f.cfg, open.Query().Get("ticket"))
	if err != nil || claims.MachineID != mobileMachineID || claims.UnionID != "u-alice" {
		t.Fatalf("ticket = %#v err=%v", claims, err)
	}
	if want := "/api/sessions/session-1/write-link"; len(f.paths) != 1 || f.paths[0] != want {
		t.Fatalf("dashboard paths = %v", f.paths)
	}
}

func TestMobileSessionOpenKeepsOtherQueryAndHash(t *testing.T) {
	f := newMobileSessionsFixture(t)
	f.writeLink = `{"url":"http://127.0.0.1:7891/s/session-1?a=1&token=x&b=two+words#frag"}`
	response := f.do(http.MethodPost, "/api/machines/"+mobileMachineID+"/sessions/session-1/open", map[string]string{"Cookie": f.cookie("u-alice")})
	var body struct {
		OpenURL string `json:"openUrl"`
	}
	_ = json.Unmarshal(response.Body.Bytes(), &body)
	open, _ := url.Parse(body.OpenURL)
	// searchParams.delete re-serializes the query form-encoded.
	if got := open.Query().Get("next"); got != "/s/session-1?a=1&b=two+words#frag" {
		t.Fatalf("next = %q (%s)", got, body.OpenURL)
	}
}

func TestMobileSessionOpenExternalTerminalKeepsExternalURL(t *testing.T) {
	f := newMobileSessionsFixture(t)
	f.writeLink = `{"writeUrl":"https://sandbox.example.test/workspace/123"}`
	response := f.do(http.MethodPost, "/api/machines/"+mobileMachineID+"/sessions/session-1/open", map[string]string{"Cookie": f.cookie("u-alice")})
	if response.Code != http.StatusOK || response.Body.String() != `{"externalUrl":"https://sandbox.example.test/workspace/123"}` {
		t.Fatalf("external = %d %s", response.Code, response.Body.String())
	}
}

func TestMobileSessionOpenWriteLinkFailures(t *testing.T) {
	for _, tc := range []struct {
		name, link string
		code       int
		wantCode   int
		wantBody   string
	}{
		{name: "relative link", link: `{"url":"/s/s1?w=1"}`, code: http.StatusOK, wantCode: http.StatusBadGateway, wantBody: `{"error":"invalid_write_link"}`},
		{name: "missing link", link: `{}`, code: http.StatusOK, wantCode: http.StatusBadGateway, wantBody: `{"error":"invalid_write_link"}`},
		{name: "upstream error passthrough", link: `{"error":"session_not_found","detail":1.50}`, code: http.StatusNotFound, wantCode: http.StatusNotFound, wantBody: `{"error":"session_not_found","detail":1.5}`},
		{name: "unparsable 2xx", link: `<html>`, code: http.StatusOK, wantCode: http.StatusBadGateway, wantBody: `{"error":"invalid_dashboard_response"}`},
		{name: "unparsable error page", link: `<html>`, code: http.StatusServiceUnavailable, wantCode: http.StatusServiceUnavailable, wantBody: `{"error":"machine_unreachable"}`},
	} {
		t.Run(tc.name, func(t *testing.T) {
			f := newMobileSessionsFixture(t)
			f.writeLink, f.writeCode = tc.link, tc.code
			response := f.do(http.MethodPost, "/api/machines/"+mobileMachineID+"/sessions/session-1/open", map[string]string{"Cookie": f.cookie("u-alice")})
			if response.Code != tc.wantCode || response.Body.String() != tc.wantBody {
				t.Fatalf("response = %d %s", response.Code, response.Body.String())
			}
		})
	}
}

func TestMobileSessionOpenRejectsMalformedSessionID(t *testing.T) {
	f := newMobileSessionsFixture(t)
	response := f.do(http.MethodPost, "/api/machines/"+mobileMachineID+"/sessions/%E0%A4x/open", map[string]string{"Cookie": f.cookie("u-alice")})
	if response.Code != http.StatusBadRequest || response.Body.String() != `{"error":"invalid_session_id"}` {
		t.Fatalf("response = %d %s", response.Code, response.Body.String())
	}
	if len(f.paths) != 0 {
		t.Fatalf("dashboard contacted: %v", f.paths)
	}
}

func TestMobileSessionOpenEncodesSessionIDForDashboard(t *testing.T) {
	f := newMobileSessionsFixture(t)
	f.do(http.MethodPost, "/api/machines/"+mobileMachineID+"/sessions/a%20b%2Fc/open", map[string]string{"Cookie": f.cookie("u-alice")})
	if want := "/api/sessions/a%20b%2Fc/write-link"; len(f.paths) != 1 || f.paths[0] != want {
		t.Fatalf("dashboard paths = %v, want %s", f.paths, want)
	}
}

func TestMobileDeviceBearerListsSessionsAndOpensTerminalTicket(t *testing.T) {
	f := newMobileSessionsFixture(t)
	device := f.seedMobileDevice(t, nil)
	sessions := f.do(http.MethodGet, "/api/machines/"+mobileMachineID+"/sessions", map[string]string{"Authorization": f.bearer(device)})
	if sessions.Code != http.StatusOK || sessions.Body.String() != `{"sessions":[{"sessionId":"session-1","title":"Codex"}]}` {
		t.Fatalf("sessions = %d %s", sessions.Code, sessions.Body.String())
	}
	opened := f.do(http.MethodPost, "/api/machines/"+mobileMachineID+"/sessions/session-1/open", map[string]string{
		"Authorization": f.bearer(device), "Content-Type": "application/json",
	})
	if opened.Code != http.StatusOK {
		t.Fatalf("open = %d %s", opened.Code, opened.Body.String())
	}
	var body struct {
		OpenURL             string  `json:"openUrl"`
		SID                 string  `json:"sid"`
		AuthExpiresAt       float64 `json:"authExpiresAt"`
		SessionMaxExpiresAt float64 `json:"sessionMaxExpiresAt"`
	}
	if err := json.Unmarshal(opened.Body.Bytes(), &body); err != nil {
		t.Fatal(err)
	}
	open, err := url.Parse(body.OpenURL)
	if err != nil {
		t.Fatal(err)
	}
	if open.Hostname() != "t-"+mobileMachineID+".localhost" || open.Query().Get("next") != "/s/session-1" {
		t.Fatalf("openUrl = %s", body.OpenURL)
	}
	claims, err := auth.VerifyDeviceProxyTicket(f.cfg, open.Query().Get("ticket"))
	if err != nil || claims.DeviceID != device.ID || claims.MachineID != mobileMachineID || claims.Purpose != auth.DeviceProxyPurposeTerminal {
		t.Fatalf("device ticket = %#v err=%v", claims, err)
	}
	if body.AuthExpiresAt == 0 || body.SID == "" || body.SessionMaxExpiresAt < body.AuthExpiresAt {
		t.Fatalf("open body = %s", opened.Body.String())
	}
}

func TestMobileSessionsRejectDeviceWithoutSessionsScope(t *testing.T) {
	f := newMobileSessionsFixture(t)
	device := f.seedMobileDevice(t, func(d *store.DeviceDoc) { d.Scopes = []string{store.DeviceScopeMachinesRead} })
	response := f.do(http.MethodGet, "/api/machines/"+mobileMachineID+"/sessions", map[string]string{"Authorization": f.bearer(device)})
	if response.Code != http.StatusForbidden || response.Body.String() != `{"error":"insufficient_scope"}` {
		t.Fatalf("response = %d %s", response.Code, response.Body.String())
	}
}
