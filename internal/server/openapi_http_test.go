package server

import (
	"bufio"
	"compress/gzip"
	"context"
	"encoding/json"
	"errors"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"regexp"
	"slices"
	"sort"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/botmux-ai/botmux-platform/internal/auth"
	"github.com/botmux-ai/botmux-platform/internal/config"
	"github.com/botmux-ai/botmux-platform/internal/store"
	"github.com/botmux-ai/botmux-platform/internal/tunnel"
)

// Port of test/server-openapi.test.ts and test/server-openapi-ws.test.ts.
// JWT verification, identity mapping and the daemon fetch are seams, so the
// tests are hermetic; the PEM is set only to pass the capability gate.

const (
	openAPIMIDAlice = "aa11bb22cc33dd44"
	openAPIMIDBob   = "bb22cc33dd44ee55"
)

var proxyCookiePattern = regexp.MustCompile(`botmux_proxy_session=`)

func openAPITestConfig() config.Config {
	return config.Config{
		SigningSecret:           "test-secret",
		PublicBaseURL:           "http://localhost",
		RootHost:                "localhost",
		MachineSubdomainPrefix:  "m-",
		TerminalSubdomainPrefix: "t-",
		StaleAfter:              90 * time.Second,
		SessionTTL:              time.Hour,
	}
}

func okJWT(email string) OpenAPIVerifier {
	return func(context.Context, string) (*OpenAPIIdentity, error) {
		return &OpenAPIIdentity{Email: email, Person: true}, nil
	}
}

type openAPIProxyCall struct {
	Method string
	URL    string
	Header http.Header
	Body   []byte
}

type openAPIHarness struct {
	t          *testing.T
	apex       *Apex
	repository *store.DocumentRepository
	base       string
	mu         sync.Mutex
	calls      []openAPIProxyCall
}

func (h *openAPIHarness) proxyCalls() []openAPIProxyCall {
	h.mu.Lock()
	defer h.mu.Unlock()
	return append([]openAPIProxyCall(nil), h.calls...)
}

func (h *openAPIHarness) recordingFetch(status int, header http.Header, body string) func(context.Context, OpenAPIProxyRequest) (OpenAPIProxyResponse, error) {
	return func(_ context.Context, request OpenAPIProxyRequest) (OpenAPIProxyResponse, error) {
		h.mu.Lock()
		h.calls = append(h.calls, openAPIProxyCall{Method: request.Method, URL: request.URL, Header: request.Header.Clone(), Body: request.Body})
		h.mu.Unlock()
		return OpenAPIProxyResponse{Status: status, Header: header, Body: []byte(body)}, nil
	}
}

func newOpenAPIHarness(t *testing.T) *openAPIHarness {
	t.Helper()
	repository := newMemoryRepository()
	h := &openAPIHarness{t: t, repository: repository}
	h.apex = &Apex{Config: openAPITestConfig(), Repository: repository}
	h.apex.OpenAPI = OpenAPIDeps{
		VerifyJWT: okJWT("alice@example.com"),
		ResolveUnionID: func(_ context.Context, email string) string {
			if email == "alice@example.com" {
				return "u-alice"
			}
			return ""
		},
		ProxyFetch: h.recordingFetch(http.StatusOK, http.Header{"Content-Type": {"application/json"}}, `{"ok":true}`),
	}
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if !h.apex.handleOpenAPI(w, r) {
			w.WriteHeader(http.StatusNotFound)
		}
	}))
	t.Cleanup(server.Close)
	h.base = server.URL
	return h
}

type openAPIResult struct {
	status int
	header http.Header
	text   string
	json   map[string]any
}

func (h *openAPIHarness) do(method, path string, header map[string]string, body string) openAPIResult {
	h.t.Helper()
	var reader io.Reader
	if body != "" {
		reader = strings.NewReader(body)
	}
	request, err := http.NewRequest(method, h.base+path, reader)
	if err != nil {
		h.t.Fatal(err)
	}
	for name, value := range header {
		request.Header.Set(name, value)
	}
	response, err := http.DefaultClient.Do(request)
	if err != nil {
		h.t.Fatal(err)
	}
	defer response.Body.Close()
	payload, _ := io.ReadAll(response.Body)
	result := openAPIResult{status: response.StatusCode, header: response.Header, text: string(payload)}
	_ = json.Unmarshal(payload, &result.json)
	return result
}

// call mirrors the TS helper: Authorization: Bearer tok by default.
func (h *openAPIHarness) call(method, path string, body string) openAPIResult {
	h.t.Helper()
	header := map[string]string{"Authorization": "Bearer tok"}
	if body != "" {
		header["Content-Type"] = "application/json"
	}
	return h.do(method, path, header, body)
}

func (h *openAPIHarness) seed(machineID, unionID, ownerName, name string, bots []store.BotInfo) {
	h.t.Helper()
	if err := seedMachine(h.repository, store.RegisterMachine{
		MachineID: machineID, UnionID: unionID, OwnerName: ownerName, Name: name,
		BotmuxVersion: "1.0.0", DashboardPort: 8800, Bots: bots, LastSeen: time.Now().UnixMilli(),
	}); err != nil {
		h.t.Fatal(err)
	}
}

func (h *openAPIHarness) seedAlice() { h.seed(openAPIMIDAlice, "u-alice", "Alice", "alice-box", nil) }

func (h *openAPIHarness) seedBobCoManagedByAlice(scopes []string) {
	h.t.Helper()
	openID := "ou_bob"
	h.seed(openAPIMIDBob, "u-bob", "Bob", "bob-box", []store.BotInfo{{AppID: "cli_bob", Name: "bob-bot", OpenID: &openID}})
	if err := h.repository.SetMachineCoManagers(context.Background(), openAPIMIDBob, "u-bob", []store.MachineCoManager{
		{UnionID: "u-alice", Name: "Alice", Scopes: scopes, GrantedAt: time.Now().UnixMilli(), GrantedBy: "u-bob"},
	}); err != nil {
		h.t.Fatal(err)
	}
}

func expectOpenAPIError(t *testing.T, r openAPIResult, status int, code string) {
	t.Helper()
	if r.status != status || r.json["error"] != code {
		t.Fatalf("got %d %s, want %d %s", r.status, r.text, status, code)
	}
	if r.header.Get("Cache-Control") != "no-store" {
		t.Fatalf("Cache-Control = %q", r.header.Get("Cache-Control"))
	}
}

func machineIDs(r openAPIResult) []string {
	var ids []string
	machines, _ := r.json["machines"].([]any)
	for _, m := range machines {
		ids = append(ids, m.(map[string]any)["machineId"].(string))
	}
	return ids
}

// failingOpenAPIRepository degrades selected reads to ErrUnavailable.
type failingOpenAPIRepository struct {
	store.Repository
	listOwned, listCoManaged, lookup bool
}

func (r failingOpenAPIRepository) ListMachinesForUsers(ctx context.Context, ids []string) ([]store.MachineDoc, error) {
	if r.listOwned {
		return nil, store.ErrUnavailable
	}
	return r.Repository.ListMachinesForUsers(ctx, ids)
}

func (r failingOpenAPIRepository) ListMachinesCoManagedBy(ctx context.Context, id string) ([]store.MachineDoc, error) {
	if r.listCoManaged {
		return nil, store.ErrUnavailable
	}
	return r.Repository.ListMachinesCoManagedBy(ctx, id)
}

func (r failingOpenAPIRepository) LookupMachine(ctx context.Context, id string, opts store.AuthorityCacheOptions) (store.MachineDoc, error) {
	if r.lookup {
		return store.MachineDoc{}, store.ErrUnavailable
	}
	return r.Repository.LookupMachine(ctx, id, opts)
}

// ── capability gate ─────────────────────────────────────────────────────────

func TestOpenAPIDisabledIs404(t *testing.T) {
	h := newOpenAPIHarness(t)
	h.apex.OpenAPI.VerifyJWT = nil
	r := h.do(http.MethodGet, "/openapi/machines", map[string]string{"Authorization": "Bearer x"}, "")
	expectOpenAPIError(t, r, http.StatusNotFound, "not_found")
	if r.text != `{"error":"not_found"}` {
		t.Fatalf("body = %s", r.text)
	}
}

func TestOpenAPIOtherPathsFallThrough(t *testing.T) {
	h := newOpenAPIHarness(t)
	for _, path := range []string{"/openapi/machines/", "/openapi/machines/xyz/proxy", "/openapi/machines/aa11bb22/proxyx"} {
		if r := h.call(http.MethodGet, path, ""); r.status != http.StatusNotFound || r.text != "" {
			t.Fatalf("%s: %d %q", path, r.status, r.text)
		}
	}
}

// ── authentication ──────────────────────────────────────────────────────────

func TestOpenAPIAuthentication(t *testing.T) {
	h := newOpenAPIHarness(t)
	r := h.do(http.MethodGet, "/openapi/machines", nil, "")
	expectOpenAPIError(t, r, http.StatusUnauthorized, "missing_jwt")
	if r.text != `{"error":"missing_jwt"}` {
		t.Fatalf("body = %s", r.text)
	}

	h.apex.OpenAPI.VerifyJWT = func(context.Context, string) (*OpenAPIIdentity, error) {
		return nil, errors.New("bad_signature")
	}
	r = h.call(http.MethodGet, "/openapi/machines", "")
	expectOpenAPIError(t, r, http.StatusUnauthorized, "invalid_jwt")
	if r.text != `{"error":"invalid_jwt","reason":"bad_signature"}` {
		t.Fatalf("body = %s", r.text)
	}

	h.apex.OpenAPI.VerifyJWT = func(context.Context, string) (*OpenAPIIdentity, error) {
		return &OpenAPIIdentity{Email: "svc@example.com"}, nil
	}
	expectOpenAPIError(t, h.call(http.MethodGet, "/openapi/machines", ""), http.StatusForbidden, "not_person_account")

	h.apex.OpenAPI.VerifyJWT = okJWT("ghost@example.com")
	expectOpenAPIError(t, h.call(http.MethodGet, "/openapi/machines", ""), http.StatusForbidden, "identity_unmapped")
}

func TestOpenAPIJWTSources(t *testing.T) {
	h := newOpenAPIHarness(t)
	h.seedAlice()
	var seen []string
	h.apex.OpenAPI.VerifyJWT = func(ctx context.Context, token string) (*OpenAPIIdentity, error) {
		seen = append(seen, token)
		return okJWT("alice@example.com")(ctx, token)
	}
	// X-Jwt-Token is accepted without Authorization; both are trimmed.
	if r := h.do(http.MethodGet, "/openapi/machines", map[string]string{"X-Jwt-Token": "  tok-x "}, ""); r.status != http.StatusOK {
		t.Fatalf("x-jwt-token: %d %s", r.status, r.text)
	}
	// Bearer wins over X-Jwt-Token; the scheme is case-insensitive.
	h.do(http.MethodGet, "/openapi/machines", map[string]string{"Authorization": "bearer   tok-b ", "X-Jwt-Token": "tok-x"}, "")
	// A non-Bearer Authorization falls back to X-Jwt-Token.
	h.do(http.MethodGet, "/openapi/machines", map[string]string{"Authorization": "Basic abc", "X-Jwt-Token": "tok-y"}, "")
	if want := []string{"tok-x", "tok-b", "tok-y"}; !slices.Equal(seen, want) {
		t.Fatalf("tokens = %q, want %q", seen, want)
	}
	// HTTP never reads ?jwt= (it would land in daemon logs / Referer).
	r := h.do(http.MethodGet, "/openapi/machines?jwt=tok", nil, "")
	expectOpenAPIError(t, r, http.StatusUnauthorized, "missing_jwt")
}

func TestOpenAPIProxyDropsJWTQuery(t *testing.T) {
	h := newOpenAPIHarness(t)
	h.seedAlice()
	r := h.call(http.MethodGet, "/openapi/machines/"+openAPIMIDAlice+"/proxy/api/sessions?jwt=leak&keep=1&a=b+c&jwt=again&e=%7E~", "")
	if r.status != http.StatusOK {
		t.Fatalf("status %d %s", r.status, r.text)
	}
	calls := h.proxyCalls()
	// URLSearchParams re-serialization: '+' stays a space, '~' is escaped.
	want := "http://m-" + openAPIMIDAlice + ".localhost/api/sessions?keep=1&a=b+c&e=%7E%7E"
	if len(calls) != 1 || calls[0].URL != want {
		t.Fatalf("calls = %+v, want %s", calls, want)
	}
	// Only jwt in the query: no '?' at all.
	h.call(http.MethodGet, "/openapi/machines/"+openAPIMIDAlice+"/proxy/api/sessions?jwt=x", "")
	if got := h.proxyCalls()[1].URL; got != "http://m-"+openAPIMIDAlice+".localhost/api/sessions" {
		t.Fatalf("url = %s", got)
	}
}

// ── list ────────────────────────────────────────────────────────────────────

func TestOpenAPIListOnlyOwnMachines(t *testing.T) {
	h := newOpenAPIHarness(t)
	h.seedAlice()
	h.seed(openAPIMIDBob, "u-bob", "Bob", "bob-box", nil)
	r := h.call(http.MethodGet, "/openapi/machines", "")
	if r.status != http.StatusOK || r.json["unionId"] != "u-alice" {
		t.Fatalf("%d %s", r.status, r.text)
	}
	if ids := machineIDs(r); !slices.Equal(ids, []string{openAPIMIDAlice}) {
		t.Fatalf("ids = %v", ids)
	}
	if r.header.Get("Cache-Control") != "no-store" {
		t.Fatalf("Cache-Control = %q", r.header.Get("Cache-Control"))
	}
	machine := r.json["machines"].([]any)[0].(map[string]any)
	if machine["online"] != true {
		t.Fatalf("machine = %v", machine)
	}
}

func TestOpenAPIListShape(t *testing.T) {
	h := newOpenAPIHarness(t)
	h.apex.OpenAPI.Now = func() time.Time { return time.UnixMilli(1_700_000_100_000) }
	openID := "ou_a"
	if err := seedMachine(h.repository, store.RegisterMachine{
		MachineID: openAPIMIDAlice, UnionID: "u-alice", OwnerName: "Alice", Name: "",
		BotmuxVersion: "2.0.0", DashboardPort: 8800, LastSeen: 1_700_000_000_000,
		Bots: []store.BotInfo{{AppID: "cli_a", Name: "A", OpenID: &openID}, {AppID: "cli_b", Name: "B"}},
	}); err != nil {
		t.Fatal(err)
	}
	r := h.call(http.MethodGet, "/openapi/machines", "")
	want := `{"unionId":"u-alice","machines":[{"machineId":"aa11bb22cc33dd44","name":"aa11bb22","botmuxVersion":"2.0.0","online":false,"lastSeen":1700000000000,"role":"owner","ownerName":null,"scopes":["machines:read","sessions:open","terminal:control","dashboard:manage"],"bots":[{"appId":"cli_a","name":"A","openId":"ou_a"},{"appId":"cli_b","name":"B","openId":null}]}]}`
	if r.text != want {
		t.Fatalf("body =\n%s\nwant\n%s", r.text, want)
	}
	// No machines: an empty array, never null.
	h.apex.OpenAPI.ResolveUnionID = func(context.Context, string) string { return "u-nobody" }
	if r := h.call(http.MethodGet, "/openapi/machines", ""); r.text != `{"unionId":"u-nobody","machines":[]}` {
		t.Fatalf("empty = %s", r.text)
	}
}

func TestOpenAPIListFailsClosed(t *testing.T) {
	h := newOpenAPIHarness(t)
	h.seedAlice()
	h.apex.Repository = failingOpenAPIRepository{Repository: h.repository, listOwned: true}
	expectOpenAPIError(t, h.call(http.MethodGet, "/openapi/machines", ""), http.StatusServiceUnavailable, "store_unavailable")
	// Half a list would read as "that machine was revoked".
	h.apex.Repository = failingOpenAPIRepository{Repository: h.repository, listCoManaged: true}
	expectOpenAPIError(t, h.call(http.MethodGet, "/openapi/machines", ""), http.StatusServiceUnavailable, "store_unavailable")
}

func TestOpenAPIListMethodNotAllowed(t *testing.T) {
	h := newOpenAPIHarness(t)
	for _, method := range []string{http.MethodPost, http.MethodHead} {
		r := h.call(method, "/openapi/machines", "")
		if r.status != http.StatusMethodNotAllowed || r.header.Get("Cache-Control") != "no-store" {
			t.Fatalf("%s: %d %s", method, r.status, r.text)
		}
	}
	// The method gate runs before authentication.
	expectOpenAPIError(t, h.do(http.MethodPost, "/openapi/machines", nil, ""), http.StatusMethodNotAllowed, "method_not_allowed")
}

func TestOpenAPIListCoManaged(t *testing.T) {
	h := newOpenAPIHarness(t)
	h.seedAlice()
	h.seedBobCoManagedByAlice(auth.ComanagerDefaultScopes())
	r := h.call(http.MethodGet, "/openapi/machines", "")
	if r.status != http.StatusOK {
		t.Fatalf("%d %s", r.status, r.text)
	}
	byID := map[string]map[string]any{}
	for _, m := range r.json["machines"].([]any) {
		machine := m.(map[string]any)
		byID[machine["machineId"].(string)] = machine
	}
	ids := make([]string, 0, len(byID))
	for id := range byID {
		ids = append(ids, id)
	}
	sort.Strings(ids)
	if !slices.Equal(ids, []string{openAPIMIDAlice, openAPIMIDBob}) {
		t.Fatalf("ids = %v", ids)
	}
	if byID[openAPIMIDAlice]["role"] != "owner" || byID[openAPIMIDAlice]["ownerName"] != nil {
		t.Fatalf("alice = %v", byID[openAPIMIDAlice])
	}
	bob := byID[openAPIMIDBob]
	if bob["role"] != "co-manager" || bob["ownerName"] != "Bob" {
		t.Fatalf("bob = %v", bob)
	}
	scopes, _ := json.Marshal(bob["scopes"])
	bots, _ := json.Marshal(bob["bots"])
	if string(scopes) != `["machines:read","sessions:open","terminal:control"]` || string(bots) != `[{"appId":"cli_bob","name":"bob-bot","openId":"ou_bob"}]` {
		t.Fatalf("scopes=%s bots=%s", scopes, bots)
	}
}

func TestOpenAPIListSkipsCoManagerWithoutScopes(t *testing.T) {
	h := newOpenAPIHarness(t)
	h.seedAlice()
	h.seedBobCoManagedByAlice([]string{})
	if ids := machineIDs(h.call(http.MethodGet, "/openapi/machines", "")); !slices.Equal(ids, []string{openAPIMIDAlice}) {
		t.Fatalf("ids = %v", ids)
	}
}

func TestOpenAPIListOwnerWinsOverCoManagerEntry(t *testing.T) {
	h := newOpenAPIHarness(t)
	h.seedAlice()
	if err := h.repository.SetMachineCoManagers(context.Background(), openAPIMIDAlice, "u-alice", []store.MachineCoManager{
		{UnionID: "u-alice", Name: "Alice", Scopes: []string{"machines:read"}, GrantedAt: time.Now().UnixMilli(), GrantedBy: "u-alice"},
	}); err != nil {
		t.Fatal(err)
	}
	r := h.call(http.MethodGet, "/openapi/machines", "")
	machines := r.json["machines"].([]any)
	if len(machines) != 1 {
		t.Fatalf("machines = %v", machines)
	}
	machine := machines[0].(map[string]any)
	if machine["role"] != "owner" || !slices.Contains(machine["scopes"].([]any), any("dashboard:manage")) {
		t.Fatalf("machine = %v", machine)
	}
}

// ── access gate ─────────────────────────────────────────────────────────────

func TestOpenAPIProxyOwnMachine(t *testing.T) {
	h := newOpenAPIHarness(t)
	h.seedAlice()
	r := h.call(http.MethodGet, "/openapi/machines/"+openAPIMIDAlice+"/proxy/api/sessions", "")
	if r.status != http.StatusOK || r.text != `{"ok":true}` {
		t.Fatalf("%d %s", r.status, r.text)
	}
	calls := h.proxyCalls()
	if len(calls) != 1 || calls[0].URL != "http://m-"+openAPIMIDAlice+".localhost/api/sessions" || calls[0].Method != http.MethodGet || calls[0].Body != nil {
		t.Fatalf("calls = %+v", calls)
	}
	if !proxyCookiePattern.MatchString(calls[0].Header.Get("Cookie")) || calls[0].Header.Get("Authorization") != "" {
		t.Fatalf("headers = %v", calls[0].Header)
	}
	// The cookie is minted for the caller on this machine.
	request := httptest.NewRequest(http.MethodGet, "http://m-x.localhost/", nil)
	request.Header.Set("Cookie", calls[0].Header.Get("Cookie"))
	session, err := auth.ReadProxySession(h.apex.Config, request)
	if err != nil || session.UnionID != "u-alice" || session.MachineID != openAPIMIDAlice {
		t.Fatalf("session = %+v, %v", session, err)
	}
}

func TestOpenAPIProxyStripsCallerCredentialsAndPlatformHeaders(t *testing.T) {
	h := newOpenAPIHarness(t)
	h.seedAlice()
	r := h.do(http.MethodGet, "/openapi/machines/"+openAPIMIDAlice+"/proxy/api/sessions", map[string]string{
		"X-Jwt-Token": "caller-jwt", "X-Botmux-Role": "owner", "X-Botmux-Forwarded": "1",
		"X-Botmux-Actor": "u-someone-else", "X-Botmux-Scopes": "dashboard:manage", "X-Botmux-Login-Url": "x",
		"Cookie": "caller=1", "Proxy-Authorization": "p", "Te": "trailers", "X-Custom": "kept",
		"Accept-Encoding": "br",
	}, "")
	if r.status != http.StatusOK {
		t.Fatalf("%d %s", r.status, r.text)
	}
	header := h.proxyCalls()[0].Header
	for _, name := range []string{"X-Jwt-Token", "Authorization", "X-Botmux-Role", "X-Botmux-Forwarded", "X-Botmux-Actor", "X-Botmux-Scopes", "X-Botmux-Login-Url", "Proxy-Authorization", "Te", "Host", "Connection", "Accept-Encoding"} {
		if values := header.Values(name); len(values) != 0 {
			t.Fatalf("%s forwarded: %q", name, values)
		}
	}
	if header.Get("X-Custom") != "kept" || !proxyCookiePattern.MatchString(header.Get("Cookie")) || strings.Contains(header.Get("Cookie"), "caller=1") {
		t.Fatalf("headers = %v", header)
	}
}

func TestOpenAPIProxyJoinsRepeatedHeadersLikeNode(t *testing.T) {
	h := newOpenAPIHarness(t)
	h.seedAlice()
	request, _ := http.NewRequest(http.MethodGet, h.base+"/openapi/machines/"+openAPIMIDAlice+"/proxy/api/sessions", nil)
	request.Header.Set("Authorization", "Bearer tok")
	request.Header.Add("X-Multi", "a")
	request.Header.Add("X-Multi", "b")
	request.Header.Add("User-Agent", "first")
	request.Header.Add("User-Agent", "second")
	response, err := http.DefaultClient.Do(request)
	if err != nil {
		t.Fatal(err)
	}
	response.Body.Close()
	header := h.proxyCalls()[0].Header
	if !slices.Equal(header.Values("X-Multi"), []string{"a, b"}) || !slices.Equal(header.Values("User-Agent"), []string{"first"}) {
		t.Fatalf("headers = %v", header)
	}
}

func TestOpenAPIProxyDeniesForeignMissingAndRetired(t *testing.T) {
	h := newOpenAPIHarness(t)
	h.seedAlice()
	h.seed(openAPIMIDBob, "u-bob", "Bob", "bob-box", nil)
	for _, id := range []string{openAPIMIDBob, strings.Repeat("0", 16)} {
		r := h.call(http.MethodGet, "/openapi/machines/"+id+"/proxy/api/sessions", "")
		expectOpenAPIError(t, r, http.StatusForbidden, "machine_not_owned")
	}
	if err := h.repository.RetireMachine(context.Background(), openAPIMIDAlice); err != nil {
		t.Fatal(err)
	}
	expectOpenAPIError(t, h.call(http.MethodGet, "/openapi/machines/"+openAPIMIDAlice+"/proxy/api/sessions", ""), http.StatusForbidden, "machine_not_owned")
	if calls := h.proxyCalls(); len(calls) != 0 {
		t.Fatalf("daemon called: %+v", calls)
	}
}

func TestOpenAPIProxyLookupDegraded(t *testing.T) {
	h := newOpenAPIHarness(t)
	h.seedAlice()
	h.apex.Repository = failingOpenAPIRepository{Repository: h.repository, lookup: true}
	expectOpenAPIError(t, h.call(http.MethodGet, "/openapi/machines/"+openAPIMIDAlice+"/proxy/api/sessions", ""), http.StatusServiceUnavailable, "store_unavailable")
}

// ── pass-through details ────────────────────────────────────────────────────

func TestOpenAPIProxyPostForwardsBodyQueryAndStatus(t *testing.T) {
	h := newOpenAPIHarness(t)
	h.seedAlice()
	h.apex.OpenAPI.ProxyFetch = h.recordingFetch(http.StatusCreated, http.Header{"Content-Type": {"application/json"}}, `{"created":1}`)
	r := h.call(http.MethodPost, "/openapi/machines/"+openAPIMIDAlice+"/proxy/api/bots/cli_a/working-dir-mode?x=1", `{"mode":"off"}`)
	if r.status != http.StatusCreated || r.json["created"] != float64(1) {
		t.Fatalf("%d %s", r.status, r.text)
	}
	call := h.proxyCalls()[0]
	if call.Method != http.MethodPost || call.URL != "http://m-"+openAPIMIDAlice+".localhost/api/bots/cli_a/working-dir-mode?x=1" || string(call.Body) != `{"mode":"off"}` {
		t.Fatalf("call = %+v", call)
	}
	if call.Header.Get("Content-Type") != "application/json" || call.Header.Get("Content-Length") != "" {
		t.Fatalf("headers = %v", call.Header)
	}
	// An empty non-GET body is still a (zero-length) body.
	h.call(http.MethodDelete, "/openapi/machines/"+openAPIMIDAlice+"/proxy/api/x", "")
	if call := h.proxyCalls()[1]; call.Method != http.MethodDelete || call.Body == nil || len(call.Body) != 0 {
		t.Fatalf("delete call = %+v", call)
	}
}

func TestOpenAPIProxyUnreachable(t *testing.T) {
	h := newOpenAPIHarness(t)
	h.seedAlice()
	h.apex.OpenAPI.ProxyFetch = func(context.Context, OpenAPIProxyRequest) (OpenAPIProxyResponse, error) {
		return OpenAPIProxyResponse{}, io.ErrUnexpectedEOF
	}
	expectOpenAPIError(t, h.call(http.MethodGet, "/openapi/machines/"+openAPIMIDAlice+"/proxy/api/sessions", ""), http.StatusBadGateway, "machine_unreachable")
}

func TestOpenAPIProxyRootPath(t *testing.T) {
	h := newOpenAPIHarness(t)
	h.seedAlice()
	if r := h.call(http.MethodGet, "/openapi/machines/"+openAPIMIDAlice+"/proxy", ""); r.status != http.StatusOK {
		t.Fatalf("%d %s", r.status, r.text)
	}
	if got := h.proxyCalls()[0].URL; got != "http://m-"+openAPIMIDAlice+".localhost/" {
		t.Fatalf("url = %s", got)
	}
}

func TestOpenAPIProxyResponseHeaders(t *testing.T) {
	h := newOpenAPIHarness(t)
	h.seedAlice()
	h.apex.OpenAPI.ProxyFetch = h.recordingFetch(http.StatusOK, http.Header{
		"Content-Type":     {"application/json"},
		"Cache-Control":    {"public, max-age=3600"},
		"Set-Cookie":       {"daemon=1"},
		"Content-Encoding": {"gzip"},
		"X-Daemon":         {"a", "b"},
	}, `{"ok":true}`)
	r := h.call(http.MethodGet, "/openapi/machines/"+openAPIMIDAlice+"/proxy/api/sessions", "")
	if r.status != http.StatusOK || r.header.Get("Cache-Control") != "no-store" {
		t.Fatalf("%d %v", r.status, r.header)
	}
	if r.header.Get("Set-Cookie") != "" || r.header.Get("Content-Encoding") != "" || !slices.Equal(r.header.Values("X-Daemon"), []string{"a, b"}) {
		t.Fatalf("headers = %v", r.header)
	}
}

func TestOpenAPIProxyBodyTooLarge(t *testing.T) {
	h := newOpenAPIHarness(t)
	h.seedAlice()
	r := h.call(http.MethodPost, "/openapi/machines/"+openAPIMIDAlice+"/proxy/api/echo", strings.Repeat("x", 1024*1024+10))
	expectOpenAPIError(t, r, http.StatusRequestEntityTooLarge, "body_too_large")
	if len(h.proxyCalls()) != 0 {
		t.Fatal("oversized body reached the daemon")
	}
	// Exactly 1 MiB is fine.
	if r := h.call(http.MethodPost, "/openapi/machines/"+openAPIMIDAlice+"/proxy/api/echo", strings.Repeat("x", 1024*1024)); r.status != http.StatusOK {
		t.Fatalf("1MiB: %d %s", r.status, r.text)
	}
}

// ── co-managers ─────────────────────────────────────────────────────────────

func TestOpenAPIProxyCoManagedMachine(t *testing.T) {
	h := newOpenAPIHarness(t)
	h.seedBobCoManagedByAlice(auth.ComanagerDefaultScopes())
	if r := h.call(http.MethodGet, "/openapi/machines/"+openAPIMIDBob+"/proxy/api/bots", ""); r.status != http.StatusOK {
		t.Fatalf("%d %s", r.status, r.text)
	}
	calls := h.proxyCalls()
	if len(calls) != 1 || calls[0].URL != "http://m-"+openAPIMIDBob+".localhost/api/bots" {
		t.Fatalf("calls = %+v", calls)
	}
	// The cookie is minted for the caller (auditable), not for the owner.
	request := httptest.NewRequest(http.MethodGet, "http://m-x.localhost/", nil)
	request.Header.Set("Cookie", calls[0].Header.Get("Cookie"))
	if session, err := auth.ReadProxySession(h.apex.Config, request); err != nil || session.UnionID != "u-alice" {
		t.Fatalf("session = %+v, %v", session, err)
	}
}

func TestOpenAPIProxyCoManagerWithoutSessionsOpen(t *testing.T) {
	h := newOpenAPIHarness(t)
	h.seedBobCoManagedByAlice([]string{"machines:read"})
	expectOpenAPIError(t, h.call(http.MethodGet, "/openapi/machines/"+openAPIMIDBob+"/proxy/api/bots", ""), http.StatusForbidden, "machine_not_owned")
	if len(h.proxyCalls()) != 0 {
		t.Fatal("daemon called")
	}
}

func TestOpenAPIProxyRetiredCoManagedMachine(t *testing.T) {
	h := newOpenAPIHarness(t)
	h.seedBobCoManagedByAlice(auth.ComanagerDefaultScopes())
	if err := h.repository.RetireMachine(context.Background(), openAPIMIDBob); err != nil {
		t.Fatal(err)
	}
	expectOpenAPIError(t, h.call(http.MethodGet, "/openapi/machines/"+openAPIMIDBob+"/proxy/api/bots", ""), http.StatusForbidden, "machine_not_owned")
}

// ── default daemon fetch ────────────────────────────────────────────────────

func TestDefaultOpenAPIProxyFetch(t *testing.T) {
	var gotURI, gotCookie, gotEncoding string
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotURI, gotCookie, gotEncoding = r.RequestURI, r.Header.Get("Cookie"), r.Header.Get("Accept-Encoding")
		if r.URL.Path == "/redirect" {
			w.Header().Set("Location", "/elsewhere")
			w.WriteHeader(http.StatusFound)
			return
		}
		w.Header().Set("Content-Encoding", "gzip")
		w.Header().Set("Content-Type", "text/plain")
		zw := gzip.NewWriter(w)
		_, _ = zw.Write([]byte("hello"))
		_ = zw.Close()
	}))
	defer upstream.Close()

	// WHATWG leaves '^' and '|' unescaped in paths; they must reach the daemon as-is.
	response, err := defaultOpenAPIProxyFetch(context.Background(), OpenAPIProxyRequest{
		Method: http.MethodGet, URL: upstream.URL + "/a^b|c/%2F?x=1+2", Header: http.Header{"Cookie": {"botmux_proxy_session=t"}},
	})
	if err != nil {
		t.Fatal(err)
	}
	if gotURI != "/a^b|c/%2F?x=1+2" || gotCookie != "botmux_proxy_session=t" || gotEncoding != "gzip" {
		t.Fatalf("uri=%q cookie=%q encoding=%q", gotURI, gotCookie, gotEncoding)
	}
	if response.Status != http.StatusOK || string(response.Body) != "hello" || response.Header.Get("Content-Encoding") != "" {
		t.Fatalf("response = %d %q %v", response.Status, response.Body, response.Header)
	}

	// Redirects are returned, not followed.
	response, err = defaultOpenAPIProxyFetch(context.Background(), OpenAPIProxyRequest{Method: http.MethodGet, URL: upstream.URL + "/redirect"})
	if err != nil || response.Status != http.StatusFound || response.Header.Get("Location") != "/elsewhere" {
		t.Fatalf("redirect = %+v, %v", response, err)
	}
	// fetch() refuses CONNECT / TRACE / TRACK.
	if _, err := defaultOpenAPIProxyFetch(context.Background(), OpenAPIProxyRequest{Method: "TRACE", URL: upstream.URL + "/"}); err == nil {
		t.Fatal("TRACE accepted")
	}
}

func TestMachineSurfaceHost(t *testing.T) {
	cfg := openAPITestConfig()
	if got := machineSurfaceHost(cfg, "abc12345", "terminal"); got != "t-abc12345.localhost" {
		t.Fatalf("terminal = %s", got)
	}
	cfg.PublicBaseURL = "http://localhost:8080"
	if got := machineSurfaceHost(cfg, "abc12345", "dashboard"); got != "m-abc12345.localhost:8080" {
		t.Fatalf("dashboard = %s", got)
	}
	cfg.PublicBaseURL = "https://botmux.example:443"
	cfg.RootHost = "botmux.example"
	if got := machineSurfaceHost(cfg, "abc12345", "dashboard"); got != "m-abc12345.botmux.example" {
		t.Fatalf("default port = %s", got)
	}
}

// ── WebSocket upgrade (server-openapi-ws.test.ts) ───────────────────────────

type openAPIWSHarness struct {
	*openAPIHarness
	delegated chan *http.Request
}

func newOpenAPIWSHarness(t *testing.T, delegate func(w http.ResponseWriter, r *http.Request, machineID, surface string)) *openAPIWSHarness {
	h := &openAPIWSHarness{openAPIHarness: newOpenAPIHarness(t), delegated: make(chan *http.Request, 4)}
	h.apex.OpenAPI.MachineWS = func(w http.ResponseWriter, r *http.Request, machineID, surface string) {
		h.delegated <- r.Clone(context.Background())
		if delegate != nil {
			delegate(w, r, machineID, surface)
		}
	}
	return h
}

// rawUpgrade sends a WebSocket handshake and returns every byte the server
// writes before closing the connection.
func (h *openAPIWSHarness) rawUpgrade(path string, header map[string]string) string {
	h.t.Helper()
	conn := h.sendUpgrade(path, header)
	defer conn.Close()
	data, _ := io.ReadAll(conn)
	return string(data)
}

// upgradeResponse sends a WebSocket handshake and parses one HTTP response
// (for delegated requests, where the connection may stay open).
func (h *openAPIWSHarness) upgradeResponse(path string, header map[string]string) *http.Response {
	h.t.Helper()
	conn := h.sendUpgrade(path, header)
	h.t.Cleanup(func() { conn.Close() })
	response, err := http.ReadResponse(bufio.NewReader(conn), nil)
	if err != nil {
		h.t.Fatal(err)
	}
	return response
}

func (h *openAPIWSHarness) sendUpgrade(path string, header map[string]string) net.Conn {
	h.t.Helper()
	conn, err := net.Dial("tcp", strings.TrimPrefix(h.base, "http://"))
	if err != nil {
		h.t.Fatal(err)
	}
	_ = conn.SetDeadline(time.Now().Add(5 * time.Second))
	var b strings.Builder
	b.WriteString("GET " + path + " HTTP/1.1\r\nHost: localhost\r\nUpgrade: websocket\r\nConnection: Upgrade\r\n")
	b.WriteString("Sec-WebSocket-Version: 13\r\nSec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\n")
	for name, value := range header {
		b.WriteString(name + ": " + value + "\r\n")
	}
	b.WriteString("\r\n")
	if _, err := conn.Write([]byte(b.String())); err != nil {
		h.t.Fatal(err)
	}
	return conn
}

func TestOpenAPIWSNonProxyPathIsDestroyed(t *testing.T) {
	h := newOpenAPIWSHarness(t, nil)
	if got := h.rawUpgrade("/openapi/machines", nil); got != "" {
		t.Fatalf("response = %q, want a closed socket", got)
	}
	if h.apex.handleOpenAPIWS(httptest.NewRecorder(), httptest.NewRequest(http.MethodGet, "/openapi/machines", nil)) {
		t.Fatal("non-proxy path claimed")
	}
}

func TestOpenAPIWSDisabledIs404(t *testing.T) {
	h := newOpenAPIWSHarness(t, nil)
	h.apex.OpenAPI.VerifyJWT = nil
	got := h.rawUpgrade("/openapi/machines/"+openAPIMIDAlice+"/proxy/s/x", nil)
	if got != "HTTP/1.1 404 Not Found\r\nconnection: close\r\n\r\n" {
		t.Fatalf("response = %q", got)
	}
}

func TestOpenAPIWSFailures(t *testing.T) {
	h := newOpenAPIWSHarness(t, nil)
	if got := h.rawUpgrade("/openapi/machines/"+openAPIMIDAlice+"/proxy/s/x", nil); got != "HTTP/1.1 401 missing_jwt\r\nconnection: close\r\n\r\n" {
		t.Fatalf("no jwt = %q", got)
	}
	h.seed(openAPIMIDBob, "u-bob", "Bob", "bob", nil)
	if got := h.rawUpgrade("/openapi/machines/"+openAPIMIDBob+"/proxy/s/x", map[string]string{"Authorization": "Bearer tok"}); got != "HTTP/1.1 403 machine_not_owned\r\nconnection: close\r\n\r\n" {
		t.Fatalf("foreign = %q", got)
	}
	h.apex.Repository = failingOpenAPIRepository{Repository: h.repository, lookup: true}
	if got := h.rawUpgrade("/openapi/machines/"+openAPIMIDAlice+"/proxy/s/x", map[string]string{"Authorization": "Bearer tok"}); got != "HTTP/1.1 503 store_unavailable\r\nconnection: close\r\n\r\n" {
		t.Fatalf("degraded = %q", got)
	}
	h.apex.Repository = h.repository
	h.apex.OpenAPI.VerifyJWT = func(context.Context, string) (*OpenAPIIdentity, error) {
		return nil, errors.New("expired")
	}
	if got := h.rawUpgrade("/openapi/machines/"+openAPIMIDAlice+"/proxy/s/x?jwt=tok", nil); got != "HTTP/1.1 401 invalid_jwt\r\nconnection: close\r\n\r\n" {
		t.Fatalf("invalid = %q", got)
	}
	if len(h.delegated) != 0 {
		t.Fatal("failed upgrade was delegated")
	}
}

// With an empty registry the real machine handler answers 502: proof that
// the query JWT was accepted and the request reached the delegation.
func TestOpenAPIWSQueryJWTReachesMachineHandler(t *testing.T) {
	registry := tunnel.NewRegistry(time.Minute, "pod-a:8080", nil)
	defer registry.Close()
	var machine *MachineHandler
	h := newOpenAPIWSHarness(t, func(w http.ResponseWriter, r *http.Request, machineID, _ string) {
		machine.ServeMachine(w, r, machineID)
	})
	machine = &MachineHandler{Config: h.apex.Config, Registry: registry}
	h.seedAlice()
	if got := h.upgradeResponse("/openapi/machines/"+openAPIMIDAlice+"/proxy/s/x?jwt=tok", nil); got.StatusCode != http.StatusBadGateway {
		t.Fatalf("status = %d", got.StatusCode)
	}
}

func TestOpenAPIWSRewritesTerminalRequest(t *testing.T) {
	h := newOpenAPIWSHarness(t, func(w http.ResponseWriter, _ *http.Request, _, surface string) {
		w.Header().Set("X-Surface", surface)
		w.WriteHeader(http.StatusTeapot)
	})
	h.seedAlice()
	got := h.upgradeResponse("/openapi/machines/"+openAPIMIDAlice+"/proxy/s/sid-1?jwt=secret-jwt&foo=1", map[string]string{
		"Authorization": "Bearer secret-jwt", "X-Botmux-Role": "owner", "X-Jwt-Token": "x", "X-Botmux-Forwarded": "1",
	})
	if got.StatusCode != http.StatusTeapot || got.Header.Get("X-Surface") != "terminal" {
		t.Fatalf("response = %d %v", got.StatusCode, got.Header)
	}
	r := <-h.delegated
	if r.Host != "t-"+openAPIMIDAlice+".localhost" || r.URL.RequestURI() != "/s/sid-1?foo=1" || r.RequestURI != "/s/sid-1?foo=1" || r.URL.Path != "/s/sid-1" {
		t.Fatalf("host=%q uri=%q raw=%q", r.Host, r.URL.RequestURI(), r.RequestURI)
	}
	if !proxyCookiePattern.MatchString(r.Header.Get("Cookie")) {
		t.Fatalf("cookie = %q", r.Header.Get("Cookie"))
	}
	for _, name := range []string{"Authorization", "X-Botmux-Role", "X-Jwt-Token", "X-Botmux-Forwarded"} {
		if r.Header.Get(name) != "" {
			t.Fatalf("%s kept", name)
		}
	}
	// The injected cookie is the caller's proxy session for this machine.
	session, err := auth.ReadProxySession(h.apex.Config, r)
	if err != nil || session.UnionID != "u-alice" || session.MachineID != openAPIMIDAlice {
		t.Fatalf("session = %+v, %v", session, err)
	}
}

func TestOpenAPIWSRewritesDashboardRequest(t *testing.T) {
	h := newOpenAPIWSHarness(t, func(w http.ResponseWriter, _ *http.Request, _, surface string) {
		w.Header().Set("X-Surface", surface)
		w.WriteHeader(http.StatusTeapot)
	})
	h.seedAlice()
	if got := h.upgradeResponse("/openapi/machines/"+openAPIMIDAlice+"/proxy/api/stream?jwt=tok", nil); got.Header.Get("X-Surface") != "dashboard" {
		t.Fatalf("response = %d %v", got.StatusCode, got.Header)
	}
	r := <-h.delegated
	if r.Host != "m-"+openAPIMIDAlice+".localhost" || r.URL.RequestURI() != "/api/stream" {
		t.Fatalf("host=%q uri=%q", r.Host, r.URL.RequestURI())
	}
}

func TestIsNodeUpgrade(t *testing.T) {
	request := httptest.NewRequest(http.MethodGet, "/", nil)
	if isNodeUpgrade(request) {
		t.Fatal("plain request")
	}
	request.Header.Set("Upgrade", "websocket")
	if isNodeUpgrade(request) {
		t.Fatal("Upgrade without Connection: upgrade")
	}
	request.Header.Set("Connection", "keep-alive, Upgrade")
	if !isNodeUpgrade(request) {
		t.Fatal("upgrade not detected")
	}
}
