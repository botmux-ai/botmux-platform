package server

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/botmux-ai/botmux-platform/internal/auth"
	"github.com/botmux-ai/botmux-platform/internal/config"
	"github.com/botmux-ai/botmux-platform/internal/store"
	"github.com/botmux-ai/botmux-platform/internal/tunnel"
)

func TestWriteJSONMatchesLegacyResponseBody(t *testing.T) {
	recorder := httptest.NewRecorder()
	writeJSON(recorder, http.StatusCreated, struct {
		Value string `json:"value"`
	}{Value: "<&"})

	response := recorder.Result()
	defer response.Body.Close()
	body, err := io.ReadAll(response.Body)
	if err != nil {
		t.Fatal(err)
	}
	if got, want := string(body), `{"value":"<&"}`; got != want {
		t.Fatalf("body = %q, want %q", got, want)
	}
	if got := response.Header.Get("Content-Type"); got != "application/json; charset=utf-8" {
		t.Fatalf("Content-Type = %q", got)
	}
}

func TestRedirectMatchesLegacyEmptyResponse(t *testing.T) {
	recorder := httptest.NewRecorder()
	request := httptest.NewRequest(http.MethodGet, "http://localhost/start", nil)
	redirectWithCookie(recorder, request, "/next", "session=value")

	response := recorder.Result()
	defer response.Body.Close()
	body, err := io.ReadAll(response.Body)
	if err != nil {
		t.Fatal(err)
	}
	if response.StatusCode != http.StatusFound || response.Header.Get("Location") != "/next" {
		t.Fatalf("redirect = status %d location %q", response.StatusCode, response.Header.Get("Location"))
	}
	if len(body) != 0 {
		t.Fatalf("redirect body = %q, want empty", body)
	}
	if got := response.Header.Get("Content-Type"); got != "" {
		t.Fatalf("redirect Content-Type = %q, want empty", got)
	}
}

func TestMeOmitsMissingAvatar(t *testing.T) {
	cfg := config.Config{SigningSecret: "secret", SessionTTL: time.Hour}
	token := auth.MintSession(cfg, auth.SessionUser{UnionID: "union", Name: "Dev"})
	request := httptest.NewRequest(http.MethodGet, "http://localhost/api/me", nil)
	request.Header.Set("Cookie", auth.SessionCookieName+"="+token)
	recorder := httptest.NewRecorder()

	(&Apex{Config: cfg}).ServeHTTP(recorder, request)

	if recorder.Code != http.StatusOK {
		t.Fatalf("status = %d, body = %s", recorder.Code, recorder.Body.String())
	}
	var body map[string]any
	if err := json.Unmarshal(recorder.Body.Bytes(), &body); err != nil {
		t.Fatal(err)
	}
	if _, exists := body["avatar"]; exists {
		t.Fatalf("avatar must be omitted: %#v", body)
	}
	if strings.HasSuffix(recorder.Body.String(), "\n") {
		t.Fatalf("JSON response has a trailing newline: %q", recorder.Body.String())
	}
}

func TestMachineBaseURLUsesPublicOrigin(t *testing.T) {
	cfg := config.Config{
		PublicBaseURL:          "https://example.com/base%2Fpath?query=1#fragment",
		RootHost:               "example.com",
		MachineSubdomainPrefix: "m-",
	}
	if got, want := MachineBaseURL(cfg, "deadbeef"), "https://m-deadbeef.example.com"; got != want {
		t.Fatalf("MachineBaseURL = %q, want %q", got, want)
	}
}

func TestMachineViewNormalizesEmptyCollections(t *testing.T) {
	registry := tunnel.NewRegistry(time.Minute, "", nil)
	registry.Upsert(&tunnel.MachineConn{
		MachineID: "deadbeef", UnionID: "owner", Name: "machine",
		BotmuxVersion: "1.2.3", LastSeen: time.Now(),
	})
	a := Apex{Config: config.Config{StaleAfter: time.Minute}, Registry: registry}
	view := a.machineView(store.MachineDoc{ID: "deadbeef", UnionID: "owner", LastSeen: time.Now().UnixMilli()})
	if view.Memberships == nil || view.Bots == nil {
		t.Fatalf("empty collections must encode as [] rather than null: %#v", view)
	}
}

func TestStaticContentTypesMatchLegacyTable(t *testing.T) {
	dir := t.TempDir()
	for _, name := range []string{"bundle.js.map", "favicon.ico", "..asset.js"} {
		if err := os.WriteFile(filepath.Join(dir, name), []byte("content"), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	tests := []struct {
		path string
		want string
	}{
		{path: "/bundle.js.map", want: "application/json; charset=utf-8"},
		{path: "/favicon.ico", want: "image/x-icon"},
		{path: "/..asset.js", want: "text/javascript; charset=utf-8"},
	}
	for _, tc := range tests {
		t.Run(tc.path, func(t *testing.T) {
			recorder := httptest.NewRecorder()
			if !serveStatic(recorder, dir, tc.path) {
				t.Fatalf("serveStatic(%q) did not find the file", tc.path)
			}
			if got := recorder.Header().Get("Content-Type"); got != tc.want {
				t.Fatalf("Content-Type = %q, want %q", got, tc.want)
			}
		})
	}
}

func TestBotDirFetchWakesWaiterAfterCacheInvalidation(t *testing.T) {
	started := make(chan struct{})
	release := make(chan struct{})
	api := NewMachineAPI(config.Config{
		PublicBaseURL:          "http://localhost",
		RootHost:               "localhost",
		MachineSubdomainPrefix: "m-",
		SigningSecret:          "secret",
		SessionTTL:             time.Hour,
	})
	api.client.Transport = roundTripFunc(func(*http.Request) (*http.Response, error) {
		close(started)
		<-release
		return &http.Response{
			StatusCode: http.StatusOK,
			Header:     make(http.Header),
			Body: io.NopCloser(strings.NewReader(
				`{"bots":[{"larkAppId":"cli_test","defaultOncall":{"enabled":true}}]}`,
			)),
		}, nil
	})

	result := make(chan map[string]BotDirConfig, 1)
	go func() {
		result <- api.GetBotDirs(context.Background(), "deadbeef", "owner", 2*time.Second)
	}()
	<-started
	api.mu.Lock()
	delete(api.cache, "deadbeef")
	api.mu.Unlock()
	close(release)

	select {
	case configs := <-result:
		cfg, ok := configs["cli_test"]
		if !ok || cfg.Mode != "oncall" {
			t.Fatalf("configs = %#v", configs)
		}
		if cfg.WorkingDir != nil {
			t.Fatalf("missing oncall workingDir = %#v, want nil", cfg.WorkingDir)
		}
	case <-time.After(500 * time.Millisecond):
		t.Fatal("waiter was not released when an in-flight cache entry was invalidated")
	}
}

func TestRosterFetchesOnlineMachineConfigsInParallel(t *testing.T) {
	repository := newMemoryRepository()
	now := time.Now().UnixMilli()
	for index, owner := range []string{"owner-one", "owner-two"} {
		id := []string{"deadbeef00000001", "deadbeef00000002"}[index]
		if err := seedMachine(repository, store.RegisterMachine{
			MachineID: id, UnionID: owner, Name: id, BotmuxVersion: "1.2.3",
			Memberships: []store.MembershipInfo{}, Bots: []store.BotInfo{}, LastSeen: now,
		}); err != nil {
			t.Fatal(err)
		}
	}

	started := make(chan struct{}, 2)
	release := make(chan struct{})
	var releaseOnce sync.Once
	defer releaseOnce.Do(func() { close(release) })
	cfg := config.Config{
		PublicBaseURL: "http://localhost", RootHost: "localhost", MachineSubdomainPrefix: "m-",
		SigningSecret: "secret", SessionTTL: time.Hour, StaleAfter: time.Minute,
	}
	api := NewMachineAPI(cfg)
	api.client.Transport = roundTripFunc(func(*http.Request) (*http.Response, error) {
		started <- struct{}{}
		<-release
		return &http.Response{
			StatusCode: http.StatusOK, Header: make(http.Header),
			Body: io.NopCloser(strings.NewReader(`{"bots":[]}`)),
		}, nil
	})
	a := Apex{Config: cfg, Registry: tunnel.NewRegistry(time.Minute, "", nil), Repository: repository, MachineAPI: api}
	type rosterResult struct {
		values []rosterMember
		err    error
	}
	result := make(chan rosterResult, 1)
	go func() {
		values, err := a.roster(context.Background(), store.TeamDoc{Members: []string{"owner-one", "owner-two"}})
		result <- rosterResult{values: values, err: err}
	}()

	for count := 0; count < 2; count++ {
		select {
		case <-started:
		case <-time.After(2 * time.Second):
			t.Fatal("online-machine configuration requests were serialized")
		}
	}
	releaseOnce.Do(func() { close(release) })
	select {
	case result := <-result:
		if result.err != nil || len(result.values) != 2 {
			t.Fatalf("roster = %#v, err=%v", result.values, result.err)
		}
	case <-time.After(time.Second):
		t.Fatal("parallel roster did not complete")
	}
}

func TestMachineListReturnsUnavailableInsteadOfLocalPartialState(t *testing.T) {
	cfg := config.Config{SigningSecret: "secret", SessionTTL: time.Hour}
	token := auth.MintSession(cfg, auth.SessionUser{UnionID: "owner", Name: "Owner"})
	request := httptest.NewRequest(http.MethodGet, "http://localhost/api/machines", nil)
	request.Header.Set("Cookie", auth.SessionCookieName+"="+token)
	recorder := httptest.NewRecorder()
	registry := tunnel.NewRegistry(time.Minute, "", nil)
	registry.Upsert(&tunnel.MachineConn{MachineID: "local-only", UnionID: "owner", Name: "partial", LastSeen: time.Now()})
	a := Apex{
		Config: cfg, Registry: registry,
		Repository: unavailableMachineRepository{Repository: newMemoryRepository()},
	}

	a.ServeHTTP(recorder, request)

	if recorder.Code != http.StatusServiceUnavailable || !strings.Contains(recorder.Body.String(), "store_unavailable") {
		t.Fatalf("response = %d %q", recorder.Code, recorder.Body.String())
	}
}

func TestLeaveTeamFailsClosedOnAuthoritativeReadError(t *testing.T) {
	cfg := config.Config{PublicBaseURL: "http://localhost", SigningSecret: "secret", SessionTTL: time.Hour}
	token := auth.MintSession(cfg, auth.SessionUser{UnionID: "member", Name: "Member"})
	request := httptest.NewRequest(http.MethodPost, "http://localhost/api/teams/deadbeef/leave", nil)
	request.Header.Set("Cookie", auth.SessionCookieName+"="+token)
	request.Header.Set("Origin", "http://localhost")
	recorder := httptest.NewRecorder()
	repository := &leaveTeamRepository{Repository: newMemoryRepository(), getTeamErr: store.ErrUnavailable}

	(&Apex{Config: cfg, Repository: repository}).ServeHTTP(recorder, request)

	if recorder.Code != http.StatusServiceUnavailable || !strings.Contains(recorder.Body.String(), "store_unavailable") {
		t.Fatalf("response = %d %q", recorder.Code, recorder.Body.String())
	}
	if repository.removeBotsCalls != 0 || repository.removeMemberCalls != 0 {
		t.Fatalf("mutations after failed authority read: bots=%d member=%d", repository.removeBotsCalls, repository.removeMemberCalls)
	}
}

func TestLeaveTeamDoesNotRemoveMemberWhenBotCleanupFails(t *testing.T) {
	cfg := config.Config{PublicBaseURL: "http://localhost", SigningSecret: "secret", SessionTTL: time.Hour}
	token := auth.MintSession(cfg, auth.SessionUser{UnionID: "member", Name: "Member"})
	request := httptest.NewRequest(http.MethodPost, "http://localhost/api/teams/deadbeef/leave", nil)
	request.Header.Set("Cookie", auth.SessionCookieName+"="+token)
	request.Header.Set("Origin", "http://localhost")
	recorder := httptest.NewRecorder()
	memory := newMemoryRepository()
	if err := memory.CreateTeam(context.Background(), store.TeamDoc{ID: "deadbeef", Name: "Team", CreatedBy: "creator", Members: []string{"creator", "member"}}); err != nil {
		t.Fatal(err)
	}
	repository := &leaveTeamRepository{Repository: memory, removeBotsErr: store.ErrUnavailable}

	(&Apex{Config: cfg, Registry: tunnel.NewRegistry(time.Minute, "", nil), Repository: repository}).ServeHTTP(recorder, request)

	if recorder.Code != http.StatusServiceUnavailable || repository.removeBotsCalls != 1 || repository.removeMemberCalls != 0 {
		t.Fatalf("response=%d %q bots=%d member=%d", recorder.Code, recorder.Body.String(), repository.removeBotsCalls, repository.removeMemberCalls)
	}
	team, err := memory.GetTeam(context.Background(), "deadbeef")
	if err != nil || !contains(team.Members, "member") {
		t.Fatalf("member removed after failed bot cleanup: %#v err=%v", team.Members, err)
	}
}

func TestCrossPodUnbindUsesInjectedForwarder(t *testing.T) {
	repository := newMemoryRepository()
	const machineID = "deadbeef00000001"
	if err := seedMachine(repository, store.RegisterMachine{
		MachineID: machineID, UnionID: "owner", Name: "machine", BotmuxVersion: "1.2.3",
		Memberships: []store.MembershipInfo{}, Bots: []store.BotInfo{}, LastSeen: time.Now().UnixMilli(),
	}); err != nil {
		t.Fatal(err)
	}
	routes := &apexRouteStore{owner: "pod-b:8080"}
	forwarded := false
	a := Apex{
		Config:   config.Config{SelfPodAddr: "pod-a:8080", MachineTokenTTL: time.Hour},
		Registry: tunnel.NewRegistry(time.Minute, "pod-a:8080", nil), Repository: repository, Routes: routes,
		ForwardHTTP: func(owner string, w http.ResponseWriter, _ *http.Request) error {
			forwarded = true
			if owner != routes.owner {
				t.Fatalf("forward owner = %q", owner)
			}
			w.WriteHeader(http.StatusAccepted)
			return nil
		},
	}
	recorder := httptest.NewRecorder()
	request := httptest.NewRequest(http.MethodPost, "http://localhost/api/machines/"+machineID+"/unbind", nil)
	a.unbind(recorder, request, &auth.SessionPayload{UnionID: "owner"}, nil, machineID)
	if !forwarded || recorder.Code != http.StatusAccepted {
		t.Fatalf("forwarded=%v status=%d", forwarded, recorder.Code)
	}
}

func TestFeishuCanarySwitchBlocksMutationBeforePersistence(t *testing.T) {
	repository := newMemoryRepository()
	cfg := config.Config{PublicBaseURL: "http://localhost", SigningSecret: "secret", SessionTTL: time.Hour}
	token := auth.MintSession(cfg, auth.SessionUser{UnionID: "owner", Name: "Owner"})
	request := httptest.NewRequest(http.MethodPost, "http://localhost/api/teams", strings.NewReader(`{"name":"must-not-exist"}`))
	request.Header.Set("Cookie", auth.SessionCookieName+"="+token)
	// A fresh same-origin session passes the SSO gate; the canary switch
	// must still stop the write before persistence.
	request.Header.Set("Origin", "http://localhost")
	request.Header.Set("Content-Type", "application/json")
	recorder := httptest.NewRecorder()

	a := Apex{Config: cfg, Repository: repository, FeishuWritesDisabled: true}
	a.ServeHTTP(recorder, request)

	if recorder.Code != http.StatusServiceUnavailable || !strings.Contains(recorder.Body.String(), "feishu_writes_disabled") {
		t.Fatalf("response = %d %q", recorder.Code, recorder.Body.String())
	}
	if recorder.Header().Get("Retry-After") != "60" {
		t.Fatalf("Retry-After = %q", recorder.Header().Get("Retry-After"))
	}
	teams, err := repository.ListTeamsForUser(context.Background(), "owner")
	if err != nil || len(teams) != 0 {
		t.Fatalf("blocked mutation persisted teams: %#v, err=%v", teams, err)
	}
}

type apexRouteStore struct {
	owner string
}

type unavailableMachineRepository struct{ store.Repository }

func (unavailableMachineRepository) ListMachinesForUser(context.Context, string) ([]store.MachineDoc, error) {
	return nil, store.ErrUnavailable
}

type leaveTeamRepository struct {
	store.Repository
	getTeamErr        error
	removeBotsErr     error
	removeBotsCalls   int
	removeMemberCalls int
}

func (r *leaveTeamRepository) GetTeam(ctx context.Context, id string) (store.TeamDoc, error) {
	if r.getTeamErr != nil {
		return store.TeamDoc{}, r.getTeamErr
	}
	return r.Repository.GetTeam(ctx, id)
}

func (r *leaveTeamRepository) RemoveUserBotsFromTeam(ctx context.Context, teamID string, machineIDs []string) error {
	r.removeBotsCalls++
	if r.removeBotsErr != nil {
		return r.removeBotsErr
	}
	return r.Repository.RemoveUserBotsFromTeam(ctx, teamID, machineIDs)
}

func (r *leaveTeamRepository) RemoveTeamMember(ctx context.Context, teamID, unionID string) error {
	r.removeMemberCalls++
	return r.Repository.RemoveTeamMember(ctx, teamID, unionID)
}

func (s *apexRouteStore) GetMachineRoute(context.Context, string) (string, error) {
	return s.owner, nil
}

func (*apexRouteStore) DeleteMachineRoute(context.Context, string, string) error {
	return nil
}

type roundTripFunc func(*http.Request) (*http.Response, error)

func (f roundTripFunc) RoundTrip(request *http.Request) (*http.Response, error) {
	return f(request)
}
