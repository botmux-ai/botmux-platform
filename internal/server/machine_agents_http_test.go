package server

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"slices"
	"testing"
	"time"

	"github.com/botmux-ai/botmux-platform/internal/auth"
	"github.com/botmux-ai/botmux-platform/internal/config"
	"github.com/botmux-ai/botmux-platform/internal/store"
)

// Port of test/server-machine-agents.test.ts (GET /v1/machine/agents). The
// harness is shared with the machine-groups tests: memory repository, team
// t1 created by u-alice, machine tokens minted for the caller.

type machineAPIHarness struct {
	t          *testing.T
	apex       *Apex
	repository *store.DocumentRepository
	base       string
}

type machineAPIResult struct {
	status int
	header http.Header
	text   string
	json   map[string]any
}

func machineAPITestConfig() config.Config {
	return config.Config{
		SigningSecret:   "test-secret",
		PublicBaseURL:   "http://localhost",
		MachineTokenTTL: 180 * 24 * time.Hour,
		StaleAfter:      90 * time.Second,
		FeishuAppID:     "cli_platform",
		FeishuAppSecret: "sec",
		FeishuHost:      "http://127.0.0.1:1",
	}
}

func newMachineAPIHarness(t *testing.T, handle func(a *Apex, w http.ResponseWriter, r *http.Request) bool) *machineAPIHarness {
	t.Helper()
	repository := newMemoryRepository()
	h := &machineAPIHarness{t: t, repository: repository}
	h.apex = &Apex{Config: machineAPITestConfig(), Repository: repository}
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if !handle(h.apex, w, r) {
			w.WriteHeader(http.StatusNotFound)
		}
	}))
	t.Cleanup(server.Close)
	h.base = server.URL
	if err := repository.CreateTeam(context.Background(), store.TeamDoc{ID: "t1", Name: "Team", Members: []string{"u-alice"}, CreatedBy: "u-alice", CreatedAt: time.Now().UnixMilli()}); err != nil {
		t.Fatal(err)
	}
	return h
}

func agentBot(appID, name string) store.BotInfo {
	openID := "ou_a"
	return store.BotInfo{AppID: appID, OpenID: &openID, Name: name}
}

func (h *machineAPIHarness) seed(machineID, unionID, ownerName, name string, lastSeen time.Time, bots ...store.BotInfo) {
	h.t.Helper()
	if err := seedMachine(h.repository, store.RegisterMachine{
		MachineID: machineID, UnionID: unionID, OwnerName: ownerName, Name: name,
		BotmuxVersion: "1.0.0", DashboardPort: 8800, Bots: bots, LastSeen: lastSeen.UnixMilli(),
	}); err != nil {
		h.t.Fatal(err)
	}
}

// seedAlice is the default caller machine m-alice.
func (h *machineAPIHarness) seedAlice(bots ...store.BotInfo) {
	h.seed("m-alice", "u-alice", "Alice", "alice-box", time.Now(), bots...)
}

// optIn adds a machine bot to team.bots (the discovery / group gate).
func (h *machineAPIHarness) optIn(machineID, appID string) {
	h.t.Helper()
	if err := h.repository.UpdateTeamBots(context.Background(), "t1", []store.TeamBotRef{{MachineID: machineID, AppID: appID}}, nil); err != nil {
		h.t.Fatal(err)
	}
}

func (h *machineAPIHarness) token(machineID, unionID, ownerName string) string {
	return auth.MintMachineToken(h.apex.Config, auth.MachineIdentity{UnionID: unionID, OwnerName: ownerName, MachineID: machineID})
}

func (h *machineAPIHarness) aliceToken() string { return h.token("m-alice", "u-alice", "Alice") }

func (h *machineAPIHarness) call(method, path, token string, body any) machineAPIResult {
	h.t.Helper()
	var reader io.Reader
	if body != nil {
		data, _ := json.Marshal(body)
		reader = bytes.NewReader(data)
	}
	request, err := http.NewRequest(method, h.base+path, reader)
	if err != nil {
		h.t.Fatal(err)
	}
	if token != "" {
		request.Header.Set("Authorization", "Bearer "+token)
	}
	if body != nil {
		request.Header.Set("Content-Type", "application/json")
	}
	response, err := http.DefaultClient.Do(request)
	if err != nil {
		h.t.Fatal(err)
	}
	defer response.Body.Close()
	payload, _ := io.ReadAll(response.Body)
	result := machineAPIResult{status: response.StatusCode, header: response.Header, text: string(payload)}
	_ = json.Unmarshal(payload, &result.json)
	return result
}

func expectMachineAPIError(t *testing.T, r machineAPIResult, status int, code string) {
	t.Helper()
	if r.status != status || r.json["error"] != code {
		t.Fatalf("got %d %s, want %d %s", r.status, r.text, status, code)
	}
}

func newAgentsHarness(t *testing.T) *machineAPIHarness {
	return newMachineAPIHarness(t, func(a *Apex, w http.ResponseWriter, r *http.Request) bool {
		return a.handleMachineAgentsAPI(w, r)
	})
}

func agentAppIDs(r machineAPIResult) []string {
	ids := []string{}
	agents, _ := r.json["agents"].([]any)
	for _, agent := range agents {
		ids = append(ids, agent.(map[string]any)["appId"].(string))
	}
	return ids
}

// ── auth (requireMachineAuth) ───────────────────────────────────────────────

func TestMachineAgentsAuth(t *testing.T) {
	h := newAgentsHarness(t)
	h.seedAlice()
	expectMachineAPIError(t, h.call(http.MethodGet, "/v1/machine/agents?teamId=t1", "", nil), http.StatusUnauthorized, "invalid_machine_token")
	// Signature valid but the machine is not registered.
	expectMachineAPIError(t, h.call(http.MethodGet, "/v1/machine/agents?teamId=t1", h.token("m-ghost", "u-alice", "Alice"), nil), http.StatusForbidden, "machine_ownership_mismatch")
	// Unbound after the token was issued.
	h.apex.KV = store.NewKVStore(store.NewMemoryKV(), "t", time.Minute, time.Minute)
	token := auth.MintMachineTokenAt(h.apex.Config, auth.MachineIdentity{UnionID: "u-alice", OwnerName: "Alice", MachineID: "m-alice"}, time.Now().Add(-time.Minute))
	if err := h.apex.KV.RevokeMachineToken(context.Background(), "m-alice", time.Now().UnixMilli(), time.Hour); err != nil {
		t.Fatal(err)
	}
	expectMachineAPIError(t, h.call(http.MethodGet, "/v1/machine/agents?teamId=t1", token, nil), http.StatusUnauthorized, "machine_revoked")
}

// ── trust-domain gate ───────────────────────────────────────────────────────

func TestMachineAgentsTeamGate(t *testing.T) {
	h := newAgentsHarness(t)
	h.seedAlice()
	r := h.call(http.MethodGet, "/v1/machine/agents", h.aliceToken(), nil)
	expectMachineAPIError(t, r, http.StatusBadRequest, "missing_teamId")
	if r.header.Get("Cache-Control") != "no-store" {
		t.Fatalf("Cache-Control = %q", r.header.Get("Cache-Control"))
	}
	// Not a member and missing team look the same (no probing).
	h.seed("m-carol", "u-carol", "Carol", "carol-box", time.Now())
	expectMachineAPIError(t, h.call(http.MethodGet, "/v1/machine/agents?teamId=t1", h.token("m-carol", "u-carol", "Carol"), nil), http.StatusNotFound, "not_found")
	expectMachineAPIError(t, h.call(http.MethodGet, "/v1/machine/agents?teamId=t-nope", h.aliceToken(), nil), http.StatusNotFound, "not_found")
}

// ── discovery (opt-in gate = team.bots) ─────────────────────────────────────

func TestMachineAgentsListsOptedInWithDefaults(t *testing.T) {
	h := newAgentsHarness(t)
	h.seedAlice(agentBot("cli_a", "AgentA"))
	h.optIn("m-alice", "cli_a")
	r := h.call(http.MethodGet, "/v1/machine/agents?teamId=t1", h.aliceToken(), nil)
	if r.status != http.StatusOK || r.json["teamId"] != "t1" || r.json["teamName"] != "Team" {
		t.Fatalf("%d %s", r.status, r.text)
	}
	agents := r.json["agents"].([]any)
	if len(agents) != 1 {
		t.Fatalf("agents = %v", agents)
	}
	a := agents[0].(map[string]any)
	specialties, _ := json.Marshal(a["specialties"])
	if a["appId"] != "cli_a" || a["mentionable"] != true || string(specialties) != "[]" || a["online"] != true ||
		a["owner"].(map[string]any)["unionId"] != "u-alice" || a["machineId"] != "m-alice" {
		t.Fatalf("agent = %v", a)
	}
}

func TestMachineAgentsShape(t *testing.T) {
	h := newAgentsHarness(t)
	unionID := "on_bot"
	mentionable := false
	bot := agentBot("cli_a", "")
	bot.UnionID = unionID
	bot.Specialties = store.BotSpecialties{"code", "review"}
	bot.Mentionable = &mentionable
	if err := seedMachine(h.repository, store.RegisterMachine{
		MachineID: "m-alice", UnionID: "u-alice", OwnerName: "", Name: "", BotmuxVersion: "1.0.0",
		DashboardPort: 8800, Bots: []store.BotInfo{bot}, LastSeen: 1,
	}); err != nil {
		t.Fatal(err)
	}
	h.optIn("m-alice", "cli_a")
	r := h.call(http.MethodGet, "/v1/machine/agents?teamId=t1", h.aliceToken(), nil)
	// Defaults: name falls back to appId, owner name to the unionId prefix,
	// machine name to the id prefix.
	want := `{"teamId":"t1","teamName":"Team","agents":[{"appId":"cli_a","openId":"ou_a","unionId":"on_bot","name":"cli_a","specialties":["code","review"],"mentionable":false,"online":false,"owner":{"unionId":"u-alice","name":"u-alice"},"machineId":"m-alice","machineName":"m-alice"}]}`
	if r.text != want {
		t.Fatalf("body =\n%s\nwant\n%s", r.text, want)
	}
}

func TestMachineAgentsRequiresTeamBotsOptIn(t *testing.T) {
	h := newAgentsHarness(t)
	h.seedAlice(agentBot("cli_a", "AgentA")) // showInTeam defaults to true but is not the gate
	r := h.call(http.MethodGet, "/v1/machine/agents?teamId=t1", h.aliceToken(), nil)
	if r.status != http.StatusOK || r.text != `{"teamId":"t1","teamName":"Team","agents":[]}` {
		t.Fatalf("%d %s", r.status, r.text)
	}
}

func TestMachineAgentsProjectsOnlyOptedInBots(t *testing.T) {
	h := newAgentsHarness(t)
	h.seedAlice(agentBot("cli_a", "AgentA"), agentBot("cli_b", "AgentB"))
	h.optIn("m-alice", "cli_a")
	if ids := agentAppIDs(h.call(http.MethodGet, "/v1/machine/agents?teamId=t1", h.aliceToken(), nil)); !slices.Equal(ids, []string{"cli_a"}) {
		t.Fatalf("ids = %v", ids)
	}
}

func TestMachineAgentsCrossMemberIncludingOffline(t *testing.T) {
	h := newAgentsHarness(t)
	if err := h.repository.AddTeamMember(context.Background(), "t1", "u-bob"); err != nil {
		t.Fatal(err)
	}
	h.seedAlice(agentBot("cli_a", "AliceAgent"))
	h.seed("m-bob", "u-bob", "Bob", "bob-box", time.Now().Add(-10*time.Minute), agentBot("cli_b", "BobAgent"))
	h.optIn("m-alice", "cli_a")
	h.optIn("m-bob", "cli_b")
	r := h.call(http.MethodGet, "/v1/machine/agents?teamId=t1", h.aliceToken(), nil)
	byApp := map[string]map[string]any{}
	for _, agent := range r.json["agents"].([]any) {
		a := agent.(map[string]any)
		byApp[a["appId"].(string)] = a
	}
	if byApp["cli_a"]["online"] != true || byApp["cli_b"]["online"] != false || byApp["cli_b"]["owner"].(map[string]any)["unionId"] != "u-bob" {
		t.Fatalf("agents = %v", byApp)
	}
	// Sorted by owner name: Alice before Bob.
	if ids := agentAppIDs(r); !slices.Equal(ids, []string{"cli_a", "cli_b"}) {
		t.Fatalf("order = %v", ids)
	}
}

func TestMachineAgentsSkipsRetiredMachines(t *testing.T) {
	h := newAgentsHarness(t)
	h.seedAlice(agentBot("cli_a", "AgentA"))
	h.seed("m-dead", "u-alice", "Alice", "dead-box", time.Now(), agentBot("cli_dead", "Dead"))
	h.optIn("m-alice", "cli_a")
	h.optIn("m-dead", "cli_dead")
	if err := h.repository.RetireMachine(context.Background(), "m-dead"); err != nil {
		t.Fatal(err)
	}
	if ids := agentAppIDs(h.call(http.MethodGet, "/v1/machine/agents?teamId=t1", h.aliceToken(), nil)); !slices.Equal(ids, []string{"cli_a"}) {
		t.Fatalf("ids = %v", ids)
	}
}

func TestMachineAgentsSortUsesLocaleCompare(t *testing.T) {
	h := newAgentsHarness(t)
	h.seedAlice(agentBot("cli_1", "beta"), agentBot("cli_2", "Alpha"), agentBot("cli_3", "alpha"), agentBot("cli_4", "Ärger"))
	for _, id := range []string{"cli_1", "cli_2", "cli_3", "cli_4"} {
		h.optIn("m-alice", id)
	}
	// ICU root collation: case-insensitive first, lower before upper on ties,
	// accents near their base letter.
	if ids := agentAppIDs(h.call(http.MethodGet, "/v1/machine/agents?teamId=t1", h.aliceToken(), nil)); !slices.Equal(ids, []string{"cli_3", "cli_2", "cli_4", "cli_1"}) {
		t.Fatalf("order = %v", ids)
	}
}

func TestMachineAgentsMethodAndStore(t *testing.T) {
	h := newAgentsHarness(t)
	h.seedAlice()
	r := h.call(http.MethodPost, "/v1/machine/agents?teamId=t1", h.aliceToken(), nil)
	expectMachineAPIError(t, r, http.StatusMethodNotAllowed, "method_not_allowed")
	// Other paths are not ours.
	if r := h.call(http.MethodGet, "/v1/machine/agents/x", h.aliceToken(), nil); r.status != http.StatusNotFound || r.text != "" {
		t.Fatalf("%d %s", r.status, r.text)
	}
	// Member machines unreadable: fail closed.
	h.apex.Repository = failingOpenAPIRepository{Repository: h.repository, listOwned: true}
	expectMachineAPIError(t, h.call(http.MethodGet, "/v1/machine/agents?teamId=t1", h.aliceToken(), nil), http.StatusServiceUnavailable, "store_unavailable")
}
