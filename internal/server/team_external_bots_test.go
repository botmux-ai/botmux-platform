package server

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/botmux-ai/botmux-platform/internal/auth"
	"github.com/botmux-ai/botmux-platform/internal/config"
	"github.com/botmux-ai/botmux-platform/internal/store"
	"github.com/botmux-ai/botmux-platform/internal/tunnel"
)

const (
	extTeam  = "deadbeef"
	extAppID = "cli_0123456789abcdef"
)

type externalBotHarness struct {
	t    *testing.T
	cfg  config.Config
	repo *store.DocumentRepository
	apex *Apex
}

// newExternalBotHarness: team deadbeef created by u-alice, with members
// u-bob and u-carol; u-bob runs botmux bot cli_botmuxbot00000001.
func newExternalBotHarness(t *testing.T) *externalBotHarness {
	t.Helper()
	cfg := config.Config{PublicBaseURL: "http://localhost", SigningSecret: "secret", SessionTTL: time.Hour, FeishuAppID: "cli_platform00000000"}
	repo := newMemoryRepository()
	if err := repo.CreateTeam(context.Background(), store.TeamDoc{
		ID: extTeam, Name: "Team", CreatedBy: "u-alice", Members: []string{"u-alice", "u-bob", "u-carol"},
		Bots: []store.TeamBotRef{{MachineID: "feedfacefeedface", AppID: "cli_botmuxbot00000001"}},
	}); err != nil {
		t.Fatal(err)
	}
	for _, profile := range []store.UserProfile{{ID: "u-alice", Name: "Alice"}, {ID: "u-bob", Name: "Bob"}} {
		if err := repo.UpsertUserProfile(context.Background(), profile); err != nil {
			t.Fatal(err)
		}
	}
	return &externalBotHarness{t: t, cfg: cfg, repo: repo, apex: &Apex{Config: cfg, Repository: repo, Registry: tunnel.NewRegistry(time.Minute, "", nil)}}
}

func (h *externalBotHarness) call(method, path, unionID string, body any) (int, map[string]any) {
	h.t.Helper()
	var reader *strings.Reader
	if body != nil {
		data, _ := json.Marshal(body)
		reader = strings.NewReader(string(data))
	} else {
		reader = strings.NewReader("")
	}
	request := httptest.NewRequest(method, "http://localhost"+path, reader)
	request.Header.Set("Cookie", auth.SessionCookieName+"="+auth.MintSession(h.cfg, auth.SessionUser{UnionID: unionID, Name: unionID}))
	request.Header.Set("Origin", "http://localhost")
	if body != nil {
		request.Header.Set("Content-Type", "application/json")
	}
	recorder := httptest.NewRecorder()
	h.apex.ServeHTTP(recorder, request)
	var out map[string]any
	_ = json.Unmarshal(recorder.Body.Bytes(), &out)
	return recorder.Code, out
}

func (h *externalBotHarness) register(unionID string, body map[string]any) (int, map[string]any) {
	return h.call(http.MethodPost, "/api/teams/"+extTeam+"/external-bots", unionID, body)
}

func (h *externalBotHarness) remove(unionID, appID string) (int, map[string]any) {
	return h.call(http.MethodDelete, "/api/teams/"+extTeam+"/external-bots/"+appID, unionID, nil)
}

func (h *externalBotHarness) externalBots() []store.TeamExternalBot {
	h.t.Helper()
	team, err := h.repo.GetTeam(context.Background(), extTeam)
	if err != nil {
		h.t.Fatal(err)
	}
	return team.ExternalBots
}

func expectExternalBotStatus(t *testing.T, gotStatus int, got map[string]any, status int, code string) {
	t.Helper()
	if gotStatus != status || (code != "" && got["error"] != code) {
		t.Fatalf("got %d %v, want %d %s", gotStatus, got, status, code)
	}
}

func TestExternalBotRegisterValidatesInput(t *testing.T) {
	h := newExternalBotHarness(t)
	status, body := h.register("u-dave", map[string]any{"appId": extAppID, "name": "Outside"})
	expectExternalBotStatus(t, status, body, http.StatusForbidden, "not_in_team")
	for _, tc := range []struct {
		body map[string]any
		code string
	}{
		{map[string]any{"appId": "ou_not_an_app", "name": "Outside"}, "invalid_app_id"},
		{map[string]any{"appId": extAppID, "name": "   "}, "name_required"},
		{map[string]any{"appId": extAppID, "name": "Outside", "unionId": "ou_open_id_is_app_scoped"}, "invalid_union_id"},
		{map[string]any{"appId": "cli_platform00000000", "name": "Platform"}, "platform_app"},
	} {
		status, body := h.register("u-bob", tc.body)
		expectExternalBotStatus(t, status, body, http.StatusBadRequest, tc.code)
	}
	// A botmux bot of the team is managed from its machine.
	status, body = h.register("u-carol", map[string]any{"appId": "cli_botmuxbot00000001", "name": "Copy"})
	expectExternalBotStatus(t, status, body, http.StatusConflict, "already_team_bot")
	if bots := h.externalBots(); len(bots) != 0 {
		t.Fatalf("refused registrations were stored: %+v", bots)
	}
}

func TestExternalBotRegisterOwnershipAndUpdate(t *testing.T) {
	h := newExternalBotHarness(t)
	status, body := h.register("u-bob", map[string]any{"appId": " " + extAppID + " ", "name": "  Outside  ", "unionId": "on_0123456789abcdef"})
	expectExternalBotStatus(t, status, body, http.StatusOK, "")
	bots := h.externalBots()
	if len(bots) != 1 || bots[0].AppID != extAppID || bots[0].Name != "Outside" || bots[0].UnionID != "on_0123456789abcdef" || bots[0].RegisteredBy != "u-bob" || bots[0].RegisteredAt == 0 {
		t.Fatalf("stored = %+v", bots)
	}
	// The caller cannot claim to be someone else, and cannot take over
	// another member's registration.
	status, body = h.register("u-carol", map[string]any{"appId": extAppID, "name": "Mine", "registeredBy": "u-carol"})
	expectExternalBotStatus(t, status, body, http.StatusConflict, "registered_by_other")
	// The registrant updates it: dropping the union_id is allowed.
	status, body = h.register("u-bob", map[string]any{"appId": extAppID, "name": "Outside v2"})
	expectExternalBotStatus(t, status, body, http.StatusOK, "")
	bots = h.externalBots()
	if len(bots) != 1 || bots[0].Name != "Outside v2" || bots[0].UnionID != "" || bots[0].RegisteredBy != "u-bob" {
		t.Fatalf("after update = %+v", bots)
	}
}

func TestExternalBotRemoveIsForTheRegistrantOrAnAdmin(t *testing.T) {
	h := newExternalBotHarness(t)
	for _, appID := range []string{extAppID, "cli_fedcba9876543210"} {
		if status, body := h.register("u-bob", map[string]any{"appId": appID, "name": "Outside"}); status != http.StatusOK {
			t.Fatalf("register %s: %d %v", appID, status, body)
		}
	}
	status, body := h.remove("u-carol", extAppID)
	expectExternalBotStatus(t, status, body, http.StatusForbidden, "not_registrant")
	status, body = h.remove("u-dave", extAppID)
	expectExternalBotStatus(t, status, body, http.StatusForbidden, "not_in_team")
	status, body = h.remove("u-bob", "cli_aaaaaaaaaaaaaaaa")
	expectExternalBotStatus(t, status, body, http.StatusNotFound, "external_bot_not_found")
	status, body = h.remove("u-bob", "not-an-app")
	expectExternalBotStatus(t, status, body, http.StatusBadRequest, "invalid_app_id")
	// The registrant, then the team creator (an admin).
	status, body = h.remove("u-bob", extAppID)
	expectExternalBotStatus(t, status, body, http.StatusOK, "")
	status, body = h.remove("u-alice", "cli_fedcba9876543210")
	expectExternalBotStatus(t, status, body, http.StatusOK, "")
	if bots := h.externalBots(); len(bots) != 0 {
		t.Fatalf("left = %+v", bots)
	}
}

func TestLeaveTeamDropsTheLeaversExternalBots(t *testing.T) {
	h := newExternalBotHarness(t)
	h.register("u-bob", map[string]any{"appId": extAppID, "name": "Bob's"})
	h.register("u-carol", map[string]any{"appId": "cli_fedcba9876543210", "name": "Carol's"})
	status, body := h.call(http.MethodPost, "/api/teams/"+extTeam+"/leave", "u-bob", nil)
	expectExternalBotStatus(t, status, body, http.StatusOK, "")
	bots := h.externalBots()
	if len(bots) != 1 || bots[0].RegisteredBy != "u-carol" {
		t.Fatalf("after leave = %+v", bots)
	}
}

func TestRosterListsActiveExternalBots(t *testing.T) {
	h := newExternalBotHarness(t)
	h.register("u-bob", map[string]any{"appId": extAppID, "name": "Outside", "unionId": "on_0123456789abcdef"})
	// An orphan: its registrant left without the cleanup.
	seedOrphanExternalBot(t, h.repo, extTeam, store.TeamExternalBot{AppID: "cli_fedcba9876543210", Name: "Orphan", RegisteredBy: "u-gone", RegisteredAt: 1})
	status, body := h.call(http.MethodGet, "/api/teams/"+extTeam+"/roster", "u-carol", nil)
	expectExternalBotStatus(t, status, body, http.StatusOK, "")
	list, _ := body["externalBots"].([]any)
	if len(list) != 1 {
		t.Fatalf("externalBots = %v", body["externalBots"])
	}
	got := list[0].(map[string]any)
	delete(got, "registeredAt")
	want := map[string]any{"appId": extAppID, "name": "Outside", "unionId": "on_0123456789abcdef", "registeredBy": "u-bob", "registeredByName": "Bob"}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("external bot = %v, want %v", got, want)
	}
}

func TestExternalBotRoutesHonourTheFeishuCanarySwitch(t *testing.T) {
	h := newExternalBotHarness(t)
	h.apex.FeishuWritesDisabled = true
	status, body := h.register("u-bob", map[string]any{"appId": extAppID, "name": "Outside"})
	expectExternalBotStatus(t, status, body, http.StatusServiceUnavailable, "feishu_writes_disabled")
	status, body = h.remove("u-bob", extAppID)
	expectExternalBotStatus(t, status, body, http.StatusServiceUnavailable, "feishu_writes_disabled")
	if bots := h.externalBots(); len(bots) != 0 {
		t.Fatalf("blocked registration persisted: %+v", bots)
	}
}

// ── daemon-facing reads ─────────────────────────────────────────────────────

func TestMachineAgentsListsActiveExternalBots(t *testing.T) {
	h := newAgentsHarness(t)
	h.seedAlice()
	ctx := context.Background()
	for _, bot := range []store.TeamExternalBot{
		{AppID: "cli_ext", Name: "Outside", UnionID: "on_ext", RegisteredBy: "u-alice", RegisteredAt: 1},
		{AppID: "cli_later", Name: "Later on botmux", RegisteredBy: "u-alice", RegisteredAt: 2},
	} {
		if err := h.repository.PutTeamExternalBot(ctx, "t1", bot); err != nil {
			t.Fatal(err)
		}
	}
	seedOrphanExternalBot(t, h.repository, "t1", store.TeamExternalBot{AppID: "cli_orphan", Name: "Orphan", RegisteredBy: "u-gone", RegisteredAt: 3})
	// cli_later was installed on a member's botmux machine after it was
	// registered: it is a botmux bot now, not an external one.
	h.seed("m-alice2", "u-alice", "Alice", "alice-box-2", time.Now(), agentBot("cli_later", "Later"))
	r := h.call(http.MethodGet, "/v1/machine/agents?teamId=t1", h.aliceToken(), nil)
	want := `{"teamId":"t1","teamName":"Team","agents":[{"appId":"cli_ext","openId":null,"unionId":"on_ext","name":"Outside","specialties":[],"mentionable":true,"online":true,"owner":{"unionId":"u-alice","name":"u-alice"},"machineId":"","machineName":"","external":true}]}`
	if r.status != http.StatusOK || r.text != want {
		t.Fatalf("%d\n%s\nwant\n%s", r.status, r.text, want)
	}
}

func TestMachineGroupsAcceptActiveExternalBots(t *testing.T) {
	h := newGroupsHarness(t)
	h.seedAlice()
	ctx := context.Background()
	if err := h.repository.AddTeamMember(ctx, "t1", "u-bob"); err != nil {
		t.Fatal(err)
	}
	if err := h.repository.PutTeamExternalBot(ctx, "t1", store.TeamExternalBot{AppID: "cli_ext", Name: "Outside", RegisteredBy: "u-bob", RegisteredAt: 1}); err != nil {
		t.Fatal(err)
	}
	seedOrphanExternalBot(t, h.repository, "t1", store.TeamExternalBot{AppID: "cli_orphan", Name: "Orphan", RegisteredBy: "u-gone", RegisteredAt: 2})
	r := h.call(http.MethodPost, "/v1/machine/groups", h.aliceToken(), groupBody("cli_ext", "cli_orphan"))
	if r.status != http.StatusForbidden || r.text != `{"error":"not_in_team_bots","appIds":["cli_orphan"]}` {
		t.Fatalf("%d %s", r.status, r.text)
	}
	// Past the opt-in gate, the unroutable Feishu answers 502.
	if r := h.call(http.MethodPost, "/v1/machine/groups", h.aliceToken(), groupBody("cli_ext")); r.status != http.StatusBadGateway {
		t.Fatalf("%d %s", r.status, r.text)
	}
}

func TestResolveOptedInBotsPullsTheRegistrantIn(t *testing.T) {
	team := store.TeamDoc{Members: []string{"u-alice", "u-bob"}, ExternalBots: []store.TeamExternalBot{{AppID: "cli_ext", Name: "Outside", RegisteredBy: "u-bob"}}}
	got := resolveOptedInBots(team, []string{"cli_ext"}, nil)
	if !reflect.DeepEqual(got, map[string]string{"cli_ext": "u-bob"}) {
		t.Fatalf("owners = %v", got)
	}
}

// seedOrphanExternalBot leaves bot in the team after its registrant is gone:
// the registrant joins, registers, then leaves without the cleanup.
func seedOrphanExternalBot(t *testing.T, repo *store.DocumentRepository, teamID string, bot store.TeamExternalBot) {
	t.Helper()
	ctx := context.Background()
	if err := repo.AddTeamMember(ctx, teamID, bot.RegisteredBy); err != nil {
		t.Fatal(err)
	}
	if err := repo.PutTeamExternalBot(ctx, teamID, bot); err != nil {
		t.Fatal(err)
	}
	if err := repo.RemoveTeamMember(ctx, teamID, bot.RegisteredBy); err != nil {
		t.Fatal(err)
	}
}

func TestExternalBotRegisterRefusesABotmuxBot(t *testing.T) {
	h := newExternalBotHarness(t)
	// Carol runs this bot on botmux and never added it to the team; whether
	// it joins is her call, not Bob's.
	if err := seedMachine(h.repo, store.RegisterMachine{
		MachineID: "cafecafecafecafe", UnionID: "u-carol", OwnerName: "Carol", Name: "carol-box", BotmuxVersion: "1.0.0",
		Bots: []store.BotInfo{{AppID: "cli_carolprivate001", Name: "Private"}}, LastSeen: time.Now().UnixMilli(),
	}); err != nil {
		t.Fatal(err)
	}
	status, body := h.register("u-bob", map[string]any{"appId": "cli_carolprivate001", "name": "Private", "unionId": "on_0123456789abcdef"})
	expectExternalBotStatus(t, status, body, http.StatusConflict, "botmux_bot")
	if bots := h.externalBots(); len(bots) != 0 {
		t.Fatalf("botmux bot registered as external: %+v", bots)
	}
}

func TestExternalBotOrphanIsReplaceableAndHidden(t *testing.T) {
	h := newExternalBotHarness(t)
	seedOrphanExternalBot(t, h.repo, extTeam, store.TeamExternalBot{AppID: extAppID, Name: "Orphan", RegisteredBy: "u-gone", RegisteredAt: 1})
	status, body := h.call(http.MethodGet, "/api/teams/"+extTeam+"/roster", "u-carol", nil)
	if status != http.StatusOK || len(body["externalBots"].([]any)) != 0 {
		t.Fatalf("roster shows an orphan: %d %v", status, body["externalBots"])
	}
	status, body = h.register("u-carol", map[string]any{"appId": extAppID, "name": "Adopted"})
	expectExternalBotStatus(t, status, body, http.StatusOK, "")
	bots := h.externalBots()
	if len(bots) != 1 || bots[0].RegisteredBy != "u-carol" || bots[0].Name != "Adopted" {
		t.Fatalf("after adoption = %+v", bots)
	}
}

func TestRejoiningDoesNotReviveOldExternalBots(t *testing.T) {
	h := newExternalBotHarness(t)
	seedOrphanExternalBot(t, h.repo, extTeam, store.TeamExternalBot{AppID: extAppID, Name: "Old vouch", RegisteredBy: "u-dave", RegisteredAt: 1})
	invite, err := auth.IssueTeamInvite(h.cfg, auth.TeamInvitePayload{TeamID: extTeam, TeamName: "Team", InviterUnionID: "u-alice"})
	if err != nil {
		t.Fatal(err)
	}
	status, body := h.call(http.MethodPost, "/api/teams/accept", "u-dave", map[string]any{"invite": invite})
	expectExternalBotStatus(t, status, body, http.StatusOK, "")
	if bots := h.externalBots(); len(bots) != 0 {
		t.Fatalf("rejoin revived %+v", bots)
	}
	// A current member accepting again keeps what they registered.
	h.register("u-dave", map[string]any{"appId": extAppID, "name": "New vouch"})
	h.call(http.MethodPost, "/api/teams/accept", "u-dave", map[string]any{"invite": invite})
	if bots := h.externalBots(); len(bots) != 1 || bots[0].Name != "New vouch" {
		t.Fatalf("accepting twice dropped %+v", bots)
	}
}
