package teamsync

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"reflect"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/botmux-ai/botmux-platform/internal/feishu"
	"github.com/botmux-ai/botmux-platform/internal/store"
	"github.com/botmux-ai/botmux-platform/internal/tunnel"
)

// Ports the pickHallTeachBackfill cases of test/hall-teach.test.ts (the
// listHallBots cases live with the feishu client) plus the master increments
// of syncHallMembers / teamEntry.

func TestPickHallTeachBackfillThrottlesPerTeam(t *testing.T) {
	s := NewService(nil, nil, nil)
	candidates := []TeachCandidate{{AppID: "cli_a", Name: "Alpha"}}
	t0 := time.UnixMilli(10_000_000)
	if got := s.PickHallTeachBackfill("team1", candidates, t0); !reflect.DeepEqual(got, []string{"Alpha"}) {
		t.Fatalf("first pick = %v", got)
	}
	if got := s.PickHallTeachBackfill("team1", candidates, t0.Add(time.Minute)); len(got) != 0 {
		t.Fatalf("pick inside window = %v", got)
	}
	if got := s.PickHallTeachBackfill("team1", candidates, t0.Add(31*time.Minute)); !reflect.DeepEqual(got, []string{"Alpha"}) {
		t.Fatalf("pick after window = %v", got)
	}
	// Other teams are independent.
	if got := s.PickHallTeachBackfill("team2", candidates, t0.Add(time.Minute)); !reflect.DeepEqual(got, []string{"Alpha"}) {
		t.Fatalf("other team pick = %v", got)
	}
}

func TestPickHallTeachBackfillCapsAttemptsPerBot(t *testing.T) {
	s := NewService(nil, nil, nil)
	candidates := []TeachCandidate{{AppID: "cli_a", Name: "Alpha"}}
	step := 31 * time.Minute
	base := time.UnixMilli(10_000_000)
	fired := 0
	for i := 0; i < 10; i++ {
		if len(s.PickHallTeachBackfill("team1", candidates, base.Add(time.Duration(i)*step))) > 0 {
			fired++
		}
	}
	if fired != hallTeachMaxAttempts {
		t.Fatalf("fired %d times, want %d", fired, hallTeachMaxAttempts)
	}
	// A newly added unlearned bot is still eligible.
	got := s.PickHallTeachBackfill("team1", append(candidates, TeachCandidate{AppID: "cli_b", Name: "Beta"}), base.Add(11*step))
	if !reflect.DeepEqual(got, []string{"Beta"}) {
		t.Fatalf("pick with new bot = %v", got)
	}
}

func TestPickHallTeachBackfillDeduplicatesNames(t *testing.T) {
	s := NewService(nil, nil, nil)
	got := s.PickHallTeachBackfill("team1", []TeachCandidate{{AppID: "cli_a", Name: "Same"}, {AppID: "cli_b", Name: "Same"}}, time.UnixMilli(10_000_000))
	if !reflect.DeepEqual(got, []string{"Same"}) {
		t.Fatalf("pick = %v", got)
	}
}

type feishuCall struct {
	Method, Path, Query, Body string
}

type fakeFeishu struct {
	t         *testing.T
	server    *httptest.Server
	mu        sync.Mutex
	calls     []feishuCall
	removeErr bool
	hallBots  []map[string]string
}

func newFakeFeishu(t *testing.T) *fakeFeishu {
	f := &fakeFeishu{t: t}
	f.server = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		f.mu.Lock()
		f.calls = append(f.calls, feishuCall{Method: r.Method, Path: r.URL.Path, Query: r.URL.RawQuery, Body: string(body)})
		removeErr, hallBots := f.removeErr, f.hallBots
		f.mu.Unlock()
		w.Header().Set("Content-Type", "application/json")
		switch {
		case r.URL.Path == "/open-apis/auth/v3/tenant_access_token/internal":
			_, _ = io.WriteString(w, `{"code":0,"tenant_access_token":"t-test","expire":7200}`)
		case r.Method == http.MethodPost && r.URL.Path == "/open-apis/im/v1/chats":
			_, _ = io.WriteString(w, `{"code":0,"data":{"chat_id":"oc_built"}}`)
		case strings.HasSuffix(r.URL.Path, "/members/bots"):
			payload, _ := json.Marshal(map[string]any{"code": 0, "data": map[string]any{"items": hallBots, "has_more": false}})
			_, _ = w.Write(payload)
		case strings.HasSuffix(r.URL.Path, "/members") && r.Method == http.MethodDelete && removeErr:
			_, _ = io.WriteString(w, `{"code":232099,"msg":"remove refused"}`)
		case strings.HasSuffix(r.URL.Path, "/members"):
			_, _ = io.WriteString(w, `{"code":0,"data":{"invalid_id_list":[]}}`)
		default:
			_, _ = io.WriteString(w, `{"code":0,"data":{}}`)
		}
	}))
	t.Cleanup(f.server.Close)
	return f
}

func (f *fakeFeishu) client() *feishu.Client {
	return feishu.NewClient(f.server.URL, "cli_platform", "secret", nil)
}

func (f *fakeFeishu) find(method, pathSuffix string) []feishuCall {
	f.mu.Lock()
	defer f.mu.Unlock()
	var out []feishuCall
	for _, call := range f.calls {
		if call.Method == method && strings.HasSuffix(call.Path, pathSuffix) {
			out = append(out, call)
		}
	}
	return out
}

func (f *fakeFeishu) count() int {
	f.mu.Lock()
	defer f.mu.Unlock()
	return len(f.calls)
}

type hallFixture struct {
	service  *Service
	repo     *store.DocumentRepository
	registry *tunnel.Registry
	feishu   *fakeFeishu
}

func newHallFixture(t *testing.T, hallChatID string) hallFixture {
	t.Helper()
	ctx := context.Background()
	repo := store.NewDocumentRepository(store.NewMemoryDatabaseProvider())
	if _, err := repo.BindMachineCAS(ctx, "aa11bb22cc33dd44", "on_owner", "Owner"); err != nil {
		t.Fatal(err)
	}
	if err := repo.PersistRegister(ctx, store.RegisterMachine{
		MachineID: "aa11bb22cc33dd44", UnionID: "on_owner", OwnerName: "Owner", Name: "box",
		Bots: []store.BotInfo{{AppID: "cli_a", Name: "Alpha"}}, LastSeen: time.Now().UnixMilli(),
	}); err != nil {
		t.Fatal(err)
	}
	if err := repo.CreateTeam(ctx, store.TeamDoc{
		ID: "team1", Name: "Team", Members: []string{"on_owner"}, CreatedBy: "on_owner", CreatedAt: time.Now().UnixMilli(),
		Bots: []store.TeamBotRef{{MachineID: "aa11bb22cc33dd44", AppID: "cli_a"}},
	}); err != nil {
		t.Fatal(err)
	}
	if hallChatID != "" {
		if won, err := repo.CompareAndSetTeamHallChat(ctx, "team1", "", hallChatID); err != nil || !won {
			t.Fatalf("seed hall: won=%v err=%v", won, err)
		}
	}
	registry := tunnel.NewRegistry(time.Minute, "", nil)
	registry.Upsert(&tunnel.MachineConn{
		MachineID: "aa11bb22cc33dd44", UnionID: "on_stale", Name: "box", LastSeen: time.Now(),
		Bots: []tunnel.BotInfo{{AppID: "cli_a", Name: "Alpha"}},
	})
	fake := newFakeFeishu(t)
	fake.hallBots = []map[string]string{{"bot_id": "ou_alpha", "bot_name": "Alpha"}, {"bot_id": "ou_other", "bot_name": "Other"}}
	service := NewService(repo, registry, fake.client())
	return hallFixture{service: service, repo: repo, registry: registry, feishu: fake}
}

func TestSyncHallMembersIgnoresRemoveFailures(t *testing.T) {
	f := newHallFixture(t, "oc_hall")
	f.feishu.removeErr = true
	if err := f.service.SyncHallMembers(context.Background(), "team1", nil, []string{"cli_gone"}); err != nil {
		t.Fatalf("SyncHallMembers returned %v; removal is best effort", err)
	}
	if calls := f.feishu.find(http.MethodDelete, "/open-apis/im/v1/chats/oc_hall/members"); len(calls) != 1 {
		t.Fatalf("remove calls = %+v", calls)
	}
}

func TestSyncHallMembersAddTeachesUnlearnedHallBots(t *testing.T) {
	f := newHallFixture(t, "oc_hall")
	if err := f.service.SyncHallMembers(context.Background(), "team1", []string{"cli_a"}, nil); err != nil {
		t.Fatal(err)
	}
	if calls := f.feishu.find(http.MethodPost, "/open-apis/im/v1/chats/oc_hall/members"); len(calls) != 1 {
		t.Fatalf("add calls = %+v", calls)
	}
	messages := f.feishu.find(http.MethodPost, "/open-apis/im/v1/messages")
	if len(messages) != 1 || !strings.Contains(messages[0].Body, `ou_alpha`) || strings.Contains(messages[0].Body, `ou_other`) {
		t.Fatalf("teach messages = %+v", messages)
	}
}

func TestSyncHallMembersBuildsHallAndTeaches(t *testing.T) {
	f := newHallFixture(t, "")
	if err := f.service.SyncHallMembers(context.Background(), "team1", []string{"cli_a"}, nil); err != nil {
		t.Fatal(err)
	}
	team, err := f.repo.GetTeam(context.Background(), "team1")
	if err != nil || team.HallChatID != "oc_built" {
		t.Fatalf("hall = %q err=%v", team.HallChatID, err)
	}
	if calls := f.feishu.find(http.MethodGet, "/open-apis/im/v1/chats/oc_built/members/bots"); len(calls) != 1 {
		t.Fatalf("teach should list the new hall's bots: %+v", f.feishu.calls)
	}
	if messages := f.feishu.find(http.MethodPost, "/open-apis/im/v1/messages"); len(messages) != 1 {
		t.Fatalf("teach messages = %+v", messages)
	}
}

func TestSyncHallMembersHonoursWriteSwitch(t *testing.T) {
	f := newHallFixture(t, "oc_hall")
	f.service.SetFeishuWrites(false)
	if err := f.service.SyncHallMembers(context.Background(), "team1", []string{"cli_a"}, []string{"cli_b"}); err != nil {
		t.Fatal(err)
	}
	if n := f.feishu.count(); n != 0 {
		t.Fatalf("feishu calls with writes disabled: %d", n)
	}
}

func TestTeamEntryCarriesOwnerAndBackfillsLiveUnlearnedBots(t *testing.T) {
	f := newHallFixture(t, "oc_hall")
	f.service.teachDelay = time.Millisecond
	entry, ok, err := f.service.teamEntry(context.Background(), "team1", nil)
	if err != nil || !ok {
		t.Fatalf("teamEntry ok=%v err=%v", ok, err)
	}
	want := []Bot{{AppID: "cli_a", Name: "Alpha", OwnerUnionID: "on_owner"}}
	if !reflect.DeepEqual(entry.Bots, want) {
		t.Fatalf("bots = %+v, want %+v (owner from MachineDoc, not the connection)", entry.Bots, want)
	}
	if !reflect.DeepEqual(entry.GroupChatIDs, []string{"oc_hall"}) {
		t.Fatalf("groupChatIds = %v", entry.GroupChatIDs)
	}
	deadline := time.Now().Add(3 * time.Second)
	for len(f.feishu.find(http.MethodPost, "/open-apis/im/v1/messages")) == 0 {
		if time.Now().After(deadline) {
			t.Fatal("backfill teach was not sent")
		}
		time.Sleep(5 * time.Millisecond)
	}
	// The window is now consumed: a second aggregation does not re-@.
	f.service.Invalidate("team1")
	if _, _, err := f.service.teamEntry(context.Background(), "team1", nil); err != nil {
		t.Fatal(err)
	}
	time.Sleep(30 * time.Millisecond)
	if n := len(f.feishu.find(http.MethodPost, "/open-apis/im/v1/messages")); n != 1 {
		t.Fatalf("teach messages = %d, want 1", n)
	}
}

func TestTeamEntryBackfillHonoursWriteSwitch(t *testing.T) {
	f := newHallFixture(t, "oc_hall")
	f.service.SetFeishuWrites(false)
	f.service.teachDelay = time.Millisecond
	if _, _, err := f.service.teamEntry(context.Background(), "team1", nil); err != nil {
		t.Fatal(err)
	}
	time.Sleep(30 * time.Millisecond)
	if n := f.feishu.count(); n != 0 {
		t.Fatalf("feishu calls with writes disabled: %d", n)
	}
}

func TestTeamEntryListsActiveExternalBots(t *testing.T) {
	f := newHallFixture(t, "oc_hall")
	f.service.SetFeishuWrites(false)
	ctx := context.Background()
	for _, member := range []string{"on_member", "on_left"} {
		if err := f.repo.AddTeamMember(ctx, "team1", member); err != nil {
			t.Fatal(err)
		}
	}
	for _, bot := range []store.TeamExternalBot{
		{AppID: "cli_ext", Name: "Outside", UnionID: "on_ext", RegisteredBy: "on_member", RegisteredAt: 1},
		// No union_id yet: still listed, daemons trust it in team groups only.
		{AppID: "cli_ext_nouid", Name: "Outside 2", RegisteredBy: "on_owner", RegisteredAt: 2},
		// Its registrant leaves below without the cleanup.
		{AppID: "cli_orphan", Name: "Orphan", UnionID: "on_orphan", RegisteredBy: "on_left", RegisteredAt: 3},
		// A botmux bot of the team already uses this appId.
		{AppID: "cli_a", Name: "Impostor", UnionID: "on_impostor", RegisteredBy: "on_member", RegisteredAt: 4},
		// A member machine runs this one on botmux (not opted in): listing
		// it would make that daemon trust on_private on all its bots.
		{AppID: "cli_private", Name: "Private", UnionID: "on_private", RegisteredBy: "on_member", RegisteredAt: 5},
	} {
		if err := f.repo.PutTeamExternalBot(ctx, "team1", bot); err != nil {
			t.Fatal(err)
		}
	}
	if err := f.repo.RemoveTeamMember(ctx, "team1", "on_left"); err != nil {
		t.Fatal(err)
	}
	if err := f.repo.PersistRegister(ctx, store.RegisterMachine{
		MachineID: "aa11bb22cc33dd44", UnionID: "on_owner", OwnerName: "Owner", Name: "box",
		Bots: []store.BotInfo{{AppID: "cli_a", Name: "Alpha"}, {AppID: "cli_private", Name: "Private"}}, LastSeen: time.Now().UnixMilli(),
	}); err != nil {
		t.Fatal(err)
	}
	entry, ok, err := f.service.teamEntry(ctx, "team1", nil)
	if err != nil || !ok {
		t.Fatalf("teamEntry ok=%v err=%v", ok, err)
	}
	want := []Bot{
		{AppID: "cli_a", Name: "Alpha", OwnerUnionID: "on_owner"},
		{AppID: "cli_ext", UnionID: "on_ext", Name: "Outside", OwnerUnionID: "on_member", External: true},
		{AppID: "cli_ext_nouid", Name: "Outside 2", OwnerUnionID: "on_owner", External: true},
	}
	if !reflect.DeepEqual(entry.Bots, want) {
		t.Fatalf("bots = %+v, want %+v", entry.Bots, want)
	}
}

func TestSyncHallMembersBuildsHallWithExternalBots(t *testing.T) {
	f := newHallFixture(t, "")
	ctx := context.Background()
	if err := f.repo.PutTeamExternalBot(ctx, "team1", store.TeamExternalBot{AppID: "cli_ext", Name: "Outside", RegisteredBy: "on_owner", RegisteredAt: 1}); err != nil {
		t.Fatal(err)
	}
	if err := f.service.SyncHallMembers(ctx, "team1", []string{"cli_ext"}, nil); err != nil {
		t.Fatal(err)
	}
	// The new hall's bots are added in batches right after the chat exists.
	var added strings.Builder
	for _, call := range f.feishu.find(http.MethodPost, "/open-apis/im/v1/chats/oc_built/members") {
		added.WriteString(call.Body)
	}
	if !strings.Contains(added.String(), `"cli_a"`) || !strings.Contains(added.String(), `"cli_ext"`) {
		t.Fatalf("hall members added = %s, want both the botmux bot and the external bot", added.String())
	}
	// The teach @ is for botmux bots only: no daemon runs an external bot.
	for _, message := range f.feishu.find(http.MethodPost, "/open-apis/im/v1/messages") {
		if strings.Contains(message.Body, "Outside") {
			t.Fatalf("external bot was hall-taught: %s", message.Body)
		}
	}
}

func TestSyncHallMembersKeepsBotsTheHallStillHolds(t *testing.T) {
	f := newHallFixture(t, "oc_hall")
	ctx := context.Background()
	if err := f.repo.PutTeamExternalBot(ctx, "team1", store.TeamExternalBot{AppID: "cli_ext", Name: "Outside", RegisteredBy: "on_owner", RegisteredAt: 1}); err != nil {
		t.Fatal(err)
	}
	// A stale removal list: cli_a is still a botmux bot of the team and
	// cli_ext still an active external bot; only cli_gone may leave.
	if err := f.service.SyncHallMembers(ctx, "team1", nil, []string{"cli_a", "cli_ext", "cli_gone"}); err != nil {
		t.Fatal(err)
	}
	removals := f.feishu.find(http.MethodDelete, "/open-apis/im/v1/chats/oc_hall/members")
	if len(removals) != 1 || strings.Contains(removals[0].Body, "cli_a\"") || strings.Contains(removals[0].Body, "cli_ext") || !strings.Contains(removals[0].Body, "cli_gone") {
		t.Fatalf("hall removals = %+v", removals)
	}
	// Nothing left to remove: no call at all.
	if err := f.service.SyncHallMembers(ctx, "team1", nil, []string{"cli_ext"}); err != nil {
		t.Fatal(err)
	}
	if n := len(f.feishu.find(http.MethodDelete, "/open-apis/im/v1/chats/oc_hall/members")); n != 1 {
		t.Fatalf("hall removals = %d, want still 1", n)
	}
}
