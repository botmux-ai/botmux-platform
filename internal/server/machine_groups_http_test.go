package server

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/botmux-ai/botmux-platform/internal/feishu"
)

// Port of test/server-machine-groups.test.ts. Feishu points at an
// unroutable host: creation fails fast with 502 after every gate; the
// add-members Feishu gates use injected checks.

var errFakeFeishu = errors.New("feishu transient")

func newGroupsHarness(t *testing.T) *machineAPIHarness {
	h := newMachineAPIHarness(t, func(a *Apex, w http.ResponseWriter, r *http.Request) bool {
		return a.handleMachineGroupsAPI(w, r)
	})
	cfg := h.apex.Config
	h.apex.Feishu = feishu.NewClient(cfg.FeishuHost, cfg.FeishuAppID, cfg.FeishuAppSecret, nil)
	h.apex.MachineGroups = MachineGroupsDeps{
		Throttle: NewMachineGroupThrottle(),
		Checks:   groupChecks(true, nil, true, nil),
	}
	return h
}

func groupChecks(botIn bool, botErr error, userIn bool, userErr error) ChatMembershipChecks {
	return ChatMembershipChecks{
		PlatformBotInChat: func(context.Context, string, string) (bool, error) { return botIn, botErr },
		UserInChat:        func(context.Context, string, string, string) (bool, error) { return userIn, userErr },
		GetToken:          func(context.Context) (string, error) { return "fake-tenant-token", nil },
	}
}

func groupBody(appIDs ...string) map[string]any {
	return map[string]any{"teamId": "t1", "appIds": appIDs}
}

// ── auth / method ───────────────────────────────────────────────────────────

func TestMachineGroupsMethodAndAuth(t *testing.T) {
	h := newGroupsHarness(t)
	h.seedAlice()
	for _, path := range []string{"/v1/machine/groups", "/v1/machine/groups/oc_group/members"} {
		r := h.call(http.MethodGet, path, h.aliceToken(), nil)
		expectMachineAPIError(t, r, http.StatusMethodNotAllowed, "method_not_allowed")
		if r.header.Get("Cache-Control") != "no-store" {
			t.Fatalf("Cache-Control = %q", r.header.Get("Cache-Control"))
		}
		expectMachineAPIError(t, h.call(http.MethodPost, path, "", groupBody("cli_a")), http.StatusUnauthorized, "invalid_machine_token")
	}
	expectMachineAPIError(t, h.call(http.MethodPost, "/v1/machine/groups", h.token("m-ghost", "u-alice", "Alice"), groupBody("cli_a")), http.StatusForbidden, "machine_ownership_mismatch")
	// Unrelated paths fall through.
	if r := h.call(http.MethodPost, "/v1/machine/groups/a/b", h.aliceToken(), nil); r.status != http.StatusNotFound || r.text != "" {
		t.Fatalf("%d %s", r.status, r.text)
	}
}

// ── parameters / trust domain ───────────────────────────────────────────────

func TestMachineGroupsParameters(t *testing.T) {
	h := newGroupsHarness(t)
	h.seedAlice()
	for _, path := range []string{"/v1/machine/groups", "/v1/machine/groups/oc_group/members"} {
		expectMachineAPIError(t, h.call(http.MethodPost, path, h.aliceToken(), map[string]any{"appIds": []string{"cli_a"}}), http.StatusBadRequest, "missing_teamId")
		expectMachineAPIError(t, h.call(http.MethodPost, path, h.aliceToken(), map[string]any{"teamId": "t1"}), http.StatusBadRequest, "appIds_required")
		// Non-string entries and empty strings are dropped before the check.
		expectMachineAPIError(t, h.call(http.MethodPost, path, h.aliceToken(), map[string]any{"teamId": "t1", "appIds": []any{1, "", nil}}), http.StatusBadRequest, "appIds_required")
		// A non-object / invalid body is null.
		expectMachineAPIError(t, h.call(http.MethodPost, path, h.aliceToken(), []string{"x"}), http.StatusBadRequest, "missing_teamId")
		// Exact key match: TeamId is not teamId.
		expectMachineAPIError(t, h.call(http.MethodPost, path, h.aliceToken(), map[string]any{"TeamId": "t1", "appIds": []string{"cli_a"}}), http.StatusBadRequest, "missing_teamId")
	}
	// A malformed chat id escape (decodeURIComponent throws) is rejected
	// before auth.
	for _, chat := range []string{"oc_%ff", "oc_%e4%b8"} {
		expectMachineAPIError(t, h.call(http.MethodPost, "/v1/machine/groups/"+chat+"/members", "", nil), http.StatusBadRequest, "invalid_chat_id")
	}
}

func TestMachineGroupsNonMemberIs404AndNotThrottled(t *testing.T) {
	h := newGroupsHarness(t)
	h.seed("m-carol", "u-carol", "Carol", "carol-box", time.Now())
	carol := h.token("m-carol", "u-carol", "Carol")
	for _, path := range []string{"/v1/machine/groups", "/v1/machine/groups", "/v1/machine/groups/oc_group/members"} {
		expectMachineAPIError(t, h.call(http.MethodPost, path, carol, groupBody("cli_a")), http.StatusNotFound, "not_found")
	}
}

// ── opt-in gate ─────────────────────────────────────────────────────────────

func TestMachineGroupsRequiresOptIn(t *testing.T) {
	h := newGroupsHarness(t)
	h.seedAlice(agentBot("cli_a", "AgentA")) // not opted in
	for _, path := range []string{"/v1/machine/groups", "/v1/machine/groups/oc_group/members", "/v1/machine/groups/oc_group/members"} {
		r := h.call(http.MethodPost, path, h.aliceToken(), groupBody("cli_a", "cli_a", "cli_x"))
		expectMachineAPIError(t, r, http.StatusForbidden, "not_in_team_bots")
		if r.text != `{"error":"not_in_team_bots","appIds":["cli_a","cli_x"]}` {
			t.Fatalf("body = %s", r.text)
		}
	}
}

func TestMachineGroupsOrphanReferenceIsForbidden(t *testing.T) {
	h := newGroupsHarness(t)
	h.seed("m-dead", "u-alice", "Alice", "dead", time.Now(), agentBot("cli_dead", "Dead"))
	h.seedAlice()
	h.optIn("m-dead", "cli_dead")
	if err := h.repository.RetireMachine(context.Background(), "m-dead"); err != nil {
		t.Fatal(err)
	}
	expectMachineAPIError(t, h.call(http.MethodPost, "/v1/machine/groups", h.aliceToken(), groupBody("cli_dead")), http.StatusForbidden, "not_in_team_bots")
}

// ── past every gate: Feishu unreachable → 502 ───────────────────────────────

func TestMachineGroupsCreateReachesFeishu(t *testing.T) {
	h := newGroupsHarness(t)
	h.seedAlice(agentBot("cli_a", "AgentA"))
	h.optIn("m-alice", "cli_a")
	r := h.call(http.MethodPost, "/v1/machine/groups", h.aliceToken(), groupBody("cli_a"))
	if r.status != http.StatusBadGateway || r.text != `{"ok":false,"error":"TypeError: fetch failed"}` {
		t.Fatalf("%d %s", r.status, r.text)
	}
}

func TestMachineGroupsCreateWithTeammateBot(t *testing.T) {
	h := newGroupsHarness(t)
	if err := h.repository.AddTeamMember(context.Background(), "t1", "u-bob"); err != nil {
		t.Fatal(err)
	}
	h.seedAlice()
	h.seed("m-bob", "u-bob", "Bob", "bob-box", time.Now(), agentBot("cli_b", "BobAgent"))
	h.optIn("m-bob", "cli_b")
	if r := h.call(http.MethodPost, "/v1/machine/groups", h.aliceToken(), groupBody("cli_b")); r.status != http.StatusBadGateway {
		t.Fatalf("%d %s", r.status, r.text)
	}
}

// ── rate limit ──────────────────────────────────────────────────────────────

func TestMachineGroupsRateLimit(t *testing.T) {
	h := newGroupsHarness(t)
	now := time.UnixMilli(1_700_000_000_000)
	h.apex.MachineGroups.Now = func() time.Time { return now }
	h.seedAlice(agentBot("cli_a", "AgentA"))
	h.optIn("m-alice", "cli_a")
	if first := h.call(http.MethodPost, "/v1/machine/groups", h.aliceToken(), groupBody("cli_a")); first.status != http.StatusBadGateway {
		t.Fatalf("first = %d %s", first.status, first.text)
	}
	now = now.Add(12_345 * time.Millisecond)
	second := h.call(http.MethodPost, "/v1/machine/groups", h.aliceToken(), groupBody("cli_a"))
	if second.status != http.StatusTooManyRequests || second.text != `{"error":"rate_limited","retryAfterMs":17655}` {
		t.Fatalf("second = %d %s", second.status, second.text)
	}
	// Creation and add-members share the window.
	expectMachineAPIError(t, h.call(http.MethodPost, "/v1/machine/groups/oc_group/members", h.aliceToken(), groupBody("cli_a")), http.StatusTooManyRequests, "rate_limited")
	now = now.Add(30 * time.Second)
	if third := h.call(http.MethodPost, "/v1/machine/groups", h.aliceToken(), groupBody("cli_a")); third.status != http.StatusBadGateway {
		t.Fatalf("after window = %d %s", third.status, third.text)
	}
}

// ── add members to an existing group ────────────────────────────────────────

func TestMachineGroupMembersRejectsHall(t *testing.T) {
	h := newGroupsHarness(t)
	h.seedAlice(agentBot("cli_a", "AgentA"))
	h.optIn("m-alice", "cli_a")
	if ok, err := h.repository.CompareAndSetTeamHallChat(context.Background(), "t1", "", "oc_hall"); err != nil || !ok {
		t.Fatalf("hall = %v %v", ok, err)
	}
	expectMachineAPIError(t, h.call(http.MethodPost, "/v1/machine/groups/oc_hall/members", h.aliceToken(), groupBody("cli_a")), http.StatusForbidden, "chat_is_hall")
}

func TestMachineGroupMembersFeishuGates(t *testing.T) {
	h := newGroupsHarness(t)
	h.seedAlice(agentBot("cli_a", "AgentA"))
	h.optIn("m-alice", "cli_a")
	path := "/v1/machine/groups/oc_group/members"

	h.apex.MachineGroups.Checks = groupChecks(false, nil, true, nil)
	r := h.call(http.MethodPost, path, h.aliceToken(), groupBody("cli_a"))
	if r.status != http.StatusForbidden || r.text != `{"error":"platform_bot_not_in_chat","platformAppId":"cli_platform"}` {
		t.Fatalf("bot not in chat = %d %s", r.status, r.text)
	}
	h.apex.Config.PlatformAppName = "Botmux"
	if r := h.call(http.MethodPost, path, h.aliceToken(), groupBody("cli_a")); r.text != `{"error":"platform_bot_not_in_chat","platformAppId":"cli_platform","platformAppName":"Botmux"}` {
		t.Fatalf("with app name = %s", r.text)
	}

	h.apex.MachineGroups.Checks = groupChecks(true, nil, false, nil)
	expectMachineAPIError(t, h.call(http.MethodPost, path, h.aliceToken(), groupBody("cli_a")), http.StatusForbidden, "requester_not_in_chat")

	// Transient failures fail closed.
	h.apex.MachineGroups.Checks = groupChecks(false, errFakeFeishu, true, nil)
	r = h.call(http.MethodPost, path, h.aliceToken(), groupBody("cli_a"))
	if r.status != http.StatusBadGateway || r.text != `{"ok":false,"error":"feishu_unavailable"}` {
		t.Fatalf("bot check error = %d %s", r.status, r.text)
	}
	h.apex.MachineGroups.Checks = groupChecks(true, nil, false, errFakeFeishu)
	expectMachineAPIError(t, h.call(http.MethodPost, path, h.aliceToken(), groupBody("cli_a")), http.StatusBadGateway, "feishu_unavailable")
	h.apex.MachineGroups.Checks = groupChecks(true, nil, true, nil)
	h.apex.MachineGroups.Checks.GetToken = func(context.Context) (string, error) { return "", errFakeFeishu }
	expectMachineAPIError(t, h.call(http.MethodPost, path, h.aliceToken(), groupBody("cli_a")), http.StatusBadGateway, "feishu_unavailable")
}

// Every gate passes; Feishu is unreachable so every id is reported invalid,
// but adding members is best effort and still answers 200.
func TestMachineGroupMembersBestEffort(t *testing.T) {
	h := newGroupsHarness(t)
	h.seedAlice(agentBot("cli_a", "AgentA"))
	h.optIn("m-alice", "cli_a")
	r := h.call(http.MethodPost, "/v1/machine/groups/oc_group/members", h.aliceToken(), groupBody("cli_a"))
	if r.status != http.StatusOK || r.text != `{"ok":true,"chatId":"oc_group","invalidBotIds":["cli_a"],"invalidOwnerUnionIds":["u-alice"]}` {
		t.Fatalf("%d %s", r.status, r.text)
	}
	// The write armed the shared window.
	expectMachineAPIError(t, h.call(http.MethodPost, "/v1/machine/groups", h.aliceToken(), groupBody("cli_a")), http.StatusTooManyRequests, "rate_limited")
}

func TestMachineGroupMembersDecodesChatID(t *testing.T) {
	h := newGroupsHarness(t)
	h.seedAlice(agentBot("cli_a", "AgentA"))
	h.optIn("m-alice", "cli_a")
	var gotChat string
	h.apex.MachineGroups.Checks.PlatformBotInChat = func(_ context.Context, _, chatID string) (bool, error) {
		gotChat = chatID
		return false, nil
	}
	h.call(http.MethodPost, "/v1/machine/groups/oc%5Fx%20y/members", h.aliceToken(), groupBody("cli_a"))
	if gotChat != "oc_x y" {
		t.Fatalf("chat = %q", gotChat)
	}
}

// ── happy paths against a fake Feishu ───────────────────────────────────────

type fakeGroupFeishu struct {
	mu    sync.Mutex
	calls []string
}

func (f *fakeGroupFeishu) handler() http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		f.mu.Lock()
		f.calls = append(f.calls, r.Method+" "+r.URL.Path)
		f.mu.Unlock()
		w.Header().Set("Content-Type", "application/json")
		switch {
		case strings.HasSuffix(r.URL.Path, "/tenant_access_token/internal"):
			_, _ = w.Write([]byte(`{"code":0,"tenant_access_token":"tok","expire":7200}`))
		case r.Method == http.MethodPost && r.URL.Path == "/open-apis/im/v1/chats":
			_, _ = w.Write([]byte(`{"code":0,"data":{"chat_id":"oc_new"}}`))
		case strings.HasSuffix(r.URL.Path, "/link"):
			_, _ = w.Write([]byte(`{"code":0,"data":{"share_link":"https://applink/x"}}`))
		case strings.Contains(r.URL.Path, "/members"):
			var body struct {
				IDList []string `json:"id_list"`
			}
			_ = json.NewDecoder(r.Body).Decode(&body)
			invalid := []string{}
			for _, id := range body.IDList {
				if strings.HasPrefix(id, "bad") {
					invalid = append(invalid, id)
				}
			}
			data, _ := json.Marshal(map[string]any{"code": 0, "data": map[string]any{"invalid_id_list": invalid}})
			_, _ = w.Write(data)
		default:
			_, _ = w.Write([]byte(`{"code":0,"data":{}}`))
		}
	})
}

func TestMachineGroupsCreateHappyPath(t *testing.T) {
	h := newGroupsHarness(t)
	fake := &fakeGroupFeishu{}
	server := httptest.NewServer(fake.handler())
	defer server.Close()
	h.apex.Feishu = feishu.NewClient(server.URL, "cli_platform", "sec", nil)
	if err := h.repository.AddTeamMember(context.Background(), "t1", "u-bob"); err != nil {
		t.Fatal(err)
	}
	h.seedAlice(agentBot("cli_a", "AgentA"))
	h.seed("m-bob", "u-bob", "Bob", "bob-box", time.Now(), agentBot("cli_b", "BobAgent"))
	h.optIn("m-alice", "cli_a")
	h.optIn("m-bob", "cli_b")
	r := h.call(http.MethodPost, "/v1/machine/groups", h.aliceToken(), map[string]any{"teamId": "t1", "appIds": []string{"cli_a", "cli_b"}, "name": "task"})
	if r.status != http.StatusOK || r.json["ok"] != true || r.json["chatId"] != "oc_new" || r.json["shareLink"] != "https://applink/x" {
		t.Fatalf("%d %s", r.status, r.text)
	}
	if !strings.HasPrefix(r.text, `{"ok":true,"chatId":"oc_new","shareLink":"https://applink/x","invalidBotIds":[],"invalidOwnerUnionIds":[]`) {
		t.Fatalf("body = %s", r.text)
	}
	// The team mirrors the new group in the background.
	deadline := time.Now().Add(2 * time.Second)
	for {
		team, err := h.repository.GetTeam(context.Background(), "t1")
		if err == nil && slices.Contains(team.GroupChatIDs, "oc_new") {
			break
		}
		if time.Now().After(deadline) {
			t.Fatalf("group not mirrored: %+v %v", team, err)
		}
		time.Sleep(10 * time.Millisecond)
	}
}

func TestMachineGroupsWritesDisabled(t *testing.T) {
	h := newGroupsHarness(t)
	h.apex.FeishuWritesDisabled = true
	h.seedAlice(agentBot("cli_a", "AgentA"))
	h.optIn("m-alice", "cli_a")
	for _, path := range []string{"/v1/machine/groups", "/v1/machine/groups/oc_group/members"} {
		r := h.call(http.MethodPost, path, h.aliceToken(), groupBody("cli_a"))
		expectMachineAPIError(t, r, http.StatusServiceUnavailable, "feishu_writes_disabled")
		if r.header.Get("Retry-After") != "60" {
			t.Fatalf("Retry-After = %q", r.header.Get("Retry-After"))
		}
	}
	// Authentication still comes first.
	expectMachineAPIError(t, h.call(http.MethodPost, "/v1/machine/groups", "", groupBody("cli_a")), http.StatusUnauthorized, "invalid_machine_token")
}

func TestGroupCreateErrorText(t *testing.T) {
	tokenFails := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte(`{"code":999,"msg":"nope"}`))
	}))
	defer tokenFails.Close()
	createFails := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if strings.HasSuffix(r.URL.Path, "/tenant_access_token/internal") {
			_, _ = w.Write([]byte(`{"code":0,"tenant_access_token":"tok","expire":7200}`))
			return
		}
		_, _ = w.Write([]byte(`{"code":1,"msg":"bad"}`))
	}))
	defer createFails.Close()
	createError := func(host string) error {
		_, err := feishu.NewClient(host, "cli_platform", "sec", nil).CreateGroup(context.Background(), feishu.GroupCreateOptions{RequesterUnionID: "u"})
		return err
	}
	cases := []struct {
		err  error
		want string
	}{
		{feishu.ErrFeishuNotConfigured, "feishu_not_configured"},
		// String(e) of the thrown tenant-token Error.
		{createError(tokenFails.URL), "Error: tenant_access_token 失败 code=999 nope"},
		// The creation failure is returned verbatim.
		{createError(createFails.URL), "建群失败 code=1 bad"},
		{createError("http://127.0.0.1:1"), "TypeError: fetch failed"},
	}
	for _, c := range cases {
		if got := groupCreateErrorText(c.err); got != c.want {
			t.Fatalf("%v: got %q want %q", c.err, got, c.want)
		}
	}
}
