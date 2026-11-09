package feishu

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"reflect"
	"strings"
	"sync"
	"testing"
)

// testdata/ts_requests.json is recorded from the TypeScript Feishu client
// (src/auth/feishu-*.ts) with fetch stubbed by the same canned responses as
// goldenResponder below. Each scenario pins method, path+query, Authorization,
// Content-Type and the exact JSON body bytes of every request.

type goldenCall struct {
	Method      string `json:"method"`
	URL         string `json:"url"`
	Auth        string `json:"auth"`
	ContentType string `json:"contentType"`
	Body        string `json:"body"`
}

type goldenScenario struct {
	Result json.RawMessage `json:"result"`
	Calls  []goldenCall    `json:"calls"`
}

const goldenHost = "https://open.feishu.test"

func loadGolden(t *testing.T) map[string]json.RawMessage {
	t.Helper()
	raw, err := os.ReadFile("testdata/ts_requests.json")
	if err != nil {
		t.Fatal(err)
	}
	var out map[string]json.RawMessage
	if err := json.Unmarshal(raw, &out); err != nil {
		t.Fatal(err)
	}
	return out
}

// recorder is an httptest Feishu that records requests and answers through a
// per-test responder.
type recorder struct {
	*httptest.Server
	mu      sync.Mutex
	calls   []goldenCall
	respond func(r *http.Request, call goldenCall) (int, string)
}

func newRecorder(t *testing.T, respond func(r *http.Request, call goldenCall) (int, string)) (*recorder, *Client) {
	t.Helper()
	rec := &recorder{respond: respond}
	rec.Server = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		call := goldenCall{
			Method: r.Method, URL: goldenHost + r.RequestURI,
			Auth: r.Header.Get("Authorization"), ContentType: r.Header.Get("Content-Type"), Body: string(body),
		}
		rec.mu.Lock()
		rec.calls = append(rec.calls, call)
		respond := rec.respond
		rec.mu.Unlock()
		status, payload := respond(r, call)
		w.WriteHeader(status)
		_, _ = io.WriteString(w, payload)
	}))
	t.Cleanup(rec.Close)
	return rec, NewClient(rec.URL, "cli_app", "sec", rec.Client())
}

func (r *recorder) take() []goldenCall {
	r.mu.Lock()
	defer r.mu.Unlock()
	out := r.calls
	r.calls = nil
	return out
}

func jsonResponse(v any) (int, string) {
	b, err := marshalJS(v)
	if err != nil {
		panic(err)
	}
	return http.StatusOK, string(b)
}

// goldenResponder mirrors respond() of the TypeScript recording script.
func goldenResponder() func(r *http.Request, call goldenCall) (int, string) {
	var mu sync.Mutex
	memberPage, botPage := 0, 0
	return func(r *http.Request, call goldenCall) (int, string) {
		mu.Lock()
		defer mu.Unlock()
		u, _ := url.Parse(call.URL)
		p := u.Path
		switch {
		case strings.HasSuffix(p, "/tenant_access_token/internal"):
			return jsonResponse(map[string]any{"code": 0, "tenant_access_token": "t-1", "expire": 7200})
		case strings.HasSuffix(p, "/users/batch_get_id"):
			return jsonResponse(map[string]any{"code": 0, "data": map[string]any{"user_list": []any{map[string]any{"email": "Alice@corp.com", "user_id": "on_alice"}}}})
		case strings.HasPrefix(p, "/open-apis/contact/v3/users/"):
			return jsonResponse(map[string]any{"code": 0, "data": map[string]any{"user": map[string]any{"open_id": "ou_resolved"}}})
		case p == "/open-apis/im/v1/messages":
			return jsonResponse(map[string]any{"code": 0})
		case p == "/open-apis/im/v1/chats" && r.Method == http.MethodPost:
			return jsonResponse(map[string]any{"code": 0, "data": map[string]any{"chat_id": "oc_new"}})
		case strings.HasSuffix(p, "/members/is_in_chat"):
			return jsonResponse(map[string]any{"code": 0, "data": map[string]any{"is_in_chat": true}})
		case strings.HasSuffix(p, "/members/bots"):
			botPage++
			if botPage == 1 {
				return jsonResponse(map[string]any{"code": 0, "data": map[string]any{"items": []any{map[string]any{"bot_id": "ou_b1", "bot_name": "B1"}, map[string]any{"bot_id": 7}}, "has_more": true, "page_token": "b p"}})
			}
			return jsonResponse(map[string]any{"code": 0, "data": map[string]any{"items": []any{map[string]any{"bot_id": "ou_b2"}}, "has_more": false}})
		case strings.HasSuffix(p, "/members") && r.Method == http.MethodGet:
			memberPage++
			if memberPage == 1 {
				return jsonResponse(map[string]any{"code": 0, "data": map[string]any{"items": []any{map[string]any{"member_id": "x"}}, "has_more": true, "page_token": "pt+1/="}})
			}
			return jsonResponse(map[string]any{"code": 0, "data": map[string]any{"items": []any{map[string]any{"member_id": "on_target"}}, "has_more": false}})
		case strings.HasSuffix(p, "/members") && u.Query().Get("member_id_type") == "union_id":
			return jsonResponse(map[string]any{"code": 0, "data": map[string]any{"invalid_id_list": []string{"on_bad"}}})
		case strings.HasSuffix(p, "/members"):
			return jsonResponse(map[string]any{"code": 0, "data": map[string]any{"invalid_id_list": []string{}}})
		case strings.HasSuffix(p, "/link"):
			return jsonResponse(map[string]any{"code": 0, "data": map[string]any{"share_link": "https://share"}})
		case r.Method == http.MethodPut:
			return jsonResponse(map[string]any{"code": 0})
		case p == "/open-apis/search/v1/user":
			return jsonResponse(map[string]any{"code": 0, "data": map[string]any{"users": []any{}}})
		case p == OAuthV2TokenPath:
			return jsonResponse(map[string]any{"code": 0, "access_token": "ua", "expires_in": 7200, "refresh_token": "ur", "refresh_token_expires_in": 604800, "scope": "offline_access"})
		case p == userInfoPath:
			return jsonResponse(map[string]any{"code": 0, "data": map[string]any{"union_id": "on_x", "open_id": "ou_x", "name": "X"}})
		}
		return jsonResponse(map[string]any{"code": 0, "data": map[string]any{}})
	}
}

func assertSameResult(t *testing.T, name string, want json.RawMessage, got any) {
	t.Helper()
	gotJSON, err := marshalJS(got)
	if err != nil {
		t.Fatal(err)
	}
	var wantValue, gotValue any
	_ = json.Unmarshal(want, &wantValue)
	_ = json.Unmarshal(gotJSON, &gotValue)
	if !reflect.DeepEqual(wantValue, gotValue) {
		t.Errorf("%s result:\n got %s\nwant %s", name, gotJSON, want)
	}
}

func TestRequestsMatchTypeScriptRecording(t *testing.T) {
	t.Parallel()
	golden := loadGolden(t)
	rec, c := newRecorder(t, nil)
	ctx := context.Background()
	ok := func(err error) map[string]any {
		if err != nil {
			return map[string]any{"ok": false, "error": err.Error()}
		}
		return map[string]any{"ok": true}
	}
	scenarios := map[string]func() any{
		"invite": func() any {
			return ok(c.SendInviteDM(ctx, "ou_recipient", InviteMessage{TeamName: "Team *A* [x]", InviterName: "Bob_`", InviterUnionID: "on_inviter", InviteURL: "https://platform.test/?invite=abc&x=<1>"}))
		},
		"firstUse": func() any {
			return ok(c.SendCredentialFirstUseDM(ctx, "on_owner", CredentialFirstUseMessage{Platform: "lark", MachineName: "mac<1>", MachineID: "m1", OwnerName: "Owner_1", AppID: "cli_x", ManageURL: "https://platform.test/credentials"}))
		},
		"joined": func() any {
			return ok(c.SendTeamJoinedDM(ctx, "on_inviter", TeamJoinedMessage{JoinerName: "J", JoinerUnionID: "on_joiner", TeamName: "T&T", InviterOpenID: "ou_inv"}))
		},
		"disbanded": func() any {
			return ok(c.SendTeamDisbandedDM(ctx, "on_member", TeamDisbandedMessage{TeamName: "T", DissolverName: "D*"}))
		},
		"deviceConfirm": func() any {
			return ok(c.SendDeviceConfirmDM(ctx, "on_owner", DeviceConfirmMessage{DeviceName: "dev", MachineName: "box", ConfirmURL: "https://platform.test/confirm?g=1", ExpiresInSec: 150}))
		},
		"deviceRevokedReuse": func() any {
			return ok(c.SendDeviceRevokedAlarmDM(ctx, "on_owner", DeviceRevokedMessage{DeviceName: "dev[1]", Reason: DeviceRevokedRefreshReuse}))
		},
		"deviceRevokedRecovery": func() any {
			return ok(c.SendDeviceRevokedAlarmDM(ctx, "on_owner", DeviceRevokedMessage{DeviceName: "dev", Reason: DeviceRevokedRecoveryRequired}))
		},
		"hallTeach": func() any {
			return c.SendHallTeachMention(ctx, "t-1", "oc_hall", []string{"ou_1", "ou_2", "ou_1", ""})
		},
		"createGroup": func() any {
			r, err := c.CreateGroup(ctx, GroupCreateOptions{Name: "G<1>", RequesterUnionID: "on_req", MemberUnionIDs: []string{"on_req", "on_bad", "", "on_req"}, BotAppIDs: []string{"a1", "a2", "a3", "a4", "a5", "a6"}})
			if err != nil {
				return ok(err)
			}
			return map[string]any{"ok": true, "chatId": r.ChatID, "shareLink": r.ShareLink, "invalidBotIds": r.InvalidBotIDs, "invalidUnionIds": r.InvalidUnionIDs, "ownerTransferred": r.OwnerTransferred}
		},
		"createHall": func() any {
			chatID, invalid, err := c.CreateHallGroup(ctx, "Team", []string{"a1"})
			if err != nil {
				return ok(err)
			}
			return map[string]any{"ok": true, "chatId": chatID, "invalidBotIds": invalid}
		},
		"isUserInChat": func() any {
			in, err := c.IsUserInChat(ctx, "t-1", "oc/1", "on_target")
			if err != nil {
				return "error"
			}
			return in
		},
		"isPlatformBotInChat": func() any {
			in, err := c.IsPlatformBotInChat(ctx, "t-1", "oc 1")
			if err != nil {
				return "error"
			}
			return in
		},
		"listHallBots": func() any { return c.ListHallBots(ctx, "t-1", "oc_hall") },
		"search": func() any {
			users, err := c.SearchUsers(ctx, "张 三&x~*'()", "u-1")
			if err != nil {
				return ok(err)
			}
			return map[string]any{"ok": true, "users": users}
		},
		"email": func() any {
			unionID, err := c.ResolveUnionIDByEmail(ctx, "t-1", "  Alice@Corp.COM ")
			if err != nil {
				return nil
			}
			return unionID
		},
		"credential": func() any {
			user, token, err := c.ExchangeCodeForCredential(ctx, "the-code", "https://platform.test/auth/callback")
			if err != nil {
				return ok(err)
			}
			return map[string]any{"user": user, "scope": token.Scope, "refresh": token.RefreshToken}
		},
	}
	for name, run := range scenarios {
		var want goldenScenario
		if err := json.Unmarshal(golden[name], &want); err != nil {
			t.Fatalf("%s: %v", name, err)
		}
		rec.mu.Lock()
		rec.respond = goldenResponder()
		rec.mu.Unlock()
		got := run()
		calls := rec.take()
		assertSameResult(t, name, want.Result, got)
		if len(calls) != len(want.Calls) {
			t.Errorf("%s: %d calls, want %d:\n got %+v\nwant %+v", name, len(calls), len(want.Calls), calls, want.Calls)
			continue
		}
		for i := range calls {
			if calls[i] != want.Calls[i] {
				t.Errorf("%s call %d:\n got %+v\nwant %+v", name, i, calls[i], want.Calls[i])
			}
		}
	}

	var hallNames []string
	if err := json.Unmarshal(golden["hallNames"], &hallNames); err != nil {
		t.Fatal(err)
	}
	inputs := []string{"Team", strings.Repeat("a", 100), strings.Repeat("a", 54) + "\U0001F600z"}
	for i, input := range inputs {
		if got := HallGroupName(input); got != hallNames[i] {
			t.Errorf("HallGroupName(%q) = %q, want %q", input, got, hallNames[i])
		}
	}
}
