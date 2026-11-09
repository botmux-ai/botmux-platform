package feishu

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"sync"
	"testing"
	"time"
)

func TestExchangeCode(t *testing.T) {
	t.Parallel()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("content-type", "application/json")
		switch r.URL.Path {
		case "/open-apis/auth/v3/app_access_token/internal":
			json.NewEncoder(w).Encode(map[string]any{"code": 0, "app_access_token": "app-token"})
		case "/open-apis/authen/v1/oidc/access_token":
			if r.Header.Get("Authorization") != "Bearer app-token" {
				t.Errorf("bad auth: %s", r.Header.Get("Authorization"))
			}
			json.NewEncoder(w).Encode(map[string]any{"code": 0, "data": map[string]any{"access_token": "user-token", "refresh_token": "refresh", "expires_in": 60}})
		case "/open-apis/authen/v1/user_info":
			if r.Header.Get("Authorization") != "Bearer user-token" {
				t.Errorf("bad auth: %s", r.Header.Get("Authorization"))
			}
			json.NewEncoder(w).Encode(map[string]any{"code": 0, "data": map[string]any{"union_id": "union", "open_id": "open", "name": "Name", "avatar_url": "avatar"}})
		default:
			http.NotFound(w, r)
		}
	}))
	defer srv.Close()
	c := NewClient(srv.URL, "app", "secret", srv.Client())
	c.now = func() time.Time { return time.Unix(1000, 0) }
	u, token, err := c.ExchangeCode(context.Background(), "code")
	if err != nil {
		t.Fatal(err)
	}
	if u.UnionID != "union" || u.OpenID != "open" || token.AccessToken != "user-token" || token.ExpiresAt != 1060 {
		t.Fatalf("unexpected: %+v %+v", u, token)
	}
}

func TestSearchUsersTokenInvalid(t *testing.T) {
	t.Parallel()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		json.NewEncoder(w).Encode(map[string]any{"code": 99991677, "msg": "token expired"})
	}))
	defer srv.Close()
	c := NewClient(srv.URL, "a", "s", srv.Client())
	if _, err := c.SearchUsers(context.Background(), "foo", "bad"); err != ErrTokenInvalid {
		t.Fatalf("error=%v", err)
	}
}

func TestCreateGroupWorkflow(t *testing.T) {
	t.Parallel()
	var mu sync.Mutex
	calls := map[string]int{}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		calls[r.Method+" "+r.URL.Path]++
		mu.Unlock()
		w.Header().Set("content-type", "application/json")
		switch {
		case r.URL.Path == "/open-apis/auth/v3/tenant_access_token/internal":
			json.NewEncoder(w).Encode(map[string]any{"code": 0, "tenant_access_token": "tenant"})
		case r.Method == http.MethodPost && r.URL.Path == "/open-apis/im/v1/chats":
			json.NewEncoder(w).Encode(map[string]any{"code": 0, "data": map[string]any{"chat_id": "chat"}})
		case r.Method == http.MethodPost && r.URL.Path == "/open-apis/im/v1/chats/chat/members":
			json.NewEncoder(w).Encode(map[string]any{"code": 0, "data": map[string]any{"invalid_id_list": []string{}}})
		case r.Method == http.MethodPost && r.URL.Path == "/open-apis/im/v1/chats/chat/link":
			json.NewEncoder(w).Encode(map[string]any{"code": 0, "data": map[string]any{"share_link": "https://chat"}})
		default:
			json.NewEncoder(w).Encode(map[string]any{"code": 0, "data": map[string]any{}})
		}
	}))
	defer srv.Close()
	c := NewClient(srv.URL, "a", "s", srv.Client())
	r, err := c.CreateGroup(context.Background(), GroupCreateOptions{Name: "G", RequesterUnionID: "u1", MemberUnionIDs: []string{"u1", "u2"}, BotAppIDs: []string{"a1", "a2"}})
	if err != nil {
		t.Fatal(err)
	}
	if r.ChatID != "chat" || r.ShareLink != "https://chat" || !r.OwnerTransferred {
		t.Fatalf("result=%+v", r)
	}
	mu.Lock()
	defer mu.Unlock()
	if calls["POST /open-apis/im/v1/chats/chat/members"] != 2 {
		t.Fatalf("member calls=%v", calls)
	}
}

func TestAddBotsGoneChatReturnsInvalidIDsForHallRecovery(t *testing.T) {
	t.Parallel()
	var mu sync.Mutex
	calls := 0
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/open-apis/im/v1/chats/gone/members" {
			http.NotFound(w, r)
			return
		}
		mu.Lock()
		calls++
		mu.Unlock()
		_ = json.NewEncoder(w).Encode(map[string]any{"code": 232009, "msg": "chat not found"})
	}))
	defer srv.Close()
	c := NewClient(srv.URL, "a", "s", srv.Client())
	invalid, err := c.AddBotsToChat(context.Background(), "tenant", "gone", []string{"app-1", "app-2"})
	if err != nil {
		t.Fatalf("gone chat must be represented as invalid IDs, got %v", err)
	}
	if len(invalid) != 2 || invalid[0] != "app-1" || invalid[1] != "app-2" {
		t.Fatalf("invalid IDs = %#v", invalid)
	}
	mu.Lock()
	defer mu.Unlock()
	if calls != 3 { // one failed batch, then one retry per bot
		t.Fatalf("member calls = %d", calls)
	}
}

func TestFeishuOperationRemovesQueryAndDynamicIdentifiers(t *testing.T) {
	t.Parallel()
	tests := map[string]string{
		"/open-apis/search/v1/user?query=private":                "get /open-apis/search/v1/user",
		"/open-apis/im/v1/chats/chat-secret/members?type=app_id": "get /open-apis/im/v1/chats/:chat_id/members",
		"/open-apis/contact/v3/users/union-secret?type=union_id": "get /open-apis/contact/v3/users/:user_id",
	}
	for input, expected := range tests {
		if got := feishuOperation(http.MethodGet, input); got != expected {
			t.Errorf("feishuOperation(%q) = %q, want %q", input, got, expected)
		}
	}
}
