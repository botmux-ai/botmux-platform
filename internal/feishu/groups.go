package feishu

import (
	"context"
	"errors"
	"log/slog"
	"net/http"
	"strings"
)

// Group calls go through lark(): like the TypeScript helper they never throw;
// transport failures and non-JSON bodies become code -1 and are handled as a
// failed call. Best-effort steps only log.

const (
	// chat-members id_list limit (official 50); app_id batches above 5 are
	// rejected with 400 in practice.
	userBatch = 50
	botBatch  = 5

	hallTeachText = " 🤖 团队自动登记：请忽略，本条用于登记 bot 身份（union_id），无需回复。"
)

type GroupCreateOptions struct {
	Name             string
	RequesterUnionID string
	MemberUnionIDs   []string
	BotAppIDs        []string
}
type GroupResult struct {
	ChatID           string   `json:"chatId"`
	ShareLink        string   `json:"shareLink,omitempty"`
	InvalidBotIDs    []string `json:"invalidBotIds,omitempty"`
	InvalidUnionIDs  []string `json:"invalidUnionIds,omitempty"`
	OwnerTransferred bool     `json:"ownerTransferred"`
}

func chatPath(chatID string) string {
	return "/open-apis/im/v1/chats/" + encodeURIComponent(chatID)
}

// CreateGroup builds a platform-bot group: bare chat, members by union_id,
// bots by app_id (batch of 5, per-bot retry when a whole batch is refused),
// share link (before the owner transfer), owner transfer to the requester and
// an @ notification. Only chat creation fails the call (error text
// `建群失败 code=<code> <msg>`); later steps are best-effort and reported in
// the result.
func (c *Client) CreateGroup(ctx context.Context, opts GroupCreateOptions) (GroupResult, error) {
	if !c.Configured() {
		return GroupResult{}, ErrFeishuNotConfigured
	}
	token, err := c.TenantAccessToken(ctx)
	if err != nil {
		return GroupResult{}, err
	}
	createBody := jsObj{}
	if opts.Name != "" {
		createBody = jsObj{{"name", opts.Name}}
	}
	created := c.lark(ctx, http.MethodPost, "/open-apis/im/v1/chats", token, createBody)
	chatID := str(created.dataFields(), "chat_id")
	if !created.ok() || !truthy(created.dataFields()["chat_id"]) || chatID == "" {
		return GroupResult{}, created.apiError("建群失败 code=" + created.codeText() + " " + created.msgOrEmpty())
	}
	result := GroupResult{ChatID: chatID, InvalidBotIDs: []string{}, InvalidUnionIDs: []string{}}
	for _, batch := range batches(unique(opts.MemberUnionIDs), userBatch) {
		result.InvalidUnionIDs = append(result.InvalidUnionIDs, c.addMembers(ctx, token, chatID, "union_id", batch)...)
	}
	result.InvalidBotIDs = append(result.InvalidBotIDs, c.addBotBatches(ctx, token, chatID, opts.BotAppIDs)...)

	// The share link must be fetched before the owner transfer: a tenant may
	// restrict sharing to owner/admins and the platform bot would lose it.
	if link, linkErr := c.CreateChatShareLink(ctx, token, chatID); linkErr == nil {
		result.ShareLink = link
	} else {
		slog.Warn("feishu chat share link failed", "chatId", chatID, "error", linkErr)
	}
	if !containsString(result.InvalidUnionIDs, opts.RequesterUnionID) {
		transfer := c.lark(ctx, http.MethodPut, chatPath(chatID)+"?user_id_type=union_id", token, jsObj{{"owner_id", opts.RequesterUnionID}})
		result.OwnerTransferred = transfer.ok()
		if !result.OwnerTransferred {
			slog.Warn("feishu chat owner transfer failed", "chatId", chatID, "code", transfer.codeText(), "msg", transfer.msgText())
		}
	}
	if err := c.SendTextToChat(ctx, token, chatID, `<at user_id="`+opts.RequesterUnionID+`"></at> 群已建好`); err != nil {
		slog.Warn("feishu group created notice failed", "chatId", chatID, "error", err)
	}
	return result, nil
}

// addMembers adds one batch with succeed_type=1 and returns the IDs that did
// not join. A failed call (non-zero code, network) counts the whole batch.
func (c *Client) addMembers(ctx context.Context, token, chatID, idType string, ids []string) []string {
	if len(ids) == 0 {
		return nil
	}
	path := chatPath(chatID) + "/members?member_id_type=" + idType + "&succeed_type=1"
	e := c.lark(ctx, http.MethodPost, path, token, jsObj{{"id_list", ids}})
	if !e.ok() {
		slog.Warn("feishu add chat members failed", "chatId", chatID, "memberIdType", idType, "count", len(ids), "code", e.codeText(), "msg", e.msgText())
		return append([]string(nil), ids...)
	}
	items, _ := arrayItems(e.dataFields()["invalid_id_list"])
	invalid := make([]string, 0, len(items))
	for _, item := range items {
		if id, ok := stringValue(item); ok {
			invalid = append(invalid, id)
		}
	}
	return invalid
}

// addBotBatches adds bots in batches of 5; a batch refused as a whole (e.g. a
// disabled app mixed in) is retried bot by bot to keep the valid ones.
func (c *Client) addBotBatches(ctx context.Context, token, chatID string, appIDs []string) []string {
	invalid := []string{}
	for _, batch := range batches(unique(appIDs), botBatch) {
		rejected := c.addMembers(ctx, token, chatID, "app_id", batch)
		if len(rejected) == len(batch) && len(batch) > 1 {
			rejected = nil
			for _, id := range batch {
				rejected = append(rejected, c.addMembers(ctx, token, chatID, "app_id", []string{id})...)
			}
		}
		invalid = append(invalid, rejected...)
	}
	return invalid
}

// AddUsersToChat adds people by union_id and returns those who could not be
// added (every ID of a failed batch, e.g. when the chat is gone). It never
// returns an error; the error result is kept for API compatibility.
func (c *Client) AddUsersToChat(ctx context.Context, token, chatID string, unionIDs []string) ([]string, error) {
	invalid := []string{}
	for _, batch := range batches(unique(unionIDs), userBatch) {
		invalid = append(invalid, c.addMembers(ctx, token, chatID, "union_id", batch)...)
	}
	return invalid, nil
}

// AddBotsToChat adds bots by app_id and returns the refused app IDs. A gone
// chat refuses every ID, which lets team-sync check GetChatStatus and rebuild
// the hall. It never returns an error (kept for API compatibility).
func (c *Client) AddBotsToChat(ctx context.Context, token, chatID string, appIDs []string) ([]string, error) {
	return c.addBotBatches(ctx, token, chatID, appIDs), nil
}

// RemoveBotsFromChat removes bots by app_id in batches of 5. Every batch is
// attempted; failures are logged and joined into the returned error
// (TypeScript ignores them: leftover members are harmless because trust
// follows the roster).
func (c *Client) RemoveBotsFromChat(ctx context.Context, token, chatID string, appIDs []string) error {
	var errs []error
	for _, batch := range batches(unique(appIDs), botBatch) {
		e := c.lark(ctx, http.MethodDelete, chatPath(chatID)+"/members?member_id_type=app_id", token, jsObj{{"id_list", batch}})
		if !e.ok() {
			slog.Warn("feishu remove hall bots failed", "chatId", chatID, "count", len(batch), "code", e.codeText(), "msg", e.msgText())
			errs = append(errs, e.apiError(""))
		}
	}
	return errors.Join(errs...)
}

// HallGroupName is shared by hall creation and team rename. Like the
// TypeScript `.slice(0, 60)` it counts UTF-16 code units.
func HallGroupName(teamName string) string {
	return sliceUTF16("🤖 "+teamName+" · 机器人大厅", 60)
}

// CreateHallGroup creates a team bot hall: bot-only bare chat plus batched
// bots; no people, no share link, no owner transfer, no notice. Creation
// failure text: `建大厅失败 code=<code> <msg>`.
func (c *Client) CreateHallGroup(ctx context.Context, teamName string, botAppIDs []string) (string, []string, error) {
	if !c.Configured() {
		return "", nil, ErrFeishuNotConfigured
	}
	token, err := c.TenantAccessToken(ctx)
	if err != nil {
		return "", nil, err
	}
	created := c.lark(ctx, http.MethodPost, "/open-apis/im/v1/chats", token, jsObj{
		{"name", HallGroupName(teamName)},
		{"description", "botmux 平台自动创建：团队 bot 身份登记与互信（bot-only，请勿拉人/解散）"},
	})
	chatID := str(created.dataFields(), "chat_id")
	if !created.ok() || chatID == "" {
		return "", nil, created.apiError("建大厅失败 code=" + created.codeText() + " " + created.msgOrEmpty())
	}
	return chatID, c.addBotBatches(ctx, token, chatID, botAppIDs), nil
}

type ChatStatus string

const (
	ChatOK    ChatStatus = "ok"
	ChatGone  ChatStatus = "gone"
	ChatError ChatStatus = "error"
)

// goneChatCode: 232009 chat does not exist; 232001/232002 no permission / the
// platform bot is not in the chat.
func goneChatCode(code int) bool { return code == 232009 || code == 232001 || code == 232002 }

// GetChatStatus reports whether the chat is alive and operable by the
// platform bot. ChatGone means rebuild; ChatError (network, rate limit, ...)
// must never trigger a rebuild.
func (c *Client) GetChatStatus(ctx context.Context, token, chatID string) ChatStatus {
	e := c.lark(ctx, http.MethodGet, chatPath(chatID), token, nil)
	if e.ok() {
		return ChatOK
	}
	if goneChatCode(e.Code) {
		return ChatGone
	}
	return ChatError
}

// IsPlatformBotInChat asks Feishu whether the tenant token's own identity
// (the platform bot) is in the chat. A non-nil error is the transient
// "error" state: callers must fail closed and neither allow nor deny.
func (c *Client) IsPlatformBotInChat(ctx context.Context, token, chatID string) (bool, error) {
	e := c.lark(ctx, http.MethodGet, chatPath(chatID)+"/members/is_in_chat", token, nil)
	if e.ok() {
		switch strings.TrimSpace(string(e.dataFields()["is_in_chat"])) {
		case "true":
			return true, nil
		case "false":
			return false, nil
		}
	}
	// Not in the chat / no permission / chat gone all answer "not in chat".
	if goneChatCode(e.Code) {
		return false, nil
	}
	return false, e.apiError("")
}

// IsUserInChat pages the member list (union_id) looking for unionID. Feishu
// lists only people, so ownership checks are person-based. Any failed page is
// an error (fail closed: an incomplete list must not read as "not in chat").
// The platform bot must already be in the chat.
func (c *Client) IsUserInChat(ctx context.Context, token, chatID, unionID string) (bool, error) {
	pageToken := ""
	for page := 0; page < 200; page++ {
		query := "member_id_type=union_id&page_size=100"
		if pageToken != "" {
			query += "&page_token=" + encodeURIComponent(pageToken)
		}
		e := c.lark(ctx, http.MethodGet, chatPath(chatID)+"/members?"+query, token, nil)
		if !e.ok() {
			return false, e.apiError("")
		}
		data := e.dataFields()
		items, _ := arrayItems(data["items"])
		for _, item := range items {
			if id, ok := stringValue(objectFields(item)["member_id"]); ok && id == unionID {
				return true, nil
			}
		}
		if !truthy(data["has_more"]) || !truthy(data["page_token"]) {
			return false, nil
		}
		pageToken = jsString(data["page_token"])
	}
	return false, nil
}

// HallBot is a bot member of a hall. OpenID is the platform app's view of the
// bot (open_id is per app), which is what the platform bot must @.
type HallBot struct {
	OpenID string `json:"openId"`
	Name   string `json:"name"`
}

// ListHallBots lists bot members through the dedicated bots endpoint (the
// generic member list omits bots). Errors are logged and the bots collected
// so far are returned (best-effort).
func (c *Client) ListHallBots(ctx context.Context, token, chatID string) []HallBot {
	out := []HallBot{}
	pageToken := ""
	for page := 0; page < 50; page++ {
		query := "page_size=100"
		if pageToken != "" {
			query += "&page_token=" + encodeURIComponent(pageToken)
		}
		e := c.lark(ctx, http.MethodGet, chatPath(chatID)+"/members/bots?"+query, token, nil)
		if !e.ok() {
			slog.Warn("feishu list hall bots failed", "chatId", chatID, "code", e.codeText(), "msg", e.msgText())
			return out
		}
		data := e.dataFields()
		items, _ := arrayItems(data["items"])
		for _, item := range items {
			fields := objectFields(item)
			if openID := str(fields, "bot_id"); openID != "" {
				out = append(out, HallBot{OpenID: openID, Name: str(fields, "bot_name")})
			}
		}
		if !truthy(data["has_more"]) || !truthy(data["page_token"]) {
			break
		}
		pageToken = jsString(data["page_token"])
	}
	return out
}

// SendHallTeachMention @-mentions bots (platform-view open_ids) in the hall so
// each learns its own union_id from mentions[]. Best-effort: false on failure
// or when there is nobody to mention.
func (c *Client) SendHallTeachMention(ctx context.Context, token, chatID string, openIDs []string) bool {
	ids := unique(openIDs)
	if len(ids) == 0 {
		return false
	}
	mentions := make([]string, len(ids))
	for i, id := range ids {
		mentions[i] = `<at user_id="` + id + `"></at>`
	}
	e := c.lark(ctx, http.MethodPost, "/open-apis/im/v1/messages?receive_id_type=chat_id", token, jsObj{
		{"receive_id", chatID},
		{"msg_type", "text"},
		{"content", stringifyJS(jsObj{{"text", strings.Join(mentions, " ") + hallTeachText}})},
	})
	if !e.ok() {
		slog.Warn("feishu hall teach mention failed", "chatId", chatID, "count", len(ids), "code", e.codeText(), "msg", e.msgText())
		return false
	}
	return true
}

// RenameChat follows a team rename. Best-effort: failures are logged.
func (c *Client) RenameChat(ctx context.Context, token, chatID, name string) error {
	e := c.lark(ctx, http.MethodPut, chatPath(chatID), token, jsObj{{"name", name}})
	if !e.ok() {
		slog.Warn("feishu rename chat failed", "chatId", chatID, "code", e.codeText(), "msg", e.msgText())
		return e.apiError("")
	}
	return nil
}

// DisbandChat removes a duplicate hall (multi-pod creation race). Best-effort.
func (c *Client) DisbandChat(ctx context.Context, token, chatID string) error {
	e := c.lark(ctx, http.MethodDelete, chatPath(chatID), token, nil)
	if !e.ok() {
		slog.Warn("feishu disband chat failed", "chatId", chatID, "code", e.codeText(), "msg", e.msgText())
		return e.apiError("")
	}
	return nil
}

// CreateChatShareLink returns a permanent share link; a missing/empty link is
// a failure.
func (c *Client) CreateChatShareLink(ctx context.Context, token, chatID string) (string, error) {
	e := c.lark(ctx, http.MethodPost, chatPath(chatID)+"/link", token, jsObj{{"validity_period", "permanently"}})
	link := str(e.dataFields(), "share_link")
	if !e.ok() || link == "" {
		return "", e.apiError("")
	}
	return link, nil
}

// SendTextToChat posts a text message to a chat with the tenant token.
func (c *Client) SendTextToChat(ctx context.Context, token, chatID, text string) error {
	e := c.lark(ctx, http.MethodPost, "/open-apis/im/v1/messages?receive_id_type=chat_id", token, jsObj{
		{"receive_id", chatID},
		{"msg_type", "text"},
		{"content", stringifyJS(jsObj{{"text", text}})},
	})
	if !e.ok() {
		return e.apiError("")
	}
	return nil
}

func unique(values []string) []string {
	seen := map[string]struct{}{}
	out := make([]string, 0, len(values))
	for _, v := range values {
		if v == "" {
			continue
		}
		if _, ok := seen[v]; ok {
			continue
		}
		seen[v] = struct{}{}
		out = append(out, v)
	}
	return out
}
func batches(values []string, size int) [][]string {
	if size <= 0 {
		panic("invalid batch size")
	}
	out := make([][]string, 0, (len(values)+size-1)/size)
	for len(values) > 0 {
		n := min(size, len(values))
		out = append(out, values[:n])
		values = values[n:]
	}
	return out
}
func containsString(values []string, target string) bool {
	for _, v := range values {
		if v == target {
			return true
		}
	}
	return false
}
