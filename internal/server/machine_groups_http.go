package server

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"log/slog"
	"net/http"
	"regexp"
	"slices"
	"strings"
	"sync"
	"time"

	"github.com/botmux-ai/botmux-platform/internal/feishu"
	"github.com/botmux-ai/botmux-platform/internal/store"
)

// Team group creation for daemons (src/server/machine-groups-http.ts).
// Owned by Phase 2 agent B4.
//
//   POST /v1/machine/groups                  create a task group with team bots
//   POST /v1/machine/groups/:chatId/members  add team bots (+ their owners) to
//                                            an existing group
//
// Machine-token entry (RequireMachineAuth). Trust domain: the caller's owner
// must be a team member and every requested bot must be opted into the team
// (team.bots) on a registered machine of a current member. Members of an
// existing chat additionally require the platform bot and the requester to
// be in it (Feishu checks fail closed). Both write paths share one 30s
// per-machine window, armed only once Feishu is about to be written.

const machineGroupWriteInterval = 30 * time.Second

var machineGroupMembersPath = regexp.MustCompile(`^/v1/machine/groups/([^/]+)/members$`)

// MachineGroupThrottle is the per-machine write window (lastGroupCreateAt).
type MachineGroupThrottle struct {
	mu   sync.Mutex
	last map[string]time.Time
}

func NewMachineGroupThrottle() *MachineGroupThrottle {
	return &MachineGroupThrottle{last: make(map[string]time.Time)}
}

// retryAfter reports the remaining window for machineID (0 = allowed).
func (t *MachineGroupThrottle) retryAfter(machineID string, now time.Time) time.Duration {
	t.mu.Lock()
	defer t.mu.Unlock()
	last, ok := t.last[machineID]
	if !ok || now.Sub(last) >= machineGroupWriteInterval {
		return 0
	}
	return machineGroupWriteInterval - now.Sub(last)
}

func (t *MachineGroupThrottle) arm(machineID string, now time.Time) {
	t.mu.Lock()
	t.last[machineID] = now
	t.mu.Unlock()
}

// defaultMachineGroupThrottle is the process-wide window used when the Apex
// was not wired with its own (TS keeps it as module state).
var defaultMachineGroupThrottle = NewMachineGroupThrottle()

// ChatMembershipChecks are the Feishu gates of the add-members path. Nil
// fields use a.Feishu. A non-nil error is the TS 'error' state (fail closed).
type ChatMembershipChecks struct {
	PlatformBotInChat func(ctx context.Context, token, chatID string) (bool, error)
	UserInChat        func(ctx context.Context, token, chatID, unionID string) (bool, error)
	GetToken          func(ctx context.Context) (string, error)
}

// MachineGroupsDeps holds machine-group seams (throttle state, chat checks).
type MachineGroupsDeps struct {
	Throttle *MachineGroupThrottle
	Checks   ChatMembershipChecks
	// Now overrides the throttle clock (tests).
	Now func() time.Time
}

func (a *Apex) machineGroupThrottle() *MachineGroupThrottle {
	if a.MachineGroups.Throttle != nil {
		return a.MachineGroups.Throttle
	}
	return defaultMachineGroupThrottle
}

func (a *Apex) machineGroupNow() time.Time {
	if a.MachineGroups.Now != nil {
		return a.MachineGroups.Now()
	}
	return time.Now()
}

type machineGroupBody struct {
	teamID  string
	appIDs  []string
	name    string
	hasName bool
}

// readMachineGroupBody mirrors `(await readJson(req)) as {...} | null` and
// the handler's typeof coercions: an unreadable, non-object or oversized body
// is null; a non-string teamId/name and non-string appIds entries are
// ignored. Keys are matched exactly (encoding/json structs would also accept
// other casings).
func readMachineGroupBody(r *http.Request) machineGroupBody {
	var out machineGroupBody
	if r.Body == nil {
		return out
	}
	defer r.Body.Close()
	data, err := io.ReadAll(io.LimitReader(r.Body, maxJSONBody+1))
	if err != nil || len(data) == 0 || len(data) > maxJSONBody {
		return out
	}
	var fields map[string]json.RawMessage
	if json.Unmarshal(data, &fields) != nil {
		return out
	}
	_ = json.Unmarshal(fields["teamId"], &out.teamID)
	if raw, ok := fields["name"]; ok && len(raw) > 0 && raw[0] == '"' {
		out.hasName = json.Unmarshal(raw, &out.name) == nil
	}
	var items []json.RawMessage
	if json.Unmarshal(fields["appIds"], &items) == nil {
		seen := make(map[string]bool, len(items))
		for _, item := range items {
			var appID string
			if len(item) == 0 || item[0] != '"' || json.Unmarshal(item, &appID) != nil || appID == "" || seen[appID] {
				continue
			}
			seen[appID] = true
			out.appIDs = append(out.appIDs, appID)
		}
	}
	return out
}

// resolveOptedInBots maps each requested appId to its owner: the bot must be
// referenced by team.bots on a machine of a current member that still runs
// it. RETIRED / unregistered machines and departed owners are orphan
// references and skipped.
func resolveOptedInBots(team store.TeamDoc, appIDs []string, docByID map[string]store.MachineDoc) map[string]string {
	ownerByApp := make(map[string]string)
	for _, ref := range team.Bots {
		if !slices.Contains(appIDs, ref.AppID) {
			continue
		}
		if _, done := ownerByApp[ref.AppID]; done {
			continue
		}
		doc, ok := docByID[ref.MachineID]
		if !ok {
			continue
		}
		if !slices.ContainsFunc(doc.Bots, func(bot store.BotInfo) bool { return bot.AppID == ref.AppID }) {
			continue
		}
		ownerByApp[ref.AppID] = doc.UnionID
	}
	return ownerByApp
}

// machineGroupGate runs the shared part of both endpoints after auth: body,
// team membership, rate window and the opt-in gate. ok=false means the
// response has been written.
type machineGroupGate struct {
	body       machineGroupBody
	team       store.TeamDoc
	ownerByApp map[string]string
	now        time.Time
}

func (a *Apex) machineGroupPreflight(w http.ResponseWriter, r *http.Request, principal *MachineAuth, chatID string, members bool) (machineGroupGate, bool) {
	var gate machineGroupGate
	gate.body = readMachineGroupBody(r)
	if gate.body.teamID == "" {
		writeJSONNoStore(w, http.StatusBadRequest, map[string]any{"error": "missing_teamId"})
		return gate, false
	}
	if len(gate.body.appIDs) == 0 {
		writeJSONNoStore(w, http.StatusBadRequest, map[string]any{"error": "appIds_required"})
		return gate, false
	}
	// getTeamDoc is null for a missing team and a read failure alike: 404
	// either way, never revealing whether the team exists.
	team, err := a.Repository.GetTeam(r.Context(), gate.body.teamID)
	if err != nil || !slices.Contains(team.Members, principal.UnionID) {
		writeJSONNoStore(w, http.StatusNotFound, map[string]any{"error": "not_found"})
		return gate, false
	}
	gate.team = team
	// The hall is a bot-only echo chamber, never a task group.
	if members && team.HallChatID != "" && chatID == team.HallChatID {
		writeJSONNoStore(w, http.StatusForbidden, map[string]any{"error": "chat_is_hall"})
		return gate, false
	}
	gate.now = a.machineGroupNow()
	if wait := a.machineGroupThrottle().retryAfter(principal.MachineID, gate.now); wait > 0 {
		writeJSONNoStore(w, http.StatusTooManyRequests, machineGroupRateLimited{Error: "rate_limited", RetryAfterMs: wait.Milliseconds()})
		return gate, false
	}
	docs, err := a.listMachinesForMembers(r, team.Members)
	if err != nil {
		writeJSONNoStore(w, http.StatusServiceUnavailable, map[string]any{"error": "store_unavailable"})
		return gate, false
	}
	docByID := make(map[string]store.MachineDoc, len(docs))
	for _, doc := range docs {
		docByID[doc.ID] = doc
	}
	gate.ownerByApp = resolveOptedInBots(team, gate.body.appIDs, docByID)
	forbidden := make([]string, 0)
	for _, appID := range gate.body.appIDs {
		if _, ok := gate.ownerByApp[appID]; !ok {
			forbidden = append(forbidden, appID)
		}
	}
	if len(forbidden) > 0 {
		writeJSONNoStore(w, http.StatusForbidden, machineGroupNotInTeamBots{Error: "not_in_team_bots", AppIDs: forbidden})
		return gate, false
	}
	return gate, true
}

// blockMachineGroupWrite is the canary kill switch (FeishuWritesDisabled)
// for the daemon-side group writes, answered after authentication like the
// SSO-side blockFeishuMutation.
func (a *Apex) blockMachineGroupWrite(w http.ResponseWriter) bool {
	if !a.FeishuWritesDisabled {
		return false
	}
	w.Header().Set("Retry-After", "60")
	writeJSONNoStore(w, http.StatusServiceUnavailable, map[string]any{"error": "feishu_writes_disabled"})
	return true
}

// Response bodies keep the TS literal key order (a map would sort them).
type machineGroupRateLimited struct {
	Error        string `json:"error"`
	RetryAfterMs int64  `json:"retryAfterMs"`
}

type machineGroupNotInTeamBots struct {
	Error  string   `json:"error"`
	AppIDs []string `json:"appIds"`
}

type machineGroupFailure struct {
	OK    bool   `json:"ok"`
	Error string `json:"error"`
}

type machineGroupCreated struct {
	OK                   bool     `json:"ok"`
	ChatID               string   `json:"chatId"`
	ShareLink            string   `json:"shareLink,omitempty"`
	InvalidBotIDs        []string `json:"invalidBotIds"`
	InvalidOwnerUnionIDs []string `json:"invalidOwnerUnionIds"`
}

type machineGroupMembersAdded struct {
	OK                   bool     `json:"ok"`
	ChatID               string   `json:"chatId"`
	InvalidBotIDs        []string `json:"invalidBotIds"`
	InvalidOwnerUnionIDs []string `json:"invalidOwnerUnionIds"`
}

// handleMachineGroupsAPI serves /v1/machine/groups and /v1/machine/groups/*.
func (a *Apex) handleMachineGroupsAPI(w http.ResponseWriter, r *http.Request) bool {
	pathname := requestPathname(r)
	membersMatch := machineGroupMembersPath.FindStringSubmatch(pathname)
	if pathname != "/v1/machine/groups" && membersMatch == nil {
		return false
	}
	if r.Method != http.MethodPost {
		writeJSONNoStore(w, http.StatusMethodNotAllowed, map[string]any{"error": "method_not_allowed"})
		return true
	}
	if membersMatch != nil {
		chatID, ok := uriComponentDecode(membersMatch[1])
		if !ok {
			writeJSONNoStore(w, http.StatusBadRequest, map[string]any{"error": "invalid_chat_id"})
			return true
		}
		a.addMachineGroupMembers(w, r, chatID)
		return true
	}
	a.createMachineGroup(w, r)
	return true
}

func (a *Apex) createMachineGroup(w http.ResponseWriter, r *http.Request) {
	principal, ok := a.RequireMachineAuth(w, r)
	if !ok || a.blockMachineGroupWrite(w) {
		return
	}
	gate, ok := a.machineGroupPreflight(w, r, principal, "", false)
	if !ok {
		return
	}
	appIDs := gate.body.appIDs
	memberUnionIDs := []string{principal.UnionID}
	for _, appID := range appIDs {
		if owner := gate.ownerByApp[appID]; !slices.Contains(memberUnionIDs, owner) {
			memberUnionIDs = append(memberUnionIDs, owner)
		}
	}
	// Only an actual creation attempt consumes the window.
	a.machineGroupThrottle().arm(principal.MachineID, gate.now)
	name := ""
	if gate.body.hasName {
		name = gate.body.name
	}
	var result feishu.GroupResult
	err := feishu.ErrFeishuNotConfigured
	if a.Feishu != nil {
		result, err = a.Feishu.CreateGroup(r.Context(), feishu.GroupCreateOptions{
			Name: name, RequesterUnionID: principal.UnionID, MemberUnionIDs: memberUnionIDs, BotAppIDs: appIDs,
		})
	}
	if err != nil {
		writeJSONNoStore(w, http.StatusBadGateway, machineGroupFailure{OK: false, Error: groupCreateErrorText(err)})
		return
	}
	if result.ChatID != "" {
		teamID, chatID := gate.team.ID, result.ChatID
		go func() {
			ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
			defer cancel()
			if err := a.Repository.AddTeamGroupChat(ctx, teamID, chatID); err != nil {
				slog.Warn("machine group: mirror team group failed", "teamId", teamID, "chatId", chatID, "error", err)
				return
			}
			if a.TeamSync != nil {
				if err := a.TeamSync.PushToMembers(ctx, teamID); err != nil {
					slog.Warn("machine group: team-sync push failed", "teamId", teamID, "chatId", chatID, "error", err)
				}
			}
		}()
	}
	slog.Info("team-agents group created", "byUnionId", principal.UnionID, "byMachineId", principal.MachineID,
		"teamId", gate.team.ID, "bots", len(appIDs), "members", len(memberUnionIDs), "chatId", result.ChatID)
	writeJSONNoStore(w, http.StatusOK, machineGroupCreated{
		OK: true, ChatID: result.ChatID, ShareLink: result.ShareLink,
		InvalidBotIDs: nonNilStrings(result.InvalidBotIDs), InvalidOwnerUnionIDs: nonNilStrings(result.InvalidUnionIDs),
	})
}

func (a *Apex) addMachineGroupMembers(w http.ResponseWriter, r *http.Request, chatID string) {
	principal, ok := a.RequireMachineAuth(w, r)
	if !ok || a.blockMachineGroupWrite(w) {
		return
	}
	gate, ok := a.machineGroupPreflight(w, r, principal, chatID, true)
	if !ok {
		return
	}
	appIDs := gate.body.appIDs
	ownerUnionIDs := make([]string, 0, len(appIDs))
	for _, appID := range appIDs {
		if owner := gate.ownerByApp[appID]; !slices.Contains(ownerUnionIDs, owner) {
			ownerUnionIDs = append(ownerUnionIDs, owner)
		}
	}
	ctx := r.Context()
	checks := a.chatMembershipChecks()
	unavailable := func() {
		writeJSONNoStore(w, http.StatusBadGateway, machineGroupFailure{OK: false, Error: "feishu_unavailable"})
	}
	token, err := checks.GetToken(ctx)
	if err != nil {
		slog.Warn("machine group members: tenant token failed", "teamId", gate.team.ID, "chatId", chatID, "error", err)
		unavailable()
		return
	}
	botIn, err := checks.PlatformBotInChat(ctx, token, chatID)
	if err != nil {
		unavailable()
		return
	}
	if !botIn {
		// platformAppId lets the client pull the platform bot in itself.
		writeJSONNoStore(w, http.StatusForbidden, platformBotNotInChat{
			Error: "platform_bot_not_in_chat", PlatformAppID: a.Config.FeishuAppID, PlatformAppName: a.Config.PlatformAppName,
		})
		return
	}
	ownerIn, err := checks.UserInChat(ctx, token, chatID, principal.UnionID)
	if err != nil {
		unavailable()
		return
	}
	if !ownerIn {
		writeJSONNoStore(w, http.StatusForbidden, map[string]any{"error": "requester_not_in_chat"})
		return
	}
	// Only an actual member write consumes the window.
	a.machineGroupThrottle().arm(principal.MachineID, gate.now)
	// Best effort like addBotsToChat/addUsersToChat: refused IDs are
	// reported, the request itself still succeeds.
	invalidBots, invalidOwners := appIDs, ownerUnionIDs
	if a.Feishu != nil {
		invalidBots, _ = a.Feishu.AddBotsToChat(ctx, token, chatID, appIDs)
		invalidOwners, _ = a.Feishu.AddUsersToChat(ctx, token, chatID, ownerUnionIDs)
	}
	if a.TeamSync != nil {
		teamID := gate.team.ID
		go func() {
			ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
			defer cancel()
			if err := a.TeamSync.PushToMembers(ctx, teamID); err != nil {
				slog.Warn("machine group members: team-sync push failed", "teamId", teamID, "chatId", chatID, "error", err)
			}
		}()
	}
	slog.Info("team-agents members added", "byUnionId", principal.UnionID, "byMachineId", principal.MachineID,
		"teamId", gate.team.ID, "chatId", chatID, "bots", len(appIDs), "owners", len(ownerUnionIDs),
		"invalidBots", len(invalidBots), "invalidOwners", len(invalidOwners))
	writeJSONNoStore(w, http.StatusOK, machineGroupMembersAdded{
		OK: true, ChatID: chatID, InvalidBotIDs: nonNilStrings(invalidBots), InvalidOwnerUnionIDs: nonNilStrings(invalidOwners),
	})
}

type platformBotNotInChat struct {
	Error           string `json:"error"`
	PlatformAppID   string `json:"platformAppId"`
	PlatformAppName string `json:"platformAppName,omitempty"`
}

var errMachineGroupFeishuMissing = errors.New("feishu client not wired")

func (a *Apex) chatMembershipChecks() ChatMembershipChecks {
	checks := a.MachineGroups.Checks
	client := a.Feishu
	if checks.GetToken == nil {
		checks.GetToken = func(ctx context.Context) (string, error) {
			if client == nil {
				return "", errMachineGroupFeishuMissing
			}
			return client.TenantAccessToken(ctx)
		}
	}
	if checks.PlatformBotInChat == nil {
		checks.PlatformBotInChat = func(ctx context.Context, token, chatID string) (bool, error) {
			if client == nil {
				return false, errMachineGroupFeishuMissing
			}
			return client.IsPlatformBotInChat(ctx, token, chatID)
		}
	}
	if checks.UserInChat == nil {
		checks.UserInChat = func(ctx context.Context, token, chatID, unionID string) (bool, error) {
			if client == nil {
				return false, errMachineGroupFeishuMissing
			}
			return client.IsUserInChat(ctx, token, chatID, unionID)
		}
	}
	return checks
}

// groupCreateErrorText renders createGroupAsPlatform's `error` string: the
// not-configured code and the chat-creation failure are returned verbatim,
// while a thrown tenant-token failure arrives as String(e) ("Error: <msg>",
// or undici's "TypeError: fetch failed" for a transport error).
func groupCreateErrorText(err error) string {
	if errors.Is(err, feishu.ErrFeishuNotConfigured) {
		return err.Error()
	}
	var apiErr *feishu.APIError
	if errors.As(err, &apiErr) {
		if strings.HasPrefix(apiErr.Error(), "建群失败 ") {
			return apiErr.Error()
		}
		return "Error: " + apiErr.Error()
	}
	var httpErr *feishu.HTTPError
	if errors.As(err, &httpErr) {
		// postJson's res.json() on a non-JSON body throws a SyntaxError
		// whose text depends on V8; keep the class name at least.
		return "SyntaxError: " + httpErr.Error()
	}
	return "TypeError: fetch failed"
}

func nonNilStrings(values []string) []string {
	if values == nil {
		return []string{}
	}
	return values
}
