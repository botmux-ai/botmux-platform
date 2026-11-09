package server

import (
	"context"
	"errors"
	"log/slog"
	"net/http"
	"strings"
	"time"

	"github.com/botmux-ai/botmux-platform/internal/auth"
	"github.com/botmux-ai/botmux-platform/internal/feishu"
	"github.com/botmux-ai/botmux-platform/internal/store"
)

// createGroup has the platform bot create a Feishu group and pull in the
// selected bots plus the related people (no daemon tunnel involved). The
// platform app is visible to everyone, so adding people is not limited by an
// app's availability range; bots only need their app enabled, and offline
// machines' bots can join too.
func (a *Apex) createGroup(w http.ResponseWriter, r *http.Request, session *auth.SessionPayload, sessionErr error) {
	if !requireSession(w, sessionErr) {
		return
	}
	body := readJSONObject(r)
	larkAppIDs := uniqueStrings(body["larkAppIds"])
	if len(larkAppIDs) == 0 {
		writeJSON(w, http.StatusBadRequest, apexError{Error: "larkAppIds_required"})
		return
	}
	// Ownership: a pullable bot is any bot on the caller's own machines plus
	// the bots in team.bots of the caller's teams (added by their owner). It
	// must not widen to "any bot of a teammate": being in a team is not
	// authorizing every bot to it. This also yields the bot -> owner map.
	ownerByApp := map[string]string{}
	machines, err := a.machinesForUser(r.Context(), session.UnionID)
	if err != nil {
		writeJSON(w, http.StatusServiceUnavailable, apexError{Error: "store_unavailable"})
		return
	}
	for _, machine := range machines {
		for _, bot := range machine.Bots {
			if _, ok := ownerByApp[bot.AppID]; !ok {
				ownerByApp[bot.AppID] = session.UnionID
			}
		}
	}
	requested := make(map[string]bool, len(larkAppIDs))
	for _, appID := range larkAppIDs {
		requested[appID] = true
	}
	// An unavailable team store continues as "no teams", like TS: the
	// caller's own bots can still be grouped; this only narrows what may be
	// pulled in.
	teams, err := a.Repository.ListTeamsForUser(r.Context(), session.UnionID)
	if err != nil {
		teams = nil
	}
	type machineInfo struct {
		owner  string
		appIDs map[string]bool
	}
	infoCache := map[string]*machineInfo{}
	for _, team := range teams {
		for _, ref := range team.Bots {
			if _, owned := ownerByApp[ref.AppID]; !requested[ref.AppID] || owned {
				continue
			}
			info, cached := infoCache[ref.MachineID]
			if !cached {
				doc, getErr := a.Repository.GetMachine(r.Context(), ref.MachineID)
				if getErr != nil && !errors.Is(getErr, store.ErrNotFound) {
					// TS folds a degraded read into "no document" and trusts the
					// pod-local registry; ownership is authority, so fail closed.
					writeJSON(w, http.StatusServiceUnavailable, apexError{Error: "store_unavailable"})
					return
				}
				live, onlineHere := a.Registry.Get(ref.MachineID)
				// `doc?.unionId ?? live?.unionId` and `live?.bots ?? doc?.bots`.
				owner := ""
				if getErr == nil {
					owner = doc.UnionID
				} else if onlineHere {
					owner = live.UnionID
				}
				appIDs := map[string]bool{}
				if onlineHere {
					for _, bot := range live.Bots {
						appIDs[bot.AppID] = true
					}
				} else if getErr == nil {
					for _, bot := range doc.Bots {
						appIDs[bot.AppID] = true
					}
				}
				if owner != "" {
					info = &machineInfo{owner: owner, appIDs: appIDs}
				}
				infoCache[ref.MachineID] = info
			}
			// Orphan references are refused: the machine changed owner, the
			// owner left the team, or the bot left the machine.
			if info != nil && contains(team.Members, info.owner) && info.appIDs[ref.AppID] {
				ownerByApp[ref.AppID] = info.owner
			}
		}
	}
	unknown := make([]string, 0)
	for _, appID := range larkAppIDs {
		if _, ok := ownerByApp[appID]; !ok {
			unknown = append(unknown, appID)
		}
	}
	if len(unknown) > 0 {
		writeJSON(w, http.StatusForbidden, forbiddenBotsResponse{Error: "unknown_or_forbidden_bot", AppIDs: unknown})
		return
	}
	// Extra people (not bot owners) must be full members of one of the
	// caller's teams (team.members, which excludes pending invitees who are
	// not in the tenant yet). Invalid entries are ignored, not an error.
	teamMembers := map[string]bool{}
	for _, team := range teams {
		for _, member := range team.Members {
			teamMembers[member] = true
		}
	}
	members := []string{session.UnionID}
	for _, appID := range larkAppIDs {
		members = append(members, ownerByApp[appID])
	}
	extras, _ := body["extraUnionIds"].([]any)
	for _, value := range extras {
		if member, ok := value.(string); ok && member != "" && teamMembers[member] {
			members = append(members, member)
		}
	}
	members = unique(members)
	// `name: body?.name` goes to Feishu untouched (an empty name is omitted).
	name, _ := body["name"].(string)
	if a.Feishu == nil {
		writeJSON(w, http.StatusBadGateway, groupFailedResponse{OK: false, Error: feishu.ErrFeishuNotConfigured.Error()})
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), 30*time.Second)
	defer cancel()
	result, err := a.Feishu.CreateGroup(ctx, feishu.GroupCreateOptions{Name: name, RequesterUnionID: session.UnionID, MemberUnionIDs: members, BotAppIDs: larkAppIDs})
	if err != nil {
		writeJSON(w, http.StatusBadGateway, groupFailedResponse{OK: false, Error: createGroupErrorText(err)})
		return
	}
	// A platform-created group joins the group list of every team whose bots
	// it contains, so team-sync mirrors it as a trusted team chat on member
	// machines; the push closes the create-then-mention race. Not blocking.
	if result.ChatID != "" {
		covered := make([]string, 0)
		for _, team := range teams {
			for _, ref := range team.Bots {
				if requested[ref.AppID] {
					covered = append(covered, team.ID)
					break
				}
			}
		}
		go func(chatID string, teamIDs []string) {
			ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
			defer cancel()
			for _, teamID := range teamIDs {
				if err := a.Repository.AddTeamGroupChat(ctx, teamID, chatID); err != nil {
					slog.Warn("record team group chat", "teamId", teamID, "chatId", chatID, "error", err)
				}
				if a.TeamSync != nil {
					_ = a.TeamSync.PushToMembers(ctx, teamID)
				}
			}
		}(result.ChatID, covered)
	}
	invalidBotIDs := result.InvalidBotIDs
	if invalidBotIDs == nil {
		invalidBotIDs = []string{}
	}
	invalidUnionIDs := result.InvalidUnionIDs
	if invalidUnionIDs == nil {
		invalidUnionIDs = []string{}
	}
	writeJSON(w, http.StatusOK, groupCreatedResponse{
		OK: true, ChatID: result.ChatID, ShareLink: result.ShareLink,
		InvalidBotIDs: invalidBotIDs, InvalidOwnerUnionIDs: invalidUnionIDs,
		// The caller was not pulled in (should not happen): the UI asks them
		// to join by hand.
		AutoInviteUnavailable: contains(invalidUnionIDs, session.UnionID),
	})
}

// createGroupErrorText reproduces createGroupAsPlatform's `error`: its own
// results (feishu_not_configured, `建群失败 code=...`) are plain strings, a
// thrown tenant-token failure is String(e) with the "Error: " prefix.
func createGroupErrorText(err error) string {
	if errors.Is(err, feishu.ErrFeishuNotConfigured) || strings.HasPrefix(err.Error(), "建群失败") {
		return err.Error()
	}
	return "Error: " + err.Error()
}

// uniqueStrings is `Array.from(new Set(arr.filter(x => typeof x ===
// 'string' && x)))` for an array value, or empty for anything else.
func uniqueStrings(value any) []string {
	items, _ := value.([]any)
	values := make([]string, 0, len(items))
	for _, item := range items {
		if text, ok := item.(string); ok {
			values = append(values, text)
		}
	}
	return unique(values)
}

func (a *Apex) searchUsers(w http.ResponseWriter, r *http.Request, session *auth.SessionPayload, sessionErr error) {
	if !requireSession(w, sessionErr) {
		return
	}
	// `!!cfg.feishuAppId`, not "fully configured": the field tells the UI
	// whether people search exists on this deployment at all.
	configured := a.Config.FeishuAppID != ""
	query := trimJS(queryParamJS(r.URL.RawQuery, "q"))
	if query == "" {
		writeJSON(w, http.StatusOK, userSearchResponse{Users: []feishu.TenantUser{}, Configured: configured})
		return
	}
	// A normal login no longer requests the search scope (no "search users"
	// consent screen). Only a real search asks for it once: without ss (basic
	// login or legacy session) the UI goes to /auth/login?scope=search
	// instead of running a doomed search.
	if !session.SearchScope || session.UserToken == nil || session.UserToken.AccessToken == "" {
		writeJSON(w, http.StatusOK, userSearchResponse{Users: []feishu.TenantUser{}, Configured: configured, NeedScope: true})
		return
	}
	if a.Feishu == nil {
		writeJSON(w, http.StatusOK, userSearchResponse{Users: []feishu.TenantUser{}, Configured: true, Error: "Error: " + feishu.ErrFeishuNotConfigured.Error()})
		return
	}
	token := *session.UserToken
	setCookie := ""
	refresh := func() bool {
		ctx, cancel := context.WithTimeout(r.Context(), 12*time.Second)
		defer cancel()
		fresh, err := a.Feishu.RefreshUserToken(ctx, token.RefreshToken)
		if err != nil {
			return false
		}
		token = auth.SessionUserToken{AccessToken: fresh.AccessToken, RefreshToken: fresh.RefreshToken, ExpiresAt: fresh.ExpiresAt}
		// Renew, never re-mint: a background refresh must not reset authTime.
		setCookie = auth.SessionCookieHeader(a.Config, auth.RenewSessionUserToken(a.Config, session, token))
		return true
	}
	// Expiring or expired: refresh first. Without a refresh token the stale
	// access token is still tried, as in TS.
	if token.ExpiresAt < time.Now().Unix()+30 && token.RefreshToken != "" && !refresh() {
		writeJSON(w, http.StatusOK, userSearchResponse{Users: []feishu.TenantUser{}, Configured: true, Reauth: true})
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), 12*time.Second)
	users, err := a.Feishu.SearchUsers(ctx, query, token.AccessToken)
	cancel()
	// Invalid before its declared expiry: refresh and retry once.
	if errors.Is(err, feishu.ErrTokenInvalid) && token.RefreshToken != "" && refresh() {
		ctx, cancel = context.WithTimeout(r.Context(), 12*time.Second)
		users, err = a.Feishu.SearchUsers(ctx, query, token.AccessToken)
		cancel()
	}
	if setCookie != "" {
		w.Header().Add("Set-Cookie", setCookie)
	}
	if errors.Is(err, feishu.ErrTokenInvalid) {
		writeJSON(w, http.StatusOK, userSearchResponse{Users: []feishu.TenantUser{}, Configured: true, Reauth: true})
		return
	}
	if err != nil {
		writeJSON(w, http.StatusOK, userSearchResponse{Users: []feishu.TenantUser{}, Configured: true, Error: searchErrorText(err)})
		return
	}
	if users == nil {
		users = []feishu.TenantUser{}
	}
	writeJSON(w, http.StatusOK, userSearchResponse{Users: users, Configured: true})
}

// searchErrorText: a Feishu business error is the plain `feishu code=...`
// result; a thrown failure is String(e). Node's own transport errors
// ("TypeError: fetch failed") have no Go equivalent, so they read
// "Error: <go error>".
func searchErrorText(err error) string {
	var apiErr *feishu.APIError
	if errors.As(err, &apiErr) && strings.HasPrefix(err.Error(), "feishu code=") {
		return err.Error()
	}
	return "Error: " + err.Error()
}

func unique(values []string) []string {
	seen := map[string]bool{}
	out := make([]string, 0, len(values))
	for _, value := range values {
		if value != "" && !seen[value] {
			seen[value] = true
			out = append(out, value)
		}
	}
	return out
}

type forbiddenBotsResponse struct {
	Error  string   `json:"error"`
	AppIDs []string `json:"appIds"`
}

type groupFailedResponse struct {
	OK    bool   `json:"ok"`
	Error string `json:"error"`
}

// groupCreatedResponse: shareLink is undefined (omitted) when Feishu did not
// produce one.
type groupCreatedResponse struct {
	OK                    bool     `json:"ok"`
	ChatID                string   `json:"chatId"`
	ShareLink             string   `json:"shareLink,omitempty"`
	InvalidBotIDs         []string `json:"invalidBotIds"`
	InvalidOwnerUnionIDs  []string `json:"invalidOwnerUnionIds"`
	AutoInviteUnavailable bool     `json:"autoInviteUnavailable"`
}

// userSearchResponse covers every /api/users/search shape; each branch sets
// at most one of reauth / error / needScope after users and configured.
type userSearchResponse struct {
	Users      []feishu.TenantUser `json:"users"`
	Configured bool                `json:"configured"`
	Reauth     bool                `json:"reauth,omitempty"`
	Error      string              `json:"error,omitempty"`
	NeedScope  bool                `json:"needScope,omitempty"`
}
