package server

import (
	"context"
	"errors"
	"log/slog"
	"net/http"
	"regexp"
	"strings"
	"sync"
	"time"

	"github.com/botmux-ai/botmux-platform/internal/auth"
	"github.com/botmux-ai/botmux-platform/internal/feishu"
	"github.com/botmux-ai/botmux-platform/internal/store"
	"github.com/botmux-ai/botmux-platform/internal/tunnel"
)

// Teams are person-level: members are people (stored in MongoDB), machines
// join through their owners. /api/teams/:id/issue-settings and /admins live
// in the issue board module.
func (a *Apex) handleTeamEndpoints(w http.ResponseWriter, r *http.Request, session *auth.SessionPayload, sessionErr error) bool {
	path := r.URL.Path
	if path == "/api/teams" && r.Method == http.MethodGet {
		if !requireSession(w, sessionErr) {
			return true
		}
		docs, err := a.Repository.ListTeamsForUser(r.Context(), session.UnionID)
		if err != nil {
			writeJSON(w, http.StatusServiceUnavailable, apexError{Error: "store_unavailable"})
			return true
		}
		teams := make([]teamListEntry, 0, len(docs))
		for _, team := range docs {
			admins := team.Admins
			if admins == nil {
				admins = []string{}
			}
			// hallChatId lets the UI show the hall state: the hall is a
			// bot-only chat, so people cannot see it otherwise.
			// repoPresetCount is a light hint for issue creation; the full
			// form is served by issue-settings.
			teams = append(teams, teamListEntry{TeamID: team.ID, TeamName: team.Name, CreatedBy: team.CreatedBy, HallChatID: team.HallChatID, Admins: admins, RepoPresetCount: len(team.RepoPresets)})
		}
		writeJSON(w, http.StatusOK, teamListResponse{Teams: teams})
		return true
	}
	if path == "/api/teams" && r.Method == http.MethodPost {
		if !requireSession(w, sessionErr) {
			return true
		}
		name := teamNameFromBody(r)
		if name == "" {
			writeJSON(w, http.StatusBadRequest, apexError{Error: "name_required"})
			return true
		}
		teamID := randomID(8)
		// People join without an online machine. A failed write must be an
		// error: a team that only lived in memory would vanish on deploy.
		err := a.Repository.CreateTeam(r.Context(), store.TeamDoc{ID: teamID, Name: name, Members: []string{session.UnionID}, CreatedBy: session.UnionID, CreatedAt: time.Now().UnixMilli()})
		if err != nil {
			writeJSON(w, http.StatusServiceUnavailable, apexError{Error: "store_unavailable"})
			return true
		}
		// Creating a team brings up its bot hall (empty chats too; bots are
		// pulled in as they join). Not blocking: heartbeat aggregation
		// repairs a failure.
		a.syncHallAsync(teamID, nil, nil, false)
		writeJSON(w, http.StatusOK, teamRef{TeamID: teamID, TeamName: name})
		return true
	}
	if match := deleteTeamPattern.FindStringSubmatch(path); match != nil && r.Method == http.MethodDelete {
		if !requireSession(w, sessionErr) {
			return true
		}
		teamID := match[1]
		team, ok := a.getTeamOr(w, r, teamID, http.StatusNotFound, "team_not_found")
		if !ok {
			return true
		}
		if team.CreatedBy != session.UnionID {
			writeJSON(w, http.StatusForbidden, apexError{Error: "not_creator"})
			return true
		}
		// The team document is the authoritative action and is refused while
		// degraded; the cleanup after it is best effort.
		if err := a.Repository.DeleteTeam(r.Context(), teamID); err != nil {
			writeJSON(w, http.StatusServiceUnavailable, apexError{Error: "store_unavailable"})
			return true
		}
		a.invalidateTeamSync(teamID)
		a.afterTeamDeleted(team, session)
		slog.Info("team deleted", "teamId", teamID, "by", session.UnionID, "members", len(team.Members))
		writeJSON(w, http.StatusOK, okResponse{OK: true})
		return true
	}
	if match := renameTeamPattern.FindStringSubmatch(path); match != nil && r.Method == http.MethodPost {
		if !requireSession(w, sessionErr) {
			return true
		}
		teamID := match[1]
		name := teamNameFromBody(r)
		if name == "" {
			writeJSON(w, http.StatusBadRequest, apexError{Error: "name_required"})
			return true
		}
		team, ok := a.getTeamOr(w, r, teamID, http.StatusNotFound, "team_not_found")
		if !ok {
			return true
		}
		if team.CreatedBy != session.UnionID {
			writeJSON(w, http.StatusForbidden, apexError{Error: "not_creator"})
			return true
		}
		if err := a.Repository.RenameTeam(r.Context(), teamID, name); err != nil {
			writeJSON(w, http.StatusServiceUnavailable, apexError{Error: "store_unavailable"})
			return true
		}
		a.invalidateTeamSync(teamID)
		// The hall name follows best effort; member machines pick up the new
		// name from the next heartbeat's team-sync revision.
		if team.HallChatID != "" && a.Feishu != nil {
			go func(chatID string) {
				ctx, cancel := context.WithTimeout(context.Background(), 12*time.Second)
				defer cancel()
				token, err := a.Feishu.TenantAccessToken(ctx)
				if err == nil {
					err = a.Feishu.RenameChat(ctx, token, chatID, feishu.HallGroupName(name))
				}
				if err != nil {
					slog.Warn("rename team hall", "teamId", teamID, "error", err)
				}
			}(team.HallChatID)
		}
		writeJSON(w, http.StatusOK, renameTeamResponse{OK: true, TeamName: name})
		return true
	}
	if match := leaveTeamPattern.FindStringSubmatch(path); match != nil && r.Method == http.MethodPost {
		if !requireSession(w, sessionErr) {
			return true
		}
		a.leaveTeam(w, r, session, match[1])
		return true
	}
	if match := hallJoinPattern.FindStringSubmatch(path); match != nil && r.Method == http.MethodPost {
		if !requireSession(w, sessionErr) {
			return true
		}
		// Hidden entry: the hall is bot-only by default and pulls no people
		// in; members who want to watch join themselves by union_id.
		team, ok := a.getTeamMember(w, r, match[1], session.UnionID)
		if !ok {
			return true
		}
		if team.HallChatID == "" {
			writeJSON(w, http.StatusConflict, apexError{Error: "hall_not_ready"})
			return true
		}
		if a.Feishu == nil {
			writeJSON(w, http.StatusBadGateway, joinFailedResponse{Error: "join_failed", Detail: "Error: feishu_not_configured"})
			return true
		}
		ctx, cancel := context.WithTimeout(r.Context(), 12*time.Second)
		defer cancel()
		token, err := a.Feishu.TenantAccessToken(ctx)
		if err != nil {
			// String(e) of the thrown token error.
			writeJSON(w, http.StatusBadGateway, joinFailedResponse{Error: "join_failed", Detail: "Error: " + err.Error()})
			return true
		}
		invalid, err := a.Feishu.AddUsersToChat(ctx, token, team.HallChatID, []string{session.UnionID})
		if err != nil {
			writeJSON(w, http.StatusBadGateway, joinFailedResponse{Error: "join_failed", Detail: "Error: " + err.Error()})
			return true
		}
		if len(invalid) > 0 {
			writeJSON(w, http.StatusBadGateway, apexError{Error: "join_failed"})
			return true
		}
		writeJSON(w, http.StatusOK, hallJoinResponse{OK: true, ChatID: team.HallChatID})
		return true
	}
	if match := inviteTeamPattern.FindStringSubmatch(path); match != nil && r.Method == http.MethodPost {
		if !requireSession(w, sessionErr) {
			return true
		}
		team, ok := a.getTeamMember(w, r, match[1], session.UnionID)
		if !ok {
			return true
		}
		invite := a.issueTeamInvite(team, session)
		// A directly clickable link: opening it joins (log in first; next
		// brings the user back to finish joining).
		writeJSON(w, http.StatusOK, inviteResponse{InviteURL: a.inviteURL(invite), Invite: invite, TeamName: team.Name})
		return true
	}
	if match := inviteUserPattern.FindStringSubmatch(path); match != nil && r.Method == http.MethodPost {
		if !requireSession(w, sessionErr) {
			return true
		}
		a.inviteUser(w, r, session, match[1])
		return true
	}
	if path == "/api/teams/accept" && r.Method == http.MethodPost {
		if !requireSession(w, sessionErr) {
			return true
		}
		a.acceptInvite(w, r, session)
		return true
	}
	if match := rosterPattern.FindStringSubmatch(path); match != nil && r.Method == http.MethodGet {
		if !requireSession(w, sessionErr) {
			return true
		}
		team, ok := a.getTeamMember(w, r, match[1], session.UnionID)
		if !ok {
			return true
		}
		members, err := a.roster(r.Context(), team)
		if err != nil {
			writeJSON(w, http.StatusServiceUnavailable, apexError{Error: "store_unavailable"})
			return true
		}
		writeJSON(w, http.StatusOK, rosterResponse{TeamID: team.ID, TeamName: team.Name, Members: members})
		return true
	}
	if match := teamBotsPattern.FindStringSubmatch(path); match != nil && r.Method == http.MethodPost {
		if !requireSession(w, sessionErr) {
			return true
		}
		a.updateTeamBots(w, r, session, match[1])
		return true
	}
	return false
}

// teamNameFromBody is `(body?.name || "").trim().slice(0, 64)`.
func teamNameFromBody(r *http.Request) string {
	name, _ := readJSONObject(r)["name"].(string)
	return truncate(trimJS(name), 64)
}

// getTeamOr reads the team; a missing team answers status/code. Unlike the
// TS getTeamDoc (which folds a degraded store into null), a store failure is
// a 503 so an outage never reads as "no such team" / "not a member".
func (a *Apex) getTeamOr(w http.ResponseWriter, r *http.Request, teamID string, status int, code string) (store.TeamDoc, bool) {
	team, err := a.Repository.GetTeam(r.Context(), teamID)
	if errors.Is(err, store.ErrNotFound) {
		writeJSON(w, status, apexError{Error: code})
		return store.TeamDoc{}, false
	}
	if err != nil {
		writeJSON(w, http.StatusServiceUnavailable, apexError{Error: "store_unavailable"})
		return store.TeamDoc{}, false
	}
	return team, true
}

// getTeamMember requires the caller to be a member (403 not_in_team).
func (a *Apex) getTeamMember(w http.ResponseWriter, r *http.Request, teamID, unionID string) (store.TeamDoc, bool) {
	team, ok := a.getTeamOr(w, r, teamID, http.StatusForbidden, "not_in_team")
	if !ok {
		return store.TeamDoc{}, false
	}
	if !contains(team.Members, unionID) {
		writeJSON(w, http.StatusForbidden, apexError{Error: "not_in_team"})
		return store.TeamDoc{}, false
	}
	return team, true
}

func (a *Apex) issueTeamInvite(team store.TeamDoc, session *auth.SessionPayload) string {
	invite, _ := auth.IssueTeamInvite(a.Config, auth.TeamInvitePayload{TeamID: team.ID, TeamName: team.Name, InviterUnionID: session.UnionID, InviterName: session.Name, InviterOpenID: session.OpenID})
	return invite
}

func (a *Apex) inviteURL(invite string) string {
	return a.Config.PublicBaseURL + "/?invite=" + encodeURIComponentJS(invite)
}

// leaveTeam follows the TS route, with two Go fail-closed rules kept from the
// earlier port: an authority read failure answers 503 before any mutation,
// and the leaver's bots are removed before the membership so a failure never
// strands bots owned by someone who already left.
func (a *Apex) leaveTeam(w http.ResponseWriter, r *http.Request, session *auth.SessionPayload, teamID string) {
	team, err := a.Repository.GetTeam(r.Context(), teamID)
	if err != nil && !errors.Is(err, store.ErrNotFound) {
		writeJSON(w, http.StatusServiceUnavailable, apexError{Error: "store_unavailable"})
		return
	}
	// The creator cannot leave: createdBy is the only holder of the disband
	// right, so leaving would make the team undeletable forever (the UI hides
	// "leave" for the creator; this is the backstop for direct API calls).
	if err == nil && team.CreatedBy == session.UnionID {
		writeJSON(w, http.StatusForbidden, apexError{Error: "creator_cannot_leave"})
		return
	}
	// A missing team still runs the cleanup below and answers ok, as TS does:
	// grants made via a deleted team must not outlive it.
	mine, err := a.machinesForUser(r.Context(), session.UnionID)
	if err != nil {
		writeJSON(w, http.StatusServiceUnavailable, apexError{Error: "store_unavailable"})
		return
	}
	ids := make([]string, 0, len(mine))
	for _, machine := range mine {
		ids = append(ids, machine.MachineID)
	}
	// Bots can only be added or removed by their owner, so nobody could
	// clean them up after the owner left.
	if err := a.Repository.RemoveUserBotsFromTeam(r.Context(), teamID, ids); err != nil && !errors.Is(err, store.ErrNotFound) {
		writeJSON(w, http.StatusServiceUnavailable, apexError{Error: "store_unavailable"})
		return
	}
	if err := a.Repository.RemoveTeamMember(r.Context(), teamID, session.UnionID); err != nil && !errors.Is(err, store.ErrNotFound) {
		writeJSON(w, http.StatusServiceUnavailable, apexError{Error: "store_unavailable"})
		return
	}
	// Leaving drops the co-manager grants this team justified on other
	// members' machines. teams and machines are separate collections, so
	// this is best effort; a missed grant shows up as leftTeam to the owner.
	dropped, dropErr := a.Repository.DropCoManagerFromTeamMachines(r.Context(), teamID, session.UnionID)
	if dropErr != nil {
		slog.Warn("drop co-manager grants on leave", "teamId", teamID, "unionId", session.UnionID, "error", dropErr)
	}
	if len(dropped) > 0 {
		slog.Info("dropped co-manager grants on leave", "teamId", teamID, "unionId", session.UnionID, "machines", dropped)
	}
	// Roster changed: push now (the leaver's machines lose the team, the
	// others get a narrower roster); the next heartbeat repairs a failure.
	a.pushTeamSyncAsync(teamID)
	writeJSON(w, http.StatusOK, okResponse{OK: true})
}

// inviteUser sends an invite card to an open_id found via people search
// (DM from the platform bot).
func (a *Apex) inviteUser(w http.ResponseWriter, r *http.Request, session *auth.SessionPayload, teamID string) {
	team, ok := a.getTeamMember(w, r, teamID, session.UnionID)
	if !ok {
		return
	}
	body := readJSONObject(r)
	openID, _ := body["openId"].(string)
	if openID == "" {
		writeJSON(w, http.StatusBadRequest, apexError{Error: "openId_required"})
		return
	}
	invite := a.issueTeamInvite(team, session)
	if a.Feishu == nil {
		writeJSON(w, http.StatusBadGateway, sendFailedResponse{Error: "send_failed", Detail: feishu.ErrFeishuNotConfigured.Error()})
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), 12*time.Second)
	defer cancel()
	err := a.Feishu.SendInviteDM(ctx, openID, feishu.InviteMessage{TeamName: team.Name, InviterName: session.Name, InviterOpenID: session.OpenID, InviterUnionID: session.UnionID, InviteURL: a.inviteURL(invite)})
	if err != nil {
		writeJSON(w, http.StatusBadGateway, sendFailedResponse{Error: "send_failed", Detail: inviteDMErrorText(err)})
		return
	}
	// Record "pending" (only a direct invite knows who the target is;
	// existing members are not recorded). Display only, best effort.
	targetUnionID, _ := body["unionId"].(string)
	targetUnionID = trimJS(targetUnionID)
	if targetUnionID != "" && !contains(team.Members, targetUnionID) {
		name, _ := body["name"].(string)
		_ = a.Repository.AddPendingInvite(r.Context(), team.ID, store.PendingInvite{UnionID: targetUnionID, OpenID: openID, Name: truncate(name, 64), InvitedBy: session.UnionID, InvitedAt: time.Now().UnixMilli()})
	}
	writeJSON(w, http.StatusOK, okResponse{OK: true})
}

// inviteDMErrorText reproduces sendInviteDM's `error`: its own results
// (feishu_not_configured, `feishu code=...`) are plain strings, while a thrown
// failure (tenant token, transport) is String(e) with the "Error: " prefix.
func inviteDMErrorText(err error) string {
	var apiErr *feishu.APIError
	if errors.Is(err, feishu.ErrFeishuNotConfigured) || (errors.As(err, &apiErr) && strings.HasPrefix(err.Error(), "feishu code=")) {
		return err.Error()
	}
	return "Error: " + err.Error()
}

func (a *Apex) acceptInvite(w http.ResponseWriter, r *http.Request, session *auth.SessionPayload) {
	invite, _ := readJSONObject(r)["invite"].(string)
	payload, err := auth.VerifyTeamInvite(a.Config, invite)
	if err != nil || payload == nil {
		writeJSON(w, http.StatusBadRequest, apexError{Error: "invalid_or_expired_invite"})
		return
	}
	if err := a.Repository.AddTeamMember(r.Context(), payload.TeamID, session.UnionID); err != nil {
		if errors.Is(err, store.ErrNotFound) {
			writeJSON(w, http.StatusNotFound, apexError{Error: "team_not_found"})
		} else {
			writeJSON(w, http.StatusServiceUnavailable, apexError{Error: "store_unavailable"})
		}
		return
	}
	// Pending -> member; then push team-sync so the new member's union_id
	// reaches every member machine (no grant needed in team chats) and the
	// new member's own machines get the full roster.
	_ = a.Repository.RemovePendingInvite(r.Context(), payload.TeamID, session.UnionID)
	a.pushTeamSyncAsync(payload.TeamID)
	if payload.InviterUnionID != "" && payload.InviterUnionID != session.UnionID && a.Feishu != nil {
		go func() {
			ctx, cancel := context.WithTimeout(context.Background(), 12*time.Second)
			defer cancel()
			_ = a.Feishu.SendTeamJoinedDM(ctx, payload.InviterUnionID, feishu.TeamJoinedMessage{JoinerName: first(session.Name, "新成员"), JoinerOpenID: session.OpenID, JoinerUnionID: session.UnionID, TeamName: payload.TeamName, InviterOpenID: payload.InviterOpenID})
		}()
	}
	writeJSON(w, http.StatusOK, teamRef{TeamID: payload.TeamID, TeamName: payload.TeamName})
}

// updateTeamBots adds/removes bots of the team's selected list. Only bots on
// the caller's own machines: whether a bot joins a team is its owner's call,
// never another member's (team admins included).
func (a *Apex) updateTeamBots(w http.ResponseWriter, r *http.Request, session *auth.SessionPayload, teamID string) {
	if _, ok := a.getTeamMember(w, r, teamID, session.UnionID); !ok {
		return
	}
	body := readJSONObject(r)
	add, remove := parseTeamBotRefs(body["add"]), parseTeamBotRefs(body["remove"])
	if len(add) == 0 && len(remove) == 0 {
		writeJSON(w, http.StatusBadRequest, apexError{Error: "no_changes"})
		return
	}
	machines, err := a.machinesForUser(r.Context(), session.UnionID)
	if err != nil {
		writeJSON(w, http.StatusServiceUnavailable, apexError{Error: "store_unavailable"})
		return
	}
	mine := map[string]bool{}
	for _, machine := range machines {
		mine[machine.MachineID] = true
	}
	// Ownership gate: one foreign bot refuses the whole request.
	for _, ref := range append(append([]store.TeamBotRef(nil), add...), remove...) {
		if !mine[ref.MachineID] {
			writeJSON(w, http.StatusForbidden, apexError{Error: "not_machine_owner"})
			return
		}
	}
	if err := a.Repository.UpdateTeamBots(r.Context(), teamID, add, remove); err != nil {
		if errors.Is(err, store.ErrNotFound) {
			writeJSON(w, http.StatusNotFound, apexError{Error: "team_not_found"})
		} else {
			writeJSON(w, http.StatusServiceUnavailable, apexError{Error: "store_unavailable"})
		}
		return
	}
	adds, removes := make([]string, 0, len(add)), make([]string, 0, len(remove))
	for _, ref := range add {
		adds = append(adds, ref.AppID)
	}
	for _, ref := range remove {
		removes = append(removes, ref.AppID)
	}
	// Hall upkeep (not blocking): create a missing hall, rebuild a disbanded
	// one when adding, best-effort removal; then push the new roster now
	// instead of waiting for the heartbeat.
	a.syncHallAsync(teamID, adds, removes, true)
	writeJSON(w, http.StatusOK, okResponse{OK: true})
}

// parseTeamBotRefs keeps {machineId, appId} entries with a hex machine id
// and a non-empty appId string. No dedupe: the store's $addToSet/$pull make
// duplicates harmless, as in TS.
func parseTeamBotRefs(value any) []store.TeamBotRef {
	items, _ := value.([]any)
	out := make([]store.TeamBotRef, 0, len(items))
	for _, item := range items {
		object, _ := item.(map[string]any)
		machineID, _ := object["machineId"].(string)
		appID, _ := object["appId"].(string)
		if machineIDPattern.MatchString(machineID) && appID != "" {
			out = append(out, store.TeamBotRef{MachineID: machineID, AppID: appID})
		}
	}
	return out
}

// pendingInviteTTL matches the 30-day invite token: a pending entry past it
// would be misleading.
const pendingInviteTTL = 30 * 24 * time.Hour

// roster is the person-level team roster: member -> profile -> every machine
// of that member (offline / other pods included). Pending invitees follow the
// members, without machines.
func (a *Apex) roster(ctx context.Context, team store.TeamDoc) ([]rosterMember, error) {
	// Valid pending = not expired and not already a member (defensive: accept
	// already removes it).
	cutoff := time.Now().Add(-pendingInviteTTL).UnixMilli()
	pending := make([]store.PendingInvite, 0)
	for _, invite := range team.PendingInvites {
		if invite.InvitedAt >= cutoff && !contains(team.Members, invite.UnionID) {
			pending = append(pending, invite)
		}
	}
	// Physically prune expired / already-member entries (self-healing, best
	// effort).
	if len(pending) != len(team.PendingInvites) {
		go func() {
			c, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			defer cancel()
			_ = a.Repository.PrunePendingInvites(c, team.ID, cutoff, team.Members)
		}()
	}
	ids := append([]string(nil), team.Members...)
	for _, invite := range pending {
		ids = append(ids, invite.UnionID)
	}
	// Profiles are display only; like the TS getUserProfiles a failed read
	// degrades to unionId-prefix names.
	profiles, err := a.Repository.GetUserProfiles(ctx, ids)
	if err != nil {
		profiles = nil
	}
	teamBots := map[string]bool{}
	for _, ref := range team.Bots {
		teamBots[ref.MachineID+"\x00"+ref.AppID] = true
	}
	// Preserve the TypeScript endpoint's parallel fan-out. Fetching members and
	// then each online machine serially can multiply the 2.5s bounded wait into
	// tens of seconds for an ordinary team roster.
	type memberView struct {
		unionID string
		views   []MachineView
		dirs    []map[string]BotDirConfig
	}
	memberViews := make([]memberView, len(team.Members))
	viewErrors := make([]error, len(team.Members))
	var viewsWG sync.WaitGroup
	for index, unionID := range team.Members {
		viewsWG.Add(1)
		go func(index int, unionID string) {
			defer viewsWG.Done()
			views, err := a.machinesForUser(ctx, unionID)
			viewErrors[index] = err
			memberViews[index] = memberView{unionID: unionID, views: views, dirs: make([]map[string]BotDirConfig, len(views))}
		}(index, unionID)
	}
	viewsWG.Wait()
	if err := errors.Join(viewErrors...); err != nil {
		return nil, err
	}

	// Online machines also report each bot's default-directory mode through
	// the tunnel (short cache + bounded wait). Unknown -> dirMode null: the UI
	// shows no badge and the next poll heals it.
	var dirsWG sync.WaitGroup
	if a.MachineAPI != nil {
		for memberIndex := range memberViews {
			for machineIndex := range memberViews[memberIndex].views {
				view := memberViews[memberIndex].views[machineIndex]
				if !view.Online {
					continue
				}
				dirsWG.Add(1)
				go func(memberIndex, machineIndex int, view MachineView) {
					defer dirsWG.Done()
					member := &memberViews[memberIndex]
					member.dirs[machineIndex] = a.MachineAPI.GetBotDirs(ctx, view.MachineID, member.unionID, 2500*time.Millisecond)
				}(memberIndex, machineIndex, view)
			}
		}
	}
	dirsWG.Wait()

	out := make([]rosterMember, 0, len(ids))
	for _, member := range memberViews {
		machines := make([]rosterMachine, 0, len(member.views))
		for machineIndex, view := range member.views {
			dirs := member.dirs[machineIndex]
			// Every candidate bot (not hidden daemon-side), each flagged with
			// whether it is in the team: the roster/group UI shows inTeam
			// ones, "manage bots" shows all.
			bots := make([]rosterBot, 0, len(view.Bots))
			for _, bot := range view.Bots {
				if bot.ShowInTeam != nil && !*bot.ShowInTeam {
					continue
				}
				entry := rosterBot{BotInfo: bot, InTeam: teamBots[view.MachineID+"\x00"+bot.AppID]}
				if cfg, ok := dirs[bot.AppID]; ok {
					mode := cfg.Mode
					entry.DirMode, entry.DirModeDir = &mode, cfg.WorkingDir
				}
				bots = append(bots, entry)
			}
			machines = append(machines, rosterMachine{MachineID: view.MachineID, Name: view.Name, BotmuxVersion: view.BotmuxVersion, Online: view.Online, Stale: view.Stale, Bots: bots})
		}
		profile := profiles[member.unionID]
		out = append(out, rosterMember{UnionID: member.unionID, Name: first(profile.Name, prefix(member.unionID, 12)), Avatar: profile.Avatar, Machines: machines})
	}
	for _, invite := range pending {
		profile := profiles[invite.UnionID]
		out = append(out, rosterMember{UnionID: invite.UnionID, Name: first(profile.Name, invite.Name, prefix(invite.UnionID, 12)), Avatar: profile.Avatar, Machines: []rosterMachine{}, Pending: true})
	}
	return out, nil
}

// afterTeamDeleted is the best-effort cleanup after the team document is
// gone: co-manager grants, the bot hall, live member machines and DMs.
func (a *Apex) afterTeamDeleted(team store.TeamDoc, session *auth.SessionPayload) {
	go func() {
		ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
		defer cancel()
		// Grants justified by this team lose their basis. Every member is
		// visited, the creator included: the creator may co-manage someone
		// else's machine via this team, and skipping them would leave a
		// dangling grant. The store skips machines the person owns.
		for _, member := range team.Members {
			dropped, err := a.Repository.DropCoManagerFromTeamMachines(ctx, team.ID, member)
			if err != nil {
				slog.Warn("drop co-manager grants on team delete", "teamId", team.ID, "unionId", member, "error", err)
			}
			if len(dropped) > 0 {
				slog.Info("dropped co-manager grants on team delete", "teamId", team.ID, "unionId", member, "machines", dropped)
			}
		}
		if team.HallChatID != "" && a.Feishu != nil {
			token, err := a.Feishu.TenantAccessToken(ctx)
			if err == nil {
				err = a.Feishu.DisbandChat(ctx, token, team.HallChatID)
			}
			if err != nil {
				slog.Warn("disband team hall (team deleted; an orphan chat is harmless)", "teamId", team.ID, "chatId", team.HallChatID, "error", err)
			}
		}
		// Offline machines drop the team on their next heartbeat's team-sync.
		if a.Registry != nil {
			for _, machine := range a.Registry.ListForTeam(team.ID) {
				a.Registry.SendToMachine(machine.MachineID, leaveTeamMessage{Type: "leave-team", TeamID: team.ID})
			}
		}
		if a.Feishu == nil {
			return
		}
		for _, member := range team.Members {
			if member == session.UnionID {
				continue
			}
			_ = a.Feishu.SendTeamDisbandedDM(ctx, member, feishu.TeamDisbandedMessage{TeamName: team.Name, DissolverName: session.Name, DissolverOpenID: session.OpenID, DissolverUnionID: session.UnionID})
		}
	}()
}

func (a *Apex) invalidateTeamSync(teamID string) {
	if a.TeamSync != nil {
		a.TeamSync.Invalidate(teamID)
	}
}

// syncHallAsync maintains the hall in the background; push also sends the
// new roster to member machines afterwards (team creation does not push, as
// in TS: nobody's machine is in the new team yet).
func (a *Apex) syncHallAsync(teamID string, add, remove []string, push bool) {
	if a.TeamSync == nil {
		return
	}
	go func() {
		ctx, cancel := context.WithTimeout(context.Background(), 25*time.Second)
		defer cancel()
		if err := a.TeamSync.SyncHallMembers(ctx, teamID, add, remove); err != nil {
			slog.Warn("sync hall", "teamId", teamID, "error", err)
			return
		}
		if push {
			_ = a.TeamSync.PushToMembers(ctx, teamID)
		}
	}()
}

func (a *Apex) pushTeamSyncAsync(teamID string) {
	if a.TeamSync == nil {
		return
	}
	go func() {
		ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
		defer cancel()
		_ = a.TeamSync.PushToMembers(ctx, teamID)
	}()
}

func contains(values []string, target string) bool {
	for _, value := range values {
		if value == target {
			return true
		}
	}
	return false
}

type okResponse struct {
	OK bool `json:"ok"`
}

type teamRef struct {
	TeamID   string `json:"teamId"`
	TeamName string `json:"teamName"`
}

type teamListEntry struct {
	TeamID          string   `json:"teamId"`
	TeamName        string   `json:"teamName"`
	CreatedBy       string   `json:"createdBy"`
	HallChatID      string   `json:"hallChatId,omitempty"`
	Admins          []string `json:"admins"`
	RepoPresetCount int      `json:"repoPresetCount"`
}

type teamListResponse struct {
	Teams []teamListEntry `json:"teams"`
}

type renameTeamResponse struct {
	OK       bool   `json:"ok"`
	TeamName string `json:"teamName"`
}

type hallJoinResponse struct {
	OK     bool   `json:"ok"`
	ChatID string `json:"chatId"`
}

type joinFailedResponse struct {
	Error  string `json:"error"`
	Detail string `json:"detail"`
}

type sendFailedResponse struct {
	Error  string `json:"error"`
	Detail string `json:"detail"`
}

type inviteResponse struct {
	InviteURL string `json:"inviteUrl"`
	Invite    string `json:"invite"`
	TeamName  string `json:"teamName"`
}

type rosterResponse struct {
	TeamID   string         `json:"teamId"`
	TeamName string         `json:"teamName"`
	Members  []rosterMember `json:"members"`
}

type rosterMember struct {
	UnionID  string          `json:"unionId"`
	Name     string          `json:"name"`
	Avatar   string          `json:"avatar,omitempty"`
	Machines []rosterMachine `json:"machines"`
	Pending  bool            `json:"pending,omitempty"`
}

type rosterMachine struct {
	MachineID     string      `json:"machineId"`
	Name          string      `json:"name"`
	BotmuxVersion string      `json:"botmuxVersion"`
	Online        bool        `json:"online"`
	Stale         bool        `json:"stale"`
	Bots          []rosterBot `json:"bots"`
}

// rosterBot is `{...bot, inTeam, dirMode, dirModeDir}`; the directory fields
// are null when unknown.
type rosterBot struct {
	tunnel.BotInfo
	InTeam     bool    `json:"inTeam"`
	DirMode    *string `json:"dirMode"`
	DirModeDir *string `json:"dirModeDir"`
}

type leaveTeamMessage struct {
	Type   string `json:"type"`
	TeamID string `json:"teamId"`
}

var (
	deleteTeamPattern = regexp.MustCompile(`^/api/teams/([a-f0-9]{8,64})$`)
	renameTeamPattern = regexp.MustCompile(`^/api/teams/([a-f0-9]{8,64})/rename$`)
	leaveTeamPattern  = regexp.MustCompile(`^/api/teams/([a-f0-9]{8,64})/leave$`)
	hallJoinPattern   = regexp.MustCompile(`^/api/teams/([a-f0-9]{8,64})/hall/join$`)
	inviteTeamPattern = regexp.MustCompile(`^/api/teams/([a-f0-9]{8,64})/invite$`)
	inviteUserPattern = regexp.MustCompile(`^/api/teams/([a-f0-9]{8,64})/invite-user$`)
	rosterPattern     = regexp.MustCompile(`^/api/teams/([a-f0-9]{8,64})/roster$`)
	teamBotsPattern   = regexp.MustCompile(`^/api/teams/([a-f0-9]{8,64})/bots$`)
)
