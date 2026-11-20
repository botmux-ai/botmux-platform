package server

import (
	"errors"
	"log/slog"
	"net/http"
	"regexp"
	"time"

	"github.com/botmux-ai/botmux-platform/internal/auth"
	"github.com/botmux-ai/botmux-platform/internal/store"
)

// External bots are Feishu bots that do not run on botmux (another bot
// framework, a hosted agent platform, a hand-written service). No machine
// reports them, so a member registers one by hand and vouches for it:
//
//   - POST   /api/teams/:id/external-bots         {appId, name, unionId?}
//   - DELETE /api/teams/:id/external-bots/:appId
//
// A registered bot joins the team hall and the team-sync roster, so member
// daemons treat it like a teammate bot (no /grant), and team agents can
// discover it and pull it into team groups. The trust comes from the member
// who registered it, so the bot leaves with them. Removal is the registrant's
// or a team admin's.

var (
	externalBotsPattern   = regexp.MustCompile(`^/api/teams/([a-f0-9]{8,64})/external-bots$`)
	externalBotOnePattern = regexp.MustCompile(`^/api/teams/([a-f0-9]{8,64})/external-bots/([^/]+)$`)
	// Feishu app ids and union ids; the length bounds are loose on purpose.
	feishuAppIDPattern   = regexp.MustCompile(`^cli_[0-9A-Za-z]{8,40}$`)
	feishuUnionIDPattern = regexp.MustCompile(`^on_[0-9A-Za-z]{8,64}$`)
)

const externalBotNameMax = 64

// handleTeamExternalBots serves the two external bot routes; it reports
// whether the request was one of them.
func (a *Apex) handleTeamExternalBots(w http.ResponseWriter, r *http.Request, session *auth.SessionPayload, sessionErr error) bool {
	path := r.URL.Path
	if match := externalBotsPattern.FindStringSubmatch(path); match != nil && r.Method == http.MethodPost {
		if !requireSession(w, sessionErr) {
			return true
		}
		a.putExternalBot(w, r, session, match[1])
		return true
	}
	if match := externalBotOnePattern.FindStringSubmatch(path); match != nil && r.Method == http.MethodDelete {
		if !requireSession(w, sessionErr) {
			return true
		}
		appID, ok := uriComponentDecode(match[2])
		if !ok || !feishuAppIDPattern.MatchString(appID) {
			writeJSON(w, http.StatusBadRequest, apexError{Error: "invalid_app_id"})
			return true
		}
		a.removeExternalBot(w, r, session, match[1], appID)
		return true
	}
	return false
}

// putExternalBot registers a bot, or updates the caller's own registration
// of it (name / union_id).
func (a *Apex) putExternalBot(w http.ResponseWriter, r *http.Request, session *auth.SessionPayload, teamID string) {
	team, ok := a.getTeamMember(w, r, teamID, session.UnionID)
	if !ok {
		return
	}
	body := readJSONObject(r)
	appID, _ := body["appId"].(string)
	appID = trimJS(appID)
	name, _ := body["name"].(string)
	name = truncate(trimJS(name), externalBotNameMax)
	unionID, _ := body["unionId"].(string)
	unionID = trimJS(unionID)
	switch {
	case !feishuAppIDPattern.MatchString(appID):
		writeJSON(w, http.StatusBadRequest, apexError{Error: "invalid_app_id"})
		return
	case name == "":
		writeJSON(w, http.StatusBadRequest, apexError{Error: "name_required"})
		return
	case unionID != "" && !feishuUnionIDPattern.MatchString(unionID):
		writeJSON(w, http.StatusBadRequest, apexError{Error: "invalid_union_id"})
		return
	case a.Config.FeishuAppID != "" && appID == a.Config.FeishuAppID:
		// The platform's own app already sits in every hall.
		writeJSON(w, http.StatusBadRequest, apexError{Error: "platform_app"})
		return
	}
	// A botmux bot carries a machine-verified owner and joins a team only by
	// that owner's choice ("manage my bots"). Registering it by hand would
	// let any member opt someone else's bot in, and a daemon trusts a roster
	// entry whose appId runs on its own machine on every bot there. Readers
	// re-check member machines, for a bot installed after registration.
	for _, ref := range team.Bots {
		if ref.AppID == appID {
			writeJSON(w, http.StatusConflict, apexError{Error: "already_team_bot"})
			return
		}
	}
	onBotmux, err := a.Repository.MachineReportsBot(r.Context(), appID)
	if err != nil {
		writeJSON(w, http.StatusServiceUnavailable, apexError{Error: "store_unavailable"})
		return
	}
	if onBotmux {
		writeJSON(w, http.StatusConflict, apexError{Error: "botmux_bot"})
		return
	}
	bot := store.TeamExternalBot{AppID: appID, Name: name, UnionID: unionID, RegisteredBy: session.UnionID, RegisteredAt: time.Now().UnixMilli()}
	if err := a.Repository.PutTeamExternalBot(r.Context(), teamID, bot); err != nil {
		switch {
		case errors.Is(err, store.ErrNotFound):
			writeJSON(w, http.StatusNotFound, apexError{Error: "team_not_found"})
		case errors.Is(err, store.ErrNotTeamMember):
			writeJSON(w, http.StatusForbidden, apexError{Error: "not_in_team"})
		case errors.Is(err, store.ErrConflict):
			writeJSON(w, http.StatusConflict, apexError{Error: a.externalBotConflict(r, teamID, appID, session.UnionID)})
		default:
			writeJSON(w, http.StatusServiceUnavailable, apexError{Error: "store_unavailable"})
		}
		return
	}
	slog.Info("team external bot registered", "teamId", teamID, "appId", appID, "by", session.UnionID, "hasUnionId", unionID != "")
	// Pull it into the hall (or build the hall) and push the new roster.
	a.syncHallAsync(teamID, []string{appID}, nil, true)
	writeJSON(w, http.StatusOK, externalBotResponse{OK: true, Bot: bot})
}

// externalBotConflict names why PutTeamExternalBot refused.
func (a *Apex) externalBotConflict(r *http.Request, teamID, appID, caller string) string {
	team, err := a.Repository.GetTeam(r.Context(), teamID)
	if err != nil {
		return "external_bot_conflict"
	}
	for _, existing := range team.ExternalBots {
		if existing.AppID == appID && existing.RegisteredBy != caller && contains(team.Members, existing.RegisteredBy) {
			return "registered_by_other"
		}
	}
	if len(team.ExternalBots) >= store.MaxTeamExternalBots {
		return "too_many_external_bots"
	}
	return "external_bot_conflict"
}

func (a *Apex) removeExternalBot(w http.ResponseWriter, r *http.Request, session *auth.SessionPayload, teamID, appID string) {
	team, ok := a.getTeamMember(w, r, teamID, session.UnionID)
	if !ok {
		return
	}
	var entry *store.TeamExternalBot
	for i := range team.ExternalBots {
		if team.ExternalBots[i].AppID == appID {
			entry = &team.ExternalBots[i]
			break
		}
	}
	if entry == nil {
		writeJSON(w, http.StatusNotFound, apexError{Error: "external_bot_not_found"})
		return
	}
	if entry.RegisteredBy != session.UnionID && !store.IsTeamAdmin(team, session.UnionID) {
		writeJSON(w, http.StatusForbidden, apexError{Error: "not_registrant"})
		return
	}
	// The store re-checks the caller's right in the same write: an admin
	// demoted meanwhile is refused.
	removed, err := a.Repository.RemoveTeamExternalBot(r.Context(), teamID, appID, entry.RegisteredBy, session.UnionID)
	if err != nil {
		switch {
		case errors.Is(err, store.ErrNotFound):
			writeJSON(w, http.StatusNotFound, apexError{Error: "team_not_found"})
		case errors.Is(err, store.ErrConflict):
			writeJSON(w, http.StatusForbidden, apexError{Error: "not_registrant"})
		default:
			writeJSON(w, http.StatusServiceUnavailable, apexError{Error: "store_unavailable"})
		}
		return
	}
	if !removed {
		// Someone removed it first; whatever is there now is not ours to
		// touch, so no hall change.
		writeJSON(w, http.StatusOK, okResponse{OK: true})
		return
	}
	slog.Info("team external bot removed", "teamId", teamID, "appId", appID, "by", session.UnionID, "registeredBy", entry.RegisteredBy)
	// Best-effort hall removal (skipped for a bot the hall should still
	// hold); trust follows the roster, pushed right after.
	a.syncHallAsync(teamID, nil, []string{appID}, true)
	writeJSON(w, http.StatusOK, okResponse{OK: true})
}

// rosterExternalBots lists the active external bots for the roster view,
// with the registrant's display name taken from the member list.
func rosterExternalBots(team store.TeamDoc, members []rosterMember, machines []store.MachineDoc) []rosterExternalBot {
	names := make(map[string]string, len(members))
	for _, member := range members {
		names[member.UnionID] = member.Name
	}
	active := team.ActiveExternalBots(machines)
	out := make([]rosterExternalBot, 0, len(active))
	for _, bot := range active {
		out = append(out, rosterExternalBot{
			AppID: bot.AppID, Name: bot.Name, UnionID: bot.UnionID,
			RegisteredBy: bot.RegisteredBy, RegisteredByName: first(names[bot.RegisteredBy], prefix(bot.RegisteredBy, 12)),
			RegisteredAt: bot.RegisteredAt,
		})
	}
	return out
}

type externalBotResponse struct {
	OK  bool                  `json:"ok"`
	Bot store.TeamExternalBot `json:"bot"`
}

type rosterExternalBot struct {
	AppID            string `json:"appId"`
	Name             string `json:"name"`
	UnionID          string `json:"unionId,omitempty"`
	RegisteredBy     string `json:"registeredBy"`
	RegisteredByName string `json:"registeredByName"`
	RegisteredAt     int64  `json:"registeredAt"`
}
