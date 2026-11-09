package server

import (
	"log/slog"
	"net/http"
	"slices"
	"sort"
	"time"

	"github.com/botmux-ai/botmux-platform/internal/store"
)

// Team agent directory for daemons (src/server/machine-agents-http.ts).
// Owned by Phase 2 agent B4.
//
// GET /v1/machine/agents?teamId= lets a daemon (machine token) discover the
// agents its team opted in. The trust domain is the person: the caller's
// owner must be a member of the team, and the result aggregates every team
// member's registered machines (offline ones included). The opt-in gate is
// team.bots — not showInTeam — so a bot is discoverable only once its owner
// added it to the team. specialties / mentionable are self-reported labels,
// passed through for display and never treated as credentials.

// agentOwner is AgentView.owner.
type agentOwner struct {
	UnionID string `json:"unionId"`
	Name    string `json:"name"`
}

// agentView is AgentView in TS key order. unionId is omitted (not null) when
// the bot has not learned it yet.
type agentView struct {
	AppID       string     `json:"appId"`
	OpenID      *string    `json:"openId"`
	UnionID     string     `json:"unionId,omitempty"`
	Name        string     `json:"name"`
	Specialties []string   `json:"specialties"`
	Mentionable bool       `json:"mentionable"`
	Online      bool       `json:"online"`
	Owner       agentOwner `json:"owner"`
	MachineID   string     `json:"machineId"`
	MachineName string     `json:"machineName"`
}

type agentsResponse struct {
	TeamID   string      `json:"teamId"`
	TeamName string      `json:"teamName"`
	Agents   []agentView `json:"agents"`
}

func (a *Apex) agentsFromMachine(doc store.MachineDoc, teamBotKeys map[string]bool, now time.Time) []agentView {
	online := now.UnixMilli()-doc.LastSeen <= a.Config.StaleAfter.Milliseconds()
	owner := agentOwner{UnionID: doc.UnionID, Name: doc.OwnerName}
	if owner.Name == "" {
		owner.Name = jsSlice(doc.UnionID, 12)
	}
	machineName := doc.DisplayName
	if machineName == "" {
		machineName = doc.Name
	}
	if machineName == "" {
		machineName = jsSlice(doc.ID, 8)
	}
	var out []agentView
	for _, bot := range doc.Bots {
		if !teamBotKeys[doc.ID+"::"+bot.AppID] {
			continue // the owner has not added this bot to the team
		}
		name := bot.Name
		if name == "" {
			name = bot.AppID
		}
		out = append(out, agentView{
			AppID:       bot.AppID,
			OpenID:      bot.OpenID,
			UnionID:     bot.UnionID,
			Name:        name,
			Specialties: bot.Specialties.Strings(),
			Mentionable: bot.Mentionable == nil || *bot.Mentionable, // absent = true
			Online:      online,
			Owner:       owner,
			MachineID:   doc.ID,
			MachineName: machineName,
		})
	}
	return out
}

// handleMachineAgentsAPI serves /v1/machine/agents.
func (a *Apex) handleMachineAgentsAPI(w http.ResponseWriter, r *http.Request) bool {
	if requestPathname(r) != "/v1/machine/agents" {
		return false
	}
	if r.Method != http.MethodGet {
		writeJSONNoStore(w, http.StatusMethodNotAllowed, map[string]any{"error": "method_not_allowed"})
		return true
	}
	principal, ok := a.RequireMachineAuth(w, r)
	if !ok {
		return true
	}
	teamID, _ := searchParamGet(requestSearchParams(r), "teamId")
	if teamID == "" {
		writeJSONNoStore(w, http.StatusBadRequest, map[string]any{"error": "missing_teamId"})
		return true
	}
	// getTeamDoc yields null for a missing team and for a read failure alike;
	// both answer 404 so the endpoint never reveals whether a team exists.
	team, err := a.Repository.GetTeam(r.Context(), teamID)
	if err != nil || !slices.Contains(team.Members, principal.UnionID) {
		writeJSONNoStore(w, http.StatusNotFound, map[string]any{"error": "not_found"})
		return true
	}
	docs, err := a.listMachinesForMembers(r, team.Members)
	if err != nil {
		writeJSONNoStore(w, http.StatusServiceUnavailable, map[string]any{"error": "store_unavailable"})
		return true
	}
	teamBotKeys := make(map[string]bool, len(team.Bots))
	for _, ref := range team.Bots {
		teamBotKeys[ref.MachineID+"::"+ref.AppID] = true
	}
	now := time.Now()
	agents := make([]agentView, 0)
	for _, doc := range docs {
		agents = append(agents, a.agentsFromMachine(doc, teamBotKeys, now)...)
	}
	collator := newLocaleCollator()
	sort.SliceStable(agents, func(i, j int) bool {
		if c := collator.compare(agents[i].Owner.Name, agents[j].Owner.Name); c != 0 {
			return c < 0
		}
		if c := collator.compare(agents[i].MachineName, agents[j].MachineName); c != 0 {
			return c < 0
		}
		return collator.compare(agents[i].Name, agents[j].Name) < 0
	})
	slog.Info("team-agents query", "byUnionId", principal.UnionID, "byMachineId", principal.MachineID, "teamId", teamID, "agentCount", len(agents))
	writeJSONNoStore(w, http.StatusOK, agentsResponse{TeamID: teamID, TeamName: team.Name, Agents: agents})
	return true
}

// listMachinesForMembers is listMachinesForUsers: an empty member list is an
// empty result without a store read.
func (a *Apex) listMachinesForMembers(r *http.Request, unionIDs []string) ([]store.MachineDoc, error) {
	if len(unionIDs) == 0 {
		return nil, nil
	}
	return a.Repository.ListMachinesForUsers(r.Context(), unionIDs)
}
