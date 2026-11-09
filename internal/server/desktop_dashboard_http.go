package server

import (
	"errors"
	"net/http"
	"regexp"
	"sort"

	"golang.org/x/text/collate"
	"golang.org/x/text/language"

	"github.com/botmux-ai/botmux-platform/internal/auth"
	"github.com/botmux-ai/botmux-platform/internal/store"
	"github.com/botmux-ai/botmux-platform/internal/tunnel"
)

// Desktop remote-dashboard control plane (src/server/desktop-dashboard.ts):
//   - GET  /v1/desktop/machines
//   - POST /v1/desktop/machines/:machineId/dashboard-access

var desktopDashboardAccessPattern = regexp.MustCompile(`^/v1/desktop/machines/([a-f0-9]{8,64})/dashboard-access$`)

// desktopMachineView is the minimal machine view a Cloud profile sees.
type desktopMachineView struct {
	MachineID     string `json:"machineId"`
	Name          string `json:"name"`
	Online        bool   `json:"online"`
	LastSeenAt    int64  `json:"lastSeenAt"`
	BotmuxVersion string `json:"botmuxVersion"`
}

// handleDesktopDashboard serves /v1/desktop/machines and everything below it
// (unknown paths answer a JSON 404).
func (a *Apex) handleDesktopDashboard(w http.ResponseWriter, r *http.Request) bool {
	path := r.URL.EscapedPath()
	if path == "/v1/desktop/machines" && r.Method == http.MethodGet {
		a.desktopMachines(w, r)
		return true
	}
	if match := desktopDashboardAccessPattern.FindStringSubmatch(path); match != nil && r.Method == http.MethodPost {
		a.desktopDashboardAccess(w, r, match[1])
		return true
	}
	writeJSONNoStore(w, http.StatusNotFound, map[string]any{"error": "not_found"})
	return true
}

func (a *Apex) liveMachine(machineID string) (tunnel.MachineConn, bool) {
	if a.Registry == nil {
		return tunnel.MachineConn{}, false
	}
	return a.Registry.Get(machineID)
}

func (a *Apex) desktopMachineFromDoc(doc store.MachineDoc) desktopMachineView {
	nowMS := a.desktopNow().UnixMilli()
	live, isLive := a.liveMachine(doc.ID)
	lastSeenAt := doc.LastSeen
	view := desktopMachineView{MachineID: doc.ID, Name: doc.DisplayName, BotmuxVersion: doc.BotmuxVersion}
	if isLive {
		lastSeenAt = max(lastSeenAt, live.LastSeen.UnixMilli())
		view.Online = !a.Registry.IsStale(live)
		if view.Name == "" {
			view.Name = live.Name
		}
		if live.BotmuxVersion != "" {
			view.BotmuxVersion = live.BotmuxVersion
		}
	} else {
		view.Online = nowMS-lastSeenAt <= a.Config.StaleAfter.Milliseconds()
	}
	view.LastSeenAt = lastSeenAt
	view.Name = first(view.Name, doc.Name, prefix(doc.ID, 8))
	view.BotmuxVersion = first(view.BotmuxVersion, "unknown")
	return view
}

func (a *Apex) desktopMachineFromLive(machine tunnel.MachineConn) desktopMachineView {
	return desktopMachineView{
		MachineID:     machine.MachineID,
		Name:          first(machine.Name, prefix(machine.MachineID, 8)),
		Online:        !a.Registry.IsStale(machine),
		LastSeenAt:    machine.LastSeen.UnixMilli(),
		BotmuxVersion: first(machine.BotmuxVersion, "unknown"),
	}
}

// desktopMachines is GET /v1/desktop/machines. With a database configured an
// unavailable store answers 503 rather than silently shrinking to the
// machines connected to this pod; the explicit in-memory mode (no database
// URI) lists the live registry, like the TypeScript memory mode.
func (a *Apex) desktopMachines(w http.ResponseWriter, r *http.Request) {
	access, ok := a.RequireActiveDesktopAccess(w, r)
	if !ok {
		return
	}
	var machines []desktopMachineView
	if a.Config.DatabaseURI == "" {
		if a.Registry != nil {
			for _, machine := range a.Registry.ListForUser(access.UnionID) {
				machines = append(machines, a.desktopMachineFromLive(machine))
			}
		}
	} else {
		if a.Repository == nil {
			writeJSONNoStore(w, http.StatusServiceUnavailable, map[string]any{"error": "store_unavailable"})
			return
		}
		docs, err := a.Repository.ListMachinesForUser(r.Context(), access.UnionID)
		if err != nil {
			writeJSONNoStore(w, http.StatusServiceUnavailable, map[string]any{"error": "store_unavailable"})
			return
		}
		for _, doc := range docs {
			machines = append(machines, a.desktopMachineFromDoc(doc))
		}
	}
	sortByLocaleName(machines)
	if machines == nil {
		machines = []desktopMachineView{}
	}
	writeJSONNoStore(w, http.StatusOK, struct {
		Machines []desktopMachineView `json:"machines"`
	}{machines})
}

// sortByLocaleName is sort((a, b) => a.name.localeCompare(b.name)): ICU root
// collation, stable for equal keys like Array#sort. A collator is not safe
// for concurrent use, so each call builds its own.
func sortByLocaleName(machines []desktopMachineView) {
	if len(machines) < 2 {
		return
	}
	collator := collate.New(language.Und)
	sort.SliceStable(machines, func(i, j int) bool {
		return collator.CompareString(machines[i].Name, machines[j].Name) < 0
	})
}

type desktopMachineOwnership int

const (
	desktopMachineOwned desktopMachineOwnership = iota
	desktopMachineNotFound
	desktopMachineUnavailable
)

// desktopOwnsActiveMachine is userOwnsActiveMachine. The Desktop chain stays
// owner-only on purpose (no co-managers): listing, ticket issuance and the
// machine-side consumer (MachineDoc.unionId === claims.sub and tunnel owner
// === claims.sub) must be widened together, with scope checks, or a
// co-manager could obtain tickets the machine then rejects.
func (a *Apex) desktopOwnsActiveMachine(r *http.Request, machineID, unionID string) desktopMachineOwnership {
	if a.Repository == nil {
		return desktopMachineUnavailable
	}
	doc, err := a.Repository.GetMachine(r.Context(), machineID)
	found := err == nil
	if err != nil && !errors.Is(err, store.ErrNotFound) {
		return desktopMachineUnavailable
	}
	live, isLive := a.liveMachine(machineID)
	if found {
		if doc.Retired() || doc.UnionID != unionID || (isLive && live.UnionID != unionID) {
			return desktopMachineNotFound
		}
		return desktopMachineOwned
	}
	// A pure in-memory deployment may not have mirrored the document yet; an
	// authenticated live tunnel is then the owner evidence (owner only).
	if isLive && live.UnionID == unionID {
		return desktopMachineOwned
	}
	return desktopMachineNotFound
}

// desktopDashboardAccess is POST /v1/desktop/machines/:id/dashboard-access:
// a purpose-isolated short ticket bound to the profile and session family,
// only for the caller's own ACTIVE machine.
func (a *Apex) desktopDashboardAccess(w http.ResponseWriter, r *http.Request, machineID string) {
	access, ok := a.RequireActiveDesktopAccess(w, r)
	if !ok {
		return
	}
	scope := auth.DesktopDashboardObserve
	if value, present := readDeviceBody(r).value("scope"); present {
		switch value {
		case string(auth.DesktopDashboardObserve):
			scope = auth.DesktopDashboardObserve
		case string(auth.DesktopDashboardManage):
			scope = auth.DesktopDashboardManage
		default:
			writeJSONNoStore(w, http.StatusBadRequest, map[string]any{"error": "invalid_scope"})
			return
		}
	}
	switch a.desktopOwnsActiveMachine(r, machineID, access.UnionID) {
	case desktopMachineUnavailable:
		writeJSONNoStore(w, http.StatusServiceUnavailable, map[string]any{"error": "store_unavailable"})
		return
	case desktopMachineNotFound:
		// Foreign and missing machines answer the same 404 (no id enumeration).
		writeJSONNoStore(w, http.StatusNotFound, map[string]any{"error": "machine_not_found"})
		return
	}

	now := a.desktopNow()
	// The signed-token boundary accepts exp === floor(now/1000); deriving a
	// ticket then would yield exp === iat, so refuse at the issue point.
	if access.Exp <= now.Unix() {
		writeJSONNoStore(w, http.StatusUnauthorized, map[string]any{"error": "access_expired"})
		return
	}
	issued := auth.MintDesktopDashboardAccessTokenAt(a.Config, access, machineID, scope, now)
	writeJSONNoStore(w, http.StatusOK, struct {
		MachineID   string                     `json:"machineId"`
		Scope       auth.DesktopDashboardScope `json:"scope"`
		Audience    string                     `json:"audience"`
		AccessToken string                     `json:"accessToken"`
		ExpiresAt   int64                      `json:"expiresAt"`
	}{machineID, scope, auth.DesktopDashboardAudience, issued.AccessToken, issued.ExpiresAt})
}
