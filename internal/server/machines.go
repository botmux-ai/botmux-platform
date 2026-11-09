package server

import (
	"context"
	"regexp"
	"sort"
	"strconv"
	"time"

	"golang.org/x/text/collate"
	"golang.org/x/text/language"

	"github.com/botmux-ai/botmux-platform/internal/auth"
	"github.com/botmux-ai/botmux-platform/internal/store"
	"github.com/botmux-ai/botmux-platform/internal/tunnel"
)

type MachineView struct {
	MachineID     string                  `json:"machineId"`
	Name          string                  `json:"name"`
	BotmuxVersion string                  `json:"botmuxVersion"`
	Stale         bool                    `json:"stale"`
	Online        bool                    `json:"online"`
	LastSeen      int64                   `json:"lastSeen"`
	Memberships   []tunnel.MembershipInfo `json:"memberships"`
	Bots          []tunnel.BotInfo        `json:"bots"`
	// CoManagerCount is the owner's list badge: how many co-managers this
	// machine is shared with.
	CoManagerCount int `json:"coManagerCount"`
	// OwnerName and MyScopes appear only in managedMachines (the grantee's
	// view): whose machine it is and which scopes the grantee holds.
	OwnerName *string  `json:"ownerName,omitempty"`
	MyScopes  []string `json:"myScopes,omitempty"`
	// MyRole is the grantee's role on a managedMachines entry: "co-manager"
	// or "viewer" (read-only).
	MyRole string `json:"myRole,omitempty"`
}

// deviceMachineView is the reduced /api/machines entry for a device
// principal (machines:read): no versions, teams or bots.
type deviceMachineView struct {
	MachineID  string `json:"machineId"`
	Name       string `json:"name"`
	Online     bool   `json:"online"`
	LastSeenAt int64  `json:"lastSeenAt"`
}

func (a *Apex) machinesForUser(ctx context.Context, unionID string) ([]MachineView, error) {
	docs, err := a.Repository.ListMachinesForUser(ctx, unionID)
	if err != nil {
		// The process-local registry is only a live overlay, never an authority.
		// Returning it after a MongoDB failure would silently hide offline machines
		// and make an outage look like a valid empty account.
		return nil, err
	}
	out := make([]MachineView, 0, len(docs))
	for _, doc := range docs {
		out = append(out, a.machineView(doc))
	}
	sortMachineViews(out)
	return out, nil
}

// machinesCoManagedBy lists the machines unionID co-manages. Like the TS
// helper it degrades to an empty list when the store cannot answer: the list
// only grants visibility, every open re-checks access authoritatively.
func (a *Apex) machinesCoManagedBy(ctx context.Context, unionID string) []MachineView {
	docs, err := a.Repository.ListMachinesCoManagedBy(ctx, unionID)
	if err != nil {
		return []MachineView{}
	}
	out := make([]MachineView, 0, len(docs))
	for _, doc := range docs {
		access := auth.ResolveMachineAccess(&doc, unionID)
		// An entry whose scopes were emptied (or are all no longer grantable)
		// is no access at all and must not be listed.
		if !access.OK || len(access.Scopes) == 0 {
			continue
		}
		view := a.machineView(doc)
		ownerName := doc.OwnerName
		view.OwnerName = &ownerName
		view.MyScopes = append([]string(nil), access.Scopes...)
		view.MyRole = string(access.Role)
		out = append(out, view)
	}
	sortMachineViews(out)
	return out
}

// sortMachineViews orders by name with String#localeCompare semantics. Node
// resolves its default collator to en-US (CLDR root order: case-insensitive
// first, punctuation before digits before letters), which byte order would
// not reproduce. The sort is stable like Array#sort.
func sortMachineViews(views []MachineView) {
	collator := collate.New(language.English)
	sort.SliceStable(views, func(i, j int) bool {
		return collator.CompareString(views[i].Name, views[j].Name) < 0
	})
}

func (a *Apex) machineView(doc store.MachineDoc) MachineView {
	live, onlineHere := a.Registry.Get(doc.ID)
	lastSeen := doc.LastSeen
	name := first(doc.DisplayName, doc.Name, prefix(doc.ID, 8))
	version := first(doc.BotmuxVersion, "unknown")
	memberships := storeMemberships(doc.Memberships)
	bots := storeBots(doc.Bots)
	if onlineHere {
		if live.LastSeen.UnixMilli() > lastSeen {
			lastSeen = live.LastSeen.UnixMilli()
		}
		name = first(doc.DisplayName, live.Name, doc.Name, prefix(doc.ID, 8))
		version = first(live.BotmuxVersion, doc.BotmuxVersion, "unknown")
		// `live?.memberships || d.memberships || []`: an array is truthy even
		// when empty, so a live machine's lists always win.
		memberships, bots = live.Memberships, live.Bots
	}
	online := false
	if onlineHere {
		online = !a.Registry.IsStale(live)
	} else {
		online = time.Now().UnixMilli()-lastSeen <= a.Config.StaleAfter.Milliseconds()
	}
	return MachineView{MachineID: doc.ID, Name: name, BotmuxVersion: version, Stale: !online, Online: online, LastSeen: lastSeen, Memberships: nonNilMemberships(memberships), Bots: nonNilBots(bots), CoManagerCount: len(doc.CoManagers)}
}

func nonNilMemberships(values []tunnel.MembershipInfo) []tunnel.MembershipInfo {
	if values == nil {
		return []tunnel.MembershipInfo{}
	}
	return values
}

func nonNilBots(values []tunnel.BotInfo) []tunnel.BotInfo {
	if values == nil {
		return []tunnel.BotInfo{}
	}
	return values
}

func storeMemberships(values []store.MembershipInfo) []tunnel.MembershipInfo {
	out := make([]tunnel.MembershipInfo, 0, len(values))
	for _, value := range values {
		out = append(out, tunnel.MembershipInfo(value))
	}
	return out
}

func storeBots(values []store.BotInfo) []tunnel.BotInfo {
	out := make([]tunnel.BotInfo, 0, len(values))
	for _, value := range values {
		out = append(out, tunnel.BotInfo{AppID: value.AppID, OpenID: value.OpenID, Name: value.Name, Avatar: value.Avatar, CLI: value.CLI, ShowInTeam: value.ShowInTeam, UnionID: value.UnionID, Specialties: tunnel.Specialties(value.Specialties), Mentionable: value.Mentionable})
	}
	return out
}

var semverPrefix = regexp.MustCompile(`^v?(\d+)\.(\d+)\.(\d+)`)

// highestVersion is the naive semver max of the owner's machines: the raw
// version string of the highest major.minor.patch, ignoring unparsable
// values, "unknown" and the 0.0.0 dev placeholder. Components are compared
// as JS Numbers, so huge components saturate instead of failing to parse.
func highestVersion(machines []MachineView) *string {
	var best string
	var bestParts [3]float64
	found := false
	for _, machine := range machines {
		match := semverPrefix.FindStringSubmatch(machine.BotmuxVersion)
		if match == nil {
			continue
		}
		var parts [3]float64
		for index := range parts {
			parts[index], _ = strconv.ParseFloat(match[index+1], 64)
		}
		if parts == [3]float64{} {
			continue
		}
		if !found || compareVersionParts(parts, bestParts) > 0 {
			best, bestParts, found = machine.BotmuxVersion, parts, true
		}
	}
	if !found {
		return nil
	}
	return &best
}

func compareVersionParts(a, b [3]float64) int {
	for index := range a {
		if a[index] != b[index] {
			if a[index] > b[index] {
				return 1
			}
			return -1
		}
	}
	return 0
}

func first(values ...string) string {
	for _, value := range values {
		if value != "" {
			return value
		}
	}
	return ""
}

func prefix(value string, count int) string {
	if len(value) <= count {
		return value
	}
	return value[:count]
}
