package store

// MembershipInfo is the legacy daemon-reported membership shape persisted in
// the machines collection. Authoritative team membership lives in TeamDoc.
type MembershipInfo struct {
	TeamID   string `json:"teamId" bson:"teamId"`
	TeamName string `json:"teamName" bson:"teamName"`
}

// BotInfo is the machine-local bot summary sent during register/heartbeat.
type BotInfo struct {
	AppID      string  `json:"appId" bson:"appId"`
	OpenID     *string `json:"openId,omitempty" bson:"openId,omitempty"`
	Name       string  `json:"name" bson:"name"`
	Avatar     string  `json:"avatar,omitempty" bson:"avatar,omitempty"`
	CLI        string  `json:"cli,omitempty" bson:"cli,omitempty"`
	ShowInTeam *bool   `json:"showInTeam,omitempty" bson:"showInTeam,omitempty"`
	UnionID    string  `json:"unionId,omitempty" bson:"unionId,omitempty"`
	// Specialties and Mentionable are daemon self-reported discovery labels
	// (protocol.ts BotInfo). Node stores the register payload verbatim, so
	// both are kept as reported; readers apply the TS defaults ([] / true).
	Specialties BotSpecialties `json:"specialties,omitempty" bson:"specialties,omitempty"`
	Mentionable *bool          `json:"mentionable,omitempty" bson:"mentionable,omitempty"`
}

// Machine lifecycle states. A missing status is treated as MachineStatusActive
// so documents written before the tombstone rollout keep working.
const (
	MachineStatusActive  = "ACTIVE"
	MachineStatusRetired = "RETIRED"
)

// MachineCoManager is a person the machine owner explicitly allowed to use the
// machine dashboard with a restricted scope set. Authorization reads only this
// list (never team membership) so it is a grant-time snapshot; removal on
// leaving a team is best effort (see DropCoManagerFromTeamMachines).
type MachineCoManager struct {
	UnionID string `json:"unionId" bson:"unionId"`
	// Name is a display-name snapshot taken from the user profile at grant time.
	Name string `json:"name" bson:"name"`
	// Scopes reuse the device scope vocabulary (see DeviceScope*).
	Scopes    []string `json:"scopes" bson:"scopes"`
	GrantedAt int64    `json:"grantedAt" bson:"grantedAt,truncate"`
	// GrantedBy is the owner unionId at grant time (audit only).
	GrantedBy string `json:"grantedBy" bson:"grantedBy"`
	// ViaTeamID is the shared team that justified the grant; leaving that team
	// drops only grants carrying the same ViaTeamID.
	ViaTeamID string `json:"viaTeamId,omitempty" bson:"viaTeamId,omitempty"`
	// Role is the grant kind. Empty (every document written before the
	// viewer role existed) means a co-manager whose Scopes decide what they
	// may do; CoManagerRoleViewer is a read-only grant that ignores Scopes.
	// Any other value is denied (auth.ResolveMachineAccess fails closed).
	Role string `json:"role,omitempty" bson:"role,omitempty"`
}

// Co-manager grant kinds (MachineCoManager.Role).
const (
	// CoManagerRoleManager is the explicit spelling of the legacy empty role.
	CoManagerRoleManager = "co-manager"
	// CoManagerRoleViewer may watch the dashboard, the session board and
	// terminal output, and nothing else.
	CoManagerRoleViewer = "viewer"
)

// MachineDoc mirrors the existing MongoDB machines collection. All timestamps
// are Unix milliseconds. DashboardToken and DirectHosts intentionally never
// appear here: they are connection secrets/state and must remain in memory.
type MachineDoc struct {
	ID            string           `json:"machineId" bson:"_id"`
	UnionID       string           `json:"unionId" bson:"unionId"`
	OwnerName     string           `json:"ownerName" bson:"ownerName"`
	Name          string           `json:"name" bson:"name"`
	DisplayName   string           `json:"displayName,omitempty" bson:"displayName,omitempty"`
	BotmuxVersion string           `json:"botmuxVersion" bson:"botmuxVersion"`
	DashboardPort int              `json:"dashboardPort" bson:"dashboardPort"`
	Memberships   []MembershipInfo `json:"memberships" bson:"memberships"`
	Bots          []BotInfo        `json:"bots,omitempty" bson:"bots,omitempty"`
	BoundAt       int64            `json:"boundAt" bson:"boundAt,truncate"`
	LastSeen      int64            `json:"lastSeen" bson:"lastSeen,truncate"`
	// Status is MachineStatusActive, MachineStatusRetired or empty (legacy
	// documents, treated as active). RETIRED is an unbind tombstone: the
	// machineId is never reused, so stale machine tokens, proxy tickets, route
	// entries and team references can never be re-attached to a new owner.
	Status string `json:"status,omitempty" bson:"status,omitempty"`
	// CoManagers is the owner-granted co-manager list. Nil/empty means only
	// the owner can access the machine.
	CoManagers []MachineCoManager `json:"coManagers,omitempty" bson:"coManagers,omitempty"`
}

// Retired reports whether the document is an unbind tombstone.
func (m MachineDoc) Retired() bool { return m.Status == MachineStatusRetired }

// MachineVersionSample is the minimal per-machine projection used by the
// version dashboard. It deliberately carries no machine or owner names.
type MachineVersionSample struct {
	// MachineID is used only to merge pod-local online state; it must never be
	// exposed in API responses.
	MachineID     string `json:"machineId"`
	UnionID       string `json:"unionId"`
	BotmuxVersion string `json:"botmuxVersion"`
	LastSeen      int64  `json:"lastSeen"`
}

type UserProfile struct {
	ID        string `json:"unionId" bson:"_id"`
	Name      string `json:"name" bson:"name"`
	Avatar    string `json:"avatar,omitempty" bson:"avatar,omitempty"`
	UpdatedAt int64  `json:"updatedAt" bson:"updatedAt,truncate"`
}

type TeamBotRef struct {
	MachineID string `json:"machineId" bson:"machineId"`
	AppID     string `json:"appId" bson:"appId"`
}

type PendingInvite struct {
	UnionID   string `json:"unionId" bson:"unionId"`
	OpenID    string `json:"openId,omitempty" bson:"openId,omitempty"`
	Name      string `json:"name" bson:"name"`
	InvitedBy string `json:"invitedBy" bson:"invitedBy"`
	InvitedAt int64  `json:"invitedAt" bson:"invitedAt,truncate"`
}

// TeamDoc mirrors the existing MongoDB teams collection.
type TeamDoc struct {
	ID             string          `json:"teamId" bson:"_id"`
	Name           string          `json:"name" bson:"name"`
	Members        []string        `json:"members" bson:"members"`
	Bots           []TeamBotRef    `json:"bots,omitempty" bson:"bots,omitempty"`
	HallChatID     string          `json:"hallChatId,omitempty" bson:"hallChatId,omitempty"`
	GroupChatIDs   []string        `json:"groupChatIds,omitempty" bson:"groupChatIds,omitempty"`
	PendingInvites []PendingInvite `json:"pendingInvites,omitempty" bson:"pendingInvites,omitempty"`
	// RepoPresets is the Issue Board preset repository list.
	RepoPresets []TeamRepoPreset `json:"repoPresets,omitempty" bson:"repoPresets,omitempty"`
	// IssueForm is the customizable Issue Board create form; nil means
	// DefaultIssueForm().
	IssueForm *IssueFormConfig `json:"issueForm,omitempty" bson:"issueForm,omitempty"`
	// Admins lists team administrators other than the creator (who is always
	// an admin). Admins may edit issue settings and perform sensitive issue
	// operations; rename/disband/appoint admins remain creator-only.
	Admins    []string `json:"admins,omitempty" bson:"admins,omitempty"`
	CreatedBy string   `json:"createdBy" bson:"createdBy"`
	CreatedAt int64    `json:"createdAt" bson:"createdAt,truncate"`
}

// IsTeamAdmin reports whether unionID is the team creator or listed in
// team.Admins.
func IsTeamAdmin(team TeamDoc, unionID string) bool {
	if team.CreatedBy == unionID {
		return true
	}
	return contains(team.Admins, unionID)
}

type RegisterMachine struct {
	MachineID     string
	UnionID       string
	OwnerName     string
	Name          string
	BotmuxVersion string
	DashboardPort int
	Memberships   []MembershipInfo
	Bots          []BotInfo
	LastSeen      int64
}

// HeartbeatUpdate uses pointers for optional arrays so an omitted field is
// distinct from an explicitly reported empty array.
type HeartbeatUpdate struct {
	BotmuxVersion *string
	Memberships   *[]MembershipInfo
	Bots          *[]BotInfo
	LastSeen      int64
}
