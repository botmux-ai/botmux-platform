package tunnel

import "encoding/json"

type MembershipInfo struct {
	TeamID   string `json:"teamId" bson:"teamId"`
	TeamName string `json:"teamName" bson:"teamName"`
}

type BotInfo struct {
	AppID      string  `json:"appId" bson:"appId"`
	OpenID     *string `json:"openId" bson:"openId"`
	Name       string  `json:"name" bson:"name"`
	Avatar     string  `json:"avatar,omitempty" bson:"avatar,omitempty"`
	CLI        string  `json:"cli,omitempty" bson:"cli,omitempty"`
	ShowInTeam *bool   `json:"showInTeam,omitempty" bson:"showInTeam,omitempty"`
	UnionID    string  `json:"unionId,omitempty" bson:"unionId,omitempty"`
	// Specialties / Mentionable are self-reported discovery labels for the
	// team agent directory; absent means "undeclared" ([] / true on read).
	Specialties Specialties `json:"specialties,omitempty" bson:"specialties,omitempty"`
	Mentionable *bool       `json:"mentionable,omitempty" bson:"mentionable,omitempty"`
}

// Specialties decodes leniently: an array keeps only its string elements and
// any other JSON shape is treated as absent, so a malformed self-reported
// label can never fail a register/heartbeat message (Node accepts the payload
// as-is and filters strings at read time).
type Specialties []string

func (s *Specialties) UnmarshalJSON(data []byte) error {
	*s = nil
	var values []json.RawMessage
	if err := json.Unmarshal(data, &values); err != nil || values == nil {
		return nil
	}
	out := make(Specialties, 0, len(values))
	for _, value := range values {
		var text string
		if len(value) > 0 && value[0] == '"' && json.Unmarshal(value, &text) == nil {
			out = append(out, text)
		}
	}
	*s = out
	return nil
}

type DaemonMessage struct {
	Type           string           `json:"type"`
	Name           string           `json:"name,omitempty"`
	BotmuxVersion  string           `json:"botmuxVersion,omitempty"`
	DashboardToken string           `json:"dashboardToken,omitempty"`
	DashboardPort  int              `json:"dashboardPort,omitempty"`
	DirectHosts    []string         `json:"directHosts,omitempty"`
	Memberships    []MembershipInfo `json:"memberships,omitempty"`
	Bots           []BotInfo        `json:"bots,omitempty"`
	TeamSyncRev    *string          `json:"teamSyncRev,omitempty"`
}

func ParseDaemonMessage(data []byte) (*DaemonMessage, bool) {
	var msg DaemonMessage
	if err := json.Unmarshal(data, &msg); err != nil {
		return nil, false
	}
	if msg.Type != "register" && msg.Type != "heartbeat" {
		return nil, false
	}
	return &msg, true
}

type TeamSyncBot struct {
	AppID   string `json:"appId"`
	UnionID string `json:"unionId,omitempty"`
	Name    string `json:"name,omitempty"`
	// OwnerUnionID is the current registered owner of the bot's machine,
	// derived by the platform from the machine token and MachineDoc; the
	// daemon-reported bots payload can never set it.
	OwnerUnionID string `json:"ownerUnionId,omitempty"`
}

type TeamSyncTeam struct {
	TeamID         string        `json:"teamId"`
	TeamName       string        `json:"teamName"`
	GroupChatIDs   []string      `json:"groupChatIds"`
	Bots           []TeamSyncBot `json:"bots"`
	MemberUnionIDs []string      `json:"memberUnionIds,omitempty"`
}
