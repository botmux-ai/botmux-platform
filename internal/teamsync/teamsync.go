package teamsync

import (
	"crypto/sha1" // Compatibility: the daemon protocol already uses a truncated SHA-1 revision.
	"encoding/hex"
	"sort"
	"unicode/utf8"
)

// Bot is one team-sync roster entry. UnionID and Name are optional on the wire
// for compatibility with bots whose identity has not yet been learned.
// OwnerUnionID is the bot's machine owner, always taken from the current
// MachineDoc (never from the daemon), and is absent when it is unknown.
type Bot struct {
	AppID        string `json:"appId"`
	UnionID      string `json:"unionId,omitempty"`
	Name         string `json:"name,omitempty"`
	OwnerUnionID string `json:"ownerUnionId,omitempty"`
}

// Team is the daemon-facing team-sync payload.
type Team struct {
	TeamID         string   `json:"teamId"`
	TeamName       string   `json:"teamName"`
	GroupChatIDs   []string `json:"groupChatIds"`
	Bots           []Bot    `json:"bots"`
	MemberUnionIDs []string `json:"memberUnionIds"`
}

// Message is the daemon-bound team-sync control message, in TS key order.
type Message struct {
	Type  string `json:"type"`
	Rev   string `json:"rev"`
	Teams []Team `json:"teams"`
}

// CanonicalBot is the revision representation. Unlike Bot, its optional wire
// fields are always materialized as empty strings before hashing.
type CanonicalBot struct {
	AppID        string `json:"appId"`
	UnionID      string `json:"unionId"`
	Name         string `json:"name"`
	OwnerUnionID string `json:"ownerUnionId"`
}

// CanonicalTeam is the stable, fully materialized revision representation.
type CanonicalTeam struct {
	TeamID         string         `json:"teamId"`
	TeamName       string         `json:"teamName"`
	GroupChatIDs   []string       `json:"groupChatIds"`
	Bots           []CanonicalBot `json:"bots"`
	MemberUnionIDs []string       `json:"memberUnionIds"`
}

// Canonicalize returns a deep, sorted copy and never mutates the daemon-facing
// payload. Identifiers in this protocol are ASCII (hex IDs, cli_/ou_/on_
// identifiers), for which Go lexical order matches the existing JavaScript
// localeCompare/default-sort behavior.
func Canonicalize(teams []Team) []CanonicalTeam {
	stable := make([]CanonicalTeam, 0, len(teams))
	for _, team := range teams {
		groupChatIDs := append([]string(nil), team.GroupChatIDs...)
		if groupChatIDs == nil {
			groupChatIDs = []string{}
		}
		sort.Strings(groupChatIDs)

		memberUnionIDs := append([]string(nil), team.MemberUnionIDs...)
		if memberUnionIDs == nil {
			memberUnionIDs = []string{}
		}
		sort.Strings(memberUnionIDs)

		bots := make([]CanonicalBot, 0, len(team.Bots))
		for _, bot := range team.Bots {
			bots = append(bots, CanonicalBot{AppID: bot.AppID, UnionID: bot.UnionID, Name: bot.Name, OwnerUnionID: bot.OwnerUnionID})
		}
		if bots == nil {
			bots = []CanonicalBot{}
		}
		sort.SliceStable(bots, func(i, j int) bool { return bots[i].AppID < bots[j].AppID })

		stable = append(stable, CanonicalTeam{
			TeamID:         team.TeamID,
			TeamName:       team.TeamName,
			GroupChatIDs:   groupChatIDs,
			Bots:           bots,
			MemberUnionIDs: memberUnionIDs,
		})
	}
	if stable == nil {
		stable = []CanonicalTeam{}
	}
	sort.SliceStable(stable, func(i, j int) bool { return stable[i].TeamID < stable[j].TeamID })
	return stable
}

// CanonicalJSON is byte-for-byte compatible with JSON.stringify(stable) in
// the TypeScript implementation, including field order and Unicode escaping.
func CanonicalJSON(teams []Team) []byte {
	stable := Canonicalize(teams)
	dst := []byte{'['}
	for i, team := range stable {
		if i > 0 {
			dst = append(dst, ',')
		}
		dst = append(dst, '{')
		dst = appendStringField(dst, "teamId", team.TeamID, true)
		dst = appendStringField(dst, "teamName", team.TeamName, false)

		dst = append(dst, `,"groupChatIds":[`...)
		for index, chatID := range team.GroupChatIDs {
			if index > 0 {
				dst = append(dst, ',')
			}
			dst = appendJSONString(dst, chatID)
		}
		dst = append(dst, ']')

		dst = append(dst, `,"bots":[`...)
		for index, bot := range team.Bots {
			if index > 0 {
				dst = append(dst, ',')
			}
			dst = append(dst, '{')
			dst = appendStringField(dst, "appId", bot.AppID, true)
			dst = appendStringField(dst, "unionId", bot.UnionID, false)
			dst = appendStringField(dst, "name", bot.Name, false)
			dst = appendStringField(dst, "ownerUnionId", bot.OwnerUnionID, false)
			dst = append(dst, '}')
		}
		dst = append(dst, ']')

		dst = append(dst, `,"memberUnionIds":[`...)
		for index, unionID := range team.MemberUnionIDs {
			if index > 0 {
				dst = append(dst, ',')
			}
			dst = appendJSONString(dst, unionID)
		}
		dst = append(dst, ']', '}')
	}
	return append(dst, ']')
}

// Revision returns the first 16 lowercase hexadecimal characters of SHA-1
// over CanonicalJSON, matching teamSyncRev in the TypeScript service.
func Revision(teams []Team) string {
	sum := sha1.Sum(CanonicalJSON(teams))
	return hex.EncodeToString(sum[:])[:16]
}

func appendStringField(dst []byte, name, value string, first bool) []byte {
	if !first {
		dst = append(dst, ',')
	}
	dst = appendJSONString(dst, name)
	dst = append(dst, ':')
	return appendJSONString(dst, value)
}

func appendJSONString(dst []byte, value string) []byte {
	dst = append(dst, '"')
	for len(value) > 0 {
		r, size := utf8.DecodeRuneInString(value)
		if r == utf8.RuneError && size == 1 {
			r = '\uFFFD'
		}
		value = value[size:]
		switch r {
		case '"', '\\':
			dst = append(dst, '\\', byte(r))
		case '\b':
			dst = append(dst, `\b`...)
		case '\f':
			dst = append(dst, `\f`...)
		case '\n':
			dst = append(dst, `\n`...)
		case '\r':
			dst = append(dst, `\r`...)
		case '\t':
			dst = append(dst, `\t`...)
		default:
			if r < 0x20 {
				const digits = "0123456789abcdef"
				dst = append(dst, '\\', 'u', '0', '0', digits[byte(r)>>4], digits[byte(r)&0xf])
			} else {
				dst = utf8.AppendRune(dst, r)
			}
		}
	}
	return append(dst, '"')
}
