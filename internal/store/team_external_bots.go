package store

import (
	"context"
	"errors"
	"strconv"
)

// MaxTeamExternalBots caps team.externalBots: every entry is pulled into the
// team hall and sent to every member machine in team-sync.
const MaxTeamExternalBots = 50

// externalBotReplaceAttempts bounds the read-then-CAS loop of a
// re-registration racing other writes to the same array.
const externalBotReplaceAttempts = 3

// ErrNotTeamMember means the member who would vouch for an external bot is
// not (or no longer) in the team.
var ErrNotTeamMember = errors.New("store: not a team member")

// PutTeamExternalBot stores bot in team.externalBots. The entry for
// bot.AppID is replaced in place (one atomic write, the bot never drops out
// of the roster in between) when bot.RegisteredBy made it, or when the member
// who made it has left the team. Every write requires bot.RegisteredBy to be
// a member at write time, so a leave racing this call cannot strand a bot
// nobody vouches for. ErrNotTeamMember: the registrant is not a member.
// ErrConflict: a current member registered that appId, the team already
// holds MaxTeamExternalBots, or the entry kept moving under concurrent
// writes. ErrNotFound: no such team. Authorization is the caller's.
func (s *DocumentRepository) PutTeamExternalBot(ctx context.Context, teamID string, bot TeamExternalBot) error {
	c, err := s.collection(ctx, collectionTeams)
	if err != nil {
		return err
	}
	document := externalBotDocument(bot)
	for attempt := 0; attempt < externalBotReplaceAttempts; attempt++ {
		team, err := s.GetTeam(ctx, teamID)
		if err != nil {
			return err
		}
		if !contains(team.Members, bot.RegisteredBy) {
			return ErrNotTeamMember
		}
		index := -1
		for i, existing := range team.ExternalBots {
			if existing.AppID == bot.AppID {
				index = i
				break
			}
		}
		var filter, update Document
		if index >= 0 {
			previous := team.ExternalBots[index].RegisteredBy
			if previous != bot.RegisteredBy && contains(team.Members, previous) {
				return ErrConflict
			}
			// Replace only while the slot still holds the entry read above
			// (a concurrent removal shifts the array and fails the match)
			// and, for an orphan, while its registrant is still gone.
			slot := "externalBots." + strconv.Itoa(index)
			var members any = bot.RegisteredBy
			if previous != bot.RegisteredBy {
				members = Document{"$in": []string{bot.RegisteredBy}, "$ne": previous}
			}
			filter = Document{"_id": teamID, "members": members, slot + ".appId": bot.AppID, slot + ".registeredBy": previous}
			update = Document{"$set": Document{slot: document}}
		} else {
			// The appId must still be free and the array below the cap at
			// write time, not just at read time.
			filter = Document{
				"_id":                teamID,
				"members":            bot.RegisteredBy,
				"externalBots.appId": Document{"$ne": bot.AppID},
				"externalBots." + strconv.Itoa(MaxTeamExternalBots-1): Document{"$exists": false},
			}
			update = Document{"$push": Document{"externalBots": document}}
		}
		r, err := c.UpdateOne(ctx, filter, update, false)
		if err != nil {
			return normalizeDBError(err)
		}
		if r.Matched > 0 {
			return nil
		}
		if index < 0 && len(team.ExternalBots) >= MaxTeamExternalBots {
			return ErrConflict
		}
	}
	return ErrConflict
}

// RemoveTeamExternalBot removes the entry registeredBy made for appID; a
// check-then-remove never deletes a newer registration by someone else.
// actor is the member asking: unless it is the registrant, the same write
// requires actor to be the creator or an admin, so a demotion racing the
// request wins (ErrConflict). removed is false when the entry was already
// gone.
func (s *DocumentRepository) RemoveTeamExternalBot(ctx context.Context, teamID, appID, registeredBy, actor string) (bool, error) {
	c, err := s.collection(ctx, collectionTeams)
	if err != nil {
		return false, err
	}
	filter := Document{"_id": teamID}
	if actor != registeredBy {
		filter["$or"] = []Document{{"createdBy": actor}, {"admins": actor}}
	}
	r, err := c.UpdateOne(ctx, filter, Document{"$pull": Document{"externalBots": Document{"appId": appID, "registeredBy": registeredBy}}}, false)
	if err != nil {
		return false, normalizeDBError(err)
	}
	if r.Matched == 0 {
		if _, err := s.GetTeam(ctx, teamID); err != nil {
			return false, err
		}
		return false, ErrConflict
	}
	return r.Modified > 0, nil
}

// RemoveTeamExternalBotsBy removes every external bot registeredBy added
// (the member is leaving or joining again: a new membership does not revive
// an old vouch).
func (s *DocumentRepository) RemoveTeamExternalBotsBy(ctx context.Context, teamID, registeredBy string) error {
	return s.updateTeamRequired(ctx, teamID, Document{"$pull": Document{"externalBots": Document{"registeredBy": registeredBy}}})
}

// MachineReportsBot reports whether a registered (not RETIRED) machine runs
// appID: such a bot joins teams through its owner, never as an external bot.
func (s *DocumentRepository) MachineReportsBot(ctx context.Context, appID string) (bool, error) {
	docs, err := s.findMachines(ctx, Document{"bots.appId": appID, "status": notRetired()})
	if err != nil {
		return false, err
	}
	return len(docs) > 0, nil
}

// externalBotDocument keeps the legacy physical schema: timestamps are BSON
// doubles and an unknown union_id is omitted rather than stored empty.
func externalBotDocument(bot TeamExternalBot) Document {
	document := Document{
		"appId": bot.AppID, "name": bot.Name, "registeredBy": bot.RegisteredBy,
		"registeredAt": bsonNumber(bot.RegisteredAt),
	}
	if bot.UnionID != "" {
		document["unionId"] = bot.UnionID
	}
	return document
}

func externalBotDocuments(bots []TeamExternalBot) []Document {
	out := make([]Document, 0, len(bots))
	for _, bot := range bots {
		out = append(out, externalBotDocument(bot))
	}
	return out
}

// ActiveExternalBots returns the external bots the team honours: the member
// who registered the bot is still in the team, and no botmux bot uses the
// same appId, neither one of the team nor one that a machine in
// memberMachines reports (a botmux bot has a verified owner and joins
// through that owner; a bot installed on botmux after it was registered
// stops counting as external). memberMachines are the members' machines
// when the caller has them; nil checks team.bots only.
func (t TeamDoc) ActiveExternalBots(memberMachines []MachineDoc) []TeamExternalBot {
	botmuxApps := make(map[string]bool, len(t.Bots))
	for _, ref := range t.Bots {
		botmuxApps[ref.AppID] = true
	}
	for _, machine := range memberMachines {
		for _, bot := range machine.Bots {
			botmuxApps[bot.AppID] = true
		}
	}
	out := make([]TeamExternalBot, 0, len(t.ExternalBots))
	for _, bot := range t.ExternalBots {
		if botmuxApps[bot.AppID] || !contains(t.Members, bot.RegisteredBy) {
			continue
		}
		out = append(out, bot)
	}
	return out
}

// HallBotAppIDs is every bot the team hall should hold: the botmux bots
// first, then the active external bots.
func (t TeamDoc) HallBotAppIDs() []string {
	external := t.ActiveExternalBots(nil)
	out := make([]string, 0, len(t.Bots)+len(external))
	for _, ref := range t.Bots {
		out = append(out, ref.AppID)
	}
	for _, bot := range external {
		out = append(out, bot.AppID)
	}
	return out
}
