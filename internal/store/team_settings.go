package store

import "context"

// maxTeamAdmins caps the stored admin list.
const maxTeamAdmins = 50

// UpdateTeamAdmins replaces the team admin list (authorization is the
// caller's job: creator only). Ids are trimmed and de-duplicated; the creator
// and anyone not currently in members are dropped; at most 50 are kept.
//
// known is an optional team document the caller already holds (avoids a
// second read); on success its Admins field is updated in place. The
// normalized list that was written is returned. ErrNotFound means the team
// does not exist.
func (s *DocumentRepository) UpdateTeamAdmins(ctx context.Context, teamID string, adminUnionIDs []string, known *TeamDoc) ([]string, error) {
	var team TeamDoc
	if known != nil {
		team = *known
	} else {
		var err error
		if team, err = s.GetTeam(ctx, teamID); err != nil {
			return nil, err
		}
	}
	members := make(map[string]bool, len(team.Members))
	for _, m := range team.Members {
		members[m] = true
	}
	admins := []string{}
	seen := map[string]bool{}
	for _, raw := range adminUnionIDs {
		id := jsTrim(raw)
		if id == "" || id == team.CreatedBy || !members[id] || seen[id] {
			continue
		}
		seen[id] = true
		admins = append(admins, id)
	}
	if len(admins) > maxTeamAdmins {
		admins = admins[:maxTeamAdmins]
	}
	c, err := s.collection(ctx, collectionTeams)
	if err != nil {
		return nil, err
	}
	r, err := c.UpdateOne(ctx, Document{"_id": teamID}, Document{"$set": Document{"admins": admins}}, false)
	if err != nil {
		return nil, normalizeDBError(err)
	}
	if r.Matched == 0 {
		return nil, ErrNotFound
	}
	if known != nil {
		known.Admins = append([]string(nil), admins...)
	}
	return admins, nil
}

// TeamIssueSettingsPatch carries raw (untrusted, JSON-decoded) Issue Board
// settings. A field is applied only when its Set flag is true, mirroring the
// TS "!== undefined" check: an explicit JSON null is still applied and
// normalizes to the empty preset list / default form.
type TeamIssueSettingsPatch struct {
	SetRepoPresets bool
	RepoPresets    any
	SetIssueForm   bool
	IssueForm      any
}

// UpdateTeamIssueSettings normalizes (NormalizeRepoPresets /
// NormalizeIssueForm) and stores the patched settings. An empty patch is a
// successful no-op; ErrNotFound means the team does not exist.
func (s *DocumentRepository) UpdateTeamIssueSettings(ctx context.Context, teamID string, patch TeamIssueSettingsPatch) error {
	set := Document{}
	if patch.SetRepoPresets {
		set["repoPresets"] = NormalizeRepoPresets(patch.RepoPresets)
	}
	if patch.SetIssueForm {
		set["issueForm"] = NormalizeIssueForm(patch.IssueForm)
	}
	if len(set) == 0 {
		return nil
	}
	return s.updateTeamRequired(ctx, teamID, Document{"$set": set})
}
