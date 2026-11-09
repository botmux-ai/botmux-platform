package teamsync

import (
	"context"
	"errors"
	"log/slog"
	"sync"
	"time"

	"github.com/botmux-ai/botmux-platform/internal/feishu"
	"github.com/botmux-ai/botmux-platform/internal/store"
	"github.com/botmux-ai/botmux-platform/internal/tunnel"
)

const (
	teamCacheTTL   = 15 * time.Second
	hallRetryDelay = 10 * time.Minute

	// Hall identity backfill (team-sync.ts HALL_TEACH_*): the one-shot @ sent
	// when a bot joins or a hall is built can be missed (daemon offline,
	// legacy teams never taught, lazily built halls). The aggregation path
	// re-@s live bots whose roster entry still lacks a union_id, throttled
	// per team, capped per bot, and delayed so the same beat's team-sync lets
	// the daemon recognise the hall first.
	hallTeachRetry       = 30 * time.Minute
	hallTeachMaxAttempts = 6
	hallTeachDelay       = 5 * time.Second
	hallTeachTimeout     = 30 * time.Second
)

type Service struct {
	repository store.Repository
	registry   *tunnel.Registry
	feishu     *feishu.Client

	mu                sync.Mutex
	cache             map[string]cachedTeam
	hallAttempts      map[string]time.Time
	hallTeachAt       map[string]time.Time
	hallTeachAttempts map[string]int
	writeEnabled      bool
	// teachDelay is hallTeachDelay; tests shorten it.
	teachDelay time.Duration
}

type cachedTeam struct {
	at   time.Time
	team Team
}

func NewService(repository store.Repository, registry *tunnel.Registry, client *feishu.Client) *Service {
	return &Service{
		repository: repository, registry: registry, feishu: client,
		cache: make(map[string]cachedTeam), hallAttempts: make(map[string]time.Time),
		hallTeachAt: make(map[string]time.Time), hallTeachAttempts: make(map[string]int),
		writeEnabled: true, teachDelay: hallTeachDelay,
	}
}

// SetFeishuWrites provides the canary safety switch requested by the migration
// runbook. Disabling writes still computes and sends authoritative team-sync.
func (s *Service) SetFeishuWrites(enabled bool) { s.mu.Lock(); s.writeEnabled = enabled; s.mu.Unlock() }

func (s *Service) Invalidate(teamID string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if teamID == "" {
		clear(s.cache)
		return
	}
	delete(s.cache, teamID)
}

func (s *Service) MaybeSendTeamSync(ctx context.Context, machineID, clientRevision string) error {
	machine, ok := s.registry.Get(machineID)
	if !ok {
		return nil
	}
	docs, err := s.repository.ListTeamsForUser(ctx, machine.UnionID)
	if err != nil {
		// A storage outage is not an authoritative empty list. Do not send an
		// empty team-sync that would revoke daemon trust.
		return err
	}
	teams := make([]Team, 0, len(docs))
	for _, doc := range docs {
		entry, exists, err := s.teamEntry(ctx, doc.ID, &doc)
		if err != nil {
			return err
		}
		if exists {
			teams = append(teams, entry)
		}
	}
	revision := Revision(teams)
	if revision == clientRevision {
		return nil
	}
	s.registry.SendToMachine(machineID, Message{Type: "team-sync", Rev: revision, Teams: teams})
	return nil
}

func (s *Service) PushToMembers(ctx context.Context, teamID string) error {
	s.Invalidate(teamID)
	team, err := s.repository.GetTeam(ctx, teamID)
	if errors.Is(err, store.ErrNotFound) {
		return nil
	}
	if err != nil {
		return err
	}
	for _, machine := range s.registry.ListForUnionIDs(team.Members) {
		if machine.TeamSyncRev == nil {
			continue
		}
		if err := s.MaybeSendTeamSync(ctx, machine.MachineID, *machine.TeamSyncRev); err != nil {
			slog.Warn("push team sync", "teamId", teamID, "machineId", machine.MachineID, "error", err)
		}
	}
	return nil
}

func (s *Service) teamEntry(ctx context.Context, teamID string, provided *store.TeamDoc) (Team, bool, error) {
	s.mu.Lock()
	if cached, ok := s.cache[teamID]; ok && time.Since(cached.at) < teamCacheTTL {
		s.mu.Unlock()
		return cloneTeam(cached.team), true, nil
	}
	s.mu.Unlock()

	var team store.TeamDoc
	if provided != nil {
		team = *provided
	} else {
		var err error
		team, err = s.repository.GetTeam(ctx, teamID)
		if errors.Is(err, store.ErrNotFound) {
			return Team{}, false, nil
		}
		if err != nil {
			return Team{}, false, err
		}
	}
	hallID := team.HallChatID
	if hallID == "" {
		hallID = s.ensureHall(ctx, team)
	}

	bots := make([]Bot, 0, len(team.Bots))
	docCache := make(map[string]*store.MachineDoc)
	var unlearnedLive []TeachCandidate
	for _, ref := range team.Bots {
		live, liveOK := s.liveMachine(ref.MachineID)
		info := ResolveBotInfo(ref, live, liveOK, s.machineDoc(ctx, docCache, ref.MachineID))
		bots = append(bots, info)
		// Only live bots are re-taught: an offline daemon cannot observe the
		// mention and would just burn an attempt.
		if info.UnionID == "" && info.Name != "" && liveHasBot(live, liveOK, ref.AppID) {
			unlearnedLive = append(unlearnedLive, TeachCandidate{AppID: ref.AppID, Name: info.Name})
		}
	}
	if hallID != "" && len(unlearnedLive) > 0 {
		if names := s.PickHallTeachBackfill(team.ID, unlearnedLive, time.Now()); len(names) > 0 {
			s.scheduleHallTeach(team, hallID, names)
		}
	}
	chatIDs := []string{}
	if hallID != "" {
		chatIDs = append(chatIDs, hallID)
		chatIDs = append(chatIDs, team.GroupChatIDs...)
	}
	entry := Team{
		TeamID: team.ID, TeamName: team.Name, GroupChatIDs: chatIDs,
		Bots: bots, MemberUnionIDs: cloneStrings(team.Members),
	}
	s.mu.Lock()
	s.cache[teamID] = cachedTeam{at: time.Now(), team: cloneTeam(entry)}
	s.mu.Unlock()
	return entry, true, nil
}

func (s *Service) ensureHall(ctx context.Context, team store.TeamDoc) string {
	s.mu.Lock()
	writeEnabled := s.writeEnabled
	last := s.hallAttempts[team.ID]
	if !writeEnabled || s.feishu == nil || !s.feishu.Configured() || (!last.IsZero() && time.Since(last) < hallRetryDelay) {
		s.mu.Unlock()
		return ""
	}
	s.hallAttempts[team.ID] = time.Now()
	s.mu.Unlock()

	appIDs := make([]string, 0, len(team.Bots))
	for _, bot := range team.Bots {
		appIDs = append(appIDs, bot.AppID)
	}
	chatID, invalid, err := s.feishu.CreateHallGroup(ctx, team.Name, appIDs)
	if err != nil || chatID == "" {
		slog.Warn("create team hall", "teamId", team.ID, "invalidBots", len(invalid), "error", err)
		return ""
	}
	won, err := s.repository.CompareAndSetTeamHallChat(ctx, team.ID, "", chatID)
	if err == nil && won {
		s.Invalidate(team.ID)
		return chatID
	}
	if token, tokenErr := s.feishu.TenantAccessToken(ctx); tokenErr == nil {
		_ = s.feishu.DisbandChat(ctx, token, chatID)
	}
	latest, getErr := s.repository.GetTeam(ctx, team.ID)
	if getErr == nil {
		return latest.HallChatID
	}
	return ""
}

// SyncHallMembers maintains hall membership after team bots change (the
// /api/teams/:id/bots hook): build a missing hall, rebuild a dissolved one,
// teach unlearned bots their union_id, and best-effort remove bots. Like the
// TS hook it only reports a failure to load the team; Feishu-side failures
// are logged and self-heal on later beats.
func (s *Service) SyncHallMembers(ctx context.Context, teamID string, addAppIDs, removeAppIDs []string) error {
	s.Invalidate(teamID)
	team, err := s.repository.GetTeam(ctx, teamID)
	if errors.Is(err, store.ErrNotFound) {
		return nil
	}
	if err != nil {
		return err
	}
	if !s.feishuWritable() {
		return nil
	}
	if team.HallChatID == "" {
		s.mu.Lock()
		delete(s.hallAttempts, teamID) // a user-driven change bypasses the retry window
		s.mu.Unlock()
		built := s.ensureHall(ctx, team)
		// CreateHallGroup pulled the existing bots in but taught nobody; teach
		// once here or bots added before the hall existed may never learn.
		if built != "" {
			s.markHallTeachAttempt(teamID)
			_ = s.PushToMembers(ctx, teamID) // the next heartbeat self-heals
			token, err := s.feishu.TenantAccessToken(ctx)
			if err != nil {
				slog.Warn("teach hall after build", "teamId", teamID, "error", err)
				return nil
			}
			team.HallChatID = built
			s.teachHallBotUnions(ctx, token, team, built, nil)
		}
		return nil
	}
	token, err := s.feishu.TenantAccessToken(ctx)
	if err != nil {
		slog.Warn("hall maintenance token", "teamId", teamID, "error", err)
		return nil
	}
	hallChatID := team.HallChatID
	if len(addAppIDs) > 0 {
		invalid, _ := s.feishu.AddBotsToChat(ctx, token, team.HallChatID, addAppIDs)
		// Every add rejected: the hall is probably gone. Confirm, then rebuild
		// with all team bots.
		if len(invalid) == len(addAppIDs) && s.feishu.GetChatStatus(ctx, token, team.HallChatID) == feishu.ChatGone {
			all := make([]string, 0, len(team.Bots))
			for _, bot := range team.Bots {
				all = append(all, bot.AppID)
			}
			newID, _, createErr := s.feishu.CreateHallGroup(ctx, team.Name, all)
			if createErr == nil && newID != "" {
				won, casErr := s.repository.CompareAndSetTeamHallChat(ctx, teamID, team.HallChatID, newID)
				if casErr == nil && won {
					hallChatID = newID
				} else {
					// Concurrent loser: another pod rebuilt first.
					_ = s.feishu.DisbandChat(ctx, token, newID)
				}
				s.Invalidate(teamID)
			} else {
				slog.Warn("rebuild team hall", "teamId", teamID, "error", createErr)
			}
		} else if len(invalid) > 0 {
			slog.Warn("add bots to hall partially failed", "teamId", teamID, "invalid", invalid)
		}
		// Push team-sync before the @ so the new bot already recognises the
		// hall and does not raise a grant card for the platform message.
		s.markHallTeachAttempt(teamID)
		_ = s.PushToMembers(ctx, teamID)
		s.teachHallBotUnions(ctx, token, team, hallChatID, nil)
	}
	if len(removeAppIDs) > 0 {
		// Best effort, like removeBotsFromChat: a leftover member is harmless
		// because trust follows the roster, not hall membership.
		if err := s.feishu.RemoveBotsFromChat(ctx, token, hallChatID, removeAppIDs); err != nil {
			slog.Warn("remove bots from hall", "teamId", teamID, "error", err)
		}
	}
	return nil
}

// TeachCandidate is a live team bot whose roster entry has no union_id yet.
type TeachCandidate struct {
	AppID string
	Name  string
}

// PickHallTeachBackfill ports pickHallTeachBackfill: it returns the bot names
// to @ on this beat (empty = do not send) and records the attempt (team
// timestamp + per-bot count) when it fires.
func (s *Service) PickHallTeachBackfill(teamID string, candidates []TeachCandidate, now time.Time) []string {
	s.mu.Lock()
	defer s.mu.Unlock()
	eligible := make([]TeachCandidate, 0, len(candidates))
	for _, candidate := range candidates {
		if s.hallTeachAttempts[teamID+":"+candidate.AppID] < hallTeachMaxAttempts {
			eligible = append(eligible, candidate)
		}
	}
	if len(eligible) == 0 {
		return []string{}
	}
	if last, ok := s.hallTeachAt[teamID]; ok && now.Sub(last) < hallTeachRetry {
		return []string{}
	}
	s.hallTeachAt[teamID] = now
	names := make([]string, 0, len(eligible))
	seen := make(map[string]struct{}, len(eligible))
	for _, candidate := range eligible {
		s.hallTeachAttempts[teamID+":"+candidate.AppID]++
		if _, dup := seen[candidate.Name]; !dup {
			seen[candidate.Name] = struct{}{}
			names = append(names, candidate.Name)
		}
	}
	return names
}

// markHallTeachAttempt defers the backfill window after an event-driven @
// (bot added / hall built) so the same beat does not @ twice.
func (s *Service) markHallTeachAttempt(teamID string) {
	s.mu.Lock()
	s.hallTeachAt[teamID] = time.Now()
	s.mu.Unlock()
}

func (s *Service) feishuWritable() bool {
	s.mu.Lock()
	writeEnabled := s.writeEnabled
	s.mu.Unlock()
	return writeEnabled && s.feishu != nil && s.feishu.Configured()
}

// scheduleHallTeach runs the backfill @ after teachDelay, detached from the
// heartbeat that triggered it. The @ is a Feishu message, so it honours the
// canary write switch like every other hall write.
func (s *Service) scheduleHallTeach(team store.TeamDoc, hallChatID string, names []string) {
	if !s.feishuWritable() {
		return
	}
	only := make(map[string]bool, len(names))
	for _, name := range names {
		only[name] = true
	}
	time.AfterFunc(s.teachDelay, func() {
		if !s.feishuWritable() {
			return
		}
		ctx, cancel := context.WithTimeout(context.Background(), hallTeachTimeout)
		defer cancel()
		token, err := s.feishu.TenantAccessToken(ctx)
		if err != nil {
			slog.Warn("hall teach backfill", "teamId", team.ID, "error", err)
			return
		}
		s.teachHallBotUnions(ctx, token, team, hallChatID, only)
	})
}

// teachHallBotUnions @s the hall bots whose roster entry still lacks a
// union_id so they learn it from mentions[].union_id. Team bots and hall
// members are matched by name (the members endpoint returns no app_id).
func (s *Service) teachHallBotUnions(ctx context.Context, token string, team store.TeamDoc, hallChatID string, onlyNames map[string]bool) {
	if len(team.Bots) == 0 {
		return
	}
	docCache := make(map[string]*store.MachineDoc)
	unlearned := make(map[string]bool)
	for _, ref := range team.Bots {
		live, liveOK := s.liveMachine(ref.MachineID)
		info := ResolveBotInfo(ref, live, liveOK, s.machineDoc(ctx, docCache, ref.MachineID))
		if info.UnionID == "" && info.Name != "" && (onlyNames == nil || onlyNames[info.Name]) {
			unlearned[info.Name] = true
		}
	}
	if len(unlearned) == 0 {
		return
	}
	var targets []string
	for _, bot := range s.feishu.ListHallBots(ctx, token, hallChatID) {
		if unlearned[bot.Name] {
			targets = append(targets, bot.OpenID)
		}
	}
	if len(targets) == 0 {
		return
	}
	s.feishu.SendHallTeachMention(ctx, token, hallChatID, targets)
}

// ResolveBotInfo ports resolveBotInfo: the bot's union_id and name come from
// the live registry entry when the bot is connected, else from the persisted
// MachineDoc. The owner is a credential boundary and always comes from the
// current MachineDoc — never from the bot or a possibly stale connection
// (a long-lived control connection may carry an older owner for a while
// after an ownership transfer). machine is nil when the document is missing
// or unreadable.
func ResolveBotInfo(ref store.TeamBotRef, live tunnel.MachineConn, liveOK bool, machine *store.MachineDoc) Bot {
	owner := ""
	if machine != nil {
		owner = machine.UnionID
	}
	if liveOK {
		for _, bot := range live.Bots {
			if bot.AppID == ref.AppID {
				return Bot{AppID: ref.AppID, UnionID: bot.UnionID, Name: bot.Name, OwnerUnionID: owner}
			}
		}
	}
	info := Bot{AppID: ref.AppID, OwnerUnionID: owner}
	if machine != nil {
		for _, bot := range machine.Bots {
			if bot.AppID == ref.AppID {
				info.UnionID, info.Name = bot.UnionID, bot.Name
				break
			}
		}
	}
	return info
}

func (s *Service) liveMachine(machineID string) (tunnel.MachineConn, bool) {
	if s.registry == nil {
		return tunnel.MachineConn{}, false
	}
	return s.registry.Get(machineID)
}

func liveHasBot(live tunnel.MachineConn, ok bool, appID string) bool {
	if !ok {
		return false
	}
	for _, bot := range live.Bots {
		if bot.AppID == appID {
			return true
		}
	}
	return false
}

// machineDoc is getMachineDoc behind a per-aggregation cache that also
// remembers misses; any read failure counts as "no document" like the TS
// getMachineDoc (it never yields an owner, so it cannot widen trust).
func (s *Service) machineDoc(ctx context.Context, cache map[string]*store.MachineDoc, machineID string) *store.MachineDoc {
	if doc, ok := cache[machineID]; ok {
		return doc
	}
	var result *store.MachineDoc
	if doc, err := s.repository.GetMachine(ctx, machineID); err == nil {
		result = &doc
	}
	cache[machineID] = result
	return result
}

// cloneTeam deep-copies a cached entry. The slices are always non-nil so a
// cache hit still marshals [] (TS arrays), never null.
func cloneTeam(in Team) Team {
	in.GroupChatIDs = cloneStrings(in.GroupChatIDs)
	in.Bots = append(make([]Bot, 0, len(in.Bots)), in.Bots...)
	in.MemberUnionIDs = cloneStrings(in.MemberUnionIDs)
	return in
}

func cloneStrings(in []string) []string {
	return append(make([]string, 0, len(in)), in...)
}
