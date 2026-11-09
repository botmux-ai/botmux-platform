package storetest

import (
	"crypto/rand"
	"encoding/json"
	"strings"
	"testing"
	"time"

	"github.com/botmux-ai/botmux-platform/internal/credential"
	"github.com/botmux-ai/botmux-platform/internal/store"
	"go.mongodb.org/mongo-driver/bson"
	"go.mongodb.org/mongo-driver/bson/bsontype"
)

// RunRepository drives the production repositories on top of the database
// under test. The expected values are the observable results on
// store.NewMemoryDatabase, which runs the same suite.
func RunRepository(t *testing.T, newDB NewDatabase, opts ...Option) {
	cfg := newConfig(opts)
	t.Run("Machines", func(t *testing.T) { testMachines(t, newDB(t)) })
	t.Run("UsersAndTeams", func(t *testing.T) { testTeams(t, newDB(t)) })
	t.Run("Devices", func(t *testing.T) { testDevices(t, newDB(t)) })
	t.Run("DesktopSessionFences", func(t *testing.T) { testDesktopFences(t, newDB(t)) })
	t.Run("Credentials", func(t *testing.T) { testCredentials(t, newDB(t)) })
	t.Run("Issues", func(t *testing.T) { testIssues(t, newDB(t), cfg) })
}

func machineIDs(docs []store.MachineDoc) []string {
	ids := make([]string, 0, len(docs))
	for _, d := range docs {
		ids = append(ids, d.ID)
	}
	return sortedStrings(ids)
}

func testMachines(t *testing.T, db store.DocumentDatabase) {
	ctx := testContext(t)
	repo := store.NewDocumentRepository(provider{db})
	must(t, repo.EnsureIndexes(ctx), "ensure indexes")
	must(t, repo.EnsureIndexes(ctx), "ensure indexes again")

	bind := func(machineID, unionID, name string, want store.BindResult) {
		t.Helper()
		got, err := repo.BindMachineCAS(ctx, machineID, unionID, name)
		must(t, err, "bind "+machineID)
		if got != want {
			t.Fatalf("bind %s by %s = %s, want %s", machineID, unionID, got, want)
		}
	}
	bind("m1", "u1", "Alice", store.BindCreated)
	bind("m1", "u1", "Alice 2", store.BindRebound)
	bind("m1", "u2", "Bob", store.BindConflictOwner)
	bind("m2", "u1", "Alice", store.BindCreated)
	bind("m3", "u2", "Bob", store.BindCreated)

	m1, err := repo.GetMachine(ctx, "m1")
	must(t, err, "get m1")
	if m1.UnionID != "u1" || m1.OwnerName != "Alice 2" || m1.Status != store.MachineStatusActive || m1.BotmuxVersion != "unknown" ||
		m1.Memberships == nil || len(m1.Memberships) != 0 || m1.BoundAt <= 0 || m1.LastSeen != 0 {
		t.Fatalf("bound m1 = %+v", m1)
	}
	var raw bson.Raw
	must(t, db.Collection("machines").FindOne(ctx, store.Document{"_id": "m1"}, &raw), "raw m1")
	wantType(t, raw, "boundAt", bsontype.Double)
	wantType(t, raw, "lastSeen", bsontype.Int32)
	wantType(t, raw, "dashboardPort", bsontype.Int32)

	showInTeam := true
	openID := "ou_bot"
	register := store.RegisterMachine{
		MachineID: "m1", UnionID: "u1", Name: "box", BotmuxVersion: "1.2.3", DashboardPort: 7000,
		Memberships: []store.MembershipInfo{{TeamID: "t1", TeamName: "Team"}},
		Bots: []store.BotInfo{{AppID: "cli_a", Name: "A", OpenID: &openID, ShowInTeam: &showInTeam,
			Specialties: store.BotSpecialties{"go", "review"}}},
		LastSeen: 1000,
	}
	must(t, repo.PersistRegister(ctx, register), "register m1")
	foreign := register
	foreign.UnionID = "u2"
	wantErr(t, repo.PersistRegister(ctx, foreign), store.ErrNotFound, "register by a foreign owner")
	version := "1.2.4"
	must(t, repo.PersistHeartbeat(ctx, "m1", store.HeartbeatUpdate{BotmuxVersion: &version, LastSeen: 2000}), "heartbeat m1")
	wantErr(t, repo.PersistHeartbeat(ctx, "missing", store.HeartbeatUpdate{LastSeen: 1}), store.ErrNotFound, "heartbeat missing")

	m1, err = repo.GetMachine(ctx, "m1")
	must(t, err, "get m1 after register")
	if m1.Name != "box" || m1.BotmuxVersion != "1.2.4" || m1.DashboardPort != 7000 || m1.LastSeen != 2000 ||
		len(m1.Bots) != 1 || m1.Bots[0].OpenID == nil || *m1.Bots[0].OpenID != openID || m1.Bots[0].ShowInTeam == nil || !*m1.Bots[0].ShowInTeam {
		t.Fatalf("registered m1 = %+v", m1)
	}
	wantEqual(t, m1.Bots[0].Specialties, store.BotSpecialties{"go", "review"}, "registered specialties")
	wantEqual(t, m1.Memberships, []store.MembershipInfo{{TeamID: "t1", TeamName: "Team"}}, "registered memberships")

	teamMachines, err := repo.ListMachinesForTeam(ctx, "t1")
	must(t, err, "list for team")
	wantEqual(t, machineIDs(teamMachines), []string{"m1"}, "machines for team")

	coManager := store.MachineCoManager{UnionID: "u1", Name: "Alice", Scopes: []string{store.DeviceScopeMachinesRead}, GrantedAt: 5, GrantedBy: "u2", ViaTeamID: "t1"}
	must(t, repo.SetMachineCoManagers(ctx, "m3", "u2", []store.MachineCoManager{coManager}), "set co-managers")
	wantErr(t, repo.SetMachineCoManagers(ctx, "m3", "u1", nil), store.ErrNotFound, "co-managers by a non-owner")
	coManaged, err := repo.ListMachinesCoManagedBy(ctx, "u1")
	must(t, err, "list co-managed")
	wantEqual(t, machineIDs(coManaged), []string{"m3"}, "co-managed machines")
	wantEqual(t, coManaged[0].CoManagers, []store.MachineCoManager{coManager}, "stored co-managers")

	all, err := repo.ListMachinesForUsers(ctx, []string{"u1", "u2"})
	must(t, err, "list for users")
	wantEqual(t, machineIDs(all), []string{"m1", "m2", "m3"}, "machines for users")
	none, err := repo.ListMachinesForUsers(ctx, nil)
	must(t, err, "list for no users")
	if none == nil || len(none) != 0 {
		t.Fatalf("list for no users = %#v", none)
	}
	nobody, err := repo.ListMachinesForUser(ctx, "nobody")
	must(t, err, "list for nobody")
	if nobody == nil || len(nobody) != 0 {
		t.Fatalf("list for nobody = %#v (must be a non-nil empty slice)", nobody)
	}

	must(t, repo.RenameMachine(ctx, "m2", "Desk"), "rename m2")
	wantErr(t, repo.RenameMachine(ctx, "missing", "x"), store.ErrNotFound, "rename missing")
	cached, err := repo.LookupMachine(ctx, "m2", store.AuthorityCacheOptions{PositiveTTL: time.Second})
	must(t, err, "lookup m2")
	if cached.DisplayName != "Desk" {
		t.Fatalf("lookup m2 = %+v", cached)
	}
	_, err = repo.LookupMachine(ctx, "missing", store.AuthorityCacheOptions{PositiveTTL: time.Second})
	wantErr(t, err, store.ErrNotFound, "lookup missing")

	must(t, repo.RetireMachine(ctx, "m2"), "retire m2")
	must(t, repo.RetireMachine(ctx, "never-bound"), "retire missing succeeds")
	bind("m2", "u1", "Alice", store.BindRetired)
	wantErr(t, repo.PersistHeartbeat(ctx, "m2", store.HeartbeatUpdate{LastSeen: 3000}), store.ErrNotFound, "heartbeat retired")
	retired, err := repo.GetMachine(ctx, "m2")
	must(t, err, "get retired")
	if !retired.Retired() {
		t.Fatalf("m2 = %+v", retired)
	}
	mine, err := repo.ListMachinesForUser(ctx, "u1")
	must(t, err, "list for u1")
	wantEqual(t, machineIDs(mine), []string{"m1"}, "u1 machines exclude the tombstone")

	samples, err := repo.ListMachineVersionSamples(ctx)
	must(t, err, "version samples")
	byID := map[string]store.MachineVersionSample{}
	for _, s := range samples {
		byID[s.MachineID] = s
	}
	wantEqual(t, byID, map[string]store.MachineVersionSample{
		"m1": {MachineID: "m1", UnionID: "u1", BotmuxVersion: "1.2.4", LastSeen: 2000},
		"m3": {MachineID: "m3", UnionID: "u2", BotmuxVersion: "unknown", LastSeen: 0},
	}, "version samples")

	affected, err := repo.DropCoManagerFromTeamMachines(ctx, "t-other", "u1")
	must(t, err, "drop co-manager via another team")
	if len(affected) != 0 {
		t.Fatalf("drop via another team affected %v", affected)
	}
	affected, err = repo.DropCoManagerFromTeamMachines(ctx, "t1", "u1")
	must(t, err, "drop co-manager")
	wantEqual(t, affected, []string{"m3"}, "dropped co-manager machines")
	m3, err := repo.GetMachine(ctx, "m3")
	must(t, err, "get m3")
	if len(m3.CoManagers) != 0 {
		t.Fatalf("co-managers after drop = %+v", m3.CoManagers)
	}
	_, err = repo.GetMachine(ctx, "missing")
	wantErr(t, err, store.ErrNotFound, "get missing machine")
}

func testTeams(t *testing.T, db store.DocumentDatabase) {
	ctx := testContext(t)
	repo := store.NewDocumentRepository(provider{db})

	must(t, repo.UpsertUserProfile(ctx, store.UserProfile{ID: "u1", Name: "Alice", Avatar: "https://a", UpdatedAt: 10}), "profile u1")
	must(t, repo.UpsertUserProfile(ctx, store.UserProfile{ID: "u1", Name: "Alice B", UpdatedAt: 20}), "profile u1 again")
	must(t, repo.UpsertUserProfile(ctx, store.UserProfile{ID: "u2", Name: "Bob", UpdatedAt: 30}), "profile u2")
	profiles, err := repo.GetUserProfiles(ctx, []string{"u1", "u2", "missing"})
	must(t, err, "get profiles")
	wantEqual(t, profiles, map[string]store.UserProfile{
		"u1": {ID: "u1", Name: "Alice B", Avatar: "https://a", UpdatedAt: 20},
		"u2": {ID: "u2", Name: "Bob", UpdatedAt: 30},
	}, "profiles")

	must(t, repo.CreateTeam(ctx, store.TeamDoc{ID: "t1", Name: "Team", Members: []string{"u1"}, CreatedBy: "u1", CreatedAt: 1000}), "create t1")
	wantErr(t, repo.CreateTeam(ctx, store.TeamDoc{ID: "t1", Name: "Again", CreatedBy: "u9"}), store.ErrConflict, "duplicate team")
	must(t, repo.CreateTeam(ctx, store.TeamDoc{ID: "t2", Name: "Other", CreatedBy: "u3"}), "create t2 with nil members")

	must(t, repo.AddTeamMember(ctx, "t1", "u2"), "add u2")
	must(t, repo.AddTeamMember(ctx, "t1", "u2"), "add u2 again")
	must(t, repo.AddTeamMember(ctx, "t2", "u1"), "add u1 to t2 (stored [] members)")
	must(t, repo.UpdateTeamBots(ctx, "t1", []store.TeamBotRef{{MachineID: "m1", AppID: "a1"}, {MachineID: "m3", AppID: "a3"}}, nil), "add bots")
	must(t, repo.UpdateTeamBots(ctx, "t1", []store.TeamBotRef{{MachineID: "m1", AppID: "a1"}}, []store.TeamBotRef{{MachineID: "m3", AppID: "a3"}}), "add dup + remove bot")
	must(t, repo.AddTeamGroupChat(ctx, "t1", "chat1"), "group chat")
	must(t, repo.AddTeamGroupChat(ctx, "t1", "chat1"), "group chat again")

	cas := func(expected, replacement string, want bool) {
		t.Helper()
		ok, err := repo.CompareAndSetTeamHallChat(ctx, "t1", expected, replacement)
		must(t, err, "hall CAS")
		if ok != want {
			t.Fatalf("hall CAS %q -> %q = %v, want %v", expected, replacement, ok, want)
		}
	}
	cas("", "h1", true)
	cas("", "h2", false)
	cas("h1", "h2", true)

	must(t, repo.AddPendingInvite(ctx, "t1", store.PendingInvite{UnionID: "u3", Name: "C", InvitedBy: "u1", InvitedAt: 100}), "invite u3")
	must(t, repo.AddPendingInvite(ctx, "t1", store.PendingInvite{UnionID: "u3", OpenID: "ou3", Name: "C", InvitedBy: "u1", InvitedAt: 200}), "re-invite u3")
	must(t, repo.AddPendingInvite(ctx, "t1", store.PendingInvite{UnionID: "u4", Name: "D", InvitedBy: "u1", InvitedAt: 50}), "invite u4")
	must(t, repo.AddPendingInvite(ctx, "t1", store.PendingInvite{UnionID: "u5", Name: "E", InvitedBy: "u1", InvitedAt: 300}), "invite u5")
	team, err := repo.GetTeam(ctx, "t1")
	must(t, err, "get t1")
	wantEqual(t, team.PendingInvites, []store.PendingInvite{
		{UnionID: "u3", OpenID: "ou3", Name: "C", InvitedBy: "u1", InvitedAt: 200},
		{UnionID: "u4", Name: "D", InvitedBy: "u1", InvitedAt: 50},
		{UnionID: "u5", Name: "E", InvitedBy: "u1", InvitedAt: 300},
	}, "pending invites")
	must(t, repo.PrunePendingInvites(ctx, "t1", 150, []string{"u3"}), "prune invites")
	must(t, repo.RemovePendingInvite(ctx, "t1", "nobody"), "remove absent invite")

	admins, err := repo.UpdateTeamAdmins(ctx, "t1", []string{" u2 ", "u1", "uX", "u2"}, nil)
	must(t, err, "update admins")
	wantEqual(t, admins, []string{"u2"}, "normalized admins")
	_, err = repo.UpdateTeamAdmins(ctx, "missing", nil, nil)
	wantErr(t, err, store.ErrNotFound, "admins of a missing team")
	must(t, repo.UpdateTeamIssueSettings(ctx, "t1", store.TeamIssueSettingsPatch{
		SetRepoPresets: true, RepoPresets: []any{map[string]any{"id": "r1", "label": " Repo ", "remote": "org/repo"}},
		SetIssueForm: true, IssueForm: nil,
	}), "issue settings")

	team, err = repo.GetTeam(ctx, "t1")
	must(t, err, "get t1 after updates")
	wantEqual(t, team.Members, []string{"u1", "u2"}, "members")
	wantEqual(t, team.Bots, []store.TeamBotRef{{MachineID: "m1", AppID: "a1"}}, "team bots")
	wantEqual(t, team.GroupChatIDs, []string{"chat1"}, "group chats")
	wantEqual(t, team.PendingInvites, []store.PendingInvite{{UnionID: "u5", Name: "E", InvitedBy: "u1", InvitedAt: 300}}, "invites after prune")
	wantEqual(t, team.Admins, []string{"u2"}, "admins")
	wantEqual(t, team.RepoPresets, []store.TeamRepoPreset{{ID: "r1", Label: "Repo", Remote: "org/repo"}}, "repo presets")
	if team.HallChatID != "h2" || team.IssueForm == nil || len(team.IssueForm.Fields) == 0 || team.CreatedAt != 1000 {
		t.Fatalf("team = %+v form=%+v", team, team.IssueForm)
	}

	must(t, repo.RemoveTeamMember(ctx, "t1", "u2"), "remove u2")
	must(t, repo.RemoveMachineFromTeamBots(ctx, "m1"), "remove machine from bots")
	must(t, repo.RemoveUserBotsFromTeam(ctx, "t1", []string{"m-none"}), "remove user bots")
	must(t, repo.RenameTeam(ctx, "t1", "Renamed"), "rename")
	team, err = repo.GetTeam(ctx, "t1")
	must(t, err, "get t1 after removals")
	if team.Name != "Renamed" || len(team.Bots) != 0 {
		t.Fatalf("team after removals = %+v", team)
	}
	wantEqual(t, team.Members, []string{"u1"}, "members after removal")
	if len(team.Admins) != 0 {
		t.Fatalf("removed member kept admin: %v", team.Admins)
	}

	mine, err := repo.ListTeamsForUser(ctx, "u1")
	must(t, err, "teams for u1")
	ids := []string{}
	for _, tm := range mine {
		ids = append(ids, tm.ID)
	}
	wantEqual(t, sortedStrings(ids), []string{"t1", "t2"}, "teams for u1")
	empty, err := repo.ListTeamsForUser(ctx, "nobody")
	must(t, err, "teams for nobody")
	if empty == nil || len(empty) != 0 {
		t.Fatalf("teams for nobody = %#v", empty)
	}
	teams, err := repo.GetTeams(ctx, []string{"t1", "missing"})
	must(t, err, "get teams")
	if len(teams) != 1 || teams["t1"].Name != "Renamed" {
		t.Fatalf("get teams = %+v", teams)
	}

	must(t, repo.DeleteTeam(ctx, "t1"), "delete t1")
	wantErr(t, repo.DeleteTeam(ctx, "t1"), store.ErrNotFound, "delete t1 again")
	wantErr(t, repo.AddTeamMember(ctx, "t1", "u2"), store.ErrNotFound, "add member to deleted team")
	_, err = repo.GetTeam(ctx, "t1")
	wantErr(t, err, store.ErrNotFound, "get deleted team")
}

func testDevices(t *testing.T, db store.DocumentDatabase) {
	ctx := testContext(t)
	repo := store.NewDocumentRepository(provider{db})
	must(t, repo.EnsureIndexes(ctx), "ensure indexes")
	now := time.Now().UnixMilli()

	device := store.DeviceDoc{
		ID: "d1", UnionID: "u1", OwnerName: "Alice", DeviceKind: store.DeviceKindDesktopIDE, DeviceName: "laptop",
		Scopes: store.DeviceMVPScopes(), CredentialVersion: 1, Status: store.DeviceStatusActive,
		RefreshFamilyID: "f1", RefreshGeneration: 1, RefreshTokenHash: "h1", RefreshCurrentJTI: "j1",
		EnrolledAt: now, DeviceExp: now + 90*24*3600*1000, LastSeenAt: now, ApprovedVia: store.DeviceApprovedViaDeviceCode,
	}
	must(t, repo.CreateDevice(ctx, device), "create d1")
	wantErr(t, repo.CreateDevice(ctx, device), store.ErrConflict, "duplicate device")
	got, err := repo.GetDevice(ctx, "d1")
	must(t, err, "get d1")
	wantEqual(t, got, device, "stored device")

	rotate := func(hash string, generation int64, key string, at int64) store.RotateRefreshOutcome {
		t.Helper()
		out, err := repo.RotateDeviceRefresh(ctx, store.RotateDeviceRefreshInput{
			DeviceID: "d1", PresentedHash: hash, PresentedGeneration: generation, RetryKeyHash: key,
			NewHash: "h2", NewJTI: "j2", NowMS: at,
		})
		must(t, err, "rotate")
		return out
	}
	out := rotate("h1", 1, "k1", now+1)
	if out.Result != store.RotateRotated || out.Device == nil || out.Device.RefreshGeneration != 2 ||
		out.Device.PrevRefreshTokenHash != "h1" || out.Device.RefreshTokenHash != "h2" || out.Device.ReplayUntil != now+1+store.DefaultRefreshReplayWindowMS {
		t.Fatalf("rotation = %+v device=%+v", out.Result, out.Device)
	}
	if out := rotate("h1", 1, "k1", now+2); out.Result != store.RotateExactReplay {
		t.Fatalf("exact replay = %s", out.Result)
	}
	if out := rotate("h1", 1, "other", now+2); out.Result != store.RotateRefreshInProgress {
		t.Fatalf("in-progress replay = %s", out.Result)
	}
	if out := rotate("h2", 2, "k2", now+3); out.Result != store.RotateCurrentWithinWindow {
		t.Fatalf("current within window = %s", out.Result)
	}
	if out := rotate("h0", 0, "k", now+3); out.Result != store.RotateStaleGeneration {
		t.Fatalf("stale generation = %s", out.Result)
	}
	if out, err := repo.RotateDeviceRefresh(ctx, store.RotateDeviceRefreshInput{DeviceID: "missing", NowMS: now}); err != nil || out.Result != store.RotateNotFound {
		t.Fatalf("rotate missing = %+v %v", out, err)
	}

	must(t, repo.TouchDeviceLastSeen(ctx, "d1", now+10), "touch")
	devices, err := repo.ListDevicesForUser(ctx, "u1")
	must(t, err, "list devices")
	if len(devices) != 1 || devices[0].LastSeenAt != now+10 || devices[0].RefreshGeneration != 2 {
		t.Fatalf("devices = %+v", devices)
	}
	wantErr(t, repo.RevokeDevice(ctx, "d1", "u2"), store.ErrNotFound, "revoke by a non-owner")
	must(t, repo.RevokeDevice(ctx, "d1", "u1"), "revoke")
	must(t, repo.RevokeDevice(ctx, "d1", "u1"), "revoke is idempotent")
	if revokedNow, err := repo.ForceRevokeDevice(ctx, "d1"); err != nil || revokedNow {
		t.Fatalf("force revoke of a revoked device = %v %v", revokedNow, err)
	}
	got, err = repo.GetDevice(ctx, "d1")
	must(t, err, "get revoked")
	if got.Status != store.DeviceStatusRevoked || got.CredentialVersion != 2 {
		t.Fatalf("revoked device = %+v", got)
	}
	var raw bson.Raw
	must(t, db.Collection("devices").FindOne(ctx, store.Document{"_id": "d1"}, &raw), "raw device")
	wantType(t, raw, "credentialVersion", bsontype.Int32)
	wantType(t, raw, "refreshGeneration", bsontype.Int32)
	wantType(t, raw, "enrolledAt", bsontype.Double)

	grant := store.DeviceGrantDoc{
		ID: "g1", Kind: store.DeviceGrantKindF1MachineEnroll, UnionID: "u1", MachineID: "m1", DeviceKind: store.DeviceKindDesktopIDE,
		DeviceName: "laptop", PollSecretHash: "ps", Status: store.DeviceGrantPending, CreatedAt: now, ExpiresAt: now + 60_000,
	}
	must(t, repo.CreateDeviceGrant(ctx, grant), "create grant")
	wantErr(t, repo.CreateDeviceGrant(ctx, grant), store.ErrConflict, "duplicate grant")
	wantErr(t, repo.ApproveDeviceGrant(ctx, "g1", "u2", "d2", now), store.ErrConflict, "approve by a non-owner")
	wantErr(t, repo.ApproveDeviceGrant(ctx, "g1", "u1", "d2", now+60_000), store.ErrConflict, "approve after expiry")
	must(t, repo.ApproveDeviceGrant(ctx, "g1", "u1", "d2", now+1), "approve")
	wantErr(t, repo.DenyDeviceGrant(ctx, "g1", "u1", now+2), store.ErrConflict, "deny after approve")
	wantErr(t, repo.ConsumeDeviceGrant(ctx, "g1", "wrong", now+2), store.ErrConflict, "consume with a wrong secret")
	must(t, repo.ConsumeDeviceGrant(ctx, "g1", "ps", now+2), "consume")
	wantErr(t, repo.ConsumeDeviceGrant(ctx, "g1", "ps", now+3), store.ErrConflict, "consume twice")
	g, err := repo.GetDeviceGrant(ctx, "g1")
	must(t, err, "get grant")
	if g.Status != store.DeviceGrantConsumed || g.DeviceID != "d2" || g.DecidedAt != now+1 || g.Scopes == nil ||
		!g.ExpireAt.Equal(time.UnixMilli(now+60_000)) {
		t.Fatalf("grant = %+v", g)
	}
	_, err = repo.GetDeviceGrant(ctx, "missing")
	wantErr(t, err, store.ErrNotFound, "missing grant")
}

func testDesktopFences(t *testing.T, db store.DocumentDatabase) {
	ctx := testContext(t)
	repo := store.NewDocumentRepository(provider{db})
	must(t, repo.EnsureIndexes(ctx), "ensure indexes")
	exp := time.Now().Add(time.Minute).UnixMilli()

	must(t, repo.ConsumeProxyTicket(ctx, "jti-1", exp), "consume ticket")
	err := repo.ConsumeProxyTicket(ctx, "jti-1", exp)
	wantErr(t, err, store.ErrReplayed, "ticket replay")
	wantErr(t, err, store.ErrConflict, "ticket replay wraps ErrConflict")
	must(t, repo.ConsumeDesktopAuthCode(ctx, "code-1", exp), "consume code")
	wantErr(t, repo.ConsumeDesktopAuthCode(ctx, "code-1", exp), store.ErrReplayed, "code replay")
	// The two fences are independent collections.
	must(t, repo.ConsumeDesktopAuthCode(ctx, "jti-1", exp), "same id in another fence")

	status, err := repo.GetDesktopSessionFamilyStatus(ctx, "sid-1", store.AuthorityCacheOptions{})
	must(t, err, "family status")
	if status != store.DesktopFamilyActive {
		t.Fatalf("fresh family = %s", status)
	}
	far := time.Now().Add(400 * 24 * time.Hour).UnixMilli()
	must(t, repo.RevokeDesktopSessionFamily(ctx, "sid-1", far), "revoke family")
	must(t, repo.RevokeDesktopSessionFamily(ctx, "sid-1", exp), "revoke family with an earlier expiry")
	status, err = repo.GetDesktopSessionFamilyStatus(ctx, "sid-1", store.AuthorityCacheOptions{PositiveTTL: time.Second})
	must(t, err, "family status after revoke")
	if status != store.DesktopFamilyRevoked {
		t.Fatalf("revoked family = %s", status)
	}
	var fence struct {
		ExpiresAt int64     `bson:"expiresAt,truncate"`
		ExpireAt  time.Time `bson:"expireAt"`
		RevokedAt int64     `bson:"revokedAt,truncate"`
	}
	must(t, db.Collection("desktop_session_revocations").FindOne(ctx, store.Document{"_id": "sid-1"}, &fence), "raw fence")
	if fence.ExpiresAt != far || !fence.ExpireAt.Equal(time.UnixMilli(far)) || fence.RevokedAt <= 0 {
		t.Fatalf("$max must keep the later expiry: %+v (want %d)", fence, far)
	}
}

func testCredentials(t *testing.T, db store.DocumentDatabase) {
	ctx := testContext(t)
	clk := newClock()
	cs := store.NewCredentialStoreWithClock(provider{db}, clk.Now)
	must(t, cs.EnsureIndexes(ctx), "ensure indexes")
	must(t, cs.EnsureIndexes(ctx), "ensure indexes again")
	kek := make([]byte, 32)
	if _, err := rand.Read(kek); err != nil {
		t.Fatal(err)
	}
	seal := func(unionID string, platform store.CredentialPlatform, text string) credential.Sealed {
		t.Helper()
		sealed, err := credential.Seal(kek, []byte(text), credential.AAD(unionID, string(platform)))
		must(t, err, "seal")
		return sealed
	}
	lark := store.CredentialPlatformLarkCLI
	id := store.CredentialID("u1", lark)

	created, err := cs.Upsert(ctx, store.UpsertCredentialInput{UnionID: "u1", Platform: lark, Kind: store.CredentialKindLarkOAuth,
		Sealed: seal("u1", lark, "tok1"), Meta: store.CredentialMeta{AppID: "cli_x", Account: "alice"}, RefreshExpiresAt: clk.ms() + 1000})
	must(t, err, "upsert create")
	if created.ID != id || created.Version != 1 || !created.ConsentTeams.All || created.CreatedAt != clk.ms() ||
		created.Status != store.CredentialActive || created.RefreshExpiresAt != clk.ms()+1000 || created.Meta.AppID != "cli_x" {
		t.Fatalf("created = %+v", created)
	}
	must(t, cs.SetConsent(ctx, "u1", lark, store.ConsentToTeams([]string{"t1"})), "set consent")
	wantErr(t, cs.SetConsent(ctx, "u9", lark, store.ConsentAll()), store.ErrNotFound, "consent without credential")

	createdAt := clk.ms()
	clk.advance(time.Minute)
	updated, err := cs.Upsert(ctx, store.UpsertCredentialInput{UnionID: "u1", Platform: lark, Kind: store.CredentialKindLarkOAuth, Sealed: seal("u1", lark, "tok2")})
	must(t, err, "upsert update")
	if updated.Version != 2 || updated.CreatedAt != createdAt || updated.UpdatedAt != clk.ms() || updated.ConsentTeams.All {
		t.Fatalf("updated = %+v", updated)
	}
	wantEqual(t, updated.ConsentTeams.Teams, []string{"t1"}, "consent preserved by upsert")

	v2 := int64(2)
	cs.MarkReauthRequired(ctx, id, "refresh_rejected", &v2)
	marked, err := cs.Get(ctx, "u1", lark)
	must(t, err, "get marked")
	if marked.Status != store.CredentialReauthRequired || marked.StatusReason != "refresh_rejected" {
		t.Fatalf("marked = %+v", marked)
	}
	wantErr(t, cs.UpdateSealed(ctx, id, 1, seal("u1", lark, "stale"), store.CredentialSealedPatch{}), store.ErrConflict, "stale CAS writeback")
	meta := store.CredentialMeta{AppID: "cli_y"}
	must(t, cs.UpdateSealed(ctx, id, 2, seal("u1", lark, "tok3"), store.CredentialSealedPatch{RefreshExpiresAt: 42, Meta: &meta}), "CAS writeback")
	stale := int64(2)
	cs.MarkReauthRequired(ctx, id, "late", &stale)
	got, err := cs.Get(ctx, "u1", lark)
	must(t, err, "get after writeback")
	if got.Version != 3 || got.Status != store.CredentialActive || got.StatusReason != "" || got.RefreshExpiresAt != 42 || got.Meta != meta {
		t.Fatalf("after writeback = %+v", got)
	}
	plain, ok := credential.Open([][]byte{kek}, got.Sealed, credential.AAD("u1", string(lark)))
	if !ok || string(plain) != "tok3" {
		t.Fatalf("sealed credential did not round-trip: %q %v", plain, ok)
	}
	var raw bson.Raw
	must(t, db.Collection("credentials").FindOne(ctx, store.Document{"_id": id}, &raw), "raw credential")
	wantType(t, raw, "version", bsontype.Int32)
	wantType(t, raw, "updatedAt", bsontype.Double)
	wantType(t, raw, "consentTeams", bsontype.Array)

	device := store.CredentialPlatform("device-cli")
	noTeams := store.ConsentToTeams(nil)
	_, err = cs.Upsert(ctx, store.UpsertCredentialInput{UnionID: "u1", Platform: device, Kind: "device-archive",
		Sealed: seal("u1", device, "archive"), DefaultConsent: &noTeams})
	must(t, err, "upsert device login")
	_, err = cs.Upsert(ctx, store.UpsertCredentialInput{UnionID: "u2", Platform: lark, Kind: store.CredentialKindLarkOAuth, Sealed: seal("u2", lark, "other")})
	must(t, err, "upsert u2")
	must(t, db.Collection("credentials").InsertOne(ctx, store.Document{"_id": "u1::junk", "unionId": "u1", "platform": "nope"}), "insert malformed")
	list, err := cs.ListForUser(ctx, "u1")
	must(t, err, "list")
	platforms := []string{}
	for _, c := range list {
		platforms = append(platforms, string(c.Platform))
		if c.Platform == device && (c.ConsentTeams.All || c.ConsentTeams.Teams == nil || len(c.ConsentTeams.Teams) != 0) {
			t.Fatalf("device login consent = %+v", c.ConsentTeams)
		}
	}
	wantEqual(t, sortedStrings(platforms), []string{"device-cli", "lark-cli"}, "listed platforms (malformed skipped)")
	cs.TouchUse(ctx, id, "m1")
	got, err = cs.Get(ctx, "u1", lark)
	must(t, err, "get after touch")
	if got.LastUsedMachineID != "m1" || got.LastUsedAt != clk.ms() {
		t.Fatalf("touched = %+v", got)
	}

	for i, machine := range []string{"m1", "m2", "m3"} {
		clk.advance(time.Second)
		outcome := store.CredentialGranted
		if i == 2 {
			outcome = store.CredentialRefused
		}
		cs.AppendGrant(ctx, store.CredentialGrantInput{UnionID: "u1", Platform: lark, MachineID: machine, OwnerUnionID: "u2",
			AppID: "cli_x", SessionID: "s" + machine, Outcome: outcome})
	}
	grants, err := cs.ListGrantsForUser(ctx, "u1", 2)
	must(t, err, "list grants")
	if len(grants) != 2 || grants[0].MachineID != "m3" || grants[1].MachineID != "m2" || grants[0].At != clk.ms() ||
		!grants[0].ExpireAt.Equal(time.UnixMilli(clk.ms()+90*24*3600*1000)) {
		t.Fatalf("grants = %+v", grants)
	}
	noGrants, err := cs.ListGrantsForUser(ctx, "nobody", 0)
	must(t, err, "list grants for nobody")
	if noGrants == nil || len(noGrants) != 0 {
		t.Fatalf("grants for nobody = %#v", noGrants)
	}
	for machine, want := range map[string]bool{"m1": true, "m3": false, "m9": false} {
		has, err := cs.HasGrantedOnMachine(ctx, "u1", machine)
		must(t, err, "has granted")
		if has != want {
			t.Fatalf("HasGrantedOnMachine(%s) = %v, want %v", machine, has, want)
		}
	}

	p1, err := cs.PutPending(ctx, "u1", device, seal("u1", device, "p1"), "https://sso/1")
	must(t, err, "put pending 1")
	p2, err := cs.PutPending(ctx, "u1", device, seal("u1", device, "p2"), "https://sso/2")
	must(t, err, "put pending 2")
	_, err = cs.GetPending(ctx, "u1", p1.ID)
	wantErr(t, err, store.ErrNotFound, "older pending login replaced")
	_, err = cs.GetPending(ctx, "u2", p2.ID)
	wantErr(t, err, store.ErrNotFound, "pending login of another person")
	current, err := cs.GetPendingForUser(ctx, "u1")
	must(t, err, "pending for user")
	if current.ID != p2.ID || current.AuthURL != "https://sso/2" || current.CreatedAt != clk.ms() || !current.ExpireAt.Equal(p2.ExpireAt) {
		t.Fatalf("pending = %+v want %+v", current, p2)
	}
	clk.advance(2 * time.Hour)
	_, err = cs.GetPendingForUser(ctx, "u1")
	wantErr(t, err, store.ErrNotFound, "logically expired pending login")
	cs.DeletePending(ctx, p2.ID)

	must(t, cs.Delete(ctx, "u1", lark), "delete")
	wantErr(t, cs.Delete(ctx, "u1", lark), store.ErrNotFound, "delete again")
	_, err = cs.Get(ctx, "u1", lark)
	wantErr(t, err, store.ErrNotFound, "get deleted")
	_, err = cs.Get(ctx, "u1", "junk")
	wantErr(t, err, store.ErrInvalid, "malformed credential")
}

func issueEventKinds(events []store.IssueEventDoc) []string {
	kinds := make([]string, 0, len(events))
	for _, e := range events {
		kinds = append(kinds, string(e.Kind))
	}
	return kinds
}

func testIssues(t *testing.T, db store.DocumentDatabase, cfg config) {
	ctx := testContext(t)
	clk := newClock()
	is := store.NewIssueStoreWithClock(provider{db}, clk.Now)
	must(t, is.EnsureIndexes(ctx), "ensure indexes")
	must(t, is.EnsureIndexes(ctx), "ensure indexes again")

	fields := store.IssueCustomFields{{ID: "prio", Value: "high"}, {ID: "areas", Value: []string{"api", "ui"}}}
	created, err := is.Create(ctx, store.CreateIssueInput{TeamID: "t1", Title: "Fix login", Body: "body", Labels: []string{},
		TargetRepoID: "r1", TargetRepoLabel: "repo", CustomFields: fields, SuggestedAssigneeUnionID: "u2", CreatedBy: "u1", CreatedByName: "Alice"})
	must(t, err, "create")
	_, err = is.Create(ctx, store.CreateIssueInput{TeamID: "t1", Title: "   "})
	wantErr(t, err, store.ErrInvalid, "blank title")

	issue, err := is.Get(ctx, created.ID)
	must(t, err, "get")
	if issue.Title != "Fix login" || issue.Status != store.IssueOpen || issue.Labels == nil || len(*issue.Labels) != 0 ||
		issue.SuggestedAssigneeUnionID == nil || *issue.SuggestedAssigneeUnionID != "u2" || issue.Rev != 1 || issue.StateRev != 1 ||
		issue.EventSeq != 1 || issue.CreatedAt != clk.ms() || issue.TargetRepoLabel != "repo" {
		t.Fatalf("stored issue = %+v", issue)
	}
	if cfg.unorderedSubdocuments && len(issue.CustomFields) == 2 && issue.CustomFields[0].ID == "areas" {
		issue.CustomFields[0], issue.CustomFields[1] = issue.CustomFields[1], issue.CustomFields[0]
	}
	wantEqual(t, issue.CustomFields, fields, "custom fields")
	_, err = is.Get(ctx, "missing")
	wantErr(t, err, store.ErrNotFound, "get missing")

	title, clear := "Fix login v2", ""
	patched, err := is.Patch(ctx, issue.ID, 1, store.IssuePatch{Title: &title, TargetRepoLabel: &clear})
	must(t, err, "patch")
	if patched.Rev != 2 || patched.Title != title || patched.TargetRepoLabel != "" || patched.TargetRepoID != "r1" {
		t.Fatalf("patched = %+v", patched)
	}
	_, err = is.Patch(ctx, issue.ID, 1, store.IssuePatch{Title: &title})
	wantErr(t, err, store.ErrRevConflict, "stale patch")

	claimed, err := is.Claim(ctx, issue.ID, store.ClaimIssueInput{ClaimID: "c1", UnionID: "u-a", Name: "A", MachineID: "m1",
		Agent: bson.D{{Key: "kind", Value: "codex"}}, RepoLabel: "", ExpectedStateRev: 1})
	must(t, err, "claim")
	if claimed.Status != store.IssueClaimed || claimed.StateRev != 2 || claimed.ClaimEpochCounter != 1 || claimed.Claim == nil ||
		claimed.Claim.ClaimEpoch != 1 || claimed.Claim.Bound || claimed.Claim.LeaseExpiresAt != clk.ms()+store.ClaimLeaseMS || claimed.Claim.RepoLabel != nil {
		t.Fatalf("claimed = %+v claim=%+v", claimed, claimed.Claim)
	}
	encoded, err := json.Marshal(claimed)
	must(t, err, "issue JSON")
	if !strings.Contains(string(encoded), `"agent":{"kind":"codex"}`) || strings.Contains(string(encoded), "repoLabel") {
		t.Fatalf("claimed issue JSON = %s", encoded)
	}
	_, err = is.Claim(ctx, issue.ID, store.ClaimIssueInput{ClaimID: "c2", UnionID: "u-b", MachineID: "m2", ExpectedStateRev: 2})
	wantErr(t, err, store.ErrAlreadyClaimed, "competing claim")
	_, err = is.Patch(ctx, issue.ID, 2, store.IssuePatch{Title: &title})
	wantErr(t, err, store.ErrIssueLocked, "patch while claimed")

	bound, err := is.Bind(ctx, issue.ID, store.BindIssueInput{ClaimID: "c1", LocalTaskRef: "rt::task", ExpectedStateRev: 2, LocalTaskLabel: "chat"})
	must(t, err, "bind")
	if !bound.Claim.Bound || bound.Claim.LocalTaskRef != "rt::task" || bound.Claim.LocalTaskLabel != "chat" || bound.Claim.LocalTaskURL != "" ||
		bound.Claim.LeaseExpiresAt != clk.ms()+store.ActivationLeaseMS || bound.StateRev != 3 || bound.Claim.ClaimID != "c1" {
		t.Fatalf("bound = %+v claim=%+v", bound, bound.Claim)
	}
	status := func(seq float64, target store.IssueStatus, stateRev int64) (store.IssueDoc, error) {
		return is.StatusWriteback(ctx, issue.ID, store.StatusWritebackInput{UnionID: "u-a", ClaimID: "c1", ClaimEpoch: 1,
			SourceSeq: seq, Target: target, ExpectedStateRev: float64(stateRev)})
	}
	progress, err := status(1, store.IssueInProgress, 3)
	must(t, err, "in progress")
	if progress.Status != store.IssueInProgress || progress.Claim == nil || progress.Claim.LastSourceSeq != 1 || progress.StateRev != 4 {
		t.Fatalf("in progress = %+v claim=%+v", progress, progress.Claim)
	}
	again, err := status(1, store.IssueInReview, 4)
	must(t, err, "duplicate sourceSeq")
	if again.Status != store.IssueInProgress || again.StateRev != 4 {
		t.Fatalf("duplicate sourceSeq changed the issue: %+v", again)
	}
	attention, err := status(2, store.IssueNeedsAttention, 4)
	must(t, err, "needs attention")
	if attention.AttentionReason != store.AttentionRunTimeout || attention.AttentionSince != clk.ms() {
		t.Fatalf("needs attention = %+v", attention)
	}
	_, err = status(3, store.IssueInProgress, 5)
	wantErr(t, err, store.ErrInvalidTransition, "unblock a non-blocked issue")
	done, err := status(3, store.IssueOpen, 5)
	must(t, err, "release to open")
	if done.Status != store.IssueOpen || done.Claim != nil || done.AttentionReason != "" || done.AttentionSince != 0 {
		t.Fatalf("released = %+v", done)
	}
	var raw bson.Raw
	must(t, db.Collection("issues").FindOne(ctx, store.Document{"_id": issue.ID}, &raw), "raw issue")
	wantMissing(t, raw, "claim")
	wantMissing(t, raw, "attentionReason")
	wantMissing(t, raw, "targetRepoLabel")
	wantType(t, raw, "stateRev", bsontype.Int32)

	events, err := is.ListEvents(ctx, issue.ID, 0)
	must(t, err, "events")
	wantEqual(t, issueEventKinds(events), []string{"created", "claimed", "bound", "status", "status", "released"}, "event kinds")
	for i, e := range events {
		if e.Seq != int64(i+1) || e.IssueID != issue.ID || e.TeamID != "t1" {
			t.Fatalf("event %d = %+v", i, e)
		}
	}
	tail, err := is.ListEvents(ctx, issue.ID, 4.5)
	must(t, err, "events after cursor")
	wantEqual(t, issueEventKinds(tail), []string{"status", "released"}, "events after 4.5")
	noEvents, err := is.ListEvents(ctx, "missing", 0)
	must(t, err, "events for missing")
	if noEvents == nil || len(noEvents) != 0 {
		t.Fatalf("events for missing = %#v", noEvents)
	}

	archived, err := is.Archive(ctx, issue.ID, "u1")
	must(t, err, "archive")
	if archived.ArchivedAt != clk.ms() {
		t.Fatalf("archived = %+v", archived)
	}

	// Lease sweeper: an unbound expired reservation reopens, a bound one
	// needs attention; a second sweep is a no-op.
	unbound, err := is.Create(ctx, store.CreateIssueInput{TeamID: "t1", Title: "unbound", CreatedBy: "u1"})
	must(t, err, "create unbound")
	_, err = is.Claim(ctx, unbound.ID, store.ClaimIssueInput{ClaimID: "c-u", UnionID: "u-a", MachineID: "m1", ExpectedStateRev: 1})
	must(t, err, "claim unbound")
	boundIssue, err := is.Create(ctx, store.CreateIssueInput{TeamID: "t1", Title: "bound", CreatedBy: "u1"})
	must(t, err, "create bound")
	_, err = is.Claim(ctx, boundIssue.ID, store.ClaimIssueInput{ClaimID: "c-b", UnionID: "u-a", MachineID: "m1", ExpectedStateRev: 1})
	must(t, err, "claim bound")
	_, err = is.Bind(ctx, boundIssue.ID, store.BindIssueInput{ClaimID: "c-b", LocalTaskRef: "rt::b", ExpectedStateRev: 2})
	must(t, err, "bind bound")

	listed, err := is.ListForTeam(ctx, "t1", false)
	must(t, err, "list without archived")
	ids := []string{}
	for _, d := range listed {
		ids = append(ids, d.ID)
	}
	wantEqual(t, sortedStrings(ids), sortedStrings([]string{unbound.ID, boundIssue.ID}), "list excludes archived")
	withArchived, err := is.ListForTeam(ctx, "t1", true)
	must(t, err, "list with archived")
	if len(withArchived) != 3 {
		t.Fatalf("list with archived = %d", len(withArchived))
	}
	other, err := is.ListForTeam(ctx, "t-none", true)
	must(t, err, "list other team")
	if other == nil || len(other) != 0 {
		t.Fatalf("list other team = %#v", other)
	}

	clk.advance(time.Duration(store.ClaimLeaseMS)*time.Millisecond + time.Second)
	swept, err := is.SweepExpiredLeases(ctx)
	must(t, err, "sweep")
	wantEqual(t, swept, store.IssueSweepResult{ToOpen: 1, ToAttention: 1}, "sweep result")
	swept, err = is.SweepExpiredLeases(ctx)
	must(t, err, "sweep again")
	wantEqual(t, swept, store.IssueSweepResult{}, "second sweep")
	reopened, err := is.Get(ctx, unbound.ID)
	must(t, err, "get swept unbound")
	if reopened.Status != store.IssueOpen || reopened.Claim != nil {
		t.Fatalf("swept unbound = %+v", reopened)
	}
	stuck, err := is.Get(ctx, boundIssue.ID)
	must(t, err, "get swept bound")
	if stuck.Status != store.IssueNeedsAttention || stuck.AttentionReason != store.AttentionClaimActivateTimeout || stuck.Claim == nil {
		t.Fatalf("swept bound = %+v", stuck)
	}
	detached, err := is.ForceDetach(ctx, boundIssue.ID, "u1", float64(stuck.StateRev))
	must(t, err, "force detach")
	if detached.Status != store.IssueReopened || detached.Claim != nil || detached.ClaimEpochCounter != 2 {
		t.Fatalf("detached = %+v", detached)
	}
}
