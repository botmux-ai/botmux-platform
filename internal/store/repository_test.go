package store

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"
	"unicode/utf8"
)

// Local development runs DocumentRepository on the Mongo-semantics memory
// database, so these tests exercise exactly the production query/update
// documents (they replace the deleted MemoryRepository tests).

type testClock struct {
	mu  sync.Mutex
	now time.Time
}

func (c *testClock) Now() time.Time {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.now
}

func (c *testClock) Advance(d time.Duration) {
	c.mu.Lock()
	c.now = c.now.Add(d)
	c.mu.Unlock()
}

// toggleProvider simulates a configured store that goes down.
type toggleProvider struct {
	db   DocumentDatabase
	down atomic.Bool
}

func (p *toggleProvider) Database(context.Context) (DocumentDatabase, error) {
	if p.down.Load() {
		return nil, ErrUnavailable
	}
	return p.db, nil
}

type memoryRepo struct {
	*DocumentRepository
	db       *MemoryDatabase
	clock    *testClock
	provider *toggleProvider
}

func newMemoryRepo(t *testing.T) memoryRepo {
	t.Helper()
	db := NewMemoryDatabase()
	provider := &toggleProvider{db: db}
	clock := &testClock{now: time.UnixMilli(1_700_000_000_000)}
	s := NewDocumentRepository(provider)
	s.now = clock.Now
	if err := s.EnsureIndexes(context.Background()); err != nil {
		t.Fatal(err)
	}
	return memoryRepo{DocumentRepository: s, db: db, clock: clock, provider: provider}
}

func (r memoryRepo) bind(t *testing.T, machineID, unionID string) {
	t.Helper()
	if result, err := r.BindMachineCAS(context.Background(), machineID, unionID, unionID+"-name"); err != nil || result != BindCreated {
		t.Fatalf("bind %s = %v %v", machineID, result, err)
	}
}

func (r memoryRepo) rawMachine(t *testing.T, machineID string) map[string]any {
	t.Helper()
	for _, doc := range r.db.MemoryCollection(collectionMachines).Documents() {
		if doc["_id"] == machineID {
			return doc
		}
	}
	t.Fatalf("machine %s not stored", machineID)
	return nil
}

func TestMemoryModeMachineLifecycle(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	s := newMemoryRepo(t)
	s.bind(t, "machine-1", "user-1")
	if err := s.RenameMachine(ctx, "machine-1", "Desk"); err != nil {
		t.Fatal(err)
	}
	if err := s.PersistRegister(ctx, RegisterMachine{
		MachineID: "machine-1", UnionID: "user-1", OwnerName: "Owner", Name: "host",
		BotmuxVersion: "1.2.3", DashboardPort: 7891, Memberships: []MembershipInfo{{TeamID: "team-1", TeamName: "T"}},
		Bots: []BotInfo{{AppID: "app-1", Name: "Bot"}}, LastSeen: 200,
	}); err != nil {
		t.Fatal(err)
	}
	m, err := s.GetMachine(ctx, "machine-1")
	if err != nil {
		t.Fatal(err)
	}
	if m.DisplayName != "Desk" || m.BoundAt != 1_700_000_000_000 || m.LastSeen != 200 || m.Status != MachineStatusActive ||
		m.OwnerName != "user-1-name" || m.Name != "host" || m.DashboardPort != 7891 {
		t.Fatalf("unexpected machine: %+v", m)
	}
	empty := []BotInfo{}
	if err := s.PersistHeartbeat(ctx, m.ID, HeartbeatUpdate{Bots: &empty, LastSeen: 300}); err != nil {
		t.Fatal(err)
	}
	m, _ = s.GetMachine(ctx, m.ID)
	if len(m.Bots) != 0 || m.LastSeen != 300 || len(m.Memberships) != 1 {
		t.Fatalf("heartbeat not applied: %+v", m)
	}
	byTeam, err := s.ListMachinesForTeam(ctx, "team-1")
	if err != nil || len(byTeam) != 1 {
		t.Fatalf("team lookup: %#v %v", byTeam, err)
	}
	byUser, err := s.ListMachinesForUser(ctx, "user-1")
	if err != nil || len(byUser) != 1 {
		t.Fatalf("user lookup: %#v %v", byUser, err)
	}
	none, err := s.ListMachinesForUser(ctx, "nobody")
	if err != nil || none == nil || len(none) != 0 {
		t.Fatalf("empty list must be an empty slice: %#v %v", none, err)
	}
}

func TestRenameMachinePreservesUTF8(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	s := newMemoryRepo(t)
	s.bind(t, "machine-1", "user-1")
	if err := s.RenameMachine(ctx, "machine-1", strings.Repeat("机", 65)); err != nil {
		t.Fatal(err)
	}
	m, err := s.GetMachine(ctx, "machine-1")
	if err != nil {
		t.Fatal(err)
	}
	if !utf8.ValidString(m.DisplayName) || utf8.RuneCountInString(m.DisplayName) != 64 {
		t.Fatalf("displayName is not a valid 64-rune string: %q", m.DisplayName)
	}
	if err := s.RenameMachine(ctx, "missing", "x"); !errors.Is(err, ErrNotFound) {
		t.Fatalf("rename missing = %v", err)
	}
}

func TestMemoryModeBSONShapesMatchNodeDriver(t *testing.T) {
	t.Parallel()
	s := newMemoryRepo(t)
	s.bind(t, "machine-1", "user-1")
	raw := s.rawMachine(t, "machine-1")
	// Node's BSON serializer stores Date.now() as a double and small integers
	// as int32; keep the physical schema identical during mixed rollout.
	if _, ok := raw["boundAt"].(float64); !ok {
		t.Fatalf("boundAt = %T", raw["boundAt"])
	}
	for _, field := range []string{"lastSeen", "dashboardPort"} {
		if _, ok := raw[field].(int32); !ok {
			t.Fatalf("%s = %T", field, raw[field])
		}
	}
	if raw["status"] != MachineStatusActive || raw["botmuxVersion"] != "unknown" || raw["name"] != "" {
		t.Fatalf("fresh machine = %#v", raw)
	}
	if memberships, ok := raw["memberships"].([]any); !ok || len(memberships) != 0 {
		t.Fatalf("memberships = %#v", raw["memberships"])
	}
	if err := s.SetMachineCoManagers(context.Background(), "machine-1", "user-1", []MachineCoManager{{UnionID: "mate", Name: "M", GrantedAt: 1_700_000_000_001, GrantedBy: "user-1"}}); err != nil {
		t.Fatal(err)
	}
	cm := s.rawMachine(t, "machine-1")["coManagers"].([]any)[0].(map[string]any)
	if _, ok := cm["grantedAt"].(float64); !ok {
		t.Fatalf("grantedAt = %T", cm["grantedAt"])
	}
	if scopes, ok := cm["scopes"].([]any); !ok || len(scopes) != 0 {
		t.Fatalf("nil scopes must be stored as an empty array: %#v", cm["scopes"])
	}
	if _, ok := cm["viaTeamId"]; ok {
		t.Fatalf("empty viaTeamId must be omitted: %#v", cm)
	}
}

func TestMemoryModeTeamLifecycleAndCopies(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	s := newMemoryRepo(t)
	team := TeamDoc{ID: "team-1", Name: "T", Members: []string{"owner"}, CreatedBy: "owner", CreatedAt: 1}
	if err := s.CreateTeam(ctx, team); err != nil {
		t.Fatal(err)
	}
	if err := s.CreateTeam(ctx, team); !errors.Is(err, ErrConflict) {
		t.Fatalf("duplicate team = %v", err)
	}
	team.Members[0] = "mutated"
	if err := s.AddTeamMember(ctx, "team-1", "member"); err != nil {
		t.Fatal(err)
	}
	if err := s.UpdateTeamBots(ctx, "team-1", []TeamBotRef{{MachineID: "m1", AppID: "a1"}, {MachineID: "m1", AppID: "a1"}}, nil); err != nil {
		t.Fatal(err)
	}
	ok, err := s.CompareAndSetTeamHallChat(ctx, "team-1", "", "chat-1")
	if err != nil || !ok {
		t.Fatalf("CAS: %v %v", ok, err)
	}
	ok, err = s.CompareAndSetTeamHallChat(ctx, "team-1", "", "chat-2")
	if err != nil || ok {
		t.Fatalf("stale CAS: %v %v", ok, err)
	}
	if err := s.AddPendingInvite(ctx, "team-1", PendingInvite{UnionID: "old", InvitedAt: 10}); err != nil {
		t.Fatal(err)
	}
	if err := s.AddPendingInvite(ctx, "team-1", PendingInvite{UnionID: "new", InvitedAt: 30}); err != nil {
		t.Fatal(err)
	}
	if err := s.PrunePendingInvites(ctx, "team-1", 20, []string{"member"}); err != nil {
		t.Fatal(err)
	}
	got, err := s.GetTeam(ctx, "team-1")
	if err != nil {
		t.Fatal(err)
	}
	if len(got.Members) != 2 || got.Members[0] != "owner" || len(got.Bots) != 1 || len(got.PendingInvites) != 1 || got.PendingInvites[0].UnionID != "new" || got.HallChatID != "chat-1" {
		t.Fatalf("unexpected team: %+v", got)
	}
	got.Members[0] = "corrupt"
	again, _ := s.GetTeam(ctx, "team-1")
	if again.Members[0] != "owner" {
		t.Fatal("GetTeam leaked internal slice")
	}
	teams, err := s.ListTeamsForUser(ctx, "member")
	if err != nil || len(teams) != 1 {
		t.Fatalf("list teams = %#v %v", teams, err)
	}
	if err := s.AddTeamMember(ctx, "missing", "x"); !errors.Is(err, ErrNotFound) {
		t.Fatalf("missing team = %v", err)
	}
}

func TestMemoryModeCreateTeamOmitsEmptyArrays(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	s := newMemoryRepo(t)
	if err := s.CreateTeam(ctx, TeamDoc{ID: "t", Name: "T", CreatedBy: "u"}); err != nil {
		t.Fatal(err)
	}
	raw := s.db.MemoryCollection(collectionTeams).Documents()[0]
	for _, field := range []string{"bots", "groupChatIds", "pendingInvites", "admins", "hallChatId"} {
		if _, ok := raw[field]; ok {
			t.Fatalf("%s must be omitted, got %#v", field, raw)
		}
	}
	if members, ok := raw["members"].([]any); !ok || len(members) != 0 {
		t.Fatalf("members = %#v", raw["members"])
	}
	// Array operators keep working on the omitted fields.
	if err := s.AddTeamGroupChat(ctx, "t", "chat"); err != nil {
		t.Fatal(err)
	}
	if err := s.UpdateTeamBots(ctx, "t", []TeamBotRef{{MachineID: "m", AppID: "a"}}, nil); err != nil {
		t.Fatal(err)
	}
}

func TestMemoryModeConcurrentMembers(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	s := newMemoryRepo(t)
	if err := s.CreateTeam(ctx, TeamDoc{ID: "t"}); err != nil {
		t.Fatal(err)
	}
	var wg sync.WaitGroup
	for i := 0; i < 50; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			if err := s.AddTeamMember(ctx, "t", fmt.Sprintf("u-%d", i)); err != nil {
				t.Error(err)
			}
		}(i)
	}
	wg.Wait()
	got, _ := s.GetTeam(ctx, "t")
	if len(got.Members) != 50 {
		t.Fatalf("members=%d", len(got.Members))
	}
}

func TestRetiredMachineIsATombstone(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	s := newMemoryRepo(t)
	s.bind(t, "m1", "alice")
	s.bind(t, "m2", "alice")
	member := []MembershipInfo{{TeamID: "team", TeamName: "T"}}
	for _, id := range []string{"m1", "m2"} {
		if err := s.PersistRegister(ctx, RegisterMachine{MachineID: id, UnionID: "alice", BotmuxVersion: "2.0.0", Memberships: member, LastSeen: 5}); err != nil {
			t.Fatal(err)
		}
	}
	if err := s.RetireMachine(ctx, "m1"); err != nil {
		t.Fatal(err)
	}
	doc, err := s.GetMachine(ctx, "m1")
	if err != nil || !doc.Retired() {
		t.Fatalf("retired doc = %+v %v", doc, err)
	}
	for name, list := range map[string]func() ([]MachineDoc, error){
		"user":  func() ([]MachineDoc, error) { return s.ListMachinesForUser(ctx, "alice") },
		"team":  func() ([]MachineDoc, error) { return s.ListMachinesForTeam(ctx, "team") },
		"users": func() ([]MachineDoc, error) { return s.ListMachinesForUsers(ctx, []string{"alice"}) },
	} {
		docs, err := list()
		if err != nil || len(docs) != 1 || docs[0].ID != "m2" {
			t.Fatalf("%s list = %+v %v", name, docs, err)
		}
	}
	samples, err := s.ListMachineVersionSamples(ctx)
	if err != nil || len(samples) != 1 || samples[0] != (MachineVersionSample{MachineID: "m2", UnionID: "alice", BotmuxVersion: "2.0.0", LastSeen: 5}) {
		t.Fatalf("samples = %+v %v", samples, err)
	}
	// A stale token can neither refresh nor resurrect the tombstone.
	if err := s.PersistRegister(ctx, RegisterMachine{MachineID: "m1", UnionID: "alice", LastSeen: 9}); !errors.Is(err, ErrNotFound) {
		t.Fatalf("register on tombstone = %v", err)
	}
	if err := s.PersistHeartbeat(ctx, "m1", HeartbeatUpdate{LastSeen: 9}); !errors.Is(err, ErrNotFound) {
		t.Fatalf("heartbeat on tombstone = %v", err)
	}
	if err := s.SetMachineCoManagers(ctx, "m1", "alice", nil); !errors.Is(err, ErrNotFound) {
		t.Fatalf("co-managers on tombstone = %v", err)
	}
	if doc, _ := s.GetMachine(ctx, "m1"); doc.LastSeen != 5 || !doc.Retired() {
		t.Fatalf("tombstone modified: %+v", doc)
	}
	// Retire is idempotent and succeeds for unknown ids.
	if err := s.RetireMachine(ctx, "m1"); err != nil {
		t.Fatal(err)
	}
	if err := s.RetireMachine(ctx, "unknown"); err != nil {
		t.Fatal(err)
	}
}

func TestPersistRegisterNeverCreatesOrTransfersOwnership(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	s := newMemoryRepo(t)
	if err := s.PersistRegister(ctx, RegisterMachine{MachineID: "unbound", UnionID: "alice", LastSeen: 1}); !errors.Is(err, ErrNotFound) {
		t.Fatalf("register unbound = %v", err)
	}
	if _, err := s.GetMachine(ctx, "unbound"); !errors.Is(err, ErrNotFound) {
		t.Fatalf("register must not upsert: %v", err)
	}
	s.bind(t, "m", "alice")
	if err := s.PersistRegister(ctx, RegisterMachine{MachineID: "m", UnionID: "mallory", OwnerName: "M", Name: "evil", LastSeen: 1}); !errors.Is(err, ErrNotFound) {
		t.Fatalf("foreign register = %v", err)
	}
	if doc, _ := s.GetMachine(ctx, "m"); doc.UnionID != "alice" || doc.Name != "" {
		t.Fatalf("ownership changed: %+v", doc)
	}
	// Legacy documents without a status field are treated as ACTIVE.
	if err := s.db.Collection(collectionMachines).InsertOne(ctx, Document{"_id": "legacy", "unionId": "bob", "ownerName": "Bob", "name": "",
		"botmuxVersion": "1.0.0", "dashboardPort": int32(0), "memberships": []any{}, "boundAt": 1.0, "lastSeen": 1.0}); err != nil {
		t.Fatal(err)
	}
	if err := s.PersistRegister(ctx, RegisterMachine{MachineID: "legacy", UnionID: "bob", Name: "host", LastSeen: 2}); err != nil {
		t.Fatalf("legacy register = %v", err)
	}
	if docs, err := s.ListMachinesForUser(ctx, "bob"); err != nil || len(docs) != 1 || docs[0].Status != "" || docs[0].Retired() {
		t.Fatalf("legacy list = %+v %v", docs, err)
	}
	if result, err := s.BindMachineCAS(ctx, "legacy", "bob", "Bob 2"); err != nil || result != BindRebound {
		t.Fatalf("legacy rebind = %v %v", result, err)
	}
}

func TestListMachinesForUsers(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	s := newMemoryRepo(t)
	s.bind(t, "a1", "alice")
	s.bind(t, "b1", "bob")
	s.bind(t, "c1", "carol")
	docs, err := s.ListMachinesForUsers(ctx, []string{"alice", "bob"})
	if err != nil || len(docs) != 2 {
		t.Fatalf("docs = %+v %v", docs, err)
	}
	// Empty input never touches the store (and is an authoritative empty).
	s.provider.down.Store(true)
	if docs, err := s.ListMachinesForUsers(ctx, nil); err != nil || docs == nil || len(docs) != 0 {
		t.Fatalf("empty input = %#v %v", docs, err)
	}
	if _, err := s.ListMachinesForUsers(ctx, []string{"alice"}); !errors.Is(err, ErrUnavailable) {
		t.Fatalf("degraded = %v", err)
	}
}

func coManager(unionID, via string) MachineCoManager {
	return MachineCoManager{UnionID: unionID, Name: strings.ToUpper(unionID), Scopes: []string{DeviceScopeMachinesRead, DeviceScopeSessionsOpen},
		GrantedAt: 1, GrantedBy: "owner", ViaTeamID: via}
}

func TestMachineCoManagers(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	s := newMemoryRepo(t)
	s.bind(t, "m1", "owner")
	s.bind(t, "m2", "owner")
	s.bind(t, "mine", "mate")
	if err := s.SetMachineCoManagers(ctx, "m1", "owner", []MachineCoManager{coManager("mate", "team-a")}); err != nil {
		t.Fatal(err)
	}
	if err := s.SetMachineCoManagers(ctx, "m2", "intruder", []MachineCoManager{coManager("mate", "team-a")}); !errors.Is(err, ErrNotFound) {
		t.Fatalf("non-owner write = %v", err)
	}
	if err := s.SetMachineCoManagers(ctx, "missing", "owner", nil); !errors.Is(err, ErrNotFound) {
		t.Fatalf("missing machine = %v", err)
	}
	// Abnormal data: mate is listed on a machine mate owns.
	if err := s.SetMachineCoManagers(ctx, "mine", "mate", []MachineCoManager{coManager("mate", "team-a")}); err != nil {
		t.Fatal(err)
	}
	docs, err := s.ListMachinesCoManagedBy(ctx, "mate")
	if err != nil || len(docs) != 1 || docs[0].ID != "m1" {
		t.Fatalf("co-managed = %+v %v", docs, err)
	}
	if cm := docs[0].CoManagers[0]; cm.Name != "MATE" || cm.GrantedAt != 1 || cm.GrantedBy != "owner" || cm.ViaTeamID != "team-a" || len(cm.Scopes) != 2 {
		t.Fatalf("co-manager round trip = %+v", docs[0].CoManagers)
	}
	// A removed co-manager loses access immediately even through the cache.
	cached := AuthorityCacheOptions{PositiveTTL: DesktopDashboardAuthCacheTTL}
	if doc, err := s.LookupMachine(ctx, "m1", cached); err != nil || len(doc.CoManagers) != 1 {
		t.Fatalf("lookup = %+v %v", doc, err)
	}
	if err := s.SetMachineCoManagers(ctx, "m1", "owner", []MachineCoManager{}); err != nil {
		t.Fatal(err)
	}
	if doc, err := s.LookupMachine(ctx, "m1", cached); err != nil || len(doc.CoManagers) != 0 {
		t.Fatalf("stale cache after revoke = %+v %v", doc, err)
	}
	if err := s.RetireMachine(ctx, "m2"); err != nil {
		t.Fatal(err)
	}
	if docs, _ := s.ListMachinesCoManagedBy(ctx, "mate"); len(docs) != 0 {
		t.Fatalf("emptied/retired machines listed: %+v", docs)
	}
}

// Store-level assertions of test/server-machine-comanagers.test.ts (team leave).
func TestDropCoManagerFromTeamMachines(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	s := newMemoryRepo(t)
	s.bind(t, "via-a", "owner")
	s.bind(t, "via-b", "owner")
	s.bind(t, "legacy", "owner")
	s.bind(t, "mine", "mate")
	s.bind(t, "retired", "owner")
	must := func(err error) {
		t.Helper()
		if err != nil {
			t.Fatal(err)
		}
	}
	must(s.SetMachineCoManagers(ctx, "via-a", "owner", []MachineCoManager{coManager("mate", "team-a"), coManager("other", "team-a")}))
	must(s.SetMachineCoManagers(ctx, "via-b", "owner", []MachineCoManager{coManager("mate", "team-b")}))
	must(s.SetMachineCoManagers(ctx, "legacy", "owner", []MachineCoManager{coManager("mate", "")}))
	must(s.SetMachineCoManagers(ctx, "mine", "mate", []MachineCoManager{coManager("mate", "team-a")}))
	must(s.SetMachineCoManagers(ctx, "retired", "owner", []MachineCoManager{coManager("mate", "team-a")}))
	must(s.RetireMachine(ctx, "retired"))

	cached := AuthorityCacheOptions{PositiveTTL: DesktopDashboardAuthCacheTTL}
	if _, err := s.LookupMachine(ctx, "via-a", cached); err != nil {
		t.Fatal(err)
	}
	affected, err := s.DropCoManagerFromTeamMachines(ctx, "team-a", "mate")
	if err != nil || len(affected) != 1 || affected[0] != "via-a" {
		t.Fatalf("affected = %v %v", affected, err)
	}
	viaA, _ := s.LookupMachine(ctx, "via-a", cached)
	if len(viaA.CoManagers) != 1 || viaA.CoManagers[0].UnionID != "other" {
		t.Fatalf("via team A must be dropped (cache invalidated): %+v", viaA.CoManagers)
	}
	for id, want := range map[string]int{"via-b": 1, "legacy": 1, "mine": 1, "retired": 1} {
		doc, _ := s.GetMachine(ctx, id)
		if len(doc.CoManagers) != want {
			t.Fatalf("%s co-managers = %+v", id, doc.CoManagers)
		}
	}
	// Empty team id never matches legacy entries without viaTeamId.
	if affected, err := s.DropCoManagerFromTeamMachines(ctx, "", "mate"); err != nil || len(affected) != 0 {
		t.Fatalf("empty team id = %v %v", affected, err)
	}
	s.provider.down.Store(true)
	if _, err := s.DropCoManagerFromTeamMachines(ctx, "team-b", "mate"); !errors.Is(err, ErrUnavailable) {
		t.Fatalf("degraded = %v", err)
	}
}

// Port of test/team-admin.test.ts plus the store write path.
func TestIsTeamAdmin(t *testing.T) {
	t.Parallel()
	cases := []struct {
		team TeamDoc
		user string
		want bool
	}{
		{TeamDoc{CreatedBy: "u1", Admins: []string{}}, "u1", true},
		{TeamDoc{CreatedBy: "u1"}, "u1", true},
		{TeamDoc{CreatedBy: "u1", Admins: []string{"u2", "u3"}}, "u2", true},
		{TeamDoc{CreatedBy: "u1", Admins: []string{"u2"}}, "u9", false},
		{TeamDoc{CreatedBy: "u1"}, "u2", false},
		{TeamDoc{CreatedBy: "u1", Admins: []string{}}, "u2", false},
	}
	for _, tc := range cases {
		if got := IsTeamAdmin(tc.team, tc.user); got != tc.want {
			t.Errorf("IsTeamAdmin(%+v, %s) = %v", tc.team, tc.user, got)
		}
	}
}

func TestUpdateTeamAdmins(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	s := newMemoryRepo(t)
	members := []string{"creator", "a", "b", "c"}
	for i := 0; i < 60; i++ {
		members = append(members, fmt.Sprintf("m%02d", i))
	}
	if err := s.CreateTeam(ctx, TeamDoc{ID: "t", Name: "T", Members: members, CreatedBy: "creator"}); err != nil {
		t.Fatal(err)
	}
	admins, err := s.UpdateTeamAdmins(ctx, "t", []string{" a ", "creator", "outsider", "a", "", "b"}, nil)
	if err != nil || strings.Join(admins, ",") != "a,b" {
		t.Fatalf("admins = %v %v", admins, err)
	}
	team, _ := s.GetTeam(ctx, "t")
	if strings.Join(team.Admins, ",") != "a,b" || !IsTeamAdmin(team, "b") || IsTeamAdmin(team, "c") {
		t.Fatalf("stored admins = %v", team.Admins)
	}
	// known is updated in place and capped at 50.
	known := team
	admins, err = s.UpdateTeamAdmins(ctx, "t", members, &known)
	if err != nil || len(admins) != 50 || len(known.Admins) != 50 || known.Admins[0] != "a" {
		t.Fatalf("capped = %d %v known=%d", len(admins), err, len(known.Admins))
	}
	// Leaving the team also drops admin rights.
	if err := s.RemoveTeamMember(ctx, "t", "a"); err != nil {
		t.Fatal(err)
	}
	team, _ = s.GetTeam(ctx, "t")
	if contains(team.Members, "a") || contains(team.Admins, "a") || len(team.Admins) != 49 {
		t.Fatalf("member/admin pull = %v / %v", team.Members, team.Admins)
	}
	if _, err := s.UpdateTeamAdmins(ctx, "missing", []string{"a"}, nil); !errors.Is(err, ErrNotFound) {
		t.Fatalf("missing team = %v", err)
	}
	if _, err := s.UpdateTeamAdmins(ctx, "missing", []string{"a"}, &TeamDoc{ID: "missing", Members: []string{"a"}}); !errors.Is(err, ErrNotFound) {
		t.Fatalf("missing known team = %v", err)
	}
}

func TestUpdateTeamIssueSettings(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	s := newMemoryRepo(t)
	if err := s.UpdateTeamIssueSettings(ctx, "missing", TeamIssueSettingsPatch{}); err != nil {
		t.Fatalf("empty patch must be a no-op: %v", err)
	}
	if err := s.UpdateTeamIssueSettings(ctx, "missing", TeamIssueSettingsPatch{SetRepoPresets: true}); !errors.Is(err, ErrNotFound) {
		t.Fatalf("missing team = %v", err)
	}
	if err := s.CreateTeam(ctx, TeamDoc{ID: "t", Name: "T", Members: []string{"u"}, CreatedBy: "u"}); err != nil {
		t.Fatal(err)
	}
	err := s.UpdateTeamIssueSettings(ctx, "t", TeamIssueSettingsPatch{
		SetRepoPresets: true, RepoPresets: []any{map[string]any{"id": "repo_a", "label": " platform "}, map[string]any{"label": ""}},
		SetIssueForm: true, IssueForm: map[string]any{"fields": []any{map[string]any{"id": "body", "type": "textarea", "label": "B", "required": true}}},
	})
	if err != nil {
		t.Fatal(err)
	}
	team, _ := s.GetTeam(ctx, "t")
	if len(team.RepoPresets) != 1 || team.RepoPresets[0] != (TeamRepoPreset{ID: "repo_a", Label: "platform"}) {
		t.Fatalf("presets = %+v", team.RepoPresets)
	}
	if team.IssueForm == nil || len(team.IssueForm.Fields) != 2 || team.IssueForm.Fields[0].ID != "title" || !team.IssueForm.Fields[1].IsRequired() {
		t.Fatalf("form = %+v", team.IssueForm)
	}
	// Explicit null still applies: empty presets, default form.
	if err := s.UpdateTeamIssueSettings(ctx, "t", TeamIssueSettingsPatch{SetRepoPresets: true, SetIssueForm: true}); err != nil {
		t.Fatal(err)
	}
	team, _ = s.GetTeam(ctx, "t")
	presets, form := ResolveTeamIssueSettings(team)
	if len(team.RepoPresets) != 0 || len(presets) != 0 || len(form.Fields) != 4 || team.IssueForm == nil {
		t.Fatalf("reset = %+v %+v", team.RepoPresets, team.IssueForm)
	}
	raw := s.db.MemoryCollection(collectionTeams).Documents()[0]
	if presets, ok := raw["repoPresets"].([]any); !ok || len(presets) != 0 {
		t.Fatalf("stored presets = %#v", raw["repoPresets"])
	}
}

func TestDegradedStoreIsNeverAnEmptyResult(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	s := newMemoryRepo(t)
	s.bind(t, "m", "u")
	s.provider.down.Store(true)
	cached := AuthorityCacheOptions{PositiveTTL: DesktopDashboardAuthCacheTTL}
	checks := map[string]error{}
	_, checks["ListMachinesForUser"] = s.ListMachinesForUser(ctx, "u")
	_, checks["ListMachinesForTeam"] = s.ListMachinesForTeam(ctx, "t")
	_, checks["ListMachinesCoManagedBy"] = s.ListMachinesCoManagedBy(ctx, "u")
	_, checks["ListMachineVersionSamples"] = s.ListMachineVersionSamples(ctx)
	_, checks["GetMachine"] = s.GetMachine(ctx, "m")
	_, checks["LookupMachine"] = s.LookupMachine(ctx, "m", AuthorityCacheOptions{})
	_, checks["LookupMachineCached"] = s.LookupMachine(ctx, "m", cached)
	_, checks["BindMachineCAS"] = s.BindMachineCAS(ctx, "m", "u", "U")
	checks["RetireMachine"] = s.RetireMachine(ctx, "m")
	_, checks["GetTeam"] = s.GetTeam(ctx, "t")
	_, checks["ListTeamsForUser"] = s.ListTeamsForUser(ctx, "u")
	_, checks["GetDevice"] = s.GetDevice(ctx, "d")
	_, checks["ListDevicesForUser"] = s.ListDevicesForUser(ctx, "u")
	_, checks["RotateDeviceRefresh"] = s.RotateDeviceRefresh(ctx, RotateDeviceRefreshInput{DeviceID: "d"})
	_, checks["ForceRevokeDevice"] = s.ForceRevokeDevice(ctx, "d")
	checks["RevokeDevice"] = s.RevokeDevice(ctx, "d", "u")
	checks["CreateDevice"] = s.CreateDevice(ctx, DeviceDoc{ID: "d"})
	_, checks["GetDeviceGrant"] = s.GetDeviceGrant(ctx, "g")
	checks["ApproveDeviceGrant"] = s.ApproveDeviceGrant(ctx, "g", "u", "d", 1)
	checks["ConsumeDeviceGrant"] = s.ConsumeDeviceGrant(ctx, "g", "h", 1)
	_, checks["GetDesktopSessionFamilyStatus"] = s.GetDesktopSessionFamilyStatus(ctx, "sid", cached)
	checks["RevokeDesktopSessionFamily"] = s.RevokeDesktopSessionFamily(ctx, "sid", 1)
	checks["ConsumeProxyTicket"] = s.ConsumeProxyTicket(ctx, "jti", 1)
	checks["ConsumeDesktopAuthCode"] = s.ConsumeDesktopAuthCode(ctx, "code", 1)
	for name, err := range checks {
		if !errors.Is(err, ErrUnavailable) {
			t.Errorf("%s err = %v, want ErrUnavailable", name, err)
		}
	}
	// Nothing unavailable was cached: recovery is immediate.
	s.provider.down.Store(false)
	if doc, err := s.LookupMachine(ctx, "m", cached); err != nil || doc.ID != "m" {
		t.Fatalf("after recovery = %+v %v", doc, err)
	}
}
