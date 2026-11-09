package store

import (
	"context"
	"errors"
	"sync"
	"testing"
	"time"
)

const bindMID = "aabbccdd11223344"

// Ports of test/store-machines-bind.test.ts.

func TestBindMachineCASCreatesActiveDocument(t *testing.T) {
	t.Parallel()
	s := newMemoryRepo(t)
	if result, err := s.BindMachineCAS(context.Background(), bindMID, "u-alice", "Alice"); err != nil || result != BindCreated {
		t.Fatalf("bind = %v %v", result, err)
	}
	doc, err := s.GetMachine(context.Background(), bindMID)
	if err != nil || doc.UnionID != "u-alice" || doc.Status != MachineStatusActive || doc.BotmuxVersion != "unknown" {
		t.Fatalf("doc = %+v %v", doc, err)
	}
}

func TestBindMachineCASReboundRefreshesOwnerNameOnly(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	s := newMemoryRepo(t)
	s.bind(t, bindMID, "u-alice")
	if err := s.PersistRegister(ctx, RegisterMachine{MachineID: bindMID, UnionID: "u-alice", Name: "alice-macbook", BotmuxVersion: "1.0.0", DashboardPort: 8800, LastSeen: 7}); err != nil {
		t.Fatal(err)
	}
	if result, err := s.BindMachineCAS(ctx, bindMID, "u-alice", "Alice Chan"); err != nil || result != BindRebound {
		t.Fatalf("rebind = %v %v", result, err)
	}
	doc, _ := s.GetMachine(ctx, bindMID)
	if doc.OwnerName != "Alice Chan" || doc.UnionID != "u-alice" || doc.Name != "alice-macbook" || doc.LastSeen != 7 {
		t.Fatalf("doc = %+v", doc)
	}
}

func TestBindMachineCASNeverOverwritesAnotherOwner(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	s := newMemoryRepo(t)
	s.bind(t, bindMID, "u-alice")
	if result, err := s.BindMachineCAS(ctx, bindMID, "u-mallory", "Mallory"); err != nil || result != BindConflictOwner {
		t.Fatalf("foreign bind = %v %v", result, err)
	}
	if doc, _ := s.GetMachine(ctx, bindMID); doc.UnionID != "u-alice" || doc.OwnerName != "u-alice-name" {
		t.Fatalf("ownership overwritten: %+v", doc)
	}
}

func TestBindMachineCASRetiredIsNeverReused(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	s := newMemoryRepo(t)
	s.bind(t, bindMID, "u-alice")
	if err := s.RetireMachine(ctx, bindMID); err != nil {
		t.Fatal(err)
	}
	for _, who := range []string{"u-alice", "u-mallory"} {
		if result, err := s.BindMachineCAS(ctx, bindMID, who, who); err != nil || result != BindRetired {
			t.Fatalf("bind %s = %v %v", who, result, err)
		}
	}
	if doc, _ := s.GetMachine(ctx, bindMID); !doc.Retired() || doc.UnionID != "u-alice" {
		t.Fatalf("tombstone = %+v", doc)
	}
}

func TestLookupMachineReturnsCopies(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	s := newMemoryRepo(t)
	s.bind(t, bindMID, "u-alice")
	if err := s.SetMachineCoManagers(ctx, bindMID, "u-alice", []MachineCoManager{coManager("mate", "team")}); err != nil {
		t.Fatal(err)
	}
	cached := AuthorityCacheOptions{PositiveTTL: DesktopDashboardAuthCacheTTL}
	doc, err := s.LookupMachine(ctx, bindMID, cached)
	if err != nil {
		t.Fatal(err)
	}
	doc.UnionID = "u-evil"
	doc.CoManagers[0].Scopes[0] = "evil"
	again, _ := s.LookupMachine(ctx, bindMID, cached)
	if again.UnionID != "u-alice" || again.CoManagers[0].Scopes[0] != DeviceScopeMachinesRead {
		t.Fatalf("cached document mutated through a returned copy: %+v", again)
	}
	if _, err := s.LookupMachine(ctx, "missing", AuthorityCacheOptions{}); !errors.Is(err, ErrNotFound) {
		t.Fatalf("missing = %v", err)
	}
}

// racingInsertDB makes the first InsertOne lose a race: another
// writer inserts the winning document right before the insert fails.
type racingInsertDB struct {
	*MemoryDatabase
	winner Document
	once   sync.Once
}

type racingInsertCollection struct {
	DocumentCollection
	db *racingInsertDB
}

func (d *racingInsertDB) Collection(name string) DocumentCollection {
	return racingInsertCollection{DocumentCollection: d.MemoryDatabase.Collection(name), db: d}
}

func (c racingInsertCollection) InsertOne(ctx context.Context, value any) error {
	raced := false
	c.db.once.Do(func() {
		raced = true
		_ = c.DocumentCollection.InsertOne(ctx, c.db.winner)
	})
	if raced {
		return c.DocumentCollection.InsertOne(ctx, value)
	}
	return c.DocumentCollection.InsertOne(ctx, value)
}

func TestBindMachineCASClassifiesConcurrentInsertWinner(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	for _, tc := range []struct {
		winner Document
		want   BindResult
	}{
		{Document{"_id": bindMID, "unionId": "u-mallory", "status": MachineStatusActive}, BindConflictOwner},
		{Document{"_id": bindMID, "unionId": "u-alice", "status": MachineStatusActive}, BindRebound},
		{Document{"_id": bindMID, "unionId": "u-alice", "status": MachineStatusRetired}, BindRetired},
	} {
		db := &racingInsertDB{MemoryDatabase: NewMemoryDatabase(), winner: tc.winner}
		s := NewDocumentRepository(StaticDatabaseProvider{DB: db})
		if result, err := s.BindMachineCAS(ctx, bindMID, "u-alice", "Alice"); err != nil || result != tc.want {
			t.Fatalf("winner %v: bind = %v %v", tc.winner, result, err)
		}
	}
}

func TestBindMachineCASConcurrentBindsHaveOneCreator(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	s := newMemoryRepo(t)
	results := make([]BindResult, 16)
	var wg sync.WaitGroup
	for i := range results {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			owner := "u-alice"
			if i%2 == 1 {
				owner = "u-bob"
			}
			results[i], _ = s.BindMachineCAS(ctx, bindMID, owner, owner)
		}(i)
	}
	wg.Wait()
	created := 0
	for _, r := range results {
		switch r {
		case BindCreated:
			created++
		case BindRebound, BindConflictOwner:
		default:
			t.Fatalf("unexpected result %q in %v", r, results)
		}
	}
	if created != 1 {
		t.Fatalf("created %d times: %v", created, results)
	}
}

// Ports of test/store-dashboard-authority-cache.test.ts.

func TestDashboardAuthorityColdConcurrentReadsCoalesce(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	s := newMemoryRepo(t)
	s.bind(t, bindMID, "u-alice")
	cached := AuthorityCacheOptions{PositiveTTL: DesktopDashboardAuthCacheTTL}
	var wg sync.WaitGroup
	for i := 0; i < 24; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			family, err := s.GetDesktopSessionFamilyStatus(ctx, "sid", cached)
			if err != nil || family != DesktopFamilyActive {
				t.Errorf("family = %v %v", family, err)
			}
			doc, err := s.LookupMachine(ctx, bindMID, cached)
			if err != nil || doc.Status != MachineStatusActive {
				t.Errorf("machine = %+v %v", doc, err)
			}
		}()
	}
	wg.Wait()
	if s.familyReads.Load() != 1 || s.machineReads.Load() != 1 {
		t.Fatalf("reads family=%d machine=%d", s.familyReads.Load(), s.machineReads.Load())
	}
}

func TestDashboardAuthoritySamePodRevokeAndRetireBreakCache(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	s := newMemoryRepo(t)
	s.bind(t, bindMID, "u-alice")
	cached := AuthorityCacheOptions{PositiveTTL: DesktopDashboardAuthCacheTTL}
	if family, _ := s.GetDesktopSessionFamilyStatus(ctx, "sid", cached); family != DesktopFamilyActive {
		t.Fatal(family)
	}
	if doc, _ := s.LookupMachine(ctx, bindMID, cached); doc.Status != MachineStatusActive {
		t.Fatal(doc)
	}
	if err := s.RevokeDesktopSessionFamily(ctx, "sid", s.nowMS()+60_000); err != nil {
		t.Fatal(err)
	}
	if err := s.RetireMachine(ctx, bindMID); err != nil {
		t.Fatal(err)
	}
	if family, _ := s.GetDesktopSessionFamilyStatus(ctx, "sid", cached); family != DesktopFamilyRevoked {
		t.Fatalf("family = %v", family)
	}
	if doc, _ := s.LookupMachine(ctx, bindMID, cached); !doc.Retired() {
		t.Fatalf("machine = %+v", doc)
	}
	if s.familyReads.Load() != 2 || s.machineReads.Load() != 2 {
		t.Fatalf("reads family=%d machine=%d", s.familyReads.Load(), s.machineReads.Load())
	}
	// Negative results (revoked / RETIRED) are never cached.
	_, _ = s.GetDesktopSessionFamilyStatus(ctx, "sid", cached)
	_, _ = s.LookupMachine(ctx, bindMID, cached)
	if s.familyReads.Load() != 3 || s.machineReads.Load() != 3 {
		t.Fatalf("negative results cached: family=%d machine=%d", s.familyReads.Load(), s.machineReads.Load())
	}
}

func TestDashboardAuthorityCacheTTLIsAbsoluteAndCapped(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	s := newMemoryRepo(t)
	s.bind(t, bindMID, "u-alice")
	cached := AuthorityCacheOptions{PositiveTTL: DesktopDashboardAuthCacheTTL}
	for i := 0; i <= 5; i++ { // reads at 0s..5s: hits do not slide the expiry
		_, _ = s.LookupMachine(ctx, bindMID, cached)
		s.clock.Advance(time.Second)
	}
	if s.machineReads.Load() != 2 {
		t.Fatalf("reads = %d", s.machineReads.Load())
	}
	s.clock.Advance(time.Hour)
	huge := AuthorityCacheOptions{PositiveTTL: time.Hour}
	_, _ = s.LookupMachine(ctx, bindMID, huge)
	s.clock.Advance(desktopDashboardAuthCacheHardMax - time.Millisecond)
	_, _ = s.LookupMachine(ctx, bindMID, huge)
	s.clock.Advance(time.Millisecond)
	_, _ = s.LookupMachine(ctx, bindMID, huge)
	if s.machineReads.Load() != 4 {
		t.Fatalf("hard max not applied: reads = %d", s.machineReads.Load())
	}
	// Missing machines are never cached.
	_, _ = s.LookupMachine(ctx, "missing", cached)
	_, _ = s.LookupMachine(ctx, "missing", cached)
	if s.machineReads.Load() != 6 {
		t.Fatalf("missing cached: reads = %d", s.machineReads.Load())
	}
}

// gatedFindDB blocks the first FindOne on a collection until released.
type gatedFindDB struct {
	*MemoryDatabase
	gate    chan struct{}
	entered chan struct{}
	once    sync.Once
}

type gatedFindCollection struct {
	DocumentCollection
	db *gatedFindDB
}

func (d *gatedFindDB) Collection(name string) DocumentCollection {
	return gatedFindCollection{DocumentCollection: d.MemoryDatabase.Collection(name), db: d}
}

func (c gatedFindCollection) FindOne(ctx context.Context, filter Document, dst any) error {
	first := false
	c.db.once.Do(func() { first = true })
	err := c.DocumentCollection.FindOne(ctx, filter, dst)
	if first {
		close(c.db.entered)
		<-c.db.gate
	}
	return err
}

func TestDashboardAuthorityInvalidationDuringReadPreventsBackfill(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	db := &gatedFindDB{MemoryDatabase: NewMemoryDatabase(), gate: make(chan struct{}), entered: make(chan struct{})}
	s := NewDocumentRepository(StaticDatabaseProvider{DB: db})
	cached := AuthorityCacheOptions{PositiveTTL: DesktopDashboardAuthCacheTTL}
	done := make(chan DesktopFamilyStatus)
	go func() {
		status, _ := s.GetDesktopSessionFamilyStatus(ctx, "sid", cached)
		done <- status
	}()
	<-db.entered // the stale "active" read has completed but not returned
	if err := s.RevokeDesktopSessionFamily(ctx, "sid", 0); err != nil {
		t.Fatal(err)
	}
	close(db.gate)
	if status := <-done; status != DesktopFamilyActive {
		t.Fatalf("in-flight status = %v", status)
	}
	if status, err := s.GetDesktopSessionFamilyStatus(ctx, "sid", cached); err != nil || status != DesktopFamilyRevoked {
		t.Fatalf("stale active was backfilled: %v %v", status, err)
	}
}

func TestDashboardAuthorityWaiterHonorsOwnContext(t *testing.T) {
	t.Parallel()
	db := &gatedFindDB{MemoryDatabase: NewMemoryDatabase(), gate: make(chan struct{}), entered: make(chan struct{})}
	s := NewDocumentRepository(StaticDatabaseProvider{DB: db})
	cached := AuthorityCacheOptions{PositiveTTL: DesktopDashboardAuthCacheTTL}
	leaderCtx, cancelLeader := context.WithCancel(context.Background())
	leader := make(chan error)
	go func() {
		_, err := s.LookupMachine(leaderCtx, bindMID, cached)
		leader <- err
	}()
	<-db.entered
	follower := make(chan error)
	go func() {
		_, err := s.LookupMachine(context.Background(), bindMID, cached)
		follower <- err
	}()
	cancelLeader()
	if err := <-leader; !errors.Is(err, context.Canceled) {
		t.Fatalf("leader err = %v", err)
	}
	close(db.gate)
	// The shared read was not cancelled with the leader.
	if err := <-follower; !errors.Is(err, ErrNotFound) {
		t.Fatalf("follower err = %v", err)
	}
}
