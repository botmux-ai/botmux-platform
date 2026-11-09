package platform

import (
	"context"
	"sync/atomic"
	"testing"
	"time"

	httpserver "github.com/botmux-ai/botmux-platform/internal/server"
	"github.com/botmux-ai/botmux-platform/internal/store"
)

type countingSweeper struct {
	calls   atomic.Int32
	running atomic.Bool
}

func (s *countingSweeper) SweepExpiredLeases(ctx context.Context) (store.IssueSweepResult, error) {
	s.running.Store(true)
	defer s.running.Store(false)
	s.calls.Add(1)
	return store.IssueSweepResult{ToOpen: 1}, nil
}

func TestIssueLeaseSweeperRunsUntilStopped(t *testing.T) {
	sweeper := &countingSweeper{}
	stop := startIssueLeaseSweeper(sweeper, 5*time.Millisecond)
	deadline := time.Now().Add(5 * time.Second)
	for sweeper.calls.Load() < 2 {
		if time.Now().After(deadline) {
			stop()
			t.Fatal("sweeper did not tick")
		}
		time.Sleep(time.Millisecond)
	}
	stop()
	if sweeper.running.Load() {
		t.Fatal("stop returned while a sweep was running")
	}
	after := sweeper.calls.Load()
	time.Sleep(20 * time.Millisecond)
	if sweeper.calls.Load() != after {
		t.Fatal("sweeper kept running after stop")
	}
}

func TestWireIssuesSkipsSweeperWithoutPersistence(t *testing.T) {
	var closers int
	env := wireEnv{addCloser: func(func() error) { closers++ }}
	for _, issues := range []*store.IssueStore{
		nil,
		store.NewIssueStore(store.UnavailableDatabaseProvider{}),
		store.NewIssueStore(store.StaticDatabaseProvider{DB: store.NewMemoryDatabase()}),
	} {
		if err := wireIssues(env, &httpserver.Apex{IssueStore: issues}); err != nil {
			t.Fatal(err)
		}
	}
	if closers != 0 {
		t.Fatalf("memory mode registered %d sweeper closers", closers)
	}
}
