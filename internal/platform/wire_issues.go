package platform

import (
	"context"
	"log/slog"
	"time"

	httpserver "github.com/botmux-ai/botmux-platform/internal/server"
	"github.com/botmux-ai/botmux-platform/internal/store"
)

// issueSweepInterval is ISSUE_SWEEP_MS (src/index.ts): a fixed 60s interval
// without jitter. Concurrent replicas are safe because every transition the
// sweep makes is a CAS.
const issueSweepInterval = 60 * time.Second

type issueLeaseSweeper interface {
	SweepExpiredLeases(ctx context.Context) (store.IssueSweepResult, error)
}

// wireIssues fills apex.Issues and starts the expired-lease sweeper
// (register its stop with env.addCloser). Owned by Phase 2 agent B2.
//
// apex.Issues keeps its zero value: the machine lookup defaults to
// apex.Repository and the fresh-SSO clock to time.Now.
func wireIssues(env wireEnv, apex *httpserver.Apex) error {
	// startIssueLeaseSweeper: skipped in memory mode, where there is no issue
	// authority to sweep.
	if apex.IssueStore == nil || !apex.IssueStore.PersistenceAvailable() {
		return nil
	}
	stop := startIssueLeaseSweeper(apex.IssueStore, issueSweepInterval)
	env.addCloser(func() error {
		stop()
		return nil
	})
	return nil
}

// startIssueLeaseSweeper runs sweeper every interval until stop is called;
// stop cancels an in-flight sweep and waits for the goroutine to exit. Like
// TS it logs only when something moved; failures are already logged by the
// store (an unavailable store is silently skipped, as TS returns zeros).
func startIssueLeaseSweeper(sweeper issueLeaseSweeper, interval time.Duration) (stop func()) {
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() {
		defer close(done)
		ticker := time.NewTicker(interval)
		defer ticker.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case <-ticker.C:
				result, _ := sweeper.SweepExpiredLeases(ctx)
				if result.ToOpen > 0 || result.ToAttention > 0 {
					slog.Info("issue 租约 sweep", "toOpen", result.ToOpen, "toAttention", result.ToAttention)
				}
			}
		}
	}()
	return func() {
		cancel()
		<-done
	}
}
