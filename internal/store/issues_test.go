package store

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"math"
	"strings"
	"testing"
	"time"

	"go.mongodb.org/mongo-driver/bson"
	"go.mongodb.org/mongo-driver/bson/primitive"
)

// Ports test/store-issues.test.ts and the store-level assertions of
// test/issues-core-claim-machine.test.ts onto MemoryDatabase, the Go
// counterpart of test/fake-issues-db.ts. MemoryDatabase rejects conflicting
// update paths exactly like MongoDB, which is what catches the 4e52262
// "$set claim.lastSourceSeq + $unset claim" regression.

type issueFixture struct {
	t     *testing.T
	ctx   context.Context
	db    *MemoryDatabase
	store *IssueStore
	now   time.Time
}

func newIssueFixture(t *testing.T) *issueFixture {
	t.Helper()
	f := &issueFixture{t: t, ctx: context.Background(), db: NewMemoryDatabase(), now: time.UnixMilli(1_760_000_000_000)}
	f.store = NewIssueStoreWithClock(StaticDatabaseProvider{DB: f.db}, func() time.Time { return f.now })
	if err := f.store.EnsureIndexes(f.ctx); err != nil {
		t.Fatalf("ensure indexes: %v", err)
	}
	return f
}

func (f *issueFixture) advance(d time.Duration) { f.now = f.now.Add(d) }

func (f *issueFixture) seedOpen() IssueDoc {
	f.t.Helper()
	doc, err := f.store.Create(f.ctx, CreateIssueInput{TeamID: "t1", Title: "Fix login", Body: "body", CreatedBy: "u-creator", CreatedByName: "Creator"})
	if err != nil {
		f.t.Fatalf("create: %v", err)
	}
	return doc
}

func (f *issueFixture) claim(issue IssueDoc, claimID, unionID, machineID string) IssueDoc {
	f.t.Helper()
	doc, err := f.store.Claim(f.ctx, issue.ID, ClaimIssueInput{ClaimID: claimID, UnionID: unionID, Name: unionID, MachineID: machineID, ExpectedStateRev: float64(issue.StateRev)})
	if err != nil {
		f.t.Fatalf("claim: %v", err)
	}
	return doc
}

func (f *issueFixture) bind(issue IssueDoc, claimID, ref string) IssueDoc {
	f.t.Helper()
	doc, err := f.store.Bind(f.ctx, issue.ID, BindIssueInput{ClaimID: claimID, LocalTaskRef: ref, ExpectedStateRev: float64(issue.StateRev)})
	if err != nil {
		f.t.Fatalf("bind: %v", err)
	}
	return doc
}

func (f *issueFixture) status(issue IssueDoc, seq float64, target IssueStatus, reason AttentionReason) (IssueDoc, error) {
	f.t.Helper()
	return f.store.StatusWriteback(f.ctx, issue.ID, StatusWritebackInput{
		UnionID: "u-a", ClaimID: "c1", ClaimEpoch: 1, SourceSeq: seq, Target: target,
		AttentionReason: reason, ExpectedStateRev: float64(issue.StateRev),
	})
}

func (f *issueFixture) get(id string) IssueDoc {
	f.t.Helper()
	doc, err := f.store.Get(f.ctx, id)
	if err != nil {
		f.t.Fatalf("get: %v", err)
	}
	return doc
}

// boundIssue walks open -> claimed(c1, u-a, m1) -> bound(local::t).
func (f *issueFixture) boundIssue() IssueDoc {
	f.t.Helper()
	issue := f.seedOpen()
	claimed := f.claim(issue, "c1", "u-a", "m1")
	return f.bind(claimed, "c1", "local::t")
}

func (f *issueFixture) rawIssue(id string) map[string]any {
	f.t.Helper()
	for _, doc := range f.db.MemoryCollection(issuesCollection).Documents() {
		if doc["_id"] == id {
			return doc
		}
	}
	f.t.Fatalf("raw issue %s not found", id)
	return nil
}

func wantReason(t *testing.T, err error, reason string) {
	t.Helper()
	if got := StoreReason(err); got != reason {
		t.Fatalf("reason = %q (%v), want %q", got, err, reason)
	}
}

func TestIssueCreateInitializesCounters(t *testing.T) {
	f := newIssueFixture(t)
	issue := f.seedOpen()
	if issue.Status != IssueOpen || issue.Rev != 1 || issue.StateRev != 1 || issue.ClaimEpochCounter != 0 || issue.EventSeq != 1 {
		t.Fatalf("created issue: %+v", issue)
	}
	if !strings.HasPrefix(issue.ID, "iss_") || len(issue.ID) != len("iss_")+24 {
		t.Fatalf("issue id %q", issue.ID)
	}
	if stored := f.get(issue.ID); stored.Title != "Fix login" || stored.CreatedAt != f.now.UnixMilli() {
		t.Fatalf("stored issue: %+v", stored)
	}
	events, err := f.store.ListEvents(f.ctx, issue.ID, 0)
	if err != nil || len(events) != 1 {
		t.Fatalf("events = %+v, %v", events, err)
	}
	if e := events[0]; e.Kind != IssueEventCreated || e.ToStatus != IssueOpen || e.Seq != 1 || e.ActorUnionID != "u-creator" || e.TeamID != "t1" {
		t.Fatalf("created event: %+v", e)
	}
}

func TestIssueClaimSnapshotsEpoch(t *testing.T) {
	f := newIssueFixture(t)
	issue := f.seedOpen()
	claimed := f.claim(issue, "c1", "u-alice", "m1")
	if claimed.Status != IssueClaimed || claimed.ClaimEpochCounter != 1 || claimed.StateRev != 2 || claimed.EventSeq != 2 {
		t.Fatalf("claimed issue: %+v", claimed)
	}
	c := claimed.Claim
	if c == nil || c.ClaimEpoch != 1 || c.Bound || c.MachineID != "m1" || c.UnionID != "u-alice" || c.LastSourceSeq != 0 {
		t.Fatalf("claim: %+v", c)
	}
	if c.ClaimedAt != f.now.UnixMilli() || c.LeaseExpiresAt != f.now.UnixMilli()+ClaimLeaseMS {
		t.Fatalf("claim lease: %+v", c)
	}
}

func TestIssueClaimIdempotentRetryPrecedesStateRev(t *testing.T) {
	f := newIssueFixture(t)
	issue := f.seedOpen()
	f.claim(issue, "c1", "u-a", "m1")
	again, err := f.store.Claim(f.ctx, issue.ID, ClaimIssueInput{ClaimID: "c1", UnionID: "u-a", Name: "A", MachineID: "m1", ExpectedStateRev: 999})
	if err != nil || again.ClaimEpochCounter != 1 {
		t.Fatalf("idempotent claim = %+v, %v", again, err)
	}
}

func TestIssueClaimSameKeyDifferentActorIsAlreadyClaimed(t *testing.T) {
	f := newIssueFixture(t)
	issue := f.seedOpen()
	claimed := f.claim(issue, "c1", "u-a", "m1")
	for name, in := range map[string]ClaimIssueInput{
		"other machine": {ClaimID: "c1", UnionID: "u-a", MachineID: "m2"},
		"other person":  {ClaimID: "c1", UnionID: "u-b", MachineID: "m1"},
	} {
		in.ExpectedStateRev = float64(claimed.StateRev)
		_, err := f.store.Claim(f.ctx, issue.ID, in)
		wantReason(t, err, "already_claimed")
		_ = name
	}
	// Even after the lease expired the shared key must not take over.
	f.advance(ClaimLease + time.Second)
	_, err := f.store.Claim(f.ctx, issue.ID, ClaimIssueInput{ClaimID: "c1", UnionID: "u-b", MachineID: "m2", ExpectedStateRev: float64(claimed.StateRev)})
	wantReason(t, err, "already_claimed")
}

func TestIssueClaimExpiredSameKeyAndStaleTakeover(t *testing.T) {
	f := newIssueFixture(t)
	issue := f.seedOpen()
	claimed := f.claim(issue, "c1", "u-a", "m1")
	f.advance(ClaimLease)
	_, err := f.store.Claim(f.ctx, issue.ID, ClaimIssueInput{ClaimID: "c1", UnionID: "u-a", MachineID: "m1", ExpectedStateRev: float64(claimed.StateRev)})
	wantReason(t, err, "claim_expired")

	// A fresh claimId takes over the expired unbound reservation.
	_, err = f.store.Claim(f.ctx, issue.ID, ClaimIssueInput{ClaimID: "c2", UnionID: "u-b", MachineID: "m2", ExpectedStateRev: 1})
	wantReason(t, err, "state_rev_conflict")
	taken, err := f.store.Claim(f.ctx, issue.ID, ClaimIssueInput{ClaimID: "c2", UnionID: "u-b", MachineID: "m2", ExpectedStateRev: float64(claimed.StateRev)})
	if err != nil || taken.Claim.ClaimID != "c2" || taken.Claim.ClaimEpoch != 2 || taken.ClaimEpochCounter != 2 {
		t.Fatalf("stale takeover = %+v, %v", taken, err)
	}
	events, _ := f.store.ListEvents(f.ctx, issue.ID, 0)
	if last := events[len(events)-1]; last.Kind != IssueEventClaimed || last.FromStatus != IssueClaimed || last.ActorUnionID != "u-b" {
		t.Fatalf("takeover event: %+v", last)
	}
}

func TestIssueClaimCompetitionAlreadyClaimed(t *testing.T) {
	f := newIssueFixture(t)
	issue := f.seedOpen()
	claimed := f.claim(issue, "c1", "u-a", "m1")
	_, err := f.store.Claim(f.ctx, issue.ID, ClaimIssueInput{ClaimID: "c2", UnionID: "u-b", Name: "B", MachineID: "m2", ExpectedStateRev: float64(claimed.StateRev)})
	wantReason(t, err, "already_claimed")
	// Bound reservations are never taken over, even when expired.
	bound := f.bind(claimed, "c1", "local::t")
	f.advance(ActivationLease + time.Second)
	_, err = f.store.Claim(f.ctx, issue.ID, ClaimIssueInput{ClaimID: "c3", UnionID: "u-b", MachineID: "m2", ExpectedStateRev: float64(bound.StateRev)})
	wantReason(t, err, "already_claimed")
	_, err = f.store.Claim(f.ctx, "iss_missing", ClaimIssueInput{ClaimID: "c1"})
	wantReason(t, err, "not_found")
}

func TestIssueBindResetsActivationLease(t *testing.T) {
	f := newIssueFixture(t)
	issue := f.seedOpen()
	claimed := f.claim(issue, "c1", "u-a", "m1")
	f.advance(time.Minute)
	bound, err := f.store.Bind(f.ctx, issue.ID, BindIssueInput{
		ClaimID: "c1", LocalTaskRef: "local::task_1", ExpectedStateRev: float64(claimed.StateRev),
		LocalTaskLabel: "issue chat", LocalTaskURL: "https://applink.feishu.cn/x",
	})
	if err != nil {
		t.Fatal(err)
	}
	c := bound.Claim
	if !c.Bound || c.LocalTaskRef != "local::task_1" || c.LeaseExpiresAt != f.now.UnixMilli()+ActivationLeaseMS {
		t.Fatalf("bound claim: %+v", c)
	}
	if c.LocalTaskLabel != "issue chat" || c.LocalTaskURL != "https://applink.feishu.cn/x" || c.MachineID != "m1" {
		t.Fatalf("bound display fields: %+v", c)
	}
	events, _ := f.store.ListEvents(f.ctx, issue.ID, 2)
	if len(events) != 1 || events[0].Kind != IssueEventBound || events[0].ActorUnionID != "u-a" || events[0].Seq != 3 {
		t.Fatalf("bound event: %+v", events)
	}
}

func TestIssueBindOmitsEmptyDisplayFields(t *testing.T) {
	f := newIssueFixture(t)
	bound := f.boundIssue()
	claim := f.rawIssue(bound.ID)["claim"].(map[string]any)
	if _, ok := claim["localTaskLabel"]; ok {
		t.Fatal("empty localTaskLabel must not be stored")
	}
	if _, ok := claim["localTaskUrl"]; ok {
		t.Fatal("empty localTaskUrl must not be stored")
	}
}

func TestIssueBindFailureBranches(t *testing.T) {
	f := newIssueFixture(t)
	issue := f.seedOpen()
	_, err := f.store.Bind(f.ctx, issue.ID, BindIssueInput{ClaimID: "c1", LocalTaskRef: "r", ExpectedStateRev: 1})
	wantReason(t, err, "claim_mismatch")
	claimed := f.claim(issue, "c1", "u-a", "m1")
	_, err = f.store.Bind(f.ctx, issue.ID, BindIssueInput{ClaimID: "other", LocalTaskRef: "r", ExpectedStateRev: float64(claimed.StateRev)})
	wantReason(t, err, "claim_mismatch")
	_, err = f.store.Bind(f.ctx, issue.ID, BindIssueInput{ClaimID: "c1", LocalTaskRef: "r", ExpectedStateRev: 1})
	wantReason(t, err, "state_rev_conflict")

	bound := f.bind(claimed, "c1", "local::t")
	// Idempotent retry with the same ref (stateRev is not consulted).
	again, err := f.store.Bind(f.ctx, issue.ID, BindIssueInput{ClaimID: "c1", LocalTaskRef: "local::t", ExpectedStateRev: 0})
	if err != nil || again.StateRev != bound.StateRev {
		t.Fatalf("idempotent bind = %+v, %v", again, err)
	}
	_, err = f.store.Bind(f.ctx, issue.ID, BindIssueInput{ClaimID: "c1", LocalTaskRef: "local::other", ExpectedStateRev: float64(bound.StateRev)})
	wantReason(t, err, "claim_mismatch")
	f.advance(ActivationLease)
	_, err = f.store.Bind(f.ctx, issue.ID, BindIssueInput{ClaimID: "c1", LocalTaskRef: "local::t", ExpectedStateRev: float64(bound.StateRev)})
	wantReason(t, err, "claim_expired")

	// An unbound reservation past its lease cannot be bound.
	other := f.seedOpen()
	otherClaimed := f.claim(other, "c9", "u-a", "m1")
	f.advance(ClaimLease)
	_, err = f.store.Bind(f.ctx, other.ID, BindIssueInput{ClaimID: "c9", LocalTaskRef: "r", ExpectedStateRev: float64(otherClaimed.StateRev)})
	wantReason(t, err, "claim_expired")
	_, err = f.store.Bind(f.ctx, "iss_missing", BindIssueInput{ClaimID: "c9"})
	wantReason(t, err, "not_found")
}

func TestIssueBoundButNoLongerClaimedIsExpired(t *testing.T) {
	f := newIssueFixture(t)
	bound := f.boundIssue()
	progressed, err := f.status(bound, 1, IssueInProgress, "")
	if err != nil {
		t.Fatal(err)
	}
	_, err = f.store.Bind(f.ctx, bound.ID, BindIssueInput{ClaimID: "c1", LocalTaskRef: "local::t", ExpectedStateRev: float64(progressed.StateRev)})
	wantReason(t, err, "claim_expired")
}

func TestIssueStatusCatchupClaimedToDoneClearsClaim(t *testing.T) {
	f := newIssueFixture(t)
	bound := f.boundIssue()
	done, err := f.status(bound, 1, IssueDone, "")
	if err != nil {
		t.Fatalf("claimed -> done must not fail (4e52262 conflict-path regression): %v", err)
	}
	if done.Status != IssueDone || done.Claim != nil {
		t.Fatalf("done issue: %+v", done)
	}
	if _, ok := f.rawIssue(bound.ID)["claim"]; ok {
		t.Fatal("claim must be removed from the stored document")
	}
	events, _ := f.store.ListEvents(f.ctx, bound.ID, 3)
	if len(events) != 1 || events[0].Kind != IssueEventReleased || events[0].FromStatus != IssueClaimed || events[0].ToStatus != IssueDone {
		t.Fatalf("release event: %+v", events)
	}
}

func TestIssueEveryClaimClearingTransitionSucceeds(t *testing.T) {
	for _, target := range []IssueStatus{IssueOpen, IssueReopened, IssueDone} {
		t.Run(string(target), func(t *testing.T) {
			f := newIssueFixture(t)
			bound := f.boundIssue()
			progressed, err := f.status(bound, 1, IssueInProgress, "")
			if err != nil {
				t.Fatal(err)
			}
			cleared, err := f.status(progressed, 2, target, "")
			if err != nil || cleared.Status != target || cleared.Claim != nil {
				t.Fatalf("in_progress -> %s = %+v, %v", target, cleared, err)
			}
		})
	}
}

func TestIssueStatusBackwardsRejectedAfterDone(t *testing.T) {
	f := newIssueFixture(t)
	bound := f.boundIssue()
	progressed, err := f.status(bound, 1, IssueInProgress, "")
	if err != nil {
		t.Fatal(err)
	}
	done, err := f.status(progressed, 2, IssueDone, "")
	if err != nil {
		t.Fatalf("in_progress -> done: %v", err)
	}
	// done cleared the claim and has no outgoing edges: terminal idempotency
	// misses (target != current) -> stale_epoch.
	_, err = f.status(done, 3, IssueInProgress, "")
	wantReason(t, err, "stale_epoch")
}

func TestIssueStatusSourceSeqIdempotency(t *testing.T) {
	f := newIssueFixture(t)
	bound := f.boundIssue()
	progressed, err := f.status(bound, 5, IssueInProgress, "")
	if err != nil {
		t.Fatal(err)
	}
	if progressed.Claim.LastSourceSeq != 5 {
		t.Fatalf("lastSourceSeq = %v", progressed.Claim.LastSourceSeq)
	}
	dup, err := f.status(progressed, 5, IssueInReview, "")
	if err != nil || dup.Status != IssueInProgress || dup.StateRev != progressed.StateRev {
		t.Fatalf("duplicate sourceSeq must be a no-op: %+v, %v", dup, err)
	}
	older, err := f.status(progressed, 4, IssueInReview, "")
	if err != nil || older.Status != IssueInProgress {
		t.Fatalf("older sourceSeq must be a no-op: %+v, %v", older, err)
	}
}

func TestIssueTerminalIdempotentRetry(t *testing.T) {
	f := newIssueFixture(t)
	bound := f.boundIssue()
	done, err := f.status(bound, 1, IssueDone, "")
	if err != nil {
		t.Fatal(err)
	}
	retry, err := f.status(done, 1, IssueDone, "")
	if err != nil || retry.Status != IssueDone || retry.StateRev != done.StateRev {
		t.Fatalf("terminal retry = %+v, %v", retry, err)
	}
	// A different epoch is not the same claim.
	_, err = f.store.StatusWriteback(f.ctx, bound.ID, StatusWritebackInput{UnionID: "u-a", ClaimID: "c1", ClaimEpoch: 2, SourceSeq: 1, Target: IssueDone, ExpectedStateRev: float64(done.StateRev)})
	wantReason(t, err, "stale_epoch")
}

func TestIssueStatusFenceAndClaimantChecks(t *testing.T) {
	f := newIssueFixture(t)
	bound := f.boundIssue()
	base := StatusWritebackInput{UnionID: "u-a", ClaimID: "c1", ClaimEpoch: 1, SourceSeq: 1, Target: IssueInProgress, ExpectedStateRev: float64(bound.StateRev)}
	cases := []struct {
		name   string
		mutate func(*StatusWritebackInput)
		reason string
	}{
		{"wrong epoch", func(in *StatusWritebackInput) { in.ClaimEpoch = 2 }, "stale_epoch"},
		{"fractional epoch", func(in *StatusWritebackInput) { in.ClaimEpoch = 1.5 }, "stale_epoch"},
		{"wrong claim", func(in *StatusWritebackInput) { in.ClaimID = "c2" }, "stale_epoch"},
		{"not the claimant", func(in *StatusWritebackInput) { in.UnionID = "u-b" }, "forbidden"},
		{"backwards target", func(in *StatusWritebackInput) { in.Target = IssueClaimed }, "invalid_transition"},
		{"cancelling target", func(in *StatusWritebackInput) { in.Target = IssueCancelling }, "invalid_transition"},
		{"unknown target", func(in *StatusWritebackInput) { in.Target = "bogus" }, "invalid_transition"},
		{"stale stateRev", func(in *StatusWritebackInput) { in.ExpectedStateRev = 1 }, "state_rev_conflict"},
		{"fractional stateRev", func(in *StatusWritebackInput) { in.ExpectedStateRev += 0.5 }, "state_rev_conflict"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			in := base
			tc.mutate(&in)
			_, err := f.store.StatusWriteback(f.ctx, bound.ID, in)
			wantReason(t, err, tc.reason)
		})
	}
	_, err := f.store.StatusWriteback(f.ctx, "iss_missing", base)
	wantReason(t, err, "not_found")
	if cur := f.get(bound.ID); cur.StateRev != bound.StateRev || cur.Status != IssueClaimed {
		t.Fatalf("rejected write-backs must not change the issue: %+v", cur)
	}
}

func TestIssueNeedsAttentionWritebackAndUnblock(t *testing.T) {
	f := newIssueFixture(t)
	bound := f.boundIssue()
	blocked, err := f.status(bound, 1, IssueNeedsAttention, AttentionTaskBlocked)
	if err != nil {
		t.Fatal(err)
	}
	if blocked.AttentionReason != AttentionTaskBlocked || blocked.AttentionSince != f.now.UnixMilli() || blocked.Claim == nil {
		t.Fatalf("blocked issue: %+v", blocked)
	}
	resumed, err := f.status(blocked, 2, IssueInProgress, "")
	if err != nil || resumed.Status != IssueInProgress {
		t.Fatalf("task_blocked -> in_progress = %+v, %v", resumed, err)
	}
	if resumed.AttentionSince != 0 || resumed.AttentionReason != "" {
		t.Fatalf("leaving needs_attention must clear attention fields: %+v", resumed)
	}
	raw := f.rawIssue(bound.ID)
	if _, ok := raw["attentionSince"]; ok {
		t.Fatal("attentionSince must be unset")
	}

	// Without a reason the default is run_timeout, which does not unblock.
	timedOut, err := f.status(resumed, 3, IssueNeedsAttention, "")
	if err != nil || timedOut.AttentionReason != AttentionRunTimeout {
		t.Fatalf("default attention reason = %+v, %v", timedOut, err)
	}
	_, err = f.status(timedOut, 4, IssueInProgress, "")
	wantReason(t, err, "invalid_transition")
	reopened, err := f.status(timedOut, 4, IssueReopened, "")
	if err != nil || reopened.Status != IssueReopened || reopened.Claim != nil || reopened.AttentionReason != "" {
		t.Fatalf("needs_attention -> reopened = %+v, %v", reopened, err)
	}
}

func TestIssueSweeperUnboundExpiredToOpen(t *testing.T) {
	f := newIssueFixture(t)
	issue := f.seedOpen()
	f.claim(issue, "c1", "u-a", "m1")
	f.advance(ClaimLease - time.Millisecond)
	if r, err := f.store.SweepExpiredLeases(f.ctx); err != nil || r != (IssueSweepResult{}) {
		t.Fatalf("live lease swept: %+v, %v", r, err)
	}
	f.advance(time.Millisecond)
	r, err := f.store.SweepExpiredLeases(f.ctx)
	if err != nil || r.ToOpen != 1 || r.ToAttention != 0 {
		t.Fatalf("sweep = %+v, %v", r, err)
	}
	after := f.get(issue.ID)
	if after.Status != IssueOpen || after.Claim != nil || after.ClaimEpochCounter != 1 {
		t.Fatalf("swept issue: %+v", after)
	}
	events, _ := f.store.ListEvents(f.ctx, issue.ID, 2)
	if len(events) != 1 || events[0].Kind != IssueEventLeaseExpired || events[0].ActorUnionID != "system" || events[0].Detail != "unbound claim lease expired" {
		t.Fatalf("lease event: %+v", events)
	}
	if r, err := f.store.SweepExpiredLeases(f.ctx); err != nil || r != (IssueSweepResult{}) {
		t.Fatalf("second sweep must be a no-op: %+v, %v", r, err)
	}
}

func TestIssueSweeperBoundExpiredToNeedsAttention(t *testing.T) {
	f := newIssueFixture(t)
	bound := f.boundIssue()
	f.advance(ActivationLease)
	r, err := f.store.SweepExpiredLeases(f.ctx)
	if err != nil || r.ToAttention != 1 || r.ToOpen != 0 {
		t.Fatalf("sweep = %+v, %v", r, err)
	}
	after := f.get(bound.ID)
	if after.Status != IssueNeedsAttention || after.AttentionReason != AttentionClaimActivateTimeout || after.AttentionSince != f.now.UnixMilli() || after.Claim == nil {
		t.Fatalf("swept issue: %+v", after)
	}
	// Once in_progress the issue leaves the sweeper's candidate set.
	g := newIssueFixture(t)
	progressed, err := g.status(g.boundIssue(), 1, IssueInProgress, "")
	if err != nil {
		t.Fatal(err)
	}
	g.advance(24 * time.Hour)
	if r, _ := g.store.SweepExpiredLeases(g.ctx); r != (IssueSweepResult{}) {
		t.Fatalf("in_progress issue swept: %+v (%s)", r, progressed.Status)
	}
}

func (f *issueFixture) needsAttention() IssueDoc {
	f.t.Helper()
	bound := f.boundIssue()
	f.advance(ActivationLease)
	if _, err := f.store.SweepExpiredLeases(f.ctx); err != nil {
		f.t.Fatal(err)
	}
	return f.get(bound.ID)
}

func TestIssueForceDetachReopensAndBumpsEpoch(t *testing.T) {
	f := newIssueFixture(t)
	na := f.needsAttention()
	detached, err := f.store.ForceDetach(f.ctx, na.ID, "u-creator", float64(na.StateRev))
	if err != nil {
		t.Fatal(err)
	}
	if detached.Status != IssueReopened || detached.Claim != nil || detached.ClaimEpochCounter != 2 || detached.AttentionReason != "" {
		t.Fatalf("detached issue: %+v", detached)
	}
	events, _ := f.store.ListEvents(f.ctx, na.ID, float64(na.EventSeq))
	if len(events) != 1 || events[0].Kind != IssueEventForceDetached || events[0].Detail != "强制脱离：旧执行可能仍在运行" {
		t.Fatalf("detach event: %+v", events)
	}
	// The old claim's write-back is now fenced off.
	_, err = f.store.StatusWriteback(f.ctx, na.ID, StatusWritebackInput{UnionID: "u-a", ClaimID: "c1", ClaimEpoch: 1, SourceSeq: 9, Target: IssueDone, ExpectedStateRev: float64(detached.StateRev)})
	wantReason(t, err, "stale_epoch")
	// A new claim gets the next epoch.
	reclaimed := f.claim(detached, "c2", "u-b", "m2")
	if reclaimed.Claim.ClaimEpoch != 3 {
		t.Fatalf("reclaim epoch = %d", reclaimed.Claim.ClaimEpoch)
	}
}

func TestIssueForceDetachFailures(t *testing.T) {
	f := newIssueFixture(t)
	open := f.seedOpen()
	_, err := f.store.ForceDetach(f.ctx, open.ID, "u", float64(open.StateRev))
	wantReason(t, err, "invalid_transition")
	na := f.needsAttention()
	_, err = f.store.ForceDetach(f.ctx, na.ID, "u", float64(na.StateRev-1))
	wantReason(t, err, "state_rev_conflict")
	_, err = f.store.ForceDetach(f.ctx, "iss_missing", "u", 1)
	wantReason(t, err, "not_found")
}

func TestIssueNeedsAttentionCannotBeClaimed(t *testing.T) {
	f := newIssueFixture(t)
	na := f.needsAttention()
	_, err := f.store.Claim(f.ctx, na.ID, ClaimIssueInput{ClaimID: "c2", UnionID: "u-b", Name: "B", MachineID: "m2", ExpectedStateRev: float64(na.StateRev)})
	wantReason(t, err, "needs_force_detach")
}

func TestIssueMachineScopedFlow(t *testing.T) {
	// Store-level half of issues-core-claim-machine.test.ts: the claim records
	// the machine that core verified, and bind/status keep working on it.
	f := newIssueFixture(t)
	issue := f.seedOpen()
	claimed := f.claim(issue, "c1", "u-a", "m-alice")
	if claimed.Claim.MachineID != "m-alice" || claimed.Claim.UnionID != "u-a" {
		t.Fatalf("claim must record the verified machine: %+v", claimed.Claim)
	}
	bound := f.bind(claimed, "c1", "local::t1")
	progressed, err := f.status(bound, 1, IssueInProgress, "")
	if err != nil || progressed.Status != IssueInProgress || progressed.Claim.MachineID != "m-alice" {
		t.Fatalf("status write = %+v, %v", progressed, err)
	}
}

func TestIssuePatch(t *testing.T) {
	f := newIssueFixture(t)
	repoID, repoLabel := "repo_1", "botmux/platform"
	created, err := f.store.Create(f.ctx, CreateIssueInput{TeamID: "t1", Title: "t", TargetRepoID: repoID, TargetRepoLabel: repoLabel, CreatedBy: "u"})
	if err != nil {
		t.Fatal(err)
	}
	title, body, empty := "new title", "new body", ""
	labels := []string{}
	assignee := ""
	patched, err := f.store.Patch(f.ctx, created.ID, float64(created.Rev), IssuePatch{
		Title: &title, Body: &body, Labels: &labels, TargetRepoLabel: &empty, SuggestedAssigneeUnionID: &assignee,
	})
	if err != nil {
		t.Fatal(err)
	}
	if patched.Rev != 2 || patched.StateRev != created.StateRev || patched.Title != title || patched.Body != body {
		t.Fatalf("patched issue: %+v", patched)
	}
	if patched.TargetRepoLabel != "" || patched.TargetRepoID != repoID {
		t.Fatalf("label must be cleared, id kept: %+v", patched)
	}
	if patched.Labels == nil || len(*patched.Labels) != 0 || patched.SuggestedAssigneeUnionID == nil || *patched.SuggestedAssigneeUnionID != "" {
		t.Fatalf("explicitly empty values must be persisted: %+v", patched)
	}
	encoded, _ := json.Marshal(patched)
	if !strings.Contains(string(encoded), `"labels":[]`) || !strings.Contains(string(encoded), `"suggestedAssigneeUnionId":""`) {
		t.Fatalf("JSON must keep explicitly empty values like JSON.stringify: %s", encoded)
	}
	longID := strings.Repeat("x", 50)
	patched, err = f.store.Patch(f.ctx, created.ID, 2, IssuePatch{TargetRepoID: &longID})
	if err != nil || patched.TargetRepoID != strings.Repeat("x", 40) {
		t.Fatalf("targetRepoId must be truncated to 40: %+v, %v", patched, err)
	}

	_, err = f.store.Patch(f.ctx, created.ID, 1, IssuePatch{Title: &title})
	wantReason(t, err, "rev_conflict")
	_, err = f.store.Patch(f.ctx, "iss_missing", 1, IssuePatch{Title: &title})
	wantReason(t, err, "not_found")
	claimed := f.claim(patched, "c1", "u-a", "m1")
	_, err = f.store.Patch(f.ctx, created.ID, float64(claimed.Rev), IssuePatch{Title: &title})
	wantReason(t, err, "issue_locked")
}

func TestIssueArchive(t *testing.T) {
	f := newIssueFixture(t)
	open := f.seedOpen()
	active := f.seedOpen()
	f.claim(active, "c1", "u-a", "m1")
	_, err := f.store.Archive(f.ctx, active.ID, "u")
	wantReason(t, err, "issue_active")

	archived, err := f.store.Archive(f.ctx, open.ID, "u-creator")
	if err != nil || archived.ArchivedAt != f.now.UnixMilli() || archived.StateRev != 2 {
		t.Fatalf("archive = %+v, %v", archived, err)
	}
	f.advance(time.Minute)
	again, err := f.store.Archive(f.ctx, open.ID, "u-creator")
	if err != nil || again.ArchivedAt != archived.ArchivedAt || again.StateRev != archived.StateRev {
		t.Fatalf("re-archive must return the archived issue unchanged: %+v, %v", again, err)
	}
	visible, err := f.store.ListForTeam(f.ctx, "t1", false)
	if err != nil || len(visible) != 1 || visible[0].ID != active.ID {
		t.Fatalf("list without archived = %+v, %v", visible, err)
	}
	all, err := f.store.ListForTeam(f.ctx, "t1", true)
	if err != nil || len(all) != 2 {
		t.Fatalf("list with archived = %+v, %v", all, err)
	}
	none, err := f.store.ListForTeam(f.ctx, "t-other", false)
	if err != nil || none == nil || len(none) != 0 {
		t.Fatalf("empty team list must be a non-nil empty slice: %#v, %v", none, err)
	}
	events, _ := f.store.ListEvents(f.ctx, open.ID, 1)
	if len(events) != 1 || events[0].Kind != IssueEventArchived || events[0].ActorUnionID != "u-creator" {
		t.Fatalf("archive event: %+v", events)
	}
	_, err = f.store.Archive(f.ctx, "iss_missing", "u")
	wantReason(t, err, "not_found")
}

func TestIssueEventsTimelineOrderAndCursor(t *testing.T) {
	f := newIssueFixture(t)
	bound := f.boundIssue()
	if _, err := f.status(bound, 1, IssueDone, ""); err != nil {
		t.Fatal(err)
	}
	events, err := f.store.ListEvents(f.ctx, bound.ID, 0)
	if err != nil {
		t.Fatal(err)
	}
	var kinds []string
	for i, e := range events {
		if e.Seq != int64(i+1) {
			t.Fatalf("event %d seq = %d", i, e.Seq)
		}
		kinds = append(kinds, string(e.Kind))
	}
	if strings.Join(kinds, ",") != "created,claimed,bound,released" {
		t.Fatalf("timeline = %v", kinds)
	}
	tail, _ := f.store.ListEvents(f.ctx, bound.ID, 2.5)
	if len(tail) != 2 || tail[0].Seq != 3 {
		t.Fatalf("afterSeq cursor = %+v", tail)
	}
	// UNIQUE(issueId, seq) is enforced once EnsureIndexes ran.
	dup := issueEventRecord{ID: "iev_dup", IssueID: bound.ID, TeamID: "t1", Seq: int32(1), Kind: IssueEventCreated, ActorUnionID: "x"}
	if err := f.db.Collection(issueEventsCollection).InsertOne(f.ctx, dup); !errors.Is(err, ErrConflict) {
		t.Fatalf("duplicate (issueId, seq) insert err = %v", err)
	}
}

func TestIssueCreateValidationAndTruncation(t *testing.T) {
	f := newIssueFixture(t)
	for _, title := range []string{"", "   ", "\t\n", " \u3000", "\ufeff"} {
		_, err := f.store.Create(f.ctx, CreateIssueInput{TeamID: "t1", Title: title, CreatedBy: "u"})
		wantReason(t, err, "invalid")
	}
	// U+0085 is not JS whitespace, so the title is not blank.
	if _, err := f.store.Create(f.ctx, CreateIssueInput{TeamID: "t1", Title: "\u0085", CreatedBy: "u"}); err != nil {
		t.Fatalf("NEL title rejected: %v", err)
	}
	longTitle := strings.Repeat("a", 199) + "😀tail"
	doc, err := f.store.Create(f.ctx, CreateIssueInput{
		TeamID: "t1", Title: longTitle, Body: strings.Repeat("中", 20000), CreatedBy: "u",
		TargetRepoLabel: strings.Repeat("r", 70), Labels: []string{},
	})
	if err != nil {
		t.Fatal(err)
	}
	if doc.Title != strings.Repeat("a", 199)+"\uFFFD" {
		t.Fatalf("title must be cut at 200 UTF-16 units like String#slice: %q", doc.Title)
	}
	if len([]rune(doc.Body)) != issueBodyMax || len(doc.TargetRepoLabel) != issueRepoLabelMax {
		t.Fatalf("body/label truncation: %d %d", len([]rune(doc.Body)), len(doc.TargetRepoLabel))
	}
	if stored := f.get(doc.ID); stored.Title != doc.Title || stored.Labels == nil || len(*stored.Labels) != 0 {
		t.Fatalf("stored issue: %+v", stored)
	}
}

func TestIssueCreateJSONMatchesTSLiteral(t *testing.T) {
	f := newIssueFixture(t)
	doc, err := f.store.Create(f.ctx, CreateIssueInput{
		TeamID: "t1", Title: "<b>&", Body: "b", Labels: []string{"bug"},
		TargetRepoID: "repo_1", TargetRepoLabel: "botmux",
		CustomFields:             IssueCustomFields{{ID: "zeta", Value: "z"}, {ID: "alpha", Value: []string{"a", "b"}}},
		SuggestedAssigneeUnionID: "u-x", CreatedBy: "u", CreatedByName: "U",
	})
	if err != nil {
		t.Fatal(err)
	}
	want := `{"_id":"` + doc.ID + `","teamId":"t1","title":"<b>&","body":"b","status":"open","labels":["bug"],` +
		`"targetRepoId":"repo_1","targetRepoLabel":"botmux","customFields":{"zeta":"z","alpha":["a","b"]},` +
		`"suggestedAssigneeUnionId":"u-x","createdBy":"u","createdByName":"U","createdAt":1760000000000,` +
		`"updatedAt":1760000000000,"rev":1,"stateRev":1,"claimEpochCounter":0,"eventSeq":1}`
	if got := marshalNoEscape(t, doc); got != want {
		t.Fatalf("create JSON:\n got %s\nwant %s", got, want)
	}
	stored := f.get(doc.ID)
	if v, ok := stored.CustomFields.Get("alpha"); !ok || strings.Join(v.([]string), ",") != "a,b" {
		t.Fatalf("custom fields round trip: %+v", stored.CustomFields)
	}
}

func TestIssueCustomFieldsKeepOrderThroughBSONAndJSON(t *testing.T) {
	fields := IssueCustomFields{{ID: "z", Value: "1"}, {ID: "a", Value: []string{}}, {ID: "m", Value: "<&>"}}
	var decoded struct {
		F IssueCustomFields `bson:"f"`
	}
	raw, err := marshalBSON(struct {
		F IssueCustomFields `bson:"f"`
	}{fields})
	if err != nil {
		t.Fatal(err)
	}
	if err := unmarshalBSON(raw, &decoded); err != nil {
		t.Fatal(err)
	}
	if got := marshalNoEscape(t, decoded.F); got != `{"z":"1","a":[],"m":"<&>"}` {
		t.Fatalf("custom fields order lost: %s", got)
	}
	var fromJSON IssueCustomFields
	if err := json.Unmarshal([]byte(`{"q":"x","b":["y","z"],"n":null}`), &fromJSON); err != nil {
		t.Fatal(err)
	}
	if got := marshalNoEscape(t, fromJSON); got != `{"q":"x","b":["y","z"],"n":null}` {
		t.Fatalf("JSON decode order: %s", got)
	}
}

func TestIssueWritesUseNodeBSONTypes(t *testing.T) {
	f := newIssueFixture(t)
	bound := f.boundIssue()
	if _, err := f.status(bound, 7, IssueInProgress, ""); err != nil {
		t.Fatal(err)
	}
	raw := f.rawIssue(bound.ID)
	for field, want := range map[string]string{
		"createdAt": "double", "updatedAt": "double", "rev": "int32", "stateRev": "int32",
		"claimEpochCounter": "int32", "eventSeq": "int32",
	} {
		if got := goBSONType(raw[field]); got != want {
			t.Errorf("issue.%s stored as %s, want %s", field, got, want)
		}
	}
	claim := raw["claim"].(map[string]any)
	for field, want := range map[string]string{
		"claimEpoch": "int32", "claimedAt": "double", "leaseExpiresAt": "double", "lastSourceSeq": "int32",
	} {
		if got := goBSONType(claim[field]); got != want {
			t.Errorf("claim.%s stored as %s, want %s", field, got, want)
		}
	}
	for _, event := range f.db.MemoryCollection(issueEventsCollection).Documents() {
		if goBSONType(event["seq"]) != "int32" || goBSONType(event["at"]) != "double" {
			t.Fatalf("event numeric types: %#v", event)
		}
	}
	// Non-int32 sourceSeq values keep JS number semantics (double).
	progressed := f.get(bound.ID)
	if _, err := f.status(progressed, 1e10, IssueInReview, ""); err != nil {
		t.Fatal(err)
	}
	if got := goBSONType(f.rawIssue(bound.ID)["claim"].(map[string]any)["lastSourceSeq"]); got != "double" {
		t.Fatalf("large sourceSeq stored as %s", got)
	}
}

type failingDatabaseProvider struct{}

func (failingDatabaseProvider) Database(context.Context) (DocumentDatabase, error) {
	return nil, errors.New("dial tcp: connection refused")
}

func TestIssueStoreFailsClosed(t *testing.T) {
	ctx := context.Background()
	for name, s := range map[string]*IssueStore{
		"nil store":        nil,
		"nil provider":     NewIssueStore(nil),
		"empty provider":   NewIssueStore(StaticDatabaseProvider{}),
		"failing provider": NewIssueStore(failingDatabaseProvider{}),
		"memory mode":      NewIssueStore(UnavailableDatabaseProvider{}),
	} {
		t.Run(name, func(t *testing.T) {
			ops := map[string]error{}
			_, ops["list"] = s.ListForTeam(ctx, "t1", false)
			_, ops["get"] = s.Get(ctx, "iss_1")
			_, ops["events"] = s.ListEvents(ctx, "iss_1", 0)
			_, ops["create"] = s.Create(ctx, CreateIssueInput{TeamID: "t1", Title: ""})
			_, ops["patch"] = s.Patch(ctx, "iss_1", 1, IssuePatch{})
			_, ops["claim"] = s.Claim(ctx, "iss_1", ClaimIssueInput{})
			_, ops["bind"] = s.Bind(ctx, "iss_1", BindIssueInput{})
			_, ops["status"] = s.StatusWriteback(ctx, "iss_1", StatusWritebackInput{})
			_, ops["detach"] = s.ForceDetach(ctx, "iss_1", "u", 1)
			_, ops["archive"] = s.Archive(ctx, "iss_1", "u")
			_, ops["sweep"] = s.SweepExpiredLeases(ctx)
			ops["indexes"] = s.EnsureIndexes(ctx)
			for op, err := range ops {
				if !errors.Is(err, ErrUnavailable) || StoreReason(err) != "unavailable" {
					t.Errorf("%s: err = %v, want unavailable (unavailable precedes invalid input)", op, err)
				}
			}
		})
	}
}

// faultDatabase injects driver errors into chosen collections.
type faultDatabase struct {
	inner  *MemoryDatabase
	faults map[string]error
}

func (d faultDatabase) Collection(name string) DocumentCollection {
	if err, ok := d.faults[name]; ok {
		return faultCollection{DocumentCollection: d.inner.Collection(name), err: err}
	}
	return d.inner.Collection(name)
}

type faultCollection struct {
	DocumentCollection
	err error
}

func (c faultCollection) InsertOne(context.Context, any) error { return c.err }
func (c faultCollection) FindOneAndUpdate(context.Context, Document, Document, FindOneAndUpdateOptions, any) error {
	return c.err
}

func TestIssueDriverErrorsMapToUnavailable(t *testing.T) {
	ctx := context.Background()
	db := NewMemoryDatabase()
	healthy := NewIssueStore(StaticDatabaseProvider{DB: db})
	issue, err := healthy.Create(ctx, CreateIssueInput{TeamID: "t1", Title: "x", CreatedBy: "u"})
	if err != nil {
		t.Fatal(err)
	}
	// TS catches every driver exception, including duplicate keys, as
	// 'unavailable' -> 503; it must not surface as a 409 'conflict'.
	broken := NewIssueStore(StaticDatabaseProvider{DB: faultDatabase{inner: db, faults: map[string]error{issuesCollection: ErrConflict}}})
	_, err = broken.Create(ctx, CreateIssueInput{TeamID: "t1", Title: "x", CreatedBy: "u"})
	wantReason(t, err, "unavailable")
	_, err = broken.Claim(ctx, issue.ID, ClaimIssueInput{ClaimID: "c1", ExpectedStateRev: 1})
	wantReason(t, err, "unavailable")

	// Event appends are best-effort: a broken timeline never fails the write.
	noEvents := NewIssueStore(StaticDatabaseProvider{DB: faultDatabase{inner: db, faults: map[string]error{issueEventsCollection: errors.New("boom")}}})
	if _, err := noEvents.Create(ctx, CreateIssueInput{TeamID: "t1", Title: "y", CreatedBy: "u"}); err != nil {
		t.Fatalf("create with broken timeline: %v", err)
	}
}

func TestIssuePersistenceAvailable(t *testing.T) {
	if NewIssueStore(UnavailableDatabaseProvider{}).PersistenceAvailable() || NewIssueStore(&UnavailableDatabaseProvider{}).PersistenceAvailable() {
		t.Fatal("memory-mode wiring has no issue authority")
	}
	if NewIssueStore(NewMemoryDatabaseProvider()).PersistenceAvailable() {
		t.Fatal("memory mode has no issue authority")
	}
	provider := NewMemoryDatabaseProvider()
	if NewIssueStore(&provider).PersistenceAvailable() {
		t.Fatal("pointer to the memory provider is still memory mode")
	}
	if NewIssueStore(nil).PersistenceAvailable() {
		t.Fatal("no provider means no persistence")
	}
	if !NewIssueStore(&RetryingDatabaseProvider{}).PersistenceAvailable() {
		t.Fatal("a MongoDB provider is persistent even while unavailable")
	}
}

func TestStoreReason(t *testing.T) {
	for err, want := range map[error]string{
		nil:                                  "",
		ErrNotFound:                          "not_found",
		ErrConflict:                          "conflict",
		ErrUnavailable:                       "unavailable",
		context.Canceled:                     "unavailable",
		failClosed(errors.New("x")):          "unavailable",
		ErrStateRevConflict:                  "state_rev_conflict",
		ErrIssueForbidden:                    "forbidden",
		errors.Join(ErrInvalid, ErrConflict): "invalid",
	} {
		if got := StoreReason(err); got != want {
			t.Errorf("StoreReason(%v) = %q, want %q", err, got, want)
		}
	}
}

func TestJSCompatibilityHelpers(t *testing.T) {
	for value, want := range map[float64]string{
		0: "int32", 1: "int32", -5: "int32", 2147483647: "int32", -2147483648: "int32",
		2147483648: "double", 1.5: "double", 1760000000000: "double",
	} {
		if got := goBSONType(jsNumber(value)); got != want {
			t.Errorf("jsNumber(%v) = %s, want %s", value, got, want)
		}
	}
	if goBSONType(jsNumber(negativeZero())) != "double" {
		t.Error("-0 is a double in the Node serializer")
	}
	for _, tc := range []struct {
		in    string
		limit int
		want  string
	}{
		{"hello", 10, "hello"}, {"hello", 3, "hel"}, {"中文字", 2, "中文"},
		{"a😀b", 2, "a\uFFFD"}, {"a😀b", 3, "a😀"}, {"😀", 0, ""},
	} {
		if got := truncateUTF16(tc.in, tc.limit); got != tc.want {
			t.Errorf("truncateUTF16(%q, %d) = %q, want %q", tc.in, tc.limit, got, tc.want)
		}
	}
	if !isJSBlank("   \ufeff") || isJSBlank("\u0085") || isJSBlank("x ") {
		t.Error("isJSBlank must follow String#trim")
	}
}

// ---- shared test helpers ----

// marshalNoEscape encodes like internal/server writeJSON (JSON.stringify bytes).
func marshalNoEscape(t *testing.T, value any) string {
	t.Helper()
	var out strings.Builder
	encoder := json.NewEncoder(&out)
	encoder.SetEscapeHTML(false)
	if err := encoder.Encode(value); err != nil {
		t.Fatalf("json encode: %v", err)
	}
	return strings.TrimSuffix(out.String(), "\n")
}

func marshalBSON(value any) ([]byte, error) { return bson.Marshal(value) }

func unmarshalBSON(raw []byte, dst any) error { return bson.Unmarshal(raw, dst) }

// goBSONType names the BSON type of a MemoryDatabase value (memdoc keeps the
// decoded driver types, so this is the physical type MongoDB would store).
func goBSONType(value any) string {
	switch value.(type) {
	case float64:
		return "double"
	case int32:
		return "int32"
	case int64:
		return "int64"
	case string:
		return "string"
	case bool:
		return "bool"
	case primitive.DateTime:
		return "date"
	case map[string]any:
		return "document"
	case []any:
		return "array"
	case nil:
		return "null"
	default:
		return fmt.Sprintf("%T", value)
	}
}

func negativeZero() float64 { return math.Copysign(0, -1) }
