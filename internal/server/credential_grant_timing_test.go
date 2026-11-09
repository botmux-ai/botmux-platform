package server

import (
	"testing"
	"time"
)

func TestStageTimerRecordsEachStageInOrder(t *testing.T) {
	now := time.Unix(100, 0)
	clock := func() time.Time { return now }
	timer := newStageTimer(clock)
	now = now.Add(12 * time.Millisecond)
	timer.mark("auth")
	now = now.Add(3700 * time.Millisecond)
	timer.mark("mint")
	now = now.Add(5 * time.Millisecond)
	timer.mark("audit")
	if got, want := timer.String(), "auth=12,mint=3700,audit=5"; got != want {
		t.Fatalf("stages %q, want %q", got, want)
	}
	if got := timer.total(); got != 3717*time.Millisecond {
		t.Fatalf("total %v", got)
	}
}
