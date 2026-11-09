package tunnel

import (
	"fmt"
	"testing"
	"time"
)

const throttleMachine = "feedfacefeedface"

func throttleAt(ms int64) time.Time { return time.UnixMilli(ms) }

func TestFanoutColdMemoRunsFirstBeat(t *testing.T) {
	t.Parallel()
	throttle := NewFanoutThrottle()
	if !throttle.ShouldRun(throttleMachine, 5*time.Second, throttleAt(1_000_000)) {
		t.Fatal("cold memo must run immediately")
	}
	if stats := throttle.Stats(); stats.Runs != 1 {
		t.Fatalf("runs = %d", stats.Runs)
	}
}

func TestFanoutStormRunsOncePerWindow(t *testing.T) {
	t.Parallel()
	throttle := NewFanoutThrottle()
	ran := 0
	for i := int64(0); i < 1000; i++ {
		if throttle.ShouldRun(throttleMachine, 5*time.Second, throttleAt(1_000_000+i)) {
			ran++
		}
	}
	if ran != 1 {
		t.Fatalf("storm ran %d times", ran)
	}
	if stats := throttle.Stats(); stats.Runs != 1 || stats.Skipped != 999 {
		t.Fatalf("stats = %+v", stats)
	}
}

func TestFanoutNormalHeartbeatsAlwaysRun(t *testing.T) {
	t.Parallel()
	throttle := NewFanoutThrottle()
	ran := 0
	for i := int64(0); i < 5; i++ {
		if throttle.ShouldRun(throttleMachine, BackendFanoutThrottle, throttleAt(1_000_000+i*30_000)) {
			ran++
		}
	}
	if ran != 5 {
		t.Fatalf("heartbeats ran %d of 5", ran)
	}
}

func TestFanoutWindowBoundaryIsAbsolute(t *testing.T) {
	t.Parallel()
	throttle := NewFanoutThrottle()
	window := 5 * time.Second
	t0 := int64(1_000_000)
	steps := []struct {
		at   int64
		want bool
	}{
		{t0, true},
		{t0 + 4999, false},
		{t0 + 5000, true},
		{t0 + 5000 + 4999, false},
	}
	for _, step := range steps {
		if got := throttle.ShouldRun(throttleMachine, window, throttleAt(step.at)); got != step.want {
			t.Fatalf("at %d: got %v want %v", step.at, got, step.want)
		}
	}
}

func TestFanoutReconnectAfterWindowRunsImmediately(t *testing.T) {
	t.Parallel()
	throttle := NewFanoutThrottle()
	if !throttle.ShouldRun(throttleMachine, 5*time.Second, throttleAt(1_000_000)) {
		t.Fatal("first beat must run")
	}
	if !throttle.ShouldRun(throttleMachine, 5*time.Second, throttleAt(1_060_000)) {
		t.Fatal("reconnect after the window must run immediately")
	}
}

func TestFanoutSerialReconnectStormIsStillThrottled(t *testing.T) {
	t.Parallel()
	throttle := NewFanoutThrottle()
	ran := 0
	for i := int64(0); i < 50; i++ {
		if throttle.ShouldRun(throttleMachine, 5*time.Second, throttleAt(1_000_000+i*100)) {
			ran++
		}
	}
	if ran != 1 {
		t.Fatalf("crash-loop reconnects ran %d times", ran)
	}
}

func TestFanoutMachinesAreIndependent(t *testing.T) {
	t.Parallel()
	throttle := NewFanoutThrottle()
	a, b := "aaaaaaaaaaaaaaaa", "bbbbbbbbbbbbbbbb"
	t0 := int64(1_000_000)
	if !throttle.ShouldRun(a, 5*time.Second, throttleAt(t0)) || !throttle.ShouldRun(b, 5*time.Second, throttleAt(t0)) {
		t.Fatal("first beat of each machine must run")
	}
	if throttle.ShouldRun(a, 5*time.Second, throttleAt(t0+100)) || throttle.ShouldRun(b, 5*time.Second, throttleAt(t0+100)) {
		t.Fatal("each machine is throttled on its own memo")
	}
	if stats := throttle.Stats(); stats.Runs != 2 {
		t.Fatalf("runs = %d", stats.Runs)
	}
}

func TestFanoutPrunesOnlyLongIdleEntriesAboveThreshold(t *testing.T) {
	t.Parallel()
	throttle := NewFanoutThrottle()
	t0 := int64(1_000_000)
	for i := 0; i < fanoutPruneWhenSizeAbove; i++ {
		throttle.ShouldRun(fmt.Sprintf("idle-%d", i), BackendFanoutThrottle, throttleAt(t0))
	}
	// At the threshold nothing is pruned yet.
	throttle.ShouldRun("recent", BackendFanoutThrottle, throttleAt(t0+int64(fanoutPruneIdle/time.Millisecond)))
	if size := throttle.Stats().Size; size != fanoutPruneWhenSizeAbove+1 {
		t.Fatalf("size before prune = %d", size)
	}
	// The next run is past the idle threshold for every idle-* entry.
	throttle.ShouldRun("trigger", BackendFanoutThrottle, throttleAt(t0+int64(fanoutPruneIdle/time.Millisecond)+1))
	if size := throttle.Stats().Size; size != 2 {
		t.Fatalf("size after prune = %d, want only the two fresh entries", size)
	}
}

func TestShouldRunBackendFanoutUsesProcessThrottle(t *testing.T) {
	t.Parallel()
	id := "process-wide-throttle-test"
	if !ShouldRunBackendFanout(id) {
		t.Fatal("first call must run")
	}
	if ShouldRunBackendFanout(id) {
		t.Fatal("immediate second call must be throttled")
	}
}
