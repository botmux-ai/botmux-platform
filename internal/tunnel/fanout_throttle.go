package tunnel

import (
	"sync"
	"time"
)

// BackendFanoutThrottle is the per-machine window for idempotent, eventually
// consistent register/heartbeat side effects (MongoDB lastSeen/metadata writes
// and team-sync aggregation). The default daemon heartbeat is 30s, far above
// this window, so normal traffic runs every beat; only heartbeat/reconnect
// storms are capped to one fan-out per window.
//
// Never route security or correctness checks through this throttle (token
// revocation, registration authority, in-memory registry updates, the
// registered reply): only side effects that converge later are allowed.
const BackendFanoutThrottle = 5 * time.Second

const (
	// Far beyond any heartbeat interval: pruning an entry only means the next
	// report from that machine runs immediately, exactly like a cold memo.
	fanoutPruneIdle          = 10 * time.Minute
	fanoutPruneWhenSizeAbove = 2000
)

// FanoutThrottle remembers when each machine last ran its backend fan-out.
// The memo is per pod and must never be cleared on socket close: a crash loop
// that disconnects and reconnects faster than the window would otherwise see a
// cold memo every time and bypass the throttle completely. Freshness alone
// separates storms (sub-window) from ordinary reconnects (memo expired).
type FanoutThrottle struct {
	mu      sync.Mutex
	last    map[string]time.Time
	runs    int
	skipped int
}

// NewFanoutThrottle returns an empty throttle.
func NewFanoutThrottle() *FanoutThrottle {
	return &FanoutThrottle{last: make(map[string]time.Time)}
}

var defaultFanoutThrottle = NewFanoutThrottle()

// ShouldRunBackendFanout applies the process-wide throttle with the default
// window at the current time.
func ShouldRunBackendFanout(machineID string) bool {
	return defaultFanoutThrottle.ShouldRun(machineID, BackendFanoutThrottle, time.Now())
}

// ShouldRun reports whether this register/heartbeat should execute the backend
// fan-out. A true result also records now as the machine's latest run; the
// window is absolute (not sliding), so skipped calls never extend it.
func (t *FanoutThrottle) ShouldRun(machineID string, window time.Duration, now time.Time) bool {
	t.mu.Lock()
	defer t.mu.Unlock()
	if last, ok := t.last[machineID]; ok && now.Sub(last) < window {
		t.skipped++
		return false
	}
	t.last[machineID] = now
	t.runs++
	t.maybePrune(now)
	return true
}

func (t *FanoutThrottle) maybePrune(now time.Time) {
	if len(t.last) <= fanoutPruneWhenSizeAbove {
		return
	}
	for id, at := range t.last {
		if now.Sub(at) > fanoutPruneIdle {
			delete(t.last, id)
		}
	}
}

// FanoutThrottleStats is a diagnostic snapshot of a throttle.
type FanoutThrottleStats struct {
	Runs    int
	Skipped int
	Size    int
}

// Stats returns run/skip counters and the current memo size.
func (t *FanoutThrottle) Stats() FanoutThrottleStats {
	t.mu.Lock()
	defer t.mu.Unlock()
	return FanoutThrottleStats{Runs: t.runs, Skipped: t.skipped, Size: len(t.last)}
}
