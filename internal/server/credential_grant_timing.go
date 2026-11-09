package server

import (
	"log/slog"
	"strconv"
	"strings"
	"time"
)

// credentialGrantSlowAfter is the total handling time above which a grant
// logs its per-stage breakdown. Daemons give the whole request 6s; about 40%
// of grants were taking 3.6–3.9s with no way to tell which downstream
// (machine auth, MongoDB, provider token refresh, audit) was slow.
const credentialGrantSlowAfter = time.Second

// stageTimer records how long each named stage of one request took.
type stageTimer struct {
	now    func() time.Time
	start  time.Time
	last   time.Time
	stages []string
}

func newStageTimer(now func() time.Time) *stageTimer {
	if now == nil {
		now = time.Now
	}
	t := now()
	return &stageTimer{now: now, start: t, last: t}
}

// mark closes the stage that started at the previous mark.
func (t *stageTimer) mark(name string) {
	n := t.now()
	t.stages = append(t.stages, name+"="+strconv.FormatInt(n.Sub(t.last).Milliseconds(), 10))
	t.last = n
}

func (t *stageTimer) total() time.Duration { return t.now().Sub(t.start) }

// String is "stage=ms,stage=ms" in the order the stages ran.
func (t *stageTimer) String() string { return strings.Join(t.stages, ",") }

// logCredentialGrantTiming emits the breakdown for slow grants only, so the
// normal ~10ms path adds no log volume.
func logCredentialGrantTiming(t *stageTimer, outcome, machineID, platform string) {
	total := t.total()
	if total < credentialGrantSlowAfter {
		return
	}
	slog.Warn("credential grant slow", "outcome", outcome, "machineId", machineID, "platform", platform,
		"totalMs", total.Milliseconds(), "stagesMs", t.String())
}
