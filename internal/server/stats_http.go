package server

import (
	"context"
	"encoding/json"
	"io"
	"log/slog"
	"net/http"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/botmux-ai/botmux-platform/internal/auth"
	"github.com/botmux-ai/botmux-platform/internal/store"
	"github.com/botmux-ai/botmux-platform/internal/tunnel"
)

// Version dashboard (src/server/stats-http.ts). Owned by Phase 2 agent B4.
//
// GET /api/stats/versions: the platform-wide botmux version distribution for
// any signed-in user. Only aggregate counts (machines + distinct owners) are
// returned — never machine names, owners or ids. Three windows are computed
// at once: online (lastSeen within StaleAfter), active7d and all (machines
// that never connected are excluded). The latest version is the official npm
// `latest` release, never the highest user-reported value (forks may report
// anything). The distribution is cached 60s per pod, the release lookup
// 10min (1min after a failure, stale-while-revalidate).

// ActiveWindow is the active7d window.
const ActiveWindow = 7 * 24 * time.Hour

const (
	statsDistributionTTL = 60 * time.Second
	releaseOKTTL         = 10 * time.Minute
	releaseRetryTTL      = time.Minute
	releaseFetchTimeout  = 3 * time.Second
)

// WindowCount is machines plus distinct owners: one person with ten machines
// counts once, so a version's stability signal is not inflated.
type WindowCount struct {
	Machines int `json:"machines"`
	Users    int `json:"users"`
}

type WindowCounts struct {
	Online   WindowCount `json:"online"`
	Active7d WindowCount `json:"active7d"`
	All      WindowCount `json:"all"`
}

// VersionBucket is one version row. AtOrAbove is the cumulative count of
// this and newer versions (owners as a union); null for versions that cannot
// be ordered (unknown, self-built).
type VersionBucket struct {
	Version   string        `json:"version"`
	Online    WindowCount   `json:"online"`
	Active7d  WindowCount   `json:"active7d"`
	All       WindowCount   `json:"all"`
	AtOrAbove *WindowCounts `json:"atOrAbove"`
}

// VersionDistribution lists versions newest first; unparseable ones last.
type VersionDistribution struct {
	GeneratedAt int64           `json:"generatedAt"`
	Totals      WindowCounts    `json:"totals"`
	Versions    []VersionBucket `json:"versions"`
}

// VersionStats is the response body; LatestVersion is null when no registry
// answered (never the highest user-reported version).
type VersionStats struct {
	VersionDistribution
	LatestVersion *string `json:"latestVersion"`
}

var (
	semverPattern = regexp.MustCompile(`^(0|[1-9]\d*)\.(0|[1-9]\d*)\.(0|[1-9]\d*)` +
		`(?:-((?:0|[1-9]\d*|\d*[A-Za-z-][0-9A-Za-z-]*)(?:\.(?:0|[1-9]\d*|\d*[A-Za-z-][0-9A-Za-z-]*))*))?` +
		`(?:\+[0-9A-Za-z-]+(?:\.[0-9A-Za-z-]+)*)?$`)
	leadingVDigit     = regexp.MustCompile(`^v\d`)
	versionCorePrefix = regexp.MustCompile(`^\d+\.\d+\.\d+`)
	// JS `.` stops at every line terminator, not only '\n'.
	buildMetadataSuffix = regexp.MustCompile(`\+[^\n\r\x{2028}\x{2029}]*$`)
	allDigits           = regexp.MustCompile(`^\d+$`)
)

// NormalizeVersion ports normalizeVersion: trim, drop a leading "v" before a
// digit and SemVer build metadata (`v1.2.3` / `1.2.3+ci.1` are 1.2.3), and
// map empty / non-string values to "unknown".
func NormalizeVersion(value any) string {
	s, _ := value.(string)
	s = strings.TrimFunc(s, isECMAWhitespace)
	if leadingVDigit.MatchString(s) {
		s = s[1:]
	}
	if versionCorePrefix.MatchString(s) {
		if loc := buildMetadataSuffix.FindStringIndex(s); loc != nil {
			s = s[:loc[0]]
		}
	}
	if s == "" {
		return "unknown"
	}
	return s
}

// isECMAWhitespace is the WhiteSpace + LineTerminator set of String#trim.
func isECMAWhitespace(r rune) bool {
	switch r {
	case '\t', '\n', '\v', '\f', '\r', ' ',
		'\u00a0', '\u1680', '\u2028', '\u2029', '\u202f', '\u205f', '\u3000', '\ufeff':
		return true
	}
	return r >= '\u2000' && r <= '\u200a'
}

type parsedSemver struct {
	core [3]float64
	pre  []string
}

func parseSemver(version string) (parsedSemver, bool) {
	m := semverPattern.FindStringSubmatch(version)
	if m == nil {
		return parsedSemver{}, false
	}
	var out parsedSemver
	for i := 0; i < 3; i++ {
		out.core[i], _ = strconv.ParseFloat(m[i+1], 64) // Number(): huge values round like JS
	}
	if m[4] != "" {
		out.pre = strings.Split(m[4], ".")
	}
	return out, true
}

// comparePrerelease is SemVer §11 precedence (ascending): a release sorts
// above any prerelease, numeric identifiers compare numerically and below
// alphanumeric ones, and a shorter prefix is lower.
func comparePrerelease(a, b []string) float64 {
	if len(a) == 0 || len(b) == 0 {
		return float64(len(b) - len(a))
	}
	for i := 0; i < len(a) && i < len(b); i++ {
		na, nb := allDigits.MatchString(a[i]), allDigits.MatchString(b[i])
		switch {
		case na && nb:
			x, _ := strconv.ParseFloat(a[i], 64)
			y, _ := strconv.ParseFloat(b[i], 64)
			if d := x - y; d != 0 {
				return d
			}
		case na != nb:
			if na {
				return -1
			}
			return 1
		case a[i] != b[i]:
			if a[i] < b[i] {
				return -1
			}
			return 1
		}
	}
	return float64(len(a) - len(b))
}

// CompareVersionDesc orders versions newest first by SemVer precedence;
// unparseable versions sort last, among themselves by localeCompare.
func CompareVersionDesc(a, b string) int {
	return compareVersionDesc(a, b, newLocaleCollator())
}

func compareVersionDesc(a, b string, collator localeCollator) int {
	pa, okA := parseSemver(a)
	pb, okB := parseSemver(b)
	switch {
	case okA && !okB:
		return -1
	case !okA && okB:
		return 1
	case okA && okB:
		for i := 0; i < 3; i++ {
			if pa.core[i] != pb.core[i] {
				return signOf(pb.core[i] - pa.core[i])
			}
		}
		if pre := comparePrerelease(pb.pre, pa.pre); pre != 0 {
			return signOf(pre)
		}
	}
	return collator.compare(a, b)
}

func signOf(value float64) int {
	switch {
	case value < 0:
		return -1
	case value > 0:
		return 1
	}
	return 0
}

// LiveMachines is the registry view used to overlay pod-local live state.
type LiveMachines interface {
	Get(machineID string) (tunnel.MachineConn, bool)
	IsStale(tunnel.MachineConn) bool
}

// OverlayLive ports overlayLive: a machine connected to this pod reports its
// live version (a newer persisted lastSeen does not mean a newer persisted
// version: persistence is throttled and heartbeats may omit the version) and
// the larger lastSeen. Stale local connections are ignored and nothing is
// added: the registered set is the persisted one (RETIRED excluded).
func OverlayLive(samples []store.MachineVersionSample, live LiveMachines) []store.MachineVersionSample {
	out := make([]store.MachineVersionSample, len(samples))
	copy(out, samples)
	if live == nil {
		return out
	}
	for i := range out {
		conn, ok := live.Get(out[i].MachineID)
		if !ok || live.IsStale(conn) {
			continue
		}
		if conn.BotmuxVersion != "" {
			out[i].BotmuxVersion = conn.BotmuxVersion
		}
		if seen := conn.LastSeen.UnixMilli(); seen > out[i].LastSeen {
			out[i].LastSeen = seen
		}
	}
	return out
}

type windowAccumulator struct {
	machines int
	users    map[string]struct{}
}

func newWindowAccumulators() [3]windowAccumulator {
	var out [3]windowAccumulator
	for i := range out {
		out[i].users = make(map[string]struct{})
	}
	return out
}

func (w windowAccumulator) count() WindowCount {
	return WindowCount{Machines: w.machines, Users: len(w.users)}
}

func windowCounts(acc [3]windowAccumulator) WindowCounts {
	return WindowCounts{Online: acc[0].count(), Active7d: acc[1].count(), All: acc[2].count()}
}

// SummarizeVersions ports summarizeVersions: samples -> windows x versions.
func SummarizeVersions(samples []store.MachineVersionSample, now time.Time, staleAfter time.Duration) VersionDistribution {
	nowMs := now.UnixMilli()
	type bucket struct {
		version string
		acc     [3]windowAccumulator
	}
	byVersion := make(map[string]*bucket)
	var order []*bucket
	totals := newWindowAccumulators()
	for _, sample := range samples {
		if sample.LastSeen <= 0 {
			continue // bound but never connected: no real version
		}
		age := nowMs - sample.LastSeen
		inWindow := [3]bool{age <= staleAfter.Milliseconds(), age <= ActiveWindow.Milliseconds(), true}
		version := NormalizeVersion(sample.BotmuxVersion)
		b := byVersion[version]
		if b == nil {
			b = &bucket{version: version, acc: newWindowAccumulators()}
			byVersion[version] = b
			order = append(order, b)
		}
		for w := 0; w < 3; w++ {
			if !inWindow[w] {
				continue
			}
			b.acc[w].machines++
			b.acc[w].users[sample.UnionID] = struct{}{}
			totals[w].machines++
			totals[w].users[sample.UnionID] = struct{}{}
		}
	}
	collator := newLocaleCollator()
	sort.SliceStable(order, func(i, j int) bool {
		return compareVersionDesc(order[i].version, order[j].version, collator) < 0
	})
	// Newest to oldest running totals; owners as a union so one person with
	// an old and a new machine is not counted twice.
	running := newWindowAccumulators()
	versions := make([]VersionBucket, 0, len(order))
	for _, b := range order {
		for w := 0; w < 3; w++ {
			running[w].machines += b.acc[w].machines
			for user := range b.acc[w].users {
				running[w].users[user] = struct{}{}
			}
		}
		row := VersionBucket{Version: b.version, Online: b.acc[0].count(), Active7d: b.acc[1].count(), All: b.acc[2].count()}
		if _, ok := parseSemver(b.version); ok {
			cumulative := windowCounts(running)
			row.AtOrAbove = &cumulative
		}
		versions = append(versions, row)
	}
	return VersionDistribution{GeneratedAt: nowMs, Totals: windowCounts(totals), Versions: versions}
}

// ReleaseFetch performs GET url with the given headers and reports whether
// the response was ok (2xx) plus its body. A non-nil error is a failed fetch.
type ReleaseFetch func(ctx context.Context, url string, headers map[string]string) (ok bool, body []byte, err error)

// ReleaseLookup is the result of one registry round. Primary reports whether
// the first (authoritative, public npm) registry answered.
type ReleaseLookup struct {
	Version *string
	Primary bool
}

func defaultReleaseFetch() ReleaseFetch {
	// Node's fetch ignores HTTP(S)_PROXY; stay direct like it.
	transport := http.DefaultTransport.(*http.Transport).Clone()
	transport.Proxy = nil
	client := &http.Client{Transport: transport}
	return func(ctx context.Context, url string, headers map[string]string) (bool, []byte, error) {
		req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
		if err != nil {
			return false, nil, err
		}
		for key, value := range headers {
			req.Header.Set(key, value)
		}
		res, err := client.Do(req)
		if err != nil {
			return false, nil, err
		}
		defer res.Body.Close()
		body, err := io.ReadAll(io.LimitReader(res.Body, 1<<20))
		if err != nil {
			return false, nil, err
		}
		return res.StatusCode >= 200 && res.StatusCode < 300, body, nil
	}
}

// FetchLatestRelease queries `${registry}/botmux/latest` on every registry
// in parallel. The first registry is authoritative: when it answers with a
// valid SemVer it wins immediately without waiting for the mirrors. Otherwise
// the highest valid mirror answer is used (mirrors lag); null when all fail.
func FetchLatestRelease(ctx context.Context, registries []string, fetch ReleaseFetch) ReleaseLookup {
	if len(registries) == 0 {
		return ReleaseLookup{}
	}
	if fetch == nil {
		fetch = defaultReleaseFetch()
	}
	results := make([]chan string, len(registries))
	for i, registry := range registries {
		results[i] = make(chan string, 1)
		go func(out chan<- string, registry string) {
			fetchCtx, cancel := context.WithTimeout(ctx, releaseFetchTimeout)
			defer cancel()
			out <- fetchReleaseVersion(fetchCtx, registry, fetch)
		}(results[i], registry)
	}
	if primary := <-results[0]; primary != "" {
		return ReleaseLookup{Version: &primary, Primary: true}
	}
	var found []string
	for _, ch := range results[1:] {
		if version := <-ch; version != "" {
			found = append(found, version)
		}
	}
	if len(found) == 0 {
		return ReleaseLookup{}
	}
	collator := newLocaleCollator()
	sort.SliceStable(found, func(i, j int) bool { return compareVersionDesc(found[i], found[j], collator) < 0 })
	return ReleaseLookup{Version: &found[0]}
}

// fetchReleaseVersion returns the registry's valid SemVer latest version or
// "" for any failure (non-2xx, bad JSON, invalid version, timeout).
func fetchReleaseVersion(ctx context.Context, registry string, fetch ReleaseFetch) string {
	type result struct {
		ok   bool
		body []byte
		err  error
	}
	done := make(chan result, 1)
	go func() {
		ok, body, err := fetch(ctx, registry+"/botmux/latest", map[string]string{"accept": "application/json"})
		done <- result{ok, body, err}
	}()
	var res result
	select {
	case res = <-done:
	case <-ctx.Done(): // AbortSignal.timeout: a stuck fetch counts as failed
		return ""
	}
	if res.err != nil || !res.ok {
		return ""
	}
	var payload any
	if json.Unmarshal(res.body, &payload) != nil {
		return ""
	}
	var raw any
	if fields, ok := payload.(map[string]any); ok {
		raw = fields["version"]
	}
	version := NormalizeVersion(raw)
	if _, ok := parseSemver(version); !ok {
		return ""
	}
	return version
}

// ReleaseState is the cached latest-release value. OK means the
// authoritative registry answered (10min cache) — otherwise retry after 1min.
// Authoritative records whether Value came from that registry (even if
// expired): a mirror answer may then never overwrite it, including after the
// registry rolled `latest` back.
type ReleaseState struct {
	At            int64   `json:"at"`
	OK            bool    `json:"ok"`
	Value         *string `json:"value"`
	Authoritative bool    `json:"authoritative"`
}

// NextReleaseState ports nextReleaseState: trust the authoritative answer
// (rollbacks included); with only a mirror answer keep an authoritative
// value, otherwise keep the newer of the known and the new mirror value;
// when everything failed keep the previous value.
func NextReleaseState(prev *ReleaseState, lookup ReleaseLookup, now int64) ReleaseState {
	if lookup.Primary && lookup.Version != nil {
		return ReleaseState{At: now, OK: true, Value: lookup.Version, Authoritative: true}
	}
	if prev != nil && prev.Authoritative {
		next := *prev
		next.At, next.OK = now, false
		return next
	}
	var known *string
	if prev != nil {
		known = prev.Value
	}
	value := known
	if lookup.Version != nil && (known == nil || CompareVersionDesc(*lookup.Version, *known) < 0) {
		value = lookup.Version
	}
	return ReleaseState{At: now, OK: false, Value: value, Authoritative: false}
}

// VersionStatsState is the per-pod cache of the dashboard (distribution and
// release lookup, each with in-flight coalescing).
type VersionStatsState struct {
	// Fetch overrides the registry HTTP call (tests).
	Fetch ReleaseFetch
	// Now overrides the clock (tests).
	Now func() time.Time

	mu              sync.Mutex
	dist            *VersionDistribution
	distAt          time.Time
	distInflight    *statsCall[*VersionDistribution]
	release         *ReleaseState
	releaseInflight *statsCall[*string]
}

type statsCall[T any] struct {
	done  chan struct{}
	value T
}

func NewVersionStatsState() *VersionStatsState { return &VersionStatsState{} }

var defaultVersionStatsState = NewVersionStatsState()

// StatsDeps holds stats seams (release registry lookups, clocks).
type StatsDeps struct {
	// State is the dashboard cache; nil uses the process-wide one.
	State *VersionStatsState
}

func (s *VersionStatsState) now() time.Time {
	if s.Now != nil {
		return s.Now()
	}
	return time.Now()
}

// loadDistribution serves the 60s cache, coalescing concurrent cold loads
// into one scan. A store failure is not cached (nil = unavailable).
func (s *VersionStatsState) loadDistribution(ctx context.Context, repo store.Repository, live LiveMachines, staleAfter time.Duration) *VersionDistribution {
	s.mu.Lock()
	if s.dist != nil && s.now().Sub(s.distAt) < statsDistributionTTL {
		value := s.dist
		s.mu.Unlock()
		return value
	}
	call := s.distInflight
	if call == nil {
		call = &statsCall[*VersionDistribution]{done: make(chan struct{})}
		s.distInflight = call
		go func() {
			var value *VersionDistribution
			defer func() {
				s.mu.Lock()
				if value != nil {
					s.dist, s.distAt = value, s.now()
				}
				s.distInflight = nil
				s.mu.Unlock()
				call.value = value
				close(call.done)
			}()
			loadCtx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
			defer cancel()
			samples, err := repo.ListMachineVersionSamples(loadCtx)
			if err != nil {
				slog.Warn("version stats: list samples failed", "error", err)
				return // degraded: not cached, retried next time
			}
			summary := SummarizeVersions(OverlayLive(samples, live), s.now(), staleAfter)
			value = &summary
		}()
	}
	s.mu.Unlock()
	select {
	case <-call.done:
		return call.value
	case <-ctx.Done():
		return nil
	}
}

// loadLatestRelease returns the cached release, refreshing it after 10min
// (1min after a degraded lookup). An expired value is returned immediately
// while a background refresh runs; only a pod's very first lookup waits.
func (s *VersionStatsState) loadLatestRelease(ctx context.Context, registries []string) *string {
	s.mu.Lock()
	now := s.now()
	if s.release != nil {
		ttl := releaseRetryTTL
		if s.release.OK {
			ttl = releaseOKTTL
		}
		if now.UnixMilli()-s.release.At < ttl.Milliseconds() {
			value := s.release.Value
			s.mu.Unlock()
			return value
		}
	}
	call := s.releaseInflight
	if call == nil {
		call = &statsCall[*string]{done: make(chan struct{})}
		s.releaseInflight = call
		fetch := s.Fetch
		go func() {
			lookup := FetchLatestRelease(context.Background(), registries, fetch)
			if !lookup.Primary {
				slog.Warn("version stats: authoritative registry lookup failed", "registries", registries)
			}
			s.mu.Lock()
			next := NextReleaseState(s.release, lookup, s.now().UnixMilli())
			s.release = &next
			s.releaseInflight = nil
			s.mu.Unlock()
			call.value = next.Value
			close(call.done)
		}()
	}
	if s.release != nil {
		value := s.release.Value
		s.mu.Unlock()
		return value
	}
	s.mu.Unlock()
	select {
	case <-call.done:
		return call.value
	case <-ctx.Done():
		return nil
	}
}

func (a *Apex) versionStatsState() *VersionStatsState {
	if a.Stats.State != nil {
		return a.Stats.State
	}
	return defaultVersionStatsState
}

// handleStatsAPI serves /api/stats/* for an already-authenticated session.
func (a *Apex) handleStatsAPI(w http.ResponseWriter, r *http.Request, session *auth.SessionPayload) bool {
	_ = session // any signed-in user sees the platform-wide aggregate
	if requestPathname(r) != "/api/stats/versions" {
		return false
	}
	if r.Method != http.MethodGet {
		writeJSON(w, http.StatusMethodNotAllowed, map[string]any{"error": "method_not_allowed"})
		return true
	}
	state := a.versionStatsState()
	var live LiveMachines
	if a.Registry != nil {
		live = a.Registry
	}
	var (
		wg     sync.WaitGroup
		dist   *VersionDistribution
		latest *string
	)
	wg.Add(2)
	go func() {
		defer wg.Done()
		dist = state.loadDistribution(r.Context(), a.Repository, live, a.Config.StaleAfter)
	}()
	go func() {
		defer wg.Done()
		latest = state.loadLatestRelease(r.Context(), a.Config.BotmuxReleaseRegistries)
	}()
	wg.Wait()
	if dist == nil {
		writeJSON(w, http.StatusServiceUnavailable, map[string]any{"error": "store_unavailable"})
		return true
	}
	writeJSON(w, http.StatusOK, VersionStats{VersionDistribution: *dist, LatestVersion: latest})
	return true
}
