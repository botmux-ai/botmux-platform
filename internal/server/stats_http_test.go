package server

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"slices"
	"sort"
	"strings"
	"testing"
	"time"

	"github.com/botmux-ai/botmux-platform/internal/auth"
	"github.com/botmux-ai/botmux-platform/internal/config"
	"github.com/botmux-ai/botmux-platform/internal/store"
	"github.com/botmux-ai/botmux-platform/internal/tunnel"
)

// Port of test/server-stats-versions.test.ts: the pure aggregation plus the
// GET /api/stats/versions auth and "aggregate only" contract. The latest
// release comes from a local fake npm registry.

var _ LiveMachines = (*tunnel.Registry)(nil)

const statsDay = 24 * time.Hour

func sample(machineID, unionID, version string, lastSeen int64) store.MachineVersionSample {
	return store.MachineVersionSample{MachineID: machineID, UnionID: unionID, BotmuxVersion: version, LastSeen: lastSeen}
}

func sortVersions(values []string) []string {
	out := append([]string(nil), values...)
	sort.SliceStable(out, func(i, j int) bool { return CompareVersionDesc(out[i], out[j]) < 0 })
	return out
}

func TestNormalizeVersion(t *testing.T) {
	cases := []struct {
		in   any
		want string
	}{
		{"v1.2.3", "1.2.3"},
		{" 1.2.3 ", "1.2.3"},
		{"", "unknown"},
		{nil, "unknown"},
		{"dev-build", "dev-build"},
		{"1.2.3+ci.1", "1.2.3"},
		{"v1.2.3-rc.1+sha.abc", "1.2.3-rc.1"},
		{"\u00a0v2.0.0\ufeff", "2.0.0"},
		{42, "unknown"},
		{"V1.0.0", "V1.0.0"},
	}
	for _, c := range cases {
		if got := NormalizeVersion(c.in); got != c.want {
			t.Fatalf("NormalizeVersion(%#v) = %q, want %q", c.in, got, c.want)
		}
	}
}

func TestCompareVersionDesc(t *testing.T) {
	got := sortVersions([]string{"1.2.10", "unknown", "1.2.9", "1.10.0", "1.2.10-beta.1", "0.9.0"})
	if want := []string{"1.10.0", "1.2.10", "1.2.10-beta.1", "1.2.9", "0.9.0", "unknown"}; !slices.Equal(got, want) {
		t.Fatalf("sorted = %v", got)
	}
	// SemVer §11: numeric identifiers numerically, numeric < alphanumeric,
	// a shorter prefix is lower.
	got = sortVersions([]string{"1.2.3-rc.1", "1.2.3-rc.10", "1.2.3-rc.9", "1.2.3", "1.2.3-rc", "1.2.3-alpha", "1.2.3-1"})
	if want := []string{"1.2.3", "1.2.3-rc.10", "1.2.3-rc.9", "1.2.3-rc.1", "1.2.3-rc", "1.2.3-alpha", "1.2.3-1"}; !slices.Equal(got, want) {
		t.Fatalf("prerelease = %v", got)
	}
	// Invalid SemVer (leading zeros / empty identifiers) sorts after every
	// valid version, by localeCompare.
	got = sortVersions([]string{"01.2.3", "1.0.0", "1.2.3-rc..1", "1.2.3-01", "1.2.3-0a"})
	if want := []string{"1.2.3-0a", "1.0.0", "01.2.3", "1.2.3-01", "1.2.3-rc..1"}; !slices.Equal(got, want) {
		t.Fatalf("invalid = %v", got)
	}
}

func TestSummarizeVersionsWindows(t *testing.T) {
	now := time.UnixMilli(10 * ActiveWindow.Milliseconds())
	ms := now.UnixMilli()
	stats := SummarizeVersions([]store.MachineVersionSample{
		sample("m1", "u1", "1.2.0", ms-1000),
		sample("m2", "u1", "v1.2.0", ms-2000),
		sample("m3", "u2", "1.2.0", ms-3*statsDay.Milliseconds()),
		sample("m4", "u3", "1.1.0", ms-30*statsDay.Milliseconds()),
		sample("m5", "u4", "unknown", 0), // bound but never connected
		sample("m6", "u5", "0.0.0", ms-1000),
	}, now, 60*time.Second)
	want := WindowCounts{Online: WindowCount{3, 2}, Active7d: WindowCount{4, 3}, All: WindowCount{5, 4}}
	if stats.Totals != want {
		t.Fatalf("totals = %+v", stats.Totals)
	}
	var versions []string
	for _, v := range stats.Versions {
		versions = append(versions, v.Version)
	}
	if !slices.Equal(versions, []string{"1.2.0", "1.1.0", "0.0.0"}) {
		t.Fatalf("versions = %v", versions)
	}
	if v := stats.Versions[0]; v.Online != (WindowCount{2, 1}) || v.Active7d != (WindowCount{3, 2}) {
		t.Fatalf("1.2.0 = %+v", v)
	}
	if v := stats.Versions[1]; v.Active7d != (WindowCount{0, 0}) || v.All != (WindowCount{1, 1}) {
		t.Fatalf("1.1.0 = %+v", v)
	}
	if stats.GeneratedAt != ms {
		t.Fatalf("generatedAt = %d", stats.GeneratedAt)
	}
}

func TestSummarizeVersionsAtOrAboveUnion(t *testing.T) {
	now := time.Now()
	ms := now.UnixMilli()
	stats := SummarizeVersions([]store.MachineVersionSample{
		sample("a1", "A", "3.0.0", ms), sample("a2", "A", "2.0.0", ms),
		sample("b1", "B", "2.0.0", ms), sample("c1", "C", "1.0.0", ms),
	}, now, 60*time.Second)
	type row struct {
		version         string
		users, machines int
	}
	var got []row
	for _, v := range stats.Versions {
		got = append(got, row{v.Version, v.AtOrAbove.Online.Users, v.AtOrAbove.Online.Machines})
	}
	// A and B for 2.0.0, not 1+2.
	if want := []row{{"3.0.0", 1, 1}, {"2.0.0", 2, 3}, {"1.0.0", 3, 4}}; !slices.Equal(got, want) {
		t.Fatalf("atOrAbove = %+v", got)
	}
	if stats.Totals.Online.Users != 3 {
		t.Fatalf("totals = %+v", stats.Totals)
	}
}

func TestSummarizeVersionsIncomparableHaveNoAtOrAbove(t *testing.T) {
	now := time.Now()
	ms := now.UnixMilli()
	stats := SummarizeVersions([]store.MachineVersionSample{
		sample("a", "A", "1.0.0", ms), sample("b", "B", "unknown", ms), sample("c", "C", "my-fork", ms),
	}, now, 60*time.Second)
	var got []string
	for _, v := range stats.Versions {
		got = append(got, v.Version)
		if (v.AtOrAbove == nil) != (v.Version != "1.0.0") {
			t.Fatalf("%s atOrAbove = %v", v.Version, v.AtOrAbove)
		}
	}
	if !slices.Equal(got, []string{"1.0.0", "my-fork", "unknown"}) {
		t.Fatalf("versions = %v", got)
	}
	bad := SummarizeVersions([]store.MachineVersionSample{sample("a", "A", "1.2.3", ms), sample("b", "B", "01.2.4", ms)}, now, 60*time.Second)
	for _, v := range bad.Versions {
		if v.Version == "01.2.4" && v.AtOrAbove != nil {
			t.Fatalf("01.2.4 atOrAbove = %+v", v.AtOrAbove)
		}
	}
	// JSON keeps the TS shape: atOrAbove null, not omitted.
	data, _ := json.Marshal(stats.Versions[2])
	if !strings.HasSuffix(string(data), `"atOrAbove":null}`) {
		t.Fatalf("json = %s", data)
	}
}

type fakeLiveMachines struct {
	conns      map[string]tunnel.MachineConn
	staleAfter time.Duration
}

func (f fakeLiveMachines) Get(id string) (tunnel.MachineConn, bool) {
	conn, ok := f.conns[id]
	return conn, ok
}

func (f fakeLiveMachines) IsStale(conn tunnel.MachineConn) bool {
	return time.Since(conn.LastSeen) > f.staleAfter
}

func TestOverlayLive(t *testing.T) {
	now := time.Now()
	conn := func(id, version string, lastSeen time.Time) tunnel.MachineConn {
		return tunnel.MachineConn{MachineID: id, UnionID: "u-" + id, BotmuxVersion: version, LastSeen: lastSeen}
	}
	live := fakeLiveMachines{staleAfter: time.Minute, conns: map[string]tunnel.MachineConn{
		"m-bound":      conn("m-bound", "2.0.0", now),
		"m-live-only":  conn("m-live-only", "2.1.0", now),
		"m-stale-live": conn("m-stale-live", "0.1.0", now.Add(-10*time.Second)),
		// A stale local connection (the machine reconnected elsewhere and
		// upgraded) must not overwrite the newer persisted version.
		"m-dead-local": conn("m-dead-local", "0.9.0", now.Add(-time.Minute-time.Second)),
	}}
	out := OverlayLive([]store.MachineVersionSample{
		sample("m-bound", "u-owner", "unknown", 0),
		sample("m-stale-live", "u-x", "1.0.0", now.UnixMilli()),
		sample("m-dead-local", "u-y", "2.0.0", now.UnixMilli()),
	}, live)
	byID := map[string]store.MachineVersionSample{}
	for _, s := range out {
		byID[s.MachineID] = s
	}
	if len(out) != 3 {
		t.Fatalf("out = %+v", out)
	}
	if got := byID["m-bound"]; got != sample("m-bound", "u-owner", "2.0.0", now.UnixMilli()) {
		t.Fatalf("m-bound = %+v", got)
	}
	if byID["m-dead-local"].BotmuxVersion != "2.0.0" {
		t.Fatalf("m-dead-local = %+v", byID["m-dead-local"])
	}
	// The persisted heartbeat only refreshed lastSeen: the live version wins.
	if got := byID["m-stale-live"]; got != sample("m-stale-live", "u-x", "0.1.0", now.UnixMilli()) {
		t.Fatalf("m-stale-live = %+v", got)
	}
}

func TestVersionSamplesFollowRegisterAndHeartbeat(t *testing.T) {
	repository := newMemoryRepository()
	ctx := context.Background()
	for _, id := range []string{"mem1", "mem2"} {
		if _, err := repository.BindMachineCAS(ctx, id, "u-"+id, ""); err != nil {
			t.Fatal(err)
		}
	}
	if err := repository.RetireMachine(ctx, "mem2"); err != nil {
		t.Fatal(err)
	}
	register := store.RegisterMachine{MachineID: "mem1", UnionID: "u-mem1", DashboardPort: 1}
	register.BotmuxVersion, register.LastSeen = "1.0.0", 100
	if err := repository.PersistRegister(ctx, register); err != nil {
		t.Fatal(err)
	}
	version := "1.1.0"
	if err := repository.PersistHeartbeat(ctx, "mem1", store.HeartbeatUpdate{BotmuxVersion: &version, LastSeen: 200}); err != nil {
		t.Fatal(err)
	}
	// Not the owner / RETIRED: no write-back.
	register.UnionID, register.BotmuxVersion, register.LastSeen = "u-evil", "6.6.6", 300
	_ = repository.PersistRegister(ctx, register)
	evil := "9.9.9"
	_ = repository.PersistHeartbeat(ctx, "mem2", store.HeartbeatUpdate{BotmuxVersion: &evil, LastSeen: 200})
	samples, err := repository.ListMachineVersionSamples(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if want := []store.MachineVersionSample{sample("mem1", "u-mem1", "1.1.0", 200)}; !slices.Equal(samples, want) {
		t.Fatalf("samples = %+v", samples)
	}
}

func fakeReleaseFetch(table map[string]any) ReleaseFetch {
	return func(_ context.Context, url string, _ map[string]string) (bool, []byte, error) {
		value, ok := table[url]
		if !ok {
			return false, []byte("{}"), nil
		}
		if err, isErr := value.(error); isErr {
			return false, nil, err
		}
		body, _ := json.Marshal(map[string]any{"version": value})
		return true, body, nil
	}
}

func lookupOf(version string, primary bool) ReleaseLookup {
	if version == "" {
		return ReleaseLookup{Primary: primary}
	}
	return ReleaseLookup{Version: &version, Primary: primary}
}

func sameLookup(a, b ReleaseLookup) bool {
	return a.Primary == b.Primary && (a.Version == nil) == (b.Version == nil) && (a.Version == nil || *a.Version == *b.Version)
}

func TestFetchLatestRelease(t *testing.T) {
	ctx := context.Background()
	registries := []string{"https://npm", "https://mirror"}
	cases := []struct {
		registries []string
		table      map[string]any
		want       ReleaseLookup
	}{
		{registries, map[string]any{"https://npm/botmux/latest": "3.42.0", "https://mirror/botmux/latest": "3.41.0"}, lookupOf("3.42.0", true)},
		{registries, map[string]any{"https://npm/botmux/latest": errors.New("ETIMEDOUT"), "https://mirror/botmux/latest": "v3.41.0"}, lookupOf("3.41.0", false)},
		{[]string{"https://npm"}, map[string]any{"https://npm/botmux/latest": "03.1.0"}, lookupOf("", false)},
		{[]string{"https://npm"}, map[string]any{}, lookupOf("", false)},
		{nil, map[string]any{}, lookupOf("", false)},
	}
	for i, c := range cases {
		if got := FetchLatestRelease(ctx, c.registries, fakeReleaseFetch(c.table)); !sameLookup(got, c.want) {
			t.Fatalf("case %d: got %+v", i, got)
		}
	}
}

func TestFetchLatestReleaseDoesNotWaitForStuckMirror(t *testing.T) {
	started := time.Now()
	got := FetchLatestRelease(context.Background(), []string{"https://npm", "https://mirror"}, func(ctx context.Context, url string, _ map[string]string) (bool, []byte, error) {
		if strings.HasPrefix(url, "https://npm") {
			return true, []byte(`{"version":"3.42.0"}`), nil
		}
		<-ctx.Done() // the mirror never answers
		return false, nil, ctx.Err()
	})
	if !sameLookup(got, lookupOf("3.42.0", true)) || time.Since(started) > 500*time.Millisecond {
		t.Fatalf("got %+v after %s", got, time.Since(started))
	}
}

func TestNextReleaseState(t *testing.T) {
	str := func(s string) *string { return &s }
	same := func(a, b ReleaseState) bool {
		return a.At == b.At && a.OK == b.OK && a.Authoritative == b.Authoritative &&
			(a.Value == nil) == (b.Value == nil) && (a.Value == nil || *a.Value == *b.Value)
	}
	authoritative := &ReleaseState{At: 0, OK: true, Value: str("3.42.0"), Authoritative: true}
	// Mirror lagging / ahead / everything failed: the authoritative value
	// stays, only the retry cadence switches to 1min.
	for _, lookup := range []ReleaseLookup{lookupOf("3.41.0", false), lookupOf("3.43.0", false), lookupOf("", false)} {
		if got := NextReleaseState(authoritative, lookup, 5); !same(got, ReleaseState{At: 5, OK: false, Value: str("3.42.0"), Authoritative: true}) {
			t.Fatalf("%+v -> %+v", lookup, got)
		}
	}
	// The registry rolled latest back: trusted, and a mirror still on the
	// rolled-back version may not restore it.
	rolledBack := NextReleaseState(authoritative, lookupOf("3.41.1", true), 5)
	if !same(rolledBack, ReleaseState{At: 5, OK: true, Value: str("3.41.1"), Authoritative: true}) {
		t.Fatalf("rolled back = %+v", rolledBack)
	}
	if got := NextReleaseState(&rolledBack, lookupOf("3.42.0", false), 6); *got.Value != "3.41.1" {
		t.Fatalf("mirror overwrote: %+v", got)
	}
	// Never authoritative: use the mirror, never going backwards.
	mirror := NextReleaseState(nil, lookupOf("3.41.0", false), 5)
	if !same(mirror, ReleaseState{At: 5, OK: false, Value: str("3.41.0"), Authoritative: false}) {
		t.Fatalf("mirror = %+v", mirror)
	}
	if got := NextReleaseState(&mirror, lookupOf("3.40.0", false), 6); *got.Value != "3.41.0" {
		t.Fatalf("went backwards: %+v", got)
	}
}

// ── GET /api/stats/versions ─────────────────────────────────────────────────

type failingVersionSamples struct{ store.Repository }

func (failingVersionSamples) ListMachineVersionSamples(context.Context) ([]store.MachineVersionSample, error) {
	return nil, store.ErrUnavailable
}

func statsTestApex(t *testing.T, registries []string) (*Apex, *store.DocumentRepository) {
	t.Helper()
	repository := newMemoryRepository()
	cfg := config.Config{
		SigningSecret: "test-secret", PublicBaseURL: "http://localhost", SessionTTL: 7 * statsDay,
		StaleAfter: 60 * time.Second, BotmuxReleaseRegistries: registries,
	}
	return &Apex{Config: cfg, Repository: repository, Stats: StatsDeps{State: NewVersionStatsState()}}, repository
}

func statsRequest(a *Apex, method string, signedIn bool) *httptest.ResponseRecorder {
	request := httptest.NewRequest(method, "http://localhost/api/stats/versions", nil)
	if signedIn {
		token := auth.MintSession(a.Config, auth.SessionUser{UnionID: "u-nobody", Name: "Nobody"})
		request.Header.Set("Cookie", auth.SessionCookieName+"="+token)
	}
	recorder := httptest.NewRecorder()
	a.ServeHTTP(recorder, request)
	return recorder
}

func TestStatsVersionsRequiresSession(t *testing.T) {
	a, _ := statsTestApex(t, nil)
	if r := statsRequest(a, http.MethodGet, false); r.Code != http.StatusUnauthorized {
		t.Fatalf("%d %s", r.Code, r.Body.String())
	}
}

func TestStatsVersionsAggregateOnly(t *testing.T) {
	npm := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		if r.URL.Path != "/botmux/latest" {
			w.WriteHeader(http.StatusNotFound)
		}
		_, _ = io.WriteString(w, `{"name":"botmux","version":"2.5.0"}`)
	}))
	defer npm.Close()
	a, repository := statsTestApex(t, []string{npm.URL})
	ctx := context.Background()
	seed := func(id, version string) {
		if err := seedMachine(repository, store.RegisterMachine{
			MachineID: id, UnionID: "u-" + id, OwnerName: "Secret Owner", Name: "secret-host-" + id,
			BotmuxVersion: version, DashboardPort: 7891, LastSeen: time.Now().UnixMilli(),
		}); err != nil {
			t.Fatal(err)
		}
	}
	seed("aaaa1111", "2.0.0")
	seed("bbbb2222", "1.9.0")
	seed("cccc3333", "1.9.0")
	if err := repository.RetireMachine(ctx, "cccc3333"); err != nil {
		t.Fatal(err)
	}
	// A fork with a higher version counts in the distribution but never
	// becomes the latest version.
	seed("dddd4444", "9.9.9")

	r := statsRequest(a, http.MethodGet, true)
	if r.Code != http.StatusOK || r.Header().Get("Content-Type") != "application/json; charset=utf-8" {
		t.Fatalf("%d %v %s", r.Code, r.Header(), r.Body.String())
	}
	text := r.Body.String()
	var body struct {
		GeneratedAt   int64           `json:"generatedAt"`
		Totals        WindowCounts    `json:"totals"`
		Versions      []VersionBucket `json:"versions"`
		LatestVersion *string         `json:"latestVersion"`
	}
	if err := json.Unmarshal([]byte(text), &body); err != nil {
		t.Fatal(err)
	}
	if body.LatestVersion == nil || *body.LatestVersion != "2.5.0" || body.Totals.Online != (WindowCount{3, 3}) {
		t.Fatalf("body = %s", text)
	}
	var versions []string
	for _, v := range body.Versions {
		versions = append(versions, v.Version)
	}
	if !slices.Equal(versions, []string{"9.9.9", "2.0.0", "1.9.0"}) {
		t.Fatalf("versions = %v", versions)
	}
	for _, leak := range []string{"aaaa1111", "u-aaaa1111", "Secret Owner", "secret-host"} {
		if strings.Contains(text, leak) {
			t.Fatalf("response leaks %q: %s", leak, text)
		}
	}
	// Key order of the TS literal.
	if !strings.HasPrefix(text, `{"generatedAt":`) || !strings.Contains(text, `],"latestVersion":"2.5.0"}`) {
		t.Fatalf("shape = %s", text)
	}
}

func TestStatsVersionsMethodAndStore(t *testing.T) {
	a, _ := statsTestApex(t, nil)
	r := statsRequest(a, http.MethodPost, true)
	if r.Code != http.StatusMethodNotAllowed || r.Body.String() != `{"error":"method_not_allowed"}` {
		t.Fatalf("%d %s", r.Code, r.Body.String())
	}
	// No registries configured: latestVersion is null.
	if r := statsRequest(a, http.MethodGet, true); r.Code != http.StatusOK || !strings.HasSuffix(r.Body.String(), `"latestVersion":null}`) {
		t.Fatalf("%d %s", r.Code, r.Body.String())
	}
	// A degraded store is a 503 and is not cached.
	b, repository := statsTestApex(t, nil)
	b.Repository = failingVersionSamples{Repository: repository}
	if r := statsRequest(b, http.MethodGet, true); r.Code != http.StatusServiceUnavailable || r.Body.String() != `{"error":"store_unavailable"}` {
		t.Fatalf("%d %s", r.Code, r.Body.String())
	}
	b.Repository = repository
	if r := statsRequest(b, http.MethodGet, true); r.Code != http.StatusOK {
		t.Fatalf("after recovery: %d %s", r.Code, r.Body.String())
	}
	// Other /api/stats/* paths are not ours.
	request := httptest.NewRequest(http.MethodGet, "http://localhost/api/stats/other", nil)
	if a.handleStatsAPI(httptest.NewRecorder(), request, nil) {
		t.Fatal("claimed /api/stats/other")
	}
}

func TestVersionStatsDistributionCache(t *testing.T) {
	repository := newMemoryRepository()
	now := time.UnixMilli(1_700_000_000_000)
	state := NewVersionStatsState()
	state.Now = func() time.Time { return now }
	ctx := context.Background()
	if err := seedMachine(repository, store.RegisterMachine{MachineID: "m1", UnionID: "u1", BotmuxVersion: "1.0.0", LastSeen: now.UnixMilli()}); err != nil {
		t.Fatal(err)
	}
	first := state.loadDistribution(ctx, repository, nil, time.Minute)
	if err := seedMachine(repository, store.RegisterMachine{MachineID: "m2", UnionID: "u2", BotmuxVersion: "2.0.0", LastSeen: now.UnixMilli()}); err != nil {
		t.Fatal(err)
	}
	if cached := state.loadDistribution(ctx, repository, nil, time.Minute); cached != first {
		t.Fatal("distribution not cached within 60s")
	}
	now = now.Add(61 * time.Second)
	if fresh := state.loadDistribution(ctx, repository, nil, time.Minute); fresh == first || len(fresh.Versions) != 2 {
		t.Fatalf("not refreshed: %+v", fresh)
	}
}
