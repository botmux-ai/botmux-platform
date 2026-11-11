package store

import (
	"context"
	"errors"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

func TestKVTTLCASAndRevocation(t *testing.T) {
	t.Parallel()
	now := time.Unix(100, 0)
	kv := NewMemoryKVWithClock(func() time.Time { return now })
	s := NewKVStore(kv, "sandbox", 2*time.Minute, 30*time.Minute)
	ctx := context.Background()
	if err := s.SetMachineRoute(ctx, "m", "pod-a"); err != nil {
		t.Fatal(err)
	}
	if deleted, err := s.DeleteMachineRoute(ctx, "m", "pod-b"); err != nil || deleted {
		t.Fatalf("stale delete: %v %v", deleted, err)
	}
	if got, _ := s.GetMachineRoute(ctx, "m"); got != "pod-a" {
		t.Fatalf("route=%q", got)
	}
	now = now.Add(2 * time.Minute)
	if got, _ := s.GetMachineRoute(ctx, "m"); got != "" {
		t.Fatalf("expired route=%q", got)
	}
	if err := s.RevokeMachineToken(ctx, "m", 1000, time.Hour); err != nil {
		t.Fatal(err)
	}
	old, equal, newer := int64(999), int64(1000), int64(1001)
	if yes, _ := s.IsMachineTokenRevoked(ctx, "m", &old); !yes {
		t.Fatal("old token accepted")
	}
	if yes, _ := s.IsMachineTokenRevoked(ctx, "m", &equal); yes {
		t.Fatal("equal iat must remain valid for legacy strict comparison")
	}
	if yes, _ := s.IsMachineTokenRevoked(ctx, "m", &newer); yes {
		t.Fatal("new token rejected")
	}
	if yes, _ := s.IsMachineTokenRevoked(ctx, "m", nil); !yes {
		t.Fatal("legacy token without iat must be rejected")
	}
	_, err := kv.Get(ctx, "missing")
	if !errors.Is(err, ErrKeyNotFound) {
		t.Fatalf("missing error=%v", err)
	}
}

func TestOpenProductionKVStoreNeverSilentlyFallsBack(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	got, closer, err := OpenProductionKVStore(ctx, KVConfig{}, nil)
	if err != nil || got != nil || closer != nil {
		t.Fatalf("disabled Redis = (%v, %v, %v)", got, closer, err)
	}
	got, closer, err = OpenProductionKVStore(ctx, KVConfig{Address: "redis://prod.example:6379"}, nil)
	if !errors.Is(err, ErrUnavailable) || got != nil || closer != nil {
		t.Fatalf("configured Redis without adapter = (%v, %v, %v)", got, closer, err)
	}
}

func TestRuntimeRouteAdapterHonorsCallerTTL(t *testing.T) {
	t.Parallel()
	now := time.Unix(100, 0)
	kv := NewMemoryKVWithClock(func() time.Time { return now })
	routes := NewRuntimeRouteAdapter(NewKVStore(kv, "sandbox", time.Hour, time.Hour))
	ctx := context.Background()
	if err := routes.SetMachineRoute(ctx, "m", "pod", time.Second); err != nil {
		t.Fatal(err)
	}
	now = now.Add(time.Second)
	if got, err := routes.GetMachineRoute(ctx, "m"); err != nil || got != "" {
		t.Fatalf("expired route = %q, %v", got, err)
	}
	if err := routes.SetSupportRoute(ctx, "s", "pod-a", time.Hour); err != nil {
		t.Fatal(err)
	}
	if err := routes.DeleteSupportRoute(ctx, "s", "pod-b"); err != nil {
		t.Fatal(err)
	}
	if got, _ := routes.GetSupportRoute(ctx, "s"); got != "pod-a" {
		t.Fatalf("stale conditional delete removed route: %q", got)
	}
}

// countingKV wraps MemoryKV and counts calls; failSets makes the next N Set
// calls fail; when firstGetGate is set the first Get reads and then blocks until it closes.
type countingKV struct {
	*MemoryKV
	gets, sets, dels atomic.Int64
	failSets         atomic.Int64
	firstGetGate     chan struct{}
}

func (c *countingKV) Get(ctx context.Context, key string) (string, error) {
	first := c.gets.Add(1) == 1
	value, err := c.MemoryKV.Get(ctx, key)
	if first && c.firstGetGate != nil {
		<-c.firstGetGate // the value was read; its return is delayed
	}
	return value, err
}
func (c *countingKV) Set(ctx context.Context, key, value string, ttl time.Duration) error {
	c.sets.Add(1)
	if c.failSets.Load() > 0 {
		c.failSets.Add(-1)
		return errors.New("ops limit exceed")
	}
	return c.MemoryKV.Set(ctx, key, value, ttl)
}
func (c *countingKV) Delete(ctx context.Context, key string) error {
	c.dels.Add(1)
	return c.MemoryKV.Delete(ctx, key)
}

type routeFixture struct {
	kv    *countingKV
	store *KVStore
	now   *time.Time
	mu    *sync.Mutex
}

func newRouteFixture(t *testing.T, initial string, gate chan struct{}) routeFixture {
	t.Helper()
	now := time.Unix(1_700_000_000, 0)
	mu := &sync.Mutex{}
	clock := func() time.Time { mu.Lock(); defer mu.Unlock(); return now }
	kv := &countingKV{MemoryKV: NewMemoryKVWithClock(clock), firstGetGate: gate}
	s := NewKVStore(kv, "test", 180*time.Second, time.Hour)
	s.routes.now = clock
	if initial != "" {
		_ = kv.MemoryKV.Set(context.Background(), s.RouteKey(routeMID), initial, 0)
	}
	return routeFixture{kv: kv, store: s, now: &now, mu: mu}
}

func (f routeFixture) advance(d time.Duration) {
	f.mu.Lock()
	*f.now = f.now.Add(d)
	f.mu.Unlock()
}

const routeMID = "cafebabecafebabe"

var routeCacheOptions = RouteCacheOptions{PositiveTTL: MachineRouteCacheTTL}

// Ports of test/store-machine-route-cache.test.ts.

func TestMachineRouteColdConcurrentReadsHitKVOnce(t *testing.T) {
	t.Parallel()
	f := newRouteFixture(t, "10.0.0.1:8080", make(chan struct{}))
	ctx := context.Background()
	var wg sync.WaitGroup
	results := make([]string, 40)
	for i := range results {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			results[i], _ = f.store.GetMachineRouteCached(ctx, routeMID, routeCacheOptions)
		}(i)
	}
	// Let every goroutine join the in-flight read before releasing it.
	for f.kv.gets.Load() == 0 {
		time.Sleep(time.Millisecond)
	}
	time.Sleep(20 * time.Millisecond)
	close(f.kv.firstGetGate)
	wg.Wait()
	for _, r := range results {
		if r != "10.0.0.1:8080" {
			t.Fatalf("results = %v", results)
		}
	}
	if f.kv.gets.Load() != 1 || f.store.routes.reads.Load() != 1 {
		t.Fatalf("40 concurrent reads must produce one Redis GET, got %d", f.kv.gets.Load())
	}
}

func TestMachineRoutePositiveHitWithinTTLAndAbsoluteExpiry(t *testing.T) {
	t.Parallel()
	f := newRouteFixture(t, "10.0.0.2:8080", nil)
	ctx := context.Background()
	for i := 0; i < 11; i++ {
		if got, err := f.store.GetMachineRouteCached(ctx, routeMID, routeCacheOptions); err != nil || got != "10.0.0.2:8080" {
			t.Fatalf("read %d = %q %v", i, got, err)
		}
	}
	if f.kv.gets.Load() != 1 {
		t.Fatalf("gets = %d", f.kv.gets.Load())
	}
	f.advance(MachineRouteCacheTTL)
	_, _ = f.store.GetMachineRouteCached(ctx, routeMID, routeCacheOptions)
	if f.kv.gets.Load() != 2 {
		t.Fatalf("expired entry must be re-read, gets = %d", f.kv.gets.Load())
	}
	// A caller asking for more than the hard max is capped at 10s.
	f.advance(time.Hour)
	_, _ = f.store.GetMachineRouteCached(ctx, routeMID, RouteCacheOptions{PositiveTTL: time.Hour})
	f.advance(machineRouteCacheHardMax)
	_, _ = f.store.GetMachineRouteCached(ctx, routeMID, RouteCacheOptions{PositiveTTL: time.Hour})
	if f.kv.gets.Load() != 4 {
		t.Fatalf("hard max not applied, gets = %d", f.kv.gets.Load())
	}
}

func TestMachineRouteMissingIsNeverCached(t *testing.T) {
	t.Parallel()
	f := newRouteFixture(t, "", nil)
	ctx := context.Background()
	for i := 0; i < 2; i++ {
		if got, err := f.store.GetMachineRouteCached(ctx, routeMID, routeCacheOptions); err != nil || got != "" {
			t.Fatalf("missing route = %q %v", got, err)
		}
	}
	if f.kv.gets.Load() != 2 {
		t.Fatalf("missing routes must not be cached, gets = %d", f.kv.gets.Load())
	}
	_ = f.kv.MemoryKV.Set(ctx, f.store.RouteKey(routeMID), "10.0.0.3:8080", time.Hour)
	if got, _ := f.store.GetMachineRouteCached(ctx, routeMID, routeCacheOptions); got != "10.0.0.3:8080" {
		t.Fatalf("route = %q", got)
	}
}

func TestMachineRouteWithoutOptionsReadsThrough(t *testing.T) {
	t.Parallel()
	f := newRouteFixture(t, "10.0.0.4:8080", nil)
	ctx := context.Background()
	_, _ = f.store.GetMachineRoute(ctx, routeMID)
	_, _ = f.store.GetMachineRouteCached(ctx, routeMID, RouteCacheOptions{})
	_, _ = NewRuntimeRouteAdapter(f.store).GetMachineRoute(ctx, routeMID)
	if f.kv.gets.Load() != 3 {
		t.Fatalf("gets = %d", f.kv.gets.Load())
	}
}

func TestMachineRouteSetAndDeleteInvalidateCache(t *testing.T) {
	t.Parallel()
	f := newRouteFixture(t, "10.0.0.5:8080", nil)
	ctx := context.Background()
	routes := NewRuntimeRouteAdapter(f.store)
	if got, _ := routes.GetMachineRouteCached(ctx, routeMID, routeCacheOptions); got != "10.0.0.5:8080" {
		t.Fatalf("route = %q", got)
	}
	if err := routes.SetMachineRoute(ctx, routeMID, "10.0.0.9:8080", 180*time.Second); err != nil {
		t.Fatal(err)
	}
	if got, _ := routes.GetMachineRouteCached(ctx, routeMID, routeCacheOptions); got != "10.0.0.9:8080" || f.kv.gets.Load() != 2 {
		t.Fatalf("set must invalidate: %q gets=%d", got, f.kv.gets.Load())
	}
	if err := routes.DeleteMachineRoute(ctx, routeMID, ""); err != nil {
		t.Fatal(err)
	}
	if got, _ := routes.GetMachineRouteCached(ctx, routeMID, routeCacheOptions); got != "" {
		t.Fatalf("delete must invalidate: %q", got)
	}
}

func TestMachineRouteUnavailableIsAnErrorAndNotCached(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	if _, err := (&KVStore{}).GetMachineRouteCached(ctx, routeMID, routeCacheOptions); !errors.Is(err, ErrUnavailable) {
		t.Fatalf("no client err = %v", err)
	}
	if _, err := NewRuntimeRouteAdapter(nil).GetMachineRouteCached(ctx, routeMID, routeCacheOptions); !errors.Is(err, ErrUnavailable) {
		t.Fatalf("nil adapter err = %v", err)
	}
}

func TestMachineRouteInvalidationDuringReadPreventsBackfill(t *testing.T) {
	t.Parallel()
	f := newRouteFixture(t, "10.0.0.1:8080", make(chan struct{}))
	ctx := context.Background()
	done := make(chan string)
	go func() {
		got, _ := f.store.GetMachineRouteCached(ctx, routeMID, routeCacheOptions)
		done <- got
	}()
	for f.kv.gets.Load() == 0 {
		time.Sleep(time.Millisecond)
	}
	// The tunnel goes offline while the stale read is in flight.
	if _, err := f.store.DeleteMachineRoute(ctx, routeMID, ""); err != nil {
		t.Fatal(err)
	}
	close(f.kv.firstGetGate)
	if got := <-done; got != "10.0.0.1:8080" {
		t.Fatalf("in-flight reader got %q", got)
	}
	if got, _ := f.store.GetMachineRouteCached(ctx, routeMID, routeCacheOptions); got != "" {
		t.Fatalf("stale read was backfilled into the cache: %q", got)
	}
}

func TestMachineRouteWriteStormIsThrottled(t *testing.T) {
	t.Parallel()
	f := newRouteFixture(t, "", nil)
	ctx := context.Background()
	for i := 0; i < 500; i++ {
		if err := f.store.SetMachineRoute(ctx, routeMID, "10.0.0.1:8080"); err != nil {
			t.Fatal(err)
		}
	}
	if f.kv.sets.Load() != 1 || f.store.routes.writes.Load() != 1 || f.store.routes.skipped.Load() != 499 {
		t.Fatalf("sets=%d writes=%d skipped=%d", f.kv.sets.Load(), f.store.routes.writes.Load(), f.store.routes.skipped.Load())
	}
	// 180s TTL -> 60s window: the next real write happens once it elapses.
	f.advance(59 * time.Second)
	_ = f.store.SetMachineRoute(ctx, routeMID, "10.0.0.1:8080")
	f.advance(time.Second)
	_ = f.store.SetMachineRoute(ctx, routeMID, "10.0.0.1:8080")
	if f.kv.sets.Load() != 2 {
		t.Fatalf("window refresh sets=%d", f.kv.sets.Load())
	}
}

func TestMachineRouteAddressChangeWritesImmediately(t *testing.T) {
	t.Parallel()
	f := newRouteFixture(t, "", nil)
	ctx := context.Background()
	for _, addr := range []string{"10.0.0.1:8080", "10.0.0.1:8080", "10.0.0.2:8080", "10.0.0.2:8080"} {
		_ = f.store.SetMachineRoute(ctx, routeMID, addr)
	}
	if f.kv.sets.Load() != 2 {
		t.Fatalf("sets = %d", f.kv.sets.Load())
	}
}

func TestMachineRouteDeleteClearsWriteMemo(t *testing.T) {
	t.Parallel()
	f := newRouteFixture(t, "", nil)
	ctx := context.Background()
	routes := NewRuntimeRouteAdapter(f.store)
	_ = routes.SetMachineRoute(ctx, routeMID, "10.0.0.1:8080", 180*time.Second)
	_ = routes.SetMachineRoute(ctx, routeMID, "10.0.0.1:8080", 180*time.Second)
	if f.kv.sets.Load() != 1 {
		t.Fatalf("sets = %d", f.kv.sets.Load())
	}
	// Conditional delete by this pod also clears the memo.
	if err := routes.DeleteMachineRoute(ctx, routeMID, "10.0.0.1:8080"); err != nil {
		t.Fatal(err)
	}
	_ = routes.SetMachineRoute(ctx, routeMID, "10.0.0.1:8080", 180*time.Second)
	if f.kv.sets.Load() != 2 {
		t.Fatalf("reconnect after delete must rewrite, sets = %d", f.kv.sets.Load())
	}
	if got, _ := routes.GetMachineRoute(ctx, routeMID); got != "10.0.0.1:8080" {
		t.Fatalf("route = %q", got)
	}
}

func TestMachineRouteFailedWriteIsRetried(t *testing.T) {
	t.Parallel()
	f := newRouteFixture(t, "", nil)
	f.kv.failSets.Store(1)
	ctx := context.Background()
	if err := f.store.SetMachineRoute(ctx, routeMID, "10.0.0.1:8080"); err == nil {
		t.Fatal("failed write must surface the error")
	}
	if err := f.store.SetMachineRoute(ctx, routeMID, "10.0.0.1:8080"); err != nil {
		t.Fatal(err)
	}
	if f.kv.sets.Load() != 2 || f.store.routes.writes.Load() != 1 {
		t.Fatalf("sets=%d writes=%d", f.kv.sets.Load(), f.store.routes.writes.Load())
	}
}

func TestRouteWriteThrottleWindow(t *testing.T) {
	t.Parallel()
	cases := map[time.Duration]time.Duration{
		0: time.Second, time.Second: time.Second, 3 * time.Second: time.Second, 6 * time.Second: 2 * time.Second,
		180 * time.Second: 60 * time.Second, time.Hour: 60 * time.Second,
	}
	for ttl, want := range cases {
		if got := routeWriteThrottle(ttl); got != want {
			t.Errorf("routeWriteThrottle(%v) = %v, want %v", ttl, got, want)
		}
	}
}

// Token cache entries hold credentials: one without a positive TTL would never
// expire, so it is refused; a delete removes only the value it expects.
func TestTokenEntriesExpireAndDeleteOnlyTheExpectedValue(t *testing.T) {
	t.Parallel()
	now := time.Unix(100, 0)
	s := NewKVStore(NewMemoryKVWithClock(func() time.Time { return now }), "sandbox", time.Minute, time.Minute)
	ctx := context.Background()
	for _, other := range []string{s.RouteKey("k"), s.StreamKey("k"), s.SupportKey("k"), s.RevokedKey("k")} {
		if s.TokenKey("k") == other {
			t.Fatalf("token entries share the key %q with another kind", other)
		}
	}
	for _, ttl := range []time.Duration{0, -time.Second} {
		if err := s.SetToken(ctx, "k", "v", ttl); !errors.Is(err, ErrTokenTTL) {
			t.Fatalf("ttl %v: err = %v", ttl, err)
		}
		if got, err := s.GetToken(ctx, "k"); got != "" || err != nil {
			t.Fatalf("ttl %v stored %q (%v)", ttl, got, err)
		}
	}
	if err := s.SetToken(ctx, "k", "v1", time.Minute); err != nil {
		t.Fatal(err)
	}
	if deleted, err := s.DeleteToken(ctx, "k", "v0"); deleted || err != nil {
		t.Fatalf("delete of another value = %v, %v", deleted, err)
	}
	if got, _ := s.GetToken(ctx, "k"); got != "v1" {
		t.Fatalf("token = %q", got)
	}
	if deleted, err := s.DeleteToken(ctx, "k", "v1"); !deleted || err != nil {
		t.Fatalf("delete = %v, %v", deleted, err)
	}
	if err := s.SetToken(ctx, "k", "v2", time.Minute); err != nil {
		t.Fatal(err)
	}
	now = now.Add(time.Minute)
	if got, err := s.GetToken(ctx, "k"); got != "" || err != nil {
		t.Fatalf("expired token = %q (%v)", got, err)
	}
	if _, err := (*KVStore)(nil).GetToken(ctx, "k"); !errors.Is(err, ErrUnavailable) {
		t.Fatalf("no store: %v", err)
	}
}
