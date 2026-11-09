package store

import (
	"context"
	"sync"
	"time"
)

// DesktopDashboardAuthCacheTTL is the recommended positive-cache TTL for the
// Desktop Dashboard authority reads (session-family tombstone and MachineDoc).
// A dashboard first paint issues dozens of concurrent requests; without the
// cache each would hit MongoDB separately.
const DesktopDashboardAuthCacheTTL = 5 * time.Second

// desktopDashboardAuthCacheHardMax caps any caller-supplied TTL.
const desktopDashboardAuthCacheHardMax = 10 * time.Second

// AuthorityCacheOptions opts an authority read into the positive cache. The
// zero value (PositiveTTL <= 0) reads straight through, which is the default
// for every other authorization path and for long-lived stream watchers.
//
// Only "still valid" results are cached: revoked families, RETIRED / missing
// machines and unavailable reads are never cached. The TTL is absolute (not
// sliding) and capped at 10s even if a caller asks for more. Same-pod
// revoke/retire/co-manager writes invalidate the entry immediately, and
// concurrent cold reads of one key are coalesced into a single authority read.
type AuthorityCacheOptions struct {
	PositiveTTL time.Duration
}

func (o AuthorityCacheOptions) ttl(hardMax time.Duration) time.Duration {
	if o.PositiveTTL <= 0 {
		return 0
	}
	if o.PositiveTTL > hardMax {
		return hardMax
	}
	return o.PositiveTTL
}

type positiveEntry[V any] struct {
	value     V
	expiresAt time.Time
}

type inflightRead[V any] struct {
	done  chan struct{}
	value V
	err   error
}

// positiveCache is a per-key positive-result cache with absolute TTL and
// in-flight read coalescing. A completed read backfills the cache only if its
// in-flight slot is still the current one, so an invalidation that races a
// read can never resurrect a stale positive entry.
type positiveCache[V any] struct {
	mu       sync.Mutex
	entries  map[string]positiveEntry[V]
	inflight map[string]*inflightRead[V]
}

func newPositiveCache[V any]() *positiveCache[V] {
	return &positiveCache[V]{entries: map[string]positiveEntry[V]{}, inflight: map[string]*inflightRead[V]{}}
}

// get returns the cached value or performs read. cacheable decides whether a
// completed read may be stored. now is evaluated on every check so tests can
// inject a clock.
func (c *positiveCache[V]) get(ctx context.Context, key string, ttl time.Duration, now func() time.Time,
	read func(context.Context) (V, error), cacheable func(V, error) bool) (V, error) {
	c.mu.Lock()
	if entry, ok := c.entries[key]; ok {
		if entry.expiresAt.After(now()) {
			c.mu.Unlock()
			return entry.value, nil
		}
		delete(c.entries, key)
	}
	call, joined := c.inflight[key]
	if !joined {
		call = &inflightRead[V]{done: make(chan struct{})}
		c.inflight[key] = call
	}
	c.mu.Unlock()

	if !joined {
		// The shared read must not fail just because the first caller went
		// away, so it is detached from that caller's cancellation while
		// keeping its deadline (if any) as an upper bound.
		readCtx := context.WithoutCancel(ctx)
		cancel := context.CancelFunc(func() {})
		if deadline, ok := ctx.Deadline(); ok {
			readCtx, cancel = context.WithDeadline(readCtx, deadline)
		}
		go func() {
			defer cancel()
			value, err := read(readCtx)
			c.mu.Lock()
			if c.inflight[key] == call {
				if cacheable(value, err) {
					c.entries[key] = positiveEntry[V]{value: value, expiresAt: now().Add(ttl)}
				}
				delete(c.inflight, key)
			}
			call.value, call.err = value, err
			c.mu.Unlock()
			close(call.done)
		}()
	}
	select {
	case <-call.done:
		return call.value, call.err
	case <-ctx.Done():
		var zero V
		return zero, ctx.Err()
	}
}

// invalidate drops the cached entry and detaches any in-flight read so its
// result is returned to its waiters but never stored.
func (c *positiveCache[V]) invalidate(key string) {
	c.mu.Lock()
	delete(c.entries, key)
	delete(c.inflight, key)
	c.mu.Unlock()
}

// reset clears everything (tests).
func (c *positiveCache[V]) reset() {
	c.mu.Lock()
	c.entries = map[string]positiveEntry[V]{}
	c.inflight = map[string]*inflightRead[V]{}
	c.mu.Unlock()
}
