package store

import (
	"context"
	"sync"
	"sync/atomic"
	"time"
)

// MachineRouteCacheTTL is the recommended positive-cache TTL for machine
// route reads on the cross-pod reverse-proxy hot path. A Desktop/terminal
// first paint fires dozens of concurrent requests for the same machine; each
// would otherwise read the same route:<machineId> key and exhaust that Redis
// shard's RU quota.
const MachineRouteCacheTTL = 5 * time.Second

// machineRouteCacheHardMax caps any caller-supplied TTL.
const machineRouteCacheHardMax = 10 * time.Second

// RouteCacheOptions opts a route read into the positive cache. The zero value
// reads straight through; online/offline decisions (ticket issuing, device
// open) must keep reading directly. Only a found pod address is cached; a
// missing route or a Redis failure never is. The TTL is absolute and capped
// at 10s; same-pod set/delete invalidates the entry; concurrent cold reads
// are coalesced. Cross-pod migrations heal within the TTL.
type RouteCacheOptions struct {
	PositiveTTL time.Duration
}

type routeWrite struct {
	addr string
	at   time.Time
}

// routeCoordinator holds the pod-local route read cache, the write throttle
// memo and test counters.
type routeCoordinator struct {
	now   func() time.Time
	cache *positiveCache[string]

	mu         sync.Mutex
	lastWrites map[string]routeWrite

	reads   atomic.Int64
	writes  atomic.Int64
	skipped atomic.Int64
}

func newRouteCoordinator() *routeCoordinator {
	return &routeCoordinator{now: time.Now, cache: newPositiveCache[string](), lastWrites: map[string]routeWrite{}}
}

// routeWriteThrottle is the window inside which the same (machineId ->
// podAddr) is written at most once: a third of the TTL, between 1s and 60s.
// With heartbeats every 30s and the default 180s TTL the key is still
// refreshed once per 60s window, so it never expires between real writes,
// while a heartbeat/reconnect storm can no longer hammer a single key.
func routeWriteThrottle(ttl time.Duration) time.Duration {
	ttlMS := ttl.Milliseconds()
	if ttlMS < 1000 {
		ttlMS = 1000
	}
	window := ttlMS / 3
	if window < 1000 {
		window = 1000
	}
	if window > 60_000 {
		window = 60_000
	}
	return time.Duration(window) * time.Millisecond
}

func (s *KVStore) setMachineRoute(ctx context.Context, machineID, podAddr string, ttl time.Duration) error {
	c, err := s.requireClient()
	if err != nil {
		return err
	}
	r := s.routes
	// Self-update on this pod: drop the read cache entry but keep the write
	// memo (otherwise the throttle would never apply).
	r.cache.invalidate(machineID)
	now := r.now()
	r.mu.Lock()
	last, ok := r.lastWrites[machineID]
	r.mu.Unlock()
	if ok && last.addr == podAddr && now.Sub(last.at) < routeWriteThrottle(ttl) {
		r.skipped.Add(1)
		return nil
	}
	if err := c.Set(ctx, s.RouteKey(machineID), podAddr, ttl); err != nil {
		return err
	}
	// Record only successful writes so a failed write is retried next beat.
	r.mu.Lock()
	r.lastWrites[machineID] = routeWrite{addr: podAddr, at: now}
	r.mu.Unlock()
	r.writes.Add(1)
	return nil
}

func (s *KVStore) readMachineRoute(ctx context.Context, machineID string) (string, error) {
	c, err := s.requireClient()
	if err != nil {
		return "", err
	}
	s.routes.reads.Add(1)
	return getOptional(ctx, c, s.RouteKey(machineID))
}

// GetMachineRouteCached reads the route through the opt-in positive cache
// (see RouteCacheOptions). With a zero TTL it is GetMachineRoute.
func (s *KVStore) GetMachineRouteCached(ctx context.Context, machineID string, opts RouteCacheOptions) (string, error) {
	if _, err := s.requireClient(); err != nil {
		return "", err
	}
	ttl := opts.PositiveTTL
	if ttl > machineRouteCacheHardMax {
		ttl = machineRouteCacheHardMax
	}
	read := func(ctx context.Context) (string, error) { return s.readMachineRoute(ctx, machineID) }
	if ttl <= 0 {
		return read(ctx)
	}
	return s.routes.cache.get(ctx, machineID, ttl, s.routes.now, read, func(addr string, err error) bool {
		return err == nil && addr != ""
	})
}

func (s *KVStore) deleteMachineRoute(ctx context.Context, machineID, expectedAddr string) (bool, error) {
	c, err := s.requireClient()
	if err != nil {
		return false, err
	}
	// Drop the read cache and the write memo so the next register/heartbeat
	// rewrites the route immediately instead of being throttled.
	s.routes.cache.invalidate(machineID)
	s.routes.mu.Lock()
	delete(s.routes.lastWrites, machineID)
	s.routes.mu.Unlock()
	if expectedAddr == "" {
		return true, c.Delete(ctx, s.RouteKey(machineID))
	}
	return c.CompareAndDelete(ctx, s.RouteKey(machineID), expectedAddr)
}
