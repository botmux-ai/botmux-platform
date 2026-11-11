package store

import (
	"context"
	"errors"
	"fmt"
	"io"
	"strconv"
	"sync"
	"time"
)

var ErrKeyNotFound = errors.New("store: key not found")

// KVClient is the small Redis-compatible surface used by the platform. Network
// adapters may implement CompareAndDelete as GET-then-DEL (CompareThenDelete)
// when the backend has no Lua support; MemoryKV implements it atomically.
type KVClient interface {
	Set(context.Context, string, string, time.Duration) error
	Get(context.Context, string) (string, error)
	Delete(context.Context, string) error
	CompareAndDelete(context.Context, string, string) (bool, error)
}

type KVConfig struct {
	// Address identifies the coordination backend (a redis:// URL for the
	// bundled Redis adapter). Empty disables cross-pod coordination.
	Address           string
	Table             string
	RouteTTL          time.Duration
	SupportSessionTTL time.Duration
}

// KVClientFactory is implemented by the production KV adapter.
// Keeping construction explicit prevents a configured production service from
// silently falling back to process-local MemoryKV.
type KVClientFactory interface {
	Open(context.Context, KVConfig) (KVClient, io.Closer, error)
}

func OpenProductionKVStore(ctx context.Context, cfg KVConfig, factory KVClientFactory) (*KVStore, io.Closer, error) {
	if cfg.Address == "" {
		return nil, nil, nil // intentionally disabled (local/single-pod mode)
	}
	if factory == nil {
		// Address may embed credentials (redis://user:pass@host), so it is never
		// echoed into errors or logs.
		return nil, nil, fmt.Errorf("%w: coordination store configured but no KV adapter is linked", ErrUnavailable)
	}
	client, closer, err := factory.Open(ctx, cfg)
	if err != nil {
		return nil, nil, fmt.Errorf("%w: initialize coordination store: %v", ErrUnavailable, err)
	}
	if client == nil {
		if closer != nil {
			_ = closer.Close()
		}
		return nil, nil, fmt.Errorf("%w: KV factory returned a nil client", ErrUnavailable)
	}
	return NewKVStore(client, cfg.Table, cfg.RouteTTL, cfg.SupportSessionTTL), closer, nil
}

type CoordinationStore interface {
	SetMachineRoute(context.Context, string, string) error
	GetMachineRoute(context.Context, string) (string, error)
	DeleteMachineRoute(context.Context, string, string) (bool, error)
	SetStreamOwner(context.Context, string, string) error
	GetStreamOwner(context.Context, string) (string, error)
	SetSupportRoute(context.Context, string, string) error
	GetSupportRoute(context.Context, string) (string, error)
	DeleteSupportRoute(context.Context, string, string) (bool, error)
	RevokeMachineToken(context.Context, string, int64, time.Duration) error
	IsMachineTokenRevoked(context.Context, string, *int64) (bool, error)
}

// KVStore is the runtime coordination store (machine/stream/support
// routes and machine-token revocation). It also owns the pod-local machine
// route read cache and write throttle (see kv_route_cache.go); share one
// instance per process.
type KVStore struct {
	client            KVClient
	table             string
	routeTTL          time.Duration
	supportSessionTTL time.Duration

	routes *routeCoordinator
}

func NewKVStore(client KVClient, table string, routeTTL, supportSessionTTL time.Duration) *KVStore {
	if table == "" {
		table = "sandbox"
	}
	return &KVStore{client: client, table: table, routeTTL: routeTTL, supportSessionTTL: supportSessionTTL,
		routes: newRouteCoordinator()}
}

func (s *KVStore) Configured(selfPodAddr string) bool {
	return s != nil && s.client != nil && selfPodAddr != ""
}
func (s *KVStore) key(kind, id string) string  { return "[" + s.table + "]" + kind + ":" + id }
func (s *KVStore) RouteKey(id string) string   { return s.key("route", id) }
func (s *KVStore) StreamKey(id string) string  { return s.key("stream", id) }
func (s *KVStore) SupportKey(id string) string { return s.key("support", id) }
func (s *KVStore) RevokedKey(id string) string { return s.key("revoked", id) }
func (s *KVStore) TokenKey(id string) string   { return s.key("token", id) }

func (s *KVStore) requireClient() (KVClient, error) {
	if s == nil || s.client == nil {
		return nil, ErrUnavailable
	}
	return s.client, nil
}

// SetMachineRoute records that machineID's tunnel lives on podAddr, using the
// store's default route TTL. Repeated writes of the same address are
// throttled (see setMachineRoute).
func (s *KVStore) SetMachineRoute(ctx context.Context, machineID, podAddr string) error {
	return s.setMachineRoute(ctx, machineID, podAddr, s.routeTTL)
}

// GetMachineRoute reads the route straight from Redis ("" when absent).
func (s *KVStore) GetMachineRoute(ctx context.Context, machineID string) (string, error) {
	return s.readMachineRoute(ctx, machineID)
}

// DeleteMachineRoute deletes the route; with expectedAddr it deletes only if
// the route still points there. Local read cache and write throttle entries
// are dropped first.
func (s *KVStore) DeleteMachineRoute(ctx context.Context, machineID, expectedAddr string) (bool, error) {
	return s.deleteMachineRoute(ctx, machineID, expectedAddr)
}
func (s *KVStore) SetStreamOwner(ctx context.Context, streamID, podAddr string) error {
	c, err := s.requireClient()
	if err != nil {
		return err
	}
	return c.Set(ctx, s.StreamKey(streamID), podAddr, 30*time.Second)
}
func (s *KVStore) GetStreamOwner(ctx context.Context, streamID string) (string, error) {
	c, err := s.requireClient()
	if err != nil {
		return "", err
	}
	return getOptional(ctx, c, s.StreamKey(streamID))
}
func (s *KVStore) SetSupportRoute(ctx context.Context, sessionID, podAddr string) error {
	c, err := s.requireClient()
	if err != nil {
		return err
	}
	return c.Set(ctx, s.SupportKey(sessionID), podAddr, s.supportSessionTTL+time.Minute)
}
func (s *KVStore) GetSupportRoute(ctx context.Context, sessionID string) (string, error) {
	c, err := s.requireClient()
	if err != nil {
		return "", err
	}
	return getOptional(ctx, c, s.SupportKey(sessionID))
}
func (s *KVStore) DeleteSupportRoute(ctx context.Context, sessionID, expectedAddr string) (bool, error) {
	c, err := s.requireClient()
	if err != nil {
		return false, err
	}
	if expectedAddr == "" {
		return true, c.Delete(ctx, s.SupportKey(sessionID))
	}
	return c.CompareAndDelete(ctx, s.SupportKey(sessionID), expectedAddr)
}
func (s *KVStore) RevokeMachineToken(ctx context.Context, machineID string, cutoffMS int64, ttl time.Duration) error {
	c, err := s.requireClient()
	if err != nil {
		return err
	}
	if ttl < time.Second {
		ttl = time.Second
	}
	return c.Set(ctx, s.RevokedKey(machineID), strconv.FormatInt(cutoffMS, 10), ttl)
}
func (s *KVStore) IsMachineTokenRevoked(ctx context.Context, machineID string, issuedAtMS *int64) (bool, error) {
	c, err := s.requireClient()
	if err != nil {
		return false, err
	}
	v, err := c.Get(ctx, s.RevokedKey(machineID))
	if errors.Is(err, ErrKeyNotFound) {
		return false, nil
	}
	if err != nil {
		return false, err
	}
	cutoff, err := strconv.ParseInt(v, 10, 64)
	if err != nil || issuedAtMS == nil {
		return true, nil
	}
	return *issuedAtMS < cutoff, nil
}

// ErrTokenTTL refuses a token cache entry without a positive TTL: Set with no
// TTL never expires, and these entries hold credentials.
var ErrTokenTTL = errors.New("store: token entry needs a positive TTL")

// GetToken reads a credential provider's cross-pod token cache entry ("" when
// absent). It and SetToken/DeleteToken implement credential.TokenStore.
func (s *KVStore) GetToken(ctx context.Context, id string) (string, error) {
	c, err := s.requireClient()
	if err != nil {
		return "", err
	}
	return getOptional(ctx, c, s.TokenKey(id))
}
func (s *KVStore) SetToken(ctx context.Context, id, value string, ttl time.Duration) error {
	c, err := s.requireClient()
	if err != nil {
		return err
	}
	if ttl <= 0 {
		return ErrTokenTTL
	}
	return c.Set(ctx, s.TokenKey(id), value, ttl)
}
func (s *KVStore) DeleteToken(ctx context.Context, id, expected string) (bool, error) {
	c, err := s.requireClient()
	if err != nil {
		return false, err
	}
	return c.CompareAndDelete(ctx, s.TokenKey(id), expected)
}

func getOptional(ctx context.Context, c KVClient, key string) (string, error) {
	v, err := c.Get(ctx, key)
	if errors.Is(err, ErrKeyNotFound) {
		return "", nil
	}
	return v, err
}

// MemoryKV is a deterministic, concurrency-safe Redis substitute. A custom
// clock makes TTL behavior testable without sleeping.
type MemoryKV struct {
	mu      sync.Mutex
	now     func() time.Time
	entries map[string]memoryKVEntry
}
type memoryKVEntry struct {
	value     string
	expiresAt time.Time
}

func NewMemoryKV() *MemoryKV { return NewMemoryKVWithClock(time.Now) }
func NewMemoryKVWithClock(now func() time.Time) *MemoryKV {
	return &MemoryKV{now: now, entries: make(map[string]memoryKVEntry)}
}
func (m *MemoryKV) Set(ctx context.Context, key, value string, ttl time.Duration) error {
	if err := checkContext(ctx); err != nil {
		return err
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	entry := memoryKVEntry{value: value}
	if ttl > 0 {
		entry.expiresAt = m.now().Add(ttl)
	}
	m.entries[key] = entry
	return nil
}
func (m *MemoryKV) Get(ctx context.Context, key string) (string, error) {
	if err := checkContext(ctx); err != nil {
		return "", err
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	e, ok := m.entries[key]
	if ok && !e.expiresAt.IsZero() && !m.now().Before(e.expiresAt) {
		delete(m.entries, key)
		ok = false
	}
	if !ok {
		return "", ErrKeyNotFound
	}
	return e.value, nil
}
func (m *MemoryKV) Delete(ctx context.Context, key string) error {
	if err := checkContext(ctx); err != nil {
		return err
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	delete(m.entries, key)
	return nil
}
func (m *MemoryKV) CompareAndDelete(ctx context.Context, key, expected string) (bool, error) {
	if err := checkContext(ctx); err != nil {
		return false, err
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	e, ok := m.entries[key]
	if ok && !e.expiresAt.IsZero() && !m.now().Before(e.expiresAt) {
		delete(m.entries, key)
		ok = false
	}
	if !ok || e.value != expected {
		return false, nil
	}
	delete(m.entries, key)
	return true, nil
}

func (s *KVStore) String() string { return fmt.Sprintf("KVStore(table=%s)", s.table) }

var _ KVClient = (*MemoryKV)(nil)
var _ CoordinationStore = (*KVStore)(nil)

// CompareThenDelete deletes key only while it still holds expected, as GET
// followed by DEL. A writer that replaces the value between the two calls can
// lose its write; route owners rewrite their route on the next heartbeat, so
// the window is bounded. Adapters for backends without Lua scripting use it.
func CompareThenDelete(
	ctx context.Context,
	key, expected string,
	get func(context.Context, string) (string, error),
	del func(context.Context, string) error,
) (bool, error) {
	current, err := get(ctx, key)
	if errors.Is(err, ErrKeyNotFound) {
		return false, nil
	}
	if err != nil {
		return false, err
	}
	if current != expected {
		return false, nil
	}
	if err := del(ctx, key); err != nil {
		return false, err
	}
	return true, nil
}
