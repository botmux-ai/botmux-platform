package store_test

import (
	"bytes"
	"context"
	"errors"
	"log/slog"
	"os"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/botmux-ai/botmux-platform/internal/store"
	"github.com/redis/go-redis/v9"
)

// Integration tests of the Redis coordination adapter (store.RedisFactory).
// They run only when BOTMUX_TEST_REDIS_URL is set, e.g.
//
//	BOTMUX_TEST_REDIS_URL=redis://127.0.0.1:6379/0 go test ./internal/store/ -run Redis
//
// Every test uses its own key namespace ([namespace] prefix, the
// REDIS_KEY_NAMESPACE / KVConfig.Table) and deletes its keys afterwards.
// The same scenarios run on MemoryKV so the Redis behaviour is pinned to the
// in-memory reference.

func redisTestURL(t *testing.T) string {
	t.Helper()
	url := os.Getenv("BOTMUX_TEST_REDIS_URL")
	if url == "" {
		t.Skip("BOTMUX_TEST_REDIS_URL not set")
	}
	return url
}

// redisNamespace returns a unique key namespace and a raw client for
// inspection; every key under the namespace is removed on cleanup.
func redisNamespace(t *testing.T, url string) (string, *redis.Client) {
	t.Helper()
	opts, err := redis.ParseURL(url)
	if err != nil {
		t.Fatalf("parse BOTMUX_TEST_REDIS_URL: %v", err)
	}
	raw := redis.NewClient(opts)
	ns := uniqueTestName("botmux_it")
	t.Cleanup(func() {
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		// '[' starts a glob character class, so the prefix is escaped.
		iter := raw.Scan(ctx, 0, `\[`+ns+`\]*`, 100).Iterator()
		for iter.Next(ctx) {
			if err := raw.Del(ctx, iter.Val()).Err(); err != nil {
				t.Errorf("cleanup %s: %v", iter.Val(), err)
			}
		}
		if err := iter.Err(); err != nil {
			t.Errorf("cleanup scan: %v", err)
		}
		_ = raw.Close()
	})
	return ns, raw
}

func openRedisKV(t *testing.T, url, ns string) store.KVClient {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	kv, closer, err := store.RedisFactory{}.Open(ctx, store.KVConfig{Address: url, Table: ns})
	if err != nil {
		t.Fatalf("open redis: %v", err)
	}
	if kv == nil || closer == nil {
		t.Fatalf("open redis returned kv=%v closer=%v", kv, closer)
	}
	t.Cleanup(func() { _ = closer.Close() })
	return kv
}

// kvBackend is one KV implementation under a scenario. advance moves time
// forward (fake clock for MemoryKV, a real sleep for Redis); pttl, when set,
// reports the remaining server-side TTL of a key (-1 = no expiry).
type kvBackend struct {
	kv      store.KVClient
	table   string
	advance func(time.Duration)
	pttl    func(key string) time.Duration
}

func memoryBackend() kvBackend {
	var mu sync.Mutex
	now := time.Unix(1_700_000_000, 0)
	kv := store.NewMemoryKVWithClock(func() time.Time { mu.Lock(); defer mu.Unlock(); return now })
	return kvBackend{kv: kv, table: "mem", advance: func(d time.Duration) { mu.Lock(); now = now.Add(d); mu.Unlock() }}
}

func redisBackend(t *testing.T, url string) kvBackend {
	t.Helper()
	ns, raw := redisNamespace(t, url)
	return kvBackend{
		kv: openRedisKV(t, url, ns), table: ns,
		advance: func(d time.Duration) { time.Sleep(d) },
		pttl: func(key string) time.Duration {
			d, err := raw.PTTL(context.Background(), key).Result()
			if err != nil {
				t.Fatalf("PTTL %s: %v", key, err)
			}
			return d
		},
	}
}

// eachKVBackend runs scenario on MemoryKV (always) and on Redis (when
// BOTMUX_TEST_REDIS_URL is set).
func eachKVBackend(t *testing.T, scenario func(t *testing.T, b kvBackend)) {
	t.Run("memory", func(t *testing.T) { scenario(t, memoryBackend()) })
	t.Run("redis", func(t *testing.T) { scenario(t, redisBackend(t, redisTestURL(t))) })
}

func wantTTL(t *testing.T, b kvBackend, key string, max time.Duration) {
	t.Helper()
	if b.pttl == nil {
		return
	}
	got := b.pttl(key)
	if max < 0 {
		if got != -1 {
			t.Fatalf("%s TTL = %v, want no expiry", key, got)
		}
		return
	}
	if got <= 0 || got > max {
		t.Fatalf("%s TTL = %v, want in (0, %v]", key, got, max)
	}
}

func TestRedisKVBasics(t *testing.T) {
	eachKVBackend(t, func(t *testing.T, b kvBackend) {
		ctx := context.Background()
		key := func(name string) string { return "[" + b.table + "]" + name }

		if _, err := b.kv.Get(ctx, key("missing")); !errors.Is(err, store.ErrKeyNotFound) {
			t.Fatalf("get missing err = %v", err)
		}
		if err := b.kv.Set(ctx, key("k"), "v1", 0); err != nil {
			t.Fatal(err)
		}
		wantTTL(t, b, key("k"), -1)
		if err := b.kv.Set(ctx, key("k"), "v2", time.Hour); err != nil {
			t.Fatal(err)
		}
		wantTTL(t, b, key("k"), time.Hour)
		if got, err := b.kv.Get(ctx, key("k")); err != nil || got != "v2" {
			t.Fatalf("get overwritten = %q %v", got, err)
		}
		// An overwrite without TTL clears the previous expiry (SET semantics).
		if err := b.kv.Set(ctx, key("k"), "v3", 0); err != nil {
			t.Fatal(err)
		}
		wantTTL(t, b, key("k"), -1)
		if err := b.kv.Delete(ctx, key("k")); err != nil {
			t.Fatal(err)
		}
		if err := b.kv.Delete(ctx, key("k")); err != nil {
			t.Fatalf("delete missing key: %v", err)
		}
		if _, err := b.kv.Get(ctx, key("k")); !errors.Is(err, store.ErrKeyNotFound) {
			t.Fatalf("get deleted err = %v", err)
		}

		// TTL expiry, including a sub-second TTL.
		if err := b.kv.Set(ctx, key("short"), "x", 300*time.Millisecond); err != nil {
			t.Fatal(err)
		}
		wantTTL(t, b, key("short"), 300*time.Millisecond)
		if err := b.kv.Set(ctx, key("sec"), "y", time.Second); err != nil {
			t.Fatal(err)
		}
		if got, err := b.kv.Get(ctx, key("sec")); err != nil || got != "y" {
			t.Fatalf("get before expiry = %q %v", got, err)
		}
		b.advance(1100 * time.Millisecond)
		for _, k := range []string{"short", "sec"} {
			if _, err := b.kv.Get(ctx, key(k)); !errors.Is(err, store.ErrKeyNotFound) {
				t.Fatalf("expired %s err = %v", k, err)
			}
		}

		// CompareAndDelete: match, mismatch, missing, expired.
		_ = b.kv.Set(ctx, key("cad"), "pod-a", time.Hour)
		if ok, err := b.kv.CompareAndDelete(ctx, key("cad"), "pod-b"); err != nil || ok {
			t.Fatalf("mismatch CAD = %v %v", ok, err)
		}
		if got, _ := b.kv.Get(ctx, key("cad")); got != "pod-a" {
			t.Fatalf("mismatch CAD removed the key: %q", got)
		}
		wantTTL(t, b, key("cad"), time.Hour)
		if ok, err := b.kv.CompareAndDelete(ctx, key("cad"), "pod-a"); err != nil || !ok {
			t.Fatalf("match CAD = %v %v", ok, err)
		}
		if _, err := b.kv.Get(ctx, key("cad")); !errors.Is(err, store.ErrKeyNotFound) {
			t.Fatalf("matched CAD kept the key: %v", err)
		}
		for _, expected := range []string{"pod-a", ""} {
			if ok, err := b.kv.CompareAndDelete(ctx, key("cad"), expected); err != nil || ok {
				t.Fatalf("missing CAD(%q) = %v %v", expected, ok, err)
			}
		}
		_ = b.kv.Set(ctx, key("cad-exp"), "pod-a", time.Second)
		b.advance(1100 * time.Millisecond)
		if ok, err := b.kv.CompareAndDelete(ctx, key("cad-exp"), "pod-a"); err != nil || ok {
			t.Fatalf("expired CAD = %v %v", ok, err)
		}
		// Values are compared byte for byte.
		_ = b.kv.Set(ctx, key("bytes"), "10.0.0.1:8080", 0)
		if ok, _ := b.kv.CompareAndDelete(ctx, key("bytes"), "10.0.0.1:808"); ok {
			t.Fatal("prefix matched in CAD")
		}
	})
}

func TestRedisCompareAndDeleteIsAtomic(t *testing.T) {
	url := redisTestURL(t)
	ns, _ := redisNamespace(t, url)
	kv := openRedisKV(t, url, ns)
	ctx := context.Background()
	key := "[" + ns + "]route:race"
	for round := 0; round < 20; round++ {
		if err := kv.Set(ctx, key, "pod-a", time.Minute); err != nil {
			t.Fatal(err)
		}
		var wins atomic.Int64
		var wg sync.WaitGroup
		for i := 0; i < 16; i++ {
			wg.Add(1)
			go func() {
				defer wg.Done()
				ok, err := kv.CompareAndDelete(ctx, key, "pod-a")
				if err != nil {
					t.Error(err)
				}
				if ok {
					wins.Add(1)
				}
			}()
		}
		wg.Wait()
		if wins.Load() != 1 {
			t.Fatalf("round %d: %d concurrent CompareAndDelete calls succeeded, want 1", round, wins.Load())
		}
	}
}

func TestRedisKVStoreMatchesMemory(t *testing.T) {
	eachKVBackend(t, func(t *testing.T, b kvBackend) {
		ctx := context.Background()
		s := store.NewKVStore(b.kv, b.table, 2*time.Second, 30*time.Minute)
		if !s.Configured("10.0.0.1:8080") || s.Configured("") {
			t.Fatal("Configured")
		}
		if got := s.RouteKey("m"); got != "["+b.table+"]route:m" {
			t.Fatalf("route key = %q", got)
		}

		if err := s.SetMachineRoute(ctx, "m", "pod-a"); err != nil {
			t.Fatal(err)
		}
		wantTTL(t, b, s.RouteKey("m"), 2*time.Second)
		if got, err := b.kv.Get(ctx, s.RouteKey("m")); err != nil || got != "pod-a" {
			t.Fatalf("raw route key = %q %v", got, err)
		}
		if deleted, err := s.DeleteMachineRoute(ctx, "m", "pod-b"); err != nil || deleted {
			t.Fatalf("stale delete = %v %v", deleted, err)
		}
		if got, _ := s.GetMachineRoute(ctx, "m"); got != "pod-a" {
			t.Fatalf("route after stale delete = %q", got)
		}
		if got, err := s.GetMachineRouteCached(ctx, "m", store.RouteCacheOptions{PositiveTTL: store.MachineRouteCacheTTL}); err != nil || got != "pod-a" {
			t.Fatalf("cached route = %q %v", got, err)
		}
		if deleted, err := s.DeleteMachineRoute(ctx, "m", "pod-a"); err != nil || !deleted {
			t.Fatalf("owner delete = %v %v", deleted, err)
		}
		if got, err := s.GetMachineRouteCached(ctx, "m", store.RouteCacheOptions{PositiveTTL: store.MachineRouteCacheTTL}); err != nil || got != "" {
			t.Fatalf("route after delete = %q %v (cache must be invalidated)", got, err)
		}
		if err := s.SetMachineRoute(ctx, "m", "pod-c"); err != nil {
			t.Fatal(err)
		}
		if deleted, err := s.DeleteMachineRoute(ctx, "m", ""); err != nil || !deleted {
			t.Fatalf("unconditional delete = %v %v", deleted, err)
		}
		if got, _ := s.GetMachineRoute(ctx, "m"); got != "" {
			t.Fatalf("route after unconditional delete = %q", got)
		}

		if err := s.SetStreamOwner(ctx, "st", "pod-a"); err != nil {
			t.Fatal(err)
		}
		wantTTL(t, b, s.StreamKey("st"), 30*time.Second)
		if got, _ := s.GetStreamOwner(ctx, "st"); got != "pod-a" {
			t.Fatalf("stream owner = %q", got)
		}
		if got, err := s.GetStreamOwner(ctx, "none"); err != nil || got != "" {
			t.Fatalf("missing stream owner = %q %v", got, err)
		}

		if err := s.SetSupportRoute(ctx, "sup", "pod-a"); err != nil {
			t.Fatal(err)
		}
		wantTTL(t, b, s.SupportKey("sup"), 31*time.Minute)
		if deleted, err := s.DeleteSupportRoute(ctx, "sup", "pod-b"); err != nil || deleted {
			t.Fatalf("stale support delete = %v %v", deleted, err)
		}
		if got, _ := s.GetSupportRoute(ctx, "sup"); got != "pod-a" {
			t.Fatalf("support route = %q", got)
		}
		if deleted, err := s.DeleteSupportRoute(ctx, "sup", "pod-a"); err != nil || !deleted {
			t.Fatalf("support delete = %v %v", deleted, err)
		}

		if err := s.RevokeMachineToken(ctx, "m", 1000, time.Hour); err != nil {
			t.Fatal(err)
		}
		wantTTL(t, b, s.RevokedKey("m"), time.Hour)
		old, equal, newer := int64(999), int64(1000), int64(1001)
		for _, tc := range []struct {
			iat  *int64
			want bool
		}{{&old, true}, {&equal, false}, {&newer, false}, {nil, true}} {
			if got, err := s.IsMachineTokenRevoked(ctx, "m", tc.iat); err != nil || got != tc.want {
				t.Fatalf("revoked(iat=%v) = %v %v, want %v", tc.iat, got, err, tc.want)
			}
		}
		if got, err := s.IsMachineTokenRevoked(ctx, "never", &old); err != nil || got {
			t.Fatalf("unrevoked machine = %v %v", got, err)
		}
		// A sub-second revocation TTL is clamped to one second.
		if err := s.RevokeMachineToken(ctx, "short", 1000, time.Millisecond); err != nil {
			t.Fatal(err)
		}
		wantTTL(t, b, s.RevokedKey("short"), time.Second)
		if got, _ := s.IsMachineTokenRevoked(ctx, "short", &old); !got {
			t.Fatal("clamped revocation expired immediately")
		}
		b.advance(1100 * time.Millisecond)
		if got, _ := s.IsMachineTokenRevoked(ctx, "short", &old); got {
			t.Fatal("revocation outlived its TTL")
		}
		// A non-numeric marker rejects every token.
		if err := b.kv.Set(ctx, s.RevokedKey("garbled"), "not-a-number", time.Minute); err != nil {
			t.Fatal(err)
		}
		if got, _ := s.IsMachineTokenRevoked(ctx, "garbled", &newer); !got {
			t.Fatal("garbled revocation marker must reject")
		}

		// The route TTL expires (2s default route TTL in this store).
		if err := s.SetMachineRoute(ctx, "m-exp", "pod-a"); err != nil {
			t.Fatal(err)
		}
		b.advance(2100 * time.Millisecond)
		if got, _ := s.GetMachineRoute(ctx, "m-exp"); got != "" {
			t.Fatalf("expired route = %q", got)
		}
	})
}

func TestRedisRuntimeRouteAdapterMatchesMemory(t *testing.T) {
	eachKVBackend(t, func(t *testing.T, b kvBackend) {
		ctx := context.Background()
		s := store.NewKVStore(b.kv, b.table, time.Hour, time.Hour)
		routes := store.NewRuntimeRouteAdapter(s)

		if err := routes.SetMachineRoute(ctx, "m", "pod", time.Second); err != nil {
			t.Fatal(err)
		}
		wantTTL(t, b, s.RouteKey("m"), time.Second)
		if got, err := routes.GetMachineRoute(ctx, "m"); err != nil || got != "pod" {
			t.Fatalf("route = %q %v", got, err)
		}
		b.advance(1100 * time.Millisecond)
		if got, err := routes.GetMachineRoute(ctx, "m"); err != nil || got != "" {
			t.Fatalf("expired route = %q %v", got, err)
		}

		if err := routes.SetMachineRoute(ctx, "m2", "pod-a", time.Minute); err != nil {
			t.Fatal(err)
		}
		if err := routes.DeleteMachineRoute(ctx, "m2", "pod-b"); err != nil {
			t.Fatal(err)
		}
		if got, _ := routes.GetMachineRouteCached(ctx, "m2", store.RouteCacheOptions{PositiveTTL: time.Second}); got != "pod-a" {
			t.Fatalf("stale conditional delete removed the route: %q", got)
		}
		if err := routes.DeleteMachineRoute(ctx, "m2", "pod-a"); err != nil {
			t.Fatal(err)
		}
		if got, _ := routes.GetMachineRouteCached(ctx, "m2", store.RouteCacheOptions{PositiveTTL: time.Second}); got != "" {
			t.Fatalf("owner delete kept the route: %q", got)
		}

		if err := routes.SetStreamOwner(ctx, "st", "pod-a", 5*time.Second); err != nil {
			t.Fatal(err)
		}
		wantTTL(t, b, s.StreamKey("st"), 5*time.Second)
		if got, _ := routes.GetStreamOwner(ctx, "st"); got != "pod-a" {
			t.Fatalf("stream owner = %q", got)
		}

		if err := routes.SetSupportRoute(ctx, "s", "pod-a", time.Hour); err != nil {
			t.Fatal(err)
		}
		if err := routes.DeleteSupportRoute(ctx, "s", "pod-b"); err != nil {
			t.Fatal(err)
		}
		if got, _ := routes.GetSupportRoute(ctx, "s"); got != "pod-a" {
			t.Fatalf("stale conditional support delete removed the route: %q", got)
		}
		if err := routes.DeleteSupportRoute(ctx, "s", ""); err != nil {
			t.Fatal(err)
		}
		if got, _ := routes.GetSupportRoute(ctx, "s"); got != "" {
			t.Fatalf("support route after delete = %q", got)
		}

		if err := s.RevokeMachineToken(ctx, "m", 5000, time.Minute); err != nil {
			t.Fatal(err)
		}
		for iat, want := range map[int64]bool{0: true, 4999: true, 5000: false} {
			if got, err := routes.IsMachineTokenRevoked(ctx, "m", iat); err != nil || got != want {
				t.Fatalf("adapter revoked(iat=%d) = %v %v, want %v", iat, got, err, want)
			}
		}
	})
}

func TestRedisOpenProductionKVStore(t *testing.T) {
	url := redisTestURL(t)
	ns, _ := redisNamespace(t, url)
	ctx := context.Background()
	s, closer, err := store.OpenProductionKVStore(ctx, store.KVConfig{Address: url, Table: ns, RouteTTL: time.Minute, SupportSessionTTL: time.Minute}, store.RedisFactory{})
	if err != nil || s == nil || closer == nil {
		t.Fatalf("open = %v %v %v", s, closer, err)
	}
	defer closer.Close()
	if err := s.SetMachineRoute(ctx, "m", "pod-a"); err != nil {
		t.Fatal(err)
	}
	// A second process opening the same namespace sees the route.
	other, otherCloser, err := store.OpenProductionKVStore(ctx, store.KVConfig{Address: url, Table: ns}, store.RedisFactory{})
	if err != nil {
		t.Fatal(err)
	}
	defer otherCloser.Close()
	if got, err := other.GetMachineRoute(ctx, "m"); err != nil || got != "pod-a" {
		t.Fatalf("cross-process route = %q %v", got, err)
	}
	// Namespaces isolate deployments sharing one Redis database.
	isolated, isolatedCloser, err := store.OpenProductionKVStore(ctx, store.KVConfig{Address: url, Table: ns + "_other"}, store.RedisFactory{})
	if err != nil {
		t.Fatal(err)
	}
	defer isolatedCloser.Close()
	if got, err := isolated.GetMachineRoute(ctx, "m"); err != nil || got != "" {
		t.Fatalf("route leaked across namespaces = %q %v", got, err)
	}
	if err := closer.Close(); err != nil {
		t.Fatalf("close: %v", err)
	}
	if _, err := s.GetMachineRoute(ctx, "m"); err == nil {
		t.Fatal("a closed client must fail instead of silently succeeding")
	}
}

// captureLogs redirects the default slog logger for the duration of the test.
func captureLogs(t *testing.T) *bytes.Buffer {
	t.Helper()
	var buf bytes.Buffer
	previous := slog.Default()
	slog.SetDefault(slog.New(slog.NewTextHandler(&buf, nil)))
	t.Cleanup(func() { slog.SetDefault(previous) })
	return &buf
}

func TestRedisFactoryOpenErrorsDoNotLeakPassword(t *testing.T) {
	url := redisTestURL(t)
	const secret = "s3cr3t-Pa55"
	opts, err := redis.ParseURL(url)
	if err != nil {
		t.Fatal(err)
	}
	cases := map[string]string{
		"unparsable URL":     "redis://user:" + secret + "@[::1",
		"wrong scheme":       "http://user:" + secret + "@" + opts.Addr,
		"bad database":       "redis://user:" + secret + "@" + opts.Addr + "/notanumber",
		"unreachable server": "redis://user:" + secret + "@127.0.0.1:1/0",
		"rejected password":  "redis://default:" + secret + "@" + opts.Addr + "/0",
	}
	for name, address := range cases {
		t.Run(name, func(t *testing.T) {
			logs := captureLogs(t)
			ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			defer cancel()
			kv, closer, err := store.RedisFactory{}.Open(ctx, store.KVConfig{Address: address, Table: "leak"})
			if err == nil {
				// The test server may accept any password (no requirepass);
				// then this case cannot fail and is not a leak.
				if closer != nil {
					_ = closer.Close()
				}
				if name == "rejected password" {
					t.Skip("test Redis accepts any password")
				}
				t.Fatalf("open %q succeeded: kv=%v", name, kv)
			}
			if kv != nil || closer != nil {
				t.Fatalf("failed open returned kv=%v closer=%v", kv, closer)
			}
			_, _, wrapped := store.OpenProductionKVStore(ctx, store.KVConfig{Address: address, Table: "leak"}, store.RedisFactory{})
			if !errors.Is(wrapped, store.ErrUnavailable) {
				t.Fatalf("OpenProductionKVStore err = %v, want ErrUnavailable", wrapped)
			}
			for what, text := range map[string]string{"error": err.Error(), "wrapped error": wrapped.Error(), "logs": logs.String()} {
				if strings.Contains(text, secret) {
					t.Fatalf("%s leaks the password: %s", what, text)
				}
			}
		})
	}
}
